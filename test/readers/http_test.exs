# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.HTTPTest do
  @moduledoc """
  The HTTP reader: its sources per network, their policies, the compiled-in defaults, and
  an online run through it end to end, every server stubbed.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.KeyringSources.WellKnown
  alias Truestamp.Verify.{Online, Report}
  alias Truestamp.Verify.Readers.HTTP
  alias Truestamp.Verify.Sources.{BitcoinCore, Esplora, Horizon, NistBeacon}
  alias Truestamp.Verify.Test.{Signing, Verification}

  test "the compiled-in defaults: production and test networks, and no regtest" do
    {HTTP, state} = HTTP.default()

    assert HTTP.sources(state, "stellar", "public") ==
             {:ok, ["horizon https://horizon.stellar.org"], :first}

    assert HTTP.sources(state, "stellar", "testnet") ==
             {:ok, ["horizon https://horizon-testnet.stellar.org"], :first}

    assert HTTP.sources(state, "bitcoin", "mainnet") ==
             {:ok, ["esplora https://blockstream.info/api"], :first}

    assert HTTP.sources(state, "bitcoin", "testnet") ==
             {:ok, ["esplora https://blockstream.info/testnet/api"], :first}

    assert HTTP.sources(state, "bitcoin", "regtest") == {:error, :no_source}

    assert HTTP.sources(state, "nist", nil) ==
             {:ok, ["nist https://beacon.nist.gov/beacon/2.0"], :first}
  end

  test "a source given replaces one default; several sources take a policy" do
    {HTTP, state} =
      HTTP.default(
        bitcoin: %{
          "mainnet" => {:all, [{Esplora, preset: :mempool}, {Esplora, preset: :blockstream}]}
        },
        nist: {NistBeacon, base_url: "https://beacon.test"}
      )

    assert HTTP.sources(state, "bitcoin", "mainnet") ==
             {:ok, ["esplora https://mempool.space/api", "esplora https://blockstream.info/api"],
              :all}

    assert HTTP.sources(state, "bitcoin", "testnet") ==
             {:ok, ["esplora https://blockstream.info/testnet/api"], :first}

    assert HTTP.sources(state, "nist", nil) == {:ok, ["nist https://beacon.test"], :first}
  end

  test "two sources described alike are told apart by their position" do
    {HTTP, state} =
      HTTP.new(
        bitcoin: %{
          "mainnet" =>
            {{:at_least, 2}, [{Esplora, preset: :mempool}, {Esplora, preset: :mempool}]}
        }
      )

    assert HTTP.sources(state, "bitcoin", "mainnet") ==
             {:ok,
              ["esplora https://mempool.space/api (1)", "esplora https://mempool.space/api (2)"],
              {:at_least, 2}}
  end

  test "refuses a source that does not answer its chain's reads, a policy its sources cannot meet, and nonsense" do
    assert_raise ArgumentError, ~r/does not answer/, fn ->
      HTTP.new(stellar: %{"public" => {Esplora, preset: :mempool}})
    end

    assert_raise ArgumentError, ~r/not a policy/, fn ->
      HTTP.new(bitcoin: %{"mainnet" => {{:at_least, 3}, [{Esplora, preset: :mempool}]}})
    end

    assert_raise ArgumentError, ~r/not a Truestamp.Verify.Source/, fn ->
      HTTP.new(bitcoin: %{"mainnet" => {:most, [{Esplora, preset: :mempool}]}})
    end

    assert_raise ArgumentError, ~r/not a source/, fn -> HTTP.new(nist: "nist") end
  end

  test "Online.defaults/1: the reader, the current keyring, and the options given" do
    options = Online.defaults(deadline: 10_000)
    assert {HTTP, _state} = options[:reader]
    assert {WellKnown, [base_url: "https://www.truestamp.com"]} = options[:current_keyring]
    assert options[:deadline] == 10_000
    assert %Verify.Config{trust: :default} = Verify.Config.external!(options)
  end

  test "Online.defaults/1: a keyring from another origin is a supplied keyring (8.3)" do
    options = Online.defaults(keyring_origin: "https://keys.test")
    refute Keyword.has_key?(options, :current_keyring)
    refute Keyword.has_key?(options, :keyring_origin)

    assert options[:trust] ==
             {:keyring_source, {WellKnown, [base_url: "https://keys.test"]}}

    assert %Verify.Config{trust: {:keyring_source, _source}} = Verify.Config.external!(options)
  end

  describe "an online run, every server stubbed" do
    # The answers of the replay `window-established.json` as each server's API writes them:
    # a regtest node for Bitcoin, Horizon for Stellar, and the Beacon for NIST.
    setup do
      {:ok, %{"reads" => reads}} =
        "vectors/corpus/replay/window-established.json"
        |> Verification.path()
        |> File.read!()
        |> Verify.JSON.parse()

      found =
        for %{"read" => read, "answer" => %{"outcome" => "found", "value" => value}} <- reads,
            do: {read, value}

      answer = fn kind, params ->
        Enum.find_value(found, fn {read, value} ->
          read == Map.put(params, "kind", kind) |> Map.merge(Map.take(read, ["network"])) && value
        end)
      end

      Req.Test.stub(__MODULE__.Stellar, fn conn ->
        case conn.request_path do
          "/" ->
            identity = answer.("stellar_identity", %{})

            Req.Test.json(conn, %{
              "network_passphrase" => identity["network_passphrase"],
              "history_latest_ledger" => 100_000,
              "history_elder_ledger" => 1
            })

          "/transactions/" <> hash ->
            tx = answer.("stellar_transaction", %{"hash" => hash})
            memo = tx["memo"] |> Base.decode16!(case: :lower) |> Base.encode64()

            Req.Test.json(conn, %{
              "hash" => hash,
              "ledger" => tx["ledger"],
              "memo_type" => tx["memo_type"],
              "memo" => memo,
              "successful" => tx["successful"]
            })

          "/ledgers/" <> sequence ->
            sequence = String.to_integer(sequence)
            ledger = answer.("stellar_ledger", %{"sequence" => sequence})

            Req.Test.json(conn, %{
              "sequence" => sequence,
              "closed_at" => ledger["closed_at"],
              "hash" => ledger["hash"]
            })
        end
      end)

      Req.Test.stub(__MODULE__.Bitcoin, fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        %{"method" => method, "params" => params} = elem(Verify.JSON.parse(body), 1)

        result =
          case {method, params} do
            {"getblockhash", [0]} ->
              answer.("bitcoin_identity", %{})["hash"]

            {"getblockcount", []} ->
              answer.("bitcoin_tip", %{})["height"]

            {"getblockhash", [height]} ->
              answer.("bitcoin_block_at_height", %{"height" => height})["hash"]

            {"getblockheader", [hash]} ->
              header(answer, found, hash)
          end

        Req.Test.json(conn, %{"result" => result, "error" => nil})
      end)

      Req.Test.stub(__MODULE__.Nist, fn conn ->
        ["", "chain", chain, "pulse", pulse] = String.split(conn.request_path, "/")

        params = %{
          "chainIndex" => String.to_integer(chain),
          "pulseIndex" => String.to_integer(pulse)
        }

        Req.Test.json(conn, %{"pulse" => Map.merge(params, answer.("nist_pulse", params))})
      end)

      :ok
    end

    defp header(answer, found, hash) do
      case answer.("bitcoin_block", %{"hash" => hash}) do
        %{} = block ->
          Map.put(
            %{
              "height" => block["height"],
              "mediantime" => block["median_time_past"],
              "time" => block["time"]
            },
            "nTx",
            1
          )

        nil ->
          {_read, value} =
            Enum.find(found, fn {read, value} ->
              read["kind"] == "bitcoin_block_at_height" and value["hash"] == hash
            end)

          %{"mediantime" => value["median_time_past"], "nTx" => value["transaction_count"]}
      end
    end

    test "Truestamp's own verifier gives verified, with both edges, through the HTTP reader" do
      reader =
        HTTP.new(
          stellar: %{
            "testnet" =>
              {Horizon,
               base_url: "https://horizon.test",
               req_options: [plug: {Req.Test, __MODULE__.Stellar}]}
          },
          bitcoin: %{
            "regtest" =>
              {BitcoinCore,
               base_url: "http://node.test",
               user: "u",
               password: "p",
               req_options: [plug: {Req.Test, __MODULE__.Bitcoin}]}
          },
          nist: {NistBeacon, req_options: [plug: {Req.Test, __MODULE__.Nist}]}
        )

      pins = %{
        commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
        entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
      }

      config =
        Verify.Config.internal!(
          environment: :prod,
          networks: pins,
          key_chain: [Signing.public_key()],
          reader: reader
        )

      {:ok, %Report{} = report} =
        Verify.verify(Signing.production_without_key_event("item"), config)

      assert report.label == :verified, inspect(Enum.reject(report.rows, &(&1.status == :pass)))
      assert report.submitted_before.source == "horizon https://horizon.test"
      assert report.submitted_after != nil
    end
  end
end
