# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.LiveTest do
  @moduledoc """
  The bundled HTTP sources against the real services, to show that each answers every
  field its read kinds need. They reach the network, so they run only with
  `task test-live` (`mix test --only live`), never in `task check`.
  """

  use ExUnit.Case, async: false

  alias Truestamp.Verify.KeyringSources.WellKnown
  alias Truestamp.Verify.Online.Answer
  alias Truestamp.Verify.Sources.{Esplora, Horizon, NistBeacon}

  @moduletag :live
  @moduletag timeout: 120_000

  @mainnet_genesis "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  for preset <- [:blockstream, :mempool] do
    test "Esplora #{preset}: every Bitcoin read, with every field in its class" do
      options = [preset: unquote(preset), receive_timeout: 20_000]

      assert {:ok, %{"hash" => @mainnet_genesis}, _meta} =
               Esplora.read(options, :bitcoin_identity, %{})

      assert {:ok, tip, _meta} = Esplora.read(options, :bitcoin_tip, %{})
      assert {:ok, height} = Answer.field(tip, "height", :int)
      assert height > 900_000

      assert {:ok, at, _meta} =
               Esplora.read(options, :bitcoin_block_at_height, %{"height" => 840_000})

      for {name, class} <- [
            {"hash", :hex64},
            {"median_time_past", :int},
            {"transaction_count", :int}
          ],
          do: assert({:ok, _} = Answer.field(at, name, class))

      assert {:ok, block, _meta} = Esplora.read(options, :bitcoin_block, %{"hash" => at["hash"]})
      assert block["height"] == 840_000

      for {name, class} <- [{"median_time_past", :int}, {"time", :int}],
          do: assert({:ok, _} = Answer.field(block, name, class))

      assert {:error, :not_found, _meta} =
               Esplora.read(options, :bitcoin_block_at_height, %{"height" => height + 10_000})
    end
  end

  test "Horizon public: identity, root and a ledger" do
    options = [base_url: "https://horizon.stellar.org", receive_timeout: 20_000]

    assert {:ok, %{"network_passphrase" => "Public Global Stellar Network ; September 2015"},
            _meta} =
             Horizon.read(options, :stellar_identity, %{})

    assert {:ok, %{"elder" => elder, "latest" => latest}, _meta} =
             Horizon.read(options, :stellar_root, %{})

    assert latest > elder

    assert {:ok, ledger, _meta} =
             Horizon.read(options, :stellar_ledger, %{"sequence" => latest - 100})

    assert {:ok, _ms} = Answer.field(ledger, "closed_at", :time)
    assert {:ok, _hash} = Answer.field(ledger, "hash", :hex64)
  end

  test "the NIST Beacon: the last pulse, read again by its indices" do
    {:ok, %{status: 200, body: %{"pulse" => last}}} =
      Req.get("https://beacon.nist.gov/beacon/2.0/pulse/last", receive_timeout: 20_000)

    params = %{"chainIndex" => last["chainIndex"], "pulseIndex" => last["pulseIndex"]}
    assert {:ok, pulse, _meta} = NistBeacon.read([receive_timeout: 20_000], :nist_pulse, params)
    assert {:ok, _hex} = Answer.field(pulse, "outputValue", :nisthex)
    assert {:ok, _ms} = Answer.field(pulse, "timeStamp", :nisttime)
  end

  test "the keyring Truestamp publishes is read, or the read fails, without a crash" do
    {WellKnown, options} = WellKnown.new(receive_timeout: 20_000)

    case WellKnown.fetch(options) do
      {:ok, {:bytes, bytes}, "https://www.truestamp.com/.well-known/keyring.json", _meta} ->
        assert is_binary(bytes)

      {:error, _reason} ->
        :ok
    end
  end
end
