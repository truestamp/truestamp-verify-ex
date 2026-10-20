# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.FrameTest do
  @moduledoc """
  Step 0's identity reads (SPEC.md section 10.2, `Truestamp.Verify.Online.Frame`): they run
  at once, each under the run's deadline and with the caller's `$callers`
  (`Truestamp.Verify.Reader`, "Processes"), and give the rows reads made one after another
  give.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{Config, Report}
  alias Truestamp.Verify.Online.Frame
  alias Truestamp.Verify.Test.{Barrier, FakeReader, Verification}

  @item Verification.path("vectors/positive/item.proof.json")
  @keyring Verification.path("vectors/keyring.test.json")
  @replay Verification.path("vectors/corpus/replay/window-established.json")
  @pins %{
    commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
    entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  # Two sources for each pinned network, so four identity reads.
  @sources %{
    {"stellar", "testnet"} => {:ok, ["a", "b"], {:at_least, 2}},
    {"bitcoin", "regtest"} => {:ok, ["a", "b"], :first},
    {"nist", nil} => {:ok, ["a"], :first}
  }

  @identities [:stellar_identity, :bitcoin_identity]

  # Long enough for reads made one after another to show, short enough to fail fast.
  @wait 1_000

  defp plain, do: FakeReader.from_replay(@replay, sources: ["a", "b"], source_map: @sources)

  # The reader `plain/0` gives, each identity read first passing through `gate`, a function
  # of its source and network, then answering as `plain/0` answers it.
  defp gated(gate) do
    {FakeReader, state} = plain()

    answers =
      Map.new(state.answers, fn
        {{id, network, kind, params} = key, _answer} when kind in @identities ->
          {key,
           fn ->
             gate.(id, network)
             FakeReader.read(state, id, network, kind, params)
           end}

        other ->
          other
      end)

    {FakeReader, %{state | answers: answers}}
  end

  defp options(reader, extra \\ []),
    do:
      [environment: :test, trust: {:keyring_file, @keyring}, reader: reader, networks: @pins] ++
        extra

  defp rows(report), do: Report.to_map(report)["rows"]

  test "the identity reads run at once, and give the rows of reads one after another" do
    {:ok, sequential} = Verify.verify_file(@item, options(plain()))
    assert sequential.label == :supplied_keyring

    for extra <- [[], [deadline: 30_000]] do
      barrier = start_supervised!({Barrier, 4}, id: make_ref())
      reader = gated(fn _id, _network -> Barrier.arrive(barrier, @wait) end)

      {:ok, concurrent} = Verify.verify_file(@item, options(reader, extra))
      assert rows(concurrent) == rows(sequential), inspect(extra)
      assert concurrent.submitted_before == sequential.submitted_before
    end
  end

  test "each identity read reaches the reader with the caller in its $callers" do
    test = self()

    reader =
      gated(fn id, network ->
        send(test, {:callers, id, network, self(), Process.get(:"$callers")})
      end)

    for extra <- [[], [deadline: 30_000]] do
      {:ok, _report} = Verify.verify_file(@item, options(reader, extra))

      for _read <- 1..4 do
        assert_receive {:callers, _id, _network, pid, callers}
        assert pid != test
        assert test in List.wrap(callers)
      end
    end
  end

  # A reader whose every source on each network gives that chain's production identity,
  # which the testnet and regtest pins both forbid.
  defp both_forbidden do
    FakeReader.from_replay(@replay,
      sources: ["a", "b"],
      source_map: @sources,
      overrides: %{
        {:stellar_identity, %{}} =>
          FakeReader.found(%{
            "network_passphrase" => "Public Global Stellar Network ; September 2015"
          }),
        {:bitcoin_identity, %{}} =>
          FakeReader.found(%{
            "hash" => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
          })
      }
    )
  end

  # Kills the mutant that judges the networks in reverse sorted order, each still with its
  # own answers, under which Stellar testnet decides.
  test "two networks with a forbidden identity: the first in sorted order decides" do
    reader = both_forbidden()

    assert {:configuration_error, :identity_forbidden, %{chain: "bitcoin", network: "regtest"}} =
             Frame.build(Config.external!(options(reader)), nil)

    for extra <- [[], [deadline: 30_000]] do
      assert {:error, rejection} = Verify.verify_file(@item, options(reader, extra))
      assert {rejection.code, rejection.reason} == {:configuration_error, :identity_forbidden}
      assert {rejection.chain, rejection.network} == {"bitcoin", "regtest"}
      assert rejection.message_id == :configuration_identity_forbidden
      assert rejection.assigns == %{chain: "bitcoin", network: "regtest"}
    end
  end

  test "each identity read is held to the run's deadline" do
    barrier = start_supervised!({Barrier, 3}, id: make_ref())
    never = start_supervised!({Barrier, 2}, id: make_ref())

    # Source b on Stellar waits for a read that never comes; the three others meet.
    reader =
      gated(fn
        "b", "testnet" -> Barrier.arrive(never, @wait * 5)
        _id, _network -> Barrier.arrive(barrier, @wait)
      end)

    config = Config.external!(options(reader))
    started = System.monotonic_time(:millisecond)
    {:ok, frame} = Frame.build(config, started + 300)
    assert System.monotonic_time(:millisecond) - started < @wait

    assert [%{id: "a", identity: :ok}, %{id: "b", identity: {:unreachable, :deadline}}] =
             frame[{"stellar", "testnet"}].sources

    assert [%{id: "a", identity: :ok}, %{id: "b", identity: :ok}] =
             frame[{"bitcoin", "regtest"}].sources
  end
end
