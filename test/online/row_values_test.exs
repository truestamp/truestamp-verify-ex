# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.RowValuesTest do
  @moduledoc """
  What a row read (SPEC.md section 10.4), over every online case: each outcome's and each
  read's `cached` is a boolean, false under a replay, and its `fetched_at` a time, never
  null, an outcome with no answer behind it included; and each reason a row writes, a
  read's and a source's identity note, is the ASCII128 its replay record gives (section
  13.2), never an Elixir term.

  Then, behind a reader that caches, the read that settles an outcome: its candidate read,
  else the last read made, whatever it answered, else, for a source asked nothing else, its
  identity read; and a read that gave no answer is `cached` false, stamped with the time its
  failure came back, by the verifier's clock.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{Conformance, JSON, Rejection, Report}
  alias Truestamp.Verify.Test.{Cases, FakeReader, Verification}

  @ascii128 ~r/\A[\x20\x21\x23-\x5b\x5d-\x7e]{1,128}\z/

  # The replay's records of `kase`, each answer by its read and its source's name, the one
  # unnamed source of a network written "replay", as a row names it.
  defp records(kase) do
    {:ok, %{"reads" => records}} =
      Cases.vectors() |> Path.join(kase["config"]["online"]) |> File.read!() |> JSON.parse()

    Map.new(records, &{{&1["read"], Map.get(&1, "source", "replay")}, &1["answer"]})
  end

  # Every source outcome of every CHAIN and SOURCES row of the case's report, with its row;
  # none for a bare rejection.
  defp outcomes(kase) do
    case Conformance.run(kase, Cases.vectors()) do
      {:ok, %Report{rows: rows}} ->
        for %{step: step, values: %{"outcomes" => outcomes}} = row <- rows,
            step in [:chain, :sources],
            outcome <- outcomes,
            do: {row, outcome}

      {:error, %Rejection{}} ->
        []
    end
  end

  test "every outcome and every read is cached false, and stamped, never null" do
    tally =
      for kase <- Cases.online(), {_row, outcome} <- outcomes(kase), reduce: %{} do
        tally ->
          assert outcome["cached"] == false, kase["id"]
          assert {:ok, _time, 0} = DateTime.from_iso8601(outcome["fetched_at"]), kase["id"]

          for read <- outcome["reads"] do
            assert read["cached"] == false, kase["id"]
            assert {:ok, _time, 0} = DateTime.from_iso8601(read["fetched_at"]), kase["id"]
          end

          no_answer? = Enum.all?(outcome["reads"], &(&1["answer"]["outcome"] == "unreachable"))
          Map.update(tally, no_answer?, 1, &(&1 + 1))
      end

    # Outcomes with no answer behind them, no read or only unreachable ones, are among them.
    assert tally[true] > 0 and tally[false] > 0
  end

  test "each unreachable read's reason is its replay record's, an ASCII128" do
    reasons =
      for kase <- Cases.online(),
          records = records(kase),
          {_row, outcome} <- outcomes(kase),
          %{"answer" => %{"outcome" => "unreachable", "reason" => reason}, "read" => read} <-
            outcome["reads"] do
        assert %{"outcome" => "unreachable", "reason" => ^reason} =
                 Map.fetch!(records, {read, outcome["source"]}),
               kase["id"]

        assert Regex.match?(@ascii128, reason), kase["id"]
        reason
      end

    assert "HTTP 503" in reasons and "timeout" in reasons
  end

  test "each identity note names the reason of the source's identity read in its replay" do
    notes =
      for kase <- Cases.online(),
          records = records(kase),
          {row, %{"reads" => []} = outcome} <- outcomes(kase),
          %{"identity" => why, "source" => source} <- row.values["notes"] || [],
          source == outcome["source"] do
        # The row's chain, which its part names, and the reasons of that source's
        # unreachable identity reads of it.
        chain = if row.part =~ "stellar", do: "stellar", else: "bitcoin"

        reasons =
          for {{%{"kind" => kind}, ^source}, %{"outcome" => "unreachable", "reason" => reason}} <-
                records,
              kind == chain <> "_identity",
              do: reason

        assert why in reasons, kase["id"]
        assert Regex.match?(@ascii128, why), kase["id"]
        kase["id"]
      end

    assert "reads-identity-stellar-unreachable" in notes
  end

  describe "behind a reader that caches" do
    @item Verification.path("vectors/positive/item.proof.json")
    @keyring Verification.path("vectors/keyring.test.json")
    @replay Verification.path("vectors/corpus/replay/window-established.json")
    @pins %{
      commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
      entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
    }

    # When a cache first read the Stellar transaction.
    @cached_at ~U[2026-10-01 08:00:00Z]

    # The outcome of the Stellar commitment entry's one source, and the bounds of the
    # verifier's clock over the run, over the replay's reads, the answer to each read of a
    # kind `answers` names passed through its function.
    defp stellar_outcome(answers) do
      {module, state} = FakeReader.from_replay(@replay)

      replaced =
        Map.new(state.answers, fn {{_id, _network, kind, _params} = key, answer} ->
          {key, Map.get(answers, kind, & &1).(answer)}
        end)

      reader = {module, %{state | answers: replaced}}
      options = [environment: :test, trust: {:keyring_file, @keyring}, networks: @pins]
      started = DateTime.utc_now()
      {:ok, %Report{rows: rows}} = Verify.verify_file(@item, [reader: reader] ++ options)
      ended = DateTime.utc_now()

      %{values: %{"outcomes" => [outcome]}} =
        Enum.find(rows, &(&1.step == :chain and &1.part == "/commitments/stellar"))

      {outcome, started, ended}
    end

    # The time a `fetched_at` writes, asserted to fall within the run.
    defp clocked(fetched_at, started, ended) do
      {:ok, time, 0} = DateTime.from_iso8601(fetched_at)
      assert DateTime.compare(time, started) != :lt and DateTime.compare(time, ended) != :gt
      time
    end

    test "a cached answer, then a read that gave none: the last read made settles the outcome" do
      {outcome, started, ended} =
        stellar_outcome(%{
          stellar_transaction: fn {:ok, transaction, meta} ->
            {:ok, transaction, %{meta | cached: true, fetched_at: @cached_at}}
          end,
          stellar_ledger: fn _answer -> {:error, {:http_status, 503}} end
        })

      assert %{"status" => "skip", "code" => "source_unreachable"} = outcome

      assert [
               %{"answer" => %{"outcome" => "found"}, "cached" => true} = transaction,
               %{"answer" => %{"outcome" => "unreachable", "reason" => "HTTP 503"}} = ledger
             ] = outcome["reads"]

      assert transaction["fetched_at"] == DateTime.to_iso8601(@cached_at)
      assert ledger["cached"] == false
      clocked(ledger["fetched_at"], started, ended)

      # The ledger read, not the cached transaction read before it, settled the outcome.
      assert outcome["cached"] == false
      assert outcome["fetched_at"] == ledger["fetched_at"]
    end

    test "every read gave no answer: the last read made, not the identity read, settles it" do
      {outcome, started, ended} =
        stellar_outcome(%{stellar_transaction: fn _answer -> {:error, :timeout} end})

      assert %{"status" => "skip", "code" => "source_unreachable", "cached" => false} = outcome
      assert [%{"answer" => %{"outcome" => "unreachable"}} = transaction] = outcome["reads"]
      assert outcome["fetched_at"] == transaction["fetched_at"]
      # The fake reader stamps the identity answer before the run began.
      clocked(outcome["fetched_at"], started, ended)
    end

    test "an identity read that gave no answer settles the outcome of a source asked nothing" do
      {outcome, started, ended} =
        stellar_outcome(%{stellar_identity: fn _answer -> {:error, :timeout} end})

      assert %{"status" => "skip", "code" => "source_unreachable", "reads" => []} = outcome
      assert outcome["cached"] == false
      clocked(outcome["fetched_at"], started, ended)
    end
  end
end
