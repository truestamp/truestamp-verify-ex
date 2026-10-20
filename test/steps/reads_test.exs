# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.ReadsTest do
  @moduledoc """
  CHAIN's and SOURCES' rows (SPEC.md section 10.4), on runs built here and through
  `Truestamp.Verify.Steps.Reads.row/6` directly: the run keeps no unreachable answer, so a
  later row that needs the same read reads again, while it keeps a found or not-found one;
  and an outcome with no read and no
  identity read, a NIST source's under a rule that reads nothing, is `cached` false and
  stamped by the verifier's clock.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Config, Run, TrustRoot}
  alias Truestamp.Verify.Online.Rule
  alias Truestamp.Verify.Steps.Reads
  alias Truestamp.Verify.Test.FakeReader

  @stellar {"stellar", "testnet"}
  @nist {"nist", nil}
  @params %{"hash" => String.duplicate("ab", 32)}

  # An open run over `reader`, its frame holding one confirmed source, "fake", for `key`;
  # a NIST source has no identity read, so no identity meta.
  defp run(reader, {chain, _network} = key) do
    meta = if chain == "nist", do: nil, else: FakeReader.meta()

    %Run{
      config: Config.external!(environment: :test, trust: :keyless, reader: reader),
      keyring: nil,
      trust_root: %TrustRoot{kind: :none},
      external_gate: :open,
      frame: %{
        key => %{policy: :first, sources: [%{id: "fake", identity: :ok, identity_meta: meta}]}
      }
    }
  end

  # A rule that reads the Stellar transaction of `@params`: it passes on a found answer and
  # settles nothing otherwise.
  defp transaction_rule(context) do
    case Rule.read(context, :stellar_transaction, @params) do
      {{:found, _fields, _meta}, context} -> Rule.pass(context)
      {_answer, context} -> Rule.skip(context, :source_unreachable)
    end
  end

  defp row(run, key, rule), do: Reads.row(run, :chain, "/commitments/stellar", key, rule, [])

  test "an unreachable answer is not kept: a later row reads again, and uses that answer" do
    asked = :counters.new(1, [])

    answer = fn ->
      :counters.add(asked, 1, 1)

      case :counters.get(asked, 1) do
        1 -> {:error, :timeout}
        _later -> FakeReader.found(%{"ledger" => 7})
      end
    end

    reader = FakeReader.new(%{{"fake", "testnet", :stellar_transaction, @params} => answer})
    run = run(reader, @stellar)

    {first, run} = row(run, @stellar, &transaction_rule/1)
    assert {first.status, first.code} == {:skip, :source_unreachable}

    {second, run} = row(run, @stellar, &transaction_rule/1)
    assert :counters.get(asked, 1) == 2
    assert second.status == :pass

    assert [%{"answer" => %{"outcome" => "found"}}] =
             hd(second.values["outcomes"])["reads"]

    # The found answer is kept: a third row uses it, and the reader is not asked again.
    {third, _run} = row(run, @stellar, &transaction_rule/1)
    assert :counters.get(asked, 1) == 2
    assert third.status == :pass
  end

  # Killed by a memo that keeps only found answers (the second row asks again).
  test "a not-found answer is kept: a later row uses it, and the reader is not asked again" do
    asked = :counters.new(1, [])

    answer = fn ->
      :counters.add(asked, 1, 1)
      FakeReader.not_found()
    end

    reader = FakeReader.new(%{{"fake", "testnet", :stellar_transaction, @params} => answer})
    run = run(reader, @stellar)

    {first, run} = row(run, @stellar, &transaction_rule/1)
    {second, _run} = row(run, @stellar, &transaction_rule/1)

    assert :counters.get(asked, 1) == 1
    assert {first.status, second.status} == {:skip, :skip}

    assert [%{"answer" => %{"outcome" => "not_found"}}] =
             hd(second.values["outcomes"])["reads"]
  end

  test "a source with no identity read whose rule reads nothing is cached false, and stamped" do
    started = DateTime.utc_now()

    {row, _run} =
      Reads.row(
        run(FakeReader.new(%{}), @nist),
        :sources,
        "/entropy/nist",
        @nist,
        &Rule.skip(&1, :source_unreachable),
        []
      )

    ended = DateTime.utc_now()

    assert {row.status, row.code} == {:skip, :source_unreachable}

    assert [%{"reads" => [], "cached" => false, "fetched_at" => fetched_at}] =
             row.values["outcomes"]

    {:ok, time, 0} = DateTime.from_iso8601(fetched_at)
    assert DateTime.compare(time, started) != :lt and DateTime.compare(time, ended) != :gt
  end
end
