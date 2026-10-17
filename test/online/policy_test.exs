# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.PolicyTest do
  @moduledoc "How several sources' outcomes combine into one row (`Truestamp.Verify.Online.Policy`)."

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Verify.Edge
  alias Truestamp.Verify.Online.Policy
  alias Truestamp.Verify.Online.Rule.Outcome

  defp edge(seconds, source, options \\ []) do
    %Edge{
      instant: DateTime.from_unix!(seconds),
      precision: :second,
      basis: "stellar_ledger_close_read",
      assumption: "a",
      part: "/commitments/stellar",
      source: source,
      cached: Keyword.get(options, :cached, false),
      fetched_at: Keyword.get(options, :fetched_at, ~U[2026-10-16 12:00:00Z])
    }
  end

  defp pass(candidate \\ nil),
    do: %Outcome{status: :pass, code: nil, values: %{"reads" => []}, candidate: candidate}

  defp fail, do: %Outcome{status: :fail, code: :chain_mismatch, values: %{}}
  defp skip(code \\ :source_unreachable), do: %Outcome{status: :skip, code: code, values: %{}}

  # Combines `outcomes`, one per source named "a", "b", ..., under `policy`.
  defp combine(policy, outcomes) do
    sources =
      outcomes |> Enum.with_index() |> Enum.map(fn {outcome, i} -> {<<?a + i>>, outcome} end)

    by_source = Map.new(sources)

    {combined, _used} =
      Policy.combine(policy, Enum.map(sources, &elem(&1, 0)), &Map.fetch!(by_source, &1))

    combined
  end

  defp verdict(%Outcome{status: status, code: code}), do: {status, code}

  test "one source gives that source's outcome, its values untouched" do
    for policy <- [:first, :all, {:at_least, 1}],
        outcome <- [pass(), fail(), skip(:not_yet_indexed)] do
      assert combine(policy, [outcome]) == outcome
    end
  end

  describe ":first" do
    test "takes the first conclusive outcome, and asks no source after it" do
      parent = self()
      outcomes = %{"a" => skip(), "b" => pass(), "c" => fail()}

      {combined, used} =
        Policy.combine(:first, ["a", "b", "c"], fn s ->
          send(parent, {:asked, s}) && outcomes[s]
        end)

      assert verdict(combined) == {:pass, nil}
      assert Enum.map(used, &elem(&1, 0)) == ["a", "b"]
      assert [{"a", %Outcome{status: :skip}}, {"b", %Outcome{status: :pass}}] = used
      refute_received {:asked, "c"}
    end

    test "a candidate rests on the one source whose outcome the row took" do
      combined = combine(:first, [skip(), pass(edge(100, "y"))])
      assert [%{source: "y"}] = Edge.sources(combined.candidate)
    end

    test "fails on a first conclusive failure" do
      assert verdict(combine(:first, [fail(), pass()])) == {:fail, :chain_mismatch}
    end

    test "with no conclusive outcome: their shared skip, or sources_incomplete" do
      assert verdict(combine(:first, [skip(:not_yet_indexed), skip(:not_yet_indexed)])) ==
               {:skip, :not_yet_indexed}

      assert verdict(combine(:first, [skip(:not_yet_indexed), skip()])) ==
               {:skip, :sources_incomplete}
    end
  end

  describe ":all and {:at_least, n}" do
    test "every source passing alike passes, the edge resting on every source" do
      combined =
        combine(:all, [
          pass(edge(100, "x")),
          pass(edge(100, "y", cached: true, fetched_at: ~U[2026-10-16 12:00:05Z]))
        ])

      # Section 11.5: the edge rests on both, and its own source, cached and fetched_at are
      # the first's.
      assert verdict(combined) == {:pass, nil}
      assert combined.candidate.source == "x"
      refute combined.candidate.cached
      assert combined.candidate.fetched_at == ~U[2026-10-16 12:00:00Z]

      assert Edge.sources(combined.candidate) == [
               %{source: "x", cached: false, fetched_at: ~U[2026-10-16 12:00:00Z]},
               %{source: "y", cached: true, fetched_at: ~U[2026-10-16 12:00:05Z]}
             ]

      assert %{"sources" => [%{"source" => "x"}, %{"source" => "y", "cached" => true}]} =
               Edge.to_map(combined.candidate)
    end

    test "passes with no candidate pass with none" do
      assert combine(:all, [pass(), pass()]).candidate == nil
    end

    test "a pass beside a failure, or two different instants, disagree" do
      assert verdict(combine(:all, [pass(), fail()])) == {:skip, :sources_disagree}

      assert verdict(combine(:all, [pass(edge(100, "x")), pass(edge(101, "y"))])) ==
               {:skip, :sources_disagree}
    end

    test "a conflict between two sources that answered disagrees, though a third timed out" do
      assert verdict(combine(:all, [pass(), fail(), skip()])) == {:skip, :sources_disagree}
    end

    test "one source answering while another hangs is incomplete, never a disagreement" do
      assert verdict(combine(:all, [pass(), skip()])) == {:skip, :sources_incomplete}
    end

    test "every source failing alike fails with their code" do
      assert verdict(combine(:all, [fail(), fail()])) == {:fail, :chain_mismatch}
    end

    test "every source skipping alike gives that skip" do
      assert verdict(combine(:all, [skip(:chain_not_final), skip(:chain_not_final)])) ==
               {:skip, :chain_not_final}

      assert verdict(combine(:all, [skip(:chain_not_final), skip()])) ==
               {:skip, :sources_incomplete}
    end

    test "{:at_least, 2} of three tolerates one outage, and no more" do
      assert verdict(combine({:at_least, 2}, [pass(), skip(), pass()])) == {:pass, nil}

      assert verdict(combine({:at_least, 2}, [pass(), skip(), skip()])) ==
               {:skip, :sources_incomplete}

      assert verdict(combine({:at_least, 2}, [fail(), fail(), skip()])) ==
               {:fail, :chain_mismatch}

      assert verdict(combine({:at_least, 2}, [pass(), pass(), skip()])) == {:pass, nil}
    end

    test "names each policy, and its n, as a row's values write them" do
      assert Enum.map([:first, :all, {:at_least, 2}], &Policy.name/1) == ~w(first all at_least)
      assert Enum.map([:first, :all, {:at_least, 2}], &Policy.required(&1, 3)) == [1, 3, 2]
    end
  end

  # Outcomes for properties: a pass at one of a few instants, a failure, or a skip.
  defp outcome_gen do
    StreamData.one_of([
      StreamData.member_of([100, 101]) |> StreamData.map(&pass(edge(&1, "s"))),
      StreamData.constant(fail()),
      StreamData.member_of([:source_unreachable, :not_yet_indexed, :not_held_by_source])
      |> StreamData.map(&skip/1)
    ])
  end

  property "a pass and a failure among the sources always disagree, under :all and :at_least" do
    check all(
            others <- StreamData.list_of(outcome_gen(), max_length: 4),
            n <- StreamData.integer(1..3)
          ) do
      outcomes = [pass(edge(100, "s")), fail() | others]
      assert verdict(combine(:all, outcomes)) == {:skip, :sources_disagree}
      assert verdict(combine({:at_least, n}, outcomes)) == {:skip, :sources_disagree}
    end
  end

  property "a pass needs at least n sources passing alike" do
    check all(
            outcomes <- StreamData.list_of(outcome_gen(), min_length: 1, max_length: 5),
            n <- StreamData.integer(1..5)
          ) do
      if combine({:at_least, n}, outcomes).status == :pass do
        assert Enum.count(outcomes, &(&1.status == :pass)) >= n
      end
    end
  end

  property "adding an inconclusive source never turns a pass into a failure" do
    check all(
            outcomes <- StreamData.list_of(outcome_gen(), min_length: 1, max_length: 4),
            n <- StreamData.integer(1..2)
          ) do
      before = combine({:at_least, n}, outcomes)
      later = combine({:at_least, n}, outcomes ++ [skip()])

      if before.status == :pass do
        assert later.status == :pass
      end
    end
  end
end
