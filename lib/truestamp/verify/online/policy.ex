# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Policy do
  @moduledoc """
  How the outcomes of several sources for one network combine into one row.

  Sources are combined per row, not per read: the engine runs a row's whole rule of SPEC.md
  section 10.4 against each source, as if it were the only one, and combines the outcomes.
  Explorers legitimately differ on reads that move, such as a tip one block behind another,
  a different latest ledger, or a shorter history, and none of that is a disagreement about
  the proof.

  An outcome is **conclusive** when it is `pass`, with its candidate, or `fail`; any skip is
  inconclusive (a timeout, a rate limit, an unusable answer, `not_held_by_source`,
  `not_yet_indexed`, `chain_not_final`).

  | Policy | Sources asked | A row passes when |
  |---|---|---|
  | `:first` | in order, until one is conclusive | the first conclusive outcome passes |
  | `{:at_least, n}` | all | at least n pass alike, and none conflicts |
  | `:all` | all | every source passes alike |

  For `{:at_least, n}` and `:all` (n the number of sources), the first of these applies:

  1. one source passes while another fails, or two pass with different candidate instants:
     `skip sources_disagree`;
  2. at least n pass: `pass`, with their common candidate;
  3. at least n fail: `fail`, with their code;
  4. none is conclusive, and every source skipped with the same code: that skip;
  5. otherwise: `skip sources_incomplete`.

  `:first` takes the first conclusive outcome, and when none is conclusive follows rules 4
  and 5 with n = 1. A source that is unreachable is never counted as disagreeing: with
  three sources, two that conflict and one that times out still disagree. Disagreement is
  never a failure, so a faulty or hostile source cannot fail a genuine proof; with `:all`
  it can only keep a row from passing, and the row says why.

  With one source every rule gives that source's outcome, exactly as a single source does.
  """

  alias Truestamp.Verify.Edge
  alias Truestamp.Verify.Online.Rule.Outcome

  @type policy :: :first | {:at_least, pos_integer()} | :all

  @doc """
  The row's outcome for `sources` under `policy`, where `evaluate` gives one source's
  outcome; with the per-source outcomes it used, in order.
  """
  @spec combine(policy(), [term(), ...], (term() -> Outcome.t()), (term() -> String.t())) ::
          {Outcome.t(), [{term(), Outcome.t()}]}
  def combine(policy, sources, evaluate, describe)

  def combine(_policy, [source], evaluate, _describe) do
    outcome = evaluate.(source)
    {outcome, [{source, outcome}]}
  end

  def combine(:first, sources, evaluate, describe) do
    outcomes =
      Enum.reduce_while(sources, [], fn source, acc ->
        outcome = evaluate.(source)
        acc = [{source, outcome} | acc]
        if conclusive?(outcome), do: {:halt, acc}, else: {:cont, acc}
      end)
      |> Enum.reverse()

    combined =
      case Enum.find(outcomes, fn {_source, outcome} -> conclusive?(outcome) end) do
        {_source, outcome} -> outcome
        nil -> inconclusive(outcomes)
      end

    {wrap(combined, :first, outcomes, describe), outcomes}
  end

  def combine(policy, sources, evaluate, describe) do
    outcomes = Enum.map(sources, &{&1, evaluate.(&1)})
    n = needed(policy, length(sources))
    passes = for {source, %Outcome{status: :pass} = outcome} <- outcomes, do: {source, outcome}
    fails = for {_source, %Outcome{status: :fail} = outcome} <- outcomes, do: outcome

    combined =
      cond do
        disagree?(passes, fails) -> %Outcome{status: :skip, code: :sources_disagree, values: %{}}
        length(passes) >= n -> agreed(passes, describe)
        length(fails) >= n -> hd(fails)
        true -> inconclusive(outcomes)
      end

    {wrap(combined, policy, outcomes, describe), outcomes}
  end

  defp needed(:all, count), do: count
  defp needed({:at_least, n}, _count), do: n

  defp conclusive?(%Outcome{status: status}), do: status in [:pass, :fail]

  defp disagree?(passes, fails) do
    instants =
      passes
      |> Enum.map(fn {_source, outcome} ->
        outcome.candidate && Edge.milliseconds(outcome.candidate)
      end)
      |> Enum.uniq()

    (passes != [] and fails != []) or length(instants) > 1
  end

  # Rules 4 and 5: no source reached the outcome the policy needs, and none conflicts.
  defp inconclusive(outcomes) do
    conclusive = Enum.filter(outcomes, fn {_source, outcome} -> conclusive?(outcome) end)
    codes = outcomes |> Enum.map(fn {_source, outcome} -> outcome.code end) |> Enum.uniq()

    case {conclusive, codes} do
      {[], [code]} -> %Outcome{status: :skip, code: code, values: %{}}
      _other -> %Outcome{status: :skip, code: :sources_incomplete, values: %{}}
    end
  end

  # Rule 2: the passes agree on their candidate; the edge records every source it rests on.
  defp agreed([{_source, first} | _rest] = passes, describe) do
    candidate =
      case first.candidate do
        nil ->
          nil

        %Edge{} = edge ->
          candidates = Enum.map(passes, fn {_source, outcome} -> outcome.candidate end)

          %{
            edge
            | source: Enum.map_join(passes, ", ", fn {source, _outcome} -> describe.(source) end),
              cached: Enum.any?(candidates, & &1.cached),
              fetched_at: candidates |> Enum.map(& &1.fetched_at) |> Enum.max(DateTime)
          }
      end

    %Outcome{status: :pass, code: nil, values: %{}, candidate: candidate}
  end

  defp wrap(combined, policy, outcomes, describe) do
    sources =
      for {source, outcome} <- outcomes do
        %{
          "code" => outcome.code && Atom.to_string(outcome.code),
          "source" => describe.(source),
          "status" => Atom.to_string(outcome.status),
          "values" => outcome.values
        }
      end

    values = %{"policy" => name(policy), "sources" => sources}

    values =
      if combined.candidate,
        do: Map.put(values, "candidate", Edge.to_map(combined.candidate)),
        else: values

    # Each source's answers stay with its own outcome, where the engine keeps them by source.
    %{combined | values: values, answers: []}
  end

  @doc "The policy as a row's `values` write it: `first`, `all`, or `at_least:<n>`."
  @spec name(policy()) :: String.t()
  def name(:first), do: "first"
  def name(:all), do: "all"
  def name({:at_least, n}), do: "at_least:#{n}"
end
