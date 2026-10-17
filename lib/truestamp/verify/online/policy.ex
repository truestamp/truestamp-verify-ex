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
  never a failure. So under `:all`, a faulty or hostile source beside honest ones can only
  keep a row from passing, and the row says why; under `{:at_least, n}`, it takes n sources
  failing alike to fail a row; and under `:first`, the first source to give a conclusive
  outcome decides the row alone, so put the source you trust most first.

  With one source every rule gives that source's outcome, exactly as a single source does.
  """

  alias Truestamp.Verify.Edge
  alias Truestamp.Verify.Online.Rule.Outcome

  @type policy :: :first | {:at_least, pos_integer()} | :all

  @doc """
  The row's outcome for `sources` under `policy`, where `evaluate` gives one source's
  outcome; with the outcomes of the sources it asked, in order. Under `:first`, a source
  after the one whose outcome the row took is not asked (section 10.4).

  A passing row's candidate is the one its counted sources share, and it rests on each of
  them: its `sources` names every source that passed under `{:at_least, n}` or `:all`, and
  the one source the row took under `:first` (section 11.5). The row's `values` are the
  caller's to write.
  """
  @spec combine(policy(), [term(), ...], (term() -> Outcome.t())) ::
          {Outcome.t(), [{term(), Outcome.t()}]}
  def combine(policy, sources, evaluate)

  # One source, under a policy one source can satisfy: exactly that source's outcome, as with
  # a single source and no policy at all. `{:at_least, n}` with fewer than n sources can
  # never pass, and falls to the rules below.
  def combine(policy, [source], evaluate) when policy in [:first, :all, {:at_least, 1}] do
    outcome = evaluate.(source)
    {outcome, [{source, outcome}]}
  end

  def combine(:first, sources, evaluate) do
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

    {combined, outcomes}
  end

  def combine(policy, sources, evaluate) do
    outcomes = Enum.map(sources, &{&1, evaluate.(&1)})
    n = required(policy, length(sources))
    passes = for {_source, %Outcome{status: :pass} = outcome} <- outcomes, do: outcome
    fails = for {_source, %Outcome{status: :fail} = outcome} <- outcomes, do: outcome

    combined =
      cond do
        disagree?(passes, fails) -> %Outcome{status: :skip, code: :sources_disagree, values: %{}}
        length(passes) >= n -> agreed(passes)
        length(fails) >= n -> hd(fails)
        true -> inconclusive(outcomes)
      end

    {combined, outcomes}
  end

  @doc """
  The n of `policy` for a network of `count` sources, the number of conclusive outcomes it
  asks for: 1 under `:first`, and `count` under `:all`.
  """
  @spec required(policy(), pos_integer()) :: non_neg_integer()
  def required(:first, _count), do: 1
  def required(:all, count), do: count
  def required({:at_least, n}, _count), do: n

  @doc "The policy as a row's `values` name it: `first`, `at_least` or `all`."
  @spec name(policy()) :: String.t()
  def name(:first), do: "first"
  def name(:all), do: "all"
  def name({:at_least, _n}), do: "at_least"

  defp conclusive?(%Outcome{status: status}), do: status in [:pass, :fail]

  defp disagree?(passes, fails) do
    instants =
      passes
      |> Enum.map(&(&1.candidate && Edge.milliseconds(&1.candidate)))
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

  # Rule 2: the passes agree on their candidate, which rests on every one of them, the first
  # giving the edge's own source, cached and fetched_at (section 11.5).
  defp agreed([first | _rest] = passes) do
    candidate =
      first.candidate &&
        %{first.candidate | sources: Enum.flat_map(passes, &Edge.sources(&1.candidate))}

    %Outcome{status: :pass, code: nil, values: %{}, candidate: candidate}
  end
end
