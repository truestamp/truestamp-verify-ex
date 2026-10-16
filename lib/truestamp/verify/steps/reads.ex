# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Reads do
  @moduledoc false
  # What CHAIN and SOURCES share (SPEC.md sections 10.2 and 10.4): one row for each entry or
  # object, by the external gate:
  #
  # | Gate | Row |
  # |---|---|
  # | `:prior_failure` | `skip prior_failure` |
  # | `:offline` | `skip offline`, whose message names the read that would confirm it |
  # | `:open` | the rule of section 10.4 against each source of the pinned network, combined by the network's policy (`Truestamp.Verify.Online.Policy`) |
  #
  # A source whose identity read gave no usable answer at step 0 serves no read: its outcome
  # is `skip source_unreachable`, with no read made. Every answer read is kept in the run, so
  # a later row that needs the same read uses it (section 10.4).

  alias Truestamp.Verify.{Row, Run}
  alias Truestamp.Verify.Online.{Policy, Reads, Rule}
  alias Truestamp.Verify.Online.Rule.Outcome

  @doc false
  # The row of `step` at `part` for the rule `rule.(context)`, on the frame entry of
  # `{chain, network}`, with the run's memo of answers updated. `offline` names the read for
  # the `skip offline` message. `side` is the edge a passing row's candidate is for, or nil.
  @spec row(Run.t(), atom(), String.t(), {String.t(), String.t() | nil}, map(), keyword()) ::
          {Row.t(), Run.t()}
  def row(%Run{external_gate: :prior_failure} = run, step, part, _key, _rule, _options),
    do: {Row.new(step, :prior_failure, part, Run.text(run, :prior_failure_external)), run}

  def row(%Run{external_gate: :offline} = run, step, part, _key, _rule, options) do
    message = Run.text(run, :offline, %{read: Keyword.fetch!(options, :offline)})
    {Row.new(step, :offline, part, message), run}
  end

  def row(%Run{external_gate: :open} = run, step, part, key, rule, options) do
    {outcome, per_source} =
      case Map.get(run.frame, key, :none) do
        :none ->
          {%Outcome{status: :skip, code: :source_unreachable, values: %{}}, []}

        %{policy: policy, sources: sources} ->
          Policy.combine(
            policy,
            sources,
            &evaluate(run, &1, key, part, rule, options),
            &describe(&1.id)
          )
      end

    run = remember(run, key, per_source)
    run = candidate(run, outcome, Keyword.get(options, :side))

    message =
      Run.text(run, :read_outcome, %{status: outcome.status, code: outcome.code, step: step})

    {Row.new(step, outcome.code, part, message, outcome.values), run}
  end

  defp evaluate(_run, %{identity: {:unreachable, _reason}}, _key, _part, _rule, _options),
    do: %Outcome{status: :skip, code: :source_unreachable, values: %{"identity" => "unreachable"}}

  defp evaluate(run, %{id: id}, {_chain, network}, part, rule, options) do
    read = Reads.bind(run.config.reader, id, network, run.reads, run.deadline)
    context = Rule.new(read, part: part, top_level?: Keyword.get(options, :top_level?, true))
    rule.(context)
  end

  defp remember(run, {_chain, network}, per_source) do
    reads =
      for {%{id: id}, %Outcome{answers: answers}} <- per_source,
          {kind, params, answer} <- answers,
          into: run.reads,
          do: {{id, network, kind, params}, answer}

    %{run | reads: reads}
  end

  defp candidate(run, %Outcome{status: :pass, candidate: %{} = edge}, side) when side != nil,
    do: %{run | candidates: run.candidates ++ [{side, edge}]}

  defp candidate(run, _outcome, _side), do: run

  defp describe(id) when is_binary(id), do: id
  defp describe(id) when is_atom(id), do: Atom.to_string(id)
  defp describe(id), do: inspect(id)
end
