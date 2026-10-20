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
  # | `:open` | the rule of section 10.4 against each source of the pinned network, combined |
  #
  # An open gate's sources combine by the network's policy (`Truestamp.Verify.Online.Policy`),
  # and the row's `values` say what it read, from one source or several (section 10.4, what
  # a row read): `policy`, `required`, one object in `outcomes` for each source the row
  # asked, each with every read made of it in the form of a replay record, and the row's
  # `candidate` when it passed with one. Anything else a source's rule noted, such as the
  # fields an answer contradicts, is in `notes`, by source.
  #
  # A source whose identity read gave no usable answer at step 0 serves no read: its outcome
  # is `skip source_unreachable`, with no read made. Every found or not-found answer is kept
  # in the run, so a later row that needs the same read uses it; an unreachable answer is
  # not kept, and a later row reads again (section 10.4, "no cache keeps the answer").

  alias Truestamp.Verify.{Edge, Row, Run}
  alias Truestamp.Verify.Online.{Answer, Policy, Reads, Rule}
  alias Truestamp.Verify.Online.Rule.Outcome

  @doc false
  # The row of `step` at `part` for the rule `rule.(context)`, on the frame entry of
  # `{chain, network}`, with the run's memo of answers updated. `offline` names the read for
  # the `skip offline` message. `side` is the edge a passing row's candidate is for, or nil.
  @spec row(
          Run.t(),
          atom(),
          String.t(),
          {String.t(), String.t() | nil},
          (Rule.context() -> Rule.outcome()),
          keyword()
        ) ::
          {Row.t(), Run.t()}
  def row(%Run{external_gate: :prior_failure} = run, step, part, _key, _rule, _options),
    do: {Row.new(step, :prior_failure, part, Run.message(run, :prior_failure_external)), run}

  def row(%Run{external_gate: :offline} = run, step, part, _key, _rule, options) do
    message = Run.message(run, :offline, %{read: Keyword.fetch!(options, :offline)})
    {Row.new(step, :offline, part, message), run}
  end

  def row(%Run{external_gate: :open} = run, step, part, key, rule, options) do
    {policy, sources} =
      case Map.get(run.frame, key, :none) do
        :none -> {:first, []}
        %{policy: policy, sources: sources} -> {policy, sources}
      end

    {outcome, per_source} =
      case sources do
        [] ->
          {%Outcome{status: :skip, code: :source_unreachable, values: %{}}, []}

        _sources ->
          Policy.combine(policy, sources, &evaluate(run, &1, key, part, rule, options))
      end

    run = remember(run, key, per_source)
    run = candidate(run, outcome, Keyword.get(options, :side))

    message =
      Run.message(run, :read_outcome, %{status: outcome.status, code: outcome.code, step: step})

    values = values(policy, max(length(sources), 1), per_source, outcome, key)
    {Row.new(step, outcome.code, part, message, values), run}
  end

  defp evaluate(_run, %{identity: {:unreachable, reason}}, _key, _part, _rule, _options),
    do: Rule.unconfirmed(reason)

  defp evaluate(run, %{id: id}, {_chain, network}, part, rule, options) do
    read = Reads.bind(run.config.reader, id, network, run.reads, run.deadline)
    context = Rule.new(read, part: part, top_level?: Keyword.get(options, :top_level?, true))
    rule.(context)
  end

  defp remember(run, {_chain, network}, per_source) do
    reads =
      for {%{id: id}, %Outcome{answers: answers}} <- per_source,
          {kind, params, answer, _answered_at} <- answers,
          not match?({:unreachable, _reason}, answer),
          into: run.reads,
          do: {{id, network, kind, params}, answer}

    %{run | reads: reads}
  end

  defp candidate(run, %Outcome{status: :pass, candidate: %{} = edge}, side) when side != nil,
    do: %{run | candidates: run.candidates ++ [{side, edge}]}

  defp candidate(run, _outcome, _side), do: run

  # ---------------------------------------------------------------------------------------
  # What the row read (section 10.4)

  defp values(policy, count, per_source, outcome, {_chain, network}) do
    values = %{
      "policy" => Policy.name(policy),
      "required" => Policy.required(policy, count),
      "outcomes" => for({source, result} <- per_source, do: outcome(source, result, network))
    }

    notes =
      for {source, %Outcome{values: noted}} <- per_source,
          noted = Map.drop(noted, ["reads", "candidate"]),
          noted != %{},
          do: Map.put(noted, "source", describe(source.id))

    values
    |> put(outcome.candidate, "candidate", &candidate_value/1)
    |> put(notes != [] && notes, "notes", & &1)
  end

  defp outcome(source, %Outcome{} = result, network) do
    reads =
      for {kind, params, answer, answered_at} <- result.answers,
          do: read(kind, params, answer, answered_at, network)

    {cached, fetched_at} = settled(source, result, reads)

    %{
      "cached" => cached,
      "fetched_at" => fetched_at,
      "reads" => reads,
      "source" => describe(source.id),
      "status" => Atom.to_string(result.status)
    }
    |> put(result.code, "code", &Atom.to_string/1)
    |> put(result.candidate, "candidate", &candidate_value/1)
  end

  # One read of a source, its `read` and `answer` in the form of a replay record (section
  # 13.2), with the `cached` and `fetched_at` of its answer. An unreachable read gave no
  # answer, so none came from a cache: its `cached` is false, and its `fetched_at` is when
  # its failure came back, by the verifier's clock (section 10.4, what a row read).
  defp read(kind, params, answer, answered_at, network) do
    read = Map.put(params, "kind", Atom.to_string(kind))
    read = if network, do: Map.put(read, "network", network), else: read
    values = Answer.to_values(answer)

    %{
      "answer" => Map.take(values, ["outcome", "reason", "value"]),
      "cached" => Map.get(values, "cached", false),
      "fetched_at" => values["fetched_at"] || DateTime.to_iso8601(answered_at),
      "read" => read
    }
  end

  # The `cached` and `fetched_at` of the read that settled a source's outcome: its candidate
  # read, else the last read made, whatever it answered, since a rule reads nothing after
  # its outcome is settled, else, for a source asked nothing else, its identity read. An
  # outcome that ends unreachable is settled by a read that gave no answer: `cached` false,
  # and the time its failure came back. A source with no identity read, NIST's, whose rule
  # read nothing, gave no answer either: `cached` false, and the time of the row, by the
  # verifier's clock.
  defp settled(_source, %Outcome{candidate: %{} = edge}, _reads),
    do: {edge.cached, DateTime.to_iso8601(edge.fetched_at)}

  defp settled(%{identity_meta: %{cached: cached, fetched_at: fetched_at}}, _result, []),
    do: {cached, DateTime.to_iso8601(fetched_at)}

  defp settled(_source, _result, []), do: {false, DateTime.to_iso8601(DateTime.utc_now())}

  defp settled(_source, _result, reads),
    do: {List.last(reads)["cached"], List.last(reads)["fetched_at"]}

  defp candidate_value(edge), do: %{"basis" => edge.basis, "instant" => Edge.instant_string(edge)}

  defp put(map, nil, _name, _fun), do: map
  defp put(map, false, _name, _fun), do: map
  defp put(map, value, name, fun), do: Map.put(map, name, fun.(value))

  defp describe(id) when is_binary(id), do: id
  defp describe(id) when is_atom(id), do: Atom.to_string(id)
  defp describe(id), do: inspect(id)
end
