# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Chain do
  @moduledoc """
  Step 10 of SPEC.md section 10.2, CHAIN: the chain reads of section 10.4, then
  KEY_EVENT_COMMITMENT (section 10.3).

  CHAIN gives one row for each commitment entry, at `/commitments/C` and
  `/signing_key_event/commitments/C`, and one for each genesis object a block record
  carries (`metadata.genesis.bitcoin`), each at the pointer of its entry or object, in
  document order. A read that contradicts the proof is `chain_mismatch`, and a read that
  settles nothing is a skip. Each entry is read on the network of the commitment pin for its
  chain, by its chain's rule (`c:Truestamp.Verify.CommitmentChain.commitment/2`), and a
  passing top-level entry gives a candidate for the submitted-before edge (section 11.1).
  When the external gate is closed, every row is `skip prior_failure` or `skip offline`.

  **KEY_EVENT_COMMITMENT**, when P carries `signing_key_event`, is the last row of CHAIN,
  at `/signing_key_event`, out of document order. Its inputs are the CHAIN rows under
  `/signing_key_event/`: the entries of `/signing_key_event/commitments` and, for a genesis
  event, its genesis object. Its status is the first of these that applies:

  1. the external gate is closed: `skip prior_failure` when a row of POLICY or DERIVE failed,
     else `skip offline`;
  2. an input failed: `fail`, with the code of the first failing input in document order;
  3. an input was skipped: `skip`, with the code of the first skipped input in document
     order;
  4. otherwise: `pass` when the attribution is `truestamp`, else `info not_attributable`.

  It states where the signing key came from, never attribution, and never feeds the window.
  """

  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.{Layout, Row, Run}
  alias Truestamp.Verify.Steps.Reads

  @key_event_part "/signing_key_event"

  @doc "Step 10, CHAIN."
  @spec chain(Run.t()) :: Run.t()
  def chain(%Run{proof: proof} = run) do
    {rows, run} =
      proof
      |> reads()
      |> Pointer.sort_by(&elem(&1, 0))
      |> Enum.map_reduce(run, &row(&2, &1))

    run = Run.add_rows(run, rows)

    if is_map(proof["signing_key_event"]),
      do: Run.add_row(run, key_event_commitment(run, rows)),
      else: run
  end

  # Each read CHAIN makes, as {pointer, chain module, :entry | :genesis, value}.
  defp reads(proof) do
    entries =
      for {at, chain, entry} <- Layout.commitment_entries(proof), do: {at, chain, :entry, entry}

    genesis =
      for {at, chain, object} <- Layout.genesis_objects(proof), do: {at, chain, :genesis, object}

    entries ++ genesis
  end

  defp row(run, {at, chain, kind, value}) do
    network = run.config.networks.commitment |> Map.fetch!(chain.name())
    key = {chain.name(), network}
    top_level? = match?(["commitments" | _], at)

    {rule, options} =
      case kind do
        :entry ->
          {&chain.commitment(&1, value),
           offline: {:commitment, chain.name(), top_level?},
           top_level?: top_level?,
           side: if(top_level?, do: :before)}

        :genesis ->
          {&chain.genesis(&1, value), offline: {:genesis, chain.name()}, top_level?: false}
      end

    Reads.row(run, :chain, Pointer.encode(at), key, rule, options)
  end

  defp key_event_commitment(%Run{external_gate: :prior_failure} = run, _rows),
    do:
      Row.new(:chain, :prior_failure, @key_event_part, Run.message(run, :prior_failure_external))

  defp key_event_commitment(%Run{external_gate: :offline} = run, _rows),
    do:
      Row.new(
        :chain,
        :offline,
        @key_event_part,
        Run.message(run, :offline, %{read: :key_event_commitment})
      )

  defp key_event_commitment(%Run{external_gate: :open} = run, rows) do
    inputs = Enum.filter(rows, &String.starts_with?(&1.part, @key_event_part <> "/"))

    case {Enum.find(inputs, &(&1.status == :fail)), Enum.find(inputs, &(&1.status == :skip))} do
      {%Row{} = failed, _skipped} ->
        message =
          Run.message(run, :key_event_commitment_input, %{status: :fail, part: failed.part})

        Row.new(:chain, failed.code, @key_event_part, message, %{"input" => failed.part})

      {nil, %Row{} = skipped} ->
        message =
          Run.message(run, :key_event_commitment_input, %{status: :skip, part: skipped.part})

        Row.new(:chain, skipped.code, @key_event_part, message, %{"input" => skipped.part})

      {nil, nil} when run.attribution == "truestamp" ->
        Row.pass(:chain, @key_event_part, Run.message(run, :key_event_commitment_pass))

      {nil, nil} ->
        Row.new(
          :chain,
          :not_attributable,
          @key_event_part,
          Run.message(run, :key_event_commitment_not_attributable)
        )
    end
  end
end
