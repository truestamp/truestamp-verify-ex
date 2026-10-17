# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Policy do
  @moduledoc """
  Step 8 of SPEC.md section 10.2, POLICY, offline, in every run that reaches it. Each
  `network` member of P must equal the verifier's pin, else `network_mismatch` at that
  `network`:

  | `network` of | Pin |
  |---|---|
  | each commitment entry, at `/commitments` and `/signing_key_event/commitments` | the commitment pin for its chain |
  | each entropy object of a source that has a network | the entropy pin for its source |
  | each genesis object, at any block position (`metadata.genesis.bitcoin`) | the commitment pin for its chain |

  The pins are the run's (`Truestamp.Verify.Config`, section 9). No pin comes from the
  document, and a network the proof lacks is never supplied: SHAPE has held every position
  above to carry one.

  Each comparison reports one row, in the document order of its part. Its `values` hold the
  chain its position names, the pin and the pin's kind, and on a failure the proof's network
  under `"declared"`. A failure here does not end the run: DERIVE still runs, and the
  external gate stays closed.
  """

  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.{Layout, Row, Run}

  @doc "Step 8, POLICY: one row for each `network` of P, against the run's pins."
  @spec policy(Run.t()) :: Run.t()
  def policy(%Run{proof: proof, config: %{networks: pins}} = run) do
    rows =
      proof
      |> comparisons()
      |> Pointer.sort_by(&elem(&1, 0))
      |> Enum.map(&row(run, &1, pins))

    Run.add_rows(run, rows)
  end

  # {pointer of the network, :commitment or :entropy, chain name, the network}.
  defp comparisons(proof) do
    commitments =
      for {at, chain, entry} <- Layout.commitment_entries(proof),
          do: {at ++ ["network"], :commitment, chain.name(), Map.fetch!(entry, "network")}

    entropy =
      for {at, source, object} <- Layout.entropy_objects(proof),
          source.networked?(),
          do: {at ++ ["network"], :entropy, source.name(), Map.fetch!(object, "network")}

    genesis =
      for {at, chain, object} <- Layout.genesis_objects(proof),
          do: {at ++ ["network"], :commitment, chain.name(), Map.fetch!(object, "network")}

    commitments ++ entropy ++ genesis
  end

  defp row(run, {at, kind, chain, network}, pins) do
    pin = pins |> Map.fetch!(kind) |> Map.fetch!(chain)
    part = Pointer.encode(at)
    values = %{"chain" => chain, "pin" => pin, "pin_kind" => Atom.to_string(kind)}
    assigns = %{chain: chain, pin: pin, kind: kind}

    if network === pin,
      do: Row.pass(:policy, part, Run.text(run, :policy_pass, assigns), values),
      else:
        Row.new(
          :policy,
          :network_mismatch,
          part,
          Run.text(run, :network_mismatch, assigns),
          Map.put(values, "declared", network)
        )
  end
end
