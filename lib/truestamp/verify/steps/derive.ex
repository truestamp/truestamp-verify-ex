# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Derive do
  @moduledoc """
  Step 9 of SPEC.md section 10.2, DERIVE, offline, in every run that reaches it, and the one
  engine of section 10.6 that every DERIVE check goes through.

  DERIVE recomputes each value that the constructions text (section 7.3) defines from the
  preimage P carries, compares it with the value P carries for it, and checks every link
  (section 10.3). It makes every check and does not stop at a failure. Its checks are, in
  this order:

  | Part of step 9 | Module |
  |---|---|
  | (a) subject hashes, (b) block nodes, (c) epochs | `Truestamp.Verify.Steps.Derive.Records` |
  | (b) each key event a block node carries (section 10.3) | `Truestamp.Verify.Steps.Derive.KeyEvents`, through `Records` |
  | (d) the evidence each commitment entry carries | its chain's `c:Truestamp.Verify.CommitmentChain.evidence_checks/2` (Bitcoin's) |
  | (e) LINK_INCLUSION, LINK_WITNESS, LINK_HEAD, LINK_KEY_EVENT, LINK_CHAIN_ORDER | `Truestamp.Verify.Steps.Derive.Links` |

  **The engine** (`engine/2`) gives the rows, one for each check, in the document order of
  their parts (a stable sort, so rows sharing a part keep the order of their checks), and
  the trace: one trace row for each traced check, in the same order (section 10.6).

  **The external gate** (section 10.2) is decided once, when DERIVE ends: it is open when
  the run has a reader and no row so far is `fail`. Otherwise it is closed, `:prior_failure`
  when a row so far fails, else `:offline`, and CHAIN and SOURCES give each of their rows
  that `skip`. Only the caller opens it; nothing in the document can.

  DERIVE reads P, K (for LINK_KEY_EVENT) and the run's attribution (for the key-history
  row), and nothing else of the run: not `constructions`, which only SHAPE reads.
  """

  alias Truestamp.Verify.{Check, Config, Layout, Messages, Row, Run, TraceRow}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Steps.Derive.{Links, Records}

  @doc "Step 9, DERIVE: every recomputation and every link, with the run's trace."
  @spec derive(Run.t()) :: Run.t()
  def derive(%Run{proof: proof, public_key: public_key, attribution: attribution} = run) do
    {rows, trace} = proof |> checks(public_key, attribution) |> engine(run.config.messages)
    run = %{Run.add_rows(run, rows) | trace: trace}
    %{run | external_gate: gate(run)}
  end

  defp gate(run) do
    cond do
      Run.failed?(run) -> :prior_failure
      Config.online?(run.config) -> :open
      true -> :offline
    end
  end

  @doc """
  Every check of DERIVE for P, in the order of step 9's parts (a) to (e) and of each table's
  rows, before the engine orders them. `public_key` is the 32 octets of K, and `attribution`
  the run's (section 10.5).
  """
  @spec checks(map(), <<_::256>>, String.t()) :: [Check.t()]
  def checks(proof, public_key, attribution) do
    evidence =
      for {at, chain, entry} <- Layout.commitment_entries(proof),
          check <- chain.evidence_checks(at, entry),
          do: check

    Records.checks(proof) ++ evidence ++ Links.checks(proof, public_key, attribution)
  end

  @doc """
  The one engine: the rows and the trace of `checks`, each in DERIVE's order, the rows'
  messages written by `messages`.
  """
  @spec engine([Check.t()], module()) :: {[Row.t()], [TraceRow.t()]}
  def engine(checks, messages \\ Messages.English) do
    ordered = Pointer.sort_by(checks, & &1.part)
    rows = Enum.map(ordered, &Check.row(&1, messages))
    trace = for %Check{traced: true} = check <- ordered, do: Check.trace_row(check)
    {rows, trace}
  end
end
