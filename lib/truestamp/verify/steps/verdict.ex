# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Verdict do
  @moduledoc """
  Step 14 of SPEC.md section 10.2, VERDICT: the label, the run's code and the two edges of
  section 10.5. It reports no row.

  The label is the first of these that applies:

  | Label | When |
  |---|---|
  | `:failed` | any row is `fail` |
  | `:unattributed` | the attribution is `unattributed` |
  | `:supplied_keyring` | the attribution is `keyring:<d>` |
  | `:internally_consistent` | the attribution is `truestamp`, and the submitted-before edge is not established |
  | `:verified` | the attribution is `truestamp`, and the submitted-before edge is established |

  The run's code is present exactly when the label is `failed`: the code of the first
  failing row, which, since rows are in step order, is the code of the first failing step's
  first failing row (section 10.2). When the label is `failed`, both edges are nil, so the
  window is not established.

  Truestamp's own verifier gives only `failed`, `internally_consistent` and `verified`
  (section 8.2): its attribution is always `truestamp` or, after a failure at the gate,
  `none`.
  """

  alias Truestamp.Verify.Run

  @labels [:failed, :unattributed, :supplied_keyring, :internally_consistent, :verified]

  @typedoc "A label of section 10.5."
  @type label :: :failed | :unattributed | :supplied_keyring | :internally_consistent | :verified

  @doc "The labels, in the order the first that applies is taken."
  @spec labels() :: [label()]
  def labels, do: @labels

  @doc "The spec's spelling of `label`, such as `\"internally-consistent\"`."
  @spec label_name(label()) :: String.t()
  def label_name(label) when label in @labels,
    do: label |> Atom.to_string() |> String.replace("_", "-")

  @doc "Step 14, VERDICT: the run with its label, its code and its edges set."
  @spec verdict(Run.t()) :: Run.t()
  def verdict(%Run{} = run) do
    case Enum.find(run.rows, &(&1.status == :fail)) do
      # The report gives no edge for a failed run (`Truestamp.Verify.Report`); the run keeps
      # the edges WINDOW drew, so `Truestamp.Verify.apply_expected_hash/2` can give the
      # report a fresh run would.
      %{code: code} ->
        %{run | label: :failed, code: code}

      nil ->
        %{run | label: label(run.attribution, run.edges.submitted_before), code: nil}
    end
  end

  defp label("unattributed", _before), do: :unattributed
  defp label("keyring:" <> _digest, _before), do: :supplied_keyring
  defp label("truestamp", nil), do: :internally_consistent
  defp label("truestamp", _before), do: :verified
end
