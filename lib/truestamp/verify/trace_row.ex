# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.TraceRow do
  @moduledoc """
  One row of a run's trace (SPEC.md section 10.6): for each DERIVE row whose part is a
  CHECKED value, other than a row of LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER, the
  value the proof declares beside the value the run recomputed.

  | Field | Holds |
  |---|---|
  | `construction` | the name of the row of the constructions text (section 7.3) that defines the value |
  | `declared` | the value the proof carries |
  | `inputs` | the pointers of the values the check reads, for reading only |
  | `part` | the part of its DERIVE row |
  | `recomputed` | what the check compares `declared` with: for example the record's `leaf_count` for a `tree_size`, 0 for a genesis `height`, nil when a walk gives no root, and for a `handover_signature` the hex of the 32 octets it was verified over |
  | `status` | `:pass` or `:fail`, the status of its DERIVE row |

  `to_map/1` writes it as a trace file does, and `Truestamp.Verify.Report.trace_json/1`
  writes a whole trace in the form of `vectors/positive/<name>.trace.json`.
  """

  @type t :: %__MODULE__{
          construction: String.t(),
          declared: term(),
          inputs: [String.t()],
          part: String.t(),
          recomputed: term(),
          status: :pass | :fail
        }

  @enforce_keys [:construction, :declared, :inputs, :part, :recomputed, :status]
  defstruct [:construction, :declared, :inputs, :part, :recomputed, :status]

  @doc "The trace row as a trace file writes it (section 10.6)."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = row) do
    %{
      "construction" => row.construction,
      "declared" => row.declared,
      "inputs" => row.inputs,
      "part" => row.part,
      "recomputed" => row.recomputed,
      "status" => Atom.to_string(row.status)
    }
  end
end
