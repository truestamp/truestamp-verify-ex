# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Run do
  @moduledoc false
  # The state of a run (SPEC.md section 10.2): the rows so far and what the later steps
  # read. CONFIGURATION creates it from a `Truestamp.Verify.Config`; each later step takes it
  # and gives it back with its rows added; VERDICT sets its label. It is internal: a caller
  # sees a `Truestamp.Verify.Report`.
  #
  # | Field | Holds | Set at |
  # |---|---|---|
  # | `config` | the run's configuration | CONFIGURATION |
  # | `keyring` | the keyring that governs: a `Keyring`, `:unavailable`, or nil in keyless mode | CONFIGURATION |
  # | `trust_root` | `%TrustRoot{}` of section 10.5 | CONFIGURATION |
  # | `frame` | the sources of an online run, each with its identity's outcome | CONFIGURATION |
  # | `reads` | the answers read so far, one per read (section 10.4) | CHAIN, SOURCES |
  # | `deadline` | the monotonic millisecond the online run must end by, or nil | CONFIGURATION |
  # | `document`, `proof` | the parsed document and P | PARSE, ENVELOPE |
  # | `public_key`, `signature` | the 32 octets of K and the 64 of V | ENVELOPE |
  # | `bound_key` | the key K bound to, or nil | KEY_BINDING |
  # | `proof_hash` | the 32 octets of SHA-256(0x50 \|\| JCS(P)) | SIGNATURE |
  # | `attribution` | nil until the gate is decided, then as section 10.5 says | SIGNATURE, or the step that ends the run |
  # | `type`, `subject_id` | the proof's type and its subject's id, nil until SHAPE passes | SHAPE |
  # | `trace` | the trace of section 10.6 | DERIVE |
  # | `external_gate` | `:open`, `:offline` or `:prior_failure`, decided once when DERIVE ends | DERIVE |
  # | `candidates` | `{:before | :after, edge}` for each passing row that gave one, in row order | CHAIN, SOURCES |
  # | `edges` | `%{submitted_after, submitted_before}` as WINDOW drew them | WINDOW |
  # | `rows` | the rows so far, in step order | every step |
  # | `ended` | whether a failure ended the run | a failure at steps 4 to 7, or a caught fault |
  # | `label`, `code` | the label and the run's code | VERDICT |

  alias Truestamp.Verify.{Config, Keyring, Messages, Row, Step, TrustRoot}

  @enforce_keys [:config, :keyring, :trust_root]
  defstruct [
    :config,
    :keyring,
    :trust_root,
    frame: %{},
    reads: %{},
    deadline: nil,
    document: nil,
    proof: nil,
    public_key: nil,
    signature: nil,
    bound_key: nil,
    proof_hash: nil,
    attribution: nil,
    type: nil,
    subject_id: nil,
    trace: [],
    external_gate: nil,
    candidates: [],
    edges: %{submitted_after: nil, submitted_before: nil},
    rows: [],
    ended: false,
    label: nil,
    code: nil
  ]

  @type t :: %__MODULE__{
          config: Config.t(),
          keyring: Keyring.t() | :unavailable | nil,
          trust_root: TrustRoot.t(),
          rows: [Row.t()],
          ended: boolean()
        }

  @doc false
  def add_row(%__MODULE__{rows: rows} = run, %Row{} = row), do: %{run | rows: rows ++ [row]}

  @doc false
  def add_rows(%__MODULE__{rows: rows} = run, new), do: %{run | rows: rows ++ new}

  @doc false
  def failed?(%__MODULE__{rows: rows}), do: Enum.any?(rows, &(&1.status == :fail))

  @doc false
  # The text of message `id` with `assigns`, from the run's message module.
  def text(%__MODULE__{config: %Config{messages: messages}}, id, assigns \\ %{}),
    do: Messages.render(messages, id, assigns)

  @doc false
  # Ends the run after a failure at steps 4 to 7, or a fault caught at steps 4 to 13: one
  # row `skip prior_failure`, part null, for each step after the last row's up to
  # EXPECTED_HASH (sections 10.2 and 10.5).
  def end_run(%__MODULE__{rows: rows} = run) do
    message = text(run, :prior_failure_gate)

    skips =
      for step <- Step.rows_after(List.last(rows).step),
          do: Row.new(step, :prior_failure, nil, message)

    %{run | rows: rows ++ skips, ended: true}
  end
end
