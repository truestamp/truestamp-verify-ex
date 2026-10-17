# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Report do
  @moduledoc """
  The report of a run that passed steps 0 to 3 (SPEC.md section 10.5), whatever its label.

  | Field | Holds |
  |---|---|
  | `label` | `:failed`, `:unattributed`, `:supplied_keyring`, `:internally_consistent` or `:verified`; nil only for a run cut short with `:until` |
  | `code` | the run's code, an atom, present exactly when `label` is `:failed` |
  | `attribution` | `"truestamp"`, `"keyring:<d>"`, `"unattributed"` or `"none"` |
  | `environment` | E_v, `:prod`, `:dev`, `:staging` or `:test` |
  | `type`, `subject_id` | the proof's type and its subject's id; nil until SHAPE passes |
  | `rows` | every `Truestamp.Verify.Row`, in step order |
  | `trace` | the trace of section 10.6, `Truestamp.Verify.TraceRow`s in DERIVE's order; empty when the run ended before DERIVE |
  | `trust_root` | `Truestamp.Verify.TrustRoot` |
  | `submitted_after`, `submitted_before` | the two edges, `Truestamp.Verify.Edge`s, or nil; both nil when `label` is `:failed` |
  | `window` | `:established` when `submitted_before` is not nil, else `:not_established` |

  `to_map/1` writes the report with exactly the members of section 10.5, `to_json/1` as JCS,
  and `trace_json/1` writes the trace as `vectors/positive/<name>.trace.json` holds it.
  `reduce/1` gives what conformance compares (section 13.1).

  Every surface draws the edges only from `submitted_after` and `submitted_before`, and
  shows no window for a `failed` run (section 11.5). The item code of section 3.9 is never
  a member or a row of a report.
  """

  alias Truestamp.Verify.{CanonicalForm, Edge, JCS, Row, Run, Spec, TraceRow, TrustRoot}
  alias Truestamp.Verify.Steps.Verdict

  @type label :: Verdict.label()

  @type t :: %__MODULE__{
          label: label() | nil,
          code: atom() | nil,
          attribution: String.t() | nil,
          environment: atom(),
          type: String.t() | nil,
          subject_id: String.t() | nil,
          rows: [Row.t()],
          trace: [TraceRow.t()],
          trust_root: TrustRoot.t(),
          submitted_after: Edge.t() | nil,
          submitted_before: Edge.t() | nil,
          window: :established | :not_established
        }

  @derive {Inspect, except: [:__run__]}
  defstruct [
    :label,
    :code,
    :attribution,
    :environment,
    :type,
    :subject_id,
    :trust_root,
    :submitted_after,
    :submitted_before,
    rows: [],
    trace: [],
    window: :not_established,
    __run__: nil
  ]

  @doc false
  # The report of `run`; it keeps the run for `Truestamp.Verify.apply_expected_hash/2`.
  @spec from_run(Run.t()) :: t()
  def from_run(%Run{} = run) do
    edges =
      if run.label in [:failed, nil],
        do: %{submitted_after: nil, submitted_before: nil},
        else: run.edges

    %__MODULE__{
      label: run.label,
      code: run.code,
      attribution: run.attribution,
      environment: Spec.environment(run.config.environment),
      type: run.type,
      subject_id: run.subject_id,
      rows: run.rows,
      trace: run.trace,
      trust_root: run.trust_root,
      submitted_after: edges.submitted_after,
      submitted_before: edges.submitted_before,
      window: if(edges.submitted_before, do: :established, else: :not_established),
      __run__: run
    }
  end

  @doc "Whether the label is `:verified`."
  @spec verified?(t()) :: boolean()
  def verified?(%__MODULE__{label: label}), do: label == :verified

  @doc "The rows whose status is `:fail`, in order."
  @spec failures(t()) :: [Row.t()]
  def failures(%__MODULE__{rows: rows}), do: Enum.filter(rows, &(&1.status == :fail))

  @doc """
  The report as section 10.5 writes it, as JSON values: `attribution`, `code` (present
  exactly when `label` is `failed`), `environment`, `label`, `rows`, `subject_id`,
  `submitted_after`, `submitted_before`, `trust_root`, `type`, `verified` and `window`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{label: label} = report) when label != nil do
    written = %{
      "attribution" => report.attribution,
      "environment" => Atom.to_string(report.environment),
      "label" => Verdict.label_name(label),
      "rows" => Enum.map(report.rows, &Row.to_map/1),
      "subject_id" => report.subject_id,
      "submitted_after" => edge(report.submitted_after),
      "submitted_before" => edge(report.submitted_before),
      "trust_root" => TrustRoot.to_map(report.trust_root),
      "type" => report.type,
      "verified" => label == :verified,
      "window" => Atom.to_string(report.window)
    }

    if report.code, do: Map.put(written, "code", Atom.to_string(report.code)), else: written
  end

  defp edge(nil), do: nil
  defp edge(%Edge{} = edge), do: Edge.to_map(edge)

  @doc "The report written with JCS, and a final line feed."
  @spec to_json(t()) :: binary()
  def to_json(%__MODULE__{} = report), do: JCS.encode(to_map(report)) <> "\n"

  @doc """
  The trace written in the canonical form of section 9, the form of
  `vectors/positive/<name>.trace.json`: an empty list when the run ended before DERIVE.
  """
  @spec trace_json(t()) :: binary()
  def trace_json(%__MODULE__{trace: trace}),
    do: CanonicalForm.encode(Enum.map(trace, &TraceRow.to_map/1))

  @doc """
  What conformance compares of a report (section 13.1): `label` and every row as
  `[code, part, status, step]`, with the two edges as `{basis, instant}` or nil, and with
  `trace`, its rows without `inputs`, when `trace?`.
  """
  @spec reduce(t(), boolean()) :: map()
  def reduce(%__MODULE__{} = report, trace? \\ false) do
    reduced = %{
      "label" => Verdict.label_name(report.label),
      "rows" => Enum.map(report.rows, &Row.reduce/1),
      "submitted_after" => reduced_edge(report.submitted_after),
      "submitted_before" => reduced_edge(report.submitted_before)
    }

    if trace?,
      do:
        Map.put(
          reduced,
          "trace",
          Enum.map(report.trace, &(&1 |> TraceRow.to_map() |> Map.delete("inputs")))
        ),
      else: reduced
  end

  defp reduced_edge(nil), do: nil

  defp reduced_edge(%Edge{} = edge),
    do: %{"basis" => edge.basis, "instant" => Edge.instant_string(edge)}
end
