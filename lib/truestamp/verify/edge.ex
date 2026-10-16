# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Edge do
  @moduledoc """
  An edge of the submission window (SPEC.md section 11), or a candidate for one: an instant
  read from a public chain or entropy source in this run, never a time the proof carries.

  | Field | Holds |
  |---|---|
  | `instant` | the instant, as a `DateTime` in UTC, at its source's precision |
  | `precision` | `:second` for Stellar and Bitcoin, `:millisecond` for NIST |
  | `basis` | `"stellar_ledger_close_read"`, `"bitcoin_median_time_read"` or `"nist_pulse_time_read"` |
  | `assumption` | the stated assumption of its basis (sections 11.1 and 11.2) |
  | `part` | the part of the CHAIN or SOURCES row whose read gave it |
  | `source` | the source of that read |
  | `cached` | whether that read's answer came from a cache |
  | `fetched_at` | when that read was made, by the verifier's clock |

  A run's `submitted_before` edge is the earliest candidate of the top-level commitment
  entries, and its `submitted_after` edge the latest candidate of its entropy objects; of
  two at the same instant, the first in row order (section 11). Instants compare exactly,
  at the precision each source gives (section 11.3). `to_map/1` writes an edge as a report
  does (section 11.5).
  """

  @type t :: %__MODULE__{
          instant: DateTime.t(),
          precision: :second | :millisecond,
          basis: String.t(),
          assumption: String.t(),
          part: String.t(),
          source: String.t(),
          cached: boolean(),
          fetched_at: DateTime.t()
        }

  @enforce_keys [:instant, :precision, :basis, :assumption, :part, :source, :cached, :fetched_at]
  defstruct [:instant, :precision, :basis, :assumption, :part, :source, :cached, :fetched_at]

  # SPEC.md 11.1 and 11.2: each basis and its stated assumption. Stellar's differs by edge.
  @assumptions %{
    {"stellar_ledger_close_read", :before} =>
      "Stellar validators did not set the ledger's close time behind real time; a close " <>
        "time set ahead of real time only makes this edge later",
    {"stellar_ledger_close_read", :after} =>
      "the network did not set the close time ahead of real time",
    {"bitcoin_median_time_read", :before} =>
      "at least 6 of blocks height + 1 to height + 10 carry honest times",
    {"bitcoin_median_time_read", :after} =>
      "at least 6 of the 11 header times ending at that block are honest",
    {"nist_pulse_time_read", :after} => "NIST does not release outputValue before timeStamp"
  }

  @doc """
  The stated assumption of `basis` for the edge `side`, `:before` or `:after`
  (sections 11.1 and 11.2).
  """
  @spec assumption(String.t(), :before | :after) :: String.t()
  def assumption(basis, side), do: Map.fetch!(@assumptions, {basis, side})

  @doc "The instant in Unix milliseconds, for exact comparison."
  @spec milliseconds(t()) :: integer()
  def milliseconds(%__MODULE__{instant: instant}), do: DateTime.to_unix(instant, :millisecond)

  @doc """
  The instant written as a report writes it (section 11.5): a TIME for Stellar and Bitcoin,
  a NISTTIME for NIST.
  """
  @spec instant_string(t()) :: String.t()
  def instant_string(%__MODULE__{instant: instant, precision: :second}),
    do: instant |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  def instant_string(%__MODULE__{instant: instant, precision: :millisecond}),
    do: instant |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()

  @doc """
  The edge as a report writes it (section 11.5):
  `{assumption, basis, cached, fetched_at, instant, part, source}`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = edge) do
    %{
      "assumption" => edge.assumption,
      "basis" => edge.basis,
      "cached" => edge.cached,
      "fetched_at" => DateTime.to_iso8601(edge.fetched_at),
      "instant" => instant_string(edge),
      "part" => edge.part,
      "source" => edge.source
    }
  end
end
