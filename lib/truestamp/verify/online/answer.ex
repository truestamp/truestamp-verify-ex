# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Answer do
  @moduledoc """
  The answer to one read of SPEC.md section 10.4, and the classes of its fields.

  A read has one of three outcomes:

  | Answer | Meaning |
  |---|---|
  | `{:found, fields, meta}` | the source returned the object asked for |
  | `{:not_found, meta}` | the source answered that it holds no such object |
  | `{:unreachable, reason}` | no usable answer: a transport failure, a rate limit, a cooldown, an operator's switch that turned reads off, a deadline, or an answer that does not parse |

  `meta` is `%{source: String.t(), fetched_at: DateTime.t(), cached: boolean()}`: where the
  answer came from, when it was read by the verifier's clock, and whether it came from a
  cache (section 10.5).

  **Fields.** A found answer holds the fields of its kind of read, each in its class
  (section 13.2's table). The rules read each field through `field/3`, which gives
  `{:ok, value}` for a field present in its class, or `:error`. An answer whose field is
  missing, or in another class, is unusable for the check that reads that field
  (`source_unreachable`), but a contradiction in a field that is present still fails the row
  (section 10.4), so a rule reads every field before it decides.

  `:unix_time` is INT for a field that becomes an edge's instant, Bitcoin's
  `median_time_past`: Unix seconds that a TIME can write, so the years 0000 to 9999
  (section 2.4). A later time is in INT but no edge can carry it, so the answer is unusable.
  """

  alias Truestamp.Verify.Instant
  alias Truestamp.Verify.Spec.Constants

  @typedoc "Where an answer came from (section 10.5)."
  @type meta :: %{source: String.t(), fetched_at: DateTime.t(), cached: boolean()}

  @type t ::
          {:found, map(), meta()}
          | {:not_found, meta()}
          | {:unreachable, term()}

  @typedoc "The class of a field (section 2.4)."
  @type class ::
          :int
          | :unix_time
          | :boolean
          | :hex64
          | :nisthex
          | :ascii128
          | :time
          | :nisttime
          | {:enum, [String.t()]}

  @max_integer Constants.max_integer()

  # The last second a TIME can write, 9999-12-31T23:59:59Z.
  @last_time_second 253_402_300_799

  @doc """
  The field `name` of `fields` in `class`: `{:ok, value}` when it is present and in its
  class, else `:error`. A `:time` or `:nisttime` field gives its instant in milliseconds.
  """
  @spec field(map(), String.t(), class()) :: {:ok, term()} | :error
  def field(fields, name, class) when is_map(fields) do
    case Map.fetch(fields, name) do
      {:ok, value} -> in_class(class, value)
      :error -> :error
    end
  end

  defp in_class(:int, value) when is_integer(value) and value in 0..@max_integer, do: {:ok, value}

  defp in_class(:unix_time, value) when is_integer(value) and value in 0..@last_time_second,
    do: {:ok, value}

  defp in_class(:boolean, value) when is_boolean(value), do: {:ok, value}
  defp in_class(:hex64, value), do: pattern(value, ~r/\A[0-9a-f]{64}\z/)
  defp in_class(:nisthex, value), do: pattern(value, ~r/\A[0-9A-F]{128}\z/)
  defp in_class(:ascii128, value), do: pattern(value, ~r/\A[\x20\x21\x23-\x5b\x5d-\x7e]{1,128}\z/)
  defp in_class({:enum, values}, value), do: if(value in values, do: {:ok, value}, else: :error)

  defp in_class(:time, value) do
    case Instant.parse(:time, value) do
      {:ok, seconds} -> {:ok, seconds * 1000}
      {:error, _flaw} -> :error
    end
  end

  defp in_class(:nisttime, value) do
    case Instant.parse(:nisttime, value) do
      {:ok, milliseconds} -> {:ok, milliseconds}
      {:error, _flaw} -> :error
    end
  end

  defp in_class(_class, _value), do: :error

  defp pattern(value, regex) when is_binary(value),
    do: if(Regex.match?(regex, value), do: {:ok, value}, else: :error)

  defp pattern(_value, _regex), do: :error

  @doc "The answer as a row's `values` write it: its outcome, and for a found one its fields."
  @spec to_values(t()) :: map()
  def to_values({:found, fields, meta}),
    do: Map.merge(%{"outcome" => "found", "value" => fields}, meta_values(meta))

  def to_values({:not_found, meta}), do: Map.merge(%{"outcome" => "not_found"}, meta_values(meta))

  def to_values({:unreachable, reason}),
    do: %{"outcome" => "unreachable", "reason" => describe(reason)}

  @doc "`meta` as a row's `values` write it: `cached`, `fetched_at` and `source`."
  @spec meta_values(meta()) :: map()
  def meta_values(%{source: source, fetched_at: fetched_at, cached: cached}) do
    %{
      "cached" => cached,
      "fetched_at" => DateTime.to_iso8601(fetched_at),
      "source" => source
    }
  end

  @doc "A plain description of why a read is unreachable."
  @spec describe(term()) :: String.t()
  def describe(reason) when is_binary(reason), do: reason
  def describe(reason) when is_atom(reason), do: Atom.to_string(reason)
  def describe(reason), do: inspect(reason, limit: 10, printable_limit: 200)
end
