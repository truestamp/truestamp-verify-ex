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

  `reason` is whatever term the reader or the engine gives; a row's `values` write it as
  `describe/1` does, as an ASCII128 that says why (section 13.2), never as a term.

  `meta` is `%{source: String.t(), fetched_at: DateTime.t(), cached: boolean()}`: where the
  answer came from, when it was read by the verifier's clock, and whether it came from a
  cache (section 10.5). A cached best-chain Bitcoin block at a height also carries
  `tip_height`, the height of the source's tip when the block was read
  (`Truestamp.Verify.Reader`, "Caches"); the engine reads it on no other answer.

  **Fields.** A found answer holds the fields of its kind of read, each in its class
  (section 13.2's table). The rules read each field through `field/3`, which gives
  `{:ok, value}` for a field present in its class, or `:error`. The fields a read uses are
  those its rule reads at that point, not every field of its kind (section 10.4), so an
  answer that holds each of them, in its class, is judged on them, whatever else it lacks
  or gives in another class: the best-chain block at a Bitcoin entry's height is judged
  without its `median_time_past`, and a Stellar ledger read after a transaction not found
  is judged on being found. An answer whose field the rule reads at that point is missing,
  or in another class, is unusable for the check that reads that field
  (`source_unreachable`), but a contradiction in a field that is present still fails the row
  (section 10.4), so a rule reads each field it uses at that point before it decides.

  `:unix_time` is INT for a field that becomes an edge's instant, Bitcoin's
  `median_time_past`: Unix seconds that a TIME can write, so the years 0000 to 9999
  (section 2.4). A later time is in INT but no edge can carry it, so the answer is unusable.
  """

  alias Truestamp.Verify.Instant
  alias Truestamp.Verify.Spec.Constants

  @typedoc """
  Where an answer came from (section 10.5), and for a cached block at a height, the tip it
  was read under.
  """
  @type meta :: %{
          required(:source) => String.t(),
          required(:fetched_at) => DateTime.t(),
          required(:cached) => boolean(),
          optional(:tip_height) => non_neg_integer()
        }

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

  @no_usable_answer "the reader gave no usable answer"

  # The reasons the engine gives, each as a sentence that says why.
  @reasons %{
    deadline: "the run's deadline passed before the answer came",
    malformed_answer: "the answer does not parse, or is not in its form",
    cached_live_read: "a cached answer, to a read made only live",
    cached_not_found: "a cached not-found answer, which only a live read gives",
    cached_not_final: "a cached block at a height, read under a tip that was not final",
    identity_not_found: "the identity read answered not found",
    identity_unusable: "the identity read gave no identity in its form",
    answered_another: "the answer names another object than the one asked for"
  }

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

  @doc """
  Why a read is unreachable, as a row's `values` write it: an ASCII128 that says why
  (sections 2.4 and 10.4), in the form a replay record's `reason` takes (section 13.2), so 1
  to 128 printable ASCII characters with no `"` or `\\`. It is never an Elixir term.

  | Reason | Written |
  |---|---|
  | text, such as a replay record's `reason` | the text, each character ASCII128 does not allow, and each octet that is not UTF-8, as `?`, cut to 128 characters |
  | `{:unreachable, text}` | the text, sanitized as a text reason is |
  | `{:http_status, status}` | `HTTP <status>` |
  | `{:transport, message}` | `transport failure: <message>` |
  | `{:rpc_error, %{"code" => code}}` | `Bitcoin Core RPC error <code>` |
  | `{:cookie, _}` | `the Bitcoin Core cookie file cannot be read` |
  | `{:reader_fault, kind, name}` | `the reader raised <name>`, `the reader threw` or `the reader exited` |
  | `{:not_in_replay, _read}` | `the replay file holds no answer to this read` |
  | `:deadline`, `:malformed_answer`, `:cached_live_read`, `:cached_not_found`, `:cached_not_final`, `:identity_not_found`, `:identity_unusable`, `:answered_another` | a sentence that says what each means |
  | any other atom | its name, as text |
  | anything else | `the reader gave no usable answer` |
  """
  @spec describe(term()) :: String.t()
  def describe({:http_status, status}) when is_integer(status), do: "HTTP #{status}"

  def describe({:transport, message}) when is_binary(message),
    do: text("transport failure: " <> message)

  def describe({:rpc_error, %{"code" => code}}) when is_integer(code),
    do: "Bitcoin Core RPC error #{code}"

  def describe({:cookie, _reason}), do: "the Bitcoin Core cookie file cannot be read"

  def describe({:reader_fault, :error, name}) when is_binary(name),
    do: text("the reader raised " <> name)

  def describe({:reader_fault, :throw, _name}), do: "the reader threw"
  def describe({:reader_fault, :exit, _name}), do: "the reader exited"
  def describe({:not_in_replay, _read}), do: "the replay file holds no answer to this read"
  def describe({:unreachable, reason}) when is_binary(reason), do: text(reason)
  def describe(reason) when is_map_key(@reasons, reason), do: Map.fetch!(@reasons, reason)
  def describe(reason) when is_binary(reason), do: text(reason)
  def describe(reason) when is_atom(reason) and reason != nil, do: text(Atom.to_string(reason))
  def describe(_reason), do: @no_usable_answer

  # Text as an ASCII128: each character it does not allow, and each octet that is not UTF-8,
  # written `?`, cut to 128 characters, and an empty text written as no usable answer.
  defp text(text) do
    case text
         |> String.replace_invalid("?")
         |> String.replace(~r/[^\x20\x21\x23-\x5b\x5d-\x7e]/u, "?")
         |> String.slice(0, 128) do
      "" -> @no_usable_answer
      written -> written
    end
  end
end
