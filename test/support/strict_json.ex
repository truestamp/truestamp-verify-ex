# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.StrictJSON do
  @moduledoc """
  Reads a JSON text under the parsing rules J1 to J6 of SPEC.md section 10.1, for the tests
  of the files under `spec/` and `vectors/`, and prints a value in the canonical forms those
  files use.

  OTP's `JSON` does the syntax, and hands each number's text to the decoders here. They
  convert it with the verifier's own `Truestamp.Verify.JSON.Binary64.nearest/1`, never with
  `Float.parse/1` or `:erlang.binary_to_float/1`: those reach the C library's `strtod`, which
  on macOS 27 aborts the runtime on some long spellings, and `vectors/` holds spellings of
  more than 600 digits. Everything else here is this module's own, so the tests still
  compare two readers of the syntax, J4 and J6, while both read a number's value alike.

  One sign is lost on the way: OTP's tokenizer hands `-0e5` to the float decoder as
  `0.0e5`, so a zero written as `-0` followed directly by an exponent reads as `0.0` here,
  not `-0.0`. JCS writes both as `0`, and the verifier's `Parser` reads `-0` as the integer
  0, so no test that compares through either sees it.
  """

  alias Truestamp.Verify.JSON.Binary64

  @max_read_octets 262_144
  @max_depth 32
  @max_safe_integer 9_007_199_254_740_991
  @float_integer_limit 1.0e21

  # A number decoder cannot throw out of :json, which reports a throw as a syntax error, so it
  # returns this marker and the decoded value is searched for it.
  @bad_number :__strict_json_bad_number__

  @doc "Decodes `bytes`, returning `{:ok, value}` or `{:error, reason}`."
  @spec decode(binary()) :: {:ok, term()} | {:error, atom()}
  def decode(bytes) when byte_size(bytes) > @max_read_octets, do: {:error, :input_too_large}
  def decode(bytes), do: decode_data(bytes)

  @doc """
  Decodes `bytes` under J2 to J6 alone, for a data file such as `vectors/cases.json`, which
  is larger than MAX_READ_OCTETS: J1 binds a document, not such a file.
  """
  @spec decode_data(binary()) :: {:ok, term()} | {:error, atom()}
  def decode_data(bytes) do
    if String.valid?(bytes), do: decode_valid(bytes), else: {:error, :invalid_utf8}
  end

  @doc "The value of the JSON data file at `path`, read with `decode_data/1`. Raises on a refusal."
  @spec read_data!(Path.t()) :: term()
  def read_data!(path) do
    case path |> File.read!() |> decode_data() do
      {:ok, value} -> value
      {:error, reason} -> raise ArgumentError, "#{path}: #{inspect(reason)}"
    end
  end

  defp decode_valid(bytes) do
    decoders = [object_push: &push/3, integer: &integer/1, float: &float/1]

    case JSON.decode(bytes, [], decoders) do
      {value, [], rest} -> one_text(value, rest)
      {:error, _reason} -> {:error, :syntax}
    end
  catch
    {:strict, reason} -> {:error, reason}
  end

  defp one_text(value, rest) do
    cond do
      String.trim(rest, " \t\r\n") != "" -> {:error, :syntax}
      bad_number?(value) -> {:error, :number}
      depth(value) > @max_depth -> {:error, :depth}
      true -> {:ok, value}
    end
  end

  defp bad_number?(@bad_number), do: true

  defp bad_number?(value) when is_map(value),
    do: value |> Map.values() |> Enum.any?(&bad_number?/1)

  defp bad_number?(value) when is_list(value), do: Enum.any?(value, &bad_number?/1)
  defp bad_number?(_value), do: false

  defp push(key, value, acc) do
    if List.keymember?(acc, key, 0), do: throw({:strict, :duplicate_name})
    [{key, value} | acc]
  end

  # An integer outside the safe range is judged, like any number, by its binary64 value. One
  # of more than 17 characters is outside it, and is never turned into a big integer.
  defp integer(text) when byte_size(text) > 17, do: float(text)

  defp integer(text) do
    value = String.to_integer(text)
    if abs(value) <= @max_safe_integer, do: value, else: float(text)
  end

  defp float(text) do
    case Binary64.nearest(text) do
      {:ok, value} -> check_float(value)
      {:error, :overflow} -> @bad_number
    end
  end

  defp check_float(value) do
    integral? = value == Float.round(value)

    if integral? and abs(value) > @max_safe_integer and abs(value) < @float_integer_limit,
      do: @bad_number,
      else: value
  end

  # The document itself counts as 1.
  defp depth(value) when is_map(value),
    do: 1 + (value |> Map.values() |> Enum.map(&depth/1) |> Enum.max(fn -> 0 end))

  defp depth(value) when is_list(value),
    do: 1 + (value |> Enum.map(&depth/1) |> Enum.max(fn -> 0 end))

  defp depth(_value), do: 0

  @doc """
  The canonical form of a file under `spec/`: keys sorted, two-space indentation, one member
  or element per line, LF line ends and a final newline.
  """
  @spec canonical(term()) :: binary()
  def canonical(value), do: IO.iodata_to_binary([pretty(value, 0), "\n"])

  defp pretty(map, _level) when map == %{}, do: "{}"

  defp pretty(map, level) when is_map(map) do
    members =
      map
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map(fn {key, value} ->
        [indent(level + 1), JSON.encode!(key), ": ", pretty(value, level + 1)]
      end)

    ["{\n", Enum.intersperse(members, ",\n"), "\n", indent(level), "}"]
  end

  defp pretty([], _level), do: "[]"

  defp pretty(list, level) when is_list(list) do
    items = Enum.map(list, &[indent(level + 1), pretty(&1, level + 1)])
    ["[\n", Enum.intersperse(items, ",\n"), "\n", indent(level), "]"]
  end

  defp pretty(scalar, _level), do: JSON.encode!(scalar)

  defp indent(level), do: String.duplicate("  ", level)

  @doc """
  The JCS (RFC 8785) bytes of an object whose names and values are all printable ASCII
  strings, as a constructions text's are: members sorted, no whitespace. For such strings,
  sorting by bytes is JCS's sort by UTF-16 code units, and `JSON.encode!/1` escapes exactly
  what JCS escapes, `"` and `\\`. Any other value raises rather than meet the number
  formatting and escaping JCS gives it.
  """
  @spec jcs(%{optional(String.t()) => String.t()}) :: binary()
  def jcs(object) when is_map(object) do
    members =
      object
      |> Enum.sort_by(fn {name, _value} -> name end)
      |> Enum.map(fn {name, value} -> [ascii_string(name), ":", ascii_string(value)] end)

    IO.iodata_to_binary(["{", Enum.intersperse(members, ","), "}"])
  end

  defp ascii_string(string) when is_binary(string) do
    if string =~ ~r/\A[\x20-\x7e]*\z/,
      do: JSON.encode!(string),
      else: raise(ArgumentError, "not a printable ASCII string: #{inspect(string)}")
  end
end
