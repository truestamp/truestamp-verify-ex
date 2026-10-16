# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JCS do
  @moduledoc """
  JCS(x), the JSON Canonicalization Scheme of RFC 8785 (SPEC.md sections 2.2 and 2.5): the
  UTF-8 bytes of a value with no whitespace, object members sorted by the UTF-16 code units
  of their names, strings escaped as RFC 8785 section 3.2.2.2 says, and numbers written as
  ECMAScript's Number.prototype.toString writes them (RFC 8785 section 3.2.2.3).

  It is for a value within the value profile of SPEC.md section 10.1, in the terms
  `Truestamp.Verify.JSON` produces. JCS is injective over that profile (section 4.1),
  and for every value v in it, JCS(v) parses back to v (section 10.1).

  It raises on exactly four kinds of term: a term JSON cannot hold (an atom other than
  `nil`, `true` and `false`, a tuple, a struct, a pid, an improper list and the like), a
  string that is not UTF-8, a member name that is not a string, and an integer of magnitude
  above MAX_INTEGER. The error is `ArgumentError`, except for an improper list, which raises
  `FunctionClauseError`. It checks nothing else of the profile. A float is written as RFC 8785 writes
  it, even one no parse gives, such as `1.0e20` or `1.0`, and the depth of a value is not
  checked, so a list 40 deep is written. No parsed value is any of these, so a term that
  reaches them comes from a defect in the caller.
  """

  alias Truestamp.Verify.JSON

  @max_integer JSON.max_integer()

  @doc "The JCS bytes of `value`."
  @spec encode(JSON.value()) :: binary()
  def encode(value), do: value |> encode_value() |> IO.iodata_to_binary()

  defp encode_value(nil), do: "null"
  defp encode_value(true), do: "true"
  defp encode_value(false), do: "false"
  defp encode_value(string) when is_binary(string), do: encode_string(string)

  defp encode_value(integer) when is_integer(integer) and abs(integer) <= @max_integer,
    do: Integer.to_string(integer)

  defp encode_value(float) when is_float(float), do: encode_number(float)

  defp encode_value(list) when is_list(list),
    do: ["[", Enum.map_intersperse(list, ",", &encode_value/1), "]"]

  defp encode_value(map) when is_map(map) and not is_struct(map) do
    members =
      map
      |> Enum.map(fn {name, value} -> {utf16_sort_key(name), name, value} end)
      |> Enum.sort()
      |> Enum.map_intersperse(",", fn {_key, name, value} ->
        [encode_string(name), ":", encode_value(value)]
      end)

    ["{", members, "}"]
  end

  defp encode_value(other),
    do: raise(ArgumentError, "not within the value profile: #{inspect(other)}")

  # RFC 8785 section 3.2.3: names sort by their UTF-16 code units, compared as unsigned
  # integers. In UTF-16BE, comparing the bytes compares the code units, and a name that is a
  # prefix of another sorts first, as in RFC 8785.
  defp utf16_sort_key(name) when is_binary(name) do
    case :unicode.characters_to_binary(name, :utf8, {:utf16, :big}) do
      utf16 when is_binary(utf16) -> utf16
      _error -> raise ArgumentError, "a member name is not UTF-8: #{inspect(name)}"
    end
  end

  defp utf16_sort_key(name),
    do: raise(ArgumentError, "a member name is not a string: #{inspect(name)}")

  # RFC 8785 section 3.2.2.2: `"` and `\` are escaped, the controls U+0000 to U+001F are
  # escaped with the short forms where JSON has one and as \u00xx in lowercase hex
  # otherwise, and every other character is written as it is.
  defp encode_string(string) do
    if String.valid?(string),
      do: [?", escape(string, ""), ?"],
      else: raise(ArgumentError, "a string is not UTF-8: #{inspect(string)}")
  end

  # A byte below 0x80 is never part of a multi-byte UTF-8 sequence, so the string is
  # escaped byte by byte.
  defp escape(<<>>, acc), do: acc
  defp escape(<<?", rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\\"">>)
  defp escape(<<?\\, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\\\">>)
  defp escape(<<0x08, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\b">>)
  defp escape(<<?\t, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\t">>)
  defp escape(<<?\n, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\n">>)
  defp escape(<<0x0C, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\f">>)
  defp escape(<<?\r, rest::binary>>, acc), do: escape(rest, <<acc::binary, "\\r">>)

  defp escape(<<c, rest::binary>>, acc) when c < 0x20 do
    hex = c |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
    escape(rest, <<acc::binary, "\\u", hex::binary>>)
  end

  defp escape(<<c, rest::binary>>, acc), do: escape(rest, <<acc::binary, c>>)

  # RFC 8785 section 3.2.2.3, which is ECMAScript's Number::toString for a finite binary64
  # value. Both zeros are "0".
  defp encode_number(float) when float == 0.0, do: "0"
  defp encode_number(float) when float < 0.0, do: ["-", encode_positive(-float)]
  defp encode_number(float), do: encode_positive(float)

  # With the shortest decimal digits `digits` (k of them) and the exponent n for which the
  # value is 0.digits x 10^n, ECMAScript chooses among four forms.
  defp encode_positive(float) do
    {digits, n} = shortest_digits(float)
    k = byte_size(digits)

    cond do
      k <= n and n <= 21 -> [digits, String.duplicate("0", n - k)]
      0 < n and n <= 21 -> [binary_part(digits, 0, n), ".", binary_part(digits, n, k - n)]
      -6 < n and n <= 0 -> ["0.", String.duplicate("0", -n), digits]
      true -> exponent_form(digits, n - 1)
    end
  end

  defp exponent_form(<<first, rest::binary>>, exponent) do
    sign = if exponent < 0, do: "-", else: "+"
    mantissa = if rest == "", do: <<first>>, else: [first, ".", rest]
    [mantissa, "e", sign, Integer.to_string(abs(exponent))]
  end

  # OTP's `:short` form is the shortest decimal that reads back as the same binary64 value,
  # the nearest one when several are that short, as ECMAScript requires. It is written
  # "I.F" or "I.FeE", and is taken apart here into its significant digits and n.
  defp shortest_digits(float) do
    text = :erlang.float_to_binary(float, [:short])
    {mantissa, exponent} = split_exponent(text)
    {integer_part, fraction_part} = split_point(mantissa)
    all = integer_part <> fraction_part
    significant = String.trim_leading(all, "0")
    leading_zeros = byte_size(all) - byte_size(significant)
    n = byte_size(integer_part) + exponent - leading_zeros
    {String.trim_trailing(significant, "0"), n}
  end

  defp split_exponent(text) do
    case String.split(text, "e") do
      [mantissa, exponent] -> {mantissa, String.to_integer(exponent)}
      [mantissa] -> {mantissa, 0}
    end
  end

  defp split_point(mantissa) do
    case String.split(mantissa, ".") do
      [integer_part, fraction_part] -> {integer_part, fraction_part}
      [integer_part] -> {integer_part, ""}
    end
  end
end
