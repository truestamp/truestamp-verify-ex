# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ItemCode do
  @moduledoc """
  The item code of SPEC.md section 3.9: a short name for an item, for people and links,
  computed from the recomputed `item_hash`. It is the leftmost 75 bits of `item_hash` as 15
  symbols, then one check symbol over GF(2^5), written with the alphabet
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ` as one run of 16 uppercase characters with no
  separator. That is its only spelling in output.

  No proof carries it, no step of section 10 reads it, and it is never a verdict input, a
  report member or a row. A surface may show an item proof's code beside the whole
  `item_hash`, never in its place and never with a pass status (section 11.5). A match shows
  only that the recomputed `item_hash` begins with those 75 bits, so equal codes are never
  read as the same item; only equal `item_hash` values are.

  - `from_item_hash/1` gives the code of an `item_hash`, as its 32 bytes or as HEX64.
  - `parse/1` reads a value a person typed or pasted, taking every permission section 3.9
    gives a reader, and gives the code in its one spelling or the reason it refuses the
    value.
  - `valid?/1` says whether `parse/1` reads a value as a code.

  The reader reads only ASCII and trims nothing. A value may hold only the symbols of the
  alphabet, the lowercase forms of its letters, `I`, `L` and `O` in either case, and three
  separators: the space, the hyphen and the underscore. It reads each lowercase letter as its
  capital, then `I` and `L` as `1` and `O` as `0`, so the two readings combine. A separator
  may stand only at the three places between four groups of four symbols, at most one at
  each, so a value is at most 19 characters. Exactly 16 symbols must remain, and the check
  loop run over all 16 must end at zero, which catches every single wrong symbol and every
  exchange of two different symbols, at any distance.
  """

  import Bitwise, only: [<<<: 2, bxor: 2]

  @typedoc "An item code in its one spelling: 16 characters of the alphabet, uppercase."
  @type t :: String.t()

  @typedoc """
  Why `parse/1` refuses a value, in the order it looks:

  - `:not_a_string`: the value is not a binary;
  - `:not_ascii`: it holds a byte above 0x7F, a character that is not ASCII or bytes that
    are not UTF-8;
  - `:character`: it holds an ASCII character that cannot stand in a value, such as a tab,
    a line feed, a carriage return, a `U` or a `u`;
  - `:length`: it holds other than 16 symbols;
  - `:separator`: a separator stands before the first symbol, after the last, inside a
    group of four, or next to another separator;
  - `:check`: the check loop over the 16 symbols does not end at zero.
  """
  @type reason :: :not_a_string | :not_ascii | :character | :length | :separator | :check

  @alphabet ~c"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @symbols List.to_tuple(@alphabet)

  # The value a reader reads each character that can stand for a symbol as: each symbol of
  # the alphabet as itself and I, L and O as 1, 1 and 0, then each lowercase letter as its
  # capital. U is neither a symbol nor a reading, so neither U nor u is here.
  @capitals @alphabet |> Enum.with_index() |> Map.new() |> Map.merge(%{?I => 1, ?L => 1, ?O => 0})
  @lowercase for {char, value} <- @capitals, char in ?A..?Z, into: %{}, do: {char + 32, value}
  @readings Map.merge(@capitals, @lowercase)

  @separators ~c" -_"

  # The number of symbols before each of the three places a separator may stand.
  @group_ends [4, 8, 12]

  @doc """
  The item code of `item_hash`, given as its 32 bytes or as HEX64 (64 lowercase hex
  characters, SPEC.md section 2.4): `{:ok, code}`, else `{:error, :not_item_hash}`.
  """
  @spec from_item_hash(term()) :: {:ok, t()} | {:error, :not_item_hash}
  def from_item_hash(<<_::binary-32>> = item_hash), do: {:ok, encode(item_hash)}

  def from_item_hash(<<_::binary-64>> = hex) do
    case Base.decode16(hex, case: :lower) do
      {:ok, item_hash} -> {:ok, encode(item_hash)}
      :error -> {:error, :not_item_hash}
    end
  end

  def from_item_hash(_item_hash), do: {:error, :not_item_hash}

  @doc """
  Reads `value` as section 3.9's reader does, with every permission it gives: `{:ok, code}`
  with the code in its one spelling, else `{:error, reason}` naming the first flaw met in
  the order of `t:reason/0`.
  """
  @spec parse(term()) :: {:ok, t()} | {:error, reason()}
  def parse(value) when is_binary(value) do
    with :ok <- ascii(value),
         {:ok, tokens} <- tokens(value, []),
         {:ok, values} <- values(tokens),
         :ok <- check(values),
         do: {:ok, spell(values)}
  end

  def parse(_value), do: {:error, :not_a_string}

  @doc "Whether `parse/1` reads `value` as an item code."
  @spec valid?(term()) :: boolean()
  def valid?(value), do: match?({:ok, _code}, parse(value))

  # Steps 1 to 3: the leftmost 75 bits as 15 values of 5 bits, most significant first, then
  # the check value, each written as its symbol.
  defp encode(<<leftmost::bitstring-size(75), _rest::bitstring>>) do
    values = for <<value::5 <- leftmost>>, do: value
    spell(values ++ [times_x(loop(values))])
  end

  defp spell(values), do: values |> Enum.map(&elem(@symbols, &1)) |> List.to_string()

  # Step 2's loop: start with r = 0, and for each value v in order set r to m(r) XOR v.
  defp loop(values), do: Enum.reduce(values, 0, fn value, r -> bxor(times_x(r), value) end)

  # m(v): v times x in GF(2^5) modulo x^5 + x^2 + 1, which is 37.
  defp times_x(value) do
    shifted = value <<< 1
    if shifted >= 32, do: bxor(shifted, 37), else: shifted
  end

  defp ascii(<<char, rest::binary>>) when char < 0x80, do: ascii(rest)
  defp ascii(<<>>), do: :ok
  defp ascii(_bytes), do: {:error, :not_ascii}

  # Each character as `:separator` or the value it reads as.
  defp tokens(<<>>, tokens), do: {:ok, Enum.reverse(tokens)}

  defp tokens(<<char, rest::binary>>, tokens) when char in @separators,
    do: tokens(rest, [:separator | tokens])

  defp tokens(<<char, rest::binary>>, tokens) when is_map_key(@readings, char),
    do: tokens(rest, [Map.fetch!(@readings, char) | tokens])

  defp tokens(_bytes, _tokens), do: {:error, :character}

  defp values(tokens) do
    values = Enum.reject(tokens, &(&1 == :separator))

    cond do
      length(values) != 16 -> {:error, :length}
      placed?(tokens, 0) -> {:ok, values}
      true -> {:error, :separator}
    end
  end

  # Whether each separator stands at one of the three places between the groups, alone
  # there: after 4, 8 or 12 symbols, with a symbol after it. `seen` counts the symbols read.
  defp placed?([], _seen), do: true

  defp placed?([:separator, value | rest], seen) when seen in @group_ends and is_integer(value),
    do: placed?(rest, seen + 1)

  defp placed?([:separator | _rest], _seen), do: false
  defp placed?([_value | rest], seen), do: placed?(rest, seen + 1)

  # The loop of step 2 over all 16 values ends with r = 0 exactly when the last is the check
  # value of the first 15.
  defp check(values), do: if(loop(values) == 0, do: :ok, else: {:error, :check})
end
