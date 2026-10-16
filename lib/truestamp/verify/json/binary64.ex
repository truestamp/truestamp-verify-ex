# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSON.Binary64 do
  @moduledoc """
  The nearest binary64 value of a JSON number, rounding to nearest with ties to even (SPEC.md
  section 10.1, J5), computed with integer arithmetic only.

  The Erlang runtime reads a decimal with the C library's `strtod`, and `Float.parse/1`,
  `String.to_float/1` and `:erlang.binary_to_float/1` all reach it. On macOS 27 that
  `strtod` aborts the whole runtime on some spellings of a few hundred digits, such as a
  637-character spelling of 75.75960580580087. This module calls none of them, and its
  work is bounded however long the spelling, so a 262,144-digit number costs no more than a
  short one plus a linear scan of its digits.

  For a spelling of RFC 8259's number grammar:

  1. The digits of the integer and fraction parts, with the leading zeros dropped, are the
     significant digits S, and P is the power of ten for which the magnitude is 0.S x 10^P,
     so it lies in [10^(P - 1), 10^P).
  2. With no significant digit the value is zero, with the spelling's sign. With P above
     309 the magnitude is at least 10^309, beyond 2^1024 - 2^970, so the number overflows.
     With P below -323 the magnitude is below 10^-324, under half the smallest subnormal
     2^-1074, so the value is zero. An exponent of more than 15 digits, once its leading
     zeros are dropped, decides one of these two alone, since no spelling has 10^15
     digits. None of this needs a big integer.
  3. At most 800 significant digits are kept. When more follow and one of them is not zero,
     a digit 1 is appended to the 800, a sticky digit. A value halfway between two adjacent
     binary64 values, or between the largest and 2^1024, has at most 768 significant
     digits (a binary64 value itself has at most 767), so no halfway point lies strictly between the digits kept and the full
     spelling, and both round alike. Trailing zeros past the 800th digit set nothing, so a
     halfway point written with any number of zeros after it is still a tie.
  4. The value is now M x 10^Q, with M below 10^801 and Q between -1124 and 308. It is
     divided, as a fraction of integers, by the power of two 2^e that leaves a quotient of
     56 or 57 bits; the remainder says whether anything was dropped. The quotient is rounded
     to 53 bits, or to a multiple of 2^-1074 for a subnormal, to nearest with ties to even,
     and the float is built from its sign, biased exponent and fraction bits.

  `nearest/1` gives only the binary64 value. Which values J5 lets through, and which of
  them the reader writes as integers, is `Truestamp.Verify.JSON`'s.
  """

  import Bitwise

  # Step 3: the significant digits kept before the sticky digit.
  @kept_digits 800
  # Step 2: 10^309 > 2^1024 - 2^970, and 10^-324 < 2^-1075.
  @max_point 309
  @min_point -323
  # Step 2: an exponent of more digits than this is beyond any digit count.
  @max_exponent_digits 15
  # Step 4: the quotient has 56 or 57 bits.
  @quotient_bits 56
  # binary64: 53 bits of significand, and the smallest subnormal is 2^-1074.
  @significand_bits 53
  @min_lsb -1074
  # The largest finite value is (2^53 - 1) x 2^971.
  @max_lsb 971

  @doc """
  The binary64 value nearest the JSON number `text`, ties to even: `{:ok, float}`, or
  `{:error, :overflow}` when that rounding gives an infinity, that is, when the magnitude is
  at least 2^1024 - 2^970. An underflow is a zero, and `-0` and every negative number that
  rounds to zero give `-0.0`. `text` that does not match RFC 8259's number grammar raises
  `ArgumentError`.
  """
  @spec nearest(binary()) :: {:ok, float()} | {:error, :overflow}
  def nearest(text) when is_binary(text) do
    case split(text) do
      {:ok, negative?, digits, point, exponent} ->
        round_decimal(negative?, digits, point, exponent)

      :error ->
        raise ArgumentError, "not a JSON number: #{inspect(text, limit: 20)}"
    end
  end

  # Step 1. `digits` are the significant digits and `point` is P before the exponent.
  defp split(text) do
    {negative?, rest} = take_sign(text)

    with {:ok, integer, rest} <- take_integer(rest),
         {:ok, fraction, rest} <- take_fraction(rest),
         {:ok, exponent} <- take_exponent(rest) do
      {zeros, digits} = drop_zeros(integer <> fraction, 0)
      {:ok, negative?, digits, byte_size(integer) - zeros, exponent}
    end
  end

  defp take_sign(<<?-, rest::binary>>), do: {true, rest}
  defp take_sign(rest), do: {false, rest}

  # `0`, or a digit from 1 to 9 followed by any digits.
  defp take_integer(<<?0, c, _::binary>>) when c in ?0..?9, do: :error
  defp take_integer(<<?0, rest::binary>>), do: {:ok, "0", rest}
  defp take_integer(<<c, _::binary>> = bytes) when c in ?1..?9, do: take_run(bytes)
  defp take_integer(_bytes), do: :error

  defp take_fraction(<<?., c, _::binary>> = bytes) when c in ?0..?9 do
    <<?., rest::binary>> = bytes
    take_run(rest)
  end

  defp take_fraction(<<?., _::binary>>), do: :error
  defp take_fraction(rest), do: {:ok, "", rest}

  # The exponent as {negative?, digits without leading zeros}, and nothing after it.
  defp take_exponent(""), do: {:ok, {false, ""}}

  defp take_exponent(<<e, rest::binary>>) when e in [?e, ?E] do
    {negative?, rest} =
      case rest do
        <<?+, rest::binary>> -> {false, rest}
        <<?-, rest::binary>> -> {true, rest}
        rest -> {false, rest}
      end

    case take_run(rest) do
      {:ok, "", _rest} -> :error
      {:ok, digits, ""} -> {:ok, {negative?, elem(drop_zeros(digits, 0), 1)}}
      {:ok, _digits, _rest} -> :error
    end
  end

  defp take_exponent(_rest), do: :error

  defp take_run(bytes) do
    length = run_length(bytes, 0)
    <<run::binary-size(^length), rest::binary>> = bytes
    {:ok, run, rest}
  end

  defp run_length(<<c, rest::binary>>, n) when c in ?0..?9, do: run_length(rest, n + 1)
  defp run_length(_bytes, n), do: n

  defp drop_zeros(<<?0, rest::binary>>, n), do: drop_zeros(rest, n + 1)
  defp drop_zeros(rest, n), do: {n, rest}

  # Step 2, then steps 3 and 4.
  defp round_decimal(negative?, "", _point, _exponent), do: {:ok, build(negative?, 0, 0)}

  defp round_decimal(negative?, digits, point, exponent) do
    case place(point, exponent) do
      :overflow -> {:error, :overflow}
      :zero -> {:ok, build(negative?, 0, 0)}
      {:point, p} -> round_scaled(negative?, digits, p)
    end
  end

  defp place(_point, {negative?, digits}) when byte_size(digits) > @max_exponent_digits,
    do: if(negative?, do: :zero, else: :overflow)

  defp place(point, {negative?, digits}) do
    magnitude = if digits == "", do: 0, else: String.to_integer(digits)
    p = if negative?, do: point - magnitude, else: point + magnitude

    cond do
      p > @max_point -> :overflow
      p < @min_point -> :zero
      true -> {:point, p}
    end
  end

  defp round_scaled(negative?, digits, p) do
    {m, count} = mantissa(digits)
    q = p - count

    {numerator, denominator} =
      if q >= 0, do: {m * Integer.pow(10, q), 1}, else: {m, Integer.pow(10, -q)}

    e = bit_length(numerator) - bit_length(denominator) - @quotient_bits
    {quotient, sticky?} = divide(numerator, denominator, e)
    round_binary(negative?, quotient, sticky?, e)
  end

  # Step 3: the first 800 significant digits, and a sticky 1 when a later digit is not zero.
  defp mantissa(digits) when byte_size(digits) <= @kept_digits,
    do: {String.to_integer(digits), byte_size(digits)}

  defp mantissa(digits) do
    <<kept::binary-size(@kept_digits), rest::binary>> = digits
    m = String.to_integer(kept)

    if drop_zeros(rest, 0) |> elem(1) == "",
      do: {m, @kept_digits},
      else: {m * 10 + 1, @kept_digits + 1}
  end

  # floor(numerator / (denominator x 2^e)), and whether that dropped anything.
  defp divide(numerator, denominator, e) when e >= 0,
    do: quotient_and_sticky(numerator, denominator <<< e)

  defp divide(numerator, denominator, e),
    do: quotient_and_sticky(numerator <<< -e, denominator)

  defp quotient_and_sticky(numerator, denominator),
    do: {div(numerator, denominator), rem(numerator, denominator) != 0}

  # Step 4: the value is (quotient + f) x 2^e, with 0 <= f < 1 and f > 0 exactly when
  # `sticky?`. `lsb` is the exponent of the last bit kept: 53 bits, or 2^-1074 at the
  # subnormals. The quotient has at least 56 bits, so at least three are dropped.
  defp round_binary(negative?, quotient, sticky?, e) do
    lsb = max(e + bit_length(quotient) - @significand_bits, @min_lsb)
    shift = lsb - e
    kept = quotient >>> shift
    dropped = quotient &&& (1 <<< shift) - 1
    half = 1 <<< (shift - 1)

    up? = dropped > half or (dropped == half and (sticky? or (kept &&& 1) == 1))
    {significand, lsb} = carry(if(up?, do: kept + 1, else: kept), lsb)

    if lsb > @max_lsb,
      do: {:error, :overflow},
      else: {:ok, build(negative?, significand, lsb)}
  end

  # Rounding up from 2^53 - 1 gives 2^53, which is 2^52 at the next exponent.
  defp carry(significand, lsb) when significand == 1 <<< @significand_bits,
    do: {1 <<< (@significand_bits - 1), lsb + 1}

  defp carry(significand, lsb), do: {significand, lsb}

  # The float of sign, significand and lsb: a normal value when the significand has 53
  # bits, and otherwise a subnormal or zero, whose lsb is -1074 and biased exponent 0.
  defp build(negative?, significand, lsb) do
    sign = if negative?, do: 1, else: 0
    normal = 1 <<< (@significand_bits - 1)

    {biased, fraction} =
      if significand >= normal,
        do: {lsb - @min_lsb + 1, significand - normal},
        else: {0, significand}

    <<float::float-64>> = <<sign::1, biased::11, fraction::52>>
    float
  end

  defp bit_length(0), do: 0

  defp bit_length(n) do
    <<first, _rest::binary>> = bytes = :binary.encode_unsigned(n)
    (byte_size(bytes) - 1) * 8 + length(Integer.digits(first, 2))
  end
end
