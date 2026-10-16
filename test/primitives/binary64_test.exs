# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSON.Binary64Test do
  # The nearest binary64 value of a JSON number (SPEC.md 10.1, J5), held to the spellings
  # that abort macOS 27's strtod, to a table of known answers from Python's float(), which is
  # correctly rounded, and, where strtod is safe, to :erlang.binary_to_float/1. Every value
  # is compared by its bits, so -0.0 and 0.0 differ.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.JSON.Binary64
  alias Truestamp.Verify.Test.CrashInputs

  @known_answers Path.expand("../data/binary64_known_answers.txt", __DIR__)
  @external_resource @known_answers

  defp bits(float) when is_float(float) do
    <<n::64>> = <<float::float-64>>
    n
  end

  defp from_bits(n) do
    <<float::float-64>> = <<n::64>>
    float
  end

  defp zero?(n), do: (n &&& 0x7FFF_FFFF_FFFF_FFFF) == 0
  defp subnormal?(n), do: (n >>> 52 &&& 0x7FF) == 0 and not zero?(n)

  # The answer as the test compares it: the value's bits, or :overflow.
  defp answer(text) do
    case Binary64.nearest(text) do
      {:ok, float} -> bits(float)
      {:error, :overflow} -> :overflow
    end
  end

  # Each line: the answer, then the number, or head, fill, count and tail for
  # head <> fill x count <> tail (see binary64_known_answers.py).
  defp known_answers do
    for line <- @known_answers |> File.read!() |> String.split("\n", trim: true),
        not String.starts_with?(line, "#") do
      [expected | spelling] = String.split(line, "\t")

      text =
        case spelling do
          [text] ->
            text

          [head, fill, count, tail] ->
            head <> String.duplicate(fill, String.to_integer(count)) <> tail
        end

      {text, if(expected == "overflow", do: :overflow, else: String.to_integer(expected, 16))}
    end
  end

  describe "the spellings that abort macOS 27's strtod" do
    test "each reads as its nearest binary64 value" do
      expected = [
        9_999_999_999_999_998.0,
        9_007_199_254_740_990.0,
        9_223_372_036_854_775_808.0,
        -9_223_372_036_854_773_760.0,
        75.75960580580087
      ]

      inputs = CrashInputs.all()
      assert Enum.map(inputs, &byte_size/1) == [348, 348, 213, 214, 637]

      for {text, value} <- Enum.zip(inputs, expected) do
        assert Binary64.nearest(text) === {:ok, value}, binary_part(text, 0, 30)
      end
    end

    test "the 637-character one is the halfway point below 75.75960580580087, zeros and a 1" do
      text = List.last(CrashInputs.all())
      value = 75.75960580580087
      below = from_bits(bits(value) - 1)

      # Both are m x 2^e with one e, so the halfway point is (m1 + m2) x 2^(e - 1), whose
      # decimal expansion is (m1 + m2) x 5^k over 10^k, with k = 1 - e.
      {low_m, e} = decompose(below)
      {high_m, ^e} = decompose(value)
      k = 1 - e
      digits = Integer.to_string((low_m + high_m) * Integer.pow(5, k))
      {integer, fraction} = String.split_at(digits, byte_size(digits) - k)
      halfway = integer <> "." <> String.trim_trailing(fraction, "0")

      assert String.starts_with?(text, halfway)
      {_halfway, rest} = String.split_at(text, byte_size(halfway))
      assert rest == String.duplicate("0", byte_size(rest) - 1) <> "1"

      # The halfway point itself is a tie, which goes to the even neighbour.
      even = if rem(bits(value), 2) == 0, do: value, else: below
      assert Binary64.nearest(halfway) === {:ok, even}
    end
  end

  # A positive normal float as m x 2^e, with m an integer of 53 bits.
  defp decompose(float) do
    <<0::1, biased::11, fraction::52>> = <<float::float-64>>
    {fraction + (1 <<< 52), biased - 1075}
  end

  describe "the known answers" do
    test "each of thousands of hard spellings reads as Python's float() reads it" do
      answers = known_answers()
      assert length(answers) >= 5000

      mismatches =
        for {text, expected} <- answers, answer(text) !== expected do
          {binary_part(text, 0, min(byte_size(text), 60)), expected, answer(text)}
        end

      assert mismatches == []
    end

    test "cover long spellings, ties, overflows, zeros, subnormals and long exponents" do
      answers = known_answers()
      lengths = Enum.map(answers, fn {text, _} -> byte_size(text) end)

      assert Enum.count(lengths, &(&1 > 30)) >= 3000
      assert Enum.count(lengths, &(&1 > 767)) >= 1000
      assert Enum.count(lengths, &(&1 >= 262_000)) >= 10

      values = for {_text, expected} <- answers, expected != :overflow, do: expected
      assert Enum.count(answers, &match?({_, :overflow}, &1)) >= 20
      assert Enum.count(values, &zero?/1) >= 20
      assert Enum.count(values, &subnormal?/1) >= 50

      texts = Enum.map(answers, &elem(&1, 0))
      assert Enum.all?(CrashInputs.all(), &(&1 in texts))
      assert Enum.any?(texts, &Regex.match?(~r/e-?0*[1-9][0-9]{19,}$/, &1))
    end
  end

  describe "the edges" do
    test "zero, with its sign, however it is spelled" do
      for text <- ["0", "0.0", "0e0", "0E+5", "0.000e-999999999999999999999"] do
        assert Binary64.nearest(text) === {:ok, 0.0}, text
      end

      for text <- ["-0", "-0.0", "-0e5", "-1e-400"] do
        assert Binary64.nearest(text) === {:ok, -0.0}, text
      end
    end

    test "the smallest subnormal and half of it, which ties to zero" do
      assert Binary64.nearest("4.9406564584124654e-324") === {:ok, from_bits(1)}
      assert Binary64.nearest("2.4703282292062327e-324") === {:ok, 0.0}
      assert Binary64.nearest("2.4703282292062328e-324") === {:ok, from_bits(1)}
      # 10^-324 lies below half the smallest subnormal, and 10^-323 above it.
      assert Binary64.nearest("1e-324") === {:ok, 0.0}
      assert Binary64.nearest("1e-323") === {:ok, from_bits(2)}
    end

    test "overflow begins at 2^1024 - 2^970, the tie between the largest value and 2^1024" do
      largest = from_bits(0x7FEF_FFFF_FFFF_FFFF)
      edge = Integer.to_string(Integer.pow(2, 1024) - Integer.pow(2, 970))

      assert Binary64.nearest("1.7976931348623158e308") === {:ok, largest}
      assert Binary64.nearest("1.7976931348623159e308") == {:error, :overflow}
      assert Binary64.nearest(edge) == {:error, :overflow}

      assert Binary64.nearest(Integer.to_string(Integer.pow(2, 1024) - Integer.pow(2, 970) - 1)) ===
               {:ok, largest}

      assert Binary64.nearest(edge <> "." <> String.duplicate("0", 5000)) == {:error, :overflow}
      assert Binary64.nearest("1e309") == {:error, :overflow}
      assert Binary64.nearest("-1e309") == {:error, :overflow}
    end

    test "an exponent of any length, with the digits' own point" do
      assert Binary64.nearest("1e" <> String.duplicate("0", 100) <> "5") === {:ok, 1.0e5}
      assert Binary64.nearest("1e-" <> String.duplicate("0", 100) <> "1") === {:ok, 0.1}
      assert Binary64.nearest("1e" <> String.duplicate("9", 20)) == {:error, :overflow}
      assert Binary64.nearest("1e-" <> String.duplicate("9", 20)) === {:ok, 0.0}
      assert Binary64.nearest("0." <> String.duplicate("0", 500) <> "1e501") === {:ok, 1.0}
      assert Binary64.nearest("1" <> String.duplicate("0", 500) <> "e-500") === {:ok, 1.0}
    end

    test "digits past the 800th: zeros keep a tie, and any other digit breaks it" do
      # 2^53 + 1, halfway between 2^53 and 2^53 + 2, goes to the even 2^53.
      tie = "9007199254740993."

      assert Binary64.nearest(tie <> String.duplicate("0", 2000)) ===
               {:ok, 9_007_199_254_740_992.0}

      assert Binary64.nearest(tie <> String.duplicate("0", 2000) <> "1") ===
               {:ok, 9_007_199_254_740_994.0}

      assert Binary64.nearest("9007199254740992." <> String.duplicate("9", 2000)) ===
               {:ok, 9_007_199_254_740_992.0}
    end

    test "a spelling of 262,144 digits costs little" do
      long = [
        "1" <> String.duplicate("0", 262_143),
        "0." <> String.duplicate("0", 262_142) <> "1",
        "9007199254740993." <> String.duplicate("0", 262_126) <> "1",
        "1e" <> String.duplicate("0", 262_141) <> "1",
        "1." <> String.duplicate("7", 262_142)
      ]

      {microseconds, answers} = :timer.tc(fn -> Enum.map(long, &Binary64.nearest/1) end)

      assert answers === [
               {:error, :overflow},
               {:ok, 0.0},
               {:ok, 9_007_199_254_740_994.0},
               {:ok, 10.0},
               {:ok, 1.7777777777777777}
             ]

      assert microseconds < 2_000_000
    end

    test "raises on a spelling outside RFC 8259's grammar" do
      for text <- [
            "",
            "-",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "1e+",
            "1.5.5",
            "0x10",
            "1 ",
            " 1",
            "1e5x",
            "NaN"
          ] do
        assert_raise ArgumentError, fn -> Binary64.nearest(text) end
      end
    end
  end

  describe "agreement with :erlang.binary_to_float/1" do
    # :erlang.binary_to_float/1 calls the C library's strtod. On macOS 27 that aborts the
    # whole runtime on some long spellings, so this comparison never runs on macOS; it runs
    # on Linux, whose glibc strtod is correctly rounded.
    if match?({:unix, :darwin}, :os.type()) do
      @tag skip: "strtod aborts the runtime on macOS 27, so binary_to_float/1 is not called here"
    end

    test "both give the same value for random spellings of up to 800 digits" do
      :rand.seed(:exsss, {11, 12, 13})

      for _ <- 1..20_000 do
        length = Enum.random([:rand.uniform(20), :rand.uniform(60), :rand.uniform(800)])
        digits = Enum.map_join(1..length, fn _ -> Integer.to_string(:rand.uniform(10) - 1) end)
        exponent = :rand.uniform(700) - 350
        sign = Enum.random(["", "-"])
        # binary_to_float/1 needs a point with a digit on each side.
        text = "#{sign}#{:rand.uniform(9)}.#{digits}e#{exponent}"

        theirs =
          try do
            bits(:erlang.binary_to_float(text))
          rescue
            ArgumentError -> :overflow
          end

        assert answer(text) === theirs, text
      end
    end
  end
end
