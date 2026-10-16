# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JCSTest do
  # JCS (RFC 8785): the corpus pairs of vectors/corpus/jcs/, then each rule of the scheme on
  # its own: string escaping, member order by UTF-16 code unit, and number formatting.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.{JCS, JSON}

  @root Truestamp.Verify.Test.Verification.root()
  @inputs @root |> Path.join("vectors/corpus/jcs/*.input.json") |> Path.wildcard() |> Enum.sort()
  for path <- Path.wildcard(Path.join(@root, "vectors/corpus/jcs/*")),
      do: @external_resource(path)

  defp decode!(text) do
    {:ok, value} = JSON.decode(text)
    value
  end

  describe "the corpus" do
    test "holds every pair SPEC.md 13.2 names" do
      names = Enum.map(@inputs, &Path.basename(&1, ".input.json"))

      for name <- ~w(rfc8785-example rfc8785-sorting rfc8785-numbers worked-example utf16-order) do
        assert name in names
      end

      for input <- @inputs do
        assert File.exists?(String.replace_suffix(input, ".input.json", ".output.json"))
      end
    end

    for input <- @inputs do
      @input input
      @output String.replace_suffix(input, ".input.json", ".output.json")

      test "#{Path.basename(input, ".input.json")}: JCS of the input's value is the output" do
        output = File.read!(@output)
        refute String.ends_with?(output, "\n")
        assert JCS.encode(decode!(File.read!(@input))) == output
        # The output is canonical already, and parses back to the same value.
        assert JCS.encode(decode!(output)) == output
        assert decode!(output) == decode!(File.read!(@input))
      end
    end
  end

  describe "literals and structure" do
    test "writes literals, empty containers and nesting with no whitespace" do
      assert JCS.encode(nil) == "null"
      assert JCS.encode(true) == "true"
      assert JCS.encode(false) == "false"
      assert JCS.encode(%{}) == "{}"
      assert JCS.encode([]) == "[]"
      assert JCS.encode([[], %{}, [nil]]) == "[[],{},[null]]"

      assert JCS.encode(%{"b" => [1, %{"d" => true, "c" => nil}], "a" => ""}) ==
               ~s({"a":"","b":[1,{"c":null,"d":true}]})
    end

    test "keeps array order" do
      assert JCS.encode([3, 1, 2]) == "[3,1,2]"
    end
  end

  describe "strings (RFC 8785 section 3.2.2.2)" do
    test "escapes each control character, with the short form where JSON has one" do
      short = %{0x08 => "\\b", 0x09 => "\\t", 0x0A => "\\n", 0x0C => "\\f", 0x0D => "\\r"}

      for c <- 0x00..0x1F do
        expected =
          Map.get_lazy(short, c, fn ->
            "\\u00" <> String.downcase(Base.encode16(<<c>>))
          end)

        assert JCS.encode(<<c>>) == ~s(") <> expected <> ~s("), inspect(c)
      end
    end

    test "escapes the quote and the backslash, and nothing else" do
      assert JCS.encode(~s(a"b\\c)) == ~s("a\\"b\\\\c")
      assert JCS.encode("/") == ~s("/")
      assert JCS.encode(" ~") == ~s(" ~")
    end

    test "writes U+007F and every character above as UTF-8, never as an escape" do
      for text <- [
            "\u007f",
            "\u0080",
            "\u{E9}",
            "\u{2028}",
            "\u{2029}",
            "\u{FEFF}",
            "\u{1F600}",
            "\u{10FFFF}"
          ] do
        assert JCS.encode(text) == ~s(") <> text <> ~s("), inspect(text)
      end
    end

    test "escapes a member name as it escapes a value" do
      assert JCS.encode(%{"a\nb" => "\u0001"}) == ~s({"a\\nb":"\\u0001"})
    end
  end

  describe "member order (RFC 8785 section 3.2.3)" do
    test "sorts by UTF-16 code unit, which differs from code point order above U+FFFF" do
      # U+FF5A sorts after U+1F600 by UTF-16 (0xFF5A > 0xD83D) but before it by code point.
      assert JCS.encode(%{"\u{FF5A}" => 1, "\u{1F600}" => 2}) ==
               ~s({"\u{1F600}":2,"\u{FF5A}":1})

      assert JCS.encode(%{"\u{E000}" => 1, "\u{10000}" => 2}) == ~s({"\u{10000}":2,"\u{E000}":1})
    end

    test "puts a name before every longer name it begins" do
      assert JCS.encode(%{"ab" => 1, "a" => 2, "b" => 3, "" => 4}) ==
               ~s({"":4,"a":2,"ab":1,"b":3})
    end

    test "sorts capitals before small letters and digits before both" do
      assert JCS.encode(%{"a" => 1, "B" => 2, "1" => 3, "_" => 4}) ==
               ~s({"1":3,"B":2,"_":4,"a":1})
    end
  end

  describe "numbers (RFC 8785 section 3.2.2.3)" do
    test "writes an integer in the profile in plain decimal" do
      for {value, text} <- [
            {0, "0"},
            {1, "1"},
            {-1, "-1"},
            {9_007_199_254_740_991, "9007199254740991"},
            {-9_007_199_254_740_991, "-9007199254740991"}
          ] do
        assert JCS.encode(value) == text
      end
    end

    test "writes each binary64 value as ECMAScript's Number::toString does" do
      for {value, text} <- [
            {0.0, "0"},
            {-0.0, "0"},
            {1.0, "1"},
            {-1.5, "-1.5"},
            {0.1, "0.1"},
            {0.1 + 0.2, "0.30000000000000004"},
            {123.456, "123.456"},
            {100.0, "100"},
            {1.0e20, "100000000000000000000"},
            {float("9.999999999999999e20"), "999999999999999900000"},
            {1.0e21, "1e+21"},
            {1.5e21, "1.5e+21"},
            {-1.0e21, "-1e+21"},
            {1.0e-6, "0.000001"},
            {1.5e-6, "0.0000015"},
            {1.0e-7, "1e-7"},
            {1.25e-7, "1.25e-7"},
            {5.0e-324, "5e-324"},
            {float("1.7976931348623157e308"), "1.7976931348623157e+308"},
            {333_333_333.3333333, "333333333.3333333"},
            {4.5, "4.5"},
            {2.0e-3, "0.002"},
            {1.0e-27, "1e-27"},
            {float("1.4249539237812062e15"), "1424953923781206.2"},
            {float("9.007199254740992e15"), "9007199254740992"}
          ] do
        assert JCS.encode(value) == text, "#{inspect(value)}"
      end
    end

    test "writes a number that reads back as the same binary64 value" do
      :rand.seed(:exsss, {1, 2, 3})

      floats =
        Stream.repeatedly(fn -> :crypto.strong_rand_bytes(8) end)
        # An exponent field of all ones is an infinity or a NaN, which binary64 JSON lacks.
        |> Stream.reject(&match?(<<_sign::1, 0x7FF::11, _fraction::52>>, &1))
        |> Stream.map(fn <<float::float-64>> -> float end)
        |> Enum.take(2000)

      for float <- floats do
        text = JCS.encode(float)
        # Float.parse/1 reaches the C library's strtod, which is safe on a text this short:
        # JCS writes at most 17 significant digits, as the assertion below holds.
        assert {parsed, ""} = Float.parse(text)
        assert parsed == float, "#{inspect(float)} wrote #{text}"
        # No more significant digits than a binary64 value ever needs.
        significant = text |> String.replace(~r/e.*|[-.]/, "") |> String.trim("0")
        assert byte_size(significant) <= 17, text
      end
    end
  end

  describe "terms outside the profile" do
    test "raise on a term JSON cannot hold, a string not UTF-8, a name not a string and an integer above MAX_INTEGER" do
      for value <- [
            9_007_199_254_740_992,
            -9_007_199_254_740_992,
            :atom,
            {1, 2},
            %{1 => 2},
            %{a: 1},
            <<0xFF>>,
            %{<<0xFF>> => 1},
            [<<0xC0, 0x80>>],
            ~D[2026-01-01]
          ] do
        assert_raise ArgumentError, fn -> JCS.encode(value) end
      end
    end

    test "write a float no parse gives and a value deeper than MAX_DEPTH, which JCS does not check" do
      # J5 refuses the number 1e20, and the parser reads 1.0 as the integer 1.
      assert JCS.encode(1.0e20) == "100000000000000000000"
      assert JCS.encode([1.0, -0.0]) == "[1,0]"

      deep = Enum.reduce(1..40, [], fn _level, inner -> [inner] end)
      assert JCS.encode(deep) == String.duplicate("[", 41) <> String.duplicate("]", 41)
    end
  end

  describe "the parse round trip of section 10.1" do
    test "JCS(v) parses back to v, for random values within the profile" do
      :rand.seed(:exsss, {4, 5, 6})

      for _ <- 1..300 do
        value = random_value(4)
        text = JCS.encode(value)
        assert JSON.decode(text) === {:ok, value}
        assert JCS.encode(decode!(text)) == text
      end
    end
  end

  @alphabet [
    "a",
    "Z",
    "0",
    " ",
    "\"",
    "\\",
    "\n",
    "\u0001",
    "\u007f",
    "\u{E9}",
    "\u{2028}",
    "\u{1F600}",
    "\u{FF5A}"
  ]

  defp random_value(0), do: random_scalar()

  defp random_value(depth) do
    case :rand.uniform(4) do
      1 -> for _ <- 1..:rand.uniform(4), into: %{}, do: {random_string(), random_value(depth - 1)}
      2 -> for _ <- 1..:rand.uniform(4), do: random_value(depth - 1)
      _ -> random_scalar()
    end
  end

  defp random_scalar do
    case :rand.uniform(7) do
      1 -> nil
      2 -> :rand.uniform(2) == 1
      3 -> :rand.uniform(9_007_199_254_740_991) * Enum.random([1, -1])
      4 -> in_profile(:rand.uniform() * :math.pow(10, :rand.uniform(40) - 20))
      5 -> Enum.random([1.0e21, 1.0e300, -2.5e-300, 5.0e-324])
      _ -> random_string()
    end
  end

  # The term the parser gives for a binary64 value, or a fraction when J5 refuses it.
  defp in_profile(float) do
    cond do
      Float.floor(float) != float -> float
      abs(float) <= 9_007_199_254_740_991 -> trunc(float)
      abs(float) >= 1.0e21 -> float
      true -> 0.5
    end
  end

  defp random_string, do: Enum.map_join(1..:rand.uniform(6), fn _ -> Enum.random(@alphabet) end)

  # A binary64 value written with all its digits, which the number literals of Elixir's
  # style would split with underscores.
  defp float(text), do: String.to_float(text)
end
