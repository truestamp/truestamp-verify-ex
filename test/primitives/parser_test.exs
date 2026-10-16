# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSONTest do
  # The parsing rules J1 to J6 of SPEC.md section 10.1, one describe block per rule, with
  # each limit tested at its value and one past it, then the parse vectors of cases.json.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.{JCS, JSON, ReasonCodes}
  alias Truestamp.Verify.Test.{CrashInputs, StrictJSON}

  @root Truestamp.Verify.Test.Verification.root()
  @max_read_octets 262_144
  @max_depth 32

  defp parse(text), do: JSON.parse(text)
  defp refused(text), do: elem(JSON.parse(text), 1)

  defp nested(depth, open, close, inner \\ ""),
    do: String.duplicate(open, depth) <> inner <> String.duplicate(close, depth)

  describe "J1, step READ" do
    test "takes exactly MAX_READ_OCTETS octets and refuses one more" do
      at_limit = "[]" <> String.duplicate(" ", @max_read_octets - 2)
      assert byte_size(at_limit) == @max_read_octets
      assert JSON.read(at_limit) == :ok
      assert JSON.decode(at_limit) === {:ok, []}

      over = at_limit <> " "
      assert JSON.read(over) == {:error, :input_too_large}
      assert JSON.decode(over) == {:error, :input_too_large}
    end

    test "comes before PARSE, so an oversized file that is also malformed is too large" do
      assert JSON.decode(String.duplicate("x", @max_read_octets + 1)) ==
               {:error, :input_too_large}

      # parse/1 alone makes no J1 check.
      assert {:ok, _value} = JSON.parse("[]" <> String.duplicate(" ", @max_read_octets))
    end

    test "read_file/1 decides J1 by reading at most MAX_READ_OCTETS + 1 octets" do
      # Outside the repository, so that no file of this test is ever tracked.
      dir = Path.join(System.tmp_dir!(), "parser-test-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      at_limit = Path.join(dir, "at_limit.json")
      File.write!(at_limit, "{}" <> String.duplicate("\n", @max_read_octets - 2))
      assert {:ok, bytes} = JSON.read_file(at_limit)
      assert byte_size(bytes) == @max_read_octets

      over = Path.join(dir, "over.json")
      File.write!(over, String.duplicate(" ", 10 * @max_read_octets))
      assert JSON.read_file(over) == {:error, :input_too_large}

      empty = Path.join(dir, "empty.json")
      File.write!(empty, "")
      assert JSON.read_file(empty) == {:ok, ""}

      assert {:error, {:unreadable, :enoent}} = JSON.read_file(Path.join(dir, "absent.json"))
    end
  end

  describe "J2, one JSON text in UTF-8 and nothing after it but whitespace" do
    test "reads each kind of value into its term" do
      assert parse(~s({"a":[true,false,null,"s",1,1.5,{}],"b":{}})) ===
               {:ok, %{"a" => [true, false, nil, "s", 1, 1.5, %{}], "b" => %{}}}

      assert parse("\"top\"") === {:ok, "top"}
      assert parse("7") === {:ok, 7}
      assert parse("null") === {:ok, nil}
    end

    test "allows RFC 8259's four whitespace characters anywhere between tokens" do
      text = " \t\r\n{ \"a\" \r\n: [ 1 ,\t2 ] , \"b\"\n:\rtrue } \n\r\t"
      assert parse(text) === {:ok, %{"a" => [1, 2], "b" => true}}
    end

    test "refuses whitespace RFC 8259 does not define" do
      for space <- ["\f", "\v", "\u00a0", "\u2028", "\u3000", <<0>>] do
        assert refused(space <> "{}") == {:malformed_json, :syntax}, inspect(space)
        assert refused("[1," <> space <> "2]") == {:malformed_json, :syntax}, inspect(space)
      end
    end

    test "refuses a byte order mark" do
      assert refused("\uFEFF{}") == {:malformed_json, :syntax}
      assert parse("{}") === {:ok, %{}}
    end

    test "refuses anything after the value but whitespace" do
      for text <- ["{}{}", "{} {}", "[] x", "1 2", "\"a\"\"b\"", "{}\u0000", "{},", "null;"] do
        assert refused(text) == {:malformed_json, :syntax}, inspect(text)
      end
    end

    test "refuses an empty text and a text of whitespace" do
      assert refused("") == {:malformed_json, :syntax}
      assert refused(" \n ") == {:malformed_json, :syntax}
    end

    test "refuses what RFC 8259's grammar lacks" do
      for text <- [
            "{a:1}",
            "{'a':1}",
            "['a']",
            "[1,]",
            ~s({"a":1,}),
            "[,1]",
            ~s({"a" 1}),
            ~s({"a":}),
            ~s({"a"}),
            ~s({,"a":1}),
            ~s({1:1}),
            "[1 2]",
            "[",
            "]",
            "{",
            ~s({"a":1),
            "[[]",
            "tru",
            "True",
            "nul",
            "NaN",
            "Infinity",
            "-Infinity",
            "undefined",
            "/* c */ 1",
            "1 // c"
          ] do
        assert refused(text) == {:malformed_json, :syntax}, inspect(text)
      end
    end

    test "refuses a number outside RFC 8259's grammar" do
      for text <-
            ["01", "-01", "00", "1.", ".5", "-.5", "+1", "-", "1e", "1e+", "1E-", "1.e5"] ++
              ["0x10", "1_000", "--1", "1.5.5", "1ee5", "- 1", "0.", "-0.e1"] do
        assert refused("[" <> text <> "]") == {:malformed_json, :syntax}, inspect(text)
      end
    end

    test "reads every number form of RFC 8259's grammar" do
      for {text, value} <- [
            {"0", 0},
            {"-0", 0},
            {"10", 10},
            {"-10", -10},
            {"1.25", 1.25},
            {"-1.25", -1.25},
            {"1e2", 100},
            {"1E2", 100},
            {"1e+2", 100},
            {"1e-2", 0.01},
            {"1.5E+3", 1500},
            {"0.0", 0},
            {"0e0", 0}
          ] do
        assert parse("[" <> text <> "]") === {:ok, [value]}, text
      end
    end

    test "refuses a string with an unterminated body, a raw control or a bad escape" do
      for text <- [
            ~s("abc),
            ~s("a\\"),
            "\"a\u0001b\"",
            "\"a\tb\"",
            "\"a\nb\"",
            "\"a\u001fb\"",
            ~s("\\x"),
            ~s("\\a"),
            ~s("\\U0041"),
            ~s("\\u004"),
            ~s("\\u00G1"),
            ~s("\\u+041"),
            ~s("\\u-041"),
            ~s("\\u 041"),
            ~s("\\')
          ] do
        assert refused(text) == {:malformed_json, :syntax}, inspect(text)
      end
    end

    test "resolves every escape" do
      text = ~s("\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u0041 \\u00e9 \\u00E9 \\u0000")
      assert parse(text) === {:ok, "\" \\ / \b \f \n \r \t A \u{E9} \u{E9} \u0000"}
    end

    test "keeps U+007F, the line and paragraph separators and non-ASCII text as written" do
      assert parse("\"\u007f\u2028\u2029\u{E9}\u{1F600}\"") ===
               {:ok, "\u007f\u2028\u2029\u{E9}\u{1F600}"}
    end
  end

  describe "J3, valid UTF-8 and no escaped lone surrogate" do
    test "refuses bytes that are not UTF-8, inside or outside a string" do
      for bytes <- [
            <<0xFF>>,
            <<0xC3>>,
            <<0xC0, 0x80>>,
            <<0xE0, 0x80, 0x80>>,
            <<0xED, 0xA0, 0x80>>,
            <<0xED, 0xBF, 0xBF>>,
            <<0xF4, 0x90, 0x80, 0x80>>,
            <<0xF8, 0x88, 0x80, 0x80, 0x80>>,
            <<0x80>>
          ] do
        assert refused(~s(") <> bytes <> ~s(")) == {:malformed_json, :invalid_utf8},
               inspect(bytes)

        assert refused(~s({"a":1}) <> bytes) == {:malformed_json, :invalid_utf8}
      end
    end

    test "takes every scalar value written raw, the noncharacters among them" do
      text = ~s(") <> <<0xEF, 0xBF, 0xBE, 0xF4, 0x8F, 0xBF, 0xBF, 0xEE, 0x80, 0x80>> <> ~s(")
      assert parse(text) === {:ok, "\u{FFFE}\u{10FFFF}\u{E000}"}
    end

    test "refuses an escaped surrogate that is not half of an escaped pair" do
      for body <- [
            "\\ud800",
            "\\udbff",
            "\\udc00",
            "\\udfff",
            "\\ud800x",
            "\\ud800\\u0041",
            "\\ud800\\ud800",
            "\\udc00\\ud800",
            "\\ude00\\ud83d",
            "a\\ud83d",
            "\\ud83d\\n\\ude00"
          ] do
        assert refused(~s(") <> body <> ~s(")) == {:malformed_json, :lone_surrogate}, body
        assert refused(~s({") <> body <> ~s(":1})) == {:malformed_json, :lone_surrogate}, body
      end
    end

    test "joins an escaped pair, in either case of hex, and the ends of the surrogate ranges" do
      assert parse(~s("\\ud83d\\ude00")) === {:ok, "\u{1F600}"}
      assert parse(~s("\\uD83D\\uDE00")) === {:ok, "\u{1F600}"}
      assert parse(~s("\\ud800\\udc00")) === {:ok, "\u{10000}"}
      assert parse(~s("\\udbff\\udfff")) === {:ok, "\u{10FFFF}"}
      assert parse(~s("\\ud7ff\\ue000")) === {:ok, "\u{D7FF}\u{E000}"}
    end
  end

  describe "J4, no object with two members of the same name" do
    test "refuses a repeated name, however it is written" do
      for text <- [
            ~s({"a":1,"a":2}),
            ~s({"a":1,"a":1}),
            ~s({"a":1,"b":2,"a":3}),
            ~s({"a":1,"\\u0061":2}),
            ~s({"\\u00e9":1,"\u{E9}":2}),
            ~s({"\u{1F600}":1,"\\ud83d\\ude00":2}),
            ~s({"":1,"":2}),
            ~s([{"x":{"a":null,"a":null}}])
          ] do
        assert refused(text) == {:malformed_json, :duplicate_name}, text
      end
    end

    test "compares names as code points, with no normalization and no case folding" do
      # U+00E9 and U+0065 U+0301 are canonically equivalent but not the same code points.
      assert {:ok, map} = parse(~s({"\\u00e9":1,"e\\u0301":2,"A":3,"a":4}))
      assert map_size(map) == 4
    end

    test "allows one name in two different objects" do
      assert parse(~s({"a":{"a":1},"b":{"a":2}})) ===
               {:ok, %{"a" => %{"a" => 1}, "b" => %{"a" => 2}}}
    end
  end

  describe "J5, numbers as their nearest binary64 value" do
    test "reads an integral value up to MAX_INTEGER as an integer, however it is written" do
      for text <- [
            "9007199254740991",
            "9007199254740991.0",
            "9007199254740991e0",
            "9.007199254740991e15",
            "90071992547409910e-1"
          ] do
        assert parse("[" <> text <> "]") === {:ok, [9_007_199_254_740_991]}, text
        assert parse("[-" <> text <> "]") === {:ok, [-9_007_199_254_740_991]}, text
      end

      assert parse("[1.0,1e0,10e-1,0.1e1]") === {:ok, [1, 1, 1, 1]}
    end

    test "reads 0, -0, -0.0, 0e5, 1.0 and 1e0 as the integers 0, 0, 0, 0, 1 and 1" do
      assert {:ok, [0, 0, 0, 0, 1, 1] = values} = parse("[0,-0,-0.0,0e5,1.0,1e0]")
      assert values === [0, 0, 0, 0, 1, 1]
      assert Enum.all?(values, &is_integer/1)
    end

    test "reads a number of any length as its nearest binary64 value, or refuses it" do
      # The spellings on which macOS 27's strtod aborts the runtime (binary64_test.exs).
      # Three have an integral nearest value above MAX_INTEGER, which J5 refuses, and one
      # reads as the integer 2^53 - 2.
      [a, b, c, d, ordinary] = CrashInputs.all()

      for text <- [a, c, d] do
        assert refused("[" <> text <> "]") == {:malformed_json, :number}
      end

      assert parse("[" <> b <> "]") === {:ok, [9_007_199_254_740_990]}
      assert parse("[" <> ordinary <> "]") === {:ok, [75.75960580580087]}

      # 2^53 + 1 followed by 600 zeros and a 1 reads as 2^53 + 2, which J5 refuses.
      long_gap = "9007199254740993." <> String.duplicate("0", 600) <> "1"
      assert refused("[" <> long_gap <> "]") == {:malformed_json, :number}

      # A document of exactly MAX_READ_OCTETS octets that is one number.
      fill = @max_read_octets - byte_size("[0.1]")
      at_limit = "[0.1" <> String.duplicate("0", fill) <> "]"
      assert byte_size(at_limit) == @max_read_octets
      assert JSON.decode(at_limit) === {:ok, [0.1]}

      too_big = "[1" <> String.duplicate("0", @max_read_octets - 3) <> "]"
      assert refused(too_big) == {:malformed_json, :number}
      tiny = "[0." <> String.duplicate("0", @max_read_octets - 5) <> "1]"
      assert parse(tiny) === {:ok, [0]}
    end

    test "refuses every integral value above MAX_INTEGER and below 10^21" do
      for text <- [
            "9007199254740992",
            "-9007199254740992",
            "9007199254740992.0",
            "9007199254740993",
            "9007199254740993e0",
            "1152921504606846976",
            "1e16",
            "1e20",
            "-1e20",
            "9.99999999999999e20",
            "123456789012345678"
          ] do
        assert refused("[" <> text <> "]") == {:malformed_json, :number}, text
      end
    end

    test "takes 10^21 and above, where binary64 rounds as every reader agrees" do
      assert parse("[1e21]") === {:ok, [1.0e21]}
      assert parse("[-1E+21]") === {:ok, [-1.0e21]}
      # 10^21 - 1 has no binary64 value of its own: its nearest is 10^21.
      assert parse("[999999999999999999999]") === {:ok, [1.0e21]}
      assert parse("[123456789012345678901234567890]") === {:ok, [float("1.2345678901234568e29")]}
      assert parse("[1.7976931348623157e308]") === {:ok, [float("1.7976931348623157e308")]}
    end

    test "reads -0 and an underflow as the integer 0" do
      for text <- ["-0", "-0.0", "-0e5", "0e-400", "1e-400", "-1e-400", "2.4703282292062327e-324"] do
        assert parse("[" <> text <> "]") === {:ok, [0]}, text
      end

      # The smallest subnormal is a value, not an underflow.
      assert parse("[4.9406564584124654e-324]") === {:ok, [5.0e-324]}
      assert parse("[2.4703282292062328e-324]") === {:ok, [5.0e-324]}
    end

    test "refuses an overflow" do
      for text <- ["1e400", "-1e400", "1.7976931348623159e308", "1e99999999999999999999"] do
        assert refused("[" <> text <> "]") == {:malformed_json, :number}, text
      end

      assert refused("[" <> String.duplicate("9", 400) <> "]") == {:malformed_json, :number}
    end

    test "reads a fraction as its nearest binary64 value" do
      assert parse("[0.1,37.7749,4.50,1e-7,333333333.33333329]") ===
               {:ok, [0.1, 37.7749, 4.5, 1.0e-7, 333_333_333.3333333]}

      # The halfway case between 2^53 - 1 and 2^53 would round to 2^53, but it has a
      # fraction as written, and 2^53 is refused whatever the spelling.
      assert refused("[9007199254740991.5]") == {:malformed_json, :number}
      assert parse("[4503599627370495.5]") === {:ok, [4_503_599_627_370_495.5]}
    end
  end

  describe "J6, depth at most MAX_DEPTH" do
    test "takes MAX_DEPTH nested arrays and refuses one more" do
      assert {:ok, _value} = parse(nested(@max_depth, "[", "]"))
      assert refused(nested(@max_depth + 1, "[", "]")) == {:malformed_json, :depth}
    end

    test "counts objects as arrays are counted" do
      objects = fn depth -> nested(depth - 1, ~s({"a":), "}", "{}") end
      assert {:ok, _value} = parse(objects.(@max_depth))
      assert refused(objects.(@max_depth + 1)) == {:malformed_json, :depth}

      # Pairs of an array holding an object, then one more array when the depth is odd.
      mixed = fn depth ->
        inner = if rem(depth, 2) == 1, do: "[]", else: "1"
        nested(div(depth, 2), ~s([{"a":), "}]", inner)
      end

      assert {:ok, _value} = parse(mixed.(@max_depth))
      assert refused(mixed.(@max_depth + 1)) == {:malformed_json, :depth}
    end

    test "adds no level for a scalar, so a scalar inside MAX_DEPTH arrays is taken" do
      for scalar <- ["1", "\"s\"", "true", "null"] do
        assert {:ok, _value} = parse(nested(@max_depth, "[", "]", scalar))
      end

      assert parse("1") === {:ok, 1}
    end

    test "refuses a deep text at MAX_DEPTH + 1, without reading further" do
      text = String.duplicate("[", 200_000)
      assert refused(text) == {:malformed_json, :depth}
    end

    test "counts depth per branch, not across siblings" do
      wide =
        "[" <> Enum.map_join(1..100, ",", fn _ -> nested(@max_depth - 1, "[", "]") end) <> "]"

      assert {:ok, list} = parse(wide)
      assert length(list) == 100
    end
  end

  describe "the parse vectors" do
    @cases @root |> Path.join("vectors/cases.json") |> StrictJSON.read_data!()
    @external_resource Path.join(@root, "vectors/cases.json")

    test "each READ and PARSE case of cases.json gives its code and sub_reason" do
      cases =
        Enum.filter(@cases, &(&1["expected"]["code"] in ["input_too_large", "malformed_json"]))

      assert length(cases) == 16

      for %{"expected" => expected, "id" => id, "proof" => proof} <- cases do
        path = Path.join(@root, "vectors/" <> proof)

        want =
          case expected do
            %{"code" => "input_too_large"} -> {:error, :input_too_large}
            %{"sub_reason" => sub} -> {:error, {:malformed_json, String.to_existing_atom(sub)}}
          end

        assert JSON.decode(File.read!(path)) == want, id
        assert read_and_parse(path) == want, id
      end
    end

    test "every sub_reason the reader gives is one of section 10.1's" do
      assert Enum.sort(ReasonCodes.sub_reasons(:malformed_json)) ==
               Enum.sort([
                 :syntax,
                 :invalid_utf8,
                 :lone_surrogate,
                 :duplicate_name,
                 :number,
                 :depth
               ])

      for text <- [
            "",
            "\uFEFF1",
            <<0xFF>>,
            ~s("\\ud800"),
            ~s({"a":1,"a":1}),
            "1e400",
            "[[[[" <> nested(40, "[", "]")
          ] do
        {:error, {:malformed_json, sub}} = parse(text)
        assert sub in ReasonCodes.sub_reasons(:malformed_json)
      end
    end
  end

  describe "the files of the repository" do
    @json_files for pattern <- ["spec/**/*.json", "vectors/**/*.json"],
                    path <- Path.wildcard(Path.join(@root, pattern)),
                    not String.contains?(path, "/negative/"),
                    do: path

    test "every file under spec/ reads under the rules, J1 included (SPEC.md 9)" do
      for path <- Path.wildcard(Path.join(@root, "spec/**/*.json")) do
        assert {:ok, _value} = read_and_parse(path), path
      end
    end

    test "every file under vectors/ but the negative ones meets J2 to J6" do
      # cases.json is larger than MAX_READ_OCTETS, which binds a document, not a data file.
      assert length(@json_files) > 100

      for path <- @json_files do
        assert {:ok, _value} = path |> File.read!() |> JSON.parse(), path
      end
    end

    test "the sameness case of exactly MAX_READ_OCTETS octets passes READ and PARSE" do
      path = Path.join(@root, "vectors/negative/sameness-max-read-octets.proof.json")
      assert File.stat!(path).size == @max_read_octets
      assert {:ok, %{"proof" => _proof, "signature" => _signature}} = read_and_parse(path)
    end

    test "each sound proof is its own JCS, and a reformatting of it parses to the same value" do
      for path <- Path.wildcard(Path.join(@root, "vectors/positive/*.proof.json")) do
        bytes = File.read!(path)
        {:ok, value} = JSON.decode(bytes)
        assert JCS.encode(value) == bytes, path

        # Pretty, CRLF line ends, every name written as \u escapes.
        {:ok, again} = value |> pretty(0) |> IO.iodata_to_binary() |> JSON.decode()
        assert again === value, path
      end
    end

    test "agrees with the test suite's own reader on every spec file" do
      for path <- Path.wildcard(Path.join(@root, "spec/*.json")) do
        bytes = File.read!(path)
        assert {:ok, ours} = JSON.decode(bytes)
        assert {:ok, theirs} = StrictJSON.decode(bytes)
        # The test reader keeps an integral float such as 1.0 as a float, which JCS writes
        # as it writes the integer, so the two readers are compared through JCS.
        assert JCS.encode(ours) == JCS.encode(theirs), path
      end
    end
  end

  defp pretty(map, level) when is_map(map) do
    members =
      map
      |> Enum.sort(:desc)
      |> Enum.map(fn {name, value} ->
        [indent(level + 1), escaped(name), " : ", pretty(value, level + 1)]
      end)

    ["{\r\n", Enum.intersperse(members, ",\r\n"), "\r\n", indent(level), "}"]
  end

  defp pretty(list, level) when is_list(list),
    do: ["[ ", Enum.map_intersperse(list, " , ", &pretty(&1, level + 1)), " ]"]

  defp pretty(integer, _level) when is_integer(integer), do: "#{integer}.0e0"
  defp pretty(scalar, _level), do: JCS.encode(scalar)

  defp indent(level), do: String.duplicate("\t", level)

  defp escaped(name) do
    units =
      for <<unit::16 <- :unicode.characters_to_binary(name, :utf8, {:utf16, :big})>>, do: unit

    [
      "\"",
      Enum.map(units, &("\\u" <> String.pad_leading(Integer.to_string(&1, 16), 4, "0"))),
      "\""
    ]
  end

  defp read_and_parse(path) do
    with {:ok, bytes} <- JSON.read_file(path), do: JSON.parse(bytes)
  end

  # A binary64 value written with all its digits, which the number literals of Elixir's
  # style would split with underscores.
  defp float(text), do: String.to_float(text)
end
