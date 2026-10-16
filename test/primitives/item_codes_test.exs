# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ItemCodesTest do
  # The known answers of vectors/item-codes.json (SPEC.md 13.2) for the item code of SPEC.md
  # 3.9, recomputed by this test's own reading of that section: the derivation, and a reader
  # that takes every permission 3.9 gives. The generator writes the file and shares no code
  # with this test. The known answers are not conformance cases (SPEC.md 13.1).
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.{JSON, Hash}
  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @spec_md Path.join(@root, "SPEC.md")
  @file_path Path.join(@root, "vectors/item-codes.json")
  @external_resource @spec_md
  @external_resource @file_path

  # The item-id handoff's four known answers (its section 2.1), kept here by hand.
  @handoff %{
    "4f1769d767cb2c83eff1c48165939090d42fac433c5eabe6f02c5cf9d025181b" => "9WBPKNV7SCP87VZW",
    "97c5fcb7f9fd0bb680eb7b302f6826a16a2e21c32695ff82ed827b6748c86b95" => "JZ2ZSDZSZM5VD073",
    "0000000000000000000000000000000000000000000000000000000000000000" => "0000000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" => "ZZZZZZZZZZZZZZZN"
  }

  # SPEC.md 3.9, from its heading to section 4, read once when the module compiles.
  [_before, section] = String.split(File.read!(@spec_md), "\n### 3.9 The item code\n")
  [section, _after] = String.split(section, "\n## 4. ", parts: 2)
  @section String.replace(section, ~r/\s+/, " ")

  defp section, do: @section

  defp number(pattern) do
    [n] = Regex.run(pattern, section(), capture: :all_but_first)
    String.to_integer(n)
  end

  # The numbers of SPEC.md 3.9, read from the text: the bits step 1 takes, the value step 2
  # XORs with, the alphabet of step 3, and the size of a group a reader reads.
  defp bits, do: number(~r/Take the leftmost (\d+) bits/)
  defp modulus, do: number(~r/XOR it with (\d+)/)

  defp alphabet do
    [alphabet] = Regex.run(~r/alphabet `([0-9A-Z]{32})`/, section(), capture: :all_but_first)
    alphabet
  end

  defp group_size do
    words = %{"three" => 3, "four" => 4, "five" => 5, "eight" => 8}
    [n] = Regex.run(~r/in four groups of (\w+)/, section(), capture: :all_but_first)
    Map.fetch!(words, n)
  end

  defp file, do: StrictJSON.read_data!(@file_path)

  # Step 2's m(v): v times x in GF(2^5), XOR with the modulus when v * 2 reaches 32.
  defp times_x(v) when v < 16, do: v * 2
  defp times_x(v), do: bxor(v * 2, modulus())

  defp remainder(values), do: Enum.reduce(values, 0, &bxor(times_x(&2), &1))

  # Steps 1 to 3: the leftmost bits as values of 5 bits, then the check value, spelled.
  defp item_code(hex) do
    int = String.to_integer(hex, 16)
    leftmost = div(int, Integer.pow(2, 256 - bits()))
    values = leftmost |> Integer.digits(32) |> pad(div(bits(), 5))
    symbols = String.graphemes(alphabet())
    Enum.map_join(values ++ [times_x(remainder(values))], &Enum.at(symbols, &1))
  end

  defp pad(digits, n), do: List.duplicate(0, n - length(digits)) ++ digits

  # A reader that takes every permission of SPEC.md 3.9: `{:ok, code}` or `:refused`. A value
  # is four groups of symbols, with at most one space, hyphen or underscore between two
  # groups; a symbol is a character of the alphabet, a lowercase one, or I, L or O in either
  # case. The pattern runs over bytes, so no byte above 0x7F matches.
  defp read(input) do
    letters = alphabet() <> String.downcase(alphabet()) <> "ILOilo"
    symbol = "[" <> Regex.escape(letters) <> "]"
    group = "(#{symbol}{#{group_size()}})"
    pattern = Regex.compile!("\\A" <> Enum.join(List.duplicate(group, 4), "[ _\\-]?") <> "\\z")
    symbols = String.graphemes(alphabet())

    with [_whole | groups] <- Regex.run(pattern, input),
         kept =
           groups
           |> Enum.join()
           |> String.upcase(:ascii)
           |> String.replace(["I", "L"], "1")
           |> String.replace("O", "0"),
         values = Enum.map(String.graphemes(kept), &Enum.find_index(symbols, fn s -> s == &1 end)),
         0 <- remainder(values) do
      {:ok, kept}
    else
      _other -> :refused
    end
  end

  test "SPEC.md 3.9's numbers: 75 bits, the modulus 37, the alphabet and groups of four" do
    assert bits() == 75
    # x^5 + x^2 + 1, whose bits are 0b100101.
    assert modulus() == 0b100101
    assert alphabet() == "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    assert group_size() == 4
    assert 4 * group_size() == div(bits(), 5) + 1
  end

  test "no group of the file is empty" do
    file = file()

    for group <- ~w(accepted derive refused) do
      assert [_ | _] = file[group], group
    end
  end

  test "the file has its three groups, each row with its members" do
    %{"accepted" => accepted, "derive" => derive, "refused" => refused} = file = file()

    assert Enum.sort(Map.keys(file)) == ~w(accepted derive refused)

    for row <- derive do
      members = ~w(about item_code item_hash) ++ if(row["proof"], do: ["proof"], else: [])
      assert Enum.sort(Map.keys(row)) == members, inspect(row)
    end

    for row <- accepted, do: assert(Enum.sort(Map.keys(row)) == ~w(about input item_code))
    for row <- refused, do: assert(Enum.sort(Map.keys(row)) == ~w(about input))
  end

  test "every derive row's item code is the one its item_hash gives" do
    for %{"item_code" => code, "item_hash" => hash} <- file()["derive"] do
      assert hash =~ ~r/\A[0-9a-f]{64}\z/
      assert item_code(hash) == code, hash
    end
  end

  test "a derive row that names a proof holds that proof's recomputed item_hash, and every sound item proof has one" do
    named =
      for %{"proof" => path, "item_hash" => hash} <- file()["derive"] do
        {:ok, %{"proof" => proof}} =
          @root |> Path.join("vectors/" <> path) |> File.read!() |> JSON.decode()

        assert proof["type"] == "item"
        assert Hash.hash_hex(:item_hash, proof["subject"]["record"]) == hash, path
        path
      end

    items =
      for path <- Path.wildcard(Path.join(@root, "vectors/positive/item*.proof.json")),
          do: Path.relative_to(path, Path.join(@root, "vectors"))

    assert Enum.sort(named) == Enum.sort(items)
  end

  test "the handoff's four known answers are rows, and the final m is what makes the first" do
    rows = Map.new(file()["derive"], &{&1["item_hash"], &1["item_code"]})

    for {hash, code} <- @handoff do
      assert rows[hash] == code, hash
      assert item_code(hash) == code, hash
    end

    # Without the final m, the check value is the loop's r itself.
    values = "9WBPKNV7SCP87VZ" |> String.graphemes() |> Enum.map(&index/1)
    last = String.at(alphabet(), remainder(values))
    assert "9WBPKNV7SCP87VZ" <> last == "9WBPKNV7SCP87VZE"
  end

  test "every accepted value reads as its item code" do
    for %{"input" => hex, "item_code" => code} <- file()["accepted"] do
      input = Base.decode16!(hex, case: :lower)
      assert read(input) == {:ok, code}, inspect(input)
      assert read(code) == {:ok, code}
    end
  end

  # A hand list, kept apart from the generator, of rows SPEC.md 3.9 depends on: dropping one of
  # them from the file fails here even when the generator's own list loses it too.
  @required_accepted [
    {"9WBPKNV7SCP87VZW", "9WBPKNV7SCP87VZW"},
    {"9wBpKnV7sCp87vZw", "9WBPKNV7SCP87VZW"},
    {"9WBP-KNV7-SCP8-7VZW", "9WBPKNV7SCP87VZW"},
    {"9WBP_KNV7_SCP8_7VZW", "9WBPKNV7SCP87VZW"},
    {"9WBP KNV7 SCP8 7VZW", "9WBPKNV7SCP87VZW"},
    {"9WBP-KNV7_SCP8 7VZW", "9WBPKNV7SCP87VZW"},
    {"9WBP-KNV7SCP87VZW", "9WBPKNV7SCP87VZW"},
    {"jz2zsdzszm5vdo73", "JZ2ZSDZSZM5VD073"},
    {"oI23456789aBcDe4", "0123456789ABCDE4"}
  ]

  @required_refused [
    "9WBUKNV7SCP87VZW",
    "9WBPKNV7SCP87VZX",
    # The code without the check's final m, for the first known answer's item_hash.
    "9WBPKNV7SCP87VZE",
    "9WBPKNV7SCP8V7ZW",
    " 9WBPKNV7SCP87VZW",
    "9WBPKNV7SCP87VZW_",
    "9WB-PKNV7SCP87VZW",
    "9WBPKNV7--SCP87VZW",
    "9WBPKNV7SCP87VZW\n",
    "9WBP\tKNV7SCP87VZW",
    "9WBP\u2010KNV7\u2010SCP8\u20107VZW",
    "9WBP\u00A0KNV7\u00A0SCP8\u00A07VZW"
  ]

  test "the file holds the rows 3.9 depends on, and reads them as this list says" do
    %{"accepted" => accepted, "refused" => refused} = file()
    accepted = Map.new(accepted, &{Base.decode16!(&1["input"], case: :lower), &1["item_code"]})
    refused = MapSet.new(refused, &Base.decode16!(&1["input"], case: :lower))

    for {input, code} <- @required_accepted do
      assert Map.get(accepted, input) == code, inspect(input)
      assert read(input) == {:ok, code}, inspect(input)
    end

    for input <- @required_refused do
      assert MapSet.member?(refused, input), inspect(input)
      assert read(input) == :refused, inspect(input)
    end
  end

  test "every refused value is refused" do
    for %{"input" => hex} <- file()["refused"] do
      input = Base.decode16!(hex, case: :lower)
      assert read(input) == :refused, inspect(input)
    end
  end

  test "at every derived code, each single wrong symbol and each exchange is refused" do
    symbols = String.graphemes(alphabet())

    for %{"item_code" => code} <- file()["derive"] do
      chars = String.graphemes(code)

      for i <- 0..15, s <- symbols, s != Enum.at(chars, i) do
        assert read(chars |> List.replace_at(i, s) |> Enum.join()) == :refused
      end

      for i <- 0..14, j <- (i + 1)..15, Enum.at(chars, i) != Enum.at(chars, j) do
        exchanged =
          chars
          |> List.replace_at(i, Enum.at(chars, j))
          |> List.replace_at(j, Enum.at(chars, i))

        assert read(Enum.join(exchanged)) == :refused, "#{code} #{i} #{j}"
      end
    end
  end

  defp index(symbol), do: alphabet() |> String.graphemes() |> Enum.find_index(&(&1 == symbol))
end
