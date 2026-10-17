# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ItemCodeTest do
  # The item code (SPEC.md 3.9). vectors/item-codes.json, read through the verifier's own
  # Parser: its rows and members, and a derive row that names a proof holds that proof's
  # item_hash as this verifier recomputes it; each row's known answer, one test per row, is
  # conformance_test.exs's. Then each part of 3.9's rule, on hashes and values of this test's
  # own: the 75 bits, the check symbol, the readings, the separators, the characters and the
  # length.
  use ExUnit.Case, async: true

  import Bitwise, only: [bxor: 2]

  alias Truestamp.Verify.{Hash, ItemCode, JSON}

  @root Truestamp.Verify.Test.Verification.root()
  @vectors Path.join(@root, "vectors")
  @path Path.join(@vectors, "item-codes.json")
  @external_resource @path

  @alphabet ~c"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @separators ["-", "_", " "]
  @reasons [:not_ascii, :character, :length, :separator, :check]

  # Every character a value may hold (3.9): the alphabet, the lowercase forms of its letters,
  # I, L and O in either case, and the three separators.
  @permitted @alphabet ++
               for(char <- @alphabet, char in ?A..?Z, do: char + 32) ++
               ~c"ILOilo" ++ ~c" -_"

  # J1, then J2 to J6, as the verifier reads any file.
  read = fn path ->
    {:ok, bytes} = JSON.read_file(path)
    {:ok, value} = JSON.parse(bytes)
    value
  end

  @codes read.(@path)

  # The recomputed item_hash, H(0x11, /subject/record) (3.6), of every sound proof of type
  # item under positive/, by its path relative to vectors/.
  @proofs Path.wildcard(Path.join(@vectors, "positive/*.proof.json"))
  for path <- @proofs, do: @external_resource(path)

  @item_hashes (for path <- @proofs,
                    %{"proof" => %{"type" => "item", "subject" => %{"record" => record}}} <-
                      [read.(path)],
                    into: %{} do
                  {Path.relative_to(path, @vectors), Hash.hash_hex(:item_hash, record)}
                end)

  # Hashes of this test's own, and their codes.
  @hashes for n <- 1..24, do: :crypto.hash(:sha256, "item code test #{n}")

  defp codes do
    for hash <- [<<0::256>> | @hashes] do
      {:ok, code} = ItemCode.from_item_hash(hash)
      code
    end
  end

  defp unhex(hex), do: Base.decode16!(hex, case: :lower)

  defp groups(code), do: for(<<group::binary-4 <- code>>, do: group)

  defp replace_at(code, index, replacement) do
    <<before::binary-size(^index), _symbol, rest::binary>> = code
    before <> replacement <> rest
  end

  defp insert_at(code, index, text) do
    <<before::binary-size(^index), rest::binary>> = code
    before <> text <> rest
  end

  describe "the file" do
    test "holds derive, accepted and refused rows, each with the members 13.2 gives it" do
      assert @codes |> Map.keys() |> Enum.sort() == ~w(accepted derive refused)

      assert Enum.map(~w(derive accepted refused), &length(@codes[&1])) == [10, 25, 99]

      for row <- @codes["derive"] do
        assert Enum.sort(Map.keys(row) -- ["proof"]) == ~w(about item_code item_hash)
      end

      for row <- @codes["accepted"],
          do: assert(row |> Map.keys() |> Enum.sort() == ~w(about input item_code))

      for row <- @codes["refused"],
          do: assert(row |> Map.keys() |> Enum.sort() == ~w(about input))
    end

    test "has a derive row naming each sound proof of type item under positive/" do
      named = for %{"proof" => proof} <- @codes["derive"], do: proof
      assert map_size(@item_hashes) == 3
      assert Enum.sort(named) == @item_hashes |> Map.keys() |> Enum.sort()
    end

    test "has derive rows for 32 zero bytes and 32 bytes of 0xff, whose codes use every symbol" do
      hashes = Enum.map(@codes["derive"], & &1["item_hash"])
      assert String.duplicate("00", 32) in hashes
      assert String.duplicate("ff", 32) in hashes

      used =
        @codes["derive"] |> Enum.flat_map(&String.to_charlist(&1["item_code"])) |> Enum.uniq()

      assert Enum.sort(used) == Enum.sort(@alphabet)
    end

    test "has accepted values of at most 19 characters, one of exactly 19" do
      lengths = Enum.map(@codes["accepted"], &byte_size(unhex(&1["input"])))
      assert Enum.max(lengths) == 19
    end

    test "has refused values that this reader refuses for every reason a string can have" do
      reasons =
        for %{"input" => input} <- @codes["refused"], into: MapSet.new() do
          {:error, reason} = ItemCode.parse(unhex(input))
          reason
        end

      assert Enum.sort(reasons) == Enum.sort(@reasons)
    end
  end

  describe "the derive rows" do
    test "that name a proof hold its item_hash as this verifier recomputes it" do
      for %{"item_hash" => hex, "proof" => proof} <- @codes["derive"] do
        assert Map.fetch!(@item_hashes, proof) == hex, proof
      end
    end
  end

  describe "the code of an item_hash" do
    test "is 16 uppercase symbols of the alphabet, the same from the bytes and from HEX64" do
      for hash <- @hashes do
        {:ok, code} = ItemCode.from_item_hash(hash)
        assert byte_size(code) == 16
        assert code |> String.to_charlist() |> Enum.all?(&(&1 in @alphabet))
        assert ItemCode.from_item_hash(Base.encode16(hash, case: :lower)) == {:ok, code}
      end
    end

    test "depends on exactly the leftmost 75 bits" do
      for hash <- Enum.take(@hashes, 6), bit <- 0..255 do
        <<before::bitstring-size(^bit), value::1, rest::bitstring>> = hash
        flipped = <<before::bitstring, bxor(value, 1)::1, rest::bitstring>>

        if bit < 75,
          do: refute(ItemCode.from_item_hash(flipped) == ItemCode.from_item_hash(hash)),
          else: assert(ItemCode.from_item_hash(flipped) == ItemCode.from_item_hash(hash))
      end
    end

    test "refuses anything but 32 bytes or HEX64" do
      hex = Base.encode16(hd(@hashes), case: :lower)

      for value <- [
            String.upcase(hex),
            binary_part(hex, 0, 63),
            hex <> "0",
            replace_at(hex, 10, "g"),
            binary_part(hd(@hashes), 0, 31),
            hd(@hashes) <> <<0>>,
            "",
            nil,
            String.to_charlist(hex)
          ] do
        assert ItemCode.from_item_hash(value) == {:error, :not_item_hash}, inspect(value)
      end
    end
  end

  describe "the reader" do
    test "catches every single wrong symbol" do
      for code <- codes(),
          index <- 0..15,
          symbol <- @alphabet,
          symbol != :binary.at(code, index) do
        assert ItemCode.parse(replace_at(code, index, <<symbol>>)) == {:error, :check}
      end
    end

    test "catches every exchange of two different symbols, at any distance" do
      for code <- codes(), first <- 0..14, second <- (first + 1)..15 do
        a = :binary.at(code, first)
        b = :binary.at(code, second)

        if a != b do
          exchanged = code |> replace_at(first, <<b>>) |> replace_at(second, <<a>>)
          assert ItemCode.parse(exchanged) == {:error, :check}
        end
      end
    end

    test "reads any mix of case, I and L as 1 and O as 0, with a separator at each place" do
      readings = %{?0 => ~w(0 O o), ?1 => ~w(1 I i L l)}

      for {code, n} <- Enum.with_index(codes()),
          first <- ["" | @separators],
          second <- ["" | @separators],
          third <- ["" | @separators] do
        # Each symbol in a case and, for 0 and 1, a letter, chosen by its place and the code.
        typed =
          for {symbol, index} <- code |> String.to_charlist() |> Enum.with_index(), into: "" do
            choice = n + index + byte_size(first <> second <> third)

            case readings do
              %{^symbol => letters} -> Enum.at(letters, rem(choice, length(letters)))
              _other when rem(choice, 2) == 0 -> String.downcase(<<symbol>>)
              _other -> <<symbol>>
            end
          end

        [a, b, c, d] = groups(typed)
        value = a <> first <> b <> second <> c <> third <> d
        assert ItemCode.parse(value) == {:ok, code}, value
        assert ItemCode.parse(String.downcase(value)) == {:ok, code}, value
        assert ItemCode.parse(String.upcase(value)) == {:ok, code}, value
      end
    end

    test "refuses a separator anywhere else, and two together" do
      for code <- codes(), separator <- @separators do
        for index <- 0..16, index not in [4, 8, 12] do
          assert ItemCode.parse(insert_at(code, index, separator)) == {:error, :separator}
        end

        for index <- [4, 8, 12], other <- @separators do
          doubled = insert_at(code, index, separator <> other)
          assert ItemCode.parse(doubled) == {:error, :separator}
        end

        # Nothing is trimmed.
        [a, b, c, d] = groups(code)
        grouped = Enum.join([a, b, c, d], separator)
        assert ItemCode.parse(separator <> grouped) == {:error, :separator}
        assert ItemCode.parse(grouped <> separator) == {:error, :separator}
      end
    end

    test "refuses every other ASCII character, and every byte above 0x7F, wherever it stands" do
      [code | _codes] = codes()

      for char <- 0..255, char not in @permitted, index <- [0, 7, 15] do
        expected = if char < 0x80, do: {:error, :character}, else: {:error, :not_ascii}
        value = <<char>>
        assert ItemCode.parse(replace_at(code, index, value)) == expected, inspect(value)
        assert ItemCode.parse(value <> code) == expected, inspect(value)
        assert ItemCode.parse(code <> value) == expected, inspect(value)
      end

      assert ItemCode.parse(code <> "\n") == {:error, :character}
      assert ItemCode.parse("\t" <> code) == {:error, :character}
      assert ItemCode.parse(code <> "\r\n") == {:error, :character}
      assert ItemCode.parse(replace_at(code, 3, "U")) == {:error, :character}
      assert ItemCode.parse(replace_at(code, 3, "u")) == {:error, :character}
      # A no-break space, U+00A0, and a non-breaking hyphen, U+2011.
      assert ItemCode.parse(insert_at(code, 4, " ")) == {:error, :not_ascii}
      assert ItemCode.parse(insert_at(code, 4, "‑")) == {:error, :not_ascii}
    end

    test "refuses a value of other than 16 symbols" do
      [code | _codes] = codes()
      [a, b, c, d] = groups(code)

      for value <- [
            "",
            "-",
            binary_part(code, 0, 15),
            code <> "0",
            code <> code,
            Enum.join([a, b, c, binary_part(d, 0, 3)], "-"),
            Enum.join([a, b, c, d <> "0"], " ")
          ] do
        assert ItemCode.parse(value) == {:error, :length}, inspect(value)
      end
    end

    test "names the first flaw in the order of its reasons" do
      [code | _codes] = codes()
      wrong = replace_at(code, 15, if(:binary.at(code, 15) == ?0, do: "1", else: "0"))

      assert ItemCode.parse(wrong) == {:error, :check}
      assert ItemCode.parse("-" <> wrong) == {:error, :separator}
      assert ItemCode.parse("-" <> binary_part(wrong, 0, 15)) == {:error, :length}
      assert ItemCode.parse("U-" <> binary_part(wrong, 0, 15)) == {:error, :character}
      assert ItemCode.parse("éU-" <> binary_part(wrong, 0, 15)) == {:error, :not_ascii}
      assert ItemCode.parse(<<0xFF>> <> code) == {:error, :not_ascii}
    end

    test "refuses a value that is not a string" do
      [code | _codes] = codes()

      for value <- [nil, 42, :code, String.to_charlist(code), [code], %{code: code}] do
        assert ItemCode.parse(value) == {:error, :not_a_string}
        refute ItemCode.valid?(value)
      end
    end
  end
end
