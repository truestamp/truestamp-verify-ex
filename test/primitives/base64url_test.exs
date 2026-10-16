# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Base64URLTest do
  # B64U32 and B64U64 (SPEC.md 2.4): vectors/corpus/base64url.json, then each part of the
  # classes' rule: length, alphabet, the last character's unused bits, and matching the
  # whole string.
  use ExUnit.Case, async: true

  import Bitwise, only: [<<<: 2]

  alias Truestamp.Verify.Base64URL
  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @corpus Path.join(@root, "vectors/corpus/base64url.json")
  @external_resource @corpus
  @classes %{"B64U32" => :b64u32, "B64U64" => :b64u64}
  @alphabet ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

  defp corpus do
    {:ok, entries} = @corpus |> File.read!() |> StrictJSON.decode()
    entries
  end

  describe "the corpus" do
    test "decodes each canonical spelling to its octets, and encodes them back" do
      canonical = Enum.filter(corpus(), &Map.has_key?(&1, "octets"))
      assert length(canonical) == 8

      for %{"class" => class, "octets" => octets, "text" => text} <- canonical do
        bytes = Base.decode16!(octets, case: :lower)
        assert Base64URL.decode(@classes[class], text) == {:ok, bytes}, text
        assert Base64URL.encode(bytes) == text
        assert Base64URL.matches?(@classes[class], text)
      end
    end

    test "refuses each spelling the corpus marks refused, whatever its flaw" do
      refused = Enum.filter(corpus(), &Map.has_key?(&1, "refused"))
      flaws = refused |> Enum.map(& &1["refused"]) |> Enum.uniq() |> Enum.sort()

      assert flaws ==
               Enum.sort(~w(padded standard_alphabet unused_bits trailing_newline embedded_crlf
                            leading_space too_short too_long other_character empty))

      for %{"class" => class, "text" => text} = entry <- refused do
        assert Base64URL.decode(@classes[class], text) == :error, inspect(entry)
        refute Base64URL.matches?(@classes[class], text)
      end

      # Where a lax decoder reads a flawed spelling as a canonical one, that canonical
      # spelling is itself taken.
      for %{"class" => class, "canonical" => canonical} <- refused do
        assert {:ok, _octets} = Base64URL.decode(@classes[class], canonical)
      end
    end

    test "has flaws a stock decoder lets through, which is why the class is matched first" do
      entry = Enum.find(corpus(), &(&1["refused"] == "unused_bits" and &1["class"] == "B64U32"))
      {:ok, canonical} = Base64URL.decode(:b64u32, entry["canonical"])

      # Elixir's decoder ignores the unused bits (SPEC.md 2.4).
      assert Base.url_decode64(entry["text"], padding: false) == {:ok, canonical}
      assert Base64URL.decode(:b64u32, entry["text"]) == :error
    end
  end

  describe "the rule of each class" do
    test "decodes to 32 and to 64 octets" do
      assert Base64URL.octets(:b64u32) == 32
      assert Base64URL.octets(:b64u64) == 64

      for _ <- 1..200, class <- [:b64u32, :b64u64] do
        bytes = :crypto.strong_rand_bytes(Base64URL.octets(class))
        text = Base64URL.encode(bytes)
        assert Base64URL.decode(class, text) == {:ok, bytes}
        # Each class takes only its own length.
        other = if class == :b64u32, do: :b64u64, else: :b64u32
        assert Base64URL.decode(other, text) == :error
      end
    end

    test "takes exactly the lengths 43 and 86, not one less or one more" do
      assert Base64URL.matches?(:b64u32, String.duplicate("A", 43))
      refute Base64URL.matches?(:b64u32, String.duplicate("A", 42))
      refute Base64URL.matches?(:b64u32, String.duplicate("A", 44))
      assert Base64URL.matches?(:b64u64, String.duplicate("A", 86))
      refute Base64URL.matches?(:b64u64, String.duplicate("A", 85))
      refute Base64URL.matches?(:b64u64, String.duplicate("A", 87))
    end

    test "takes exactly the last characters whose unused bits are zero" do
      # 32 octets leave 2 unused bits in the 43rd character, 64 octets leave 4 in the 86th.
      for {class, length, unused} <- [{:b64u32, 43, 2}, {:b64u64, 86, 4}] do
        taken =
          for c <- @alphabet,
              Base64URL.matches?(class, String.duplicate("A", length - 1) <> <<c>>),
              do: c

        expected =
          for {c, index} <- Enum.with_index(@alphabet), rem(index, 1 <<< unused) == 0, do: c

        assert taken == expected
        assert length(taken) == div(64, 1 <<< unused)
      end
    end

    test "takes every character of the url alphabet in the leading positions, and no other" do
      for c <- @alphabet do
        assert Base64URL.matches?(:b64u32, <<c>> <> String.duplicate("A", 42)), <<c>>
      end

      for c <- 0..255, c not in @alphabet do
        refute Base64URL.matches?(:b64u32, <<c>> <> String.duplicate("A", 42)), inspect(c)
      end
    end

    test "matches the whole string, so a final newline is refused" do
      text = Base64URL.encode(:crypto.strong_rand_bytes(32))
      refute Base64URL.matches?(:b64u32, text <> "\n")
      refute Base64URL.matches?(:b64u32, "\n" <> text)
      refute Base64URL.matches?(:b64u32, text <> "\r\n")
      refute Base64URL.matches?(:b64u32, text <> <<0>>)
    end

    test "refuses what is not a string" do
      for term <- [nil, 1, :b64u32, [], %{}, String.to_charlist(String.duplicate("A", 43))] do
        refute Base64URL.matches?(:b64u32, term)
        assert Base64URL.decode(:b64u32, term) == :error
      end
    end
  end

  describe "agreement with spec/encodings.json" do
    test "each class's pattern and octet count equal the file's" do
      {:ok, encodings} =
        @root |> Path.join("spec/encodings.json") |> File.read!() |> StrictJSON.decode()

      for {name, class} <- @classes do
        assert Base64URL.pattern(class) == encodings[name]["pattern"]
        assert Base64URL.octets(class) == encodings[name]["decodes_to_octets"]
      end
    end
  end
end
