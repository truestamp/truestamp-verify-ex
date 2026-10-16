# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec.ConstructionsTest do
  # The accepted constructions texts, spec/constructions/<d>.json (SPEC.md 7 and 9). Each file
  # holds a text's exact JCS bytes (spec_files_test.exs checks that form) and is named by their
  # SHA-256, the digest d that section 7.2 checks. The last two describes are the checks
  # section 7.3 asks of every implementation's CI: each SHA-256(0xNN || ...) in the text names
  # the registry's byte and preimage, and the set of rows is the spec's.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @spec_md Path.join(@root, "SPEC.md")
  @dir Path.join(@root, "spec/constructions")
  @files @dir |> Path.join("*") |> Path.wildcard(match_dot: true) |> Enum.sort()
  @external_resource @spec_md
  for file <- @files, do: @external_resource(file)

  defp spec_md, do: File.read!(@spec_md)

  defp read_json(path) do
    {:ok, value} = path |> File.read!() |> StrictJSON.decode()
    value
  end

  defp sha256_hex(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp integer(text), do: text |> String.replace(",", "") |> String.to_integer()

  # Section 7.3 as a whole, and the text it prints, parsed.
  defp section_7_3 do
    [_before, rest] = String.split(spec_md(), "\n### 7.3 The text\n", parts: 2)
    [section, _after] = String.split(rest, "\n### 7.4 ", parts: 2)
    [_prose, block] = String.split(section, "\n```json\n", parts: 2)
    [json, _prose] = String.split(block, "\n```\n", parts: 2)
    {:ok, text} = StrictJSON.decode(json)
    {section, text}
  end

  defp stated_digest(section),
    do: ~r/digest\s+`([0-9a-f]{64})`/ |> Regex.run(section, capture: :all_but_first) |> hd()

  describe "the files" do
    test "are each named by the SHA-256 of their bytes" do
      for file <- @files do
        assert Path.basename(file) == sha256_hex(File.read!(file)) <> ".json", file
      end
    end

    test "are exactly the text 7.3 prints, under the digest, row count and size 7.3 states" do
      {section, text} = section_7_3()
      digest = stated_digest(section)

      [rows, octets] =
        Regex.run(~r/(\d+) rows, ([\d,]+) octets under JCS/, section, capture: :all_but_first)

      jcs = StrictJSON.jcs(text)
      assert sha256_hex(jcs) == digest
      assert map_size(text) == integer(rows)
      assert byte_size(jcs) == integer(octets)

      # CONSTRUCTIONS_ACCEPTED is the digests of these files (section 9), so today it is 7.3's
      # digest alone.
      assert Enum.map(@files, &Path.basename/1) == [digest <> ".json"]
      assert File.read!(Path.join(@dir, digest <> ".json")) == jcs
    end

    test "hold only printable ASCII values with no quote or backslash, as 7.3 says" do
      for file <- @files, {row, value} <- read_json(file) do
        assert value =~ ~r/\A[\x20\x21\x23-\x5b\x5d-\x7e]*\z/, "#{Path.basename(file)}: #{row}"
      end
    end

    test "save the octets 7.3 states in reference mode and with none" do
      {section, text} = section_7_3()

      [reference, none] =
        ~r/Reference mode saves ([\d,]+) octets per proof, and `none` ([\d,]+) more/
        |> Regex.run(section, capture: :all_but_first)
        |> Enum.map(&integer/1)

      [template] =
        Regex.run(~r/the string `(https:[^`]+<d>\.json)`/, spec_md(), capture: :all_but_first)

      url = JSON.encode!(String.replace(template, "<d>", stated_digest(section)))

      # In JCS(proof) the member is "constructions":VALUE, with one comma beside it.
      assert byte_size(StrictJSON.jcs(text)) - byte_size(url) == reference
      assert byte_size(~s("constructions":) <> url <> ",") == none
    end
  end

  # How the text names the preimage of each prefixed hash, read from the text and SPEC.md 4.3
  # and not from prefixes.json: {row, preimage as the text writes it} =>
  # {the registry kind it computes, that kind's preimage as the registry writes it}. In a row
  # named for a record hash, `record` is that kind of record; the key_event the handover row
  # signs is a rotation event; `its 32 bytes` are public_key's; and `p` and `r` are the
  # sibling and the running hash of merkle_path, in the two orders of a node.
  @reading %{
    {"block_hash", "JCS(record)"} => {"block_hash", "JCS(block record)"},
    {"claims_hash", "JCS(claims)"} => {"claims_hash", "JCS(claims)"},
    {"entropy_hash", "JCS(entropy object)"} => {"entropy_hash", "JCS(entropy object)"},
    {"epoch_hash", "JCS(record)"} => {"epoch_hash", "JCS(epoch record)"},
    {"genesis", "JCS(metadata.genesis)"} =>
      {"genesis_previous_block_hash", "JCS(genesis object)"},
    {"handover", "JCS(the key_event without handover_signature)"} =>
      {"handover", "JCS(rotation event without handover_signature)"},
    {"item_hash", "JCS(record)"} => {"item_hash", "JCS(item record)"},
    {"key_event", "its 32 bytes"} => {"key_id", "the 32 key bytes; the hash cut to 4 bytes"},
    {"merkle_path", "start"} => {"merkle_leaf", "the 32 bytes of the leaf value"},
    {"merkle_path", "p || r"} =>
      {"merkle_node", "the 32 bytes of the left child, then of the right"},
    {"merkle_path", "r || p"} =>
      {"merkle_node", "the 32 bytes of the left child, then of the right"},
    {"observation_hash", "JCS(record)"} => {"observation_hash", "JCS(observation record)"},
    {"signature", "JCS(proof)"} => {"proof_hash", "JCS(proof)"}
  }

  describe "every SHA-256(0xNN || ...) in a text" do
    test "names the registry's byte and preimage" do
      # prefixes.json is SPEC.md 4.3's table, row for row (spec_files_test.exs).
      registry = read_json(Path.join(@root, "spec/prefixes.json"))

      for file <- @files do
        found = prefixed_hashes(read_json(file))

        assert found |> Enum.map(fn {row, _byte, preimage} -> {row, preimage} end) |> Enum.sort() ==
                 @reading |> Map.keys() |> Enum.sort(),
               "#{Path.basename(file)}: every prefixed hash is read once, and every reading is used"

        for {row, byte, preimage} <- found do
          {kind, registry_preimage} = Map.fetch!(@reading, {row, preimage})
          assert %{"byte" => ^byte, "hashed" => ^registry_preimage} = registry[kind], row
        end
      end
    end
  end

  describe "every spelling of SHA-256 in a text" do
    test "is SHA-256(0x, or Bitcoin's SHA-256d over a raw transaction or a header" do
      for file <- @files, {row, value} <- read_json(file) do
        for [spelling] <- Regex.scan(~r/SHA-?256d?\s*\(/i, value) do
          assert spelling in ["SHA-256(", "SHA-256d("], "#{row}: #{spelling}"
        end

        for [argument] <- Regex.scan(~r/SHA-256d\(([^)]*)\)/, value, capture: :all_but_first) do
          assert argument in ["raw_transaction", "header"], "#{row}: SHA-256d(#{argument})"
        end
      end
    end
  end

  # Every SHA-256(...) in a text, as {row, byte, preimage}. Each has the form
  # SHA-256(0xNN || P), with P read to the parenthesis that closes it.
  defp prefixed_hashes(text) do
    for {row, value} <- text, opened <- value |> String.split("SHA-256(") |> tl() do
      assert [_, byte, rest] = Regex.run(~r/\A(0x[0-9a-f]{2}) \|\| (.*)\z/s, opened), row
      {row, byte, closing(rest, 0, "")}
    end
  end

  defp closing(")" <> _rest, 0, acc), do: acc
  defp closing(")" <> rest, depth, acc), do: closing(rest, depth - 1, acc <> ")")
  defp closing("(" <> rest, depth, acc), do: closing(rest, depth + 1, acc <> "(")
  defp closing(<<char, rest::binary>>, depth, acc), do: closing(rest, depth, acc <> <<char>>)

  describe "the rows" do
    test "of a text are the rows 7.3 prints" do
      {_section, text} = section_7_3()
      listed = Map.keys(text)

      for file <- @files do
        rows = file |> read_json() |> Map.keys()
        assert {rows -- listed, listed -- rows} == {[], []}, Path.basename(file)
      end
    end

    test "include every row SPEC.md names as a row of 7.3" do
      {_section, text} = section_7_3()
      md = spec_md()

      # The "Row of 7.3" column of every table that has one.
      columns =
        for [_, body] <- Regex.scan(~r/^\|.* \| Row of 7\.3 \|\n\|[-|]+\|\n((?:\|.*\n)+)/m, md),
            line <- String.split(body, "\n", trim: true) do
          line |> String.split(" | ") |> List.last() |> String.trim_trailing("|") |> cell_name()
        end

      # "(row `X`)" and "the `X` row of section 7.3", and "the `X` row" inside section 7.
      [_before, section_7] = String.split(md, "\n## 7. Constructions\n", parts: 2)
      [section_7, _after] = String.split(section_7, "\n## 8. ", parts: 2)

      prose =
        for {pattern, source} <- [
              {~r/\(row `([a-z_]+)`\)/, md},
              {~r/`([a-z_]+)` row of section\s+7\.3/, md},
              {~r/`([a-z_]+)` row\b/, section_7}
            ],
            [_, row] <- Regex.scan(pattern, source),
            do: row

      assert columns != [] and prose != []
      assert Enum.uniq(columns ++ prose) -- Map.keys(text) == []
    end
  end

  defp cell_name(cell), do: cell |> String.trim() |> String.trim("`")
end
