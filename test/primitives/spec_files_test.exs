# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec.DatasTest do
  # The files under spec/ are SPEC.md's data. These tests hold each one to the text: every file
  # reads under the parsing rules and is in canonical form, every table agrees with SPEC.md's,
  # the key values are recomputed, and schema.json and value-classes.json are
  # run over well-formed sample proofs and their mutations.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.Test.{Samples, SchemaSubset, StrictJSON}

  @root Truestamp.Verify.Test.Verification.root()
  @spec_md Path.join(@root, "SPEC.md")
  @spec_dir Path.join(@root, "spec")
  @constructions_dir Path.join(@spec_dir, "constructions")
  @spec_files @spec_dir
              |> Path.join("**/*")
              |> Path.wildcard(match_dot: true)
              |> Enum.filter(&File.regular?/1)
              |> Enum.sort()
  @external_resource @spec_md

  # The root of the empty tree, SHA-256 of zero bytes (SPEC.md 5.4).
  @empty_root Base.encode16(:crypto.hash(:sha256, ""), case: :lower)
  for file <- @spec_files, do: @external_resource(file)

  defp spec_md, do: File.read!(@spec_md)

  defp read(name) do
    {:ok, value} = @root |> Path.join("spec/" <> name) |> File.read!() |> StrictJSON.decode()
    value
  end

  # The rows of the Markdown table that follows `header` in SPEC.md, as lists of cells.
  defp table_after(header) do
    [_before, rest] = String.split(spec_md(), header <> "\n", parts: 2)

    rest
    |> String.split("\n")
    |> Enum.drop(1)
    |> Enum.take_while(&String.starts_with?(&1, "|"))
    |> Enum.map(fn row ->
      row |> String.trim("|") |> String.split(" | ") |> Enum.map(&String.trim/1)
    end)
  end

  defp backticked(text), do: ~r/`([^`]+)`/ |> Regex.scan(text) |> Enum.map(&List.last/1)

  defp unmark(text), do: text |> String.replace("`", "") |> String.trim()

  describe "the strict reader the other tests rely on" do
    test "refuses what the parsing rules refuse" do
      for {text, reason} <- [
            {~s({"a":1,"a":2}), :duplicate_name},
            {~s({"n":9007199254740992}), :number},
            {~s({"n":-9007199254740992}), :number},
            {~s({"n":9007199254740992.0}), :number},
            {~s({"n":1e16}), :number},
            {~s({"n":1e400}), :number},
            {~s({"s":"\\ud800"}), :syntax},
            {<<0xEF, 0xBB, 0xBF>> <> "{}", :syntax},
            {"{} {}", :syntax},
            {<<"{\"s\":\"", 0xFF, "\"}">>, :invalid_utf8},
            {String.duplicate("[", 33) <> String.duplicate("]", 33), :depth}
          ] do
        assert StrictJSON.decode(text) == {:error, reason}, inspect(text)
      end

      assert StrictJSON.decode(String.duplicate(" ", 262_145)) == {:error, :input_too_large}
    end

    test "accepts what they allow" do
      assert StrictJSON.decode(~s({"n":9007199254740991})) ==
               {:ok, %{"n" => 9_007_199_254_740_991}}

      assert StrictJSON.decode(~s({"n":1e21})) == {:ok, %{"n" => 1.0e21}}
      # J5 judges the binary64 value, whichever way the number is written.
      assert StrictJSON.decode(~s({"n":1000000000000000000000})) == {:ok, %{"n" => 1.0e21}}
      assert StrictJSON.decode(~s({"n":999999999999999999999})) == {:ok, %{"n" => 1.0e21}}
      assert StrictJSON.decode(~s({"n":1e-400})) == {:ok, %{"n" => 0.0}}
      assert {:ok, _} = StrictJSON.decode(String.duplicate("[", 32) <> String.duplicate("]", 32))
    end

    test "writes JCS for an object of printable ASCII strings, and refuses any other value" do
      assert StrictJSON.jcs(%{"b" => ~s(x"y), "a" => "\\", "B" => ""}) ==
               ~S({"B":"","a":"\\","b":"x\"y"})

      assert StrictJSON.jcs(%{}) == "{}"

      for value <- [1, %{}] do
        assert_raise FunctionClauseError, fn -> StrictJSON.jcs(%{"a" => value}) end
      end

      for value <- ["caf\u00e9", "a\nb"] do
        assert_raise ArgumentError, fn -> StrictJSON.jcs(%{"a" => value}) end
        assert_raise ArgumentError, fn -> StrictJSON.jcs(%{value => "a"}) end
      end
    end
  end

  describe "every file under spec/" do
    test "is one of the files section 9 lists, and every file it lists is here" do
      listed =
        "| File | Holds |" |> table_after() |> Enum.map(fn [file, _holds] -> unmark(file) end)

      assert Enum.map(@spec_files, &Path.relative_to(&1, @spec_dir)) == Enum.sort(listed)
    end

    for file <- @spec_files do
      @file_path file
      test "#{Path.relative_to(file, @spec_dir)} reads under the parsing rules, in canonical ASCII form" do
        bytes = File.read!(@file_path)
        assert {:ok, value} = StrictJSON.decode(bytes)
        assert bytes =~ ~r/\A[\x20-\x7e\n]*\z/
        assert canonical(@file_path, value) == bytes
      end
    end
  end

  # Section 9: a constructions text is its exact JCS bytes, and every other file is indented.
  defp canonical(path, value) do
    if Path.dirname(path) == @constructions_dir,
      do: StrictJSON.jcs(value),
      else: StrictJSON.canonical(value)
  end

  describe "prefixes.json" do
    test "is the table of section 4.3, row for row" do
      signers = %{
        "never" => nil,
        "yes, by the active key" => "active_key",
        "yes, by the key the chain assigns" => "chain_assigned_key",
        "yes, by the outgoing key" => "outgoing_key"
      }

      rows =
        for [byte, family, construction, hashed, signed] <-
              table_after("| Prefix | Family | Construction | Hashed after the prefix | Signed |") do
          %{
            "byte" => unmark(byte),
            "family" => family,
            "construction" => unmark(construction),
            "hashed" => unmark(hashed),
            "signer" => Map.fetch!(signers, signed)
          }
        end

      from_file =
        for {kind, entry} <- read("prefixes.json") do
          assert entry["signed"] == Map.has_key?(entry, "signer")
          # Each entry is keyed by its construction's name, Merkle ones prefixed.
          name = String.replace(entry["construction"], " ", "_")
          assert kind == if(entry["family"] == "Merkle", do: "merkle_" <> name, else: name)

          %{
            "byte" => entry["byte"],
            "family" => entry["family"],
            "construction" => entry["construction"],
            "hashed" => entry["hashed"],
            "signer" => entry["signer"]
          }
        end

      assert length(rows) == 13
      assert Enum.sort_by(from_file, & &1["byte"]) == Enum.sort_by(rows, & &1["byte"])
    end

    test "each byte appears once, and each kind is a family's lowest free low nibble in turn" do
      bytes = read("prefixes.json") |> Map.values() |> Enum.map(& &1["byte"])
      assert bytes == Enum.uniq(bytes)

      bytes
      |> Enum.map(fn "0x" <> hex -> String.to_integer(hex, 16) end)
      |> Enum.group_by(&(&1 >>> 4), &(&1 &&& 0xF))
      |> Enum.each(fn {family, lows} ->
        assert Enum.sort(lows) == Enum.to_list(0..(length(lows) - 1)), "family #{family}"
      end)
    end

    test "the families follow the processing order with no gap, and 4.2 names the next one" do
      families =
        read("prefixes.json")
        |> Map.values()
        |> Enum.map(fn %{"byte" => "0x" <> hex, "family" => family} ->
          {String.to_integer(hex, 16) >>> 4, family}
        end)
        |> Enum.uniq()
        |> Enum.sort()

      assert Enum.map(families, &elem(&1, 1)) ==
               ~w(Merkle Items Entropy Blocks Epochs Proofs Keys)

      assert Enum.map(families, &elem(&1, 0)) == Enum.to_list(0..(length(families) - 1))

      next = Integer.to_string(length(families), 16)
      assert spec_md() =~ "lowest free high nibble (`0x#{next}_` next)"
    end

    test "within a family, a value comes before the record that contains it" do
      bytes = Map.new(read("prefixes.json"), fn {kind, %{"byte" => byte}} -> {kind, byte} end)

      for {inner, outer} <- [
            {"claims_hash", "item_hash"},
            {"entropy_hash", "observation_hash"},
            {"genesis_previous_block_hash", "block_hash"},
            {"key_id", "handover"},
            {"prerotation_commitment", "handover"}
          ] do
        assert bytes[inner] < bytes[outer], "#{inner} before #{outer}"
      end
    end
  end

  describe "constants.json" do
    test "holds every constant of section 9 but SMALL_ORDER_KEYS, with its value" do
      rows = table_after("| Constant | Value |")

      from_spec =
        Enum.flat_map(rows, fn [names, value] ->
          names = String.split(names, ", ")
          Enum.zip(names, spec_values(names, value))
        end)
        |> Map.new()

      constants = read("constants.json")

      assert Map.keys(from_spec) -- ["SMALL_ORDER_KEYS"] ==
               Enum.sort(Map.keys(constants))

      for {name, value} <- constants do
        assert from_spec[name] == value, name
      end
    end

    test "VECTOR_KEY is the Ed25519 public key of the seed of 32 bytes of 0x42" do
      {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<0x42>>, 32))
      assert read("constants.json")["VECTOR_KEY"] == Base.encode16(public, case: :lower)
    end
  end

  describe "the sizes of section 3.8" do
    test "hold the table's own arithmetic, and the bounds for items that follow from it" do
      rows =
        Map.new(
          table_after(
            "| Proof | Typical, full | Typical, reference | Typical, none | Worst, full |"
          ),
          fn [proof | sizes] -> {proof, Enum.map(sizes, &octets/1)} end
        )

      assert Map.keys(rows) ==
               Enum.sort(~w(item entropy_nist entropy_stellar entropy_bitcoin block beacon))

      # The constructions text in full is 8,597 octets longer than its reference, and the
      # reference 140 longer than none, whatever the proof.
      for {proof, [full, reference, none, _worst]} <- rows do
        assert full - reference == 8_597, proof
        assert reference - none == 140, proof
      end

      text = String.replace(spec_md(), ~r/\s+/, " ")

      [claims] =
        Regex.run(~r/\*\*Worst:\*\* ([0-9,]+)-octet claims/, text, capture: :all_but_first)

      [full, reference, none, staging, marker, worst_staging] =
        Regex.run(
          ~r/For items, the served size is at most ([0-9,]+) \+ \|JCS\(claims\)\| octets in full mode \(([0-9,]+) by reference, ([0-9,]+) with none\), plus at most ([0-9,]+) octets for `([^`]+)`\. The worst staging item is ([0-9,]+) octets, under MAX_DOCUMENT_OCTETS/,
          text,
          capture: :all_but_first
        )

      [_full, _reference, _none, worst] = rows["item"]
      claims = octets(claims)
      assert claims == 20_480

      # Each bound is the worst item of its mode less its claims.
      assert octets(full) == worst - claims
      assert octets(reference) == worst - 8_597 - claims
      assert octets(none) == worst - 8_597 - 140 - claims

      assert octets(staging) == byte_size(marker)
      assert marker == ~s("environment":"staging",)
      assert octets(worst_staging) == worst + 24
      assert octets(worst_staging) <= read("constants.json")["MAX_DOCUMENT_OCTETS"]
    end
  end

  defp octets(text), do: text |> String.replace(",", "") |> String.to_integer()

  # The values a section 9 row gives its names: numbers with thousands separators, the hex
  # after `=` for MAX_INTEGER, a backticked hex key, or nil for the row that names a file.
  defp spec_values([_name], value) do
    cond do
      value =~ ~r/= (\d+)/ ->
        [~r/= (\d+)/ |> Regex.run(value) |> List.last() |> String.to_integer()]

      value =~ ~r/^`[0-9a-f]{64}`/ ->
        [value |> backticked() |> hd()]

      value =~ ~r/^\d/ ->
        [
          ~r/^\d{1,3}(?:,\d{3})*/
          |> Regex.run(value)
          |> hd()
          |> String.replace(",", "")
          |> String.to_integer()
        ]

      true ->
        [nil]
    end
  end

  defp spec_values(names, value) do
    numbers =
      value
      |> String.split(", ")
      |> Enum.map(&(&1 |> String.replace(",", "") |> String.to_integer()))

    assert length(numbers) == length(names)
    numbers
  end

  describe "reason-codes.json" do
    test "is the table of section 12.1, row for row and in its order, with the count 12.1 states" do
      rows =
        "| Code | Step | Status | Meaning |"
        |> table_after()
        |> Enum.map(fn [code, step, status, meaning] ->
          %{
            "code" => unmark(code),
            "meaning" => unmark(meaning),
            "status" => status,
            "step" => step
          }
        end)

      [count] =
        Regex.run(~r/The table lists the codes in step order\. (\d+) codes\./, spec_md(),
          capture: :all_but_first
        )

      assert length(rows) == String.to_integer(count)
      assert Enum.map(read("reason-codes.json"), &Map.delete(&1, "sub_reasons")) == rows

      codes = Enum.map(rows, & &1["code"])
      assert codes == Enum.uniq(codes)
      for code <- codes, do: assert(code =~ ~r/\A[a-z]+(?:_[a-z]+)*\z/, code)
    end

    test "gives the sub_reasons of sections 10.1 and 10.2, step 3, in their order, on malformed_json and invalid_envelope alone" do
      [_before, parse] = String.split(spec_md(), "- J2 to J6 are step PARSE.", parts: 2)
      [parse, _after] = String.split(parse, "(J6).", parts: 2)
      [_before, envelope] = String.split(spec_md(), "**3. ENVELOPE.**", parts: 2)
      [envelope, _after] = String.split(envelope, "The message is", parts: 2)

      parse_names = backticked(parse) -- ["malformed_json", "sub_reason"]

      envelope_names =
        ~r/^\d\. `([a-z_]+)`:/m |> Regex.scan(envelope) |> Enum.map(&List.last/1)

      assert parse_names == ~w(syntax invalid_utf8 lone_surrogate duplicate_name number depth)
      assert envelope_names == ~w(document proof signature alg public_key value)

      sub_reasons =
        for %{"code" => code} = row <- read("reason-codes.json"),
            Map.has_key?(row, "sub_reasons"),
            into: %{},
            do: {code, row["sub_reasons"]}

      assert sub_reasons == %{
               "malformed_json" => parse_names,
               "invalid_envelope" => envelope_names
             }

      # Each sub_reason a case of cases.json gives is one its code lists, and each listed
      # sub_reason has a case.
      cases = @root |> Path.join("vectors/cases.json") |> StrictJSON.read_data!()

      given =
        for %{"expected" => %{"code" => code, "sub_reason" => sub}} <- cases,
            uniq: true,
            do: {code, sub}

      listed = for {code, names} <- sub_reasons, name <- names, do: {code, name}
      assert Enum.sort(given) == Enum.sort(listed)
    end

    test "lists the codes in step order, by the first step each names, with the codes of any step last" do
      steps = steps()

      positions =
        for %{"step" => step} <- read("reason-codes.json") do
          if String.starts_with?(step, "any step"),
            do: map_size(steps),
            else: Map.fetch!(steps, step |> step_names() |> hd())
        end

      assert positions == Enum.sort(positions)
    end

    test "names only the steps of section 10.2, and gives each step of the bare rejection one bare code" do
      steps = steps()
      codes = read("reason-codes.json")

      for %{"code" => code, "step" => step} <- codes do
        names = step_names(step)
        assert names -- Map.keys(steps) == [], "#{code}: #{step}"
      end

      [first, last] =
        Regex.run(~r/A failure at steps (\d+) to (\d+) is a bare rejection\./, spec_md(),
          capture: :all_but_first
        )

      bare = for %{"status" => "bare", "step" => step} <- codes, do: Map.fetch!(steps, step)
      assert bare == Enum.to_list(String.to_integer(first)..String.to_integer(last))

      # A row with the status `pass` carries no code (section 10.5), so no code has it.
      statuses =
        "| Status | Meaning |"
        |> table_after()
        |> Enum.map(fn [status, _meaning] -> unmark(status) end)

      assert "pass" in statuses

      for %{"code" => code, "status" => status} <- codes, status != "bare" do
        assert status in (statuses -- ["pass"]), code
      end
    end

    test "gives each code a step of section 10.2 names with `else` that step" do
      steps = steps()
      steps_of = Map.new(read("reason-codes.json"), &{&1["code"], step_names(&1["step"])})
      [_before, section] = String.split(spec_md(), "\n### 10.2 Steps\n", parts: 2)
      [section, _after] = String.split(section, "\n### 10.3 ", parts: 2)

      paragraphs =
        Regex.scan(~r/^\*\*(\d+)\. ([A-Z_]+)\b(.*?)(?=^\*\*\d+\. |\z)/ms, section,
          capture: :all_but_first
        )

      assert Enum.map(paragraphs, &Enum.at(&1, 1)) ==
               steps |> Enum.sort_by(&elem(&1, 1)) |> Enum.map(&elem(&1, 0))

      named =
        for [number, name, body] <- paragraphs,
            [code] <- Regex.scan(~r/else `([a-z_]+)`/, body, capture: :all_but_first) do
          assert Map.fetch!(steps, name) == String.to_integer(number), name
          assert name in Map.fetch!(steps_of, code), "#{code} at #{name}"
          code
        end

      assert length(Enum.uniq(named)) >= 5
    end

    test "agrees with every status and code SPEC.md writes together" do
      status_of = Map.new(read("reason-codes.json"), &{&1["code"], &1["status"]})

      pairs =
        ~r/`(pass|fail|skip|warn|info) ([a-z_]+)`/
        |> Regex.scan(spec_md(), capture: :all_but_first)
        |> Enum.uniq()

      assert length(pairs) >= 10

      for [status, code] <- pairs do
        assert Map.fetch!(status_of, code) == status, "#{status} #{code}"
      end
    end

    test "mentions sub_reason in exactly the meanings of the codes that 12.1 and the gate give one" do
      md = spec_md()

      [bullet] =
        Regex.run(~r/`sub_reason` is present for (.*?), and absent otherwise/s, md,
          capture: :all_but_first
        )

      [gate] =
        Regex.run(~r/with `sub_reason` only for (.*?), and no report/s, md,
          capture: :all_but_first
        )

      with_sub_reason =
        for %{"code" => code, "meaning" => meaning} <- read("reason-codes.json"),
            meaning =~ "sub_reason",
            do: code

      assert with_sub_reason == backticked(bullet)
      assert with_sub_reason == backticked(gate)
    end
  end

  # The steps of section 10.2's table, by name.
  defp steps do
    "| Step | Name | What it checks |"
    |> table_after()
    |> Map.new(fn [number, name, _checks] -> {name, String.to_integer(number)} end)
  end

  # The step names a cell of 12.1's Step column gives: step names, or one of its two phrases.
  defp step_names("any step after a failure"), do: []

  defp step_names("any step from " <> _ = cell) do
    [name] = Regex.run(~r/\Aany step from ([A-Z_]+) on\z/, cell, capture: :all_but_first)
    [name]
  end

  defp step_names(cell), do: String.split(cell, ", ")

  describe "exit-codes.json" do
    test "is the table of section 12.2, row for row, numbered from 0 with no gap" do
      rows =
        "| Code | The run |"
        |> table_after()
        |> Enum.map(fn [code, run] ->
          %{"code" => String.to_integer(code), "run" => unmark(run)}
        end)

      assert read("exit-codes.json") == rows
      assert Enum.map(rows, & &1["code"]) == Enum.to_list(0..(length(rows) - 1))
    end

    test "gives each label of section 10.5 one code, and each bare code of reason-codes.json one" do
      runs = table_after("| Code | The run |")

      labels =
        "| `label` | When | What it says |"
        |> table_after()
        |> Enum.map(fn [label, _when, _says] -> unmark(label) end)

      labelled = for [_code, "label `" <> label] <- runs, do: String.trim_trailing(label, "`")
      assert Enum.sort(labelled) == Enum.sort(labels)

      bare = for %{"code" => code, "status" => "bare"} <- read("reason-codes.json"), do: code

      # A run names a bare code by itself, or as the one exception of "a bare rejection other
      # than ...". Every code a run names is bare.
      assert runs
             |> Enum.flat_map(fn [_code, run] -> backticked(run) end)
             |> Enum.uniq()
             |> Kernel.--(labels)
             |> Kernel.--(bare) == []

      for code <- bare do
        exits =
          for [exit, run] <- runs,
              run == "`#{code}`" or
                (String.starts_with?(run, "a bare rejection other than") and
                   code not in backticked(run)),
              do: exit

        assert length(exits) == 1, "#{code}: #{inspect(exits)}"
      end
    end
  end

  @p Integer.pow(2, 255) - 19

  describe "small-order-keys.json" do
    test "holds the eight canonical encodings of the points of order 1, 2, 4 and 8, and two sign-bit variants" do
      keys = read("small-order-keys.json")
      assert length(keys) == 10

      assert keys |> Enum.map(& &1["hex"]) |> Enum.uniq() |> length() == 10

      assert keys
             |> Enum.filter(& &1["sign_bit_variant"])
             |> Enum.map(& &1["order"])
             |> Enum.sort() ==
               [1, 2]

      canonical =
        for entry <- keys do
          assert %{"hex" => hex, "order" => order, "sign_bit_variant" => variant} = entry
          assert map_size(entry) == 3
          bytes = Base.decode16!(hex, case: :lower)
          {point, negative_zero?} = decode_point(bytes)
          assert point_order(point) == order, hex
          assert negative_zero? == variant, hex

          if variant do
            assert {x, _y} = point
            assert x == 0

            assert encode_point(point) ==
                     bytes
                     |> :binary.bin_to_list()
                     |> List.update_at(31, &(&1 &&& 0x7F))
                     |> :binary.list_to_bin()

            nil
          else
            assert encode_point(point) == bytes
            point
          end
        end
        |> Enum.reject(&is_nil/1)

      # The small-order points form a subgroup of exactly eight, so eight distinct ones are all.
      assert length(Enum.uniq(canonical)) == 8

      assert canonical |> Enum.map(&point_order/1) |> Enum.frequencies() == %{
               1 => 1,
               2 => 1,
               4 => 2,
               8 => 4
             }
    end
  end

  defp modpow(base, exp, mod), do: :crypto.mod_pow(base, exp, mod) |> :binary.decode_unsigned()
  defp inv(x), do: modpow(Integer.mod(x, @p), @p - 2, @p)
  defp d, do: Integer.mod(-121_665 * inv(121_666), @p)

  defp decode_point(<<bytes::binary-size(32)>>) do
    n = :binary.decode_unsigned(bytes, :little)
    sign = n >>> 255
    y = n &&& Integer.pow(2, 255) - 1
    assert y < @p
    u = Integer.mod(y * y - 1, @p)
    v = Integer.mod(d() * y * y + 1, @p)
    x2 = Integer.mod(u * inv(v), @p)
    x = modpow(x2, div(@p + 3, 8), @p)

    x =
      if Integer.mod(x * x, @p) == x2,
        do: x,
        else: Integer.mod(x * modpow(2, div(@p - 1, 4), @p), @p)

    assert Integer.mod(x * x, @p) == x2, "not on the curve"
    x = if x != 0 and (x &&& 1) != sign, do: @p - x, else: x
    {{x, y}, x == 0 and sign == 1}
  end

  defp encode_point({x, y}),
    do: :binary.encode_unsigned(y ||| (x &&& 1) <<< 255, :little) |> pad32()

  defp pad32(bytes), do: bytes <> :binary.copy(<<0>>, 32 - byte_size(bytes))

  defp add({x1, y1}, {x2, y2}) do
    t = Integer.mod(d() * x1 * x2 * y1 * y2, @p)

    {Integer.mod((x1 * y2 + y1 * x2) * inv(1 + t), @p),
     Integer.mod((y1 * y2 + x1 * x2) * inv(1 - t), @p)}
  end

  defp point_order(point) do
    Enum.reduce_while([1, 2, 4, 8], point, fn order, multiple ->
      if multiple == {0, 1}, do: {:halt, order}, else: {:cont, add(multiple, multiple)}
    end)
  end

  describe "encodings.json and networks.json" do
    test "the classes and patterns are those of section 2.4" do
      rows = table_after("| Class | Pattern or rule | Used for |")
      encodings = read("encodings.json")

      names =
        rows |> Enum.flat_map(fn [names | _] -> String.split(names, ", ") end) |> Enum.sort()

      assert names == Enum.sort(Map.keys(encodings))

      for [name, rule, _used] <- rows,
          name in ~w(HEX64 KID HEXBYTES B64U32 B64U64 TIME NISTHEX UUID7) do
        assert encodings[name]["pattern"] == rule |> backticked() |> hd(), name
      end

      assert encodings["NISTTIME"]["pattern"] ==
               String.replace(encodings["TIME"]["pattern"], "Z", "\\.[0-9]{3}Z")

      assert encodings["INT"]["maximum"] == read("constants.json")["MAX_INTEGER"]
    end

    test "every other member of a class agrees with section 2.4 and the other files" do
      encodings = read("encodings.json")
      constants = read("constants.json")
      rows = table_after("| Class | Pattern or rule | Used for |")
      [[_, _, hexbytes]] = Enum.filter(rows, &(hd(&1) == "HEXBYTES"))
      [[_, time, _]] = Enum.filter(rows, &(hd(&1) == "TIME"))

      caps =
        ~r/`(\w+)` \(at most ([\d,]+)/
        |> Regex.scan(hexbytes)
        |> Map.new(fn [_, member, n] ->
          {member, String.to_integer(String.replace(n, ",", ""))}
        end)

      assert encodings["HEXBYTES"]["caps_in_octets"] == caps

      assert caps == %{
               "raw_transaction" => constants["RAW_TX_MAX_OCTETS"],
               "txoutproof" => constants["TXOUTPROOF_MAX_OCTETS"]
             }

      assert encodings["B64U32"]["decodes_to_octets"] == 32
      assert encodings["B64U64"]["decodes_to_octets"] == 64
      assert time =~ "format(parse(s)) = s"
      assert for({name, %{"round_trip" => true}} <- encodings, do: name) == ["NISTTIME", "TIME"]
      assert encodings["INT"]["minimum"] == 0

      assert ["schema.json", "/$defs/MERKLE_PROOF"] =
               String.split(encodings["MERKLE_PROOF"]["schema"], "#")

      assert Map.has_key?(read("schema.json")["$defs"], "MERKLE_PROOF")
    end

    test "the ASCII classes admit exactly the printable characters but the quote and backslash" do
      for {name, max} <- [{"ASCII128", 128}, {"ASCII16", 16}] do
        regex = Regex.compile!("\\A" <> read("encodings.json")[name]["pattern"] <> "\\z")

        for c <- 0..127 do
          expected = c in 0x20..0x7E and c not in [?", ?\\]
          assert Regex.match?(regex, <<c>>) == expected, "#{name} #{c}"
        end

        assert Regex.match?(regex, String.duplicate("a", max))
        refute Regex.match?(regex, String.duplicate("a", max + 1))
        refute Regex.match?(regex, "")
      end
    end

    test "the network names and environments are those of section 2.4" do
      rows = table_after("| Class | Pattern or rule | Used for |")
      [[_, network, _]] = Enum.filter(rows, &(hd(&1) == "NETWORK"))
      [stellar, bitcoin] = network |> String.split(" (never") |> hd() |> String.split("; ")

      assert read("networks.json") == %{
               "stellar" => backticked(stellar),
               "bitcoin" => backticked(bitcoin)
             }

      assert read("encodings.json")["NETWORK"]["values_by_chain"] == read("networks.json")

      [[_, env, _]] = Enum.filter(rows, &(hd(&1) == "ENV"))
      assert read("encodings.json")["ENV"]["values"] == backticked(env)
    end

    test "network-pins.json is section 9's table of default pins, a network of each chain" do
      table =
        Map.new(table_after("| E_v | Commitment pins | Entropy pins |"), fn [e_v, c, e] ->
          {e_v |> backticked() |> hd(), %{"commitment" => pins(c), "entropy" => pins(e)}}
        end)

      assert read("network-pins.json") == table
      environments = ["prod" | read("encodings.json")["ENV"]["values"]]
      assert Enum.sort(Map.keys(table)) == Enum.sort(environments)
      networks = read("networks.json")

      for {_e_v, row} <- table, {_kind, chains} <- row do
        assert Enum.sort(Map.keys(chains)) == Enum.sort(Map.keys(networks))
        assert Enum.all?(chains, fn {chain, net} -> net in Map.fetch!(networks, chain) end)
      end

      assert table["prod"]["commitment"] == Map.new(networks, fn {c, [n | _]} -> {c, n} end)
      assert table["prod"]["entropy"] == table["prod"]["commitment"]
    end
  end

  # A cell of section 9's table of default pins, such as "Stellar `public`, Bitcoin
  # `mainnet`", as a map from the chain's name to its network.
  defp pins(cell) do
    ~r/(\w+) `(\w+)`/
    |> Regex.scan(cell, capture: :all_but_first)
    |> Map.new(fn [chain, network] -> {String.downcase(chain), network} end)
  end

  describe "schema.json" do
    test "uses only the keywords section 9 lists, refers only into $defs, and closes every object" do
      [_, paragraph] = String.split(spec_md(), "**The schema.**", parts: 2)

      [listed, _rest] =
        paragraph
        |> String.split("\n\n", parts: 2)
        |> hd()
        |> String.split("keywords", parts: 2)
        |> List.last()
        |> String.split("boolean schemas", parts: 2)

      listed = listed |> backticked() |> Enum.reject(&(&1 in ["#/$defs", "false"]))
      assert Enum.sort(listed) == Enum.sort(SchemaSubset.keywords())

      schema = read("schema.json")
      assert Enum.sort(schema_keywords(schema)) -- listed == []
      assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

      for {key, value} <- schema_entries(schema), key == "$ref" do
        assert "#/$defs/" <> name = value
        assert Map.has_key?(schema["$defs"], name), value
      end

      for {key, value} <- schema_entries(schema),
          key == "additionalProperties",
          do: assert(value == false)
    end

    test "writes the environments, the ASCII limits and the reference URL as the other files and SPEC.md do" do
      defs = read("schema.json")["$defs"]
      encodings = read("encodings.json")
      assert defs["ENV"]["enum"] == encodings["ENV"]["values"]
      assert defs["INT"]["minimum"] == encodings["INT"]["minimum"]

      for {name, max} <- [{"ASCII128", 128}, {"ASCII16", 16}] do
        assert {defs[name]["minLength"], defs[name]["maxLength"]} == {1, max}, name
        assert String.ends_with?(encodings[name]["pattern"], "{1,#{max}}"), name
      end

      [[_, reference, _]] =
        Enum.filter(
          table_after("| Mode | `proof.constructions` | Digest d checked |"),
          &(hd(&1) == "reference")
        )

      ["\\A" <> _ = pattern] =
        reference |> backticked() |> Enum.filter(&String.starts_with?(&1, "\\A"))

      expected = pattern |> String.replace_prefix("\\A", "^") |> String.replace_suffix("\\z", "$")
      assert defs["CONSTRUCTIONS"]["then"]["pattern"] == expected
    end

    test "writes every pattern between ^ and $, guarded by an exact length or against newlines" do
      for {pattern, node} <- patterns(read("schema.json")), pattern != "\\n" do
        assert String.starts_with?(pattern, "^") and String.ends_with?(pattern, "$"), pattern

        guarded? =
          node["not"] == %{"pattern" => "\\n"} or
            (node["minLength"] != nil and node["minLength"] == node["maxLength"])

        assert guarded?, pattern
      end
    end

    test "writes each class of encodings.json as its pattern between ^ and $, and each cap from constants.json" do
      defs = read("schema.json")["$defs"]
      constants = read("constants.json")

      for {name, %{"pattern" => pattern}} <- read("encodings.json") do
        assert defs[name]["pattern"] == "^" <> pattern <> "$", name
      end

      assert defs["INT"]["maximum"] == constants["MAX_INTEGER"]
      assert defs["MERKLE_PROOF"]["properties"]["path"]["maxItems"] == constants["MAX_PATH_STEPS"]
      assert defs["RAW_TRANSACTION"]["maxLength"] == 2 * constants["RAW_TX_MAX_OCTETS"]
      assert defs["TXOUTPROOF"]["maxLength"] == 2 * constants["TXOUTPROOF_MAX_OCTETS"]
      assert defs["BITCOIN_NETWORK"]["enum"] == read("networks.json")["bitcoin"]
      assert defs["STELLAR_NETWORK"]["enum"] == read("networks.json")["stellar"]
    end

    test "accepts every sample" do
      schema = read("schema.json")

      for {name, sample} <- Samples.all() do
        assert SchemaSubset.valid?(schema, sample), name
      end
    end

    test "refuses every generated single defect of the base samples" do
      schema = read("schema.json")

      for {name, sample} <- Samples.base(), {defect, document} <- generated_defects(sample) do
        refute SchemaSubset.valid?(schema, document), "#{name}: #{defect}"
      end
    end

    test "refuses every mutation of a sample" do
      schema = read("schema.json")

      for {name, document} <- mutations() do
        refute SchemaSubset.valid?(schema, document), name
      end
    end
  end

  defp schema_keywords(node) when is_map(node) do
    Enum.flat_map(node, fn
      {key, sub} when key in ["properties", "$defs"] ->
        [key | Enum.flat_map(Map.values(sub), &schema_keywords/1)]

      {key, _value} when key in ["const", "enum", "required", "pattern"] ->
        [key]

      {key, sub} ->
        [key | schema_keywords(sub)]
    end)
    |> Enum.uniq()
  end

  defp schema_keywords(list) when is_list(list), do: Enum.flat_map(list, &schema_keywords/1)
  defp schema_keywords(_scalar), do: []

  # Single defects of a valid envelope: an unknown member in every object, every member that
  # is not optional deleted, every value replaced by null and by a value of another JSON type,
  # and every member its type forbids added. The open claims object and the constructions
  # member are single opaque nodes.
  defp generated_defects(sample) do
    proof = sample["proof"]

    sample
    |> nodes([])
    |> Enum.flat_map(fn {path, value} ->
      added =
        if is_map(value),
          do: [{"an unknown member at #{show(path)}", put(sample, path ++ ["zz_unknown"], 1)}],
          else: []

      member? = path != [] and is_binary(List.last(path))

      deleted =
        if member? and not optional?(path, sample),
          do: [{"no #{show(path)}", pop(sample, path)}],
          else: []

      replaced =
        if path != [],
          do: [
            {"null at #{show(path)}", put(sample, path, nil)},
            {"another type at #{show(path)}", put(sample, path, other_type(value))}
          ],
          else: []

      added ++ deleted ++ replaced
    end)
    |> Kernel.++(
      for {member, value} <- forbidden_members(proof["type"]),
          do: {"#{member} in a #{proof["type"]} proof", put(sample, ["proof", member], value)}
    )
  end

  defp nodes(_value, ["proof", "subject", "claims"] = path), do: [{path, :opaque}]
  defp nodes(_value, ["proof", "constructions"] = path), do: [{path, :opaque}]

  defp nodes(value, path) when is_map(value),
    do: [{path, value} | Enum.flat_map(value, fn {key, sub} -> nodes(sub, path ++ [key]) end)]

  defp nodes(value, path) when is_list(value) do
    elements =
      value |> Enum.with_index() |> Enum.flat_map(fn {sub, i} -> nodes(sub, path ++ [i]) end)

    [{path, value} | elements]
  end

  defp nodes(value, path), do: [{path, value}]

  defp show(path), do: "/" <> Enum.map_join(path, "/", &to_string/1)

  defp put(_document, [], value), do: value

  defp put(document, [key | rest], value) when is_map(document),
    do: Map.put(document, key, put(document[key], rest, value))

  defp put(document, [i | rest], value) when is_list(document),
    do: List.replace_at(document, i, put(Enum.at(document, i), rest, value))

  defp other_type(value) when is_binary(value), do: 1
  defp other_type(value) when is_number(value), do: "1"
  defp other_type(value) when is_list(value), do: "x"
  defp other_type(_value), do: [1]

  # The members sections 3.2 to 3.6 let a document leave out.
  defp optional?(path, sample) do
    parent = sample |> get(Enum.drop(path, -1))

    case path do
      ["proof", member] -> member in ~w(constructions environment signing_key_event)
      ["proof", "witnesses", "entropy_" <> _] -> true
      ["proof", "subject", "record", "witness_hashes", "entropy_" <> _] -> true
      ["proof", "observations", _] -> true
      [_ | _] = path -> optional_nested?(path, parent)
    end
  end

  defp optional_nested?(path, parent) do
    optional_member?(Enum.take(path, -2), parent, Enum.at(path, 1))
  end

  defp optional_member?(["commitments", _chain], parent, _section), do: map_size(parent) == 2

  defp optional_member?(["key_event", "prerotation_commitment"], parent, _section),
    do: parent["type"] != "prerotation"

  defp optional_member?(["key_event", "handover_signature"], parent, _section),
    do: parent["type"] == "emergency_rotation"

  defp optional_member?(["metadata", "key_event"], parent, section),
    do: not Map.has_key?(parent, "genesis") and section != "signing_key_event"

  defp optional_member?(_tail, _parent, _section), do: false

  defp get(document, []), do: document
  defp get(document, [key | rest]) when is_map(document), do: get(document[key], rest)
  defp get(document, [i | rest]) when is_list(document), do: get(Enum.at(document, i), rest)

  # Section 3.2's F entries, each with a value that would be valid where it is allowed.
  defp forbidden_members(type) do
    samples = Samples.base()
    item = samples["item"]["proof"]
    observations = samples["beacon"]["proof"]["observations"]

    case type do
      "item" ->
        [{"observations", observations}]

      "block" ->
        [
          {"subject", item["subject"]},
          {"witnesses", item["witnesses"]},
          {"observations", observations}
        ]

      "beacon" ->
        [{"subject", item["subject"]}, {"witnesses", item["witnesses"]}]

      "entropy_" <> _ ->
        [{"witnesses", item["witnesses"]}, {"observations", observations}]
    end
  end

  # Every {keyword, value} pair in the schema, outside the names under properties and $defs.
  defp schema_entries(node) when is_map(node) do
    Enum.flat_map(node, fn
      {key, sub} when key in ["properties", "$defs"] ->
        Enum.flat_map(Map.values(sub), &schema_entries/1)

      {key, sub} ->
        [{key, sub} | schema_entries(sub)]
    end)
  end

  defp schema_entries(list) when is_list(list), do: Enum.flat_map(list, &schema_entries/1)
  defp schema_entries(_scalar), do: []

  defp patterns(node) when is_map(node) do
    own = if is_binary(node["pattern"]), do: [{node["pattern"], node}], else: []
    own ++ Enum.flat_map(node, fn {_key, sub} -> patterns(sub) end)
  end

  defp patterns(list) when is_list(list), do: Enum.flat_map(list, &patterns/1)
  defp patterns(_scalar), do: []

  @hex Samples.hex64("x")

  defp mutations do
    s = Samples.all()
    item = s["item"]
    rotation = ["proof", "signing_key_event", "block", "record", "metadata", "key_event"]
    genesis_block = s["block"]["proof"]["block"]
    stellar_entropy = s["entropy_stellar"]["proof"]["subject"]["entropy"]

    [
      {"a member beside proof and signature", Map.put(item, "x", 1)},
      {"a member not in the proof layout", put_in(item, ["proof", "generated_at"], "x")},
      {"a null environment", put_in(s["entropy_nist"], ["proof", "environment"], nil)},
      {"environment prod", put_in(s["entropy_nist"], ["proof", "environment"], "prod")},
      {"an uppercase hash", put_in(item, ["proof", "subject", "item_hash"], String.upcase(@hex))},
      {"a hash with a final newline",
       put_in(item, ["proof", "subject", "item_hash"], @hex <> "\n")},
      {"a short hash with a final newline",
       put_in(item, ["proof", "subject", "item_hash"], binary_part(@hex, 0, 63) <> "\n")},
      {"a reason with a final newline", put_in(item, rotation ++ ["reason"], "scheduled\n")},
      {"a reason with a quote", put_in(item, rotation ++ ["reason"], ~s(a"b))},
      {"a raw transaction with a final newline",
       put_in(item, ["proof", "commitments", "bitcoin", "raw_transaction"], "ab\n")},
      {"a raw transaction of odd length",
       put_in(item, ["proof", "commitments", "bitcoin", "raw_transaction"], "abc")},
      {"a raw transaction over its cap",
       put_in(
         item,
         ["proof", "commitments", "bitcoin", "raw_transaction"],
         String.duplicate("ab", 1001)
       )},
      {"a txoutproof over its cap",
       put_in(
         item,
         ["proof", "commitments", "bitcoin", "txoutproof"],
         String.duplicate("ab", 1025)
       )},
      {"a key with nonzero unused bits",
       update_in(item, ["signature", "public_key"], &(binary_part(&1, 0, 42) <> "B"))},
      {"a signature with nonzero unused bits",
       update_in(item, ["signature", "value"], &(binary_part(&1, 0, 85) <> "B"))},
      {"an integer above MAX_INTEGER",
       put_in(item, ["proof", "block", "record", "height"], 9_007_199_254_740_992)},
      {"a negative integer", put_in(item, ["proof", "block", "record", "height"], -1)},
      {"a fractional integer", put_in(item, ["proof", "block", "record", "height"], 1.5)},
      {"a path of 33 nodes",
       put_in(item, ["proof", "subject", "inclusion_proof", "path"], List.duplicate(@hex, 33))},
      {"an item without witnesses", pop(item, ["proof", "witnesses"])},
      {"a block with a subject", put_in(s["block"], ["proof", "subject"], %{})},
      {"a beacon with witnesses",
       put_in(s["beacon"], ["proof", "witnesses"], item["proof"]["witnesses"])},
      {"a beacon without observations", pop(s["beacon"], ["proof", "observations"])},
      {"an entropy_nist subject holding Stellar entropy",
       put_in(s["entropy_nist"], ["proof", "subject", "entropy"], stellar_entropy)},
      {"a NIST witness holding Stellar entropy",
       put_in(item, ["proof", "witnesses", "entropy_nist"], stellar_entropy)},
      {"genesis beside a rotation",
       put_in(
         item,
         ["proof", "signing_key_event", "block", "record", "metadata", "genesis"],
         genesis_block["record"]["metadata"]["genesis"]
       )},
      {"a genesis event without genesis",
       pop(s["block"], ["proof", "block", "record", "metadata", "genesis"])},
      {"a prerotation at /signing_key_event/block",
       put_in(
         item,
         ["proof", "signing_key_event", "block", "record", "metadata"],
         s["entropy_nist"]["proof"]["block"]["record"]["metadata"]
       )},
      {"no key event at /signing_key_event/block",
       put_in(item, ["proof", "signing_key_event", "block", "record", "metadata"], %{})},
      {"no commitments", put_in(item, ["proof", "commitments"], %{})},
      {"a commitment on another chain", put_in(item, ["proof", "commitments", "ethereum"], %{})},
      {"Bitcoin network testnet4",
       put_in(item, ["proof", "commitments", "bitcoin", "network"], "testnet4")},
      {"a block with leaves under the empty root",
       put_in(item, ["proof", "block", "record", "merkle_root"], @empty_root)},
      {"a block with no leaves under a real root",
       put_in(item, ["proof", "witnesses", "block", "record", "leaf_count"], 0)},
      {"Stellar network mainnet",
       put_in(item, ["proof", "commitments", "stellar", "network"], "mainnet")},
      {"a reference URL on another host",
       update_in(
         s["entropy_nist"],
         ["proof", "constructions"],
         &String.replace(&1, "truestamp.com", "truestamp.org")
       )},
      {"constructions as a number", put_in(item, ["proof", "constructions"], 1)},
      {"version 2", put_in(item, ["proof", "version"], 2)},
      {"another format", put_in(item, ["proof", "format"], "truestamp-proof-2")},
      {"alg Ed25519", put_in(item, ["signature", "alg"], "Ed25519")},
      {"a rotation without a handover signature", pop(item, rotation ++ ["handover_signature"])},
      {"a genesis event of sequence 1",
       put_in(s["block"], ["proof", "block", "record", "metadata", "key_event", "sequence"], 1)},
      {"a rotation of sequence 0", put_in(item, rotation ++ ["sequence"], 0)},
      {"an item id of UUID version 4",
       put_in(item, ["proof", "subject", "record", "id"], "01920000-0000-4000-8000-000000000030")},
      {"an item id in capitals",
       put_in(item, ["proof", "subject", "record", "id"], "0192ABCD-0000-7000-8000-00000000003A")},
      {"a TIME with a fraction",
       put_in(
         item,
         ["proof", "commitments", "bitcoin", "header_time"],
         "2026-09-25T12:00:00.000Z"
       )},
      {"witness hashes without block",
       pop(item, ["proof", "subject", "record", "witness_hashes", "block"])},
      {"a member in an epoch record",
       put_in(item, ["proof", "commitments", "stellar", "epoch", "record", "x"], 1)},
      {"a commitment without its epoch", pop(item, ["proof", "commitments", "stellar", "epoch"])},
      {"a fourth observation",
       put_in(
         s["beacon"],
         ["proof", "observations", "entropy_x"],
         s["beacon"]["proof"]["observations"]["entropy_nist"]
       )},
      {"a NIST version of 17 characters",
       put_in(
         item,
         ["proof", "witnesses", "entropy_nist", "payload", "pulse", "version"],
         String.duplicate("v", 17)
       )}
    ]
  end

  defp pop(document, path), do: document |> pop_in(path) |> elem(1)

  describe "value-classes.json" do
    test "names the classes and treatments of section 3.7" do
      rows = table_after("| Class | Members | Treatment |")

      assert Map.new(rows, fn [class, _members, treatment] -> {class, unmark(treatment)} end) ==
               read("value-classes.json")["classes"]
    end

    test "gives each member the class section 3.7 gives it" do
      for rule <- read("value-classes.json")["members"] do
        assert Map.get(rule, "document", "proof") in ["proof", "envelope"], rule["pointer"]

        assert {rule["class"], rule["when"], rule["otherwise"]} == expected_class(rule["pointer"]),
               rule["pointer"]
      end
    end

    test "gives every member of every sample exactly one rule, and every rule a member" do
      %{"classes" => classes, "conditions" => conditions, "members" => rules} =
        read("value-classes.json")

      for rule <- rules do
        assert rule["class"] in Map.keys(classes)
        assert Map.get(rule, "when") in [nil | Map.keys(conditions)]
        assert Map.has_key?(rule, "when") == Map.has_key?(rule, "otherwise")
        assert Map.get(rule, "otherwise", rule["class"]) in Map.keys(classes)
      end

      {proof_rules, envelope_rules} =
        Enum.split_with(rules, &(Map.get(&1, "document", "proof") == "proof"))

      used =
        Enum.flat_map(Samples.all(), fn {name, sample} ->
          covered(sample["proof"], [], proof_rules, name) ++
            covered(%{"alg" => sample["signature"]["alg"]}, ["signature"], envelope_rules, name)
        end)

      assert Enum.sort(Enum.uniq(used)) == Enum.sort(Enum.map(rules, & &1["pointer"]))
    end
  end

  # Section 3.7 read member by member, independently of value-classes.json: the class of the
  # member at `pointer`, with the condition and the other class where 3.7 makes it conditional.
  # The first table that knows the pointer decides.
  @pointer_classes %{
    "/constructions" => "PINNED",
    "/environment" => "PINNED",
    "/format" => "PINNED",
    "/type" => "PINNED",
    "/version" => "PINNED",
    "/signature/alg" => "PINNED",
    "/subject/claims" => "SUBMITTED",
    "/block/record/leaf_count" => "PREIMAGE",
    "/block/record/merkle_root" => {"CHECKED", "walked", "PREIMAGE"},
    "/subject/entropy/payload/hash" => {"PREIMAGE", "stellar_source", "CHAIN POINTER"}
  }

  @tail_classes [
    {["epoch", "epoch_hash"], "CHECKED"},
    {["epoch", "record", "merkle_root"], "CHECKED"},
    {["epoch", "record", "leaf_count"], "PREIMAGE"},
    {["record", "merkle_root"], "PREIMAGE"},
    {["record", "leaf_count"], "PREIMAGE"},
    {["record", "previous_block_hash"], {"CHECKED", "genesis_block", "RECORDED"}},
    {["record", "signing_key_id"], {"CHECKED", "introduces_key_or_prerotation", "RECORDED"}},
    {["record", "height"], {"CHECKED", "genesis_block", "BLOCK HEIGHT"}},
    {["record", "id"], "RECORDED"},
    {["inclusion_proof", "tree_size"], "CHECKED"},
    {["inclusion_proof", "path"], "PATH INPUT"},
    {["inclusion_proof", "leaf_index"], "PATH INPUT"}
  ]

  @hash_leaves ~w(claims_hash item_hash entropy_hash observation_hash block_hash)

  defp expected_class(pointer) do
    segments = String.split(pointer, "/", trim: true)

    class =
      Map.get(@pointer_classes, pointer) ||
        Enum.find_value(@tail_classes, fn {tail, class} ->
          if Enum.take(segments, -length(tail)) == tail, do: class
        end) ||
        context_class(segments, List.last(segments))

    case class do
      {_class, _when, _otherwise} = conditional -> conditional
      class -> {class, nil, nil}
    end
  end

  defp context_class(segments, leaf) do
    cond do
      "witness_hashes" in segments or leaf in @hash_leaves -> "CHECKED"
      "genesis" in segments -> "CHAIN POINTER"
      "key_event" in segments -> key_event_class(leaf)
      "commitments" in segments -> commitment_class(segments, leaf)
      true -> entropy_class(segments, leaf)
    end
  end

  defp key_event_class(leaf)
       when leaf in ~w(key_id previous_key_id handover_signature height previous_block_hash),
       do: "CHECKED"

  defp key_event_class(leaf) when leaf in ~w(public_key type active_key_id), do: "PREIMAGE"

  defp key_event_class(leaf)
       when leaf in ~w(prerotation_commitment previous_public_key sequence reason revoked_key_id),
       do: "RECORDED"

  defp commitment_class(segments, leaf) do
    cond do
      leaf in ~w(header_hash header_merkle_root header_time) -> "CHECKED"
      leaf == "transaction_hash" and "bitcoin" in segments -> "CHECKED"
      leaf in ~w(transaction_hash ledger height network) -> "CHAIN POINTER"
      leaf in ~w(raw_transaction txoutproof) -> "PREIMAGE"
    end
  end

  defp entropy_class(segments, leaf) do
    cond do
      leaf in ~w(network chainIndex pulseIndex sequence) -> "CHAIN POINTER"
      leaf in ~w(source outputValue timeStamp closed_at height time) -> "PREIMAGE"
      leaf == "version" -> "RECORDED"
      leaf == "hash" and "entropy_stellar" in segments -> "PREIMAGE"
      leaf == "hash" and "entropy_bitcoin" in segments -> "CHAIN POINTER"
    end
  end

  # The pointers of the rules that `value` at `path` meets, failing on a member no rule meets
  # or that more than one does. A member a rule meets is not looked into further.
  defp covered(value, path, rules, name) do
    case Enum.filter(rules, &pointer_match?(&1["pointer"], path)) do
      [rule] ->
        [rule["pointer"]]

      [] when is_map(value) ->
        Enum.flat_map(value, fn {key, sub} -> covered(sub, path ++ [key], rules, name) end)

      [] ->
        flunk("#{name}: no rule for /#{Enum.join(path, "/")}")

      many ->
        flunk(
          "#{name}: /#{Enum.join(path, "/")} meets #{inspect(Enum.map(many, & &1["pointer"]))}"
        )
    end
  end

  defp pointer_match?(pointer, path) do
    segments = String.split(pointer, "/", trim: true)

    length(segments) == length(path) and
      segments
      |> Enum.zip(path)
      |> Enum.all?(fn {pattern, segment} -> segment_match?(pattern, segment) end)
  end

  defp segment_match?("*", _segment), do: true

  defp segment_match?(pattern, segment),
    do:
      if(String.ends_with?(pattern, "*"),
        do: String.starts_with?(segment, String.trim_trailing(pattern, "*")),
        else: pattern == segment
      )
end
