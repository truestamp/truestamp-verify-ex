# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CompiledConstantsTest do
  # The agreement tests of SPEC.md 4 and 12.1: each table the verifier holds as compiled
  # constants equals the file under spec/ that publishes it, read here by the test suite's
  # own reader, and the values SPEC.md states in its text.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Ed25519, ExitCode, JSON, ReasonCodes}
  alias Truestamp.Verify.Spec.{Constants, Prefixes}
  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()

  defp spec_file(name) do
    {:ok, value} = @root |> Path.join("spec/" <> name) |> File.read!() |> StrictJSON.decode()
    value
  end

  defp spec_md, do: File.read!(Path.join(@root, "SPEC.md"))

  # The text of SPEC.md from `from` up to the next line that begins with `to`.
  defp section(from, to) do
    [_before, rest] = String.split(spec_md(), from, parts: 2)
    [text | _after] = String.split(rest, "\n" <> to, parts: 2)
    text
  end

  describe "the byte-prefix registry" do
    test "equals spec/prefixes.json, row by row and member by member" do
      file = spec_file("prefixes.json")

      compiled =
        Map.new(Prefixes.table(), fn {name, entry} ->
          row = %{
            "byte" => "0x" <> String.downcase(Base.encode16(<<entry.byte>>)),
            "construction" => entry.construction,
            "family" => entry.family,
            "hashed" => entry.hashed,
            "signed" => entry.signed
          }

          row = if entry.signer, do: Map.put(row, "signer", entry.signer), else: row
          {Atom.to_string(name), row}
        end)

      assert compiled == file
    end

    test "gives each construction the byte of SPEC.md 4.3" do
      expected = %{
        merkle_leaf: 0x00,
        merkle_node: 0x01,
        claims_hash: 0x10,
        item_hash: 0x11,
        entropy_hash: 0x20,
        observation_hash: 0x21,
        genesis_previous_block_hash: 0x30,
        block_hash: 0x31,
        epoch_hash: 0x40,
        proof_hash: 0x50,
        key_id: 0x60,
        prerotation_commitment: 0x61,
        handover: 0x62
      }

      assert Map.new(Prefixes.table(), fn {name, entry} -> {name, entry.byte} end) == expected

      for {name, byte} <- expected, do: assert(Prefixes.byte(name) == byte)
      assert Prefixes.names() == Enum.sort_by(Map.keys(expected), &expected[&1])
    end

    test "matches the table's prefixes in SPEC.md 4.3 in order" do
      bytes =
        ~r/^\| `0x([0-9a-f]{2})` \|/m
        |> Regex.scan(section("### 4.3 The table", "Every other byte"))
        |> Enum.map(fn [_row, hex] -> String.to_integer(hex, 16) end)

      assert bytes == Enum.map(Prefixes.names(), &Prefixes.byte/1)
    end

    test "marks as signed exactly the three kinds of SPEC.md 4.1" do
      signed = for {name, %{signed: true}} <- Prefixes.table(), do: name
      assert Enum.sort(signed) == [:block_hash, :handover, :proof_hash]
    end

    test "has no byte for a name it lacks" do
      assert_raise FunctionClauseError, fn ->
        Prefixes.byte(String.to_atom("not_a_construction"))
      end
    end
  end

  describe "the reason codes" do
    test "equal spec/reason-codes.json, in its order, sub_reasons included" do
      compiled =
        for entry <- ReasonCodes.table() do
          row = %{
            "code" => Atom.to_string(entry.code),
            "meaning" => entry.meaning,
            "status" => Atom.to_string(entry.status),
            "step" => entry.step
          }

          case entry.sub_reasons do
            [] -> row
            names -> Map.put(row, "sub_reasons", Enum.map(names, &Atom.to_string/1))
          end
        end

      assert compiled == spec_file("reason-codes.json")

      assert for(%{code: code, sub_reasons: [_ | _]} <- ReasonCodes.table(), do: code) ==
               [:malformed_json, :invalid_envelope]
    end

    test "are the 36 codes of SPEC.md 12.1, in its order" do
      text = section("### 12.1 Reason codes", "### 12.2")
      assert text =~ "36 codes."

      codes =
        ~r/^\| `([a-z_]+)` \| ([^|]+) \| ([a-z]+) \|/m
        |> Regex.scan(text)
        |> Enum.map(fn [_row, code, step, status] ->
          {String.to_atom(code), String.trim(step), String.to_atom(status)}
        end)

      assert length(codes) == 36

      assert codes ==
               Enum.map(ReasonCodes.table(), &{&1.code, &1.step, &1.status})

      assert ReasonCodes.codes() == Enum.map(codes, &elem(&1, 0))
    end

    test "answer status/1, step/1 and code?/1 for each code, and nothing else" do
      for %{code: code, status: status, step: step} <- ReasonCodes.table() do
        assert ReasonCodes.status(code) == status
        assert ReasonCodes.step(code) == step
        assert ReasonCodes.code?(code)
      end

      assert ReasonCodes.status(:malformed_json) == :bare
      assert ReasonCodes.status(:expected_hash_weak_algorithm) == :warn
      refute ReasonCodes.code?(:not_a_code)
      refute ReasonCodes.code?("malformed_json")
      assert_raise FunctionClauseError, fn -> ReasonCodes.status(String.to_atom("not_a_code")) end
    end

    test "has four bare codes, as SPEC.md 12.1 says" do
      bare = for %{code: code, status: :bare} <- ReasonCodes.table(), do: code
      assert bare == [:configuration_error, :input_too_large, :malformed_json, :invalid_envelope]
    end

    test "code/1 expands to a code, and stops the build on any other name" do
      require ReasonCodes
      assert ReasonCodes.code(:derivation_mismatch) == :derivation_mismatch

      assert_raise ArgumentError, ~r/not a reason code/, fn ->
        Code.eval_string(
          "require Truestamp.Verify.ReasonCodes; Truestamp.Verify.ReasonCodes.code(:derivation_mismatches)"
        )
      end
    end

    test "sub_reasons, compiled from the file, are SPEC.md's for malformed_json and invalid_envelope, and none else" do
      parse_names =
        ~r/`([a-z_0-9]+)`/
        |> Regex.scan(section("- J2 to J6 are step PARSE.", "  (J6)"))
        |> Enum.map(fn [_name, name] -> String.to_atom(name) end)
        |> Enum.reject(&(&1 == :malformed_json or &1 == :sub_reason))

      assert ReasonCodes.sub_reasons(:malformed_json) == parse_names

      envelope_names =
        ~r/^\d\. `([a-z_]+)`:/m
        |> Regex.scan(section("**3. ENVELOPE.**", "The message is"))
        |> Enum.map(fn [_item, name] -> String.to_atom(name) end)

      assert ReasonCodes.sub_reasons(:invalid_envelope) == envelope_names

      for code <- ReasonCodes.codes() -- [:malformed_json, :invalid_envelope] do
        assert ReasonCodes.sub_reasons(code) == []
      end
    end
  end

  describe "the constants" do
    test "equal spec/constants.json" do
      file = spec_file("constants.json")
      assert Constants.all() == file

      for {name, value} <- file do
        function = name |> String.downcase() |> String.to_existing_atom()
        assert apply(Constants, function, []) == value
      end
    end

    test "hold SPEC.md 9's values" do
      assert Constants.max_read_octets() == 262_144
      assert Constants.max_read_octets() == 4 * Constants.max_document_octets()
      assert Constants.max_depth() == 32
      assert Constants.max_integer() == Integer.pow(2, 53) - 1
      assert Constants.max_path_steps() == 32

      assert Constants.vector_key() ==
               "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
    end

    test "equal the copies the parser holds" do
      assert JSON.max_read_octets() == Constants.max_read_octets()
      assert JSON.max_depth() == Constants.max_depth()
      assert JSON.max_integer() == Constants.max_integer()
    end
  end

  describe "SMALL_ORDER_KEYS" do
    test "equals spec/small-order-keys.json, in its order" do
      file = for %{"hex" => hex} <- spec_file("small-order-keys.json"), do: hex
      assert Enum.map(Ed25519.small_order_keys(), &Base.encode16(&1, case: :lower)) == file
    end
  end

  describe "the exit codes" do
    test "equal spec/exit-codes.json, in its order" do
      compiled = for {code, run} <- ExitCode.table(), do: %{"code" => code, "run" => run}
      assert compiled == spec_file("exit-codes.json")
    end

    test "give each ending the code of SPEC.md 12.2's table" do
      text = section("### 12.2 Exit codes", "- Only 0")

      runs =
        ~r/^\| (\d) \| (.+) \|$/m
        |> Regex.scan(text, capture: :all_but_first)
        |> Map.new(fn [code, run] -> {run, String.to_integer(code)} end)

      assert map_size(runs) == 9

      for {ending, run} <- [
            {{:label, :verified}, "label `verified`"},
            {{:label, :failed}, "label `failed`"},
            {{:label, :unattributed}, "label `unattributed`"},
            {{:label, :supplied_keyring}, "label `supplied-keyring`"},
            {{:label, :internally_consistent}, "label `internally-consistent`"},
            {:bare_rejection, "a bare rejection other than `configuration_error`"},
            {:configuration_error, "`configuration_error`"}
          ] do
        assert ExitCode.code(ending) == Map.fetch!(runs, run), inspect(ending)
      end

      assert [{runtime, _code}] =
               Enum.filter(runs, &String.starts_with?(elem(&1, 0), "a runtime"))

      assert ExitCode.code(:runtime_error) == runs[runtime]
      assert [{fault, _code}] = Enum.filter(runs, &String.contains?(elem(&1, 0), "fault"))
      assert ExitCode.code(:fault) == runs[fault]
    end
  end
end
