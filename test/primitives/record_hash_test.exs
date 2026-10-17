# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.HashTest do
  # The rule H(p, R) = SHA-256(p || JCS(R)) of SPEC.md 4.1 and the key id of 3.3, then both
  # against every trace row of the sound proofs that recomputes a record hash or a key id,
  # and every handover signature those proofs carry.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Base64URL, Ed25519, Hash, Instant, JCS, JSON, KeyId}

  @root Truestamp.Verify.Test.Verification.root()

  # SPEC.md 4.3, the bytes of the kinds under the rule.
  @record_bytes %{
    claims_hash: 0x10,
    item_hash: 0x11,
    entropy_hash: 0x20,
    observation_hash: 0x21,
    genesis_previous_block_hash: 0x30,
    block_hash: 0x31,
    epoch_hash: 0x40,
    proof_hash: 0x50,
    handover: 0x62
  }

  defp sha256_hex(iodata), do: :crypto.hash(:sha256, iodata) |> Base.encode16(case: :lower)

  describe "the rule" do
    test "hashes the kind's byte, then JCS of the record, for each kind under the rule" do
      record = %{"b" => [1, "x"], "a" => %{"c" => nil}}
      jcs = ~s({"a":{"c":null},"b":[1,"x"]})

      for {kind, byte} <- @record_bytes do
        assert Hash.hash(kind, record) == :crypto.hash(:sha256, <<byte>> <> jcs)
        assert Hash.hash_hex(kind, record) == sha256_hex(<<byte>> <> jcs)
      end
    end

    test "gives each kind a different hash of one record" do
      hashes = for kind <- Hash.kinds(), do: Hash.hash(kind, %{})
      assert length(Enum.uniq(hashes)) == map_size(@record_bytes)
    end

    test "covers exactly the nine kinds SPEC.md 4.3 hashes as JCS of a value" do
      assert Enum.sort(Hash.kinds()) == Enum.sort(Map.keys(@record_bytes))
    end

    test "refuses the kinds outside the rule, an unknown kind and a record that is not an object" do
      for kind <- [:merkle_leaf, :merkle_node, :key_id, :prerotation_commitment, :other] do
        assert_raise FunctionClauseError, fn -> Hash.hash(kind, %{}) end
      end

      for record <- [[], "x", 1, nil, ~D[2026-01-01]] do
        assert_raise FunctionClauseError, fn -> Hash.hash(:block_hash, record) end
      end
    end

    test "depends on the value, not on how its file was written" do
      compact = ~s({"a":1,"b":"\\u00e9"})
      loose = ~s({ "b" : "é" ,\r\n "a" : 1.0e0 })
      {:ok, one} = JSON.decode(compact)
      {:ok, two} = JSON.decode(loose)

      assert Hash.hash(:item_hash, one) == Hash.hash(:item_hash, two)
      assert Hash.hash_hex(:item_hash, one) == sha256_hex([0x11, JCS.encode(one)])
    end
  end

  describe "the key id" do
    test "is the first 4 bytes of SHA-256(0x60 || key), in hex" do
      key = :binary.copy(<<7>>, 32)
      <<four::binary-4, _::binary>> = :crypto.hash(:sha256, <<0x60>> <> key)
      assert KeyId.of(key) == Base.encode16(four, case: :lower)
    end

    test "is SPEC.md 9's for the keys of the published seeds" do
      for {seed, id} <- [
            {0x41, "f12cfabb"},
            {0x42, "fbd680e8"},
            {0x43, "9602c03e"},
            {0x44, "d0b1cefe"}
          ] do
        {key, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))
        assert KeyId.of(key) == id
      end
    end

    test "is the key_id of each key in spec/keys.nonproduction.json" do
      {:ok, %{"keys" => keys}} =
        @root |> Path.join("spec/keys.nonproduction.json") |> File.read!() |> JSON.decode()

      assert keys != []

      for %{"key_id" => id, "public_key" => text} <- keys do
        {:ok, key} = Base64URL.decode(:b64u32, text)
        assert KeyId.of(key) == id
      end
    end

    test "takes only 32 octets" do
      assert_raise FunctionClauseError, fn -> KeyId.of(<<0::248>>) end
      assert_raise FunctionClauseError, fn -> KeyId.of(<<0::264>>) end
    end
  end

  describe "the trace rows of the sound proofs" do
    @proofs Path.wildcard(Path.join(@root, "vectors/positive/*.proof.json"))

    defp rows do
      for proof <- @proofs,
          {:ok, document} = proof |> File.read!() |> JSON.decode(),
          {:ok, rows} =
            proof
            |> String.replace_suffix(".proof.json", ".trace.json")
            |> File.read!()
            |> JSON.decode(),
          row <- rows,
          do: {document["proof"], row}
    end

    defp pointer(value, "/" <> path) do
      path
      |> String.split("/")
      |> Enum.map(&(&1 |> String.replace("~1", "/") |> String.replace("~0", "~")))
      |> Enum.reduce(value, fn segment, node -> Map.fetch!(node, segment) end)
    end

    defp last_segment(part), do: part |> String.split("/") |> List.last()

    # A handover row with one input checks an id or a position, not a record hash.
    defp record_kind(%{"construction" => "handover"}), do: nil

    defp record_kind(%{"construction" => "witnesses", "part" => part}),
      do: if(last_segment(part) == "block", do: :block_hash, else: :entropy_hash)

    defp record_kind(%{"construction" => "genesis", "part" => part}),
      do: if(last_segment(part) == "previous_block_hash", do: :genesis_previous_block_hash)

    defp record_kind(%{"construction" => construction}),
      do: Enum.find(Hash.kinds(), &(Atom.to_string(&1) == construction))

    test "every record hash they recompute is H of its input's record" do
      checked =
        for {proof, %{"inputs" => [input], "recomputed" => recomputed} = row} <- rows(),
            kind = record_kind(row),
            kind != nil do
          assert Hash.hash_hex(kind, pointer(proof, input)) == recomputed, inspect(row)
          assert row["declared"] == recomputed
          kind
        end

      assert Enum.sort(Enum.uniq(checked)) ==
               Enum.sort([
                 :block_hash,
                 :claims_hash,
                 :entropy_hash,
                 :epoch_hash,
                 :genesis_previous_block_hash,
                 :item_hash,
                 :observation_hash
               ])
    end

    # A row that recomputes a key id from one key: a key event's key_id, and its
    # signing_key_id when that is taken from its own public_key, and a handover's
    # previous_key_id. A signing_key_id taken from active_key_id checks an id, not a key.
    defp key_id_row?("key_event", "key_id", _input), do: true

    defp key_id_row?("key_event", "signing_key_id", input),
      do: last_segment(input) == "public_key"

    defp key_id_row?("handover", "previous_key_id", _input), do: true
    defp key_id_row?(_construction, _last, _input), do: false

    test "every key id they recompute is the key id of its input key" do
      checked =
        for {proof, %{"inputs" => [input], "part" => part} = row} <- rows(),
            key_id_row?(row["construction"], last_segment(part), input) do
          {:ok, key} = Base64URL.decode(:b64u32, pointer(proof, input))
          assert KeyId.of(key) == row["recomputed"], inspect(row)
          assert pointer(proof, part) == row["recomputed"]
          last_segment(part)
        end

      assert Enum.frequencies(checked) == %{
               "key_id" => 16,
               "signing_key_id" => 16,
               "previous_key_id" => 13
             }

      assert length(checked) == 45
    end

    test "every handover signature verifies under the previous key over H(0x62, the event)" do
      checked =
        for {proof, %{"construction" => "handover", "inputs" => [event, previous]} = row} <-
              rows() do
          event = Map.delete(pointer(proof, event), "handover_signature")
          message = Hash.hash(:handover, event)
          assert Base.encode16(message, case: :lower) == row["recomputed"]

          {:ok, key} = Base64URL.decode(:b64u32, pointer(proof, previous))
          {:ok, signature} = Base64URL.decode(:b64u64, row["declared"])
          assert Ed25519.check_key_bytes(key) == :ok
          assert Ed25519.verify(key, message, signature) == :ok
          # The handover byte binds the kind: the same signature fails under another prefix.
          refute Ed25519.verify(key, Hash.hash(:block_hash, event), signature) == :ok
        end

      assert length(checked) == 12
    end

    test "every header_time they recompute is the header's nTime written as TIME" do
      checked =
        for {proof, %{"construction" => "bitcoin", "inputs" => [input], "part" => part} = row} <-
              rows(),
            last_segment(part) == "header_time" do
          <<_::binary-68, n_time::little-unsigned-32, _::binary>> =
            proof |> pointer(input) |> Base.decode16!(case: :lower)

          assert Instant.format(:time, n_time) == {:ok, row["recomputed"]}
        end

      assert length(checked) == 19
    end
  end

  describe "the sound proofs" do
    test "each is signed by VECTOR_KEY over H(0x50, proof), and only over that proof" do
      proofs = Path.wildcard(Path.join(@root, "vectors/positive/*.proof.json"))
      assert length(proofs) == 11

      for path <- proofs do
        {:ok, %{"proof" => proof, "signature" => signature}} = JSON.decode(File.read!(path))
        {:ok, key} = Base64URL.decode(:b64u32, signature["public_key"])
        {:ok, value} = Base64URL.decode(:b64u64, signature["value"])

        assert KeyId.of(key) == "fbd680e8"
        assert Ed25519.check_key_bytes(key) == :ok
        assert Ed25519.verify(key, Hash.hash(:proof_hash, proof), value) == :ok, path

        altered = Map.put(proof, "version", 2)

        assert Ed25519.verify(key, Hash.hash(:proof_hash, altered), value) ==
                 {:error, :equation}
      end
    end
  end
end
