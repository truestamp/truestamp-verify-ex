# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyringTest do
  # spec/keyring.production.json, the compiled pin of SPEC.md 8.3, held to the keyring form
  # and the load checks of section 10.2, step 0, which are read from SPEC.md; and
  # spec/keys.nonproduction.json, the non-production keys the last check refuses. The pin
  # holds no key yet, so the verifier's loader, Truestamp.Verify.Keyring.load/3, is also
  # run on keyrings built here, ones that pass and one that breaks each check.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.Keyring
  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @spec_md Path.join(@root, "SPEC.md")
  @keyring Path.join(@root, "spec/keyring.production.json")
  @external_resource @spec_md
  @external_resource @keyring

  @p Integer.pow(2, 255) - 19

  defp spec_md, do: File.read!(@spec_md)

  defp read(name) do
    {:ok, value} = @root |> Path.join("spec/" <> name) |> File.read!() |> StrictJSON.decode()
    value
  end

  # Section 10.2, step 0: a keyring's two members, the string `version` holds, and each key's
  # members with their classes, read from the paragraph that states them.
  defp form do
    [_before, rest] =
      String.split(spec_md(), "A keyring is read under section 10.1 and", parts: 2)

    [paragraph, _after] = String.split(rest, ", where:\n", parts: 2)

    [keys, version, literal] =
      Regex.run(
        ~r/exactly two\s+members: `(\w+)`, an array, and `(\w+)`, the string `"([^"`]+)"`/,
        paragraph,
        capture: :all_but_first
      )

    [_keyring, element] = String.split(paragraph, "Each element of `#{keys}`", parts: 2)

    members =
      ~r/`(\w+)` \(([^)]+)\)/
      |> Regex.scan(element, capture: :all_but_first)
      |> Map.new(fn [member, class] -> {member, class} end)

    %{keys: keys, version: version, literal: literal, members: members}
  end

  # The bulleted load checks that follow the form, whitespace collapsed.
  defp load_check_bullets do
    [_before, rest] = String.split(spec_md(), "`sequence` (INT), where:\n\n", parts: 2)

    [list, _after] =
      String.split(rest, "\n\nA verifier makes exactly these load checks.", parts: 2)

    list
    |> String.split(~r/^- /m, trim: true)
    |> Enum.map(
      &(&1
        |> String.replace(~r/\s+/, " ")
        |> String.trim()
        |> String.trim_trailing(";")
        |> String.trim_trailing("."))
    )
  end

  describe "keyring.production.json" do
    test "is a keyring in the form of section 10.2, step 0, and passes its load checks under prod" do
      assert {:ok, %Keyring{}} = @keyring |> File.read!() |> Keyring.load("prod")
    end
  end

  describe "keys.nonproduction.json" do
    test "lists each key once, with its environment and key id, in order" do
      %{"keys" => keys} = file = read("keys.nonproduction.json")
      assert Map.keys(file) == ["keys"]
      environments = read("encodings.json")["ENV"]["values"]

      for key <- keys do
        assert members?(key, ["environment", "key_id", "public_key"]), inspect(key)
        assert key["environment"] in environments, inspect(key)
        assert class?("B64U32", key["public_key"]), inspect(key)
        assert key["key_id"] == key_id(decode(key["public_key"])), inspect(key)
        assert key_bytes?(decode(key["public_key"])), inspect(key)
      end

      pairs = Enum.map(keys, &{&1["key_id"], &1["public_key"]})
      assert unique?(pairs)
      assert keys == Enum.sort_by(keys, &{&1["environment"], &1["key_id"]})
    end

    test "holds VECTOR_KEY among the test keys" do
      vector = read("constants.json")["VECTOR_KEY"]

      assert %{"environment" => "test"} =
               Enum.find(read("keys.nonproduction.json")["keys"], fn key ->
                 hex(decode(key["public_key"])) == vector
               end)
    end

    # Section 9 publishes the seed of each key the vectors use, and the key id of each but
    # VECTOR_KEY, whose value the constants table gives.
    test "holds the key of every seed SPEC.md publishes among the test keys" do
      text = String.replace(spec_md(), ~r/\s+/, " ")

      seeds =
        ~r/the seed of 32 bytes of 0x([0-9A-F]{2})/
        |> Regex.scan(text, capture: :all_but_first)
        |> Enum.map(fn [byte] -> String.to_integer(byte, 16) end)
        |> Enum.uniq()

      ids =
        ~r/the seed of 32 bytes of 0x([0-9A-F]{2}), whose key id is `([0-9a-f]{8})`/
        |> Regex.scan(text, capture: :all_but_first)
        |> Map.new(fn [byte, key_id] -> {String.to_integer(byte, 16), key_id} end)

      assert Enum.sort(seeds) == [0x41, 0x42, 0x43, 0x44]
      assert Enum.sort(Map.keys(ids)) == [0x41, 0x43, 0x44]

      test_keys =
        for %{"environment" => "test"} = key <- read("keys.nonproduction.json")["keys"], do: key

      for seed <- seeds do
        {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))
        listed = Enum.find(test_keys, &(&1["public_key"] == b64u(public)))
        assert listed, "the key of the seed of 0x#{Integer.to_string(seed, 16)}"
        assert listed["key_id"] == Map.get(ids, seed, key_id(public))
      end
    end

    # Section 9's fifth key is no seed's: it is the 0x44 key plus a point of order 8, under
    # which anyone who holds the 0x44 seed can sign (section 6.2).
    test "holds the 0x44 key plus a point of order 8 among the test keys, with its key id" do
      text = String.replace(spec_md(), ~r/\s+/, " ")

      [id] =
        Regex.run(
          ~r/whose key id is `([0-9a-f]{8})`, is the 0x44 key plus a point of order 8/,
          text,
          capture: :all_but_first
        )

      {other, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<0x44>>, 32))

      sums =
        for %{"order" => 8, "hex" => hex} <- read("small-order-keys.json") do
          point = hex |> Base.decode16!(case: :lower) |> decode_point()
          other |> decode_point() |> add(point) |> encode_point()
        end

      assert length(sums) == 4

      listed = Enum.find(read("keys.nonproduction.json")["keys"], &(&1["key_id"] == id))

      assert %{"environment" => "test"} = listed
      assert decode(listed["public_key"]) in sums
    end
  end

  describe "the load checks of section 10.2, step 0" do
    test "are the ones SPEC.md lists, on a keyring of the form it states" do
      assert load_check_bullets() == [
               "`key_id` is the key id of `public_key` (section 3.3)",
               "no two keys share a `key_id` or a `public_key`",
               "`public_key` passes the checks of a key's bytes (section 6.2): its y is below " <>
                 "2^255 - 19, and it is not one of SMALL_ORDER_KEYS",
               "no key is VECTOR_KEY unless E_v is `test`",
               "in a production keyring (section 6.4), no key is in `spec/keys.nonproduction.json`"
             ]

      assert form() == %{
               keys: "keys",
               version: "version",
               literal: "1.0",
               members: %{
                 "active" => "a boolean",
                 "key_id" => "KID",
                 "public_key" => "B64U32",
                 "sequence" => "INT"
               }
             }
    end

    test "pass sound keyrings in every environment" do
      [one, two] = [key(1), key(2)]

      for keyring <- [
            keyring([]),
            keyring([entry(one)]),
            keyring([entry(one, active: false), entry(two, sequence: 1)]),
            # A number's spelling changes no value (section 10.1), so 1.0 is the INT 1.
            keyring([entry(one, sequence: 1.0)])
          ],
          env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        assert load(keyring, env) == :ok, "#{env}: #{inspect(keyring)}"
      end
    end

    test "refuse a keyring that breaks one, with that check" do
      [one, two] = [key(1), key(2)]
      sound = keyring([entry(one)])

      vector =
        "constants.json" |> read() |> Map.fetch!("VECTOR_KEY") |> Base.decode16!(case: :lower)

      identity = "small-order-keys.json" |> read() |> hd() |> Map.fetch!("hex")

      for {defect, keyring, error} <- [
            {"a member beside keys and version", Map.put(sound, "expires", 1), :keyring_members},
            {"no version", Map.delete(sound, "version"), :keyring_members},
            {"a keyring that is an array", [entry(one)], :keyring_members},
            {"version 1.0 as a number", Map.put(sound, "version", 1.0), :keyring_members},
            {"version \"1\"", Map.put(sound, "version", "1"), :keyring_members},
            {"keys as an object", Map.put(sound, "keys", %{}), :keyring_members},
            {"a key with a member more", keyring([Map.put(entry(one), "revoked", false)]),
             :key_members},
            {"a key without its sequence", keyring([Map.delete(entry(one), "sequence")]),
             :key_members},
            {"active as a string", keyring([entry(one, active: "true")]), :key_members},
            {"an uppercase key id", keyring([entry(one, key_id: String.upcase(key_id(one)))]),
             :key_members},
            {"a padded key", keyring([entry(one, public_key: b64u(one) <> "=")]), :key_members},
            {"a key in standard base64", keyring([entry(one, public_key: Base.encode64(one))]),
             :key_members},
            {"a key with nonzero unused bits",
             keyring([entry(one, public_key: binary_part(b64u(one), 0, 42) <> "B")]),
             :key_members},
            {"sequence -1", keyring([entry(one, sequence: -1)]), :key_members},
            {"sequence 1.5", keyring([entry(one, sequence: 1.5)]), :key_members},
            {"a key id of another key", keyring([entry(one, key_id: key_id(two))]), :key_id},
            {"a key id hashed without the prefix byte",
             keyring([entry(one, key_id: :sha256 |> :crypto.hash(one) |> hex8())]), :key_id},
            {"one key twice", keyring([entry(one), entry(one, sequence: 1)]),
             :repeated_public_key},
            {"the identity", keyring([entry(Base.decode16!(identity, case: :lower))]),
             :small_order_key},
            {"a key written with y = p", keyring([entry(<<@p::little-256>>)]), :y_not_below_p},
            {"a key written with y = p + 1", keyring([entry(<<@p + 1::little-256>>)]),
             :y_not_below_p},
            {"VECTOR_KEY", keyring([entry(vector)]), :vector_key},
            {"a non-production key", keyring([entry(nonproduction("dev"))]), :nonproduction_key}
          ] do
        assert load(keyring, "prod") == {:error, error}, defect
      end
    end

    test "allow a non-production key only when the verifier's environment is not prod" do
      keyring = keyring([entry(nonproduction("dev"))])

      for env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        expected = if env == "prod", do: {:error, :nonproduction_key}, else: :ok
        assert load(keyring, env) == expected, env
      end
    end

    test "allow VECTOR_KEY only when the verifier's environment is test" do
      vector =
        "constants.json" |> read() |> Map.fetch!("VECTOR_KEY") |> Base.decode16!(case: :lower)

      keyring = keyring([entry(vector)])

      for env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        expected = if env == "test", do: :ok, else: {:error, :vector_key}
        assert load(keyring, env) == expected, env
      end
    end
  end

  # Truestamp.Verify.Keyring.load/3 over a keyring built here, written in canonical form:
  # :ok, or {:error, failure} naming the first check the keyring fails.
  defp load(keyring, env) do
    case keyring |> StrictJSON.canonical() |> Keyring.load(env) do
      {:ok, %Keyring{}} -> :ok
      {:error, failure} -> {:error, failure}
    end
  end

  # The bytes of the first key keys.nonproduction.json lists for an environment.
  defp nonproduction(environment) do
    read("keys.nonproduction.json")["keys"]
    |> Enum.find(&(&1["environment"] == environment))
    |> Map.fetch!("public_key")
    |> decode()
  end

  defp members?(object, names),
    do: is_map(object) and Enum.sort(Map.keys(object)) == Enum.sort(names)

  defp class?("a boolean", value), do: is_boolean(value)

  defp class?(class, value) do
    case Map.fetch!(read("encodings.json"), class) do
      %{"pattern" => pattern} ->
        is_binary(value) and value =~ Regex.compile!("\\A(?:" <> pattern <> ")\\z")

      %{"minimum" => minimum, "maximum" => maximum} ->
        is_number(value) and value >= minimum and value <= maximum and trunc(value) == value
    end
  end

  # A B64U32 value, which class?/2 has matched, so its spelling is canonical.
  defp decode(public_key), do: Base.url_decode64!(public_key, padding: false)

  defp unique?(pairs) do
    {ids, keys} = Enum.unzip(pairs)
    ids == Enum.uniq(ids) and keys == Enum.uniq(keys)
  end

  # Section 6.2, steps 2 and 3: y below p, and not one of SMALL_ORDER_KEYS.
  defp key_bytes?(bytes) do
    y = :binary.decode_unsigned(bytes, :little) &&& Integer.pow(2, 255) - 1
    small_order = Enum.map(read("small-order-keys.json"), & &1["hex"])
    y < @p and hex(bytes) not in small_order
  end

  # Section 3.3: the hex of the first 4 bytes of SHA-256(0x60 || the key), with the byte taken
  # from the registry.
  defp key_id(bytes) do
    "0x" <> byte = read("prefixes.json")["key_id"]["byte"]
    :sha256 |> :crypto.hash(Base.decode16!(byte, case: :lower) <> bytes) |> hex8()
  end

  # Points of edwards25519 in affine coordinates (RFC 8032 section 5.1), for the fifth key: an
  # encoding known to be of a point on the curve decoded, two points added, and a point encoded.
  defp decode_point(<<n::little-256>>) do
    y = n &&& Integer.pow(2, 255) - 1
    x2 = Integer.mod((y * y - 1) * inverse(d() * y * y + 1), @p)
    x = power(x2, div(@p + 3, 8))

    x =
      if Integer.mod(x * x - x2, @p) == 0,
        do: x,
        else: Integer.mod(x * power(2, div(@p - 1, 4)), @p)

    0 = Integer.mod(x * x - x2, @p)
    if (x &&& 1) == n >>> 255, do: {x, y}, else: {Integer.mod(-x, @p), y}
  end

  defp add({x1, y1}, {x2, y2}) do
    t = Integer.mod(d() * x1 * x2 * y1 * y2, @p)

    {Integer.mod((x1 * y2 + y1 * x2) * inverse(1 + t), @p),
     Integer.mod((y1 * y2 + x1 * x2) * inverse(1 - t), @p)}
  end

  defp encode_point({x, y}), do: <<y ||| (x &&& 1) <<< 255::little-256>>

  defp d, do: Integer.mod(-121_665 * inverse(121_666), @p)
  defp inverse(x), do: power(x, @p - 2)
  defp power(x, e), do: :binary.decode_unsigned(:crypto.mod_pow(Integer.mod(x, @p), e, @p))

  defp hex8(digest), do: digest |> binary_part(0, 4) |> hex()
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp b64u(bytes), do: Base.url_encode64(bytes, padding: false)

  defp key(n) do
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<n>>, 32))
    public
  end

  defp keyring(keys), do: %{"keys" => keys, "version" => "1.0"}

  defp entry(bytes, overrides \\ []) do
    Map.merge(
      %{
        "active" => true,
        "key_id" => key_id(bytes),
        "public_key" => b64u(bytes),
        "sequence" => 0
      },
      Map.new(overrides, fn {name, value} -> {Atom.to_string(name), value} end)
    )
  end
end
