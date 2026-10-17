# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyringLoadTest do
  # Truestamp.Verify.Keyring: the load checks of SPEC.md 10.2, step 0, each shown to
  # refuse on its own, the negative keyrings of vectors/ each refused by the check it breaks,
  # checks 6 and 7 by E_v (a production keyring is any keyring loaded under prod, section
  # 6.4), every check made on every key, not only the first, and no check beyond the list
  # (no [L]A check, D58 item 16, and no decoding of the point).
  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Base64URL, Ed25519, JSON, KeyId, Keyring}
  alias Truestamp.Verify.Test.{Cases, StrictJSON}

  @root Truestamp.Verify.Test.Verification.root()

  defp seed_key(byte) do
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<byte>>, 32))
    public
  end

  defp entry(octets, sequence \\ 0) do
    %{
      "active" => true,
      "key_id" => KeyId.of(octets),
      "public_key" => Base64URL.encode(octets),
      "sequence" => sequence
    }
  end

  defp key_id_collision, do: key_id_collision(0, %{})

  defp key_id_collision(n, seen) do
    # Its last octet is 0x01, so y is below p, and no key of SMALL_ORDER_KEYS ends so.
    candidate = <<n::little-64, 0::184, 1>>
    id = KeyId.of(candidate)

    case seen do
      %{^id => earlier} -> {earlier, candidate}
      _other -> key_id_collision(n + 1, Map.put(seen, id, candidate))
    end
  end

  defp keyring(entries), do: StrictJSON.canonical(%{"keys" => entries, "version" => "1.0"})

  # A key of order L that no file under spec/ lists: the key of an unpublished seed.
  defp production_key, do: seed_key(0x07)

  defp load(value, environment \\ "prod") when is_map(value),
    do: Keyring.load(StrictJSON.canonical(value), environment)

  describe "a keyring that passes" do
    test "gives its keys in order, as octets, with the digest of the bytes as read" do
      a = production_key()
      b = seed_key(0x08)
      bytes = keyring([entry(a, 0), %{entry(b, 5) | "active" => false}])
      assert {:ok, keyring} = Keyring.load(bytes, "prod", "k.json")

      assert keyring.keys == [
               %{active: true, key_id: KeyId.of(a), public_key: a, sequence: 0},
               %{active: false, key_id: KeyId.of(b), public_key: b, sequence: 5}
             ]

      assert keyring.digest == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
      assert keyring.location == "k.json"
    end

    test "is read under 10.1, so any formatting of the same value loads alike" do
      compact =
        ~s({"version":"1.0","keys":[{"sequence":0,"public_key":") <>
          Base64URL.encode(production_key()) <>
          ~s(","key_id":"#{KeyId.of(production_key())}","active":true}]})

      assert {:ok, a} = Keyring.load(compact, "prod")
      assert {:ok, b} = Keyring.load(keyring([entry(production_key())]), "prod")
      assert a.keys == b.keys
      refute a.digest == b.digest
    end

    test "may hold no key, and a key at MAX_INTEGER's sequence" do
      assert {:ok, %Keyring{keys: []}} = Keyring.load(keyring([]), "prod")
      max = JSON.max_integer()

      assert {:ok, _keyring} =
               load(%{"keys" => [entry(production_key(), max)], "version" => "1.0"})
    end

    # D58 item 16: the load checks are exactly those of step 0. The 5e81cc77 key is the 0x44
    # key plus a point of order 8, of mixed order (SPEC.md 9): it passes the checks of a
    # key's bytes, and only an [L]A check would refuse it.
    test "makes no [L]A check: a mixed-order key loads where no other check refuses it" do
      %{"keys" => keys} = StrictJSON.read_data!(Path.join(@root, "spec/keys.nonproduction.json"))
      mixed = Enum.find(keys, &(&1["key_id"] == "5e81cc77"))
      {:ok, octets} = Base64URL.decode(:b64u32, mixed["public_key"])

      assert {:ok, %Keyring{keys: [%{key_id: "5e81cc77"}]}} =
               Keyring.load(keyring([entry(octets)]), "test")

      assert {:error, :nonproduction_key} = Keyring.load(keyring([entry(octets)]), "prod")
    end

    # D74: the checks of a key's bytes do not decode the point (6.2), so a key whose y is
    # below p but that is on no point of the curve loads; it fails only at SIGNATURE.
    test "does not decode the point: a key off the curve loads under every E_v" do
      off_curve = <<2, 0::248>>
      assert Ed25519.check_key_bytes(off_curve) == :ok
      assert Ed25519.decode_point(off_curve) == {:error, :not_on_curve}
      bytes = keyring([entry(production_key()), entry(off_curve, 1)])

      for environment <- ~w(prod dev staging test) do
        assert {:ok, %Keyring{keys: [_first, %{public_key: ^off_curve}]}} =
                 Keyring.load(bytes, environment),
               environment
      end
    end
  end

  describe "each load check refuses on its own" do
    test "1. the keyring's members, the array and the version" do
      good = %{"keys" => [entry(production_key())], "version" => "1.0"}
      assert {:ok, _keyring} = load(good)

      for bad <- [
            Map.put(good, "comment", "x"),
            Map.delete(good, "version"),
            Map.delete(good, "keys"),
            %{good | "version" => "1.1"},
            %{good | "version" => 1},
            %{good | "keys" => %{}},
            %{good | "keys" => nil}
          ] do
        assert load(bad) == {:error, :keyring_members}, inspect(bad)
      end

      assert Keyring.load("[]", "prod") == {:error, :keyring_members}
      assert Keyring.load(~s("1.0"), "prod") == {:error, :keyring_members}
    end

    test "2. each key's members and their classes" do
      key = entry(production_key())
      assert {:ok, _keyring} = load(%{"keys" => [key], "version" => "1.0"})

      for bad <- [
            Map.put(key, "environment", "test"),
            Map.delete(key, "active"),
            %{key | "active" => "true"},
            %{key | "key_id" => String.upcase(key["key_id"])},
            %{key | "key_id" => key["key_id"] <> "\n"},
            %{key | "public_key" => key["public_key"] <> "="},
            %{key | "public_key" => key["public_key"] <> "\n"},
            %{key | "sequence" => -1},
            %{key | "sequence" => 1.5},
            %{key | "sequence" => "0"},
            %{key | "key_id" => 5},
            %{key | "key_id" => nil},
            "not an object"
          ] do
        assert load(%{"keys" => [bad], "version" => "1.0"}) == {:error, :key_members},
               inspect(bad)
      end
    end

    test "3. each key_id is the key id of its public_key" do
      key = entry(production_key())
      bad = %{key | "key_id" => KeyId.of(seed_key(0x08))}
      assert load(%{"keys" => [bad], "version" => "1.0"}) == {:error, :key_id}

      # On a key other than the first, with the id of a key the keyring does not hold.
      second = %{entry(seed_key(0x08), 1) | "key_id" => KeyId.of(seed_key(0x09))}
      assert load(%{"keys" => [key, second], "version" => "1.0"}) == {:error, :key_id}
    end

    test "4. no two keys share a public_key or a key_id" do
      key = entry(production_key())

      assert load(%{"keys" => [key, %{key | "sequence" => 1}], "version" => "1.0"}) ==
               {:error, :repeated_public_key}

      # A repeat that is not next to its first appearance.
      other = entry(seed_key(0x08), 1)

      assert load(%{"keys" => [key, other, %{key | "sequence" => 2}], "version" => "1.0"}) ==
               {:error, :repeated_public_key}

      assert {:ok, _keyring} =
               load(%{"keys" => [key, entry(seed_key(0x08), 1)], "version" => "1.0"})

      # Two keys whose key ids collide. The load checks read a key's bytes only through the
      # checks of section 6.2, steps 2 and 3, so any two 32-octet values with y below p and
      # of no small order serve; a birthday search over 4-octet ids finds a pair quickly.
      {a, b} = key_id_collision()
      assert KeyId.of(a) == KeyId.of(b) and a != b

      assert load(%{"keys" => [entry(a), entry(b, 1)], "version" => "1.0"}) ==
               {:error, :repeated_key_id}
    end

    test "5. the checks of a key's bytes: y below p, and not a small-order key" do
      identity = <<1, 0::248>>

      assert load(%{"keys" => [entry(identity)], "version" => "1.0"}) ==
               {:error, :small_order_key}

      p_plus_one = <<Integer.pow(2, 255) - 18::little-256>>

      assert load(%{"keys" => [entry(p_plus_one)], "version" => "1.0"}) ==
               {:error, :y_not_below_p}

      assert load(%{"keys" => [entry(production_key()), entry(identity, 1)], "version" => "1.0"}) ==
               {:error, :small_order_key}
    end

    test "6. VECTOR_KEY only when E_v is test" do
      bytes = keyring([entry(Keyring.vector_key())])
      assert {:ok, _keyring} = Keyring.load(bytes, "test")

      for environment <- ~w(prod dev staging) do
        assert Keyring.load(bytes, environment) == {:error, :vector_key}
      end

      # On a key other than the first.
      second = keyring([entry(production_key()), entry(Keyring.vector_key(), 1)])
      assert Keyring.load(second, "staging") == {:error, :vector_key}
      assert {:ok, _keyring} = Keyring.load(second, "test")
    end

    test "7. under prod, no key of spec/keys.nonproduction.json; under any other E_v, any" do
      for octets <- Keyring.nonproduction_keys() -- [Keyring.vector_key()] do
        bytes = keyring([entry(production_key()), entry(octets, 1)])
        assert Keyring.load(bytes, "prod") == {:error, :nonproduction_key}

        for environment <- ~w(dev staging test) do
          assert {:ok, _keyring} = Keyring.load(bytes, environment)
        end
      end
    end

    test "J1 to J6 first: a file too large, and one that breaks a parsing rule" do
      padded = keyring([]) <> String.duplicate(" ", JSON.max_read_octets())
      assert Keyring.load(padded, "prod") == {:error, {:json, :input_too_large}}

      assert Keyring.load(~s({"keys":[],"version":"1.0","keys":[]}), "prod") ==
               {:error, {:json, {:malformed_json, :duplicate_name}}}
    end
  end

  describe "the keyrings of vectors/negative/" do
    @failures %{
      "configuration-keyring-duplicate_name" => {:json, {:malformed_json, :duplicate_name}},
      "configuration-keyring-extra_member" => :keyring_members,
      "configuration-keyring-key_extra_member" => :key_members,
      "configuration-keyring-repeated_key" => :repeated_public_key,
      "configuration-keyring-small_order_key" => :small_order_key,
      "configuration-keyring-version" => :keyring_members,
      "configuration-keyring-wrong_key_id" => :key_id,
      "configuration-keyring-y_not_below_p" => :y_not_below_p
    }

    test "each fails the one check its name gives, under test, the E_v of its case" do
      dir = Path.join(Cases.vectors(), "negative")
      files = dir |> File.ls!() |> Enum.filter(&String.starts_with?(&1, "configuration-keyring-"))

      assert Enum.sort(files) ==
               Enum.sort(Enum.map(Map.keys(@failures), &(&1 <> ".keyring.json")))

      for {name, failure} <- @failures do
        bytes = File.read!(Path.join(dir, name <> ".keyring.json"))
        assert Keyring.load(bytes, "test") == {:error, failure}, name
      end
    end

    test "the non-production keyring loads under test, and is refused as a production keyring" do
      path =
        Path.join(
          Cases.vectors(),
          "negative/configuration-nonproduction_key-under-prod.keyring.json"
        )

      bytes = File.read!(path)
      assert {:ok, _keyring} = Keyring.load(bytes, "test")
      assert Keyring.load(bytes, "prod") == {:error, :nonproduction_key}
    end
  end

  describe "the compiled pin" do
    test "is spec/keyring.production.json byte for byte, and passes the load checks under prod" do
      bytes = File.read!(Path.join(@root, "spec/keyring.production.json"))
      assert Keyring.compiled_pin() == bytes
      assert {:ok, %Keyring{}} = Keyring.load(bytes, "prod")
    end

    test "spec/keys.nonproduction.json and VECTOR_KEY are compiled in" do
      %{"keys" => keys} = StrictJSON.read_data!(Path.join(@root, "spec/keys.nonproduction.json"))

      assert Keyring.nonproduction_keys() ==
               Enum.map(keys, fn %{"public_key" => text} ->
                 {:ok, octets} = Base64URL.decode(:b64u32, text)
                 octets
               end)

      assert Base.encode16(Keyring.vector_key(), case: :lower) ==
               StrictJSON.read_data!(Path.join(@root, "spec/constants.json"))["VECTOR_KEY"]
    end
  end

  test "find/2 compares all 32 octets and reads no key id" do
    k = production_key()
    other = seed_key(0x08)

    keyring = %Keyring{
      keys: [%{active: true, key_id: KeyId.of(k), public_key: other, sequence: 0}],
      digest: "",
      location: nil
    }

    assert Keyring.find(keyring, k) == nil
    assert %{public_key: ^other} = Keyring.find(keyring, other)

    # A key that shares the key id of a keyring key, and one that differs from it in its
    # last octet only, bind nothing (section 6.1: only the full comparison binds).
    {a, b} = key_id_collision()
    {:ok, loaded} = Keyring.load(keyring([entry(a)]), "test")
    <<head::binary-31, last>> = a
    assert %{public_key: ^a} = Keyring.find(loaded, a)
    assert Keyring.find(loaded, b) == nil
    assert Keyring.find(loaded, <<head::binary, Bitwise.bxor(last, 1)>>) == nil
  end

  test "describe/1 gives a sentence for every failure" do
    failures = [
      {:json, :input_too_large},
      {:json, {:malformed_json, :depth}},
      :keyring_members,
      :key_members,
      :key_id,
      :repeated_key_id,
      :repeated_public_key,
      :y_not_below_p,
      :small_order_key,
      :vector_key,
      :nonproduction_key
    ]

    descriptions = Enum.map(failures, &Keyring.describe/1)
    assert Enum.uniq(descriptions) == descriptions
  end
end
