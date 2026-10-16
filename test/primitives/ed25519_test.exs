# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Ed25519Test do
  # Strict verification (SPEC.md 6.2): vectors/corpus/ed25519.json, each held to the step
  # that refuses it; each step on its own, at its boundary; SMALL_ORDER_KEYS against
  # SPEC.md and against the points it names; and agreement with OTP's :crypto on keys and
  # signatures that pass steps 2 and 3, where section 6.2 says OpenSSL makes steps 4 to 7 as
  # written.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.{Base64URL, Ed25519}
  alias Truestamp.Verify.Spec.Constants
  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @corpus Path.join(@root, "vectors/corpus/ed25519.json")
  @external_resource @corpus

  @p (1 <<< 255) - 19
  @l (1 <<< 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
  @steps %{
    y_not_below_p: 2,
    small_order_key: 3,
    not_on_curve: 4,
    s_not_below_l: 5,
    equation: 7
  }

  @cases with {:ok, cases} <- @corpus |> File.read!() |> StrictJSON.decode(), do: cases

  defp corpus, do: @cases

  defp le(integer), do: <<integer::little-unsigned-256>>

  defp keypair(seed) do
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, seed)
    {public, seed}
  end

  defp sign(seed, message), do: :crypto.sign(:eddsa, :none, message, [seed, :ed25519])

  defp step(:ok), do: :pass
  defp step({:error, refusal}), do: Map.fetch!(@steps, refusal)

  describe "the corpus" do
    test "holds a passing case and a case for each step that can refuse" do
      cases = corpus()
      assert length(cases) == 28
      assert Enum.any?(cases, &(&1["verify"] == "pass"))

      assert cases
             |> Enum.map(& &1["step"])
             |> Enum.reject(&is_nil/1)
             |> Enum.uniq()
             |> Enum.sort() == [2, 3, 4, 5, 7]
    end

    for entry <- @cases do
      @entry entry

      test "#{entry["id"]}" do
        {:ok, key} = Base64URL.decode(:b64u32, @entry["public_key"])
        {:ok, signature} = Base64URL.decode(:b64u64, @entry["signature"])
        message = Base.decode16!(@entry["message"], case: :lower)
        expected = if @entry["verify"] == "pass", do: :pass, else: @entry["step"]

        assert step(Ed25519.verify(key, message, signature)) == expected
      end
    end
  end

  describe "the checks of a key's bytes (steps 2 and 3)" do
    test "take y = p - 1 and refuse y = p, with the sign bit clear and set" do
      # y = p - 1 is -1, the point of order 2, which step 3 refuses.
      assert Ed25519.check_key_bytes(le(@p - 1)) == {:error, :small_order_key}
      assert Ed25519.check_key_bytes(le(@p)) == {:error, :y_not_below_p}
      assert Ed25519.check_key_bytes(le(@p ||| 1 <<< 255)) == {:error, :y_not_below_p}
      assert Ed25519.check_key_bytes(le(@p - 2)) == :ok
      assert Ed25519.check_key_bytes(le(@p - 2 ||| 1 <<< 255)) == :ok
    end

    test "refuse every y from p to 2^255 - 1, the second spellings of y below 19" do
      for y <- @p..((1 <<< 255) - 1), sign <- [0, 1] do
        assert Ed25519.check_key_bytes(le(y ||| sign <<< 255)) == {:error, :y_not_below_p}
      end
    end

    test "refuse each of SMALL_ORDER_KEYS, and take a key that differs from one in a bit" do
      for key <- Ed25519.small_order_keys() do
        assert Ed25519.check_key_bytes(key) == {:error, :small_order_key}
        <<first, rest::binary>> = key

        refute Ed25519.check_key_bytes(<<bxor(first, 0x04), rest::binary>>) ==
                 {:error, :small_order_key}
      end
    end

    test "take every key Truestamp's generator derives from a seed" do
      for seed <- [<<0x41>>, <<0x42>>, <<0x43>>, <<0x44>>] do
        {key, _seed} = keypair(:binary.copy(seed, 32))
        assert Ed25519.check_key_bytes(key) == :ok
      end
    end

    test "are made inside Verify, before the key is decoded" do
      signature = <<1, 0::248, 0::256>>
      message = <<0::256>>
      # The identity, whose signature (identity, 0) verifies over every message, is refused
      # at step 3, and its spelling with y = p + 1 at step 2.
      assert Ed25519.verify(le(1), message, signature) == {:error, :small_order_key}
      assert Ed25519.verify(le(@p + 1), message, signature) == {:error, :y_not_below_p}
    end
  end

  describe "SMALL_ORDER_KEYS" do
    test "is SPEC.md's list of ten, in its order" do
      listed =
        ~r/^([0-9a-f]{64})   (identity|order [248])/m
        |> Regex.scan(File.read!(Path.join(@root, "SPEC.md")))
        |> Enum.map(fn [_line, hex, _order] -> Base.decode16!(hex, case: :lower) end)

      assert length(listed) == 10
      assert Ed25519.small_order_keys() == listed
      assert Enum.uniq(listed) == listed
    end

    test "names every point whose order divides 8, each once with y below p" do
      {canonical, variants} =
        Enum.split_with(Ed25519.small_order_keys(), fn key ->
          match?({:ok, _point}, Ed25519.decode_point(key))
        end)

      # The eight points of the 8-torsion subgroup, all distinct, each killed by [8].
      assert length(canonical) == 8
      identity = Ed25519.encode_point(Ed25519.identity())

      for key <- canonical do
        {:ok, point} = Ed25519.decode_point(key)
        assert Ed25519.encode_point(Ed25519.multiply(8, point)) == identity
        assert Ed25519.encode_point(point) == key
      end

      orders =
        for key <- canonical do
          {:ok, point} = Ed25519.decode_point(key)

          Enum.find(
            [1, 2, 4, 8],
            &(Ed25519.encode_point(Ed25519.multiply(&1, point)) == identity)
          )
        end

      assert Enum.frequencies(orders) == %{1 => 1, 2 => 1, 4 => 2, 8 => 4}

      # The other two are the identity and the point of order 2 with the sign bit set, which
      # RFC 8032 refuses to decode.
      assert Enum.sort(variants) == Enum.sort([le(1 ||| 1 <<< 255), le(@p - 1 ||| 1 <<< 255)])
    end
  end

  describe "the curve's constants" do
    test "the base point is RFC 8032's, and has order L" do
      base = Ed25519.base_point()
      assert Ed25519.encode_point(base) == <<0x58>> <> :binary.copy(<<0x66>>, 31)

      assert Ed25519.encode_point(Ed25519.multiply(@l, base)) ==
               Ed25519.encode_point(Ed25519.identity())

      refute Ed25519.encode_point(Ed25519.multiply(@l - 1, base)) ==
               Ed25519.encode_point(Ed25519.identity())
    end

    test "every public key :crypto derives is [a]B for its clamped secret scalar a" do
      for seed <- [:binary.copy(<<0x42>>, 32), :crypto.strong_rand_bytes(32)] do
        {key, _seed} = keypair(seed)
        <<low::binary-32, _high::binary-32>> = :crypto.hash(:sha512, seed)
        <<a::little-unsigned-256>> = low
        a = (a &&& (1 <<< 254) - 8) ||| 1 <<< 254
        assert Ed25519.encode_point(Ed25519.multiply(a, Ed25519.base_point())) == key
      end
    end
  end

  describe "steps 4 to 7" do
    test "step 4 refuses a y with no x on the curve" do
      {:ok, key} =
        Base64URL.decode(:b64u32, Enum.find(corpus(), &(&1["step"] == 4))["public_key"])

      assert Ed25519.decode_point(key) == {:error, :not_on_curve}
      assert Ed25519.check_key_bytes(key) == :ok

      assert Ed25519.verify(key, <<0::256>>, <<0::512>>) == {:error, :not_on_curve}

      # Steps 4 and 5 in order: a key off the curve with s = L, which step 5 would refuse
      # too, is refused at step 4.
      assert Ed25519.verify(key, <<0::256>>, <<1, 0::248, @l::little-unsigned-256>>) ==
               {:error, :not_on_curve}

      # The corpus holds the same pair of refusals.
      entry = Enum.find(corpus(), &(&1["id"] == "step_4-not_on_curve-s_equal_l"))
      assert entry["step"] == 4
      {:ok, key} = Base64URL.decode(:b64u32, entry["public_key"])

      {:ok, <<_r::binary-32, s::little-unsigned-256>> = signature} =
        Base64URL.decode(:b64u64, entry["signature"])

      assert s >= @l
      assert Ed25519.check_key_bytes(key) == :ok
      assert Ed25519.decode_point(key) == {:error, :not_on_curve}
      message = Base.decode16!(entry["message"], case: :lower)
      assert Ed25519.verify(key, message, signature) == {:error, :not_on_curve}
    end

    test "step 5 takes s = L - 1 and refuses s = L and s + L, which step 7 alone would take" do
      {key, seed} = keypair(:binary.copy(<<0x42>>, 32))
      message = :crypto.hash(:sha256, "step 5")
      <<r::binary-32, s::little-unsigned-256>> = sign(seed, message)

      assert Ed25519.verify(key, message, <<r::binary, s::little-unsigned-256>>) == :ok

      assert Ed25519.verify(key, message, <<r::binary, s + @l::little-unsigned-256>>) ==
               {:error, :s_not_below_l}

      # [s + L]B = [s]B, so only step 5 tells the two spellings apart.
      base = Ed25519.base_point()

      assert Ed25519.encode_point(Ed25519.multiply(s + @l, base)) ==
               Ed25519.encode_point(Ed25519.multiply(s, base))

      assert Ed25519.verify(key, message, <<r::binary, @l::little-unsigned-256>>) ==
               {:error, :s_not_below_l}

      assert Ed25519.verify(key, message, <<r::binary, @l - 1::little-unsigned-256>>) ==
               {:error, :equation}

      assert Ed25519.verify(key, message, <<r::binary, (1 <<< 256) - 1::little-unsigned-256>>) ==
               {:error, :s_not_below_l}
    end

    test "step 7 binds the message, the key and every octet of the signature" do
      {key, seed} = keypair(:binary.copy(<<0x44>>, 32))
      {other_key, _seed} = keypair(:binary.copy(<<0x41>>, 32))
      message = :crypto.hash(:sha256, "step 7")
      signature = sign(seed, message)

      assert Ed25519.verify(key, message, signature) == :ok
      assert Ed25519.verify(other_key, message, signature) == {:error, :equation}

      for bit <- 0..255 do
        flipped = <<bxor(:binary.decode_unsigned(message), 1 <<< bit)::256>>
        assert Ed25519.verify(key, flipped, signature) == {:error, :equation}
      end

      # Every bit of R and of s: a changed s is refused at step 5 when it reaches L, and at
      # step 7 otherwise.
      for bit <- 0..511 do
        <<head::bitstring-size(^bit), b::1, tail::bitstring>> = signature
        tampered = <<head::bitstring, 1 - b::1, tail::bitstring>>

        assert Ed25519.verify(key, message, tampered) in [
                 {:error, :equation},
                 {:error, :s_not_below_l}
               ]
      end
    end

    test "step 7 compares every bit of R: R one bit off, with s derived for it, is refused" do
      # VECTOR_KEY's seed, and r, the nonce of RFC 8032 section 5.1.6 for this message. For
      # each R' one bit off R = [r]B, s' = r + k'a mod L with k' = SHA-512(R' || A || M) mod
      # L, so [s']B - [k']A = [r]B = R: everything holds but the comparison of R' with R.
      seed = :binary.copy(<<0x42>>, 32)
      {key, _seed} = keypair(seed)
      assert Base.encode16(key, case: :lower) == Constants.vector_key()
      message = :crypto.hash(:sha256, "step 7, R")

      <<low::little-unsigned-256, prefix::binary-32>> = :crypto.hash(:sha512, seed)
      a = (low &&& (1 <<< 254) - 8) ||| 1 <<< 254
      <<nonce::little-unsigned-512>> = :crypto.hash(:sha512, [prefix, message])
      r = rem(nonce, @l)
      big_r = Ed25519.encode_point(Ed25519.multiply(r, Ed25519.base_point()))

      signed_with = fn r_bytes ->
        <<k::little-unsigned-512>> = :crypto.hash(:sha512, [r_bytes, key, message])
        <<r_bytes::binary, rem(r + rem(k, @l) * a, @l)::little-unsigned-256>>
      end

      # For R itself the construction is RFC 8032's signature, which verifies.
      assert signed_with.(big_r) == sign(seed, message)
      assert Ed25519.verify(key, message, signed_with.(big_r)) == :ok

      for bit <- 0..255 do
        <<head::bitstring-size(^bit), b::1, tail::bitstring>> = big_r
        signature = signed_with.(<<head::bitstring, 1 - b::1, tail::bitstring>>)

        assert Ed25519.verify(key, message, signature) == {:error, :equation}, "bit #{bit}"
        refute :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519]), "bit #{bit}"
      end
    end

    test "verifies over a message of any length, not only 32 octets" do
      {key, seed} = keypair(:binary.copy(<<0x43>>, 32))

      for message <- ["", "a", :binary.copy("x", 1000)] do
        assert Ed25519.verify(key, message, sign(seed, message)) == :ok
      end
    end

    test "refuses a key or a signature of the wrong size by raising" do
      assert_raise FunctionClauseError, fn -> Ed25519.verify(<<0::248>>, "", <<0::512>>) end
      assert_raise FunctionClauseError, fn -> Ed25519.verify(le(1), "", <<0::504>>) end
      assert_raise FunctionClauseError, fn -> Ed25519.check_key_bytes(<<0::264>>) end
    end
  end

  describe "agreement with OTP's :crypto" do
    test "both pass each genuine signature, and both refuse each tampered one" do
      for _ <- 1..40 do
        {key, seed} = keypair(:crypto.strong_rand_bytes(32))
        message = :crypto.strong_rand_bytes(32)
        signature = sign(seed, message)

        assert Ed25519.verify(key, message, signature) == :ok
        assert :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519])

        <<_r::binary-32, s::binary-32>> = signature
        other = :crypto.strong_rand_bytes(32)

        for {m, sig} <- [{other, signature}, {message, <<other::binary, s::binary>>}] do
          refute Ed25519.verify(key, m, sig) == :ok
          refute :crypto.verify(:eddsa, :none, m, sig, [key, :ed25519])
        end
      end
    end
  end
end
