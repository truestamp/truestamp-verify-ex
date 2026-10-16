# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Ed25519 do
  @moduledoc """
  Strict Ed25519 verification, Verify(A, msg, S) of SPEC.md section 6.2: pure Ed25519
  (RFC 8032) with one fixed rule at the edges, so that every conforming verifier accepts
  exactly the same signatures.

  Step 1, the canonical base64url spelling of A and S, is the caller's: it decodes them with
  `Truestamp.Verify.Base64URL`, which matches B64U32 and B64U64 first. `verify/3` makes
  steps 2 to 7, in order, and names the step that refuses:

  | Step | Refusal |
  |---|---|
  | 2. y, the little-endian integer of A with its highest bit cleared, is below p | `:y_not_below_p` |
  | 3. A is not one of SMALL_ORDER_KEYS | `:small_order_key` |
  | 4. A decodes as a point, as RFC 8032 section 5.1.3 does | `:not_on_curve` |
  | 5. s, the last 32 octets of S as a little-endian integer, is below L | `:s_not_below_l` |
  | 6. k = SHA-512(R \\|\\| A \\|\\| msg) mod L | (cannot refuse) |
  | 7. the encoding of [s]B - [k]A equals R, the first 32 octets of S | `:equation` |

  Step 7 is the cofactorless equation, with R compared as its encoding; the cofactored one
  accepts signatures this rule refuses (section 6.2). The arithmetic is RFC 8032's own, in
  extended coordinates as its section 6 writes it, and nothing here calls a library's
  Ed25519, since neither OpenSSL nor Go's `crypto/ed25519` makes steps 2 and 3
  (section 6.2, informative).

  Steps 2 and 3 are also "the checks of a key's bytes", which a verifier makes outside
  Verify: on K at ENVELOPE, on each key of a keyring it loads, and on each key event's
  `public_key` at DERIVE (section 6.2). `check_key_bytes/1` makes them.

  SMALL_ORDER_KEYS is compiled from `spec/small-order-keys.json`, and a test holds it to
  SPEC.md's list and to the points it names.
  """

  import Bitwise

  alias Truestamp.Verify.Spec.Data

  @typedoc "Why a key's bytes are refused: step 2 or step 3 of section 6.2."
  @type key_refusal :: :y_not_below_p | :small_order_key

  @typedoc "Why Verify refuses, by the step of section 6.2 that refuses."
  @type refusal :: key_refusal() | :not_on_curve | :s_not_below_l | :equation

  # RFC 8032 section 5.1: p, L, d and the base point B (x even, y = 4/5).
  @p (1 <<< 255) - 19
  @l (1 <<< 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
  @d 37_095_705_934_669_439_343_138_083_508_754_565_189_542_113_879_843_219_016_388_785_533_085_940_283_555
  @sqrt_minus_one 19_681_161_376_707_505_956_807_079_304_988_542_015_446_066_515_923_890_162_744_021_073_123_829_784_752
  @base_x 15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202
  @base_y 46_316_835_694_926_478_169_428_394_003_475_163_141_307_993_866_256_225_615_783_033_603_165_251_855_960

  @external_resource Data.path("small-order-keys.json")

  @small_order_keys (for %{"hex" => hex} <- Data.read!("small-order-keys.json") do
                       Base.decode16!(hex, case: :lower)
                     end)

  @doc "SMALL_ORDER_KEYS (section 6.2): the ten encodings every mode refuses."
  @spec small_order_keys() :: [<<_::256>>]
  def small_order_keys, do: @small_order_keys

  @doc """
  The checks of a key's bytes, steps 2 and 3 of section 6.2, on the 32 octets of a public
  key: `:ok`, `{:error, :y_not_below_p}` or `{:error, :small_order_key}`.
  """
  @spec check_key_bytes(<<_::256>>) :: :ok | {:error, key_refusal()}
  def check_key_bytes(<<_::binary-32>> = key) do
    cond do
      y_of(key) >= @p -> {:error, :y_not_below_p}
      key in @small_order_keys -> {:error, :small_order_key}
      true -> :ok
    end
  end

  @doc """
  Verify(A, msg, S) of section 6.2: `:ok` when the 64-octet signature `signature` verifies
  under the 32-octet public key `key` over `message`, else `{:error, refusal}` naming the
  first step that refuses. Every message Truestamp signs is 32 octets (section 4.1), but the
  rule itself holds for any.
  """
  @spec verify(<<_::256>>, binary(), <<_::512>>) :: :ok | {:error, refusal()}
  def verify(<<_::binary-32>> = key, message, <<r::binary-32, s::binary-32>>)
      when is_binary(message) do
    with :ok <- check_key_bytes(key),
         {:ok, point} <- decode_point(key),
         {:ok, s} <- scalar_below_l(s) do
      <<k::little-unsigned-512>> = :crypto.hash(:sha512, [r, key, message])
      k = rem(k, @l)
      candidate = add(multiply(s, base_point()), negate(multiply(k, point)))
      if encode_point(candidate) == r, do: :ok, else: {:error, :equation}
    end
  end

  defp scalar_below_l(<<s::little-unsigned-256>>) when s < @l, do: {:ok, s}
  defp scalar_below_l(_s), do: {:error, :s_not_below_l}

  defp y_of(<<y::little-unsigned-256>>), do: y &&& (1 <<< 255) - 1

  # Points are in extended homogeneous coordinates {X, Y, Z, T}, with x = X/Z, y = Y/Z and
  # x * y = T/Z (RFC 8032 section 5.1.4 and its section 6).

  @doc false
  @spec base_point() :: tuple()
  def base_point, do: {@base_x, @base_y, 1, mod(@base_x * @base_y)}

  @doc false
  @spec identity() :: tuple()
  def identity, do: {0, 1, 1, 0}

  @doc false
  # RFC 8032 section 5.1.3, for a key whose y is below p. `{:error, :not_on_curve}` when
  # no x satisfies the curve equation, or when x is 0 and the sign bit is set.
  @spec decode_point(<<_::256>>) :: {:ok, tuple()} | {:error, :not_on_curve}
  def decode_point(<<_::binary-32>> = bytes) do
    <<encoded::little-unsigned-256>> = bytes
    y = y_of(bytes)
    sign = encoded >>> 255

    with {:ok, x} <- recover_x(y, sign), do: {:ok, {x, y, 1, mod(x * y)}}
  end

  # x^2 = (y^2 - 1) / (d y^2 + 1). A candidate root is x2^((p + 3) / 8); when its square is
  # -x2 instead, it is multiplied by sqrt(-1); when it is neither, there is no root.
  defp recover_x(y, sign) do
    x2 = mod((y * y - 1) * inverse(@d * y * y + 1))
    x = pow(x2, div(@p + 3, 8))
    x = if mod(x * x - x2) == 0, do: x, else: mod(x * @sqrt_minus_one)

    cond do
      mod(x * x - x2) != 0 -> {:error, :not_on_curve}
      x == 0 and sign == 1 -> {:error, :not_on_curve}
      (x &&& 1) != sign -> {:ok, @p - x}
      true -> {:ok, x}
    end
  end

  @doc false
  # RFC 8032 section 5.1.2: y in little-endian, with the low bit of x in the highest bit.
  @spec encode_point(tuple()) :: <<_::256>>
  def encode_point({x, y, z, _t}) do
    z_inverse = inverse(z)
    x = mod(x * z_inverse)
    y = mod(y * z_inverse)
    <<y ||| (x &&& 1) <<< 255::little-unsigned-256>>
  end

  @doc false
  # The unified addition of RFC 8032 section 6, which also doubles.
  @spec add(tuple(), tuple()) :: tuple()
  def add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    a = mod((y1 - x1) * (y2 - x2))
    b = mod((y1 + x1) * (y2 + x2))
    c = mod(2 * t1 * t2 * @d)
    d = mod(2 * z1 * z2)
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    {mod(e * f), mod(g * h), mod(f * g), mod(e * h)}
  end

  @doc false
  # [n]P, by double and add from the lowest bit.
  @spec multiply(non_neg_integer(), tuple()) :: tuple()
  def multiply(n, point) when is_integer(n) and n >= 0, do: multiply(n, point, identity())

  defp multiply(0, _point, acc), do: acc

  defp multiply(n, point, acc) do
    acc = if (n &&& 1) == 1, do: add(acc, point), else: acc
    multiply(n >>> 1, add(point, point), acc)
  end

  defp negate({x, y, z, t}), do: {mod(-x), y, z, mod(-t)}

  defp mod(a), do: Integer.mod(a, @p)

  defp inverse(a), do: pow(a, @p - 2)

  # a^e mod p, by square and multiply.
  defp pow(a, e), do: pow(mod(a), e, 1)
  defp pow(_a, 0, acc), do: acc
  defp pow(a, e, acc) when (e &&& 1) == 1, do: pow(mod(a * a), e >>> 1, mod(acc * a))
  defp pow(a, e, acc), do: pow(mod(a * a), e >>> 1, acc)
end
