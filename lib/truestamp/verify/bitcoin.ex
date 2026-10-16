# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Bitcoin do
  @moduledoc """
  What the Bitcoin evidence checks of SPEC.md section 10.2, step 9 (d), share: SHA-256d,
  display order, the compact size, and the 80-octet block header.

  SHA-256d is SHA-256 applied twice, and rev reverses byte order (the `encoding` row of
  section 7.3). A Bitcoin hash is written in display order, rev of the order it is hashed in,
  as a proof's members are (section 2.2).

  **The compact size** is Bitcoin's variable-length integer: one octet below 0xfd, or 0xfd,
  0xfe or 0xff followed by 2, 4 or 8 octets little-endian. `compact_size/1` reads only the
  shortest form, as step 9 (d) requires of every compact size in a `raw_transaction` or a
  `txoutproof`.

  **The header's fields**, by octet (step 9 (d)): the version (0 to 3), the previous block
  hash (4 to 35), the Merkle root field (36 to 67), nTime (68 to 71, little-endian Unix
  seconds), nBits (72 to 75, little-endian) and the nonce (76 to 79).

  **The target** nBits encodes, with n the nBits value, e = n >> 24, and w = n & 0x007fffff,
  shifted right by 8 x (3 - e) bits when e is at most 3:

  - the encoding is negative when w is not 0 and n & 0x00800000 is not 0;
  - it overflows when w is not 0 and e > 34, or w > 0xff and e > 33, or w > 0xffff and
    e > 32;
  - the target is w when e is at most 3, and w x 256^(e - 3) otherwise.

  A header meets its target unless its encoding is negative or overflows, the target is 0,
  or rev(SHA-256d(header)), read as a big-endian integer, is above the target.
  """

  import Bitwise

  @typedoc "An 80-octet block header."
  @type header :: <<_::640>>

  @doc "SHA-256d: SHA-256 applied twice."
  @spec sha256d(iodata()) :: <<_::256>>
  def sha256d(bytes), do: :crypto.hash(:sha256, :crypto.hash(:sha256, bytes))

  @doc "rev(`bytes`) as lowercase hex: a Bitcoin hash in display order."
  @spec display(binary()) :: String.t()
  def display(bytes) when is_binary(bytes),
    do: bytes |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin() |> hex()

  @doc "`bytes` as lowercase hex, in the order they are held."
  @spec hex(binary()) :: String.t()
  def hex(bytes) when is_binary(bytes), do: Base.encode16(bytes, case: :lower)

  @doc """
  Reads a compact size from the front of `bytes`: `{:ok, n, rest}`, or `:error` when the
  bytes run out or the size is not in its shortest form.
  """
  @spec compact_size(binary()) :: {:ok, non_neg_integer(), binary()} | :error
  def compact_size(<<n, rest::binary>>) when n < 0xFD, do: {:ok, n, rest}
  def compact_size(<<0xFD, n::little-16, rest::binary>>) when n >= 0xFD, do: {:ok, n, rest}

  def compact_size(<<0xFE, n::little-32, rest::binary>>) when n > 0xFFFF,
    do: {:ok, n, rest}

  def compact_size(<<0xFF, n::little-64, rest::binary>>) when n > 0xFFFF_FFFF,
    do: {:ok, n, rest}

  def compact_size(_bytes), do: :error

  @doc "rev(SHA-256d(header)): the header's hash, in display order."
  @spec header_hash(header()) :: String.t()
  def header_hash(<<_::binary-80>> = header), do: header |> sha256d() |> display()

  @doc "rev(the header's Merkle root field), in display order."
  @spec header_merkle_root(header()) :: String.t()
  def header_merkle_root(<<_::binary-36, root::binary-32, _::binary-12>>), do: display(root)

  @doc "The header's Merkle root field, in the order it is hashed in."
  @spec merkle_root_field(header()) :: <<_::256>>
  def merkle_root_field(<<_::binary-36, root::binary-32, _::binary-12>>), do: root

  @doc "The header's nTime: Unix seconds."
  @spec header_time(header()) :: non_neg_integer()
  def header_time(<<_::binary-68, time::little-32, _::binary-8>>), do: time

  @doc "Whether the header meets the target its nBits field encodes."
  @spec meets_target?(header()) :: boolean()
  def meets_target?(<<_::binary-72, bits::little-32, _::binary-4>> = header) do
    <<hash::little-unsigned-256>> = sha256d(header)

    case target(bits) do
      {:ok, target} -> target > 0 and hash <= target
      :error -> false
    end
  end

  @doc """
  The target an nBits value `n` encodes: `{:ok, target}`, or `:error` when the encoding is
  negative or overflows.
  """
  @spec target(non_neg_integer()) :: {:ok, non_neg_integer()} | :error
  def target(n) when is_integer(n) and n >= 0 do
    e = n >>> 24
    w = n &&& 0x007FFFFF
    w = if e <= 3, do: w >>> (8 * (3 - e)), else: w

    cond do
      w != 0 and (n &&& 0x00800000) != 0 -> :error
      w != 0 and overflows?(w, e) -> :error
      e <= 3 -> {:ok, w}
      true -> {:ok, w <<< (8 * (e - 3))}
    end
  end

  defp overflows?(w, e), do: e > 34 or (w > 0xFF and e > 33) or (w > 0xFFFF and e > 32)
end
