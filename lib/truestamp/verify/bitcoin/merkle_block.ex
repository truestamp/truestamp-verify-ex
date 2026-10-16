# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Bitcoin.MerkleBlock do
  @moduledoc """
  A `txoutproof` and its well-formedness (SPEC.md section 10.2, step 9 (d)). The bytes are
  well formed when these rules hold. They are checked in this order, except that the
  partial-tree and duplicate-pair rules are reported in the order the walk meets them: the
  counts of hashes and flag bits before the walk, then the first duplicate pair or the
  first node that finds no bit or hash left, then, after the walk, whether it used every
  hash and every flag bit.

  | Rule | Holds when | Else |
  |---|---|---|
  | parse | they parse completely as a BIP 37 merkleblock: an 80-octet header; `total_txs`, 4 octets little-endian; a compact size and that many 32-octet hashes; a compact size and that many flag octets; and nothing after, with every compact size in its shortest form | `:parse` |
  | total_txs | `total_txs` is from 1 to BITCOIN_MAX_TOTAL_TXS | `:total_txs` |
  | partial tree | the partial Merkle tree walks as Bitcoin Core's CPartialMerkleTree walks one: it has no more hashes than `total_txs` and no fewer flag bits than hashes, and the walk uses every hash and every flag bit, with the bits after the last one used in the final flag octet zero | `:partial_tree` |
  | duplicate pair | no node of the walk has a right child equal to its left (CVE-2012-2459) | `:duplicate_pair` |
  | matches | the walk matches exactly one transaction | `:matches` |
  | merkle root | the root the walk gives equals the header's Merkle root field | `:merkle_root` |
  | target | the header meets the target its nBits field encodes (`Truestamp.Verify.Bitcoin`) | `:target` |

  The walk (Bitcoin Core, src/merkleblock.cpp): the tree over `total_txs` leaves has height
  h, the least with width(h) = 1, where width(g) = (`total_txs` + 2^g - 1) >> g. From the
  root, each node takes the next flag bit, the bits read from the lowest bit of each octet
  up. A node at height 0, or one whose bit is 0, takes the next hash as its value, and a
  leaf whose bit is 1 is a match. Any other node is SHA-256d of its left child and its right
  child, the right child being the left when the node has no right (its position times 2,
  plus 1, is not below the width one level down). A walk that runs out of bits or hashes
  fails `:partial_tree`.

  `parse/1` gives the header, `total_txs` and the one matched hash, in the order it is
  hashed in, or the first rule that fails, in the order above.
  """

  import Bitwise

  alias Truestamp.Verify.Bitcoin
  alias Truestamp.Verify.Spec.Constants

  @typedoc "The first rule of a well-formed `txoutproof` that the bytes break."
  @type rule ::
          :parse
          | :total_txs
          | :partial_tree
          | :duplicate_pair
          | :matches
          | :merkle_root
          | :target

  @typedoc "What a well-formed `txoutproof` gives."
  @type t :: %{header: Bitcoin.header(), total_txs: pos_integer(), matched: <<_::256>>}

  @doc """
  `{:ok, %{header, total_txs, matched}}` when `bytes` is a well-formed `txoutproof`, with
  `matched` the one hash it matches; otherwise `{:error, rule}`, the first rule it breaks.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, rule()}
  def parse(bytes) when is_binary(bytes) do
    with {:ok, header, total, hashes, flags} <- split(bytes),
         :ok <- total_txs(total),
         {:ok, root, matches} <- walk(total, hashes, flags),
         {:ok, matched} <- one_match(matches),
         :ok <- merkle_root(header, root),
         :ok <- target(header) do
      {:ok, %{header: header, total_txs: total, matched: matched}}
    end
  end

  defp split(<<header::binary-80, total::little-32, rest::binary>>) do
    with {:ok, count, rest} <- Bitcoin.compact_size(rest),
         octets = count * 32,
         <<hashes::binary-size(^octets), rest::binary>> <- rest,
         {:ok, count, rest} <- Bitcoin.compact_size(rest),
         <<flags::binary-size(^count)>> <- rest do
      {:ok, header, total, hashes(hashes), flags}
    else
      _broken -> {:error, :parse}
    end
  end

  defp split(_bytes), do: {:error, :parse}

  defp hashes(bytes), do: for(<<hash::binary-32 <- bytes>>, do: hash) |> List.to_tuple()

  defp total_txs(total) when total >= 1, do: max_total_txs(total)
  defp total_txs(_total), do: {:error, :total_txs}

  defp max_total_txs(total) do
    if total <= Constants.bitcoin_max_total_txs(), do: :ok, else: {:error, :total_txs}
  end

  # The walk of CPartialMerkleTree::ExtractMatches, with the check that the unused bits of
  # the final flag octet are zero.
  defp walk(total, hashes, flags) do
    bits = bit_size(flags)

    if tuple_size(hashes) > total or bits < tuple_size(hashes) do
      {:error, :partial_tree}
    else
      state = %{total: total, hashes: hashes, flags: flags, bit: 0, hash: 0, matches: []}

      with {:ok, root, state} <- traverse(height(total, 0), 0, state),
           :ok <- all_used(state, bits),
           do: {:ok, root, state.matches}
    end
  end

  defp height(total, h), do: if(width(total, h) > 1, do: height(total, h + 1), else: h)

  defp width(total, h), do: (total + (1 <<< h) - 1) >>> h

  defp traverse(_h, _position, %{bit: bit, flags: flags}) when bit >= bit_size(flags),
    do: {:error, :partial_tree}

  defp traverse(h, position, state) do
    parent = flag(state.flags, state.bit)
    state = %{state | bit: state.bit + 1}

    if h == 0 or parent == 0,
      do: take_hash(h, position, parent, state),
      else: children(h, position, state)
  end

  defp take_hash(_h, _position, _parent, %{hash: next, hashes: hashes})
       when next >= tuple_size(hashes),
       do: {:error, :partial_tree}

  defp take_hash(h, position, parent, state) do
    hash = elem(state.hashes, state.hash)
    state = %{state | hash: state.hash + 1}

    state =
      if h == 0 and parent == 1,
        do: %{state | matches: [{position, hash} | state.matches]},
        else: state

    {:ok, hash, state}
  end

  defp children(h, position, state) do
    with {:ok, left, state} <- traverse(h - 1, position * 2, state),
         {:ok, right, state} <- right_child(h, position, left, state) do
      {:ok, Bitcoin.sha256d([left, right]), state}
    end
  end

  defp right_child(h, position, left, state) do
    if position * 2 + 1 < width(state.total, h - 1) do
      case traverse(h - 1, position * 2 + 1, state) do
        {:ok, ^left, _state} -> {:error, :duplicate_pair}
        other -> other
      end
    else
      {:ok, left, state}
    end
  end

  # Bit i is bit i mod 8 of octet i div 8, counting from the lowest.
  defp flag(flags, i), do: :binary.at(flags, div(i, 8)) >>> rem(i, 8) &&& 1

  defp all_used(%{bit: used, hash: hashes_used, hashes: hashes, flags: flags}, bits) do
    cond do
      hashes_used != tuple_size(hashes) -> {:error, :partial_tree}
      div(used + 7, 8) != div(bits, 8) -> {:error, :partial_tree}
      unused_bits(flags, used) != 0 -> {:error, :partial_tree}
      true -> :ok
    end
  end

  defp unused_bits(flags, used) do
    for i <- used..(bit_size(flags) - 1)//1, reduce: 0 do
      acc -> acc ||| flag(flags, i)
    end
  end

  defp one_match([{_position, hash}]), do: {:ok, hash}
  defp one_match(_matches), do: {:error, :matches}

  defp merkle_root(header, root) do
    if Bitcoin.merkle_root_field(header) == root, do: :ok, else: {:error, :merkle_root}
  end

  defp target(header), do: if(Bitcoin.meets_target?(header), do: :ok, else: {:error, :target})
end
