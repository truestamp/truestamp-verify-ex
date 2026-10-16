# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.MerkleWalkTest do
  # The pinned truestamp_merkle walks an inclusion proof as RFC 9162 section 2.1.3.2
  # does. The case is the last entry of the "leaf-3" tree in the library's
  # vectors/merkle.json, recomputed here with :crypto so the library's root is not taken
  # on trust.
  use ExUnit.Case, async: true

  @digest0 "d103cfb5e499c566904787533afbdec56f95492d67fc00e2c0d0161ba99653f1"
  @digest1 "5038da95330ba16edb486954197e37eb777c3047327ca54df4199c35c5edc17a"
  @digest2 "f2764fd79fdab5132fc349ba555c9c56ff0c935c889c17ebe3d61315d780934e"
  @node01 "5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5"
  @root "f078fbabd10cf51db1dc3552d960996e0fdae24ca5559d3aec20bf04cb65c441"

  test "walk reaches the RFC 9162 root of a three-entry tree from its last entry" do
    leaf = fn hex -> :crypto.hash(:sha256, <<0>> <> Base.decode16!(hex, case: :lower)) end
    node = fn left, right -> :crypto.hash(:sha256, <<1>> <> left <> right) end
    hex = &Base.encode16(&1, case: :lower)

    # RFC 9162 splits three leaves into two and one, with no padding leaf.
    node01 = node.(leaf.(@digest0), leaf.(@digest1))
    assert hex.(node01) == @node01
    assert hex.(node.(node01, leaf.(@digest2))) == @root

    proof = %{leaf_index: 2, tree_size: 3, path: [@node01]}
    assert Truestamp.Merkle.walk(@digest2, proof) == {:ok, @root}

    # Index 2 of four leaves takes two path nodes, so the same path is refused there.
    assert Truestamp.Merkle.walk(@digest2, %{proof | tree_size: 4}) ==
             {:error, :wrong_path_length}
  end
end
