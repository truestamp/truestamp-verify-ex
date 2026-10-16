# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSON.PointerTest do
  # JSON Pointers into P and the document order of SPEC.md 10.2: a depth-first walk, each
  # value before its contents, members in JCS order and elements by index.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.JCS
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Test.ProofMutants

  test "encode writes RFC 6901, escaping ~ and / in a name" do
    assert Pointer.encode([]) == ""
    assert Pointer.encode(~w(block record merkle_root)) == "/block/record/merkle_root"

    assert Pointer.encode(["subject", "inclusion_proof", "path", 10]) ==
             "/subject/inclusion_proof/path/10"

    assert Pointer.encode(["a/b", "c~d", "~1"]) == "/a~1b/c~0d/~01"
    assert Pointer.encode([""]) == "/"
  end

  test "a prefix comes before what it holds" do
    assert Pointer.compare(["block"], ~w(block record)) == :lt
    assert Pointer.compare(~w(block record), ["block"]) == :gt
    assert Pointer.compare([], ["block"]) == :lt
    assert Pointer.compare(~w(a b), ~w(a b)) == :eq
  end

  test "indices compare by value, not as text" do
    assert Pointer.compare(["path", 2], ["path", 10]) == :lt
    assert Pointer.compare(["path", 10], ["path", 9]) == :gt

    assert Pointer.sort_by([["path", 10], ["path", 1], ["path", 2], ["path"]]) ==
             [["path"], ["path", 1], ["path", 2], ["path", 10]]
  end

  test "names compare as JCS orders members: by UTF-16 code units" do
    # U+FF5A is one code unit, 0xFF5A; U+1F600 is two, 0xD83D 0xDE00, so it sorts first in
    # UTF-16 though its code point is larger (RFC 8785 3.2.3).
    high = "\u{1F600}"
    wide = "\u{FF5A}"
    assert Pointer.compare([high], [wide]) == :lt
    assert JCS.encode(%{high => 1, wide => 2}) == ~s({"#{high}":1,"#{wide}":2})

    assert Pointer.compare(["witnesses"], ["type"]) == :gt
    assert Pointer.compare(["a"], ["ab"]) == :lt
    assert Pointer.compare(["Z"], ["a"]) == :lt
  end

  test "a missing member takes the place it would take" do
    assert Pointer.sort_by([~w(record merkle_root), ~w(record leaf_count), ~w(record id)]) ==
             [~w(record id), ~w(record leaf_count), ~w(record merkle_root)]
  end

  test "sorting the nodes of every sound proof gives the depth-first walk" do
    for {name, proof} <- ProofMutants.bases() do
      walk = proof |> ProofMutants.nodes() |> Enum.map(&elem(&1, 0))
      assert Pointer.sort_by(Enum.shuffle(walk)) == walk, name
    end
  end

  test "first_by gives the earliest, the first of equals, and nil for none" do
    assert Pointer.first_by([]) == nil
    list = [{["b"], 1}, {["a", 3], 2}, {["a", 3], 3}, {["a", 20], 4}]
    assert Pointer.first_by(list, &elem(&1, 0)) == {["a", 3], 2}

    assert Pointer.sort_by(list, &elem(&1, 0)) == [
             {["a", 3], 2},
             {["a", 3], 3},
             {["a", 20], 4},
             {["b"], 1}
           ]
  end
end
