# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.EdgesTest do
  @moduledoc """
  The edges of the building blocks that no conformance case reaches: structures cut short,
  empty values, the order of mixed pointer segments, and the defaults of public functions.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.Bitcoin.{MerkleBlock, Transaction}
  alias Truestamp.Verify.{CanonicalForm, Check, Conformance, JSON, Keyring, Layout, Report}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.Rule
  alias Truestamp.Verify.Test.{Rules, Verification}

  describe "a raw_transaction cut short is refused at :parse" do
    test "before its version, inside an input, inside an output" do
      assert Transaction.parse(<<1, 0, 0>>) == {:error, :parse}
      # version, one input, then the outpoint stops short.
      assert Transaction.parse(<<1, 0, 0, 0, 1, 0::size(20)-unit(8)>>) == {:error, :parse}
      # version, one input with an empty script, one output whose value stops short.
      input = <<0::size(36)-unit(8), 0, 0xFF, 0xFF, 0xFF, 0xFF>>
      assert Transaction.parse(<<1, 0, 0, 0, 1, input::binary, 1, 0, 0, 0>>) == {:error, :parse}
    end
  end

  test "a txoutproof whose walk runs out of flag bits is refused at :partial_tree" do
    header = <<0::size(80)-unit(8)>>
    # 1,024 transactions need a walk of 11 levels; one flag octet, all ones, holds 8 bits.
    bytes = <<header::binary, 1024::little-32, 1, 0::size(32)-unit(8), 1, 0xFF>>
    assert MerkleBlock.parse(bytes) == {:error, :partial_tree}
  end

  test "the canonical form of an empty object and an empty array" do
    assert CanonicalForm.encode(%{}) == "{}\n"
    assert CanonicalForm.encode([]) == "[]\n"
    assert CanonicalForm.encode(%{"a" => [], "b" => %{}}) == "{\n  \"a\": [],\n  \"b\": {}\n}\n"
  end

  test "an index and a name at one position are ordered index first, only to be total" do
    assert Pointer.compare([0], ["a"]) == :lt
    assert Pointer.compare(["a"], [0]) == :gt
    assert Pointer.compare(["a", 1], ["a", 1]) == :eq
  end

  describe "reading a file (J1)" do
    @tag :tmp_dir
    test "an empty file is the empty document; a directory cannot be read", %{tmp_dir: dir} do
      path = Path.join(dir, "empty.json")
      File.write!(path, "")
      assert JSON.read_file(path) == {:ok, ""}
      assert {:error, {:unreadable, _reason}} = JSON.read_file(dir)
    end
  end

  test "the defaults of the public functions" do
    check = Check.equal(["a"], "c", [], 1, 1)
    assert check.outcome == :pass and check.traced

    {:ok, value} = JSON.decode(File.read!(Verification.path("vectors/keyring.test.json")))
    assert {:ok, %Keyring{digest: nil, location: nil}} = Keyring.load_value(value, "test")

    context = Rules.context(%{})
    assert Rule.fail(context, :chain_mismatch).values == %{"reads" => []}

    {:ok, report} =
      Verify.verify_file(Verification.path("vectors/positive/item.proof.json"),
        environment: :test,
        trust: {:keyring_file, Verification.path("vectors/keyring.test.json")}
      )

    refute Map.has_key?(Report.reduce(report), "trace")
  end

  test "the layout skips what P's type does not hold" do
    assert Layout.entropy_objects(%{"type" => "entropy_moon"}) == []
    assert Layout.get(%{"a" => [%{"b" => 1}]}, ["a", 0, "b"]) == 1
    assert Layout.get(%{"a" => 1}, ["a", 0]) == nil
  end

  test "a difference in an output of another shape is named whole" do
    assert {:error, "expected " <> _} =
             Conformance.compare(
               %{"expected" => %{"label" => "failed", "rows" => []}},
               %{"code" => "x"},
               Verification.vectors()
             )
  end
end
