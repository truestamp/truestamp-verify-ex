# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.ReadsTest do
  @moduledoc """
  The engine's side of every read (SPEC.md section 10.4), the same for every reader: the
  three shapes of an answer, the live-read rules, one answer per read, the deadline, and a
  reader that raises.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Online.Reads
  alias Truestamp.Verify.Test.FakeReader

  defp read(answer, kind \\ :stellar_ledger, deadline \\ nil) do
    reader = FakeReader.new(%{{"fake", "testnet", kind, %{}} => answer})
    Reads.read(reader, "fake", "testnet", kind, %{}, deadline)
  end

  test "a found, a not-found and an error answer each keep their shape" do
    assert {:found, %{"a" => 1}, %{cached: false}} = read(FakeReader.found(%{"a" => 1}))
    assert {:not_found, %{source: "fake"}} = read(FakeReader.not_found())
    assert read({:error, :timeout}) == {:unreachable, :timeout}
  end

  test "an answer in no shape, or with no usable meta, is unreachable" do
    assert read(:what) == {:unreachable, :malformed_answer}
    assert read({:ok, [1], FakeReader.meta()}) == {:unreachable, :malformed_answer}
    assert read({:ok, %{}, %{source: "s"}}) == {:unreachable, :malformed_answer}
    assert read({:error, :not_found, %{}}) == {:unreachable, :malformed_answer}
  end

  test "a cached not-found answer is refused, since every not-found answer is read live" do
    assert read(FakeReader.not_found(cached: true)) == {:unreachable, :cached_not_found}
  end

  test "a cached answer to a read the spec requires live is refused, and any other is kept" do
    for kind <- [:stellar_identity, :bitcoin_identity, :stellar_root, :bitcoin_tip] do
      assert read(FakeReader.found(%{}, cached: true), kind) == {:unreachable, :cached_live_read}
    end

    assert {:found, _fields, %{cached: true}} =
             read(FakeReader.found(%{}, cached: true), :stellar_ledger)
  end

  test "a reader that raises, throws or exits gives an unreachable read, never a fault" do
    assert {:unreachable, {:reader_fault, :error, "RuntimeError"}} = read(fn -> raise "boom" end)
    assert {:unreachable, {:reader_fault, :throw, nil}} = read(fn -> throw(:boom) end)
    assert {:unreachable, {:reader_fault, :exit, nil}} = read(fn -> exit(:boom) end)
  end

  test "a read past the deadline is unreachable, and one that outlasts it is cut short" do
    past = System.monotonic_time(:millisecond) - 1
    assert read(FakeReader.found(%{}), :stellar_ledger, past) == {:unreachable, :deadline}

    soon = System.monotonic_time(:millisecond) + 50
    slow = fn -> Process.sleep(2_000) && FakeReader.found(%{}) end
    assert read(slow, :stellar_ledger, soon) == {:unreachable, :deadline}

    later = System.monotonic_time(:millisecond) + 5_000

    assert {:found, %{"a" => 1}, _meta} =
             read(FakeReader.found(%{"a" => 1}), :stellar_ledger, later)
  end

  test "a bound read answers from the run's memo before it asks the reader" do
    key = {"fake", "testnet", :stellar_root, %{}}
    memo = %{key => {:not_found, FakeReader.meta()}}
    read = Reads.bind(FakeReader.new(%{}), "fake", "testnet", memo, nil)
    assert {:not_found, _meta} = read.(:stellar_root, %{})
    assert read.(:stellar_ledger, %{}) == {:unreachable, :not_scripted}
  end
end
