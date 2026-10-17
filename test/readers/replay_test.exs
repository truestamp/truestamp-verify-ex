# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.ReplayTest do
  @moduledoc "The replay reader of SPEC.md section 13.2, beyond the online cases."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.JCS
  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Test.Verification

  @replay Verification.path("vectors/corpus/replay/window-established.json")

  @tag :tmp_dir
  test "refuses a file that is missing, not JSON, or not a replay file", %{tmp_dir: dir} do
    assert {:error, :enoent} = Replay.new(Path.join(dir, "none.json"))

    for {name, bytes} <- [
          {"bad.json", "{,}"},
          {"object.json", "{}"},
          {"record.json", ~s({"reads": [{"answer": {}}]})}
        ] do
      path = Path.join(dir, name)
      File.write!(path, bytes)
      assert {:error, _reason} = Replay.new(path), name
    end

    assert_raise ArgumentError, fn -> Replay.new!(Path.join(dir, "none.json")) end
  end

  @tag :tmp_dir
  test "refuses two records of one read and source, and gives each named source its own", %{
    tmp_dir: dir
  } do
    read = %{"kind" => "bitcoin_tip", "network" => "regtest"}
    found = &%{"outcome" => "found", "value" => %{"height" => &1}}
    path = Path.join(dir, "r.json")

    File.write!(
      path,
      JCS.encode(%{
        "reads" => [
          %{"read" => read, "answer" => found.(1)},
          %{"read" => read, "answer" => found.(2)}
        ]
      })
    )

    assert Replay.new(path) == {:error, :not_a_replay_file}

    records = [
      %{"read" => read, "answer" => found.(1), "source" => "a"},
      %{"read" => read, "answer" => found.(2), "source" => "b"},
      %{"read" => read, "answer" => found.(3)}
    ]

    File.write!(path, JCS.encode(%{"reads" => records}))

    {:ok, {Replay, state}} =
      Replay.new(path, sources: %{"bitcoin" => %{"regtest" => {:all, ["a", "b"]}}})

    assert Replay.sources(state, "bitcoin", "regtest") == {:ok, ["a", "b"], :all}

    assert {:ok, %{"height" => 2}, %{source: "b"}} =
             Replay.read(state, "b", "regtest", :bitcoin_tip, %{})

    assert {:ok, %{"height" => 3}, %{source: "replay"}} =
             Replay.read(state, "replay", "regtest", :bitcoin_tip, %{})
  end

  test "names its one source for the networks whose identity it holds, and NIST" do
    {Replay, state} = Replay.new!(@replay, fetched_at: ~U[2026-01-01 00:00:00Z])
    assert Replay.sources(state, "stellar", "testnet") == {:ok, ["replay"], :first}
    assert Replay.sources(state, "nist", nil) == {:ok, ["replay"], :first}
    assert Replay.sources(state, "bitcoin", "mainnet") == {:error, :no_source}
  end

  test "answers a read it holds, and a read it does not hold is unreachable" do
    {Replay, state} = Replay.new!(@replay, fetched_at: ~U[2026-01-01 00:00:00Z])

    assert {:ok, %{"height" => _},
            %{source: "replay", cached: false, fetched_at: ~U[2026-01-01 00:00:00Z]}} =
             Replay.read(state, "replay", "regtest", :bitcoin_tip, %{})

    assert {:error, {:not_in_replay, %{"kind" => "bitcoin_tip", "network" => "mainnet"}}} =
             Replay.read(state, "replay", "mainnet", :bitcoin_tip, %{})
  end
end
