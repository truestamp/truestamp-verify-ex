# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.ReplayTest do
  @moduledoc "The replay reader of SPEC.md section 13.2, beyond the online cases."

  use ExUnit.Case, async: true

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
