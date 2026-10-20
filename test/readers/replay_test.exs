# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.ReplayTest do
  @moduledoc "The replay reader of SPEC.md section 13.2, beyond the online cases."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Conformance, JCS, JSON}
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
             Replay.read(state, :replay, "regtest", :bitcoin_tip, %{})

    # A source named "replay" is a named source: it reads only the records that name it.
    assert {:error, {:not_in_replay, ^read}} =
             Replay.read(state, "replay", "regtest", :bitcoin_tip, %{})
  end

  test "names its one source for the networks whose identity it holds, and NIST" do
    {Replay, state} = Replay.new!(@replay, fetched_at: ~U[2026-01-01 00:00:00Z])
    assert Replay.sources(state, "stellar", "testnet") == {:ok, [:replay], :first}
    assert Replay.sources(state, "nist", nil) == {:ok, [:replay], :first}
    assert Replay.sources(state, "bitcoin", "mainnet") == {:error, :no_source}
  end

  test "answers a read it holds, and a read it does not hold is unreachable" do
    {Replay, state} = Replay.new!(@replay, fetched_at: ~U[2026-01-01 00:00:00Z])

    assert {:ok, %{"height" => _}, meta} =
             Replay.read(state, :replay, "regtest", :bitcoin_tip, %{})

    # Nothing it answers is cached, and no meta carries a tip_height.
    assert meta == %{source: "replay", cached: false, fetched_at: ~U[2026-01-01 00:00:00Z]}

    assert {:ok, %{"hash" => _}, ^meta} =
             Replay.read(state, :replay, "regtest", :bitcoin_block_at_height, %{"height" => 222})

    assert {:error, {:not_in_replay, %{"kind" => "bitcoin_tip", "network" => "mainnet"}}} =
             Replay.read(state, :replay, "mainnet", :bitcoin_tip, %{})
  end

  describe "a source named \"replay\"" do
    # Every case that names several sources, with one of its sources renamed "replay" in
    # its config and in the records of its replay that name it: section 13.2's names are
    # strings, and "replay" is one, so the case gives the same output as before. The
    # unnamed source of every other network keeps answering from its own records.
    @vectors Verification.vectors()
    {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))
    @sources_cases Enum.filter(cases, &Map.has_key?(&1["config"], "sources"))

    @tag :tmp_dir
    test "gives each case the output it gives under the source's own name", %{tmp_dir: dir} do
      vectors = Path.join(dir, "vectors")
      File.mkdir_p!(vectors)

      for entry <- File.ls!(@vectors),
          do: File.ln_s!(Path.join(@vectors, entry), Path.join(vectors, entry))

      renamed = Path.join(vectors, "renamed")
      File.mkdir_p!(renamed)

      runs =
        for kase <- @sources_cases,
            {chain, networks} <- kase["config"]["sources"],
            {network, %{"sources" => names}} <- networks,
            name <- names do
          {kase, renamed(kase, chain, network, name, renamed)}
        end

      assert length(runs) > length(@sources_cases)

      for {kase, renamed_case} <- runs do
        options = [online?: true, trace?: Map.has_key?(kase["expected"], "trace")]
        expected = kase |> Conformance.run(@vectors) |> Conformance.output(options)
        output = renamed_case |> Conformance.run(vectors) |> Conformance.output(options)

        assert output == expected, renamed_case["id"]
        assert Conformance.compare(kase, output, @vectors) == :ok, renamed_case["id"]
      end
    end

    # The case with `name` of `chain` and `network` renamed "replay", in its config and in
    # its replay's records of that network, the replay written under `dir`.
    defp renamed(kase, chain, network, name, dir) do
      {:ok, %{"reads" => records}} =
        @vectors |> Path.join(kase["config"]["online"]) |> File.read!() |> JSON.parse()

      records =
        for record <- records do
          if record["source"] == name and record["read"]["network"] == network and
               String.starts_with?(record["read"]["kind"], chain <> "_"),
             do: %{record | "source" => "replay"},
             else: record
        end

      assert Enum.any?(records, &(&1["source"] == "replay"))

      id = Enum.join([kase["id"], chain, network, name], "-")
      File.write!(Path.join(dir, id <> ".json"), JCS.encode(%{"reads" => records}))

      kase
      |> Map.put("id", id)
      |> put_in(["config", "online"], "renamed/#{id}.json")
      |> update_in(["config", "sources", chain, network, "sources"], fn names ->
        Enum.map(names, &if(&1 == name, do: "replay", else: &1))
      end)
    end
  end
end
