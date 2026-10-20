# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ConformanceModuleTest do
  @moduledoc """
  `Truestamp.Verify.Conformance` itself: what it refuses of a cases file, how it reports a
  difference, and the document `mix truestamp.conformance` writes.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Conformance, Fault, JSON, ReadError}
  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Test.{Cases, Verification}

  @vectors Verification.vectors()

  defp kase(config, extra \\ %{}) do
    Map.merge(
      %{
        "id" => "x",
        "proof" => "positive/item.proof.json",
        "config" => config,
        "expected" => %{"label" => "failed", "rows" => []}
      },
      extra
    )
  end

  @networks %{
    "commitment" => %{"bitcoin" => "regtest", "stellar" => "testnet"},
    "entropy" => %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  describe "cases/1" do
    @tag :tmp_dir
    test "refuses a file that cannot be read, is not JSON, or is not an array", %{tmp_dir: dir} do
      assert {:error, "/no/cases.json cannot be read: " <> _} =
               Conformance.cases("/no/cases.json")

      File.write!(Path.join(dir, "bad.json"), "{,}")
      assert {:error, message} = Conformance.cases(Path.join(dir, "bad.json"))
      assert message =~ "not JSON"
      File.write!(Path.join(dir, "object.json"), "{}")
      assert {:error, message} = Conformance.cases(Path.join(dir, "object.json"))
      assert message =~ "not an array"
    end
  end

  # Cases whose `sources` 13.2 does not allow: beside no `online`, or of the wrong form.
  defp invalid_sources do
    entry = &%{"stellar" => %{"testnet" => &1}}
    online = &Map.put(&1, "online", "corpus/replay/window-established.json")
    base = %{"environment" => "test", "networks" => @networks}

    for {config, online?} <- [
          {%{"sources" => entry.(%{"policy" => "all", "sources" => ["a"]})}, false},
          {%{"sources" => []}, true},
          {%{"sources" => %{"stellar" => []}}, true},
          {%{"sources" => entry.(%{"policy" => "most", "sources" => ["a"]})}, true},
          {%{"sources" => entry.(%{"policy" => "all", "sources" => []})}, true},
          {%{"sources" => entry.(%{"policy" => "all", "sources" => ["a", "a"]})}, true},
          {%{"sources" => entry.(%{"policy" => "all", "sources" => [~s(a"b)]})}, true},
          {%{"sources" => entry.(%{"policy" => "all", "sources" => "a"})}, true},
          {%{
             "sources" => entry.(%{"policy" => "at_least", "required" => -1, "sources" => ["a"]})
           }, true}
        ] do
      config = Map.merge(base, config)
      {kase(if(online?, do: online.(config), else: config)), "an invalid sources"}
    end
  end

  describe "options/2" do
    test "refuses a case whose form or configuration section 13.2 does not allow" do
      for {kase, why} <-
            [
              {%{"id" => "x"}, "Not a case"},
              {kase(%{"environment" => "test", "networks" => @networks, "extra" => 1}),
               "which 13.2 does not"},
              {kase(%{"environment" => "moon", "networks" => @networks}), "invalid environment"},
              {kase(%{"environment" => "test", "networks" => %{}}), "invalid networks"},
              {kase(%{"environment" => "test", "networks" => @networks, "keyring" => 7}),
               "invalid keyring"},
              {kase(%{
                 "environment" => "test",
                 "networks" => @networks,
                 "keyring" => "unavailable"
               }), "belongs to an online case"},
              {kase(%{
                 "environment" => "test",
                 "networks" => @networks,
                 "online" => "corpus/replay/none.json"
               }), "replay file cannot be read"}
            ] ++ invalid_sources() do
        assert {:error, message} = Conformance.options(kase, @vectors)
        assert message =~ why, inspect(kase)
      end
    end

    test "an online case reads its replay file, and its keyring read" do
      online = Cases.get!("key_binding-unavailable-unreachable")
      assert {:ok, options} = Conformance.options(online, @vectors)
      assert {Replay, _state} = options[:reader]
      assert {_module, _state} = options[:current_keyring]
    end
  end

  describe "output/2 and compare/3" do
    test "a result that is neither a report nor a rejection is an error, which compares as one" do
      assert %{"error" => "Cannot read" <> _} =
               Conformance.output({:error, ReadError.new("p", :enoent)})

      assert %{"error" => _} = Conformance.output({:error, Fault.new(:throw, :x, [])})
      assert Conformance.output({:error, "a case's message"}) == %{"error" => "a case's message"}
      assert Conformance.compare(kase(%{}), %{"error" => "why"}, @vectors) == {:error, "why"}
    end

    test "names the first row that differs, a label that differs, and an edge that differs" do
      expected = %{
        "label" => "failed",
        "rows" => [["a", nil, "fail", "READ"], ["b", nil, "fail", "PARSE"]]
      }

      assert {:error, "row 1:" <> _} =
               Conformance.compare(
                 %{"expected" => expected},
                 %{
                   expected
                   | "rows" => [["a", nil, "fail", "READ"], ["c", nil, "fail", "PARSE"]]
                 },
                 @vectors
               )

      assert {:error, "row 2:" <> _} =
               Conformance.compare(
                 %{"expected" => expected},
                 %{expected | "rows" => expected["rows"] ++ [["d", nil, "fail", "SHAPE"]]},
                 @vectors
               )

      assert {:error, "expected " <> _} =
               Conformance.compare(
                 %{"expected" => expected},
                 %{expected | "label" => "verified"},
                 @vectors
               )

      assert {:error, "expected " <> _} =
               Conformance.compare(%{"expected" => %{"code" => "x"}}, %{"code" => "y"}, @vectors)

      edge = %{"basis" => "stellar_ledger_close_read", "instant" => "2026-09-26T01:48:30Z"}
      with_edges = Map.merge(expected, %{"submitted_after" => nil, "submitted_before" => edge})
      assert Conformance.compare(%{"expected" => with_edges}, with_edges, @vectors) == :ok

      same_instant =
        Map.put(with_edges, "submitted_before", %{edge | "instant" => "2026-09-26T01:48:30.000Z"})

      assert Conformance.compare(%{"expected" => with_edges}, same_instant, @vectors) == :ok

      assert {:error, "submitted_before" <> _} =
               Conformance.compare(
                 %{"expected" => with_edges},
                 Map.put(with_edges, "submitted_before", nil),
                 @vectors
               )

      assert {:error, "submitted_after" <> _} =
               Conformance.compare(
                 %{"expected" => with_edges},
                 Map.put(with_edges, "submitted_after", edge),
                 @vectors
               )
    end
  end

  describe "the run's code of a report case (sections 13.1 and 13.2)" do
    test "output_options/1 asks for the code exactly where the expected output gives one" do
      two_steps = Cases.get!("two_steps-policy-derive")
      assert Conformance.output_options(two_steps)[:code?] == true
      assert Conformance.output_options(Cases.get!("sound-item"))[:code?] == false
      assert Conformance.output_options(Cases.get!("reads-bitcoin-tip_final"))[:online?] == true
    end

    test "output/2 gives a failed report's code only under code?, and compare/3 compares it" do
      two_steps = Cases.get!("two_steps-policy-derive")
      result = Conformance.run(two_steps, @vectors)

      with_code = Conformance.output(result, Conformance.output_options(two_steps))
      assert with_code["code"] == "network_mismatch"
      assert Conformance.compare(two_steps, with_code, @vectors) == :ok

      without = Conformance.output(result, trace?: false, online?: false)
      refute Map.has_key?(without, "code")
      assert {:error, "expected " <> _} = Conformance.compare(two_steps, without, @vectors)

      # The second failing row's code is not the run's.
      later = %{with_code | "code" => "derivation_mismatch"}
      assert {:error, "expected " <> _} = Conformance.compare(two_steps, later, @vectors)

      # A report that did not fail has no code to give, so a case that expects one differs.
      passed = Conformance.run(Cases.get!("sound-item"), @vectors)
      refute Map.has_key?(Conformance.output(passed, code?: true), "code")
    end
  end

  describe "main/1" do
    @cases Verification.path("vectors/cases.json")

    test "writes the document of every case, or of the offline ones under --offline-only" do
      offline = Enum.reject(Cases.all(), &Conformance.online?/1)
      expected = Conformance.document(offline, @vectors)

      for argv <- [[@cases, "--offline-only"], ["--offline-only", @cases]] do
        assert {0, ^expected, summary} = Conformance.main(argv)
        left_out = length(Cases.all()) - length(offline)
        assert summary =~ "Ran #{length(offline)} cases of #{@cases}; left out #{left_out} online"
      end
    end

    @tag :tmp_dir
    test "refuses a command line, or a cases file, it cannot use", %{tmp_dir: dir} do
      File.write!(Path.join(dir, "form.json"), ~s([{"id": "x"}]))

      for argv <- [
            [],
            [@cases, @cases],
            [@cases, "--online-only"],
            [<<0xFF>>],
            [Path.join(dir, "none.json")],
            [Path.join(dir, "form.json")]
          ] do
        assert {1, "", stderr} = Conformance.main(argv), inspect(argv)
        assert IO.iodata_to_binary(stderr) =~ Conformance.usage()
      end
    end

    test "a fault inside the entry point exits 2, with nothing on standard output" do
      assert {2, "", stderr} = Conformance.main([123])
      assert IO.iodata_to_binary(stderr) =~ "A fault inside the conformance entry point: "
    end
  end

  test "document/2: one entry per case, in order, each {id, output}" do
    cases = Enum.take(Cases.all(), 3) ++ [Cases.get!("reads-bitcoin-tip_final")]
    document = Conformance.document(cases, @vectors)
    assert String.ends_with?(document, "\n")
    {:ok, entries} = JSON.parse(document)
    assert Enum.map(entries, & &1["id"]) == Enum.map(cases, & &1["id"])

    assert Enum.all?(
             entries,
             &(Map.has_key?(&1["output"], "label") or Map.has_key?(&1["output"], "code"))
           )

    assert Map.has_key?(List.last(entries)["output"], "submitted_before")
  end
end
