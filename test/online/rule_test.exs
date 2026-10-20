# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.RuleTest do
  @moduledoc """
  One entry judged outside a run (`Truestamp.Verify.Online.Rule`, "Judging one entry
  outside a run"): a context over a reader reads as a whole run reads, through the engine's
  side of every read, and gives each source the outcome a whole run gives it;
  `confirm_identity/2` is step 0's identity read for one source; a context over a read
  function takes its answers as they come. The outcomes of each rule, one branch at a time,
  are the tests of each chain module, whose contexts are built over a reader
  (`Truestamp.Verify.Test.Rules`).
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.Chains.{Bitcoin, Nist, Stellar}
  alias Truestamp.Verify.{Config, Conformance, Edge, Hash, JSON, Keyring, Layout, Report, Row}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.Rule
  alias Truestamp.Verify.Test.{Cases, FakeReader, Verification}

  @passphrase "Test SDF Network ; September 2015"
  @production_passphrase "Public Global Stellar Network ; September 2015"
  @mainnet_genesis "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  @record %{"leaf_count" => 1, "merkle_root" => String.duplicate("ab", 32)}
  @tx String.duplicate("cd", 32)
  @stellar_entry %{
    "epoch" => %{"record" => @record},
    "ledger" => 1000,
    "network" => "testnet",
    "transaction_hash" => @tx
  }
  @transaction_read {"fake", "testnet", :stellar_transaction, %{"hash" => @tx}}
  @root_read {"fake", "testnet", :stellar_root, %{}}

  defp over(answers, options \\ []) do
    Rule.new(
      FakeReader.new(answers),
      Keyword.merge([source: "fake", network: "testnet", part: "/commitments/stellar"], options)
    )
  end

  defp reasons(outcome), do: for(read <- outcome.values["reads"], do: read["reason"])

  describe "a context over a reader" do
    test "a cached not-found answer is refused, so only a live one reaches the rule" do
      cached =
        Stellar.commitment(
          over(%{@transaction_read => FakeReader.not_found(cached: true)}),
          @stellar_entry
        )

      assert {cached.status, cached.code} == {:skip, :source_unreachable}
      assert reasons(cached) == ["cached_not_found"]

      live =
        Stellar.commitment(
          over(%{
            @transaction_read => FakeReader.not_found(),
            @root_read => FakeReader.found(%{"elder" => 1001, "latest" => 5000})
          }),
          @stellar_entry
        )

      assert {live.status, live.code} == {:skip, :not_held_by_source}
      assert live.values["elder"] == 1001
    end

    test "a cached root, a read the spec requires live, is refused" do
      outcome =
        Stellar.commitment(
          over(%{
            @transaction_read => FakeReader.not_found(),
            @root_read => FakeReader.found(%{"elder" => 1001, "latest" => 5000}, cached: true)
          }),
          @stellar_entry
        )

      assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
      assert reasons(outcome) == [nil, "cached_live_read"]
    end

    test "a reader that raises, throws or exits gives an unreachable read, never a raise" do
      for {fault, kind} <- [
            {fn -> raise "boom" end, "RuntimeError"},
            {fn -> throw(:boom) end, nil},
            {fn -> exit(:boom) end, nil}
          ],
          deadline <- [nil, 5_000] do
        outcome =
          Stellar.commitment(
            over(%{@transaction_read => fault}, deadline: deadline),
            @stellar_entry
          )

        assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
        assert [%{"outcome" => "unreachable", "reason" => reason}] = outcome.values["reads"]
        assert reason =~ "reader_fault"
        if kind, do: assert(reason =~ kind)
      end
    end

    test "an answer in no shape is unreachable" do
      outcome = Stellar.commitment(over(%{@transaction_read => {:ok, :what}}), @stellar_entry)
      assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
      assert reasons(outcome) == ["malformed_answer"]
    end

    test "a deadline that ends a read leaves it unreachable, and a spent one reads nothing" do
      slow = fn -> Process.sleep(2_000) && FakeReader.found(%{"ledger" => 1000}) end
      started = System.monotonic_time(:millisecond)

      outcome =
        Stellar.commitment(over(%{@transaction_read => slow}, deadline: 50), @stellar_entry)

      assert System.monotonic_time(:millisecond) - started < 1_500
      assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
      assert reasons(outcome) == ["deadline"]

      counter = :counters.new(1, [])

      counted = fn ->
        :counters.add(counter, 1, 1)
        FakeReader.not_found()
      end

      outcome =
        Stellar.commitment(over(%{@transaction_read => counted}, deadline: 0), @stellar_entry)

      assert reasons(outcome) == ["deadline"]
      assert :counters.get(counter, 1) == 0
    end

    test "every read goes to the source and network named, and only to them" do
      elsewhere = FakeReader.found(%{"successful" => false})

      answers = %{
        @transaction_read => FakeReader.not_found(),
        @root_read => FakeReader.found(%{"elder" => 1001, "latest" => 5000}),
        {"other", "testnet", :stellar_transaction, %{"hash" => @tx}} => elsewhere,
        {"fake", "public", :stellar_transaction, %{"hash" => @tx}} => elsewhere,
        {"testnet", "fake", :stellar_transaction, %{"hash" => @tx}} => elsewhere
      }

      outcome = Stellar.commitment(over(answers), @stellar_entry)
      assert {outcome.status, outcome.code} == {:skip, :not_held_by_source}

      assert [
               %{"kind" => "stellar_transaction", "outcome" => "not_found", "source" => "fake"},
               _root
             ] =
               outcome.values["reads"]
    end

    test "top_level? false reads no candidate, and the default is true" do
      transaction =
        FakeReader.found(%{
          "ledger" => 1000,
          "memo" => Hash.hash_hex(:epoch_hash, @record),
          "memo_type" => "hash",
          "successful" => true
        })

      ledger = {"fake", "testnet", :stellar_ledger, %{"sequence" => 1000}}
      closed = FakeReader.found(%{"closed_at" => "2026-09-26T01:48:30Z", "hash" => "x"})
      answers = %{@transaction_read => transaction, ledger => closed}

      nested = Stellar.commitment(over(answers, top_level?: false), @stellar_entry)
      assert {nested.status, nested.candidate} == {:pass, nil}

      top = Stellar.commitment(over(answers), @stellar_entry)
      assert %Edge{part: "/commitments/stellar", source: "fake"} = top.candidate
    end

    test "an option missing, unknown or out of its class raises" do
      reader = FakeReader.new(%{})
      base = [source: "fake", network: "testnet", part: "/p"]

      for name <- [:source, :network, :part] do
        assert_raise KeyError, fn -> Rule.new(reader, Keyword.delete(base, name)) end
      end

      assert_raise ArgumentError, fn -> Rule.new(reader, [{:sorce, "fake"} | base]) end

      assert_raise ArgumentError, ~r/part/, fn ->
        Rule.new(reader, Keyword.put(base, :part, ["p"]))
      end

      assert_raise ArgumentError, ~r/top_level/, fn ->
        Rule.new(reader, base ++ [top_level?: "yes"])
      end

      for deadline <- [-1, 1.5, :soon] do
        assert_raise ArgumentError, ~r/deadline/, fn ->
          Rule.new(reader, base ++ [deadline: deadline])
        end
      end
    end

    test "a network is a string, or nil for NIST, and anything else raises" do
      reader = FakeReader.new(%{})
      base = [source: "fake", part: "/p"]

      for network <- [:mainnet, :testnet, 42, ["testnet"]] do
        assert_raise ArgumentError, ~r/network/, fn ->
          Rule.new(reader, [network: network] ++ base)
        end
      end

      for network <- ["testnet", nil] do
        assert %Rule{part: "/p"} = Rule.new(reader, [network: network] ++ base)
      end
    end

    test "with no deadline a read runs in the calling process, and with one in a task it started" do
      caller = self()

      probe = fn ->
        send(caller, {:read_in, self(), Process.get(:"$callers")})
        FakeReader.not_found()
      end

      answers = %{@transaction_read => probe, @root_read => FakeReader.not_found()}

      Stellar.commitment(over(answers), @stellar_entry)
      assert_receive {:read_in, ^caller, _callers}

      Stellar.commitment(over(answers, deadline: 5_000), @stellar_entry)
      assert_receive {:read_in, task, [^caller | _]}
      assert task != caller

      identity = %{{"fake", "testnet", :stellar_identity, %{}} => probe}
      options = [chain: "stellar", source: "fake", network: "testnet"]

      Rule.confirm_identity(FakeReader.new(identity), options)
      assert_receive {:read_in, ^caller, _callers}

      Rule.confirm_identity(FakeReader.new(identity), options ++ [deadline: 5_000])
      assert_receive {:read_in, task, [^caller | _]}
      assert task != caller
    end
  end

  describe "a cached best-chain Bitcoin block at a height, judged by Bitcoin's rule" do
    {:ok, document} =
      "vectors/positive/item.proof.json" |> Verification.path() |> File.read!() |> JSON.parse()

    @entry document["proof"]["commitments"]["bitcoin"]
    @height @entry["height"]

    defp bitcoin(tip_options) do
      block = fn height, fields ->
        {{"fake", "regtest", :bitcoin_block_at_height, %{"height" => height}},
         FakeReader.found(fields, [cached: true] ++ tip_options)}
      end

      answers =
        Map.new([
          {{"fake", "regtest", :bitcoin_tip, %{}}, FakeReader.found(%{"height" => @height + 11})},
          block.(@height, %{
            "hash" => @entry["header_hash"],
            "median_time_past" => 1,
            "transaction_count" => 5
          }),
          block.(@height + 10, %{
            "hash" => "x",
            "median_time_past" => 1_790_387_820,
            "transaction_count" => 1
          })
        ])

      Bitcoin.commitment(
        Rule.new(FakeReader.new(answers),
          source: "fake",
          network: "regtest",
          part: "/commitments/bitcoin"
        ),
        @entry
      )
    end

    test "read under a final tip for both heights, it passes, its candidate cached" do
      outcome = bitcoin(tip_height: @height + 20)
      assert {outcome.status, outcome.code} == {:pass, nil}
      assert %Edge{cached: true} = outcome.candidate
      assert Edge.milliseconds(outcome.candidate) == 1_790_387_820_000
    end

    test "read under a tip final for h but not for h + 10, the candidate read is refused" do
      outcome = bitcoin(tip_height: @height + 19)
      assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
      assert reasons(outcome) == [nil, nil, "cached_not_final"]
    end

    test "with no tip, the block at h is refused" do
      outcome = bitcoin([])
      assert {outcome.status, outcome.code} == {:skip, :source_unreachable}
      assert reasons(outcome) == [nil, "cached_not_final"]
    end
  end

  describe "confirm_identity/2" do
    defp identity(network, kind, answer, options \\ []) do
      reader = FakeReader.new(%{{"fake", network, kind, %{}} => answer})
      chain = if kind == :stellar_identity, do: "stellar", else: "bitcoin"
      Rule.confirm_identity(reader, [chain: chain, source: "fake", network: network] ++ options)
    end

    test "a source that shows the network it is pinned to is confirmed" do
      passphrase = FakeReader.found(%{"network_passphrase" => @passphrase})
      assert identity("testnet", :stellar_identity, passphrase) == :ok

      production = FakeReader.found(%{"network_passphrase" => @production_passphrase})
      assert identity("public", :stellar_identity, production) == :ok

      genesis = FakeReader.found(%{"hash" => @mainnet_genesis})
      assert identity("mainnet", :bitcoin_identity, genesis) == :ok

      assert identity(
               "regtest",
               :bitcoin_identity,
               FakeReader.found(%{"hash" => String.duplicate("0f", 32)})
             ) == :ok
    end

    test "a source that shows another network is forbidden" do
      production = FakeReader.found(%{"network_passphrase" => @production_passphrase})
      assert identity("testnet", :stellar_identity, production) == :forbidden

      genesis = FakeReader.found(%{"hash" => @mainnet_genesis})
      assert identity("regtest", :bitcoin_identity, genesis) == :forbidden

      other = FakeReader.found(%{"hash" => String.duplicate("0f", 32)})
      assert identity("mainnet", :bitcoin_identity, other) == :forbidden
    end

    test "no usable answer leaves the source unreachable" do
      assert identity("testnet", :stellar_identity, FakeReader.not_found()) ==
               {:unreachable, :identity_not_found}

      assert identity(
               "testnet",
               :stellar_identity,
               FakeReader.found(%{"network_passphrase" => 7})
             ) ==
               {:unreachable, :identity_unusable}

      cached = FakeReader.found(%{"network_passphrase" => @passphrase}, cached: true)
      assert identity("testnet", :stellar_identity, cached) == {:unreachable, :cached_live_read}

      assert {:unreachable, {:reader_fault, :error, "RuntimeError"}} =
               identity("testnet", :stellar_identity, fn -> raise "boom" end)

      slow = fn ->
        Process.sleep(2_000) && FakeReader.found(%{"network_passphrase" => @passphrase})
      end

      assert identity("testnet", :stellar_identity, slow, deadline: 50) ==
               {:unreachable, :deadline}
    end

    test "NIST has no identity read, and a name no chain has is refused" do
      for chain <- ["nist", "ethereum", :stellar] do
        assert_raise ArgumentError, ~r/chain/, fn ->
          Rule.confirm_identity(FakeReader.new(%{}), chain: chain, source: "fake", network: nil)
        end
      end

      assert_raise KeyError, fn ->
        Rule.confirm_identity(FakeReader.new(%{}), chain: "stellar", source: "fake")
      end
    end

    test "a network the specification does not name for the chain is refused, before any read" do
      counter = :counters.new(1, [])

      counted = fn ->
        :counters.add(counter, 1, 1)
        FakeReader.found(%{"hash" => @mainnet_genesis})
      end

      for {chain, network} <- [
            {"bitcoin", "public"},
            {"bitcoin", "Mainnet"},
            {"bitcoin", :mainnet},
            {"bitcoin", nil},
            {"stellar", "mainnet"},
            {"stellar", nil},
            {"stellar", 42}
          ] do
        reader = FakeReader.new(%{{"fake", network, :bitcoin_identity, %{}} => counted})

        assert_raise ArgumentError, ~r/network/, fn ->
          Rule.confirm_identity(reader, chain: chain, source: "fake", network: network)
        end
      end

      assert :counters.get(counter, 1) == 0
    end
  end

  describe "unconfirmed/1" do
    test "is the outcome a run gives each entry against a source whose identity is unconfirmed" do
      assert Rule.unconfirmed(:identity_not_found) == %Rule.Outcome{
               status: :skip,
               code: :source_unreachable,
               values: %{"identity" => "identity_not_found"}
             }

      replay = Verification.path("vectors/corpus/replay/window-established.json")

      reader =
        FakeReader.from_replay(replay,
          overrides: %{{:stellar_identity, %{}} => {:error, :timeout}}
        )

      assert {:unreachable, reason} =
               Rule.confirm_identity(reader,
                 chain: "stellar",
                 source: "fake",
                 network: "testnet"
               )

      expected = Rule.unconfirmed(reason)

      config =
        Config.internal!(environment: :test, key_chain: [Keyring.vector_key()], reader: reader)

      {:ok, report} =
        Verify.verify_file(Verification.path("vectors/positive/item.proof.json"), config)

      served =
        for %Row{step: step, values: %{"outcomes" => [outcome]}} = row <- report.rows,
            step in [:chain, :sources],
            row.part in ["/commitments/stellar", "/witnesses/entropy_stellar"],
            do: {row, outcome}

      assert length(served) == 2

      for {row, outcome} <- served do
        assert {row.status, row.code} == {expected.status, expected.code}

        assert {outcome["status"], outcome["code"], outcome["reads"]} ==
                 {Atom.to_string(expected.status), Atom.to_string(expected.code), []}

        assert row.values["notes"] == [Map.put(expected.values, "source", "fake")]
      end
    end
  end

  describe "a context over a read function" do
    test "its answers are judged as they come, a cached not-found among them" do
      read = fn
        :stellar_transaction, _params ->
          {:not_found, FakeReader.meta(cached: true)}

        :stellar_root, _params ->
          {:found, %{"elder" => 1001, "latest" => 5000}, FakeReader.meta()}
      end

      outcome = Stellar.commitment(Rule.new(read, part: "/commitments/stellar"), @stellar_entry)
      assert {outcome.status, outcome.code} == {:skip, :not_held_by_source}
    end

    test "a function that raises raises through the rule" do
      read = fn _kind, _params -> raise "boom" end

      assert_raise RuntimeError, "boom", fn ->
        Stellar.commitment(Rule.new(read, part: "/p"), @stellar_entry)
      end
    end
  end

  describe "against a whole run" do
    # Each entry or object of a proof, by its pointer: its module, rule, value, whether it is
    # top-level, and the pin that names its network.
    defp judged_values(proof) do
      entries =
        for {at, chain, entry} <- Layout.commitment_entries(proof),
            do: {at, {chain, :commitment, entry, match?(["commitments" | _], at), :commitment}}

      genesis =
        for {at, chain, object} <- Layout.genesis_objects(proof),
            do: {at, {chain, :genesis, object, false, :commitment}}

      entropy =
        for {at, source, object} <- Layout.entropy_objects(proof),
            do: {at, {source, :entropy, object, true, :entropy}}

      Map.new(entries ++ genesis ++ entropy, fn {at, value} -> {Pointer.encode(at), value} end)
    end

    defp judge(reader, config, {module, rule, value, top_level?, pin}, part, name) do
      network = if module == Nist, do: nil, else: config.networks[pin][module.name()]

      # The reader's id of the source a row's values name: a string names itself, and an
      # atom, such as the replay's one source `:replay`, is named by its text.
      {reader_module, state} = reader
      {:ok, ids, _policy} = reader_module.sources(state, module.name(), network)
      source = Enum.find(ids, &(to_string(&1) == name)) || flunk("no source #{name}")

      confirmed =
        if module == Nist,
          do: :ok,
          else:
            Rule.confirm_identity(reader, chain: module.name(), source: source, network: network)

      case confirmed do
        :ok ->
          context =
            Rule.new(reader, source: source, network: network, part: part, top_level?: top_level?)

          outcome = apply(module, rule, [context, value])

          {Atom.to_string(outcome.status), outcome.code && Atom.to_string(outcome.code),
           outcome.candidate &&
             %{
               "basis" => outcome.candidate.basis,
               "instant" => Edge.instant_string(outcome.candidate)
             }}

        {:unreachable, reason} ->
          outcome = Rule.unconfirmed(reason)
          {Atom.to_string(outcome.status), Atom.to_string(outcome.code), nil}
      end
    end

    test "each source of each row of every online case is given the outcome the run gives it" do
      judged =
        for kase <- Cases.online(),
            {:ok, %Report{rows: rows}} <- [Conformance.run(kase, Cases.vectors())],
            options = Cases.options(kase),
            {:ok, config} = Config.external(options),
            {:ok, document} = kase |> Cases.proof() |> JSON.parse(),
            values = judged_values(document["proof"]),
            %Row{step: step, values: %{"outcomes" => outcomes}} = row <- rows,
            step in [:chain, :sources],
            outcome <- outcomes do
          {module, rule, _value, _top_level?, _pin} = value = Map.fetch!(values, row.part)
          expected = {outcome["status"], outcome["code"], outcome["candidate"]}
          actual = judge(options[:reader], config, value, row.part, outcome["source"])
          assert actual == expected, "#{kase["id"]} #{row.part} #{outcome["source"]}"
          {module, rule, outcome["status"]}
        end

      assert length(judged) > 500

      # Every outcome a whole run gives each rule in the cases, each of them at least once; no
      # case's genesis object skips, so Bitcoin's own tests hold that branch.
      for {module, rule, statuses} <- [
            {Stellar, :commitment, ["pass", "fail", "skip"]},
            {Bitcoin, :commitment, ["pass", "fail", "skip"]},
            {Bitcoin, :genesis, ["pass", "fail"]},
            {Nist, :entropy, ["pass", "fail", "skip"]},
            {Stellar, :entropy, ["pass", "fail", "skip"]},
            {Bitcoin, :entropy, ["pass", "fail", "skip"]}
          ],
          status <- statuses do
        assert {module, rule, status} in judged, "#{inspect(module)}.#{rule} #{status}"
      end
    end
  end

  describe "a repeat online run whose Bitcoin blocks at a height are cached" do
    @item Verification.path("vectors/positive/item.proof.json")
    @replay Verification.path("vectors/corpus/replay/window-established.json")

    # The replay's reads, the Stellar transaction unreachable so that Bitcoin alone gives the
    # submitted-before edge, and each block at a height answered as `blocks` gives it.
    defp reader(blocks) do
      {module, state} = FakeReader.from_replay(@replay)

      answers =
        Map.new(state.answers, fn
          {{_id, _network, :stellar_transaction, _params} = key, _answer} ->
            {key, {:error, :timeout}}

          {{_id, _network, :bitcoin_block_at_height, _params} = key, {:ok, fields, meta}} ->
            {key, {:ok, fields, blocks.(meta)}}

          other ->
            other
        end)

      {module, %{state | answers: answers}}
    end

    defp run(blocks) do
      config =
        Config.internal!(
          environment: :test,
          key_chain: [Keyring.vector_key()],
          reader: reader(blocks)
        )

      {:ok, report} = Verify.verify_file(@item, config)
      report
    end

    defp rows(report), do: for(row <- report.rows, do: {row.step, row.part, row.status, row.code})

    defp bitcoin_row(report),
      do: Enum.find(report.rows, &(&1.step == :chain and &1.part == "/commitments/bitcoin"))

    test "read under a final tip, it keeps the label, the rows and the edge of a live run" do
      live = run(& &1)
      assert live.label == :verified
      assert live.submitted_before.basis == "bitcoin_median_time_read"

      cached = run(&Map.merge(&1, %{cached: true, tip_height: 242}))
      assert cached.label == :verified
      assert rows(cached) == rows(live)

      assert Edge.milliseconds(cached.submitted_before) ==
               Edge.milliseconds(live.submitted_before)

      assert cached.submitted_before.cached
      assert [%{"cached" => true}] = bitcoin_row(cached).values["outcomes"]
    end

    test "read under a tip not final for its candidate, or with no tip, the edge is lost" do
      for blocks <- [
            &Map.merge(&1, %{cached: true, tip_height: 241}),
            &Map.put(&1, :cached, true)
          ] do
        report = run(blocks)
        assert report.label == :internally_consistent
        assert report.submitted_before == nil

        assert {bitcoin_row(report).status, bitcoin_row(report).code} ==
                 {:skip, :source_unreachable}
      end
    end
  end
end
