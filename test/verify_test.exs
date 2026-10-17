# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.VerifyTest do
  @moduledoc """
  The public API, end to end: the results of `Truestamp.Verify.verify/2` and its kin, the two
  roles of SPEC.md section 8, the online run of section 10.4 beyond the shared cases, and
  `apply_expected_hash/2`.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{Config, Edge, Fault, ReadError, Rejection, Report, Row}
  alias Truestamp.Verify.KeyringSources
  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Test.{Cases, FakeReader, Signing, Verification}

  @item Verification.path("vectors/positive/item.proof.json")
  @keyring Verification.path("vectors/keyring.test.json")
  @replay Verification.path("vectors/corpus/replay/window-established.json")
  @test_pins %{
    commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
    entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  defp vector_options(extra \\ []),
    do: [environment: :test, trust: {:keyring_file, @keyring}] ++ extra

  defp codes(%Report{rows: rows}, step),
    do: for(%Row{step: ^step} = row <- rows, do: {row.status, row.code})

  describe "the results" do
    test "a sound vector offline: supplied-keyring, its rows, its trace and no window" do
      assert {:ok, %Report{} = report} = Verify.verify_file(@item, vector_options())
      assert report.label == :supplied_keyring
      assert report.environment == :test
      assert report.type == "item"
      assert report.window == :not_established
      assert report.submitted_before == nil
      assert "keyring:" <> _digest = report.attribution
      assert report.trust_root.kind == :supplied_keyring
      assert length(report.trace) > 10
      refute Verify.verified?(report)
      assert Report.failures(report) == []
    end

    test "bytes and a file give the same report" do
      {:ok, from_file} = Verify.verify_file(@item, vector_options())
      {:ok, from_bytes} = Verify.verify(File.read!(@item), vector_options())
      assert Report.to_map(from_file) == Report.to_map(from_bytes)
    end

    test "a bare rejection, an unreadable file, and the bang forms" do
      assert {:error, %Rejection{code: :malformed_json, sub_reason: :syntax}} =
               Verify.verify("{", vector_options())

      assert {:error, %ReadError{path: "/nonexistent"}} =
               Verify.verify_file("/nonexistent", vector_options())

      assert_raise Rejection, fn -> Verify.verify!("{", vector_options()) end
      assert_raise ReadError, fn -> Verify.verify_file!("/nonexistent", vector_options()) end
      assert %Report{} = Verify.verify!(File.read!(@item), vector_options())
      assert %Report{} = Verify.verify_file!(@item, vector_options())
    end

    test "an invalid option raises, as a caller's defect" do
      assert_raise ArgumentError, fn -> Verify.verify("{}", environment: :nowhere) end
      assert_raise ArgumentError, fn -> Verify.verify("{}", bogus: 1) end
    end

    test "a fault before steps 0 to 3 passed gives no report" do
      defmodule FaultyMessages do
        @behaviour Truestamp.Verify.Messages
        @impl true
        def message(:configuration_pass, _assigns), do: raise("boom")
        def message(_id, _assigns), do: nil
      end

      assert {:error, %Fault{kind: :error} = fault} =
               Verify.verify("{}", messages: FaultyMessages)

      assert fault.message =~ "boom"
      assert_raise Fault, fn -> Verify.verify!("{}", messages: FaultyMessages) end
    end

    test "a run cut short with :until has the rows up to that step and no label" do
      {:ok, report} = Verify.verify_file(@item, vector_options(until: :derive))
      assert report.label == nil
      assert List.last(report.rows).step == :derive
      assert_raise ArgumentError, fn -> Verify.apply_expected_hash(report, "00") end

      assert_raise ArgumentError, fn ->
        Verify.verify_file(@item, vector_options(until: :verdict))
      end
    end
  end

  describe "Truestamp's own role (section 8.2)" do
    defp vector_key, do: Signing.public_key(0x42)

    defp internal(options) do
      Config.internal!([environment: :prod, networks: @test_pins] ++ options)
    end

    test "a verified key chain and an online run give verified, with both edges" do
      bytes = Signing.production("item", 0x42)
      config = internal(key_chain: [vector_key()], reader: Replay.new!(@replay))
      assert {:ok, report} = Verify.verify(bytes, config)
      assert report.label == :verified
      assert report.attribution == "truestamp"
      assert report.trust_root.kind == :key_chain
      assert report.window == :established
      assert %Edge{basis: "stellar_ledger_close_read"} = report.submitted_before
      assert %Edge{} = report.submitted_after
      assert Verify.verified?(report)
      assert codes(report, :chain) |> List.last() == {:pass, nil}
      assert Report.to_map(report)["verified"] == true
    end

    test "offline, the same run is internally consistent" do
      bytes = Signing.production("item", 0x42)

      assert {:ok, %Report{label: :internally_consistent}} =
               Verify.verify(bytes, internal(key_chain: [vector_key()]))
    end

    test "an unverified key chain fails closed, whatever the key" do
      bytes = Signing.production("item", 0x42)
      {:ok, report} = Verify.verify(bytes, internal(key_chain: :unavailable))
      assert report.label == :failed
      assert report.code == :keyring_unavailable
      assert report.attribution == "none"
    end

    test "a key outside the key chain fails key binding" do
      {:ok, report} =
        Verify.verify(
          Signing.production("item", 0x42),
          internal(key_chain: [Signing.public_key()])
        )

      assert report.code == :key_binding_failed
    end
  end

  describe "the keyring read online (section 8.3)" do
    defmodule KeyringFromBytes do
      @behaviour Truestamp.Verify.KeyringSource
      @impl true
      def fetch({:bytes, bytes}),
        do:
          {:ok, {:bytes, bytes}, "https://example.test/.well-known/keyring.json",
           FakeReader.meta()}

      def fetch(:raise), do: raise("down")
      def fetch(:error), do: {:error, :timeout}

      def fetch(:other),
        do: {:ok, :nonsense, "https://example.test/keyring.json", FakeReader.meta()}
    end

    defp online_prod(source) do
      [
        networks: @test_pins,
        reader: Replay.new!(@replay),
        current_keyring: {KeyringFromBytes, source}
      ]
    end

    test "the current keyring governs an online run under prod, and binds the key it holds" do
      {:ok, report} =
        Verify.verify(Signing.production("item"), online_prod({:bytes, Signing.keyring()}))

      assert report.trust_root.kind == :current_keyring
      assert report.trust_root.location == "https://example.test/.well-known/keyring.json"
      assert report.trust_root.digest =~ ~r/\A[0-9a-f]{64}\z/
      assert report.attribution == "truestamp"
      assert {:pass, nil} in codes(report, :key_binding)
    end

    test "a read that fails, for any reason, binds no key" do
      for source <- [{:bytes, "not json"}, :raise, :error, :other] do
        {:ok, report} = Verify.verify(Signing.production("item"), online_prod(source))
        assert report.code == :keyring_unavailable, inspect(source)
        assert report.trust_root.kind == :current_keyring
      end
    end

    test "a keyring read from another origin is a supplied keyring" do
      options = [
        environment: :test,
        networks: @test_pins,
        trust: {:keyring_source, {KeyringFromBytes, {:bytes, File.read!(@keyring)}}}
      ]

      {:ok, report} = Verify.verify_file(@item, options)
      assert report.trust_root.kind == :supplied_keyring
      assert report.label == :supplied_keyring

      {:ok, report} =
        Verify.verify_file(
          @item,
          Keyword.put(options, :trust, {:keyring_source, {KeyringFromBytes, :error}})
        )

      assert report.code == :keyring_unavailable
    end

    test "a replay's keyring has no bytes, so no digest" do
      {:ok, {Replay, state}} =
        Replay.new(
          Verification.path("vectors/corpus/replay/key_binding-unavailable-load_check.json")
        )

      assert {:ok, {:value, _keyring}, _url, _meta} =
               KeyringSources.Replay.fetch(
                 {state, "https://www.truestamp.com/.well-known/keyring.json"}
               )

      assert {:error, :not_in_replay} =
               KeyringSources.Replay.fetch({state, "https://other.test/keyring.json"})
    end
  end

  describe "the reads of an online run" do
    defp online(reader, extra \\ []),
      do: vector_options([networks: @test_pins, reader: reader] ++ extra)

    test "several sources under :all agree, and the edge rests on both" do
      reader =
        FakeReader.from_replay(@replay,
          sources: [:one, {:two, 2}],
          source_map: %{
            {"stellar", "testnet"} => {:ok, [:one, {:two, 2}], :all},
            {"bitcoin", "regtest"} => {:ok, [:one, {:two, 2}], :all},
            {"nist", nil} => {:ok, [:one, {:two, 2}], :all}
          }
        )

      {:ok, report} = Verify.verify_file(@item, online(reader))
      assert report.label == :supplied_keyring
      assert report.submitted_before.source == "one, {:two, 2}"
      stellar = Enum.find(report.rows, &(&1.part == "/commitments/stellar"))
      assert stellar.values["policy"] == "all"
    end

    test "a reader with no NIST source leaves each NIST row unreachable" do
      reader = FakeReader.from_replay(@replay, source_map: %{{"nist", nil} => {:error, :none}})
      {:ok, report} = Verify.verify_file(@item, online(reader))
      nist = Enum.find(report.rows, &(&1.part == "/witnesses/entropy_nist"))
      assert {nist.status, nist.code} == {:skip, :source_unreachable}
    end

    test "a reader whose sources raise is configuration_error" do
      defmodule RaisingSources do
        @behaviour Truestamp.Verify.Reader
        @impl true
        def sources(_state, _chain, _network), do: raise("no")
        @impl true
        def read(_state, _source, _network, _kind, _params), do: {:error, :none}
      end

      assert {:error, %Rejection{code: :configuration_error}} =
               Verify.verify_file(@item, online({RaisingSources, nil}))
    end

    test "an identity that is not found, or unusable, leaves its source's rows unreachable" do
      for answer <- [FakeReader.not_found(), FakeReader.found(%{"network_passphrase" => 7})] do
        reader = FakeReader.from_replay(@replay, overrides: %{{:stellar_identity, %{}} => answer})
        {:ok, report} = Verify.verify_file(@item, online(reader))
        stellar = Enum.find(report.rows, &(&1.part == "/commitments/stellar"))
        assert {stellar.status, stellar.code} == {:skip, :source_unreachable}
        assert stellar.values == %{"identity" => "unreachable"}
      end
    end

    test "a deadline of 0 leaves every read unreachable, and the window not established" do
      {:ok, report} = Verify.verify_file(@item, online(Replay.new!(@replay), deadline: 0))
      assert report.window == :not_established
      assert {:skip, :source_unreachable} in codes(report, :chain)
      assert {:info, :window_not_established} in codes(report, :window)
    end

    test "an online run whose reads fail before CHAIN reads nothing: prior_failure" do
      reader = Replay.new!(@replay)
      {:ok, report} = Verify.verify_file(@item, online(reader, expected_hash: "00"))
      assert report.label == :failed
      assert report.code == :expected_hash_mismatch
      assert report.submitted_before == nil
    end
  end

  describe "apply_expected_hash/2" do
    test "gives the report a fresh run with that hash gives, on every case" do
      for kase <- Cases.all(), kase["expected"]["label"] do
        options = Cases.options(kase)
        path = Path.join(Cases.vectors(), kase["proof"])
        {:ok, without} = Verify.verify_file(path, Keyword.delete(options, :expected_hash))

        for hash <- [nil, "00", String.duplicate("a", 64), kase["config"]["expected_hash"]] do
          {:ok, fresh} = Verify.verify_file(path, Keyword.put(options, :expected_hash, hash))
          applied = Verify.apply_expected_hash(without, hash)

          assert Report.to_map(applied) == Report.to_map(fresh),
                 "#{kase["id"]} with #{inspect(hash)}"
        end
      end
    end
  end

  test "the report's JSON forms" do
    {:ok, report} = Verify.verify_file(@item, vector_options())
    map = Report.to_map(report)
    assert map["label"] == "supplied-keyring"
    refute Map.has_key?(map, "code")
    assert Report.to_json(report) |> String.ends_with?("}\n")

    assert Report.trace_json(report) ==
             File.read!(Verification.path("vectors/positive/item.trace.json"))

    refute inspect(report) =~ "__run__"

    {:ok, failed} = Verify.verify_file(@item, vector_options(expected_hash: "00"))
    assert Report.to_map(failed)["code"] == "expected_hash_mismatch"
    assert [%Row{code: :expected_hash_mismatch}] = Report.failures(failed)
  end
end
