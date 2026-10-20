# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.EngineTest do
  @moduledoc """
  The engine beyond the shared cases: faults caught inside a step (SPEC.md sections 10.5
  and 12.2), the input limits of step 1, and the keyrings of step 0.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{Config, Engine, Fault, Messages, ReadError, Rejection, Report, Row, Run}
  alias Truestamp.Verify.Steps.Derive.KeyEvents
  alias Truestamp.Verify.Test.{FakeReader, Verification}

  @item Verification.path("vectors/positive/item.proof.json")
  @keyring Verification.path("vectors/keyring.test.json")
  @replay Verification.path("vectors/corpus/replay/window-established.json")

  defp options(extra), do: [environment: :test, trust: {:keyring_file, @keyring}] ++ extra

  # A message module that faults while one step writes its row.
  defmodule Faulty do
    @behaviour Truestamp.Verify.Messages
    @impl true
    def message(:environment_pass, _assigns), do: raise(ArgumentError, "a value of the proof")
    def message(:shape_pass, _assigns), do: throw(:shape)
    def message(_id, _assigns), do: nil
  end

  describe "a fault caught inside a step" do
    test "at a gate step: an internal_error row, attribution none, and every later step skipped" do
      {:ok, report} = Verify.verify_file(@item, options(messages: Faulty))
      assert report.label == :failed
      assert report.code == :internal_error
      assert report.attribution == "none"

      assert [%Row{step: :environment, code: :internal_error, part: nil, values: values} | later] =
               Enum.drop_while(report.rows, &(&1.step != :environment))

      assert values == %{"kind" => "error", "module" => "ArgumentError"}
      refute inspect(report.rows) =~ "a value of the proof"
      assert Enum.all?(later, &(&1.code == :prior_failure and &1.part == nil))
      assert List.last(later).step == :expected_hash
    end

    test "after the gate: the attribution stands, and a throw names no module" do
      defmodule FaultyAtShape do
        @behaviour Truestamp.Verify.Messages
        @impl true
        def message(:shape_pass, _assigns), do: throw(:shape)
        def message(_id, _assigns), do: nil
      end

      {:ok, report} = Verify.verify_file(@item, options(messages: FaultyAtShape))
      assert report.code == :internal_error
      assert "keyring:" <> _ = report.attribution

      assert %Row{values: %{"kind" => "throw", "module" => nil}} =
               Enum.find(report.rows, &(&1.code == :internal_error))
    end
  end

  # A message module that faults on the ids of `faults` (every id by default) but those of
  # `spared`, by `with`: a raise, a throw, an exit, a value that is not text, or a binary
  # that is not UTF-8.
  # `spared: :admission` spares every id of steps 0 to 3 that a sound proof's run renders.
  defmodule Faults do
    @moduledoc false
    @admission [:configuration_pass, :read_pass, :parse_pass, :envelope_pass]

    defmacro __using__(options) do
      spared =
        case Keyword.get(options, :spared, []) do
          :admission -> @admission
          ids -> ids
        end

      quote do
        @behaviour Truestamp.Verify.Messages
        @impl true
        def message(id, _assigns) do
          faults = unquote(Keyword.get(options, :faults, :all))

          cond do
            id in unquote(spared) ->
              nil

            faults == :all or id in faults ->
              Faults.fault(unquote(Keyword.get(options, :with, :raise)))

            true ->
              nil
          end
        end
      end
    end

    def fault(:raise), do: raise("a faulty message module")
    def fault(:throw), do: throw(:x)
    def fault(:exit), do: exit(:x)
    def fault(:not_text), do: 42
    def fault(:not_utf8), do: <<0xFF, 0xFE>>
  end

  describe "a message module that faults (SPEC.md 10.5)" do
    test "on every id: a fault before any report, never a raise" do
      defmodule FaultsEverywhere, do: use(Faults)

      assert {:error, %Fault{kind: :error}} =
               Verify.verify_file(@item, options(messages: FaultsEverywhere))
    end

    test "at a gate step and on the rows that record it: internal_error, in English" do
      defmodule FaultsAfterAdmission, do: use(Faults, spared: :admission)

      {:ok, report} = Verify.verify_file(@item, options(messages: FaultsAfterAdmission))
      assert {report.label, report.code, report.attribution} == {:failed, :internal_error, "none"}

      [fault | later] = Enum.drop_while(report.rows, &(&1.step != :environment))
      assert {fault.step, fault.code} == {:environment, :internal_error}
      assert fault.message == Messages.English.message(:internal_error, fault.assigns)
      assert fault.values == %{"kind" => "error", "module" => "RuntimeError"}

      assert Enum.map(later, &{&1.code, &1.message}) ==
               for(
                 _step <- later,
                 do: {:prior_failure, Messages.English.message(:prior_failure_gate, %{})}
               )

      assert List.last(later).step == :expected_hash
    end

    test "at DERIVE: internal_error at DERIVE, the attribution standing" do
      defmodule FaultsAtDerive do
        use Faults, faults: [:value_recomputed, :internal_error, :prior_failure_gate]
      end

      {:ok, report} = Verify.verify_file(@item, options(messages: FaultsAtDerive))
      assert report.code == :internal_error
      assert "keyring:" <> _ = report.attribution
      fault = Enum.find(report.rows, &(&1.code == :internal_error))
      assert {fault.step, fault.message_id} == {:derive, :internal_error}
      assert Enum.all?(report.rows, &(&1.step != :derive or &1.code == :internal_error))
      assert List.last(report.rows).code == :prior_failure
    end

    # NotUtf8 kills the mutant that takes any binary as text, under which the run passes
    # with bytes that are not UTF-8 in its rows and `Report.to_json/1` raises.
    test "that throws, exits or gives other than text, on the fault's rows too" do
      defmodule Throws, do: use(Faults, spared: :admission, with: :throw)
      defmodule Exits, do: use(Faults, spared: :admission, with: :exit)
      defmodule NotText, do: use(Faults, spared: :admission, with: :not_text)
      defmodule NotUtf8, do: use(Faults, spared: :admission, with: :not_utf8)

      for module <- [Throws, Exits, NotText, NotUtf8] do
        {:ok, report} = Verify.verify_file(@item, options(messages: module))
        fault = Enum.find(report.rows, &(&1.code == :internal_error))
        assert %Row{step: :environment} = fault, inspect(module)
        assert fault.message == Messages.English.message(:internal_error, fault.assigns)
        assert Enum.all?(report.rows, &String.valid?(&1.message)), inspect(module)
        assert is_binary(Report.to_json(report))
      end

      assert_raise ArgumentError, ~r/no UTF-8 text/, fn ->
        Messages.render(NotUtf8, :signature_pass, %{})
      end
    end

    test "in apply_expected_hash/2: the internal_error row a fresh run gives" do
      defmodule FaultsAtExpectedHash do
        use Faults,
          faults:
            for(
              id <- Messages.English.ids(),
              String.starts_with?(Atom.to_string(id), "expected_hash_"),
              id != :expected_hash_not_checked,
              do: id
            ) ++ [:internal_error]
      end

      {:ok, without} = Verify.verify_file(@item, options(messages: FaultsAtExpectedHash))
      assert without.code == nil
      hash = Report.document(without)["proof"]["subject"]["claims"]["hash"]

      for given <- [hash, "00"] do
        applied = Verify.apply_expected_hash(without, given)

        {:ok, fresh} =
          Verify.verify_file(@item, options(messages: FaultsAtExpectedHash, expected_hash: given))

        assert Report.to_map(applied) == Report.to_map(fresh)
        assert %Row{step: :expected_hash, code: :internal_error} = List.last(applied.rows)
      end
    end
  end

  describe "apply_expected_hash/2 on a report whose own EXPECTED_HASH faulted" do
    # Kills the mutant that keeps an ended run as it is (`if run.ended, do: run`), under which
    # the applied report keeps the stale internal_error row; and the one that drops the row
    # but leaves the run ended, under which it has no EXPECTED_HASH row at all.
    test "makes the step again: the report a fresh run gives" do
      defmodule FaultsOnNotChecked, do: use(Faults, faults: [:expected_hash_not_checked])

      {:ok, without} = Verify.verify_file(@item, options(messages: FaultsOnNotChecked))
      assert %Row{step: :expected_hash, code: :internal_error} = List.last(without.rows)
      assert {without.label, without.code} == {:failed, :internal_error}
      hash = Report.document(without)["proof"]["subject"]["claims"]["hash"]

      for given <- [hash, "00", nil] do
        applied = Verify.apply_expected_hash(without, given)

        {:ok, fresh} =
          Verify.verify_file(@item, options(messages: FaultsOnNotChecked, expected_hash: given))

        assert Report.to_map(applied) == Report.to_map(fresh), inspect(given)
        assert {applied.label, applied.code} == {fresh.label, fresh.code}
        assert Enum.count(applied.rows, &(&1.step == :expected_hash)) == 1
      end

      assert List.last(Verify.apply_expected_hash(without, hash).rows).code != :internal_error
    end
  end

  describe "a fault at VERDICT or while the report is written" do
    # A run no conforming input reaches: one VERDICT cannot label, or one with no
    # configuration to report.
    defp unlabelled, do: %Run{config: Config.external!([]), keyring: nil, trust_root: nil}

    defp unreportable,
      do: %Run{config: nil, keyring: nil, trust_root: nil, attribution: "truestamp"}

    test "is a fault, with no report" do
      assert {:fault, %Fault{kind: :error}} = Engine.conclude(unlabelled())
      assert {:fault, %Fault{kind: :error}} = Engine.conclude(unreportable())
      assert {:fault, %Fault{}} = Engine.conclude(unreportable(), false)
    end

    test "in apply_expected_hash/2 raises the fault" do
      {:ok, report} = Verify.verify_file(@item, options([]))
      broken = %{report | __run__: %{report.__run__ | attribution: nil}}
      assert_raise Fault, fn -> Verify.apply_expected_hash(broken, nil) end
    end
  end

  describe "the input" do
    @tag :tmp_dir
    test "a document over MAX_READ_OCTETS is input_too_large, as bytes or as a file", %{
      tmp_dir: dir
    } do
      big = String.duplicate(" ", 262_145)
      assert {:error, %Rejection{code: :input_too_large}} = Verify.verify(big, options([]))

      path = Path.join(dir, "big.json")
      File.write!(path, big)
      assert {:error, %Rejection{code: :input_too_large}} = Verify.verify_file(path, options([]))
    end
  end

  describe "the keyring of step 0" do
    test "a keyring given as its bytes is a supplied keyring, its location as given" do
      {:ok, report} =
        Verify.verify_file(@item,
          environment: :test,
          trust: {:keyring, File.read!(@keyring), "mine"}
        )

      assert report.trust_root.kind == :supplied_keyring
      assert report.trust_root.location == "mine"
    end

    test "a supplied keyring that fails a load check is configuration_error" do
      assert {:error, %Rejection{code: :configuration_error, message: message}} =
               Verify.verify_file(@item, environment: :test, trust: {:keyring, "{\"keys\": 1}"})

      assert message =~ "load check"
    end

    @tag :tmp_dir
    test "a keyring file too large is configuration_error; one that cannot be read is no result",
         %{tmp_dir: dir} do
      path = Path.join(dir, "keyring.json")
      File.write!(path, String.duplicate(" ", 262_145))

      assert {:error, %Rejection{code: :configuration_error}} =
               Verify.verify_file(@item, environment: :test, trust: {:keyring_file, path})

      assert {:error, %ReadError{path: "/no/such/keyring"}} =
               Verify.verify_file(@item,
                 environment: :test,
                 trust: {:keyring_file, "/no/such/keyring"}
               )
    end

    test "the default trust under an environment other than prod is configuration_error" do
      assert {:error, %Rejection{code: :configuration_error}} =
               Verify.verify_file(@item, environment: :test)
    end
  end

  @pins %{
    commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
    entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  defp sourced(source_map) do
    reader = FakeReader.from_replay(@replay, sources: ["a", "b"], source_map: source_map)
    Verify.verify_file(@item, options(reader: reader, networks: @pins))
  end

  test "several sources: what each row read, named as the reader names them (10.4)" do
    {:ok, %Report{} = report} =
      sourced(%{
        {"stellar", "testnet"} => {:ok, ["a", "b"], {:at_least, 2}},
        {"bitcoin", "regtest"} => {:ok, ["a", "b"], :first},
        {"nist", nil} => {:ok, ["a"], :first}
      })

    assert report.label == :supplied_keyring
    stellar = Enum.find(report.rows, &(&1.part == "/commitments/stellar"))

    assert %{"policy" => "at_least", "required" => 2, "candidate" => candidate} =
             stellar.values

    assert %{"basis" => "stellar_ledger_close_read", "instant" => _instant} = candidate

    assert [%{"source" => "a", "status" => "pass"} = a, %{"source" => "b", "status" => "pass"}] =
             stellar.values["outcomes"]

    refute Map.has_key?(a, "code")
    assert a["candidate"] == candidate

    assert [%{"read" => %{"kind" => "stellar_transaction", "network" => "testnet"}} | _] =
             a["reads"]

    assert Enum.all?(a["reads"], &match?(%{"answer" => %{"outcome" => "found"}}, &1))

    # Under :first the row takes the first conclusive source, and asks no other.
    bitcoin = Enum.find(report.rows, &(&1.part == "/commitments/bitcoin"))
    assert %{"policy" => "first", "required" => 1} = bitcoin.values
    assert [%{"source" => "a"}] = bitcoin.values["outcomes"]

    # The edge rests on both Stellar sources, the first giving its own source.
    assert %{source: "a", sources: [%{source: "a"}, %{source: "b"}]} = report.submitted_before
  end

  test "a policy's n of 0 or above the sources, or several NIST sources, is configuration_error" do
    for stellar <- [{:ok, ["a", "b"], {:at_least, 3}}, {:ok, ["a", "b"], {:at_least, 0}}] do
      assert {:error, %Rejection{code: :configuration_error, message: message}} =
               sourced(%{{"stellar", "testnet"} => stellar})

      assert message =~ "source policy of the stellar network testnet"
    end

    assert {:error, %Rejection{code: :configuration_error, message: message}} =
             sourced(%{{"nist", nil} => {:ok, ["a", "b"], :first}})

    assert message =~ "NIST's Randomness Beacon, which is one source"

    assert {:error, %Rejection{code: :configuration_error}} =
             sourced(%{{"stellar", "testnet"} => {:ok, ["a"], :most}})
  end

  test "a revocation introduces no key, and is not checked (section 10.3)" do
    record = %{"metadata" => %{"key_event" => %{"type" => "revocation"}}}
    assert KeyEvents.checks(["block"], record) == []
  end
end
