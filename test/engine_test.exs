# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.EngineTest do
  @moduledoc """
  The engine beyond the shared cases: faults caught inside a step (SPEC.md sections 10.5
  and 12.2), the input limits of step 1, and the keyrings of step 0.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{ReadError, Rejection, Report, Row}
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

  test "several sources named by strings are named so in the row's values" do
    reader =
      FakeReader.from_replay(@replay,
        sources: ["a", "b"],
        source_map: %{
          {"stellar", "testnet"} => {:ok, ["a", "b"], {:at_least, 2}},
          {"bitcoin", "regtest"} => {:ok, ["a", "b"], :first},
          {"nist", nil} => {:ok, ["a", "b"], :all}
        }
      )

    pins = %{
      commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
      entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
    }

    {:ok, %Report{} = report} = Verify.verify_file(@item, options(reader: reader, networks: pins))
    stellar = Enum.find(report.rows, &(&1.part == "/commitments/stellar"))
    assert [%{"source" => "a"}, %{"source" => "b"}] = stellar.values["sources"]
    assert report.label == :supplied_keyring
  end

  test "a revocation introduces no key, and is not checked (section 10.3)" do
    record = %{"metadata" => %{"key_event" => %{"type" => "revocation"}}}
    assert KeyEvents.checks(["block"], record) == []
  end
end
