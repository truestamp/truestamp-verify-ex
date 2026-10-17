# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ResultsTest do
  @moduledoc """
  The shapes a run gives (SPEC.md sections 10.2, 10.5 and 12.2): rows, bare rejections,
  faults, unreadable inputs, and their exit codes.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{ExitCode, Fault, ReadError, Rejection, Report, Row, Step}
  alias Truestamp.Verify.Steps.Verdict

  describe "a row" do
    test "takes the status its code has, and refuses a code it cannot carry" do
      assert %Row{status: :skip} = Row.new(:chain, :offline, "/commitments/stellar", "m")
      assert %Row{status: :pass, code: nil} = Row.new(:chain, nil, nil, "m")

      assert_raise ArgumentError, ~r/not a reason code/, fn ->
        Row.new(:chain, :nope, nil, "m")
      end

      assert_raise ArgumentError, ~r/bare rejection/, fn ->
        Row.new(:read, :input_too_large, nil, "m")
      end

      assert_raise ArgumentError, ~r/not a step/, fn -> Row.pass(:nowhere, nil, "m") end
    end

    test "as a report and as conformance write it" do
      row = Row.new(:window, :window_not_established, nil, "m", %{"a" => 1})

      assert Row.to_map(row) == %{
               "code" => "window_not_established",
               "message" => "m",
               "part" => nil,
               "status" => "info",
               "step" => "WINDOW",
               "values" => %{"a" => 1}
             }

      assert Row.reduce(row) == ["window_not_established", nil, "info", "WINDOW"]
      refute Map.has_key?(Row.to_map(Row.pass(:read, nil, "m")), "code")
    end
  end

  describe "a bare rejection" do
    test "takes only a bare code, and a sub_reason only where its code lists one" do
      assert %Rejection{sub_reason: :syntax} = Rejection.new(:malformed_json, "m", :syntax)
      assert %Rejection{sub_reason: nil} = Rejection.new(:configuration_error, "m")

      assert_raise ArgumentError, ~r/not a bare code/, fn ->
        Rejection.new(:signature_invalid, "m")
      end

      assert_raise ArgumentError, ~r/not a sub_reason/, fn ->
        Rejection.new(:malformed_json, "m", :nope)
      end

      assert_raise ArgumentError, ~r/not a sub_reason/, fn ->
        Rejection.new(:malformed_json, "m")
      end

      assert_raise ArgumentError, ~r/not a sub_reason/, fn ->
        Rejection.new(:input_too_large, "m", :syntax)
      end
    end

    test "is written as only {code, message, sub_reason}" do
      assert Rejection.to_map(Rejection.new(:invalid_envelope, "m", :alg)) ==
               %{"code" => "invalid_envelope", "message" => "m", "sub_reason" => "alg"}

      assert Rejection.to_map(Rejection.new(:configuration_error, "m")) ==
               %{"code" => "configuration_error", "message" => "m"}

      assert Exception.message(Rejection.new(:configuration_error, "why")) == "why"
    end
  end

  test "a fault and an unreadable input carry what a person needs, and nothing of the proof" do
    fault = Fault.new(:error, %RuntimeError{message: "x"}, [])
    assert fault.kind == :error
    assert fault.message =~ "fault before it could give a report"
    read_error = ReadError.new("/nowhere", :enoent)
    assert read_error.message == "Cannot read /nowhere: no such file or directory"
  end

  test "the exit code of every result (section 12.2)" do
    for {label, code} <- [
          verified: 0,
          failed: 3,
          unattributed: 5,
          supplied_keyring: 6,
          internally_consistent: 7
        ] do
      assert ExitCode.of({:ok, %Report{label: label}}) == code
    end

    assert ExitCode.of({:error, Rejection.new(:configuration_error, "m")}) == 8
    assert ExitCode.of({:error, Rejection.new(:input_too_large, "m")}) == 4
    assert ExitCode.of({:error, ReadError.new("x", :enoent)}) == 1
    assert ExitCode.of({:error, Fault.new(:throw, :x, [])}) == 2
    assert length(ExitCode.table()) == 9
  end

  test "the steps and labels by their spec names" do
    assert length(Step.all()) == 15
    assert Step.from_name("KEY_BINDING") == :key_binding
    assert Step.from_name("NOT_A_STEP") == nil
    assert Step.name(:expected_hash) == "EXPECTED_HASH"
    assert Step.rows_after(:window) == [:expected_hash]

    assert Verdict.labels() == [
             :failed,
             :unattributed,
             :supplied_keyring,
             :internally_consistent,
             :verified
           ]

    assert Verdict.label_name(:supplied_keyring) == "supplied-keyring"
  end
end
