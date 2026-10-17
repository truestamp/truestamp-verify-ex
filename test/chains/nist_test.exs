# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.NistTest do
  @moduledoc "The NIST rule of SPEC.md section 10.4."

  use ExUnit.Case, async: true

  import Truestamp.Verify.Test.Rules

  alias Truestamp.Verify.Chains.Nist
  alias Truestamp.Verify.Edge

  @output String.duplicate("AB", 64)
  @object %{
    "payload" => %{
      "pulse" => %{
        "chainIndex" => 2,
        "outputValue" => @output,
        "pulseIndex" => 7,
        "timeStamp" => "2026-09-26T01:48:00.000Z",
        "version" => "2.0"
      }
    },
    "source" => "nist"
  }

  defp entropy(answer),
    do:
      Nist.entropy(
        context(%{{:nist_pulse, %{"chainIndex" => 2, "pulseIndex" => 7}} => answer}),
        @object
      )

  test "a pulse that matches passes, its timeStamp the candidate at a millisecond's precision" do
    outcome =
      entropy(found(%{"outputValue" => @output, "timeStamp" => "2026-09-26T01:48:00.000Z"}))

    assert verdict(outcome) == {:pass, nil}
    assert %Edge{basis: "nist_pulse_time_read", precision: :millisecond} = outcome.candidate
    assert Edge.instant_string(outcome.candidate) == "2026-09-26T01:48:00.000Z"
  end

  test "a different outputValue or timeStamp fails with entropy_mismatch" do
    assert verdict(
             entropy(
               found(%{
                 "outputValue" => String.duplicate("CD", 64),
                 "timeStamp" => "2026-09-26T01:48:00.000Z"
               })
             )
           ) ==
             {:fail, :entropy_mismatch}

    assert verdict(
             entropy(
               found(%{"outputValue" => @output, "timeStamp" => "2026-09-26T01:48:00.001Z"})
             )
           ) ==
             {:fail, :entropy_mismatch}
  end

  test "an unusable field, a pulse not held, or no answer settles nothing" do
    assert verdict(
             entropy(
               found(%{
                 "outputValue" => String.downcase(@output),
                 "timeStamp" => "2026-09-26T01:48:00.000Z"
               })
             )
           ) ==
             {:skip, :source_unreachable}

    assert verdict(entropy(not_found())) == {:skip, :not_held_by_source}
    assert verdict(entropy(unreachable())) == {:skip, :source_unreachable}
  end

  test "what it declares to the engine" do
    assert Nist.name() == "nist"
    refute Nist.networked?()
    assert Nist.entropy_times() == [{["payload", "pulse", "timeStamp"], :nisttime}]
  end
end
