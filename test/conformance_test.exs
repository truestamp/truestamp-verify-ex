# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ConformanceTest do
  @moduledoc """
  SPEC.md section 13.1: every case of `vectors/cases.json` applies to this library, offline
  and online, and each gives its expected output, one test per case. The output is what
  section 13.1 compares: a bare rejection's code and sub_reason, or the label, every row
  reduced to `[code, part, status, step]`, the trace without `inputs` where the case names
  one, and for an online case both edges, instants compared as instants.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Conformance
  alias Truestamp.Verify.Test.Verification

  @vectors Verification.vectors()
  @external_resource Path.join(@vectors, "cases.json")
  {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))

  test "the cases file holds cases" do
    {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))
    assert length(cases) >= 443
  end

  for %{"id" => id} = kase <- cases do
    @kase kase
    @tag online: Conformance.online?(kase)
    test "case #{id}" do
      kase = @kase

      options = [
        trace?: Map.has_key?(kase["expected"], "trace"),
        online?: Conformance.online?(kase)
      ]

      output = kase |> Conformance.run(@vectors) |> Conformance.output(options)
      assert Conformance.compare(kase, output, @vectors) == :ok
    end
  end
end
