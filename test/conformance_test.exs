# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ConformanceTest do
  @moduledoc """
  SPEC.md section 13.1: every case of `vectors/cases.json` applies to this library, offline
  and online, and each gives its expected output, one test per case. The output is what
  section 13.1 compares: a bare rejection's code and sub_reason, or the label, the run's code
  where the case gives one, every row reduced to `[code, part, status, step]`, the trace
  without `inputs` where the case names one, and for an online case both edges, instants
  compared as instants.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Conformance
  alias Truestamp.Verify.Test.Verification

  @vectors Verification.vectors()
  @external_resource Path.join(@vectors, "cases.json")
  {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))

  test "the cases file holds cases" do
    {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))
    assert length(cases) >= 482
  end

  # Pinned: a run against truestamp-verification's main (.github/workflows/upstream.yml)
  # reads another commit, whose cases may number more, and leaves this test out.
  @tag :pinned
  test "the pinned commit's cases: 482, of them 395 offline and 87 online" do
    {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))
    assert length(cases) == 482
    assert Enum.count(cases, &Conformance.online?/1) == 87
    assert Enum.count(cases, &(not Conformance.online?(&1))) == 395
    assert length(Enum.uniq_by(cases, & &1["id"])) == 482
  end

  # Pinned, as above. Section 13.2: a report case gives the run's code only where its point
  # is which failing row decides the run, and a bare rejection's expected output is the one
  # with no label.
  @tag :pinned
  test "the pinned commit's one report case that gives the run's code" do
    {:ok, cases} = Conformance.cases(Path.join(@vectors, "cases.json"))
    with_code = for %{"expected" => %{"label" => _, "code" => _}} = kase <- cases, do: kase
    assert [%{"id" => "two_steps-policy-derive"} = kase] = with_code
    assert kase["expected"]["code"] == "network_mismatch"
    assert Conformance.output_options(kase)[:code?] == true

    # Its rows fail at two steps, and the run's code is the first failing row's.
    failing = for [code, _part, "fail", step] <- kase["expected"]["rows"], do: {code, step}
    assert failing == [{"network_mismatch", "POLICY"}, {"derivation_mismatch", "DERIVE"}]
  end

  for %{"id" => id} = kase <- cases do
    @kase kase
    @tag online: Conformance.online?(kase)
    test "case #{id}" do
      kase = @kase

      output =
        kase |> Conformance.run(@vectors) |> Conformance.output(Conformance.output_options(kase))

      assert Conformance.compare(kase, output, @vectors) == :ok
    end
  end
end
