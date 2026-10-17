# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.ConformanceTest do
  @moduledoc """
  `mix truestamp.conformance` writes what `Truestamp.Verify.Conformance.main/1` gives,
  stdout and stderr, as raw bytes, and exits with its code: the same bytes on a latin1
  device, so the JSON stays UTF-8 whatever the locale; and, run as its own process on a
  build that has to compile, as truestamp-verification's generator runs it, still exactly
  one JSON document on stdout. What the document holds is `conformance_test.exs`'s. Not
  async: it captures standard error.
  """

  use ExUnit.Case, async: false

  alias Mix.Tasks.Truestamp.Conformance, as: ConformanceTask
  alias Truestamp.Verify.{Conformance, JCS, JSON}
  alias Truestamp.Verify.Test.{Cases, TaskRun, Verification}

  @cases Verification.path("vectors/cases.json")

  # A cases file of one offline case, in a directory whose name is not ASCII, whose proof is
  # missing, so its entry is an `error` naming that path.
  defp missing_proof_cases(tmp_dir) do
    dir = Path.join(tmp_dir, "clés-鍵")
    File.mkdir_p!(dir)
    kase = Enum.find(Cases.all(), &(not Conformance.online?(&1)))
    kase = put_in(%{kase | "proof" => "missing.proof.json"}, ["config", "keyring"], "none")
    path = Path.join(dir, "cases.json")
    File.write!(path, JCS.encode([kase]))
    {path, Path.join(dir, "missing.proof.json")}
  end

  test "writes the entry point's output and returns for exit code 0" do
    argv = [@cases, "--offline-only"]
    {0, stdout, stderr} = Conformance.main(argv)
    {written_out, written_err, ended} = TaskRun.capture(fn -> ConformanceTask.run(argv) end)
    assert ended == :ok
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = TaskRun.capture(fn -> ConformanceTask.run([]) end)
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ Conformance.usage()
  end

  @tag :tmp_dir
  test "writes raw bytes, so an entry naming a non-ASCII path is UTF-8 JSON on a latin1 device",
       %{tmp_dir: tmp_dir} do
    {cases, missing} = missing_proof_cases(tmp_dir)
    {0, stdout, _stderr} = Conformance.main([cases])

    {written_out, _written_err, :ok} =
      TaskRun.capture(fn -> ConformanceTask.run([cases]) end, :latin1)

    assert written_out == IO.iodata_to_binary(stdout)
    assert {:ok, [%{"output" => %{"error" => error}}]} = JSON.parse(written_out)
    assert error =~ missing
  end

  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document" do
    {stdout, exit_status, stderr} =
      TaskRun.fresh_build(
        "truestamp.conformance",
        [@cases],
        [Mix.Tasks.Truestamp.Conformance, Truestamp.Verify.Conformance]
      )

    assert exit_status == 0, stderr
    assert String.ends_with?(stdout, "]\n") and length(String.split(stdout, "\n")) == 2
    assert {:ok, document} = JSON.parse(String.trim_trailing(stdout, "\n"))
    {0, expected, _stderr} = Conformance.main([@cases])
    assert stdout == IO.iodata_to_binary(expected)
    assert JCS.encode(document) <> "\n" == stdout
  end
end
