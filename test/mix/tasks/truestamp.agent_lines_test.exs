# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.AgentLinesTest do
  @moduledoc """
  `mix truestamp.agent_lines` writes what `Truestamp.Verify.AgentLines.main/1` gives, stdout
  and stderr, as raw bytes, and exits with its code: 0 with the document, 1 for a command
  line it cannot use, and 2 for a fault inside the entry point; and, run as its own process
  on a build that has to compile, as truestamp-verification's generator runs it, still
  exactly one JSON document on stdout. What the document holds is `agent_lines_test.exs`'s.
  Not async: it captures standard error.
  """

  use ExUnit.Case, async: false

  alias Mix.Tasks.Truestamp.AgentLines, as: AgentLinesTask
  alias Truestamp.Verify.{AgentLines, JCS, JSON}
  alias Truestamp.Verify.Test.{TaskRun, Verification}

  # A runs file of the sound item under the test keyring, beside copies of both.
  defp runs_file(dir) do
    for name <- ["keyring.test.json", "positive/item.proof.json"],
        do: File.cp!(Verification.path("vectors/#{name}"), Path.join(dir, Path.basename(name)))

    run = %{
      "environment" => "test",
      "id" => "item",
      "keyring" => "keyring.test.json",
      "proof" => "item.proof.json"
    }

    path = Path.join(dir, "runs.json")
    File.write!(path, JCS.encode([run]))
    path
  end

  @tag :tmp_dir
  test "writes the entry point's output and returns for exit code 0", %{tmp_dir: tmp_dir} do
    argv = [runs_file(tmp_dir)]
    {0, stdout, stderr} = AgentLines.main(argv)
    {written_out, written_err, ended} = TaskRun.capture(fn -> AgentLinesTask.run(argv) end)
    assert ended == :ok
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = TaskRun.capture(fn -> AgentLinesTask.run([]) end)
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ AgentLines.usage()
  end

  test "a fault inside the entry point exits 2, with nothing on standard output" do
    {written_out, written_err, ended} = TaskRun.capture(fn -> AgentLinesTask.run([123]) end)
    assert ended == {:exit, {:shutdown, 2}}
    assert written_out == ""
    assert written_err =~ "A fault inside the agent-test entry point: "
  end

  @tag :tmp_dir
  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document",
       %{tmp_dir: tmp_dir} do
    runs = runs_file(tmp_dir)

    {stdout, exit_status, stderr} =
      TaskRun.fresh_build(
        "truestamp.agent_lines",
        [runs],
        [Mix.Tasks.Truestamp.AgentLines, Truestamp.Verify.AgentLines]
      )

    assert exit_status == 0, stderr
    assert String.ends_with?(stdout, "]\n") and length(String.split(stdout, "\n")) == 2
    assert {:ok, document} = JSON.parse(String.trim_trailing(stdout, "\n"))
    {0, expected, _stderr} = AgentLines.main([runs])
    assert stdout == IO.iodata_to_binary(expected)
    assert JCS.encode(document) <> "\n" == stdout
  end
end
