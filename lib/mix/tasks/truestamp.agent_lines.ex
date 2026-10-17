# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.AgentLines do
  @shortdoc "Prints the agent-test lines of SPEC.md 7.4 that the verifier computes"

  @moduledoc """
  Gives, for each proof of a runs file, the lines of the agent-sufficiency test (SPEC.md
  section 7.4) that the verifier computes, every line but the two window lines:

      mix truestamp.agent_lines RUNS_JSON

  Standard output carries one JSON document, written with JCS: an array with one entry per
  run, in the file's order, each `{id, lines}`, or `{error, id}`. truestamp-verification's
  generator derives these lines on its own and writes them under `agent-test/expected/`;
  this library's tests hold the lines the task gives to those files.
  `Truestamp.Verify.AgentLines` describes the runs file, each line and each exit code.

  Like `mix truestamp.verify`, the task compiles the project quietly, so a run that compiles
  writes nothing to standard output but the document; `Mix.Tasks.Truestamp.Verify` says how
  a project that depends on this library keeps the build of its dependencies off it too.
  """

  use Mix.Task

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verify.AgentLines

  @impl Mix.Task
  def run(argv) do
    Verify.quiet_start()
    argv |> AgentLines.main() |> Verify.finish()
  end
end
