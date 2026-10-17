# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.Conformance do
  @shortdoc "Runs every case of a cases.json and prints what SPEC.md 13.1 compares"

  @moduledoc """
  Runs the verifier over the cases of a file in the form of `vectors/cases.json` (SPEC.md
  sections 13.1 and 13.2), each with its full configuration, its network pins included, and
  each online case answered from its replay file:

      mix truestamp.conformance CASES_JSON [--offline-only]

  Standard output carries one JSON document, written with JCS: an array with one entry per
  case, in the file's order, each `{id, output}`, where `output` is what section 13.1
  compares. `--offline-only` leaves the online cases out, as an offline verifier does. The
  task compares nothing. `Truestamp.Verify.Conformance.main/1` describes each output and
  each exit code.

  Like `mix truestamp.verify`, the task compiles the project quietly, so a run that compiles
  writes nothing to standard output but the document; `Mix.Tasks.Truestamp.Verify` says how
  a project that depends on this library keeps the build of its dependencies off it too.
  """

  use Mix.Task

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verify.Conformance

  @impl Mix.Task
  def run(argv) do
    Verify.quiet_start()
    argv |> Conformance.main() |> Verify.finish()
  end
end
