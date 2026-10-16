# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.CrashInputs do
  @moduledoc """
  The spellings in `test/data/strtod_crash_inputs.txt`, on which macOS 27's `strtod` aborts
  the Erlang runtime: four found by fuzzing, then a 637-character spelling of
  75.75960580580087. Only `Truestamp.Verify.JSON.Binary64` may read them as numbers here.
  """

  @path Path.expand("../data/strtod_crash_inputs.txt", __DIR__)
  @external_resource @path

  @inputs for line <- @path |> File.read!() |> String.split("\n", trim: true),
              not String.starts_with?(line, "#"),
              do: line

  @doc "The five spellings, in the file's order."
  @spec all() :: [String.t()]
  def all, do: @inputs
end
