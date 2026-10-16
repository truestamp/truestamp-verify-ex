# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ReasonCodes do
  @moduledoc """
  The reason codes of SPEC.md section 12.1, as compiled constants: the table compiled from
  `spec/reason-codes.json`, in its order, which is step order. A test holds the compiled
  table equal to that file.

  No other code is valid (section 12.1). Code that names a code writes `code(:name)`, a
  macro that expands to the atom and stops the build on a name the table lacks.

  The rows of `malformed_json` and `invalid_envelope` also list the values their
  `sub_reason` takes (sections 10.1 and 10.2, step 3), and `sub_reasons/1` gives them,
  compiled from the same file. A test holds them equal to SPEC.md's text too.
  """

  alias Truestamp.Verify.Spec.Data

  @typedoc "A reason code of section 12.1."
  @type code :: atom()

  @typedoc "A code's status: `bare` ends the run in a bare rejection, the others are row statuses."
  @type status :: :bare | :fail | :skip | :info | :warn

  @typedoc "One row of the table."
  @type entry :: %{
          code: code(),
          meaning: String.t(),
          status: status(),
          step: String.t(),
          sub_reasons: [atom()]
        }

  @statuses %{"bare" => :bare, "fail" => :fail, "skip" => :skip, "info" => :info, "warn" => :warn}

  @external_resource Data.path("reason-codes.json")

  @table (for row <- Data.read!("reason-codes.json") do
            %{
              code: row |> Map.fetch!("code") |> String.to_atom(),
              meaning: Map.fetch!(row, "meaning"),
              status: Map.fetch!(@statuses, Map.fetch!(row, "status")),
              step: Map.fetch!(row, "step"),
              sub_reasons: row |> Map.get("sub_reasons", []) |> Enum.map(&String.to_atom/1)
            }
          end)

  @codes Enum.map(@table, & &1.code)

  if Enum.uniq(@codes) != @codes,
    do: raise(ArgumentError, "spec/reason-codes.json: a code appears twice")

  @doc "The table of section 12.1, in its order."
  @spec table() :: [entry()]
  def table, do: @table

  @doc "Every code, in the table's order."
  @spec codes() :: [code()]
  def codes, do: @codes

  @doc "Whether `term` is a code of the table."
  @spec code?(term()) :: boolean()
  def code?(term), do: term in @codes

  @doc "The status of `code`."
  @spec status(code()) :: status()
  for %{code: code, status: status} <- @table do
    def status(unquote(code)), do: unquote(status)
  end

  @doc "The step of `code`, as the table writes it (\"DERIVE, CHAIN\" for a code of two)."
  @spec step(code()) :: String.t()
  for %{code: code, step: step} <- @table do
    def step(unquote(code)), do: unquote(step)
  end

  @doc """
  The `sub_reason` values of `code`, in the file's order, which is SPEC.md's: those of
  `malformed_json` (section 10.1) and of `invalid_envelope` (section 10.2, step 3), and none
  for every other code, which carries no `sub_reason` (section 12.1).
  """
  @spec sub_reasons(code()) :: [atom()]
  for %{code: code, sub_reasons: sub_reasons} <- @table do
    def sub_reasons(unquote(code)), do: unquote(sub_reasons)
  end

  @doc """
  Expands to `name` when it is a code of the table, and otherwise raises `ArgumentError`
  while the caller compiles.
  """
  defmacro code(name) when is_atom(name) do
    if name in @codes,
      do: name,
      else: raise(ArgumentError, "#{inspect(name)} is not a reason code of SPEC.md 12.1")
  end
end
