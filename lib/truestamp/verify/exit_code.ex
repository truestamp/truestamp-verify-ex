# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ExitCode do
  @moduledoc """
  The exit codes of SPEC.md section 12.2, as compiled constants: the table compiled from
  `spec/exit-codes.json`, in its order, with a test that holds it equal to that file.

  `of/1` gives the code of any result of `Truestamp.Verify.verify/2`, and `code/1` the code
  of how a command-line run ended, each ending named by the words of its row, so a row the
  file changes stops the build:

  | Ending | Row |
  |---|---|
  | `{:label, label}`, one of the five labels of section 10.5 | `label <label>` |
  | `:runtime_error`, an invalid command line or an input that cannot be read, with no report | `a runtime error outside verification` |
  | `:fault`, a fault the verifier did not catch, or caught before steps 0 to 3 passed | `the verifier stopped on a fault` |
  | `:bare_rejection`, a bare rejection other than `configuration_error` | `a bare rejection other than configuration_error` |
  | `:configuration_error` | `configuration_error` |

  Only 0 says that Truestamp signed the proof and that its submission window is
  established. Truestamp's own verifier has no command line and no exit code (section 8.2).
  """

  alias Truestamp.Verify.{Fault, ReadError, Rejection, Report}
  alias Truestamp.Verify.Spec.Data
  alias Truestamp.Verify.Steps.Verdict

  @typedoc "How a run of a command ended."
  @type ending ::
          {:label, Verdict.label()}
          | :runtime_error
          | :fault
          | :bare_rejection
          | :configuration_error

  @external_resource Data.path("exit-codes.json")
  @table for %{"code" => code, "run" => run} <- Data.read!("exit-codes.json"), do: {code, run}

  @others [
    runtime_error: "a runtime error outside verification",
    fault: "the verifier stopped on a fault",
    bare_rejection: "a bare rejection other than configuration_error",
    configuration_error: "configuration_error"
  ]

  @codes (for {ending, beginning} <-
                Enum.map(Verdict.labels(), &{{:label, &1}, "label " <> Verdict.label_name(&1)}) ++
                  @others,
              into: %{} do
            case for({code, run} <- @table, String.starts_with?(run, beginning), do: code) do
              [code] ->
                {ending, code}

              found ->
                raise "spec/exit-codes.json: #{inspect(ending)} has the rows #{inspect(found)}"
            end
          end)

  if Enum.sort(Map.values(@codes)) != @table |> Enum.map(&elem(&1, 0)) |> Enum.sort(),
    do: raise("spec/exit-codes.json: a row matches no ending, or two endings share one")

  @doc "The table of section 12.2, as `{code, run}`, in its order."
  @spec table() :: [{non_neg_integer(), String.t()}]
  def table, do: @table

  @doc "The exit code of an ending."
  @spec code(ending()) :: non_neg_integer()
  def code(ending), do: Map.fetch!(@codes, ending)

  @doc "The exit code of a result of `Truestamp.Verify.verify/2`."
  @spec of({:ok, Report.t()} | {:error, Rejection.t() | ReadError.t() | Fault.t()}) ::
          non_neg_integer()
  def of({:ok, %Report{label: label}}) when label != nil, do: code({:label, label})
  def of({:error, %Rejection{code: :configuration_error}}), do: code(:configuration_error)
  def of({:error, %Rejection{}}), do: code(:bare_rejection)
  def of({:error, %ReadError{}}), do: code(:runtime_error)
  def of({:error, %Fault{}}), do: code(:fault)
end
