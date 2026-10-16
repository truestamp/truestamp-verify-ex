# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Row do
  @moduledoc """
  A report row, `{code, message, part, status, step, values}` (SPEC.md section 10.5).

  | Field | Holds |
  |---|---|
  | `step` | its step, as an atom of `Truestamp.Verify.Step`, such as `:key_binding` |
  | `status` | `:pass`, `:fail`, `:skip`, `:warn` or `:info` |
  | `code` | a reason code of section 12.1, as an atom; nil exactly when the status is `:pass` |
  | `part` | an RFC 6901 pointer into the proof, or nil for a row about no single member |
  | `values` | what this run computed or read, as JSON values; a failed comparison also gives the declared value it contradicts, under `"declared"` |
  | `message` | for display only, never compared; written by the run's message module (`Truestamp.Verify.Messages`) |

  Codes and values are the contract. A message is presentation, and nothing depends on its
  wording (section 12.1).

  `new/5` refuses a row whose code is not in the table of section 12.1, or a status other
  than the one the table gives its code, so no row can carry a code that does not mean what
  its status says. `reduce/1` gives what conformance compares (section 13.1), and
  `to_map/1` the row as a report writes it.
  """

  alias Truestamp.Verify.{ReasonCodes, Step}

  @typedoc "A row status (section 10.5)."
  @type status :: :pass | :fail | :skip | :warn | :info

  @type t :: %__MODULE__{
          step: Step.t(),
          status: status(),
          code: ReasonCodes.code() | nil,
          part: String.t() | nil,
          values: map(),
          message: String.t()
        }

  @enforce_keys [:step, :status, :code, :part, :values, :message]
  defstruct [:step, :status, :code, :part, :values, :message]

  @doc "A `pass` row of `step` at `part`."
  @spec pass(Step.t(), String.t() | nil, String.t(), map()) :: t()
  def pass(step, part, message, values \\ %{}), do: build(step, nil, part, :pass, message, values)

  @doc """
  A row of `step` with `code` at `part`, whose status is the one section 12.1 gives the code,
  or a pass when `code` is nil. Raises `ArgumentError` for a code the table lacks, or one
  whose status is "bare", which ends a run in a bare rejection and never makes a row.
  """
  @spec new(Step.t(), ReasonCodes.code() | nil, String.t() | nil, String.t(), map()) :: t()
  def new(step, code, part, message, values \\ %{})

  def new(step, nil, part, message, values), do: build(step, nil, part, :pass, message, values)

  def new(step, code, part, message, values) do
    unless ReasonCodes.code?(code),
      do: raise(ArgumentError, "#{inspect(code)} is not a reason code of SPEC.md 12.1")

    case ReasonCodes.status(code) do
      :bare -> raise ArgumentError, "#{code} ends a run in a bare rejection, not a row"
      status -> build(step, code, part, status, message, values)
    end
  end

  defp build(step, code, part, status, message, values)
       when is_binary(message) and is_map(values) and (is_nil(part) or is_binary(part)) do
    unless Step.step?(step), do: raise(ArgumentError, "#{inspect(step)} is not a step")

    %__MODULE__{
      step: step,
      status: status,
      code: code,
      part: part,
      values: values,
      message: message
    }
  end

  @doc "What conformance compares of a row: `[code, part, status, step]` (section 13.1)."
  @spec reduce(t()) :: [String.t() | nil]
  def reduce(%__MODULE__{} = row),
    do: [code_name(row.code), row.part, Atom.to_string(row.status), Step.name(row.step)]

  @doc """
  The row as a report writes it (section 10.5): `{code, message, part, status, step,
  values}`, with `code` absent exactly when the status is `pass`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = row) do
    written = %{
      "message" => row.message,
      "part" => row.part,
      "status" => Atom.to_string(row.status),
      "step" => Step.name(row.step),
      "values" => row.values
    }

    if row.code, do: Map.put(written, "code", Atom.to_string(row.code)), else: written
  end

  defp code_name(nil), do: nil
  defp code_name(code), do: Atom.to_string(code)
end
