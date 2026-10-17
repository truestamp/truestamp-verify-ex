# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Check do
  @moduledoc """
  One check of DERIVE (SPEC.md section 10.2, step 9), as the one engine of section 10.6
  takes it: `Truestamp.Verify.Steps.Derive` turns each check into its report row and, when
  the check is traced, its trace row.

  | Field | Holds |
  |---|---|
  | `part` | the check's part (section 10.2's one rule): the carried value the check finds wrong when it fails, which for a recomputation is the declared value; a pointer as its segments |
  | `construction` | the name of the row of the constructions text (section 7.3) that defines the value |
  | `inputs` | the pointers of the values the check reads, for reading only |
  | `declared` | the carried value the check compares: the value at `part`, except in the OP_RETURN row and the row of the matched hash, where it is the 32 bytes read out of that part (section 10.2, step 9 (d)); nil for a well-formedness check |
  | `recomputed` | what the check compares `declared` with, as its table defines it (section 10.6), or nil where the check computes none, or where a walk gives no root |
  | `outcome` | `:pass`, `{:fail, code}` or `{:info, code}` |
  | `traced` | whether the check gives a trace row: its part is a CHECKED value (section 3.7), and it is not a row of LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER (section 10.6) |
  | `values` | what else the row's `values` hold: a refusal's name, or the rule a structure breaks |
  | `message` | the row's message, as `{id, assigns}` for `Truestamp.Verify.Messages` |

  **A row's values** (section 10.5). A pass row holds `construction`. A failing row holds
  `construction`, `declared`, the carried value the check found wrong, and `recomputed`,
  what it was compared with as section 10.6 defines it, even when the proof carries that
  value, where the check compares values. A check that compares no values holds instead the
  rule the structure breaks (a well-formedness check), or `declared` and the step of section
  6.2 that refused the key (the checks of a key's bytes); a handover signature that does not
  verify also names that step. An `info` row holds `construction`.
  """

  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.{Messages, ReasonCodes, Row, TraceRow}

  @typedoc "A check's outcome."
  @type outcome :: :pass | {:fail, ReasonCodes.code()} | {:info, ReasonCodes.code()}

  @type t :: %__MODULE__{
          part: Pointer.t(),
          construction: String.t(),
          inputs: [Pointer.t()],
          declared: term(),
          recomputed: term(),
          outcome: outcome(),
          traced: boolean(),
          values: map(),
          message: {Messages.id(), map()}
        }

  @enforce_keys [:part, :construction, :inputs, :declared, :outcome, :traced, :message]
  defstruct [
    :part,
    :construction,
    :inputs,
    :declared,
    :outcome,
    :traced,
    :message,
    recomputed: nil,
    values: %{}
  ]

  @doc """
  The check that the value at `part` equals `recomputed`: pass when they are equal, with
  `===`, and otherwise a failure with `code`, `:derivation_mismatch` by default. Options:

  - `:code`, the failure's code;
  - `:traced`, true by default;
  - `:noun`, what the value is, an atom the message module names (`:value` by default);
  - `:assigns`, further assigns for the message, such as where the inclusion proof is
    that walks to the value.
  """
  @spec equal(Pointer.t(), String.t(), [Pointer.t()], term(), term(), keyword()) :: t()
  def equal(part, construction, inputs, declared, recomputed, options \\ []) do
    assigns =
      Map.merge(Keyword.get(options, :assigns, %{}), %{
        noun: Keyword.get(options, :noun, :value),
        part: Pointer.encode(part),
        construction: construction
      })

    {outcome, id} =
      if declared === recomputed,
        do: {:pass, :value_recomputed},
        else: {{:fail, Keyword.get(options, :code, :derivation_mismatch)}, :value_not_recomputed}

    %__MODULE__{
      part: part,
      construction: construction,
      inputs: Pointer.sort_by(inputs),
      declared: declared,
      recomputed: recomputed,
      outcome: outcome,
      traced: Keyword.get(options, :traced, true),
      message: {id, assigns}
    }
  end

  @doc "The check's report row (section 10.5), its message written by `messages`."
  @spec row(t(), module()) :: Row.t()
  def row(%__MODULE__{outcome: outcome, message: {id, assigns}} = check, messages) do
    text = Messages.render(messages, id, assigns)
    part = Pointer.encode(check.part)

    case outcome do
      :pass -> Row.pass(:derive, part, text, name(check))
      {:info, code} -> Row.new(:derive, code, part, text, name(check))
      {:fail, code} -> Row.new(:derive, code, part, text, failure_values(check))
    end
  end

  defp name(check), do: %{"construction" => check.construction}

  defp failure_values(%__MODULE__{values: values} = check) when map_size(values) > 0,
    do: check |> name() |> Map.merge(values)

  defp failure_values(check) do
    check
    |> name()
    |> Map.merge(%{"declared" => check.declared, "recomputed" => check.recomputed})
  end

  @doc "The check's trace row (section 10.6). Only a traced check has one."
  @spec trace_row(t()) :: TraceRow.t()
  def trace_row(%__MODULE__{traced: true} = check) do
    %TraceRow{
      construction: check.construction,
      declared: check.declared,
      inputs: Enum.map(check.inputs, &Pointer.encode/1),
      part: Pointer.encode(check.part),
      recomputed: check.recomputed,
      status: if(check.outcome == :pass, do: :pass, else: :fail)
    }
  end
end
