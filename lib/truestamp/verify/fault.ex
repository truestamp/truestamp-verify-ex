# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Fault do
  @moduledoc """
  A fault inside the verifier that leaves no report (SPEC.md sections 10.5 and 12.2, exit
  code 2): one caught before steps 0 to 3 passed, or at VERDICT or while the report is
  written, so no report exists to hold its row.

  A fault caught from ENVIRONMENT to EXPECTED_HASH is not this: it is an `internal_error`
  row of a `failed` report, the run ended as a failure at the gate ends it. Either way the
  fault may be in the caller's message module (`Truestamp.Verify.Messages`): the outcome is
  that of where it happens, and never a raise from `Truestamp.Verify.verify/2`. `kind` is `:error`, `:throw` or `:exit`, and `description` the fault as
  Elixir formats it, for a person; no conforming input causes one.
  """

  @type t :: %__MODULE__{
          kind: :error | :throw | :exit,
          description: String.t(),
          message: String.t()
        }

  defexception [:kind, :description, :message]

  @doc "The fault of `kind` and `reason`, raised or thrown with `stacktrace`."
  @spec new(:error | :throw | :exit, term(), Exception.stacktrace()) :: t()
  def new(kind, reason, stacktrace) do
    description = Exception.format_banner(kind, reason, stacktrace)

    %__MODULE__{
      kind: kind,
      description: description,
      message: "The verifier stopped on a fault before it could give a report: " <> description
    }
  end
end
