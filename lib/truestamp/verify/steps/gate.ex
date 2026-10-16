# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Gate do
  @moduledoc false
  # What steps 4 to 6 share (SPEC.md section 10.2, the gate): a failure at ENVIRONMENT,
  # KEY_BINDING or SIGNATURE sets the attribution `none` and ends the run, so each later
  # step up to EXPECTED_HASH reports one row `skip prior_failure`, part null.

  alias Truestamp.Verify.{Row, Run}

  @doc false
  @spec failure(Run.t(), Row.t()) :: Run.t()
  def failure(run, row), do: %{run | attribution: "none"} |> Run.add_row(row) |> Run.end_run()
end
