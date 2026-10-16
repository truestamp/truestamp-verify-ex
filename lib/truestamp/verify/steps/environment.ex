# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Environment do
  @moduledoc """
  Step 4 of SPEC.md section 10.2, ENVIRONMENT: the check of section 6.4, one row at
  `/environment`. Under E_v `prod` the member is absent; under any other E_v it is present,
  a string, and equal to E_v. Anything else is `environment_mismatch`, which ends the run
  with the attribution `none`.

  The message never quotes the marker: it names the marked environment only when the marker
  is `dev`, `staging` or `test`, says production when there is no marker, and otherwise says
  that the proof carries a marker no Truestamp environment uses (section 6.4). The marker is
  given only under `"declared"` in the row's values.
  """

  alias Truestamp.Verify.{Row, Run, Spec}
  alias Truestamp.Verify.Steps.Gate

  @known_markers Spec.environments() -- ["prod"]

  @doc "Step 4, ENVIRONMENT."
  @spec environment(Run.t()) :: Run.t()
  def environment(%Run{ended: true} = run), do: run

  def environment(%Run{config: %{environment: e_v}, proof: proof} = run) do
    marker = Map.fetch(proof, "environment")
    values = %{"environment" => e_v}

    if passes?(e_v, marker) do
      Run.add_row(
        run,
        Row.pass(
          :environment,
          "/environment",
          Run.text(run, :environment_pass, %{environment: e_v}),
          values
        )
      )
    else
      message = Run.text(run, mismatch(e_v, marker), %{environment: e_v, marker: known(marker)})
      values = declared(values, marker)

      Gate.failure(
        run,
        Row.new(:environment, :environment_mismatch, "/environment", message, values)
      )
    end
  end

  defp passes?("prod", :error), do: true
  defp passes?(e_v, {:ok, e_v}) when e_v != "prod", do: true
  defp passes?(_e_v, _marker), do: false

  defp mismatch(_e_v, :error), do: :environment_mismatch_unmarked

  defp mismatch("prod", {:ok, marker}) when marker in @known_markers,
    do: :environment_mismatch_marked_under_prod

  defp mismatch(_e_v, {:ok, marker}) when marker in @known_markers,
    do: :environment_mismatch_marked

  defp mismatch(_e_v, {:ok, _marker}), do: :environment_mismatch_unknown_marker

  defp known({:ok, marker}) when marker in @known_markers, do: marker
  defp known(_marker), do: nil

  # A failed comparison gives the declared value it contradicts (section 10.5), in `values`
  # only, never in the message.
  defp declared(values, {:ok, marker}), do: Map.put(values, "declared", marker)
  defp declared(values, :error), do: values
end
