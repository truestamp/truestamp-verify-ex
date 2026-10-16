# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Sources do
  @moduledoc """
  Step 11 of SPEC.md section 10.2, SOURCES: the entropy reads of section 10.4.

  SOURCES gives one row for each entropy object P carries: `/subject/entropy` in an entropy
  type, each `/witnesses/entropy_X` in an item and each `/observations/entropy_X/entropy` in
  a beacon, at the pointer of the object, in document order. Each is read by its source's
  rule (`c:Truestamp.Verify.EntropySource.entropy/2`), on the network of the entropy pin for
  that source, which can differ from the commitment pin of the same chain. A read that
  contradicts the proof is `entropy_mismatch`, and a passing row gives a candidate for the
  submitted-after edge (section 11.2). When the external gate is closed, every row is
  `skip prior_failure` or `skip offline`; a failure at CHAIN does not close it.
  """

  alias Truestamp.Verify.{Layout, Run}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Steps.Reads

  @doc "Step 11, SOURCES: one row for each entropy object."
  @spec sources(Run.t()) :: Run.t()
  def sources(%Run{ended: true} = run), do: run

  def sources(%Run{proof: proof} = run) do
    {rows, run} =
      proof
      |> Layout.entropy_objects()
      |> Pointer.sort_by(&elem(&1, 0))
      |> Enum.map_reduce(run, fn {at, source, object}, run ->
        network =
          if source.networked?(), do: Map.fetch!(run.config.networks.entropy, source.name())

        Reads.row(
          run,
          :sources,
          Pointer.encode(at),
          {source.name(), network},
          &source.entropy(&1, object),
          offline: {:entropy, source.name()},
          side: :after
        )
      end)

    Run.add_rows(run, rows)
  end
end
