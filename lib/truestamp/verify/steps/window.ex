# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Window do
  @moduledoc """
  Step 12 of SPEC.md section 10.2, WINDOW: the submission window of section 11, drawn as a
  fixed function of the reads this run made, and reported.

  - **The submitted-before edge** is the earliest candidate of the CHAIN rows that passed
    for the top-level entries, `/commitments/C` (section 11.1); the entries at
    `/signing_key_event/commitments` never give one.
  - **The submitted-after edge** is the latest candidate of the SOURCES rows that passed
    (section 11.2).
  - Of two candidates at the same instant, the edge is the first in the order of their
    rows. Instants compare exactly, at the precision each source gives: milliseconds for
    NIST and for the time inside an id, and seconds for Stellar and Bitcoin.

  WINDOW gives the first of these rows that applies, with a null part (section 11.3):

  1. a row has failed: `skip prior_failure`;
  2. both edges exist and the submitted-after edge is later than the submitted-before edge:
     `fail window_inverted`;
  3. the submitted-before edge does not exist: `info window_not_established`;
  4. otherwise: `pass`.

  When that row is `pass` and the time inside the subject's id is later than the
  submitted-before edge, or earlier than the submitted-after edge, WINDOW adds one row,
  `info recorded_time_outside_window`, at the pointer of that id. The time is the leftmost
  48 bits of the id, Unix milliseconds (RFC 9562 section 5.7), a RECORDED value, so the row
  informs and changes no label.

  The row's `values` give every candidate the run read, each edge that exists, and, for
  each edge that does not, its reason: the part and code of each CHAIN or SOURCES row that
  could have given a candidate, a list that is empty when the proof carries none, as for a
  block proof's submitted-after edge. Absence never fails.
  """

  alias Truestamp.Verify.{Chains, Edge, Row, Run}

  @top_level Enum.map(Chains.chain_names(), &("/commitments/" <> &1))

  @doc "Step 12, WINDOW."
  @spec window(Run.t()) :: Run.t()
  def window(%Run{} = run) do
    before_edge = earliest(for {:before, edge} <- run.candidates, do: edge)
    after_edge = latest(for {:after, edge} <- run.candidates, do: edge)
    run = %{run | edges: %{submitted_after: after_edge, submitted_before: before_edge}}
    values = values(run, before_edge, after_edge)

    cond do
      Run.failed?(run) ->
        Run.add_row(
          run,
          Row.new(:window, :prior_failure, nil, Run.message(run, :window_prior_failure))
        )

      before_edge && after_edge && Edge.milliseconds(after_edge) > Edge.milliseconds(before_edge) ->
        Run.add_row(
          run,
          Row.new(:window, :window_inverted, nil, Run.message(run, :window_inverted), values)
        )

      is_nil(before_edge) ->
        message = Run.message(run, :window_not_established, %{online: run.external_gate == :open})
        Run.add_row(run, Row.new(:window, :window_not_established, nil, message, values))

      true ->
        run
        |> Run.add_row(Row.pass(:window, nil, Run.message(run, :window_pass), values))
        |> recorded_time(before_edge, after_edge)
    end
  end

  # The first earliest, and the first latest, in row order.
  defp earliest([]), do: nil
  defp earliest(edges), do: Enum.min_by(edges, &Edge.milliseconds/1)

  defp latest([]), do: nil
  defp latest(edges), do: Enum.max_by(edges, &Edge.milliseconds/1)

  defp values(run, before_edge, after_edge) do
    candidates =
      for {side, edge} <- run.candidates,
          do:
            Map.put(
              Edge.to_map(edge),
              "edge",
              if(side == :before, do: "submitted_before", else: "submitted_after")
            )

    absent =
      %{}
      |> absent(
        "submitted_before",
        before_edge,
        for(%Row{step: :chain, part: part} = row <- run.rows, part in @top_level, do: reason(row))
      )
      |> absent(
        "submitted_after",
        after_edge,
        for(%Row{step: :sources} = row <- run.rows, do: reason(row))
      )

    edges =
      for {name, edge} <- [submitted_after: after_edge, submitted_before: before_edge],
          edge != nil,
          into: %{},
          do: {Atom.to_string(name), Edge.to_map(edge)}

    %{"absent" => absent, "candidates" => candidates, "edges" => edges}
  end

  defp absent(absent, _name, %Edge{}, _reasons), do: absent
  defp absent(absent, name, nil, reasons), do: Map.put(absent, name, reasons)

  defp reason(%Row{code: code, part: part}),
    do: %{"code" => code && Atom.to_string(code), "part" => part}

  # SPEC.md 11.3: the time inside the subject's id, against the window that holds.
  defp recorded_time(%Run{subject_id: id, type: type} = run, before_edge, after_edge) do
    time = id_time(id)

    outside? =
      Edge.milliseconds(before_edge) < time or
        (after_edge != nil and time < Edge.milliseconds(after_edge))

    if outside? do
      part = if type in ["block", "beacon"], do: "/block/record/id", else: "/subject/record/id"
      values = %{"id_time" => id_time_text(time)}

      Run.add_row(
        run,
        Row.new(
          :window,
          :recorded_time_outside_window,
          part,
          Run.message(run, :recorded_time_outside_window, %{
            attributed: run.attribution == "truestamp"
          }),
          values
        )
      )
    else
      run
    end
  end

  # The leftmost 48 bits of the 16 bytes the id's 32 hex digits spell: its first 12 hex
  # digits, the hyphen skipped, an unsigned big-endian count of milliseconds.
  defp id_time(<<a::binary-8, "-", b::binary-4, _rest::binary>>),
    do: String.to_integer(a <> b, 16)

  # The id's time as an instant, or, for a time past the year 9999 that its 48 bits can
  # hold, its count of milliseconds.
  defp id_time_text(milliseconds) do
    case DateTime.from_unix(milliseconds, :millisecond) do
      {:ok, instant} -> DateTime.to_iso8601(instant)
      {:error, _beyond} -> milliseconds
    end
  end
end
