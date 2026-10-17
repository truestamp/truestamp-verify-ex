# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.WindowTest do
  @moduledoc """
  WINDOW's row for the time inside the subject's id (SPEC.md sections 11.3 and 11.5), on runs
  built here: no conformance case carries an id whose time no TIME can write, or a run that
  attributes the proof to Truestamp with that row.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Config, Edge, Run, TrustRoot}
  alias Truestamp.Verify.Steps.Window

  defp run(subject_id, attribution) do
    edge = %Edge{
      instant: ~U[2026-09-26 01:51:15Z],
      precision: :second,
      basis: "stellar_ledger_close_read",
      assumption: Edge.assumption("stellar_ledger_close_read", :before),
      part: "/commitments/stellar",
      source: "replay",
      cached: false,
      fetched_at: ~U[2026-10-17 00:00:00Z]
    }

    %Run{
      config: Config.external!(environment: :test, trust: :keyless),
      keyring: nil,
      trust_root: %TrustRoot{kind: :none},
      type: "item",
      subject_id: subject_id,
      attribution: attribution,
      candidates: [{:before, edge}]
    }
  end

  defp recorded(run), do: run |> Window.window() |> Map.fetch!(:rows) |> List.last()

  test "an id whose time is past the year 9999 gives its milliseconds, never a fault" do
    # 0xffffffffffff milliseconds is in the year 10889.
    row = recorded(run("ffffffff-ffff-7000-8000-000000000000", "unattributed"))
    assert row.code == :recorded_time_outside_window
    assert row.values == %{"id_time" => 0xFFFFFFFFFFFF}
  end

  test "the id's time is Truestamp's record only in a run attributed to Truestamp" do
    later = "01a0dc00-0000-7000-8000-000000000000"

    assert recorded(run(later, "truestamp")).message =~ "recorded by Truestamp"
    assert recorded(run(later, "keyring:abc")).message =~ "declared by the signer"
    assert recorded(run(later, "keyring:abc")).values["id_time"] =~ ~r/\A\d{4}-/
  end
end
