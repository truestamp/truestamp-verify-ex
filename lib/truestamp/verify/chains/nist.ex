# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.Nist do
  @moduledoc """
  NIST's Randomness Beacon, as an entropy source (`Truestamp.Verify.EntropySource`). It is
  no commitment chain, and its entropy objects carry no network, so POLICY has nothing of it
  to compare and step 0 no identity to read.

  **The read of section 10.4**: the pulse at `chainIndex` and `pulseIndex`. Its
  `outputValue` and `timeStamp` must equal the object's, or `entropy_mismatch`; the
  `timeStamp` read is the object's candidate for the submitted-after edge
  (`nist_pulse_time_read`), at a millisecond's precision. A source that does not hold the
  pulse gives `skip not_held_by_source`.

  `outputValue` compares as the bytes it spells, and `timeStamp` as an instant. Called
  directly on an object whose pulse lacks a member the rule reads, or holds one out of its
  class, the rule makes no read and fails with `shape_invalid`
  (`Truestamp.Verify.Online.Rule.carried/3`).
  """

  @behaviour Truestamp.Verify.Chains.Member
  @behaviour Truestamp.Verify.EntropySource

  alias Truestamp.Verify.Edge
  alias Truestamp.Verify.Online.{Answer, Rule}

  @impl Truestamp.Verify.Chains.Member
  def name, do: "nist"

  @impl true
  def networked?, do: false

  @impl true
  def entropy_times, do: [{["payload", "pulse", "timeStamp"], :nisttime}]

  @impl true
  def entropy(context, object) do
    members =
      for {name, class} <- [
            {"chainIndex", :int},
            {"outputValue", :nisthex},
            {"pulseIndex", :int},
            {"timeStamp", :nisttime}
          ],
          do: {["payload", "pulse", name], class}

    with {:ok, [chain_index, output_value, pulse_index, declared_ms]} <-
           Rule.carried(context, object, members) do
      params = %{"chainIndex" => chain_index, "pulseIndex" => pulse_index}
      pulse(context, params, output_value, declared_ms)
    end
  end

  defp pulse(context, params, output_value, declared_ms) do
    {answer, context} = Rule.read(context, :nist_pulse, params)

    case answer do
      {:found, fields, meta} ->
        time_stamp = Answer.field(fields, "timeStamp", :nisttime)

        checks = [
          {"outputValue",
           Answer.field(fields, "outputValue", :nisthex) |> Rule.compare(output_value)},
          {"timeStamp", Rule.compare(time_stamp, declared_ms)}
        ]

        case Rule.decide(checks) do
          :ok ->
            {:ok, read_ms} = time_stamp
            Rule.pass(context, edge(read_ms, context.part, meta))

          {:contradiction, names} ->
            Rule.fail(context, :entropy_mismatch, %{"differs" => names})

          {:unusable, names} ->
            Rule.skip(context, :source_unreachable, %{"unusable" => names})
        end

      {:not_found, _meta} ->
        Rule.skip(context, :not_held_by_source)

      {:unreachable, _reason} ->
        Rule.skip(context, :source_unreachable)
    end
  end

  defp edge(ms, part, meta) do
    %Edge{
      instant: DateTime.from_unix!(ms, :millisecond),
      precision: :millisecond,
      basis: "nist_pulse_time_read",
      assumption: Edge.assumption("nist_pulse_time_read", :after),
      part: part,
      source: meta.source,
      cached: meta.cached,
      fetched_at: meta.fetched_at
    }
  end
end
