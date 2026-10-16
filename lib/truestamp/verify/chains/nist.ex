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

  `outputValue` compares as the bytes it spells, and `timeStamp` as an instant.
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
    pulse = object["payload"]["pulse"]
    params = %{"chainIndex" => pulse["chainIndex"], "pulseIndex" => pulse["pulseIndex"]}
    {answer, context} = Rule.read(context, :nist_pulse, params)

    case answer do
      {:found, fields, meta} ->
        {:ok, declared_ms} = Answer.field(pulse, "timeStamp", :nisttime)
        time_stamp = Answer.field(fields, "timeStamp", :nisttime)

        checks = [
          {"outputValue",
           Answer.field(fields, "outputValue", :nisthex) |> Rule.compare(pulse["outputValue"])},
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
