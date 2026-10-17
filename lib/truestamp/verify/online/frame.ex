# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Frame do
  @moduledoc false
  # The sources of an online run, fixed at CONFIGURATION before the file is read (SPEC.md
  # section 10.2, step 0):
  #
  # - every Stellar and Bitcoin network the run pins, as a commitment pin or an entropy pin,
  #   must have a source, or the run is `configuration_error`;
  # - every such source has its identity read, live, and confirmed against its chain's
  #   production value: a source pinned to the production network must give it, and a
  #   source pinned to any other network must not, or the run is `configuration_error`;
  # - a source whose identity read gives no usable answer serves no read: each row it serves
  #   is `skip source_unreachable`;
  # - NIST has no network and no identity read; a reader with no NIST source leaves each
  #   NIST row `skip source_unreachable`.
  #
  # The frame maps each `{chain, network}` (`{"nist", nil}` for NIST) to its policy and its
  # sources, each with the outcome of its identity read.

  alias Truestamp.Verify.{Chains, Config}
  alias Truestamp.Verify.Online.Reads

  @type entry :: %{
          policy: term(),
          sources: [%{id: term(), identity: :ok | {:unreachable, term()}}]
        }
  @type t :: %{{String.t(), String.t() | nil} => entry() | :none}

  @doc false
  @spec build(Config.t(), integer() | nil) ::
          {:ok, t()} | {:configuration_error, atom(), map()}
  def build(%Config{reader: nil}, _deadline), do: {:ok, %{}}

  def build(%Config{reader: reader, networks: pins}, deadline) do
    with {:ok, frame} <- networks(reader, pins),
         {:ok, frame} <- identities(reader, frame, deadline) do
      {:ok, Map.put(frame, {"nist", nil}, nist(reader))}
    end
  end

  # Every pinned network of every commitment chain, each with the sources the reader names.
  defp networks({module, state}, pins) do
    pinned =
      for chain <- Chains.commitment_chains(),
          kind <- [:commitment, :entropy],
          network = pins |> Map.fetch!(kind) |> Map.get(chain.name()),
          network != nil,
          uniq: true,
          do: {chain.name(), network}

    Enum.reduce_while(pinned, {:ok, %{}}, fn {chain, network} = key, {:ok, frame} ->
      case safe_sources(module, state, chain, network) do
        {:ok, [_ | _] = ids, policy} ->
          sources = Enum.map(ids, &%{id: &1, identity: :ok})
          {:cont, {:ok, Map.put(frame, key, %{policy: policy, sources: sources})}}

        _none ->
          {:halt, {:configuration_error, :no_source, %{chain: chain, network: network}}}
      end
    end)
  end

  # One identity read for each source of each pinned network, checked against that network.
  # A reader scopes its source ids to a chain and network, so two networks' sources are two
  # reads even when the reader gives them one id.
  defp identities(reader, frame, deadline) do
    frame
    |> Enum.sort()
    |> Enum.reduce_while({:ok, frame}, fn {key, entry}, {:ok, frame} ->
      case confirm(reader, key, entry, deadline) do
        {:ok, entry} -> {:cont, {:ok, Map.put(frame, key, entry)}}
        error -> {:halt, error}
      end
    end)
  end

  # The network's entry with each source's identity confirmed, or configuration_error when
  # any source gives a value step 0 forbids for that network.
  defp confirm(reader, {chain, network}, entry, deadline) do
    module = Chains.commitment_chain(chain)
    {production, kind} = module.identity()

    judged =
      for source <- entry.sources do
        answer = identity(reader, source.id, network, kind, deadline)
        {source, judge(module, answer, network == production)}
      end

    if Enum.any?(judged, &match?({_source, :forbidden}, &1)),
      do: {:configuration_error, :identity_forbidden, %{chain: chain, network: network}},
      else: {:ok, %{entry | sources: Enum.map(judged, &confirmed/1)}}
  end

  defp confirmed({source, :ok}), do: source

  defp confirmed({source, {:unreachable, reason}}),
    do: %{source | identity: {:unreachable, reason}}

  defp identity({module, state}, source, network, kind, deadline),
    do: Reads.read({module, state}, source, network, kind, %{}, deadline)

  # A forbidden identity is configuration_error; one that gives no usable answer leaves the
  # source unreachable.
  defp judge(module, {:found, fields, _meta}, production?) do
    case module.production_identity?(fields) do
      {:ok, ^production?} -> :ok
      {:ok, _other} -> :forbidden
      :error -> {:unreachable, :identity_unusable}
    end
  end

  defp judge(_module, {:not_found, _meta}, _production?), do: {:unreachable, :identity_not_found}
  defp judge(_module, {:unreachable, reason}, _production?), do: {:unreachable, reason}

  defp nist({module, state}) do
    case safe_sources(module, state, "nist", nil) do
      {:ok, [_ | _] = ids, policy} ->
        %{policy: policy, sources: Enum.map(ids, &%{id: &1, identity: :ok})}

      _none ->
        :none
    end
  end

  defp safe_sources(module, state, chain, network) do
    module.sources(state, chain, network)
  catch
    _kind, _reason -> {:error, :reader_fault}
  end
end
