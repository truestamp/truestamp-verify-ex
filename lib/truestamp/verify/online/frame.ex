# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Frame do
  @moduledoc false
  # The sources of an online run, fixed at CONFIGURATION before the file is read (SPEC.md
  # section 10.2, step 0):
  #
  # - every Stellar and Bitcoin network the run pins, as a commitment pin or an entropy pin,
  #   must have a source, or the run is `configuration_error`;
  # - a network's policy `{:at_least, n}` needs n from 1 to the number of its sources, or the
  #   run is `configuration_error` (section 9);
  # - NIST's Randomness Beacon is one source (section 9): a reader that names several for it
  #   makes the run `configuration_error`;
  # - every such source has its identity read, live, and confirmed against its chain's
  #   production value: a source pinned to the production network must give it, and a
  #   source pinned to any other network must not, or the run is `configuration_error`; the
  #   reads run concurrently, and the first network, in order, with a forbidden identity
  #   decides the error;
  # - a source whose identity read gives no usable answer serves no read: each row it serves
  #   is `skip source_unreachable`;
  # - NIST has no network and no identity read; a reader with no NIST source leaves each
  #   NIST row `skip source_unreachable`.
  #
  # The frame maps each `{chain, network}` (`{"nist", nil}` for NIST) to its policy and its
  # sources, each with the outcome of its identity read and that read's meta, which a row
  # whose source was asked nothing else reports (section 10.4, what a row read).

  alias Truestamp.Verify.{Chains, Config}
  alias Truestamp.Verify.Online.Reads

  @type entry :: %{
          policy: term(),
          sources: [
            %{id: term(), identity: :ok | {:unreachable, term()}, identity_meta: map() | nil}
          ]
        }
  @type t :: %{{String.t(), String.t() | nil} => entry() | :none}

  @doc false
  @spec build(Config.t(), integer() | nil) ::
          {:ok, t()} | {:configuration_error, atom(), map()}
  def build(%Config{reader: nil}, _deadline), do: {:ok, %{}}

  def build(%Config{reader: reader, networks: pins}, deadline) do
    with {:ok, frame} <- networks(reader, pins),
         {:ok, nist} <- nist(reader),
         {:ok, frame} <- identities(reader, frame, deadline) do
      {:ok, Map.put(frame, {"nist", nil}, nist)}
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
      case entry(safe_sources(module, state, chain, network), chain, network) do
        {:ok, entry} -> {:cont, {:ok, Map.put(frame, key, entry)}}
        error -> {:halt, error}
      end
    end)
  end

  # A pinned network's frame entry, from what its reader names: its sources under a policy
  # section 9 allows for their number.
  defp entry({:ok, [_ | _] = ids, policy}, chain, network) do
    if policy?(policy, length(ids)),
      do: {:ok, %{policy: policy, sources: Enum.map(ids, &unconfirmed/1)}},
      else:
        {:configuration_error, :invalid_policy,
         %{chain: chain, network: network, count: length(ids)}}
  end

  defp entry(_none, chain, network),
    do: {:configuration_error, :no_source, %{chain: chain, network: network}}

  defp unconfirmed(id), do: %{id: id, identity: :ok, identity_meta: nil}

  # One identity read for each source of each pinned network, checked against that network.
  # A reader scopes its source ids to a chain and network, so two networks' sources are two
  # reads even when the reader gives them one id.
  #
  # The reads run at once, each in a task of its own, and each under the run's deadline, as
  # `Reads.read/6` holds every read to it; they are then judged in the order of the networks,
  # so the outcome is the one reads made one after another give. A task carries the calling
  # process in its `$callers`, which is how a reader's process-local stubs reach the read
  # (`Truestamp.Verify.Reader`, "Processes").
  defp identities(reader, frame, deadline) do
    networks = Enum.sort(frame)

    reads =
      for {{chain, network}, entry} <- networks, source <- entry.sources do
        {_production, kind} = Chains.commitment_chain(chain).identity()
        {source.id, network, kind}
      end

    answers =
      reads
      |> Task.async_stream(
        fn {id, network, kind} -> identity(reader, id, network, kind, deadline) end,
        max_concurrency: max(length(reads), 1),
        ordered: true,
        timeout: :infinity
      )
      |> Enum.map(fn {:ok, answer} -> answer end)

    networks
    |> Enum.reduce_while({:ok, frame, answers}, fn {key, entry}, {:ok, frame, answers} ->
      {mine, rest} = Enum.split(answers, length(entry.sources))

      case confirm(key, entry, mine) do
        {:ok, entry} -> {:cont, {:ok, Map.put(frame, key, entry), rest}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, frame, _no_answer_left} -> {:ok, frame}
      error -> error
    end
  end

  # The network's entry with each source's identity confirmed from its answer, or
  # configuration_error when any source gives a value step 0 forbids for that network.
  defp confirm({chain, network}, entry, answers) do
    module = Chains.commitment_chain(chain)
    {production, _kind} = module.identity()

    judged =
      for {source, answer} <- Enum.zip(entry.sources, answers) do
        {%{source | identity_meta: meta(answer)}, judge(module, answer, network == production)}
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

  defp meta({:found, _fields, meta}), do: meta
  defp meta({:not_found, meta}), do: meta
  defp meta({:unreachable, _reason}), do: nil

  # Section 9: `{:at_least, n}` with n from 1 to the number of the network's sources.
  defp policy?(policy, _count) when policy in [:first, :all], do: true
  defp policy?({:at_least, n}, count) when is_integer(n), do: n in 1..count//1
  defp policy?(_policy, _count), do: false

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

  # NIST has no network and no identity read, and is one source (section 9).
  defp nist({module, state}) do
    case safe_sources(module, state, "nist", nil) do
      {:ok, [id], _policy} ->
        {:ok, %{policy: :first, sources: [unconfirmed(id)]}}

      {:ok, [_, _ | _], _policy} ->
        {:configuration_error, :nist_sources, %{}}

      _none ->
        {:ok, :none}
    end
  end

  defp safe_sources(module, state, chain, network) do
    module.sources(state, chain, network)
  catch
    _kind, _reason -> {:error, :reader_fault}
  end
end
