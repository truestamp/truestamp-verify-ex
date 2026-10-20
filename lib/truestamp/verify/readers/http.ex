# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Readers.HTTP do
    @moduledoc """
    A `Truestamp.Verify.Reader` that reads public servers over HTTP, one or several sources
    for each network, each a `Truestamp.Verify.Source`.

        Truestamp.Verify.Readers.HTTP.new(
          stellar: %{"public" => {Sources.Horizon, base_url: "https://horizon.stellar.org"}},
          bitcoin: %{
            "mainnet" =>
              {:all, [{Sources.Esplora, preset: :mempool}, {Sources.Esplora, preset: :blockstream}]},
            "regtest" => {Sources.BitcoinCore, base_url: "http://127.0.0.1:18443", cookie: "..."}
          },
          nist: {Sources.NistBeacon, []}
        )

    Each network takes one source, `{module, options}`, or several under a policy,
    `{policy, [source, ...]}`, where the policy is `:first`, `{:at_least, n}` or `:all`
    (`Truestamp.Verify.Online.Policy`); `:nist` takes one source, since NIST's Randomness
    Beacon is one (section 9). A network the reader has no source for makes an online run
    that pins it a `configuration_error`, as section 10.2, step 0 requires.

    `default/1` gives the compiled-in defaults, the same as the Go CLI's, with any of them
    replaced by the sources given:

    | Network | Default source |
    |---|---|
    | Stellar `public` | Horizon `https://horizon.stellar.org` |
    | Stellar `testnet` | Horizon `https://horizon-testnet.stellar.org` |
    | Bitcoin `mainnet` | Esplora `https://blockstream.info/api` |
    | Bitcoin `testnet` | Esplora `https://blockstream.info/testnet/api` |
    | Bitcoin `regtest` | none: a regtest chain is private to whoever runs it |
    | NIST | the Beacon at `https://beacon.nist.gov/beacon/2.0` |

    The reader caches nothing: every answer is read live from its server when the engine
    asks, and is `cached: false`, with no `tip_height` (`Truestamp.Verify.Reader`,
    "Caches"). A cache belongs in a reader of its own, in front of this one or in place of
    it.

    Production is the default only in the sense that matters: a run's environment chooses
    the networks it reads, and `:prod` reads only Stellar `public` and Bitcoin `mainnet`. A
    test network's source is used only by a run that pins that network.
    """

    @behaviour Truestamp.Verify.Reader

    alias Truestamp.Verify.Sources.{Esplora, Horizon, NistBeacon}

    @defaults [
      stellar: %{
        "public" => {Horizon, base_url: "https://horizon.stellar.org"},
        "testnet" => {Horizon, base_url: "https://horizon-testnet.stellar.org"}
      },
      bitcoin: %{
        "mainnet" => {Esplora, preset: :blockstream},
        "testnet" => {Esplora, preset: :blockstream_testnet}
      },
      nist: {NistBeacon, []}
    ]

    @typedoc "A source: a module that implements `Truestamp.Verify.Source`, and its options."
    @type source :: {module(), keyword()}

    @typedoc "One network's sources: one, or several under a policy."
    @type network_sources :: source() | {Truestamp.Verify.Reader.policy(), [source(), ...]}

    @doc "The reader of the sources given (see the module doc)."
    @spec new(keyword()) :: {module(), map()}
    def new(options) when is_list(options) do
      networks =
        for {chain, by_network} <- Keyword.delete(options, :nist),
            {network, sources} <- by_network,
            into: %{},
            do: {{Atom.to_string(chain), network}, entry(chain, sources)}

      networks =
        case Keyword.fetch(options, :nist) do
          {:ok, sources} -> Map.put(networks, {"nist", nil}, entry(:nist, sources))
          :error -> networks
        end

      {__MODULE__, %{networks: networks}}
    end

    @doc "The reader of the compiled-in defaults, with the sources given in their place."
    @spec default(keyword()) :: {module(), map()}
    def default(overrides \\ []) do
      @defaults
      |> Keyword.merge(overrides, fn
        :nist, _default, given -> given
        _chain, defaults, given -> Map.merge(defaults, given)
      end)
      |> new()
    end

    # A policy's form: `:first`, `:all` or `{:at_least, n}`, never a module, so that a source
    # given with options, `{module, [option, ...]}`, is never taken for several sources.
    defguardp is_policy(policy)
              when policy in [:first, :all] or (is_tuple(policy) and elem(policy, 0) == :at_least)

    # One network's sources, with ids that name them in a row's values, after checking that
    # each source answers the reads of its chain.
    defp entry(:nist, {policy, [_, _ | _]}) when is_policy(policy),
      do: raise(ArgumentError, "nist: NIST's Randomness Beacon is one source (SPEC.md 9)")

    defp entry(chain, {policy, [_ | _] = sources}) when is_policy(policy) do
      valid_policy!(policy, length(sources))
      sources = Enum.map(sources, &checked!(chain, &1))
      ids = sources |> Enum.map(fn {module, options} -> module.describe(options) end) |> unique()
      %{policy: policy, sources: Map.new(Enum.zip(ids, sources)), order: ids}
    end

    defp entry(chain, {module, options} = source) when is_atom(module) and is_list(options),
      do: entry(chain, {:first, [source]})

    defp entry(chain, other),
      do:
        raise(
          ArgumentError,
          "#{chain}: not a source or {policy, [source, ...]}: #{inspect(other)}"
        )

    defp valid_policy!({:at_least, n}, count) when is_integer(n) and n >= 1 and n <= count,
      do: :ok

    defp valid_policy!(policy, _count) when policy in [:first, :all], do: :ok

    defp valid_policy!(policy, count),
      do: raise(ArgumentError, "#{inspect(policy)} is not a policy #{count} sources can meet")

    @kinds %{
      stellar: ~w(stellar_identity stellar_root stellar_transaction stellar_ledger)a,
      bitcoin: ~w(bitcoin_identity bitcoin_tip bitcoin_block_at_height bitcoin_block)a,
      nist: [:nist_pulse]
    }

    defp checked!(chain, {module, options} = source) when is_atom(module) and is_list(options) do
      unless Code.ensure_loaded?(module) and function_exported?(module, :kinds, 0),
        do: raise(ArgumentError, "#{inspect(module)} is not a Truestamp.Verify.Source")

      missing = Map.fetch!(@kinds, chain) -- module.kinds()

      if missing == [],
        do: source,
        else:
          raise(
            ArgumentError,
            "#{inspect(module)} does not answer #{inspect(missing)}, which #{chain} needs"
          )
    end

    # Two sources described alike, such as the same preset twice, are told apart by position.
    defp unique(ids) do
      ids
      |> Enum.with_index(1)
      |> Enum.map(fn {id, i} ->
        if Enum.count(ids, &(&1 == id)) > 1, do: "#{id} (#{i})", else: id
      end)
    end

    @impl true
    def sources(%{networks: networks}, chain, network) do
      case Map.fetch(networks, {chain, network}) do
        {:ok, %{policy: policy, order: ids}} -> {:ok, ids, policy}
        :error -> {:error, :no_source}
      end
    end

    @impl true
    def read(%{networks: networks}, id, network, kind, params) do
      chain = kind |> Atom.to_string() |> String.split("_", parts: 2) |> hd()

      {module, options} =
        networks |> Map.fetch!({chain, network}) |> Map.fetch!(:sources) |> Map.fetch!(id)

      module.read(options, kind, params)
    end
  end
end
