# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.Replay do
  @moduledoc """
  A `Truestamp.Verify.Reader` that answers every read from a replay file of SPEC.md section
  13.2, in place of the network: the reader that runs the online conformance cases, and one
  any caller can use to test online verification with no network.

  A replay file is `{"reads": [{answer, read}, {answer, read, source}, ...]}`. A `read` names
  the read: its `kind`, its `network` for a Stellar or Bitcoin read, and its parameters, each
  spelled as the proof spells the value it comes from. A record with `source` answers for
  that one of a network's several sources (section 9); one without answers for the network's
  one source. The reader finds an answer by building the same object.

  - The file stands as the operator-pinned source for each Stellar or Bitcoin network whose
    identity read it holds, and for NIST: `c:Truestamp.Verify.Reader.sources/3` names one
    source, the atom `:replay`, for those, and none for any other network, which makes a
    run that pins one a `configuration_error` (section 10.2, step 0). It answers from the
    records that name no source. A source's name in a case's `sources` is a string, so no
    name, `"replay"` among them, can spell it, and a named source never reads the records
    of a network's one source.
  - A network given several sources with the `:sources` option of `new/2`, as a case's
    `sources` member gives them (section 13.2), has those sources, in their order and under
    their policy, each answering from the records that name it.
  - A read the file does not hold has no answer: it is unreachable, with the reason
    `{:not_in_replay, read}`, so the test that makes it fails on its rows.

  Every answer is stamped with its source's name (`"replay"` for a network's one source),
  `cached: false`, and the `fetched_at` given to `new/2`, the same for every read, so two
  runs with one reader give equal reports. A replay file stands for live reads, so no answer
  is marked cached, and none carries a `tip_height` (`Truestamp.Verify.Reader`, "Caches").

  A case's `config` names no keyring origin, so the keyring read a case makes is of
  www.truestamp.com (section 13.2), which `Truestamp.Verify.KeyringSources.Replay` answers
  from the same file.
  """

  @behaviour Truestamp.Verify.Reader

  alias Truestamp.Verify.{Chains, JSON}

  @typedoc """
  The several sources of each network that has them: chain name to network to its policy and
  the names of its sources, in order.
  """
  @type named :: %{
          String.t() => %{String.t() => {Truestamp.Verify.Reader.policy(), [String.t(), ...]}}
        }

  @typedoc "A loaded replay file: each answer by its read and its source's name, or nil."
  @type t :: %__MODULE__{
          reads: %{{map(), String.t() | nil} => map()},
          named: named(),
          fetched_at: DateTime.t()
        }

  @enforce_keys [:reads, :fetched_at]
  defstruct [:reads, :fetched_at, named: %{}]

  # A network's one source: an atom, which no source name, a string, can spell.
  @source :replay

  @doc """
  The reader of the replay file at `path`: `{:ok, {Replay, state}}`, or `{:error, reason}`.
  Options:

  - `:fetched_at`, the instant each answer is stamped with, now by default;
  - `:sources`, the several sources of each network that has them, `named()`, such as
    `%{"stellar" => %{"testnet" => {:all, ["a", "b"]}}}`; every other network has one.
  """
  @spec new(Path.t(), keyword()) :: {:ok, {module(), t()}} | {:error, term()}
  def new(path, options \\ []) do
    with {:ok, bytes} <- File.read(path),
         {:ok, %{"reads" => records}} when is_list(records) <- JSON.parse(bytes),
         {:ok, reads} <- index(records) do
      fetched_at = Keyword.get_lazy(options, :fetched_at, fn -> DateTime.utc_now() end)
      named = Keyword.get(options, :sources, %{})
      {:ok, {__MODULE__, %__MODULE__{reads: reads, named: named, fetched_at: fetched_at}}}
    else
      {:error, reason} -> {:error, reason}
      _other -> {:error, :not_a_replay_file}
    end
  end

  @doc "As `new/2`, raising on a file that is not a replay file."
  @spec new!(Path.t(), keyword()) :: {module(), t()}
  def new!(path, options \\ []) do
    case new(path, options) do
      {:ok, reader} -> reader
      {:error, reason} -> raise ArgumentError, "#{path}: #{inspect(reason)}"
    end
  end

  # Each record by its read and its source's name, or nil; no two records the same.
  defp index(records) do
    Enum.reduce_while(records, {:ok, %{}}, fn record, {:ok, reads} ->
      case record(record) do
        {:ok, key, answer} when not is_map_key(reads, key) ->
          {:cont, {:ok, Map.put(reads, key, answer)}}

        _invalid_or_repeated ->
          {:halt, {:error, :not_a_replay_file}}
      end
    end)
  end

  defp record(%{"read" => %{"kind" => _} = read, "answer" => %{"outcome" => _} = answer} = record)
       when map_size(record) == 2,
       do: {:ok, {read, nil}, answer}

  defp record(
         %{"read" => %{"kind" => _} = read, "answer" => %{"outcome" => _} = answer, "source" => s} =
           record
       )
       when map_size(record) == 3 and is_binary(s),
       do: {:ok, {read, s}, answer}

  defp record(_record), do: :error

  @impl true
  def sources(%__MODULE__{}, "nist", nil), do: {:ok, [@source], :first}

  def sources(%__MODULE__{reads: reads, named: named}, chain, network) do
    case named |> Map.get(chain, %{}) |> Map.get(network) do
      {policy, [_ | _] = names} ->
        {:ok, names, policy}

      nil ->
        if Map.has_key?(reads, {%{"kind" => chain <> "_identity", "network" => network}, nil}),
          do: {:ok, [@source], :first},
          else: {:error, :no_source}
    end
  end

  @impl true
  def read(%__MODULE__{reads: reads, fetched_at: fetched_at}, source, network, kind, params) do
    read = key(network, kind, params)
    {named, name} = if source == @source, do: {nil, "replay"}, else: {source, source}
    meta = %{source: name, fetched_at: fetched_at, cached: false}

    case Map.fetch(reads, {read, named}) do
      {:ok, %{"outcome" => "found", "value" => value}} -> {:ok, value, meta}
      {:ok, %{"outcome" => "not_found"}} -> {:error, :not_found, meta}
      {:ok, %{"outcome" => "unreachable"} = answer} -> {:error, {:unreachable, answer["reason"]}}
      :error -> {:error, {:not_in_replay, read}}
    end
  end

  defp key(network, kind, params) do
    read = Map.put(params, "kind", Atom.to_string(kind))
    if network != nil and networked?(kind), do: Map.put(read, "network", network), else: read
  end

  # Every read of a Stellar or Bitcoin source names its network; a NIST read has none.
  defp networked?(kind) do
    name = Atom.to_string(kind)
    Enum.any?(Chains.chain_names(), &String.starts_with?(name, &1 <> "_"))
  end

  @doc false
  # The answer the file holds for `read`, as `Truestamp.Verify.KeyringSources.Replay` reads it.
  @spec answer(t(), map()) :: map() | nil
  def answer(%__MODULE__{reads: reads}, read), do: Map.get(reads, {read, nil})
end
