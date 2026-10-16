# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Readers.Replay do
  @moduledoc """
  A `Truestamp.Verify.Reader` that answers every read from a replay file of SPEC.md section
  13.2, in place of the network: the reader that runs the online conformance cases, and one
  any caller can use to test online verification with no network.

  A replay file is `{"reads": [{answer, read}, ...]}`. A `read` names the read: its `kind`,
  its `network` for a Stellar or Bitcoin read, and its parameters, each spelled as the proof
  spells the value it comes from. The reader finds an answer by building the same object.

  - The file stands as the operator-pinned source for each Stellar or Bitcoin network whose
    identity read it holds, and for NIST: `c:sources/3` names one source, `"replay"`, for
    those, and none for any other network, which makes a run that pins one a
    `configuration_error` (section 10.2, step 0).
  - A read the file does not hold has no answer: it is unreachable, with the reason
    `{:not_in_replay, read}`, so the test that makes it fails on its rows.

  Every answer is stamped `source: "replay"`, `cached: false`, and the `fetched_at` given to
  `new/2`, the same for every read, so two runs with one reader give equal reports.
  """

  @behaviour Truestamp.Verify.Reader

  alias Truestamp.Verify.{Chains, JSON}

  @typedoc "A loaded replay file."
  @type t :: %__MODULE__{reads: %{map() => map()}, fetched_at: DateTime.t()}

  @enforce_keys [:reads, :fetched_at]
  defstruct [:reads, :fetched_at]

  @source "replay"

  @doc """
  The reader of the replay file at `path`: `{:ok, {Replay, state}}`, or `{:error, reason}`.
  Option `:fetched_at`, the instant each answer is stamped with, defaults to now.
  """
  @spec new(Path.t(), keyword()) :: {:ok, {module(), t()}} | {:error, term()}
  def new(path, options \\ []) do
    with {:ok, bytes} <- File.read(path),
         {:ok, %{"reads" => records}} when is_list(records) <- JSON.parse(bytes),
         {:ok, reads} <- index(records) do
      fetched_at = Keyword.get_lazy(options, :fetched_at, fn -> DateTime.utc_now() end)
      {:ok, {__MODULE__, %__MODULE__{reads: reads, fetched_at: fetched_at}}}
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

  defp index(records) do
    Enum.reduce_while(records, {:ok, %{}}, fn
      %{"read" => %{"kind" => _} = read, "answer" => %{"outcome" => _} = answer}, {:ok, reads} ->
        {:cont, {:ok, Map.put(reads, read, answer)}}

      _record, _acc ->
        {:halt, {:error, :not_a_replay_file}}
    end)
  end

  @impl true
  def sources(%__MODULE__{}, "nist", nil), do: {:ok, [@source], :first}

  def sources(%__MODULE__{reads: reads}, chain, network) do
    if Map.has_key?(reads, %{"kind" => chain <> "_identity", "network" => network}),
      do: {:ok, [@source], :first},
      else: {:error, :no_source}
  end

  @impl true
  def read(%__MODULE__{reads: reads, fetched_at: fetched_at}, @source, network, kind, params) do
    read = key(network, kind, params)
    meta = %{source: @source, fetched_at: fetched_at, cached: false}

    case Map.fetch(reads, read) do
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
  def answer(%__MODULE__{reads: reads}, read), do: Map.get(reads, read)
end
