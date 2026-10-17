# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.FakeReader do
  @moduledoc """
  A `Truestamp.Verify.Reader` whose answers a test writes: a map from
  `{source, network, kind, params}` to the reader's own return value, or to a function of
  no arguments that gives it (to raise, sleep or count). A read it does not hold is
  `{:error, :not_scripted}`.

  Its sources are given per `{chain, network}`, as `{:ok, ids, policy}` or `{:error, why}`;
  a pair it does not list has one source, `"fake"`, under `:first`.
  """

  @behaviour Truestamp.Verify.Reader

  alias Truestamp.Verify.JSON

  @doc "The reader of `answers`, with `sources` naming the sources of each network."
  @spec new(map(), map()) :: {module(), map()}
  def new(answers, sources \\ %{}), do: {__MODULE__, %{answers: answers, sources: sources}}

  @doc """
  The reader of a replay file of SPEC.md section 13.2, its every Stellar, Bitcoin and NIST
  read scripted for each source in `sources` (default `["fake"]`), and then `overrides`, a
  map of `{kind, params}` (on any network, for every source) or of full keys to answers.
  """
  @spec from_replay(Path.t(), keyword()) :: {module(), map()}
  def from_replay(path, options \\ []) do
    {:ok, %{"reads" => records}} = path |> File.read!() |> JSON.parse()
    ids = Keyword.get(options, :sources, ["fake"])

    answers =
      for %{"read" => %{"kind" => kind} = read, "answer" => answer} <- records,
          kind != "keyring",
          id <- ids,
          into: %{} do
        params = Map.drop(read, ["kind", "network"])
        {{id, read["network"], String.to_atom(kind), params}, replay_answer(answer)}
      end

    answers =
      Enum.reduce(Keyword.get(options, :overrides, %{}), answers, fn
        {{_source, _network, _kind, _params} = key, answer}, answers ->
          Map.put(answers, key, answer)

        {{kind, params}, answer}, answers ->
          Map.new(answers, fn
            {{id, network, ^kind, ^params}, _old} -> {{id, network, kind, params}, answer}
            other -> other
          end)
      end)

    new(answers, Keyword.get(options, :source_map, %{}))
  end

  defp replay_answer(%{"outcome" => "found", "value" => value}), do: found(value)
  defp replay_answer(%{"outcome" => "not_found"}), do: not_found()
  defp replay_answer(%{"outcome" => "unreachable", "reason" => reason}), do: {:error, reason}

  @doc "A meta of a found or not-found answer."
  @spec meta(keyword()) :: map()
  def meta(options \\ []) do
    %{
      source: Keyword.get(options, :source, "fake"),
      fetched_at: Keyword.get(options, :fetched_at, ~U[2026-10-16 12:00:00Z]),
      cached: Keyword.get(options, :cached, false)
    }
  end

  @doc "A found answer."
  @spec found(map(), keyword()) :: tuple()
  def found(fields, options \\ []), do: {:ok, fields, meta(options)}

  @doc "A not-found answer."
  @spec not_found(keyword()) :: tuple()
  def not_found(options \\ []), do: {:error, :not_found, meta(options)}

  @impl true
  def sources(%{sources: sources}, chain, network),
    do: Map.get(sources, {chain, network}, {:ok, ["fake"], :first})

  # Each answer of a source named by a string other than "fake" carries that name, as a real
  # reader's answers name their source.
  @impl true
  def read(%{answers: answers}, source, network, kind, params) do
    case Map.fetch(answers, {source, network, kind, params}) do
      {:ok, answer} when is_function(answer, 0) -> answer.()
      {:ok, answer} -> named(answer, source)
      :error -> {:error, :not_scripted}
    end
  end

  defp named({:ok, fields, %{source: "fake"} = meta}, source) when is_binary(source),
    do: {:ok, fields, %{meta | source: source}}

  defp named({:error, :not_found, %{source: "fake"} = meta}, source) when is_binary(source),
    do: {:error, :not_found, %{meta | source: source}}

  defp named(answer, _source), do: answer
end
