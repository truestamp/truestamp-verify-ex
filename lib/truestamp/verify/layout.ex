# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Layout do
  @moduledoc """
  Where P, the parsed value of `proof`, holds each kind of node (SPEC.md sections 3.3 to
  3.6), each with its pointer (`Truestamp.Verify.JSON.Pointer`).

  The positions come from the registry of chains and sources (`Truestamp.Verify.Chains`)
  and from `type`, never from the names a document happens to hold: `type` is the only
  member that selects what runs (section 10.6, rule 3), and the chains and sources are the
  alternatives the schema lists. Each function reads a node only where the layout of P's
  type puts one, and skips a position P leaves empty. SHAPE (section 10.2, step 7) has held
  P to the schema before any later step reads these.

  | Function | Positions |
  |---|---|
  | `block_nodes/1` | `/block`; `/signing_key_event/block`; `/witnesses/block` in an item |
  | `commitment_entries/1` | `/commitments/C` and `/signing_key_event/commitments/C`, for each commitment chain C |
  | `entropy_objects/1` | `/subject/entropy` in an entropy type; `/witnesses/entropy_X` in an item; `/observations/entropy_X/entropy` in a beacon |
  | `genesis_objects/1` | B`/record/metadata/genesis/C` for each block node B and each chain C a genesis names |
  """

  alias Truestamp.Verify.Chains
  alias Truestamp.Verify.JSON.Pointer

  @typedoc "A node of P, at its pointer."
  @type at(node) :: {Pointer.t(), node}

  @doc "Every block node P carries, as `{pointer, node}`."
  @spec block_nodes(map()) :: [at(map())]
  def block_nodes(proof) do
    [
      {["block"], proof["block"]},
      {["signing_key_event", "block"], get(proof, ["signing_key_event", "block"])},
      {["witnesses", "block"], if(item?(proof), do: get(proof, ["witnesses", "block"]))}
    ]
    |> Enum.filter(fn {_at, node} -> is_map(node) end)
  end

  @doc "Every commitment entry P carries, as `{pointer, chain module, entry}`."
  @spec commitment_entries(map()) :: [{Pointer.t(), module(), map()}]
  def commitment_entries(proof) do
    for base <- [["commitments"], ["signing_key_event", "commitments"]],
        chain <- Chains.commitment_chains(),
        entry = get(proof, base ++ [chain.name()]),
        is_map(entry),
        do: {base ++ [chain.name()], chain, entry}
  end

  @doc """
  Every entropy object P carries, as `{pointer, source module, object}`, where the source is
  the one its position names: the proof's type for `/subject/entropy`, and the member's name
  in `/witnesses` and `/observations`.
  """
  @spec entropy_objects(map()) :: [{Pointer.t(), module(), map()}]
  def entropy_objects(%{"type" => "entropy_" <> name} = proof) do
    case Chains.entropy_source(name) do
      nil -> []
      source -> present_objects([{["subject", "entropy"], source}], proof)
    end
  end

  def entropy_objects(%{"type" => "item"} = proof) do
    positions =
      for source <- Chains.entropy_sources(), do: {["witnesses", member(source)], source}

    present_objects(positions, proof)
  end

  def entropy_objects(%{"type" => "beacon"} = proof) do
    positions =
      for source <- Chains.entropy_sources(),
          do: {["observations", member(source), "entropy"], source}

    present_objects(positions, proof)
  end

  def entropy_objects(_proof), do: []

  @doc """
  Every genesis object of a chain P carries, one for each block node whose record's
  metadata holds `genesis` with a member for that chain, as `{pointer, chain module,
  object}`: today `metadata.genesis.bitcoin`.
  """
  @spec genesis_objects(map()) :: [{Pointer.t(), module(), map()}]
  def genesis_objects(proof) do
    for {at, node} <- block_nodes(proof),
        chain <- Chains.commitment_chains(),
        chain.genesis?(),
        relative = ["record", "metadata", "genesis", chain.name()],
        object = get(node, relative),
        is_map(object),
        do: {at ++ relative, chain, object}
  end

  @doc "The member that names an entropy source in `/witnesses` and `/observations`."
  @spec member(module()) :: String.t()
  def member(source), do: "entropy_" <> source.name()

  @doc "The value at `pointer` in `value`, or nil where there is none."
  @spec get(term(), Pointer.t()) :: term()
  def get(value, []), do: value
  def get(value, [name | rest]) when is_map(value) and is_binary(name), do: get(value[name], rest)

  def get(value, [index | rest]) when is_list(value) and is_integer(index),
    do: get(Enum.at(value, index), rest)

  def get(_value, _pointer), do: nil

  defp item?(proof), do: proof["type"] == "item"

  defp present_objects(positions, proof) do
    for {at, source} <- positions,
        object = get(proof, at),
        is_map(object),
        do: {at, source, object}
  end
end
