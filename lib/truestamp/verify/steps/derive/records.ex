# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Derive.Records do
  @moduledoc """
  The record hashes of DERIVE (SPEC.md section 10.2, step 9): parts (a) to (c), each a
  `Truestamp.Verify.Check` that recomputes a value from the preimage P carries and compares
  it with the value P carries for it.

  **(a) Subject hashes**, by `type`, the only member that selects what runs (section 10.6,
  rule 3):

  | Recomputed | In | Part | Row of 7.3 |
  |---|---|---|---|
  | H(0x10, `/subject/claims`) | `item` | `/subject/record/claims_hash` | `claims_hash` |
  | H(0x11, `/subject/record`) | `item` | `/subject/item_hash` | `item_hash` |
  | H(0x20, `/subject/entropy`) | the entropy types | `/subject/record/entropy_hash` | `entropy_hash` |
  | H(0x21, `/subject/record`) | the entropy types | `/subject/observation_hash` | `observation_hash` |
  | H(0x20, `/observations/entropy_X/entropy`) | `beacon` | `/observations/entropy_X/record/entropy_hash` | `entropy_hash` |
  | H(0x21, `/observations/entropy_X/record`) | `beacon` | `/observations/entropy_X/observation_hash` | `observation_hash` |

  **(b) Block nodes.** For each block node B P carries (`Truestamp.Verify.Layout`):

  | Check | Part | Row of 7.3 |
  |---|---|---|
  | H(0x31, B`/record`) = B`/block_hash` | B`/block_hash` | `block_hash` |
  | with B`/record/metadata/genesis`: B`/record/height` = 0 | B`/record/height` | `genesis` |
  | with B`/record/metadata/genesis`: H(0x30, B`/record/metadata/genesis`) = B`/record/previous_block_hash` | B`/record/previous_block_hash` | `genesis` |

  and each key event B carries is checked by `Truestamp.Verify.Steps.Derive.KeyEvents`.

  **(c) Epochs.** For each commitment entry N, H(0x40, N`/epoch/record`) = N`/epoch/epoch_hash`,
  at that part (row `epoch_hash`).

  Every prefix byte comes from the compiled registry, through `Truestamp.Verify.Hash`
  and a kind this module names (section 10.6, rule 2), and every check is traced: each part
  above is a CHECKED value (section 3.7).
  """

  alias Truestamp.Verify.{Chains, Check, Hash, Layout}
  alias Truestamp.Verify.Steps.Derive.KeyEvents

  @doc "The checks of (a), (b) and (c), in that order."
  @spec checks(map()) :: [Check.t()]
  def checks(proof), do: subject(proof) ++ block_nodes(proof) ++ epochs(proof)

  @doc """
  The height a block record counts as where a check compares it (sections 10.2, step 9 (b),
  and 10.3): 0 when it carries `metadata.genesis`, whatever it declares, and otherwise the
  height it carries.
  """
  @spec height(map()) :: integer()
  def height(%{"metadata" => %{"genesis" => _genesis}}), do: 0
  def height(%{"height" => height}), do: height

  # (a)

  defp subject(%{"type" => "item"} = proof) do
    [
      hash(proof, ["subject", "record", "claims_hash"], :claims_hash, ["subject", "claims"]),
      hash(proof, ["subject", "item_hash"], :item_hash, ["subject", "record"])
    ]
  end

  defp subject(%{"type" => "entropy_" <> _source} = proof), do: observation(proof, ["subject"])

  defp subject(%{"type" => "beacon"} = proof) do
    for source <- Chains.entropy_sources(),
        at = ["observations", Layout.member(source)],
        is_map(Layout.get(proof, at)),
        check <- observation(proof, at),
        do: check
  end

  defp subject(%{"type" => "block"}), do: []

  defp observation(proof, at) do
    [
      hash(proof, at ++ ["record", "entropy_hash"], :entropy_hash, at ++ ["entropy"]),
      hash(proof, at ++ ["observation_hash"], :observation_hash, at ++ ["record"])
    ]
  end

  # (b)

  defp block_nodes(proof) do
    for {at, node} <- Layout.block_nodes(proof),
        check <- block_node(at, node),
        do: check
  end

  defp block_node(at, %{"record" => record} = node) do
    block_hash =
      Check.equal(
        at ++ ["block_hash"],
        "block_hash",
        [at ++ ["record"]],
        node["block_hash"],
        Hash.hash_hex(:block_hash, record),
        noun: :block_hash
      )

    [block_hash | genesis(at ++ ["record"], record)] ++ KeyEvents.checks(at, record)
  end

  defp genesis(at, %{"metadata" => %{"genesis" => genesis}} = record) do
    inputs = [at ++ ["metadata", "genesis"]]

    [
      Check.equal(at ++ ["height"], "genesis", inputs, record["height"], 0,
        noun: :genesis_height
      ),
      Check.equal(
        at ++ ["previous_block_hash"],
        "genesis",
        inputs,
        record["previous_block_hash"],
        Hash.hash_hex(:genesis_previous_block_hash, genesis),
        noun: :genesis_previous_block_hash
      )
    ]
  end

  defp genesis(_at, _record), do: []

  # (c)

  defp epochs(proof) do
    for {at, _chain, %{"epoch" => epoch}} <- Layout.commitment_entries(proof) do
      Check.equal(
        at ++ ["epoch", "epoch_hash"],
        "epoch_hash",
        [at ++ ["epoch", "record"]],
        epoch["epoch_hash"],
        Hash.hash_hex(:epoch_hash, epoch["record"]),
        noun: :epoch_hash
      )
    end
  end

  defp hash(proof, part, kind, preimage) do
    Check.equal(
      part,
      Atom.to_string(kind),
      [preimage],
      Layout.get(proof, part),
      Hash.hash_hex(kind, Layout.get(proof, preimage)),
      noun: kind
    )
  end
end
