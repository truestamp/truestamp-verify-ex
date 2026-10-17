# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Derive.Links do
  @moduledoc """
  The links of DERIVE (SPEC.md section 10.2, step 9 (e), and section 10.3), in this order:

  | Link | Rule | Part | Failure | Row of 7.3 | Traced |
  |---|---|---|---|---|---|
  | LINK_INCLUSION | each inclusion proof walks from its recomputed leaf to its record's `merkle_root`, and its `tree_size` equals the record's `leaf_count` | the record's `merkle_root`; the proof's `tree_size` | `derivation_mismatch` | `inclusion` | yes |
  | LINK_WITNESS | each `witness_hashes` entry equals the recomputed hash of its witness | `/subject/record/witness_hashes/W` | `derivation_mismatch` | `witnesses` | yes |
  | LINK_HEAD | `/witnesses/block/record/height` is below `/block/record/height` | `/witnesses/block/record/height` | `ordering_violation` | `height` | no |
  | LINK_KEY_EVENT | the key event at `/signing_key_event/block` introduces K | that event's `public_key` | `key_event_mismatch` | `key_event` | no |
  | LINK_CHAIN_ORDER | a Stellar entropy `sequence` is below the top-level Stellar `ledger`, and a Bitcoin entropy `height` at most the top-level Bitcoin `height`, on the same network | that `sequence` or `height` | `ordering_violation` | `chain_order` | no |

  **LINK_INCLUSION** covers every inclusion proof Q, at both tree levels (section 5.4), in the
  document order of Q, and gives two rows for each: the root, at R`/merkle_root`, where the
  walk of section 5.3 from the recomputed leaf v must succeed and give R's `merkle_root`
  (`recomputed` is nil when it gives no root); and the size, at Q`/tree_size`, which must
  equal R's `leaf_count` whether or not the walk succeeded (`recomputed` is that count).

  | Q | v, recomputed | R |
  |---|---|---|
  | `/subject/inclusion_proof`, in an item | H(0x11, `/subject/record`) | `/block/record` |
  | `/subject/inclusion_proof`, in an entropy type | H(0x21, `/subject/record`) | `/block/record` |
  | `/observations/entropy_X/inclusion_proof` | H(0x21, `/observations/entropy_X/record`) | `/block/record` |
  | `/commitments/C/inclusion_proof` | H(0x31, `/block/record`) | `/commitments/C/epoch/record` |
  | `/signing_key_event/commitments/C/inclusion_proof` | H(0x31, `/signing_key_event/block/record`) | `/signing_key_event/commitments/C/epoch/record` |

  The walk is `Truestamp.Merkle.walk/3`, RFC 9162 section 2.1.3.2, with at most
  MAX_PATH_STEPS path nodes; the leaf and node bytes 0x00 and 0x01 are used only inside it
  (section 10.6, rule 2). Every walk starts from a value this run recomputed, never from the
  one P carries (rule 4), so a graft fails where section 10.3 says.

  **LINK_WITNESS**, in an item, for each name W of `/subject/record/witness_hashes`: the
  entry equals H(0x31, `/witnesses/block/record`) when W is `block`, and H(0x20,
  `/witnesses/entropy_X`) when W is `entropy_X`.

  **LINK_HEAD**, in an item. A block record that carries `metadata.genesis` counts as height
  0 here, whatever it declares (section 10.3). A failing row's `declared` is the height the
  witness block carries, and its `recomputed` the height, so counted, of `/block`, which the
  witness block's had to be below.

  **LINK_KEY_EVENT**, when P carries `signing_key_event`: the 32 octets the event's
  `public_key` decodes to must equal K's. It fails when they differ, in every run; otherwise
  it is `pass` when the attribution is `truestamp`, and `info not_attributable` when it is not
  (section 10.3; section 10.6, rule 7). A failing row's `recomputed` is K.

  **LINK_CHAIN_ORDER** pairs each Stellar or Bitcoin entropy object with the top-level entry
  of its chain when their `network` values are equal; every other pair reports no row. A
  failing row's `recomputed` is the `ledger` or `height` it was held to.
  """

  alias Truestamp.Verify.{Base64URL, Chains, Check, Hash, Layout}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Spec.Constants
  alias Truestamp.Verify.Steps.Derive.Records

  @witness_names ["block" | Enum.map(Chains.entropy_sources(), &Layout.member/1)]

  @doc """
  The link checks, in the order above. `public_key` is the 32 octets of K, and `attribution`
  the run's (section 10.5).
  """
  @spec checks(map(), <<_::256>>, String.t()) :: [Check.t()]
  def checks(proof, public_key, attribution) do
    Enum.concat([
      inclusion(proof),
      witness(proof),
      head(proof),
      key_event(proof, public_key, attribution),
      chain_order(proof)
    ])
  end

  # LINK_INCLUSION

  defp inclusion(proof) do
    for {q, leaf_record, r} <- inclusion_proofs(proof),
        check <- inclusion(proof, q, leaf_record, r),
        do: check
  end

  # {Q, {the kind of v, the record v is the hash of}, R}, in the document order of Q.
  defp inclusion_proofs(proof) do
    subject = subject_proofs(proof)

    commitments =
      for {at, _chain, _entry} <- Layout.commitment_entries(proof) do
        block = Enum.drop(at, -2) ++ ["block", "record"]
        {at ++ ["inclusion_proof"], {:block_hash, block}, at ++ ["epoch", "record"]}
      end

    Pointer.sort_by(subject ++ commitments, &elem(&1, 0))
  end

  defp subject_proofs(%{"type" => "item"}),
    do: [
      {["subject", "inclusion_proof"], {:item_hash, ["subject", "record"]}, ["block", "record"]}
    ]

  defp subject_proofs(%{"type" => "entropy_" <> _source}),
    do: [
      {["subject", "inclusion_proof"], {:observation_hash, ["subject", "record"]},
       ["block", "record"]}
    ]

  defp subject_proofs(%{"type" => "beacon"} = proof) do
    for source <- Chains.entropy_sources(),
        at = ["observations", Layout.member(source)],
        is_map(Layout.get(proof, at)),
        do:
          {at ++ ["inclusion_proof"], {:observation_hash, at ++ ["record"]}, ["block", "record"]}
  end

  defp subject_proofs(%{"type" => "block"}), do: []

  defp inclusion(proof, q, {kind, leaf_at}, r) do
    inclusion_proof = Layout.get(proof, q)
    record = Layout.get(proof, r)
    leaf = Hash.hash_hex(kind, Layout.get(proof, leaf_at))
    root = walk(leaf, inclusion_proof)

    [
      Check.equal(r ++ ["merkle_root"], "inclusion", [q, leaf_at], record["merkle_root"], root,
        noun: :inclusion_root,
        assigns: %{inclusion_proof: Pointer.encode(q)}
      ),
      Check.equal(
        q ++ ["tree_size"],
        "inclusion",
        [r ++ ["leaf_count"]],
        inclusion_proof["tree_size"],
        record["leaf_count"],
        noun: :tree_size
      )
    ]
  end

  defp walk(leaf, %{"leaf_index" => index, "path" => path, "tree_size" => size}) do
    proof = %{leaf_index: index, path: path, tree_size: size}

    case Truestamp.Merkle.walk(leaf, proof, max_steps: Constants.max_path_steps()) do
      {:ok, root} -> root
      {:error, _refusal} -> nil
    end
  end

  # LINK_WITNESS

  defp witness(%{"type" => "item"} = proof) do
    hashes = Layout.get(proof, ["subject", "record", "witness_hashes"])

    for name <- @witness_names, Map.has_key?(hashes, name) do
      {kind, at} = witness_preimage(name)

      Check.equal(
        ["subject", "record", "witness_hashes", name],
        "witnesses",
        [at],
        hashes[name],
        Hash.hash_hex(kind, Layout.get(proof, at)),
        noun: :witness_hash
      )
    end
  end

  defp witness(_proof), do: []

  defp witness_preimage("block"), do: {:block_hash, ["witnesses", "block", "record"]}
  defp witness_preimage(name), do: {:entropy_hash, ["witnesses", name]}

  # LINK_HEAD

  defp head(%{"type" => "item"} = proof) do
    part = ["witnesses", "block", "record", "height"]
    declared = Layout.get(proof, part)
    witness = proof |> Layout.get(["witnesses", "block", "record"]) |> Records.height()
    block = proof |> Layout.get(["block", "record"]) |> Records.height()

    order =
      if witness < block,
        do: {:pass, {:head_order_holds, %{}}},
        else: {{:fail, :ordering_violation}, {:head_order_violated, %{}}}

    [ordered(part, "height", [part, ["block", "record", "height"]], declared, block, order)]
  end

  defp head(_proof), do: []

  # LINK_KEY_EVENT

  defp key_event(proof, public_key, attribution) do
    at = ["signing_key_event", "block", "record", "metadata", "key_event"]

    case Layout.get(proof, at ++ ["public_key"]) do
      nil -> []
      text -> [introduces(at ++ ["public_key"], text, public_key, attribution)]
    end
  end

  defp introduces(part, text, public_key, attribution) do
    {:ok, key} = Base64URL.decode(:b64u32, text)
    k = Base64URL.encode(public_key)

    {outcome, message} =
      cond do
        key != public_key -> {{:fail, :key_event_mismatch}, {:link_key_event_fail, %{}}}
        attribution == "truestamp" -> {:pass, {:link_key_event_pass, %{}}}
        true -> {{:info, :not_attributable}, {:link_key_event_not_attributable, %{}}}
      end

    %Check{
      part: part,
      construction: "key_event",
      inputs: [part],
      declared: text,
      recomputed: k,
      outcome: outcome,
      traced: false,
      message: message
    }
  end

  # LINK_CHAIN_ORDER: each entropy object of a commitment chain, with the top-level entry of
  # that chain on the same network; the chain's module holds the order.
  defp chain_order(proof) do
    for {at, source, object} <- Layout.entropy_objects(proof),
        chain = Chains.commitment_chain(source.name()),
        chain != nil,
        entry = Layout.get(proof, ["commitments", chain.name()]),
        is_map(entry),
        entry["network"] === object["network"],
        do: chain.chain_order(at, object, entry)
  end

  defp ordered(part, construction, inputs, declared, bound, {outcome, message}) do
    %Check{
      part: part,
      construction: construction,
      inputs: Pointer.sort_by(inputs),
      declared: declared,
      recomputed: bound,
      outcome: outcome,
      traced: false,
      message: message
    }
  end
end
