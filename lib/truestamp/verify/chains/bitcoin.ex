# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.Bitcoin do
  @moduledoc """
  Bitcoin, as a commitment chain (`Truestamp.Verify.CommitmentChain`) and as an entropy
  source (`Truestamp.Verify.EntropySource`).

  ## Offline: the evidence an entry carries (SPEC.md section 10.2, step 9 (d))

  For each Bitcoin entry N, at `/commitments/bitcoin` and
  `/signing_key_event/commitments/bitcoin`, under the constructions row `bitcoin`:

  | Check | Part | Code | Traced |
  |---|---|---|---|
  | `raw_transaction` is well formed (`Truestamp.Verify.Bitcoin.Transaction`) | N`/raw_transaction` | `bitcoin_evidence_invalid` | no |
  | the 32 bytes its OP_RETURN script pushes equal the recomputed `epoch_hash` (section 5.4) | N`/raw_transaction` | `derivation_mismatch` | no |
  | rev(SHA-256d(`raw_transaction`)) = `transaction_hash` | N`/transaction_hash` | `derivation_mismatch` | yes |
  | `txoutproof` is well formed (`Truestamp.Verify.Bitcoin.MerkleBlock`) | N`/txoutproof` | `bitcoin_evidence_invalid` | no |
  | the one hash it matches equals SHA-256d(`raw_transaction`) | N`/txoutproof` | `derivation_mismatch` | no |
  | rev(SHA-256d(header)) = `header_hash` | N`/header_hash` | `derivation_mismatch` | yes |
  | rev(the header's Merkle root field) = `header_merkle_root` | N`/header_merkle_root` | `derivation_mismatch` | yes |
  | the header's nTime, formatted as TIME, = `header_time` | N`/header_time` | `derivation_mismatch` | yes |

  Apart from the two checks of well-formedness, a check that reads a value out of
  `raw_transaction` or `txoutproof` is made only when that structure is well formed: the
  `transaction_hash` row is always made, the OP_RETURN row needs a well-formed
  `raw_transaction`, and the row of the matched hash and the three header rows need a
  well-formed `txoutproof`. The OP_RETURN is compared with the `epoch_hash` this run
  recomputed from N`/epoch/record`, never with the one N carries (section 10.6, rule 4).

  LINK_CHAIN_ORDER (section 10.3): a Bitcoin entropy object's `height` is at most the
  height of the top-level Bitcoin entry on the same network. Equality is allowed, so that an
  entropy block later orphaned at the entry's height does not fail an honest proof.

  ## Online: the reads of section 10.4

  **A commitment entry**, with h its `height`:

  1. read the tip's height, t; when h > t the row is `skip not_yet_indexed`, and when
     t < h + BITCOIN_FINALITY, `skip chain_not_final`;
  2. read the best-chain block at h: its hash must equal the `header_hash` this run
     computed from the txoutproof's header, and its transaction count the txoutproof's
     `total_txs`, or the row fails with `chain_mismatch`;
  3. for a top-level entry, read the best-chain block at h + BITCOIN_FINALITY: its median
     time past is the entry's candidate for the submitted-before edge
     (`bitcoin_median_time_read`).

  **`genesis.bitcoin`**: items 1 and 2 of that rule with h its `height`, then the hash of
  the best-chain block at h must equal `genesis.bitcoin.header_hash`, or `chain_mismatch`.
  Nothing else is compared, and the read gives no edge.

  **An entropy object**: read the block whose hash is `hash`. Its `height`, and its `time`
  against the header's nTime, must equal the object's, or `entropy_mismatch`; its median time
  past is the object's candidate for the submitted-after edge. The block need not be on the
  best chain. A source that does not hold it gives `skip not_held_by_source`.

  A read that answers not found where the rule gives no outcome for that answer leaves the
  row `skip not_held_by_source`, and an unusable answer `skip source_unreachable`. Hashes
  compare as the bytes they spell.
  """

  @behaviour Truestamp.Verify.Chains.Member
  @behaviour Truestamp.Verify.CommitmentChain
  @behaviour Truestamp.Verify.EntropySource

  alias Truestamp.Verify.{Bitcoin, Check, Edge, Hash, Instant}
  alias Truestamp.Verify.Bitcoin.{MerkleBlock, Transaction}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.{Answer, Rule}
  alias Truestamp.Verify.Spec.Constants

  @construction "bitcoin"
  @finality Constants.bitcoin_finality()

  # SPEC.md 10.2, step 0: a source pinned to mainnet gives this hash for its block at
  # height 0, and a source pinned to any other network must not.
  @mainnet_genesis "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  @impl Truestamp.Verify.Chains.Member
  def name, do: "bitcoin"

  @impl Truestamp.Verify.CommitmentChain
  def commitment_times, do: [{["header_time"], :time}]

  @impl Truestamp.Verify.EntropySource
  def networked?, do: true

  @impl Truestamp.Verify.EntropySource
  def entropy_times, do: []

  @impl true
  def genesis?, do: true

  @impl true
  def identity, do: {"mainnet", :bitcoin_identity}

  @impl true
  def production_identity?(fields) do
    case Answer.field(fields, "hash", :hex64) do
      {:ok, hash} -> {:ok, hash == @mainnet_genesis}
      :error -> :error
    end
  end

  # ---------------------------------------------------------------------------------------
  # Offline: DERIVE (d)

  @impl true
  def evidence_checks(at, entry) do
    raw = Base.decode16!(entry["raw_transaction"], case: :lower)
    txid = Bitcoin.sha256d(raw)
    epoch_hash = Hash.hash_hex(:epoch_hash, entry["epoch"]["record"])
    transaction = Transaction.parse(raw)
    merkle_block = entry["txoutproof"] |> Base.decode16!(case: :lower) |> MerkleBlock.parse()

    Enum.concat([
      [well_formed(at ++ ["raw_transaction"], "raw_transaction", transaction)],
      op_return(at, transaction, epoch_hash),
      [transaction_hash(at, entry, txid)],
      [well_formed(at ++ ["txoutproof"], "txoutproof", merkle_block)],
      from_txoutproof(at, entry, merkle_block, txid)
    ])
  end

  defp well_formed(part, member, {:ok, _structure}) do
    %Check{
      part: part,
      construction: @construction,
      inputs: [part],
      declared: nil,
      outcome: :pass,
      traced: false,
      message: {:bitcoin_well_formed, %{member: member}}
    }
  end

  defp well_formed(part, member, {:error, rule}) do
    %Check{
      part: part,
      construction: @construction,
      inputs: [part],
      declared: nil,
      outcome: {:fail, :bitcoin_evidence_invalid},
      traced: false,
      values: %{"rule" => Atom.to_string(rule)},
      message:
        {:bitcoin_not_well_formed,
         %{member: member, part: Pointer.encode(part), rule: Atom.to_string(rule)}}
    }
  end

  defp op_return(at, {:ok, pushed}, epoch_hash) do
    part = at ++ ["raw_transaction"]

    [
      Check.equal(
        part,
        @construction,
        [at ++ ["epoch", "record"], part],
        Bitcoin.hex(pushed),
        epoch_hash,
        traced: false,
        noun: :op_return
      )
    ]
  end

  defp op_return(_at, {:error, _rule}, _epoch_hash), do: []

  defp transaction_hash(at, entry, txid) do
    Check.equal(
      at ++ ["transaction_hash"],
      @construction,
      [at ++ ["raw_transaction"]],
      entry["transaction_hash"],
      Bitcoin.display(txid),
      noun: :transaction_hash
    )
  end

  defp from_txoutproof(at, entry, {:ok, block}, txid) do
    header = block.header
    {:ok, time} = Instant.format(:time, Bitcoin.header_time(header))

    matched =
      Check.equal(
        at ++ ["txoutproof"],
        @construction,
        [at ++ ["raw_transaction"], at ++ ["txoutproof"]],
        Bitcoin.display(block.matched),
        Bitcoin.display(txid),
        traced: false,
        noun: :matched_hash
      )

    [
      matched,
      header(at, entry, "header_hash", Bitcoin.header_hash(header)),
      header(at, entry, "header_merkle_root", Bitcoin.header_merkle_root(header)),
      header(at, entry, "header_time", time)
    ]
  end

  defp from_txoutproof(_at, _entry, {:error, _rule}, _txid), do: []

  defp header(at, entry, member, recomputed) do
    Check.equal(at ++ [member], @construction, [at ++ ["txoutproof"]], entry[member], recomputed,
      noun: String.to_existing_atom(member)
    )
  end

  # ---------------------------------------------------------------------------------------
  # Offline: LINK_CHAIN_ORDER

  @impl true
  def chain_order(at, object, entry) do
    part = at ++ ["payload", "height"]
    height = object["payload"]["height"]
    committed = entry["height"]

    {outcome, id} =
      if height <= committed,
        do: {:pass, :bitcoin_order_holds},
        else: {{:fail, :ordering_violation}, :bitcoin_order_violated}

    %Check{
      part: part,
      construction: "chain_order",
      inputs: Pointer.sort_by([part, ["commitments", "bitcoin", "height"]]),
      declared: height,
      recomputed: committed,
      outcome: outcome,
      traced: false,
      message: {id, %{}}
    }
  end

  # ---------------------------------------------------------------------------------------
  # Online: CHAIN

  @impl true
  def commitment(context, entry) do
    height = entry["height"]
    {:ok, block} = entry["txoutproof"] |> Base.decode16!(case: :lower) |> MerkleBlock.parse()
    header_hash = Bitcoin.header_hash(block.header)

    with {:final, context} <- final(context, height),
         {:ok, context} <- block_at(context, height, header_hash, block.total_txs) do
      if context.top_level?, do: candidate(context, height), else: Rule.pass(context)
    end
  end

  @impl true
  def genesis(context, object) do
    height = object["height"]

    with {:final, context} <- final(context, height) do
      {answer, context} = Rule.read(context, :bitcoin_block_at_height, %{"height" => height})
      genesis_block(context, answer, object["header_hash"])
    end
  end

  # Only the hash of the best-chain block at the genesis object's height is compared.
  defp genesis_block(context, {:found, fields, _meta}, header_hash) do
    case fields |> Answer.field("hash", :hex64) |> Rule.compare(header_hash) do
      :ok -> Rule.pass(context)
      :contradiction -> Rule.fail(context, :chain_mismatch, %{"differs" => ["hash"]})
      :unusable -> Rule.skip(context, :source_unreachable, %{"unusable" => ["hash"]})
    end
  end

  defp genesis_block(context, answer, _header_hash), do: settles_nothing(context, answer)

  # Items 1 and 2: the tip, and finality.
  defp final(context, height) do
    {answer, context} = Rule.read(context, :bitcoin_tip, %{})

    case answer do
      {:found, fields, _meta} ->
        case Answer.field(fields, "height", :int) do
          {:ok, tip} when height > tip ->
            Rule.skip(context, :not_yet_indexed, %{"height" => height, "tip" => tip})

          {:ok, tip} when tip < height + @finality ->
            Rule.skip(context, :chain_not_final, %{"height" => height, "tip" => tip})

          {:ok, _tip} ->
            {:final, context}

          :error ->
            Rule.skip(context, :source_unreachable, %{"unusable" => ["height"]})
        end

      # A tip is never not found (section 13.2); a source that says so leaves the row as
      # section 10.4 leaves any not-found answer its rules give no outcome for.
      other ->
        settles_nothing(context, other)
    end
  end

  # Item 2: the best-chain block at the entry's height.
  defp block_at(context, height, header_hash, total_txs) do
    {answer, context} = Rule.read(context, :bitcoin_block_at_height, %{"height" => height})

    case answer do
      {:found, fields, _meta} ->
        checks = [
          {"hash", Answer.field(fields, "hash", :hex64) |> Rule.compare(header_hash)},
          {"transaction_count",
           Answer.field(fields, "transaction_count", :int) |> Rule.compare(total_txs)}
        ]

        case Rule.decide(checks) do
          :ok -> {:ok, context}
          {:contradiction, names} -> Rule.fail(context, :chain_mismatch, %{"differs" => names})
          {:unusable, names} -> Rule.skip(context, :source_unreachable, %{"unusable" => names})
        end

      other ->
        settles_nothing(context, other)
    end
  end

  # Item 4: the candidate, the median time past of the block at height + BITCOIN_FINALITY.
  defp candidate(context, height) do
    {answer, context} =
      Rule.read(context, :bitcoin_block_at_height, %{"height" => height + @finality})

    case answer do
      {:found, fields, meta} ->
        case Answer.field(fields, "median_time_past", :int) do
          {:ok, seconds} -> Rule.pass(context, edge(seconds, :before, context.part, meta))
          :error -> Rule.skip(context, :source_unreachable, %{"unusable" => ["median_time_past"]})
        end

      other ->
        settles_nothing(context, other)
    end
  end

  # ---------------------------------------------------------------------------------------
  # Online: SOURCES

  @impl Truestamp.Verify.EntropySource
  def entropy(context, object) do
    payload = object["payload"]
    {answer, context} = Rule.read(context, :bitcoin_block, %{"hash" => payload["hash"]})

    case answer do
      {:found, fields, meta} ->
        checks = [
          {"height", Answer.field(fields, "height", :int) |> Rule.compare(payload["height"])},
          {"time", Answer.field(fields, "time", :int) |> Rule.compare(payload["time"])},
          {"median_time_past", Answer.field(fields, "median_time_past", :int) |> present()}
        ]

        case Rule.decide(checks) do
          :ok ->
            {:ok, seconds} = Answer.field(fields, "median_time_past", :int)
            Rule.pass(context, edge(seconds, :after, context.part, meta))

          {:contradiction, names} ->
            Rule.fail(context, :entropy_mismatch, %{"differs" => names})

          {:unusable, names} ->
            Rule.skip(context, :source_unreachable, %{"unusable" => names})
        end

      other ->
        settles_nothing(context, other)
    end
  end

  defp present({:ok, _value}), do: :ok
  defp present(:error), do: :unusable

  # A not-found answer where the rule gives no outcome for it, or an unreachable read.
  defp settles_nothing(context, {:not_found, _meta}), do: Rule.skip(context, :not_held_by_source)

  defp settles_nothing(context, {:unreachable, _reason}),
    do: Rule.skip(context, :source_unreachable)

  defp edge(seconds, side, part, meta) do
    %Edge{
      instant: DateTime.from_unix!(seconds),
      precision: :second,
      basis: "bitcoin_median_time_read",
      assumption: Edge.assumption("bitcoin_median_time_read", side),
      part: part,
      source: meta.source,
      cached: meta.cached,
      fetched_at: meta.fetched_at
    }
  end
end
