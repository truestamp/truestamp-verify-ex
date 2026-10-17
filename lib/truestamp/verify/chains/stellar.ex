# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.Stellar do
  @moduledoc """
  Stellar, as a commitment chain (`Truestamp.Verify.CommitmentChain`) and as an entropy
  source (`Truestamp.Verify.EntropySource`).

  ## Offline

  A Stellar entry carries no evidence that DERIVE can check offline: its memo is unknown
  until it is read (section 5.4). LINK_CHAIN_ORDER (section 10.3): a Stellar entropy
  object's `sequence` is below the `ledger` of the top-level Stellar entry on the same
  network.

  ## Online: the reads of section 10.4

  **A commitment entry**, with L its `ledger`:

  1. read the transaction whose hash is `transaction_hash`;
  2. found: `successful` is true, `memo_type` is `hash`, the memo is the 32 bytes of
     H(0x40, `epoch.record`) as this run computed it, and the transaction is in ledger L, or
     the row fails with `chain_mismatch`. For a top-level entry, then read ledger L: its
     `closed_at` is the entry's candidate for the submitted-before edge
     (`stellar_ledger_close_read`);
  3. not found: read the source's root, for `latest` and `elder`. When
     L > latest - STELLAR_INDEX_MARGIN the row is `skip not_yet_indexed`; when L < elder,
     `skip not_held_by_source`, its values naming elder; otherwise read ledger L: not found
     is `skip not_held_by_source`, its values naming L, and found fails with
     `chain_mismatch`, since the source holds the ledger and it lacks the transaction.

  **An entropy object**: read the ledger whose sequence is `sequence`. Its `hash` and
  `closed_at` must equal the object's, or `entropy_mismatch`; its `closed_at` is the object's
  candidate for the submitted-after edge. Not found is `skip not_yet_indexed` when
  `sequence` > latest - STELLAR_INDEX_MARGIN, with latest from a live read of the root, and
  otherwise `skip not_held_by_source`.

  Hashes compare as the bytes they spell, and times as instants (section 10.4).
  """

  @behaviour Truestamp.Verify.Chains.Member
  @behaviour Truestamp.Verify.CommitmentChain
  @behaviour Truestamp.Verify.EntropySource

  alias Truestamp.Verify.{Check, Edge, Hash}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.{Answer, Rule}
  alias Truestamp.Verify.Spec.Constants

  @margin Constants.stellar_index_margin()

  # SPEC.md 10.2, step 0: a source pinned to public gives this passphrase, and a source
  # pinned to any other network must not.
  @public_passphrase "Public Global Stellar Network ; September 2015"

  @memo_types ~w(none text id hash return)

  @impl Truestamp.Verify.Chains.Member
  def name, do: "stellar"

  @impl Truestamp.Verify.CommitmentChain
  def commitment_times, do: []

  @impl Truestamp.Verify.EntropySource
  def networked?, do: true

  @impl Truestamp.Verify.EntropySource
  def entropy_times, do: [{["payload", "closed_at"], :time}]

  @impl true
  def genesis?, do: false

  @impl true
  def identity, do: {"public", :stellar_identity}

  @impl true
  def production_identity?(fields) do
    case Answer.field(fields, "network_passphrase", :ascii128) do
      {:ok, passphrase} -> {:ok, passphrase == @public_passphrase}
      :error -> :error
    end
  end

  @impl true
  def evidence_checks(_at, _entry), do: []

  @impl true
  def chain_order(at, object, entry) do
    part = at ++ ["payload", "sequence"]
    sequence = object["payload"]["sequence"]
    ledger = entry["ledger"]

    {outcome, id} =
      if sequence < ledger,
        do: {:pass, :stellar_order_holds},
        else: {{:fail, :ordering_violation}, :stellar_order_violated}

    %Check{
      part: part,
      construction: "chain_order",
      inputs: Pointer.sort_by([part, ["commitments", "stellar", "ledger"]]),
      declared: sequence,
      recomputed: ledger,
      outcome: outcome,
      traced: false,
      message: {id, %{}}
    }
  end

  # ---------------------------------------------------------------------------------------
  # Online: CHAIN

  @impl true
  def commitment(context, entry) do
    ledger = entry["ledger"]
    memo = Hash.hash_hex(:epoch_hash, entry["epoch"]["record"])

    {answer, context} =
      Rule.read(context, :stellar_transaction, %{"hash" => entry["transaction_hash"]})

    case answer do
      {:found, fields, _meta} -> transaction(context, fields, memo, ledger)
      {:not_found, _meta} -> missing_transaction(context, ledger)
      {:unreachable, _reason} -> Rule.skip(context, :source_unreachable)
    end
  end

  defp transaction(context, fields, memo, ledger) do
    memo_type = Answer.field(fields, "memo_type", {:enum, @memo_types})

    checks = [
      {"successful", Answer.field(fields, "successful", :boolean) |> Rule.compare(true)},
      {"memo_type", memo_type |> Rule.compare("hash")},
      {"memo", memo_check(fields, memo_type, memo)},
      {"ledger", Answer.field(fields, "ledger", :int) |> Rule.compare(ledger)}
    ]

    case Rule.decide(checks) do
      :ok when context.top_level? -> candidate(context, ledger)
      :ok -> Rule.pass(context)
      {:contradiction, names} -> Rule.fail(context, :chain_mismatch, %{"differs" => names})
      {:unusable, names} -> Rule.skip(context, :source_unreachable, %{"unusable" => names})
    end
  end

  # The memo is present only when memo_type is hash or return. A memo present is compared;
  # an absent one is needed only when memo_type is hash or cannot be read, since any other
  # memo_type already contradicts the proof.
  defp memo_check(fields, memo_type, memo) do
    case {Answer.field(fields, "memo", :hex64), memo_type} do
      {{:ok, _value} = field, _memo_type} -> Rule.compare(field, memo)
      {:error, {:ok, type}} when type not in ["hash", "return"] -> :ok
      {:error, _memo_type} -> :unusable
    end
  end

  defp candidate(context, ledger) do
    {answer, context} = Rule.read(context, :stellar_ledger, %{"sequence" => ledger})

    case answer do
      {:found, fields, meta} ->
        case Answer.field(fields, "closed_at", :time) do
          {:ok, ms} -> Rule.pass(context, edge(ms, :before, context.part, meta))
          :error -> Rule.skip(context, :source_unreachable, %{"unusable" => ["closed_at"]})
        end

      {:not_found, _meta} ->
        Rule.skip(context, :not_held_by_source, %{"ledger" => ledger})

      {:unreachable, _reason} ->
        Rule.skip(context, :source_unreachable)
    end
  end

  defp missing_transaction(context, ledger) do
    with {:root, latest, elder, context} <- root(context) do
      cond do
        ledger > latest - @margin ->
          Rule.skip(context, :not_yet_indexed, %{"latest" => latest, "ledger" => ledger})

        ledger < elder ->
          Rule.skip(context, :not_held_by_source, %{"elder" => elder})

        true ->
          held_ledger(context, ledger)
      end
    end
  end

  # The source holds ledger L's history: a ledger it holds without the transaction is a
  # contradiction, and one it does not hold is absence.
  defp held_ledger(context, ledger) do
    {answer, context} = Rule.read(context, :stellar_ledger, %{"sequence" => ledger})

    case answer do
      {:found, _fields, _meta} -> Rule.fail(context, :chain_mismatch, %{"ledger" => ledger})
      {:not_found, _meta} -> Rule.skip(context, :not_held_by_source, %{"ledger" => ledger})
      {:unreachable, _reason} -> Rule.skip(context, :source_unreachable)
    end
  end

  # The source's root, always read live (section 10.4); never not found (section 13.2).
  defp latest(context) do
    {answer, context} = Rule.read(context, :stellar_root, %{})

    with {:found, fields, _meta} <- answer,
         {:ok, latest} <- Answer.field(fields, "latest", :int) do
      {:root, latest, context}
    else
      other -> unsettled_root(context, other)
    end
  end

  defp root(context) do
    {answer, context} = Rule.read(context, :stellar_root, %{})

    with {:found, fields, _meta} <- answer,
         {:ok, latest} <- Answer.field(fields, "latest", :int),
         {:ok, elder} <- Answer.field(fields, "elder", :int) do
      {:root, latest, elder, context}
    else
      other -> unsettled_root(context, other)
    end
  end

  # A root is never not found (section 13.2); a source that says so leaves the row as section
  # 10.4 leaves any not-found answer its rules give no outcome for. Any other answer, or a
  # field it lacks, is no usable answer.
  defp unsettled_root(context, {:not_found, _meta}), do: Rule.skip(context, :not_held_by_source)
  defp unsettled_root(context, _unusable), do: Rule.skip(context, :source_unreachable)

  # ---------------------------------------------------------------------------------------
  # Online: SOURCES

  @impl Truestamp.Verify.EntropySource
  def entropy(context, object) do
    %{"sequence" => sequence, "hash" => hash} = object["payload"]
    {answer, context} = Rule.read(context, :stellar_ledger, %{"sequence" => sequence})

    case answer do
      {:found, fields, meta} ->
        {:ok, declared_ms} = Answer.field(object["payload"], "closed_at", :time)
        read_closed_at = Answer.field(fields, "closed_at", :time)

        checks = [
          {"hash", Answer.field(fields, "hash", :hex64) |> Rule.compare(hash)},
          {"closed_at", Rule.compare(read_closed_at, declared_ms)}
        ]

        case Rule.decide(checks) do
          :ok ->
            {:ok, read_ms} = read_closed_at
            Rule.pass(context, edge(read_ms, :after, context.part, meta))

          {:contradiction, names} ->
            Rule.fail(context, :entropy_mismatch, %{"differs" => names})

          {:unusable, names} ->
            Rule.skip(context, :source_unreachable, %{"unusable" => names})
        end

      {:not_found, _meta} ->
        missing_ledger(context, sequence)

      {:unreachable, _reason} ->
        Rule.skip(context, :source_unreachable)
    end
  end

  defp missing_ledger(context, sequence) do
    with {:root, latest, context} <- latest(context) do
      if sequence > latest - @margin,
        do: Rule.skip(context, :not_yet_indexed, %{"latest" => latest, "sequence" => sequence}),
        else: Rule.skip(context, :not_held_by_source, %{"sequence" => sequence})
    end
  end

  defp edge(ms, side, part, meta) do
    %Edge{
      instant: DateTime.from_unix!(div(ms, 1000)),
      precision: :second,
      basis: "stellar_ledger_close_read",
      assumption: Edge.assumption("stellar_ledger_close_read", side),
      part: part,
      source: meta.source,
      cached: meta.cached,
      fetched_at: meta.fetched_at
    }
  end
end
