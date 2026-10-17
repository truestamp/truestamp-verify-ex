# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.StellarTest do
  @moduledoc "The Stellar rules of SPEC.md section 10.4, one branch at a time."

  use ExUnit.Case, async: true

  import Truestamp.Verify.Test.Rules

  alias Truestamp.Verify.Chains.Stellar
  alias Truestamp.Verify.{Edge, Hash}

  @record %{"leaf_count" => 1, "merkle_root" => String.duplicate("ab", 32)}
  @memo Hash.hash_hex(:epoch_hash, @record)
  @tx String.duplicate("cd", 32)
  @entry %{
    "epoch" => %{"record" => @record},
    "ledger" => 1000,
    "network" => "testnet",
    "transaction_hash" => @tx
  }
  @transaction %{"ledger" => 1000, "memo" => @memo, "memo_type" => "hash", "successful" => true}
  @ledger %{"closed_at" => "2026-09-26T01:48:30Z", "hash" => String.duplicate("ef", 32)}

  defp commitment(answers, options \\ []),
    do: Stellar.commitment(context(answers, options), @entry)

  defp tx(fields), do: %{{:stellar_transaction, %{"hash" => @tx}} => found(fields)}
  defp ledger(answer), do: %{{:stellar_ledger, %{"sequence" => 1000}} => answer}
  defp root(fields), do: %{{:stellar_root, %{}} => found(fields)}

  describe "a commitment entry whose transaction is found" do
    test "a top-level entry passes with the ledger's close time as its candidate" do
      outcome = commitment(Map.merge(tx(@transaction), ledger(found(@ledger))))
      assert verdict(outcome) == {:pass, nil}
      assert %Edge{basis: "stellar_ledger_close_read", precision: :second} = outcome.candidate
      assert Edge.instant_string(outcome.candidate) == "2026-09-26T01:48:30Z"

      assert [%{"kind" => "stellar_transaction"}, %{"kind" => "stellar_ledger"}] =
               outcome.values["reads"]

      assert outcome.values["candidate"]["basis"] == "stellar_ledger_close_read"
    end

    test "an entry under signing_key_event passes on the transaction alone, with no candidate" do
      outcome = commitment(tx(@transaction), top_level?: false)
      assert verdict(outcome) == {:pass, nil}
      assert outcome.candidate == nil
    end

    test "the candidate read settles nothing when the ledger is missing, unusable or unread" do
      assert verdict(commitment(Map.merge(tx(@transaction), ledger(not_found())))) ==
               {:skip, :not_held_by_source}

      assert verdict(commitment(Map.merge(tx(@transaction), ledger(unreachable())))) ==
               {:skip, :source_unreachable}

      bad = found(%{"closed_at" => "2026-02-30T00:00:00Z", "hash" => @ledger["hash"]})

      assert verdict(commitment(Map.merge(tx(@transaction), ledger(bad)))) ==
               {:skip, :source_unreachable}
    end

    test "each contradiction fails the row with chain_mismatch, naming the field" do
      for {field, value} <- [
            {"successful", false},
            {"memo_type", "text"},
            {"memo", String.duplicate("00", 32)},
            {"ledger", 999}
          ] do
        fields = Map.put(@transaction, field, value)
        fields = if field == "memo_type", do: Map.delete(fields, "memo"), else: fields
        outcome = commitment(tx(fields))
        assert verdict(outcome) == {:fail, :chain_mismatch}, field
        assert field in outcome.values["differs"]
      end
    end

    test "a contradiction fails the row even when another field is unusable" do
      outcome = commitment(tx(%{@transaction | "successful" => "yes", "ledger" => 7}))
      assert verdict(outcome) == {:fail, :chain_mismatch}
      assert outcome.values["differs"] == ["ledger"]
    end

    test "a field missing or in another class leaves the row unreachable" do
      for fields <- [
            Map.delete(@transaction, "successful"),
            Map.delete(@transaction, "memo"),
            %{@transaction | "memo_type" => "other"} |> Map.delete("memo"),
            %{@transaction | "ledger" => -1}
          ] do
        assert verdict(commitment(tx(fields))) == {:skip, :source_unreachable}
      end
    end

    test "a return memo is compared like a hash memo, and fails on its memo_type" do
      assert verdict(commitment(tx(%{@transaction | "memo_type" => "return"}))) ==
               {:fail, :chain_mismatch}
    end
  end

  describe "a commitment entry whose transaction is not found" do
    defp missing(extra),
      do: Map.merge(%{{:stellar_transaction, %{"hash" => @tx}} => not_found()}, extra)

    test "within STELLAR_INDEX_MARGIN of the source's latest ledger, it is not yet indexed" do
      outcome = commitment(missing(root(%{"elder" => 1, "latest" => 1059})))
      assert verdict(outcome) == {:skip, :not_yet_indexed}
    end

    test "below the source's elder ledger, the source does not hold it" do
      outcome = commitment(missing(root(%{"elder" => 1001, "latest" => 5000})))
      assert verdict(outcome) == {:skip, :not_held_by_source}
      assert outcome.values["elder"] == 1001
    end

    test "a ledger the source holds without the transaction fails; one it lacks is absence" do
      held = root(%{"elder" => 1, "latest" => 5000})

      assert verdict(commitment(missing(Map.merge(held, ledger(found(@ledger)))))) ==
               {:fail, :chain_mismatch}

      assert verdict(commitment(missing(Map.merge(held, ledger(not_found()))))) ==
               {:skip, :not_held_by_source}

      assert verdict(commitment(missing(Map.merge(held, ledger(unreachable()))))) ==
               {:skip, :source_unreachable}
    end

    test "the boundaries: L = latest - 60 and L = elder are held" do
      held = Map.merge(root(%{"elder" => 1000, "latest" => 1060}), ledger(not_found()))
      assert verdict(commitment(missing(held))) == {:skip, :not_held_by_source}
      assert commitment(missing(held)).values["ledger"] == 1000
    end

    test "a root that is not found, unusable or unread settles nothing" do
      assert verdict(commitment(missing(%{{:stellar_root, %{}} => not_found()}))) ==
               {:skip, :not_held_by_source}

      assert verdict(commitment(missing(root(%{"latest" => 5000})))) ==
               {:skip, :source_unreachable}

      assert verdict(commitment(missing(%{}))) == {:skip, :source_unreachable}
    end
  end

  test "an unreachable transaction read settles nothing" do
    assert verdict(commitment(%{})) == {:skip, :source_unreachable}
  end

  describe "an entropy object" do
    @object %{
      "network" => "testnet",
      "payload" => %{
        "closed_at" => "2026-09-26T01:48:30Z",
        "hash" => @ledger["hash"],
        "sequence" => 1000
      },
      "source" => "stellar"
    }

    defp entropy(answers), do: Stellar.entropy(context(answers), @object)

    test "a ledger that matches passes, with its close time as the candidate" do
      outcome = entropy(ledger(found(@ledger)))
      assert verdict(outcome) == {:pass, nil}
      assert outcome.candidate.basis == "stellar_ledger_close_read"
    end

    test "a ledger whose hash or close time differs fails with entropy_mismatch" do
      assert verdict(entropy(ledger(found(%{@ledger | "hash" => String.duplicate("00", 32)})))) ==
               {:fail, :entropy_mismatch}

      assert verdict(entropy(ledger(found(%{@ledger | "closed_at" => "2026-09-26T01:48:31Z"})))) ==
               {:fail, :entropy_mismatch}
    end

    test "a ledger with an unusable field, or no answer, settles nothing" do
      assert verdict(entropy(ledger(found(%{@ledger | "hash" => "nope"})))) ==
               {:skip, :source_unreachable}

      assert verdict(entropy(ledger(unreachable()))) == {:skip, :source_unreachable}
    end

    test "a ledger not found is not yet indexed within the margin, else not held" do
      missing = ledger(not_found())

      assert verdict(entropy(Map.merge(missing, root(%{"latest" => 1059})))) ==
               {:skip, :not_yet_indexed}

      assert verdict(entropy(Map.merge(missing, root(%{"latest" => 1060})))) ==
               {:skip, :not_held_by_source}

      assert verdict(entropy(missing)) == {:skip, :source_unreachable}
    end
  end

  test "its identity: the public passphrase is production, any other is not" do
    assert Stellar.identity() == {"public", :stellar_identity}

    assert Stellar.production_identity?(%{
             "network_passphrase" => "Public Global Stellar Network ; September 2015"
           }) == {:ok, true}

    assert Stellar.production_identity?(%{
             "network_passphrase" => "Test SDF Network ; September 2015"
           }) == {:ok, false}

    assert Stellar.production_identity?(%{"network_passphrase" => 42}) == :error
  end

  test "what it declares to the engine" do
    assert Stellar.name() == "stellar"
    assert Stellar.networked?()
    refute Stellar.genesis?()
    assert Stellar.commitment_times() == []
    assert Stellar.entropy_times() == [{["payload", "closed_at"], :time}]
    assert Stellar.evidence_checks(["commitments", "stellar"], @entry) == []
  end

  test "LINK_CHAIN_ORDER: a sequence below the ledger holds, any other is an ordering violation" do
    at = ["witnesses", "entropy_stellar"]
    earlier = put_in(@object, ["payload", "sequence"], 999)
    assert Stellar.chain_order(at, earlier, @entry).outcome == :pass
    assert Stellar.chain_order(at, @object, @entry).outcome == {:fail, :ordering_violation}
  end
end
