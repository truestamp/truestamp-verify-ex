# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.BitcoinTest do
  @moduledoc "The Bitcoin rules of SPEC.md section 10.4, one branch at a time."

  use ExUnit.Case, async: true

  import Truestamp.Verify.Test.Rules

  alias Truestamp.Verify.Chains.Bitcoin
  alias Truestamp.Verify.{Edge, JSON}
  alias Truestamp.Verify.Test.Verification

  {:ok, document} =
    "vectors/positive/item.proof.json" |> Verification.path() |> File.read!() |> JSON.parse()

  @proof document["proof"]
  @entry @proof["commitments"]["bitcoin"]
  @height @entry["height"]
  @header_hash @entry["header_hash"]
  @total_txs 5

  @genesis %{"header_hash" => String.duplicate("0a", 32), "height" => 0, "network" => "regtest"}

  defp tip(height), do: %{{:bitcoin_tip, %{}} => found(%{"height" => height})}
  defp at(height, answer), do: %{{:bitcoin_block_at_height, %{"height" => height}} => answer}

  defp block(fields) do
    found(
      Map.merge(
        %{
          "hash" => @header_hash,
          "median_time_past" => 1_790_387_220,
          "transaction_count" => @total_txs
        },
        fields
      )
    )
  end

  defp commitment(answers, options \\ []),
    do: Bitcoin.commitment(context(answers, options), @entry)

  defp final(extra), do: Map.merge(tip(@height + 10), extra)

  test "the vector's entry is what these tests assume" do
    assert is_integer(@height)

    assert verdict(
             commitment(final(Map.merge(at(@height, block(%{})), at(@height + 10, block(%{})))))
           ) == {:pass, nil}
  end

  describe "the tip and finality" do
    test "an entry above the tip is not yet indexed, and one within 10 of it not final" do
      assert verdict(commitment(tip(@height - 1))) == {:skip, :not_yet_indexed}
      assert verdict(commitment(tip(@height + 9))) == {:skip, :chain_not_final}
    end

    test "a tip that is unusable, not found or unread settles nothing" do
      assert verdict(commitment(%{{:bitcoin_tip, %{}} => found(%{"height" => -5})})) ==
               {:skip, :source_unreachable}

      assert verdict(commitment(%{{:bitcoin_tip, %{}} => not_found()})) ==
               {:skip, :not_held_by_source}

      assert verdict(commitment(%{})) == {:skip, :source_unreachable}
    end
  end

  describe "the best-chain block at the entry's height" do
    test "a different hash or transaction count fails with chain_mismatch" do
      outcome = commitment(final(at(@height, block(%{"hash" => String.duplicate("00", 32)}))))
      assert verdict(outcome) == {:fail, :chain_mismatch}
      assert outcome.values["differs"] == ["hash"]

      outcome = commitment(final(at(@height, block(%{"transaction_count" => 6}))))
      assert outcome.values["differs"] == ["transaction_count"]
    end

    test "a missing field, a block not held, or no answer settles nothing" do
      assert verdict(commitment(final(at(@height, found(%{"hash" => @header_hash}))))) ==
               {:skip, :source_unreachable}

      assert verdict(commitment(final(at(@height, not_found())))) == {:skip, :not_held_by_source}
      assert verdict(commitment(final(%{}))) == {:skip, :source_unreachable}
    end

    test "an entry under signing_key_event passes with no candidate read" do
      outcome = commitment(final(at(@height, block(%{}))), top_level?: false)
      assert verdict(outcome) == {:pass, nil}
      assert outcome.candidate == nil
    end

    test "is judged on the hash and transaction count alone, whatever else it lacks (10.4)" do
      fields = %{"hash" => @header_hash, "transaction_count" => @total_txs}

      for fields <- [fields, Map.put(fields, "median_time_past", "noon")] do
        outcome = commitment(final(at(@height, found(fields))), top_level?: false)
        assert verdict(outcome) == {:pass, nil}, inspect(fields)
      end
    end
  end

  describe "the candidate: the median time past at height + 10" do
    test "a top-level entry's candidate is that block's median time past" do
      outcome =
        commitment(
          final(
            Map.merge(
              at(@height, block(%{})),
              at(@height + 10, block(%{"median_time_past" => 1_790_387_820}))
            )
          )
        )

      assert %Edge{basis: "bitcoin_median_time_read", precision: :second} = outcome.candidate
      assert Edge.milliseconds(outcome.candidate) == 1_790_387_820_000
    end

    test "a candidate read that is unusable, not found or unread settles nothing" do
      base = final(at(@height, block(%{})))

      assert verdict(
               commitment(Map.merge(base, at(@height + 10, found(%{"hash" => @header_hash}))))
             ) == {:skip, :source_unreachable}

      assert verdict(commitment(Map.merge(base, at(@height + 10, not_found())))) ==
               {:skip, :not_held_by_source}

      assert verdict(commitment(base)) == {:skip, :source_unreachable}
    end

    test "a median time past past the year 9999, which no TIME can write, is unusable" do
      base = final(at(@height, block(%{})))
      last = 253_402_300_799

      assert verdict(
               commitment(
                 Map.merge(base, at(@height + 10, block(%{"median_time_past" => last + 1})))
               )
             ) == {:skip, :source_unreachable}

      outcome =
        commitment(Map.merge(base, at(@height + 10, block(%{"median_time_past" => last}))))

      assert verdict(outcome) == {:pass, nil}
      assert Edge.instant_string(outcome.candidate) == "9999-12-31T23:59:59Z"
    end
  end

  describe "genesis.bitcoin" do
    defp genesis(answers), do: Bitcoin.genesis(context(answers), @genesis)

    test "the best-chain block at its height must have its header_hash" do
      assert verdict(
               genesis(Map.merge(tip(10), at(0, found(%{"hash" => @genesis["header_hash"]}))))
             ) == {:pass, nil}

      assert verdict(
               genesis(Map.merge(tip(10), at(0, found(%{"hash" => String.duplicate("00", 32)}))))
             ) == {:fail, :chain_mismatch}

      assert verdict(genesis(Map.merge(tip(10), at(0, found(%{}))))) ==
               {:skip, :source_unreachable}

      assert verdict(genesis(Map.merge(tip(10), at(0, not_found())))) ==
               {:skip, :not_held_by_source}

      assert verdict(genesis(tip(9))) == {:skip, :chain_not_final}
    end
  end

  describe "an entropy object" do
    @object %{
      "network" => "regtest",
      "payload" => %{
        "hash" => String.duplicate("1b", 32),
        "height" => 200,
        "time" => 1_790_387_100
      },
      "source" => "bitcoin"
    }

    defp entropy(answer),
      do:
        Bitcoin.entropy(
          context(%{{:bitcoin_block, %{"hash" => @object["payload"]["hash"]}} => answer}),
          @object
        )

    test "a block that matches passes, with its median time past as the candidate" do
      outcome =
        entropy(
          found(%{"height" => 200, "median_time_past" => 1_790_386_800, "time" => 1_790_387_100})
        )

      assert verdict(outcome) == {:pass, nil}
      assert Edge.milliseconds(outcome.candidate) == 1_790_386_800_000
    end

    test "a different height or time fails; a missing median time past settles nothing" do
      assert verdict(
               entropy(
                 found(%{"height" => 201, "median_time_past" => 1, "time" => 1_790_387_100})
               )
             ) == {:fail, :entropy_mismatch}

      assert verdict(entropy(found(%{"height" => 200, "median_time_past" => 1, "time" => 1}))) ==
               {:fail, :entropy_mismatch}

      assert verdict(entropy(found(%{"height" => 200, "time" => 1_790_387_100}))) ==
               {:skip, :source_unreachable}

      assert verdict(
               entropy(
                 found(%{
                   "height" => 200,
                   "median_time_past" => 300_000_000_000,
                   "time" => 1_790_387_100
                 })
               )
             ) == {:skip, :source_unreachable}

      assert verdict(entropy(not_found())) == {:skip, :not_held_by_source}
      assert verdict(entropy(unreachable())) == {:skip, :source_unreachable}
    end
  end

  test "its identity: mainnet's genesis hash is production, any other is not" do
    mainnet = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    assert Bitcoin.identity() == {"mainnet", :bitcoin_identity}
    assert Bitcoin.production_identity?(%{"hash" => mainnet}) == {:ok, true}
    assert Bitcoin.production_identity?(%{"hash" => String.duplicate("0f", 32)}) == {:ok, false}
    assert Bitcoin.production_identity?(%{"hash" => "nope"}) == :error
  end

  test "what it declares to the engine" do
    assert Bitcoin.name() == "bitcoin"
    assert Bitcoin.networked?()
    assert Bitcoin.genesis?()
    assert Bitcoin.commitment_times() == [{["header_time"], :time}]
    assert Bitcoin.entropy_times() == []
  end

  test "LINK_CHAIN_ORDER: an entropy height at most the committed height holds" do
    at = ["witnesses", "entropy_bitcoin"]
    entry = %{"height" => 200}
    assert Bitcoin.chain_order(at, @object, entry).outcome == :pass

    assert Bitcoin.chain_order(at, @object, %{"height" => 199}).outcome ==
             {:fail, :ordering_violation}
  end
end
