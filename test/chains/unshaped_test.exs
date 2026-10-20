# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.UnshapedTest do
  @moduledoc """
  The public rules of every chain and source, called directly on a value SHAPE would refuse
  (`Truestamp.Verify.Online.Rule`, "A value SHAPE would refuse"): none raises. DERIVE's
  Bitcoin evidence checks fail the well-formedness check of the member they cannot read and
  make no check that reads it, and fail the OP_RETURN check of an entry with no epoch
  record; the online rules make no read and fail with `shape_invalid`, naming each member
  missing or out of its class; Bitcoin's online rule fails a hex `txoutproof` that is not
  well formed with `bitcoin_evidence_invalid`; LINK_CHAIN_ORDER fails on a height, sequence
  or ledger that is not an INT. A whole run never gives one of these
  outcomes, since SHAPE refuses the value first; the conformance cases hold that.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import Truestamp.Verify.Test.Rules

  alias Truestamp.Verify.Chains.{Bitcoin, Nist, Stellar}
  alias Truestamp.Verify.{Check, JSON, Messages}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.Answer
  alias Truestamp.Verify.Test.Verification

  {:ok, document} =
    "vectors/positive/item.proof.json" |> Verification.path() |> File.read!() |> JSON.parse()

  @proof document["proof"]
  @bitcoin @proof["commitments"]["bitcoin"]
  @stellar @proof["commitments"]["stellar"]
  @at ["commitments", "bitcoin"]

  @genesis %{"header_hash" => String.duplicate("0a", 32), "height" => 0, "network" => "regtest"}
  @bitcoin_entropy %{
    "network" => "regtest",
    "payload" => %{"hash" => String.duplicate("1b", 32), "height" => 200, "time" => 1_790_387_100},
    "source" => "bitcoin"
  }
  @stellar_entropy %{
    "network" => "testnet",
    "payload" => %{
      "closed_at" => "2026-09-26T01:48:30Z",
      "hash" => String.duplicate("ef", 32),
      "sequence" => 990
    },
    "source" => "stellar"
  }
  @nist_entropy %{
    "payload" => %{
      "pulse" => %{
        "chainIndex" => 2,
        "outputValue" => String.duplicate("AB", 64),
        "pulseIndex" => 7,
        "timeStamp" => "2026-09-26T01:48:00.000Z",
        "version" => "2.0"
      }
    },
    "source" => "nist"
  }

  @hexbytes ~r/\A(?:[0-9a-f]{2})+\z/

  # The rules a transaction or a merkleblock that parses from hex can break.
  @structure_rules ~w(parse length op_return total_txs partial_tree duplicate_pair matches
                      merkle_root target)

  # ---------------------------------------------------------------------------------------
  # Generators

  # A value that is not lowercase hex of whole octets, or hex whose octets are no
  # well-formed structure: a strict prefix of `hex`, in characters, so possibly of odd
  # length; fewer than 80 random octets, which hold no merkleblock's header; the same in
  # uppercase; text that is not hex; or no string at all.
  defp unshaped_hex(hex) do
    StreamData.one_of([
      StreamData.integer(0..(byte_size(hex) - 1)) |> StreamData.map(&binary_part(hex, 0, &1)),
      StreamData.binary(max_length: 79) |> StreamData.map(&Base.encode16(&1, case: :lower)),
      StreamData.binary(min_length: 1, max_length: 79)
      |> StreamData.map(&Base.encode16(&1, case: :upper)),
      StreamData.string(:printable, min_length: 1) |> StreamData.filter(&(not (&1 =~ @hexbytes))),
      StreamData.one_of([StreamData.integer(), StreamData.constant(nil), StreamData.boolean()])
    ])
  end

  # A JSON value of any class, or none at all (`:absent`).
  defp json_value do
    StreamData.one_of([
      StreamData.constant(:absent),
      StreamData.constant(nil),
      StreamData.integer(),
      StreamData.boolean(),
      StreamData.string(:printable, max_length: 8),
      StreamData.list_of(StreamData.integer(), max_length: 2),
      StreamData.map_of(StreamData.string(:alphanumeric, max_length: 3), StreamData.integer(),
        max_length: 2
      )
    ])
  end

  # `value` with the member at `path` replaced by `member`, or removed for `:absent`; a map
  # missing on the way is created.
  defp put(value, [name], :absent), do: Map.delete(value, name)
  defp put(value, [name], member), do: Map.put(value, name, member)

  defp put(value, [name | rest], member),
    do: Map.put(value, name, put(Map.get(value, name, %{}), rest, member))

  # Whether `member` is in `class`, as the schema has it.
  defp in_class?(:absent, _class), do: false
  defp in_class?(member, :object), do: is_map(member)
  defp in_class?(member, :hexbytes), do: is_binary(member) and member =~ @hexbytes

  defp in_class?(member, class),
    do: match?({:ok, _value}, Answer.field(%{"m" => member}, "m", class))

  # ---------------------------------------------------------------------------------------
  # Bitcoin's evidence checks (DERIVE)

  defp parts(checks), do: Enum.map(checks, & &1.part)

  defp at_member(checks, member), do: Enum.filter(checks, &(&1.part == @at ++ [member]))

  property "a raw_transaction or txoutproof that is not hex, or truncated, fails its own check" do
    check all(
            member <- StreamData.member_of(["raw_transaction", "txoutproof"]),
            bad <- unshaped_hex(@bitcoin[member])
          ) do
      checks = Bitcoin.evidence_checks(@at, Map.put(@bitcoin, member, bad))

      assert [%Check{outcome: {:fail, :bitcoin_evidence_invalid}} = failed] =
               at_member(checks, member)

      if is_binary(bad) and bad =~ @hexbytes,
        do: assert(failed.values["rule"] in @structure_rules),
        else: assert(failed.values["rule"] == "hex")

      # Every check writes its row.
      for check <- checks, do: assert(%{} = Check.row(check, Messages.English))

      case member do
        "raw_transaction" ->
          # No OP_RETURN is read out of it. Hex is still hashed, so the transaction_hash and
          # the matched hash are compared; text that is not hex is not, and neither is made.
          # The header rows are made either way.
          hashed? = is_binary(bad) and bad =~ @hexbytes
          assert hashed? == (@at ++ ["transaction_hash"]) in parts(checks)
          assert length(at_member(checks, "txoutproof")) == if(hashed?, do: 2, else: 1)
          assert (@at ++ ["header_hash"]) in parts(checks)

        "txoutproof" ->
          assert [_well_formed] = at_member(checks, "txoutproof")

          for header <- ~w(header_hash header_merkle_root header_time),
              do: refute((@at ++ [header]) in parts(checks))

          assert [%Check{outcome: :pass}] = at_member(checks, "transaction_hash")
      end
    end
  end

  test "the vector's entry gives every evidence check, each passing" do
    checks = Bitcoin.evidence_checks(@at, @bitcoin)
    assert length(checks) == 8
    assert Enum.all?(checks, &(&1.outcome == :pass))
  end

  # Kills the mutant that makes no OP_RETURN check for an entry with no epoch record (the
  # clause `op_return(_at, {:ok, _pushed}, :error)` giving no check), which leaves every check
  # passing.
  test "no epoch record fails the OP_RETURN check; for any other term, no check passes" do
    for entry <- [
          Map.delete(@bitcoin, "epoch"),
          Map.put(@bitcoin, "epoch", "x"),
          Map.put(@bitcoin, "epoch", %{}),
          put(@bitcoin, ["epoch", "record"], nil),
          put(@bitcoin, ["epoch", "record"], "x"),
          put(@bitcoin, ["epoch", "record"], [1]),
          put(@bitcoin, ["epoch", "record"], ~U[2026-01-01 00:00:00Z])
        ] do
      checks = Bitcoin.evidence_checks(@at, entry)
      assert length(checks) == 8

      assert [%Check{outcome: :pass}, op_return] = at_member(checks, "raw_transaction")
      assert op_return.outcome == {:fail, :bitcoin_evidence_invalid}
      assert op_return.values == %{"member" => "epoch/record"}
      assert op_return.inputs == [@at ++ ["epoch", "record"], @at ++ ["raw_transaction"]]

      assert %{code: :bitcoin_evidence_invalid, message_id: :bitcoin_no_epoch_record} =
               row = Check.row(op_return, Messages.English)

      assert row.values == %{"construction" => "bitcoin", "member" => "epoch/record"}
      assert row.part == "/commitments/bitcoin/raw_transaction"
      assert Enum.all?(checks -- [op_return], &(&1.outcome == :pass))
    end

    for entry <- [nil, "x", [1], 5, %{}] do
      checks = Bitcoin.evidence_checks(@at, entry)

      assert [{:fail, :bitcoin_evidence_invalid}, {:fail, :bitcoin_evidence_invalid}] ==
               Enum.map(checks, & &1.outcome)
    end
  end

  # ---------------------------------------------------------------------------------------
  # The online rules

  # Each rule, the sound value it is given, and the members it reads, in the order its
  # outcome names them.
  defp rules do
    [
      {"Bitcoin commitment", &Bitcoin.commitment/2, @bitcoin,
       [{["height"], :int}, {["txoutproof"], :hexbytes}]},
      {"Bitcoin genesis", &Bitcoin.genesis/2, @genesis,
       [{["header_hash"], :hex64}, {["height"], :int}]},
      {"Bitcoin entropy", &Bitcoin.entropy/2, @bitcoin_entropy,
       [{["payload", "hash"], :hex64}, {["payload", "height"], :int}, {["payload", "time"], :int}]},
      {"Stellar commitment", &Stellar.commitment/2, @stellar,
       [{["epoch", "record"], :object}, {["ledger"], :int}, {["transaction_hash"], :hex64}]},
      {"Stellar entropy", &Stellar.entropy/2, @stellar_entropy,
       [
         {["payload", "closed_at"], :time},
         {["payload", "hash"], :hex64},
         {["payload", "sequence"], :int}
       ]},
      {"NIST entropy", &Nist.entropy/2, @nist_entropy,
       [
         {["payload", "pulse", "chainIndex"], :int},
         {["payload", "pulse", "outputValue"], :nisthex},
         {["payload", "pulse", "pulseIndex"], :int},
         {["payload", "pulse", "timeStamp"], :nisttime}
       ]}
    ]
  end

  test "each rule reads, and settles, its sound value" do
    for {name, rule, value, _members} <- rules() do
      outcome = rule.(context(%{}), value)
      assert outcome.code != :shape_invalid, name
      assert outcome.values["reads"] != [], name
    end
  end

  property "a member missing or out of its class: no read, and shape_invalid naming it" do
    check all(
            {name, rule, value, members} <- StreamData.member_of(rules()),
            replaced <- StreamData.list_of(json_value(), length: length(members)),
            mask <- StreamData.list_of(StreamData.boolean(), length: length(members)),
            Enum.any?(mask)
          ) do
      chosen =
        for {{member, replacement}, true} <- Enum.zip(Enum.zip(members, replaced), mask),
            do: {member, replacement}

      unshaped =
        for {{_path, class} = member, replacement} <- chosen,
            not in_class?(replacement, class),
            do: member

      value =
        Enum.reduce(chosen, value, fn {{path, _class}, member}, value ->
          put(value, path, member)
        end)

      if unshaped != [] do
        outcome = rule.(context(%{}), value)
        assert {outcome.status, outcome.code} == {:fail, :shape_invalid}, name

        assert outcome.values == %{
                 "reads" => [],
                 "unshaped" => Enum.map(unshaped, &Pointer.encode(elem(&1, 0)))
               }
      end
    end
  end

  # Kills the mutant whose `:object` class takes a list, under which Stellar's commitment
  # rule hashes a list as its epoch record and raises.
  test "Stellar's epoch record that is not an object: no read, shape_invalid naming it" do
    for record <- [[1], [], "x", 1, nil, true] do
      outcome = Stellar.commitment(context(%{}), put(@stellar, ["epoch", "record"], record))
      assert {outcome.status, outcome.code} == {:fail, :shape_invalid}, inspect(record)
      assert outcome.values == %{"reads" => [], "unshaped" => ["/epoch/record"]}
    end
  end

  property "any term in place of the value: no raise, no read, shape_invalid" do
    check all(
            {name, rule, _value, members} <- StreamData.member_of(rules()),
            term <- StreamData.term()
          ) do
      outcome = rule.(context(%{}), term)
      assert {outcome.status, outcome.code} == {:fail, :shape_invalid}, name
      assert outcome.values["reads"] == []
      assert outcome.values["unshaped"] == Enum.map(members, &Pointer.encode(elem(&1, 0)))
    end
  end

  property "Bitcoin's txoutproof: not hex is shape_invalid; hex but no merkleblock, its rule" do
    check all(bad <- unshaped_hex(@bitcoin["txoutproof"])) do
      outcome = Bitcoin.commitment(context(%{}), Map.put(@bitcoin, "txoutproof", bad))
      assert outcome.status == :fail
      assert outcome.values["reads"] == []

      if is_binary(bad) and bad =~ @hexbytes do
        assert outcome.code == :bitcoin_evidence_invalid
        assert %{"member" => "txoutproof", "rule" => rule} = outcome.values
        assert rule in @structure_rules
      else
        assert outcome.code == :shape_invalid
        assert outcome.values["unshaped"] == ["/txoutproof"]
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # LINK_CHAIN_ORDER

  test "an order that cannot be read fails, a missing bound included" do
    for {chain, object, member} <- [
          {Bitcoin, @bitcoin_entropy, "height"},
          {Stellar, @stellar_entropy, "ledger"}
        ] do
      sound = Map.put(%{}, member, 100_000_000)
      assert chain.chain_order(["witnesses"], object, sound).outcome == :pass

      for entry <- [%{}, %{member => "100000000"}, nil, "x"],
          object <- [object, put(object, ["payload"], "x"), nil] do
        assert chain.chain_order(["witnesses"], object, entry).outcome ==
                 {:fail, :ordering_violation}
      end
    end
  end
end
