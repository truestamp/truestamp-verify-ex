# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.SchemaTest do
  # The verifier's own checker for spec/schema.json (SPEC.md 9), SHAPE's check 3:
  #
  # - agreement: the compiled schema is the file, its keywords are the subset SPEC.md 9
  #   lists, and on every document tried here the checker's verdict equals the test suite's
  #   own interpreter's (test/support/schema_subset.ex), which reads `$` leniently, as PCRE
  #   does, while the verifier reads it as ECMA-262 does;
  # - parts: for every single defect of every sound value of P, the first failure in document
  #   order is at the pointer SPEC.md 10.2's rule gives (the member missing, extra or
  #   forbidden, or the value that breaks its rule; for a count, the object or array), and
  #   of two extra members either side of U+FFFF it is the one first in JCS order;
  # - the keywords' meaning, one test each where the vectors and samples do not reach.
  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{JSON, Row, Schema}

  alias Truestamp.Verify.Test.{
    Cases,
    ProofMutants,
    Samples,
    SchemaSubset,
    Signing,
    StrictJSON,
    Verification
  }

  @schema_file Truestamp.Verify.Test.Verification.path("spec/schema.json")
  @external_resource @schema_file

  defp file_schema, do: StrictJSON.read_data!(@schema_file)

  defp first_part(proof) do
    case Schema.proof_failures(proof) do
      [] -> nil
      [first | _] -> first.part
    end
  end

  defp envelope(proof), do: %{"proof" => proof, "signature" => Samples.all()["item"]["signature"]}

  describe "agreement with spec/schema.json" do
    test "the compiled schema is the file's value" do
      assert Schema.schema() == file_schema()
    end

    test "its keywords are the subset of SPEC.md 9, the test interpreter's list" do
      assert Schema.keywords() == SchemaSubset.keywords()

      spec_md = File.read!(Verification.path("SPEC.md"))
      [_, section] = String.split(spec_md, "**The schema.**", parts: 2)
      [listed, _] = String.split(section, "and the boolean schemas", parts: 2)

      named =
        ~r/`([$a-zA-Z]+)`/
        |> Regex.scan(listed, capture: :all_but_first)
        |> List.flatten()
        |> Enum.reject(&(&1 in ["false", "true"]))

      assert Enum.sort(named) == Enum.sort(Schema.keywords())
    end

    test "agrees with the test interpreter on every sample, sound proof and case proof" do
      schema = file_schema()

      documents =
        Map.values(Samples.all()) ++
          Map.values(ProofMutants.positive()) ++
          for kase <- Cases.all(),
              {:ok, %{"proof" => _} = document} <- [JSON.decode(Cases.proof(kase))],
              do: document

      assert length(documents) > 300

      for document <- documents do
        assert Schema.valid?(document) == SchemaSubset.valid?(schema, document)
      end
    end

    # Over a minute on a slow machine, such as a CI runner.
    @tag timeout: 300_000
    test "agrees with the test interpreter on every mutant of every sound value of P" do
      schema = file_schema()

      for {name, proof} <- ProofMutants.bases(),
          {about, _at, mutant} <-
            ProofMutants.defects(proof) ++
              for({at, m} <- ProofMutants.newline_mutants(proof), do: {"newline", at, m}) ++
              for({at, m} <- ProofMutants.null_mutants(proof), do: {"null", at, m}) ++
              for({at, k, m} <- ProofMutants.empty_root_mutants(proof), do: {k, at, m}) do
        document = envelope(mutant)
        verdict = Schema.valid?(document)
        assert verdict == SchemaSubset.valid?(schema, document), "#{name}: #{inspect(about)}"
        refute verdict, "#{name}: #{inspect(about)}"
        assert Schema.proof_failures(mutant) == [] == verdict
      end
    end

    test "passes every sound value of P, whole or as the proof member" do
      for {name, proof} <- ProofMutants.bases() do
        assert Schema.proof_failures(proof) == [], name
        assert Schema.failures(envelope(proof)) == [], name
      end
    end

    test "a document's failures are P's, under /proof" do
      proof = put_in(Samples.all()["item"]["proof"], ["block", "record", "leaf_count"], -1)
      [failure] = Schema.failures(envelope(proof))
      assert failure.part == ["proof", "block", "record", "leaf_count"]
      assert Schema.proof_failures(proof) == [%{failure | part: tl(failure.part)}]
    end
  end

  describe "the part of the first failure, in document order" do
    test "is the pointer of each generic single defect" do
      for {name, proof} <- ProofMutants.bases(),
          {about, at, mutant} <- ProofMutants.defects(proof) do
        assert first_part(mutant) == at, "#{name}: #{about}"
      end
    end

    test "a genesis event without metadata.genesis fails at the event's type" do
      cases =
        for {name, proof} <- ProofMutants.bases(),
            {position, mutant} <- ProofMutants.genesis_deleted(proof),
            do: {name, position, mutant}

      assert length(cases) >= 3

      for {name, position, mutant} <- cases do
        assert first_part(mutant) == position ++ ~w(record metadata key_event type), name
      end
    end

    test "metadata.genesis beside an event that is not genesis fails at the event's type" do
      proof = Samples.all()["item rotation at /block"]["proof"]
      genesis = Samples.all()["block"]["proof"]["block"]["record"]["metadata"]["genesis"]
      mutant = put_in(proof, ~w(block record metadata genesis), genesis)
      assert first_part(mutant) == ~w(block record metadata key_event type)
    end

    test "is the earliest of several, whatever order the checks meet them in" do
      proof = Samples.all()["item"]["proof"]

      mutant =
        proof
        |> put_in(~w(witnesses block record id), "x")
        |> put_in(~w(block record signing_key_id), "x")
        |> put_in(~w(commitments stellar ledger), -1)

      parts = Enum.map(Schema.proof_failures(mutant), & &1.part)
      assert hd(parts) == ~w(block record signing_key_id)

      path = for i <- 0..11, do: if(i in [2, 10], do: "x", else: Samples.hex64("#{i}"))
      at = ~w(subject inclusion_proof path)
      assert first_part(put_in(proof, at, path)) == at ++ [2]
      assert ~w(commitments stellar ledger) in parts
      assert ~w(witnesses block record id) in parts
    end

    # SPEC.md 13.3 leaves this case to each verifier's own tests. By code point U+FF5A comes
    # before U+1F600; by UTF-16 code unit, JCS's order, U+1F600 (D83D DE00) comes before
    # U+FF5A, so the first failure is at U+1F600, in the schema's list and in SHAPE's row.
    test "of two extra members either side of U+FFFF is the one first in JCS order" do
      at = ~w(commitments stellar)

      extra = fn proof ->
        proof |> put_in(at ++ ["\u{FF5A}"], 1) |> put_in(at ++ ["\u{1F600}"], 1)
      end

      mutant = extra.(Samples.all()["item"]["proof"])
      assert first_part(mutant) == at ++ ["\u{1F600}"]
      assert hd(Schema.failures(envelope(mutant))).part == ["proof" | at ++ ["\u{1F600}"]]

      bytes = "item" |> Signing.positive() |> extra.() |> Signing.signed()
      {:ok, report} = Verify.verify(bytes, environment: :test, trust: :keyless)
      assert report.code == :shape_invalid

      assert [%Row{status: :fail, code: :shape_invalid, part: "/commitments/stellar/\u{1F600}"}] =
               Enum.filter(report.rows, &(&1.step == :shape and &1.status == :fail))
    end
  end

  describe "keywords" do
    setup do
      %{proof: Samples.all()["item"]["proof"]}
    end

    test "a count fails at the object or the array", %{proof: proof} do
      assert first_part(put_in(proof, ["commitments"], %{})) == ["commitments"]

      path = for i <- 1..33, do: Samples.hex64("#{i}")

      assert first_part(put_in(proof, ~w(subject inclusion_proof path), path)) ==
               ~w(subject inclusion_proof path)

      assert first_part(put_in(proof, ~w(subject inclusion_proof path), Enum.take(path, 32))) ==
               nil
    end

    test "a member the type forbids fails at that member", %{proof: proof} do
      beacon = Samples.all()["beacon"]["proof"]

      assert first_part(Map.put(proof, "observations", beacon["observations"])) == [
               "observations"
             ]

      assert first_part(Map.put(beacon, "subject", proof["subject"])) == ["subject"]
      assert first_part(Map.put(beacon, "witnesses", proof["witnesses"])) == ["witnesses"]
    end

    test "an integer is any number with no fraction, within the bounds", %{proof: proof} do
      at = ~w(commitments stellar ledger)
      assert first_part(put_in(proof, at, 9_007_199_254_740_991)) == nil
      assert first_part(put_in(proof, at, 1.0e21)) == at
      assert first_part(put_in(proof, at, 2.5)) == at
      assert first_part(put_in(proof, at, -1)) == at
      assert first_part(put_in(proof, at, true)) == at
    end

    test "a length counts code points, and a pattern matches the whole string", %{proof: proof} do
      at = ~w(signing_key_event block record metadata key_event reason)
      assert first_part(put_in(proof, at, String.duplicate("r", 128))) == nil
      assert first_part(put_in(proof, at, String.duplicate("r", 129))) == at
      # A character above U+007E is outside ASCII128, as one code point or as its bytes.
      assert first_part(put_in(proof, at, "ré")) == at
      assert first_part(put_in(proof, at, "")) == at
      assert first_part(put_in(proof, at, "tab\there")) == at
    end

    test "HEXBYTES' pattern has no length, so its newline guard decides", %{proof: proof} do
      at = ~w(commitments bitcoin raw_transaction)
      assert first_part(put_in(proof, at, "abcd")) == nil
      assert first_part(put_in(proof, at, "abcd\n")) == at
      assert first_part(put_in(proof, at, "abc")) == at
      assert first_part(put_in(proof, at, String.duplicate("ab", 1000))) == nil
      assert first_part(put_in(proof, at, String.duplicate("ab", 1001))) == at
    end

    test "const and enum compare JSON values", %{proof: proof} do
      assert first_part(Map.put(proof, "version", 1.0)) == nil
      assert first_part(Map.put(proof, "version", "1")) == ["version"]
      assert first_part(Map.put(proof, "type", "Item")) == ["type"]

      assert first_part(put_in(proof, ~w(commitments stellar network), "mainnet")) ==
               ~w(commitments stellar network)
    end

    test "null is no value of any type", %{proof: proof} do
      for at <- [["block"], ~w(block record height), ~w(subject item_hash), ["commitments"]] do
        assert first_part(put_in(proof, at, nil)) == at
      end
    end
  end
end
