# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Shape do
  @moduledoc """
  Step 7 of SPEC.md section 10.2, SHAPE, on P, the parsed value of `proof`. Its checks run
  in this order, and the first that fails is the step's one failing row:

  | Check | Holds when | Else, at |
  |---|---|---|
  | 1 | `format` is `"truestamp-proof"` | `unsupported_format`, `/format` |
  | 2 | `version` is 1 | `unsupported_version`, `/version` |
  | 3 | P satisfies `spec/schema.json` (`Truestamp.Verify.Schema`) | `shape_invalid`, the first failure's part in document order |
  | 4 | in an item, `/witnesses` has exactly the names of `/subject/record/witness_hashes` | `shape_invalid`, `/witnesses` |
  | 5 | every TIME and NISTTIME value equals the formatting of its own parse | `shape_invalid`, the first such value in document order |
  | 6 | when `constructions` is present, its digest d is in CONSTRUCTIONS_ACCEPTED | `construction_mismatch`, `/constructions` |

  Checks 1 and 2 come first, so an absent `format` or `version` is that check's failure, not
  the schema's. Check 5 reads the TIME and NISTTIME values each chain and source declares
  (`c:Truestamp.Verify.CommitmentChain.commitment_times/0` and
  `c:Truestamp.Verify.EntropySource.entropy_times/0`), after check 3 has held each to its
  pattern.

  **Constructions** (section 7.2). Check 6 is the one place any step reads `constructions`.
  Its JSON type tells the mode: an object is the full text, whose d is SHA-256(JCS(value));
  a string is a reference, whose d is the 64 hex characters of its URL, and check 3 has
  already failed a string off the reference pattern; absent is mode none, which checks
  nothing. The text is never interpreted and the URL never fetched.

  When SHAPE passes it reports one row, `pass`, with part null, and the run takes the proof's
  type and subject id (section 10.5): `/subject/record/id`, or `/block/record/id` for
  `block` and `beacon`. A failure ends the run as a failure at the gate does.

  **Values** (section 10.5):

  | Row | `values` |
  |---|---|
  | pass | `constructions`, the mode; in full mode also `constructions_digest`, the d it computed |
  | check 1 or 2 | `declared`, the `format` or `version` P carries, when it carries one |
  | check 3 | `keyword` and `schema`, the rule broken and where it sits in the schema |
  | check 4 | `rule`, which names the rule; never the names P carries |
  | check 5 | `class`, TIME or NISTTIME, and `declared`, the value |
  | check 6 | `constructions`, the mode; in full mode `constructions_digest`, the d it computed, and in reference mode `declared`, the d of the URL |
  """

  alias Truestamp.Verify.{Instant, JCS, Layout, Row, Run, Schema}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Spec.Constructions

  @format "truestamp-proof"
  @version 1

  # SPEC.md 7.2: the reference mode's URL, with d between these two.
  @reference_prefix "https://www.truestamp.com/.well-known/constructions-"
  @reference_suffix ".json"

  @witness_rule "witnesses_named_by_witness_hashes"

  @doc "Step 7, SHAPE: the six checks above, in order, on the run's P."
  @spec shape(Run.t()) :: Run.t()
  def shape(%Run{ended: true} = run), do: run

  def shape(%Run{proof: proof} = run) when is_map(proof) do
    with nil <- format(proof),
         nil <- version(proof),
         nil <- schema(proof),
         nil <- witnesses(proof),
         nil <- times(proof),
         {:ok, constructions} <- constructions(proof) do
      pass(run, proof, constructions)
    else
      {code, part, {id, assigns}, values} ->
        fail(run, code, part, Run.text(run, id, assigns), values)
    end
  end

  defp pass(run, proof, constructions) do
    type = Map.fetch!(proof, "type")
    row = Row.pass(:shape, nil, Run.text(run, :shape_pass, %{type: type}), constructions)
    Run.add_row(%{run | type: type, subject_id: subject_id(type, proof)}, row)
  end

  defp fail(run, code, part, message, values) do
    row = Row.new(:shape, code, Pointer.encode(part), message, values)
    run |> Run.add_row(row) |> Run.end_run()
  end

  defp subject_id(type, proof) when type in ["block", "beacon"],
    do: Layout.get(proof, ["block", "record", "id"])

  defp subject_id(_type, proof), do: Layout.get(proof, ["subject", "record", "id"])

  # 1. format
  defp format(proof) do
    unless Map.get(proof, "format") === @format,
      do:
        {:unsupported_format, ["format"], {:unsupported_format, %{format: @format}},
         declared(proof, "format")}
  end

  # 2. version
  defp version(proof) do
    unless Map.get(proof, "version") === @version,
      do:
        {:unsupported_version, ["version"], {:unsupported_version, %{version: @version}},
         declared(proof, "version")}
  end

  defp declared(proof, member) do
    case Map.fetch(proof, member) do
      {:ok, value} -> %{"declared" => value}
      :error -> %{}
    end
  end

  # 3. the schema
  defp schema(proof) do
    case Schema.proof_failures(proof) do
      [] ->
        nil

      [%{part: part, keyword: keyword, schema: location} | _later] ->
        message = {:shape_schema, %{part: Pointer.encode(part), rule: location}}
        {:shape_invalid, part, message, %{"keyword" => keyword, "schema" => location}}
    end
  end

  # 4. the witnesses of an item
  defp witnesses(%{"type" => "item"} = proof) do
    witnesses = proof |> Map.fetch!("witnesses") |> Map.keys() |> Enum.sort()

    names =
      proof |> Layout.get(["subject", "record", "witness_hashes"]) |> Map.keys() |> Enum.sort()

    unless witnesses == names,
      do: {:shape_invalid, ["witnesses"], {:shape_witnesses, %{}}, %{"rule" => @witness_rule}}
  end

  defp witnesses(_proof), do: nil

  # 5. the TIME and NISTTIME round trips
  defp times(proof) do
    failing =
      for {at, class} <- time_positions(proof),
          text = Layout.get(proof, at),
          match?({:error, _flaw}, Instant.parse(class, text)),
          do: {at, class}

    case Pointer.first_by(failing, &elem(&1, 0)) do
      nil ->
        nil

      {at, class} ->
        message = {:shape_time, %{part: Pointer.encode(at), class: class_name(class)}}

        {:shape_invalid, at, message,
         %{"class" => class_name(class), "declared" => Layout.get(proof, at)}}
    end
  end

  defp time_positions(proof) do
    commitment =
      for {at, chain, _entry} <- Layout.commitment_entries(proof),
          {member, class} <- chain.commitment_times(),
          do: {at ++ member, class}

    entropy =
      for {at, source, _object} <- Layout.entropy_objects(proof),
          {member, class} <- source.entropy_times(),
          do: {at ++ member, class}

    commitment ++ entropy
  end

  defp class_name(:time), do: "TIME"
  defp class_name(:nisttime), do: "NISTTIME"

  # 6. constructions: the only read of the member in any step (sections 7.2 and 10.6).
  defp constructions(proof) do
    case Map.fetch(proof, "constructions") do
      :error -> {:ok, %{"constructions" => "none"}}
      {:ok, text} when is_map(text) -> full(sha256_hex(JCS.encode(text)))
      {:ok, url} when is_binary(url) -> reference(reference_digest(url))
    end
  end

  # Full mode: this run computed d, so the row gives it, pass or fail.
  defp full(digest) do
    values = %{"constructions" => "full", "constructions_digest" => digest}

    if Constructions.accepted?(digest),
      do: {:ok, values},
      else:
        {:construction_mismatch, ["constructions"], {:construction_mismatch_full, %{}}, values}
  end

  # Reference mode: d is the proof's, so only a failure gives it, marked as declared.
  defp reference(digest) do
    if Constructions.accepted?(digest),
      do: {:ok, %{"constructions" => "reference"}},
      else:
        {:construction_mismatch, ["constructions"], {:construction_mismatch_reference, %{}},
         %{"constructions" => "reference", "declared" => digest}}
  end

  # Check 3 has held the string to the reference pattern, so d is the 64 characters between
  # the prefix and the suffix.
  defp reference_digest(url) do
    <<@reference_prefix, digest::binary-size(64), @reference_suffix>> = url
    digest
  end

  defp sha256_hex(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
end
