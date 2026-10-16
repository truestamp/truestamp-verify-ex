# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.ProofMutants do
  @moduledoc """
  Sound values of P, the `proof` member, and single-defect mutants of them, each with the
  pointer SPEC.md section 10.2 gives its defect, for the tests of SHAPE and POLICY.

  The sound values are the proofs under `vectors/positive/`, read with the verifier's own
  `Parser`, and the samples of `Truestamp.Verify.Test.Samples`, which put every kind of key
  event at every block position. This module knows the layouts of SPEC.md 3 on its own, from
  the text, and shares nothing with the verifier's `Schema`, `Shape` or `Layout`.

  A pointer is a list of segments, names and array indices, outermost first. Nothing inside
  the open `subject.claims`, or inside a full constructions text, is a node here: each is one
  value.
  """

  alias Truestamp.Verify.JSON
  alias Truestamp.Verify.Test.Samples

  @positive Truestamp.Verify.Test.Verification.path("vectors/positive")
  @constructions Truestamp.Verify.Test.Verification.path("spec/constructions")
  @reference "https://www.truestamp.com/.well-known/constructions-"

  @empty_root "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  @time ~r/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/
  @nisttime ~r/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\z/

  @doc "The empty tree's root, SHA-256 of zero bytes (SPEC.md 5.4)."
  @spec empty_root() :: String.t()
  def empty_root, do: @empty_root

  @doc "The sound proofs under `vectors/positive/`, by name, each the parsed document."
  @spec positive() :: %{String.t() => map()}
  def positive do
    for file <- Path.wildcard(Path.join(@positive, "*.proof.json")), into: %{} do
      {:ok, document} = file |> File.read!() |> JSON.decode()
      {Path.basename(file, ".proof.json"), document}
    end
  end

  @doc """
  Every sound value of P: each positive proof's, and each sample's, keyed by
  `"positive <name>"` or `"sample <name>"`. A sample's hashes are not computed, and neither
  is its constructions member: here a sample that carries a text carries the accepted one,
  and a sample that carries a reference names it, so each passes every check of SHAPE.
  """
  @spec bases() :: %{String.t() => map()}
  def bases do
    [text_file] = Path.wildcard(Path.join(@constructions, "*.json"))
    {:ok, text} = text_file |> File.read!() |> JSON.decode()
    url = @reference <> Path.basename(text_file)

    positive = for {name, doc} <- positive(), into: %{}, do: {"positive #{name}", doc["proof"]}

    samples =
      for {name, doc} <- Samples.all(), into: %{} do
        {"sample #{name}", accepted_constructions(doc["proof"], text, url)}
      end

    Map.merge(positive, samples)
  end

  defp accepted_constructions(%{"constructions" => value} = proof, text, _url) when is_map(value),
    do: Map.put(proof, "constructions", text)

  defp accepted_constructions(%{"constructions" => value} = proof, _text, url)
       when is_binary(value),
       do: Map.put(proof, "constructions", url)

  defp accepted_constructions(proof, _text, _url), do: proof

  @doc "Every node of `proof` as `{pointer, value}`, each value before its contents."
  @spec nodes(map()) :: [{list(), term()}]
  def nodes(proof), do: nodes(proof, [])

  defp nodes(value, ["subject", "claims"] = at), do: [{at, value}]
  defp nodes(value, ["constructions"] = at), do: [{at, value}]

  defp nodes(value, at) when is_map(value) do
    inner = value |> Enum.sort() |> Enum.flat_map(fn {name, sub} -> nodes(sub, at ++ [name]) end)
    [{at, value} | inner]
  end

  defp nodes(value, at) when is_list(value) do
    inner = value |> Enum.with_index() |> Enum.flat_map(fn {sub, i} -> nodes(sub, at ++ [i]) end)
    [{at, value} | inner]
  end

  defp nodes(value, at), do: [{at, value}]

  @doc "The value at `pointer`, or nil."
  @spec get(term(), list()) :: term()
  def get(value, []), do: value
  def get(value, [name | rest]) when is_map(value), do: get(Map.get(value, name), rest)
  def get(value, [i | rest]) when is_list(value), do: get(Enum.at(value, i), rest)
  def get(_value, _pointer), do: nil

  @doc "`value` with `new` at `pointer`, a member added where the object lacks it."
  @spec put(term(), list(), term()) :: term()
  def put(_value, [], new), do: new

  def put(value, [name | rest], new) when is_map(value),
    do: Map.put(value, name, put(Map.get(value, name), rest, new))

  def put(value, [i | rest], new) when is_list(value),
    do: List.replace_at(value, i, put(Enum.at(value, i), rest, new))

  @doc "`value` without the member at `pointer`."
  @spec delete(map(), list()) :: map()
  def delete(value, [name]), do: Map.delete(value, name)

  def delete(value, [name | rest]),
    do: Map.put(value, name, delete(Map.fetch!(value, name), rest))

  @doc "The RFC 6901 string of a pointer."
  @spec show(list()) :: String.t()
  def show(pointer), do: Enum.map_join(pointer, &["/", to_string(&1)])

  @doc """
  The members of `proof` that are optional (SPEC.md 3: an O, a witness or observation of a
  source, a chain of COMMITMENTS, a key event where the block's metadata may hold none), and
  those it lacks but its layout allows, each as a pointer, `environment` apart.
  """
  @spec optional_members(map()) :: [list()]
  def optional_members(proof) do
    top = for name <- ~w(constructions signing_key_event), do: [name]
    entropy = ~w(entropy_bitcoin entropy_nist entropy_stellar)

    by_type =
      case proof["type"] do
        "item" ->
          for n <- entropy,
              base <- [["witnesses"], ["subject", "record", "witness_hashes"]],
              do: base ++ [n]

        "beacon" ->
          for n <- entropy, do: ["observations", n]

        _other ->
          []
      end

    top ++
      by_type ++
      commitment_chains(proof) ++ Enum.flat_map(block_positions(proof), &event_members(proof, &1))
  end

  defp commitment_chains(proof) do
    bases =
      [["commitments"]] ++
        if(proof["signing_key_event"], do: [["signing_key_event", "commitments"]], else: [])

    for base <- bases, chain <- ~w(bitcoin stellar), do: base ++ [chain]
  end

  defp event_members(proof, position) do
    metadata = get(proof, position ++ ["record", "metadata"])
    event = metadata["key_event"]
    at = position ++ ["record", "metadata", "key_event"]

    optional_event =
      if position != ["signing_key_event", "block"] and not Map.has_key?(metadata, "genesis"),
        do: [at],
        else: []

    optional_event ++ event_optional_members(event, at)
  end

  defp event_optional_members(%{"type" => type}, at) when type in ~w(genesis rotation),
    do: [at ++ ["prerotation_commitment"]]

  defp event_optional_members(%{"type" => "emergency_rotation"}, at),
    do: [at ++ ["prerotation_commitment"], at ++ ["handover_signature"]]

  defp event_optional_members(_event, _at), do: []

  @doc "The block positions `proof` fills: `/block`, `/witnesses/block`, `/signing_key_event/block`."
  @spec block_positions(map()) :: [list()]
  def block_positions(proof) do
    for position <- [["block"], ["witnesses", "block"], ["signing_key_event", "block"]],
        is_map(get(proof, position)),
        do: position
  end

  @doc """
  A `\\n` escaped onto the end of each string value of `proof` other than `environment`,
  claims and a full constructions text aside, as `{pointer, mutant}`.
  """
  @spec newline_mutants(map()) :: [{list(), map()}]
  def newline_mutants(proof) do
    for {at, value} <- nodes(proof),
        is_binary(value),
        at != ["environment"],
        do: {at, put(proof, at, value <> "\n")}
  end

  @doc "Each optional member other than `environment` as `null`, as `{pointer, mutant}`."
  @spec null_mutants(map()) :: [{list(), map()}]
  def null_mutants(proof), do: for(at <- optional_members(proof), do: {at, put(proof, at, nil)})

  @doc """
  The two empty-root mutants (SPEC.md 5.4) of each block record, as `{position, kind,
  mutant}`: `:leaves_under_empty_root`, a `leaf_count` of 1 or more under the empty root,
  and `:no_leaves_under_real_root`, a `leaf_count` of 0 under another root.
  """
  @spec empty_root_mutants(map()) :: [{list(), atom(), map()}]
  def empty_root_mutants(proof) do
    for position <- block_positions(proof),
        record = position ++ ["record"],
        {kind, changes} <- empty_root_changes(get(proof, record)) do
      mutant = Enum.reduce(changes, proof, fn {member, v}, p -> put(p, record ++ [member], v) end)
      {position, kind, mutant}
    end
  end

  defp empty_root_changes(%{"leaf_count" => 0, "merkle_root" => @empty_root}) do
    [
      leaves_under_empty_root: [{"leaf_count", 1}],
      no_leaves_under_real_root: [{"merkle_root", Samples.hex64("a real root")}]
    ]
  end

  defp empty_root_changes(%{"leaf_count" => count}) when count > 0 do
    [
      leaves_under_empty_root: [{"merkle_root", @empty_root}],
      no_leaves_under_real_root: [{"leaf_count", 0}]
    ]
  end

  @doc "The TIME and NISTTIME values of `proof`, found by their patterns, as `{pointer, class}`."
  @spec times(map()) :: [{list(), :time | :nisttime}]
  def times(proof) do
    for {at, value} <- nodes(proof),
        is_binary(value),
        class = time_class(value),
        class != nil,
        do: {at, class}
  end

  defp time_class(value) do
    cond do
      Regex.match?(@time, value) -> :time
      Regex.match?(@nisttime, value) -> :nisttime
      true -> nil
    end
  end

  @doc """
  Generic single defects of a sound `proof`, each `{about, pointer, mutant}` with the pointer
  SHAPE's check 3 reports: an unknown member in every object, at that member; every value
  replaced by a value of another JSON type, at that value; and every member deleted that the
  layout requires, at that member. Deleting a genesis block's `metadata.genesis` is left out:
  SPEC.md 10.2, step 7, puts that failure at the key event's `type`, not at the missing
  member (`genesis_deleted/1`).
  """
  @spec defects(map()) :: [{String.t(), list(), map()}]
  def defects(proof) do
    optional = MapSet.new(optional_members(proof))

    Enum.flat_map(nodes(proof), fn {at, value} ->
      unknown(proof, at, value) ++ other_type(proof, at) ++ deleted(proof, at, optional)
    end)
  end

  defp unknown(proof, at, value)
       when is_map(value) and at != ["subject", "claims"] and at != ["constructions"],
       do: [
         {"an unknown member in #{show(at)}", at ++ ["zz_unknown"],
          put(proof, at ++ ["zz_unknown"], 1)}
       ]

  defp unknown(_proof, _at, _value), do: []

  defp other_type(_proof, []), do: []

  defp other_type(proof, at),
    do: [{"another type at #{show(at)}", at, put(proof, at, another_type(get(proof, at)))}]

  defp another_type(value) when is_binary(value), do: 1
  defp another_type(value) when is_number(value), do: "1"
  defp another_type(value) when is_list(value), do: "x"
  defp another_type(_value), do: [1]

  defp deleted(proof, at, optional) do
    cond do
      at == [] or is_integer(List.last(at)) -> []
      at == ["environment"] or MapSet.member?(optional, at) -> []
      List.last(at) == "genesis" and Enum.at(at, -2) == "metadata" -> []
      true -> [{"no #{show(at)}", at, delete(proof, at)}]
    end
  end

  @doc """
  Each genesis block's `metadata.genesis` deleted, as `{position, mutant}`: the key event is
  then a `genesis` event without it, which the schema's pairing rule refuses at the event's
  `type`.
  """
  @spec genesis_deleted(map()) :: [{list(), map()}]
  def genesis_deleted(proof) do
    for position <- block_positions(proof),
        metadata = position ++ ["record", "metadata"],
        Map.has_key?(get(proof, metadata), "genesis"),
        do: {position, delete(proof, metadata ++ ["genesis"])}
  end
end
