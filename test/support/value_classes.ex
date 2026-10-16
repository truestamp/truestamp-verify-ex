# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.ValueClasses do
  @moduledoc """
  The value class of a member of P (SPEC.md section 3.7), read from `spec/value-classes.json`
  for the tests, so that the trace's membership (section 10.6: a trace row for each DERIVE
  row whose part is a CHECKED value) is checked against the published table rather than
  against the verifier's own idea of it. The verifier never reads this file.

  A member's pointer in the file may hold `*` for any one segment and `entropy_*` for a
  segment that begins `entropy_`. A member with `when` has the class `class` when its
  condition holds in P, and `otherwise` when it does not. The conditions are the file's four,
  each read from P here:

  - `genesis_block`: the block record's metadata has a `genesis` member;
  - `introduces_key_or_prerotation`: the block record's `metadata.key_event` is a `genesis`,
    `rotation`, `emergency_rotation` or `prerotation`;
  - `walked`: the `inclusion_proof` of the subject or of an observation walks to this value,
    which it does in every type but `block` and a `beacon` with no observations;
  - `stellar_source`: the entropy object's `source` is `stellar`.
  """

  alias Truestamp.Verify.Test.StrictJSON

  @path Truestamp.Verify.Test.Verification.path("spec/value-classes.json")
  @external_resource @path
  @members @path |> StrictJSON.read_data!() |> Map.fetch!("members")

  @blocks [["block"], ["witnesses", "block"], ["signing_key_event", "block"]]

  @doc "The class of the member of `proof` at `pointer` (segments), or nil when none is listed."
  @spec class(map(), [String.t() | non_neg_integer()]) :: String.t() | nil
  def class(proof, pointer) do
    case Enum.find(@members, &matches?(split(&1["pointer"]), pointer)) do
      nil -> nil
      %{"when" => condition} = member -> conditional(member, holds?(condition, proof, pointer))
      member -> member["class"]
    end
  end

  @doc "Whether the member of `proof` at `pointer` is CHECKED."
  @spec checked?(map(), [String.t() | non_neg_integer()]) :: boolean()
  def checked?(proof, pointer), do: class(proof, pointer) == "CHECKED"

  defp conditional(member, true), do: member["class"]
  defp conditional(member, false), do: member["otherwise"]

  defp split("/" <> pointer), do: String.split(pointer, "/")

  defp matches?(pattern, pointer) when length(pattern) != length(pointer), do: false

  defp matches?(pattern, pointer) do
    pattern
    |> Enum.zip(pointer)
    |> Enum.all?(fn {want, have} -> segment?(want, have) end)
  end

  defp segment?("*", _have), do: true
  defp segment?("entropy_*", have), do: is_binary(have) and String.starts_with?(have, "entropy_")
  defp segment?(want, have), do: want == have

  defp holds?("genesis_block", proof, pointer),
    do: is_map(get(record(proof, pointer), ["metadata", "genesis"]))

  defp holds?("introduces_key_or_prerotation", proof, pointer) do
    get(record(proof, pointer), ["metadata", "key_event", "type"]) in ~w(genesis rotation emergency_rotation prerotation)
  end

  defp holds?("walked", proof, _pointer) do
    case proof["type"] do
      "block" -> false
      "beacon" -> map_size(proof["observations"]) > 0
      _item_or_entropy -> true
    end
  end

  defp holds?("stellar_source", proof, pointer),
    do: get(proof, Enum.take(pointer, length(pointer) - 2) ++ ["source"]) == "stellar"

  # The block record whose member `pointer` names.
  defp record(proof, pointer) do
    block = Enum.find(@blocks, &(Enum.take(pointer, length(&1)) == &1))
    get(proof, block ++ ["record"])
  end

  defp get(value, []), do: value
  defp get(value, [name | rest]) when is_map(value), do: get(Map.get(value, name), rest)
  defp get(_value, _pointer), do: nil
end
