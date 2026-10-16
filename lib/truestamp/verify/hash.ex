# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Hash do
  @moduledoc """
  The rule of SPEC.md section 4.1, the record hash of section 2.2:

      H(p, R) = SHA-256(p || JCS(R))

  where `p` is the one byte the registry (section 4.3, `Truestamp.Verify.Spec.Prefixes`)
  assigns to R's kind, and R is a JSON object within the value profile of section 10.1,
  hashed exactly as carried.

  The kinds under the rule are those the registry hashes as JCS of a value. The Merkle leaf
  and node (0x00, 0x01), the key id (0x60) and the prerotation commitment (0x61) are outside
  it (section 4.1): they hash raw bytes, not a record, and `hash/2` refuses them.
  `Truestamp.Verify.KeyId` computes the key id.
  """

  alias Truestamp.Verify.{JCS, JSON}
  alias Truestamp.Verify.Spec.Prefixes

  # SPEC.md 4.1, "Outside the rule".
  @outside_the_rule [:merkle_leaf, :merkle_node, :key_id, :prerotation_commitment]

  @kinds Prefixes.names() -- @outside_the_rule

  @typedoc """
  A kind under the rule: `:claims_hash`, `:item_hash`, `:entropy_hash`, `:observation_hash`,
  `:genesis_previous_block_hash`, `:block_hash`, `:epoch_hash`, `:proof_hash` or `:handover`.
  """
  @type kind :: Prefixes.name()

  @doc "The kinds under the rule, in the order of their bytes."
  @spec kinds() :: [kind()]
  def kinds, do: @kinds

  @doc "H(p, R): the 32 octets of SHA-256(p || JCS(record)), with p the byte of `kind`."
  @spec hash(kind(), %{optional(String.t()) => JSON.value()}) :: <<_::256>>
  def hash(kind, record) when kind in @kinds and is_map(record) and not is_struct(record),
    do: :crypto.hash(:sha256, [Prefixes.byte(kind), JCS.encode(record)])

  @doc "H(p, R) as 64 lowercase hex characters, the HEX64 a proof carries."
  @spec hash_hex(kind(), %{optional(String.t()) => JSON.value()}) :: String.t()
  def hash_hex(kind, record), do: kind |> hash(record) |> Base.encode16(case: :lower)
end
