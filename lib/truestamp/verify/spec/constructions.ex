# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec.Constructions do
  @moduledoc """
  CONSTRUCTIONS_ACCEPTED (SPEC.md sections 7.2 and 9): the digests of the constructions texts
  under `spec/constructions/`, as compiled constants. Each file there holds a text's exact
  JCS bytes and is named `<d>.json`, where d is the lowercase hex SHA-256 of those bytes; the
  build stops on a file whose name is not the digest of its bytes.

  This module holds the digests only. It never reads a proof: SHAPE's check 6 (section
  10.2, step 7) computes a full text's digest, or takes a reference's from its URL, and asks
  `accepted?/1`.
  """

  alias Truestamp.Verify.Spec.Data

  @dir Data.path("constructions")
  @files @dir |> Path.join("*") |> Path.wildcard(match_dot: true) |> Enum.sort()

  for file <- @files, do: @external_resource(file)

  @accepted (for file <- @files do
               digest = Path.basename(file, ".json")
               bytes = File.read!(file)
               actual = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

               unless Path.extname(file) == ".json" and digest =~ ~r/\A[0-9a-f]{64}\z/ and
                        digest == actual,
                      do: raise("spec/constructions/: #{Path.basename(file)} is not <d>.json")

               digest
             end)

  if @accepted == [], do: raise("spec/constructions/ holds no text")

  # A text added to or removed from the directory recompiles this module.
  @doc false
  def __mix_recompile__?,
    do: @dir |> Path.join("*") |> Path.wildcard(match_dot: true) |> Enum.sort() != @files

  @doc "CONSTRUCTIONS_ACCEPTED: the accepted digests, sorted."
  @spec accepted() :: [String.t()]
  def accepted, do: @accepted

  @doc "Whether `digest`, 64 lowercase hex characters, is in CONSTRUCTIONS_ACCEPTED."
  @spec accepted?(String.t()) :: boolean()
  def accepted?(digest) when is_binary(digest), do: digest in @accepted
end
