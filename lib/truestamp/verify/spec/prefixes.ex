# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec.Prefixes do
  @moduledoc """
  The byte-prefix registry of SPEC.md section 4, as compiled constants: the table of section
  4.3, compiled from `spec/prefixes.json`, which publishes it keyed by construction name. A
  test holds the compiled table equal to that file and to the bytes of section 4.3.

  A verifier never takes a prefix from a document (section 4): every prefix it uses comes
  from here. Names are the file's keys as atoms: `:merkle_leaf`, `:merkle_node`,
  `:claims_hash`, `:item_hash`, `:entropy_hash`, `:observation_hash`,
  `:genesis_previous_block_hash`, `:block_hash`, `:epoch_hash`, `:proof_hash`, `:key_id`,
  `:prerotation_commitment` and `:handover`.
  """

  alias Truestamp.Verify.Spec.Data

  @typedoc "The name of a construction in the registry."
  @type name :: atom()

  @typedoc "One row of the table."
  @type entry :: %{
          byte: byte(),
          construction: String.t(),
          family: String.t(),
          hashed: String.t(),
          signed: boolean(),
          signer: String.t() | nil
        }

  @external_resource Data.path("prefixes.json")

  @table (for {name, row} <- Data.read!("prefixes.json"), into: %{} do
            entry = %{
              byte: Data.byte!(Map.fetch!(row, "byte")),
              construction: Map.fetch!(row, "construction"),
              family: Map.fetch!(row, "family"),
              hashed: Map.fetch!(row, "hashed"),
              signed: Map.fetch!(row, "signed"),
              signer: Map.get(row, "signer")
            }

            {String.to_atom(name), entry}
          end)

  bytes = @table |> Map.values() |> Enum.map(& &1.byte)

  if Enum.uniq(bytes) != bytes,
    do: raise(ArgumentError, "spec/prefixes.json: two constructions share a byte")

  @doc "The table of section 4.3, by name."
  @spec table() :: %{name() => entry()}
  def table, do: @table

  @doc "The names of the registry, in the order of their bytes."
  @spec names() :: [name()]
  def names,
    do: @table |> Enum.sort_by(fn {_name, entry} -> entry.byte end) |> Enum.map(&elem(&1, 0))

  @doc "The prefix byte the registry assigns to `name`."
  @spec byte(name()) :: byte()
  for {name, entry} <- @table do
    def byte(unquote(name)), do: unquote(entry.byte)
  end
end
