# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Step do
  @moduledoc """
  The steps of SPEC.md section 10.2, 0 to 14, in order.

  A step is an atom in this library's structs, such as `:key_binding`, and is written with
  the spec's name, such as `"KEY_BINDING"`, wherever a report or a conformance output holds
  it (`name/1`, `from_name/1`).

  | Step | Atom | Name |
  |---|---|---|
  | 0 | `:configuration` | CONFIGURATION |
  | 1 | `:read` | READ |
  | 2 | `:parse` | PARSE |
  | 3 | `:envelope` | ENVELOPE |
  | 4 | `:environment` | ENVIRONMENT |
  | 5 | `:key_binding` | KEY_BINDING |
  | 6 | `:signature` | SIGNATURE |
  | 7 | `:shape` | SHAPE |
  | 8 | `:policy` | POLICY |
  | 9 | `:derive` | DERIVE |
  | 10 | `:chain` | CHAIN |
  | 11 | `:sources` | SOURCES |
  | 12 | `:window` | WINDOW |
  | 13 | `:expected_hash` | EXPECTED_HASH |
  | 14 | `:verdict` | VERDICT |

  Steps 0 to 6 are the gate. VERDICT reports no row, so a report's rows stop at
  EXPECTED_HASH.
  """

  @steps [
    configuration: "CONFIGURATION",
    read: "READ",
    parse: "PARSE",
    envelope: "ENVELOPE",
    environment: "ENVIRONMENT",
    key_binding: "KEY_BINDING",
    signature: "SIGNATURE",
    shape: "SHAPE",
    policy: "POLICY",
    derive: "DERIVE",
    chain: "CHAIN",
    sources: "SOURCES",
    window: "WINDOW",
    expected_hash: "EXPECTED_HASH",
    verdict: "VERDICT"
  ]

  @atoms Keyword.keys(@steps)
  @by_name Map.new(@steps, fn {atom, name} -> {name, atom} end)

  @typedoc "A step of section 10.2."
  @type t ::
          :configuration
          | :read
          | :parse
          | :envelope
          | :environment
          | :key_binding
          | :signature
          | :shape
          | :policy
          | :derive
          | :chain
          | :sources
          | :window
          | :expected_hash
          | :verdict

  @doc "Every step, 0 to 14, in order."
  @spec all() :: [t()]
  def all, do: @atoms

  @doc "The steps that report rows, 0 to 13, in order: every step but VERDICT."
  @spec with_rows() :: [t()]
  def with_rows, do: @atoms -- [:verdict]

  @doc "The steps after `step` that report rows, in order."
  @spec rows_after(t()) :: [t()]
  def rows_after(step) when step in @atoms,
    do: with_rows() |> Enum.drop_while(&(&1 != step)) |> Enum.drop(1)

  @doc "The spec's name of `step`, such as `\"KEY_BINDING\"`."
  @spec name(t()) :: String.t()
  def name(step) when step in @atoms, do: Keyword.fetch!(@steps, step)

  @doc "The step whose spec name is `name`, or nil."
  @spec from_name(String.t()) :: t() | nil
  def from_name(name) when is_binary(name), do: Map.get(@by_name, name)

  @doc "Whether `term` is a step."
  @spec step?(term()) :: boolean()
  def step?(term), do: term in @atoms
end
