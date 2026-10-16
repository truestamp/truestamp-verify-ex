# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains do
  @moduledoc """
  The registry of commitment chains and entropy sources the specification defines, each a
  module of its own:

  | Name | Commitment chain | Entropy source | Module |
  |---|---|---|---|
  | `bitcoin` | yes | yes | `Truestamp.Verify.Chains.Bitcoin` |
  | `nist` | no | yes | `Truestamp.Verify.Chains.Nist` |
  | `stellar` | yes | yes | `Truestamp.Verify.Chains.Stellar` |

  Every list is in JCS order of the names, which is the document order of the members they
  key. The engine reads the chains and sources only from here, so no step holds a branch of
  its own for any of them.

  **The registry is closed.** A verifier refuses what the specification does not define,
  so no caller can add a chain or a source at run time: a new one arrives with a change to
  the specification and a release of this library. The build stops unless the commitment
  chains are exactly the chains of `spec/networks.json`, and a test holds both lists to the
  schema.
  """

  alias Truestamp.Verify.Chains.{Bitcoin, Nist, Stellar}
  alias Truestamp.Verify.Spec

  @commitment_chains [Bitcoin, Stellar]
  @entropy_sources [Bitcoin, Nist, Stellar]

  if Enum.map(@commitment_chains, & &1.name()) != Enum.sort(Map.keys(Spec.networks())),
    do: raise("the commitment chains differ from the chains of spec/networks.json")

  @doc "The commitment chain modules, in JCS order of their names."
  @spec commitment_chains() :: [module()]
  def commitment_chains, do: @commitment_chains

  @doc "The entropy source modules, in JCS order of their names."
  @spec entropy_sources() :: [module()]
  def entropy_sources, do: @entropy_sources

  @doc "The names of the commitment chains, in JCS order."
  @spec chain_names() :: [String.t()]
  def chain_names, do: Enum.map(@commitment_chains, & &1.name())

  @doc "The names of the entropy sources, in JCS order."
  @spec source_names() :: [String.t()]
  def source_names, do: Enum.map(@entropy_sources, & &1.name())

  @doc "The commitment chain module named `name`."
  @spec commitment_chain(String.t()) :: module()
  def commitment_chain(name), do: Enum.find(@commitment_chains, &(&1.name() == name))

  @doc "The entropy source module named `name`."
  @spec entropy_source(String.t()) :: module()
  def entropy_source(name), do: Enum.find(@entropy_sources, &(&1.name() == name))
end
