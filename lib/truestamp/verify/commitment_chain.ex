# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CommitmentChain do
  @moduledoc """
  What the engine needs of a public chain that Truestamp writes epoch hashes to (SPEC.md
  sections 3.4, 5.4, 10.2 to 10.4 and 11.1): everything about one chain lives in one module,
  and the engine's steps hold no branch of their own for any chain.

  The chains are the members of COMMITMENTS that the schema allows, today `bitcoin` and
  `stellar` (`Truestamp.Verify.Chains`). The registry is closed: a chain the specification
  does not define is refused by SHAPE, and no caller can add one at run time. A new chain is
  a change to the specification first, then a module that implements this behaviour.
  """

  alias Truestamp.Verify.{Check, Instant}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.Rule

  @doc """
  The TIME and NISTTIME values a commitment entry carries, as pointers relative to the
  entry, with their class, for SHAPE's check 5 (section 10.2, step 7).
  """
  @callback commitment_times() :: [{Pointer.t(), Instant.class()}]

  @doc """
  The checks of DERIVE that read the evidence an entry at `at` carries, beyond the epoch and
  its inclusion proof (section 10.2, step 9 (d)): none for a chain whose evidence only a
  read confirms.
  """
  @callback evidence_checks(at :: Pointer.t(), entry :: map()) :: [Check.t()]

  @doc """
  LINK_CHAIN_ORDER (section 10.3) for an entropy object of this chain at `at`, held to the
  top-level entry of the same chain on the same network.
  """
  @callback chain_order(at :: Pointer.t(), object :: map(), entry :: map()) :: Check.t()

  @doc """
  Whether a block record's `metadata.genesis` carries an object of this chain, which CHAIN
  reads (section 10.4, `genesis.bitcoin`) and POLICY compares with the commitment pin.
  """
  @callback genesis?() :: boolean()

  @doc """
  The network whose sources must give the chain's production identity, and that identity's
  read kind (section 10.2, step 0): `{production_network, kind}`.
  """
  @callback identity() :: {String.t(), atom()}

  @doc """
  Whether an identity read's fields show the chain's production network (section 10.2, step
  0): `{:ok, boolean}`, or `:error` for fields that do not hold the identity.
  """
  @callback production_identity?(fields :: map()) :: {:ok, boolean()} | :error

  @doc "The CHAIN rule of section 10.4 for a commitment entry, against one source."
  @callback commitment(Rule.context(), entry :: map()) :: Rule.outcome()

  @doc """
  The CHAIN rule of section 10.4 for a genesis object of this chain, against one source;
  only a chain whose `genesis?/0` is true is asked.
  """
  @callback genesis(Rule.context(), object :: map()) :: Rule.outcome()

  @optional_callbacks genesis: 2
end
