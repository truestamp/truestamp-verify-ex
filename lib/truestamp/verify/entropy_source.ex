# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.EntropySource do
  @moduledoc """
  What the engine needs of a public entropy source (SPEC.md sections 3.5, 10.2, 10.4 and
  11.2): everything about one source lives in one module, and the engine's steps hold no
  branch of their own for any source.

  The sources are the values an entropy object's `source` takes in the schema, today
  `bitcoin`, `nist` and `stellar` (`Truestamp.Verify.Chains`). As with the chains, the
  registry is closed: a new source is a change to the specification first.
  """

  alias Truestamp.Verify.Instant
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.Rule

  @doc """
  Whether the source's entropy objects carry a `network`, which POLICY compares with the
  entropy pin (section 10.2, step 8). NIST has no network.
  """
  @callback networked?() :: boolean()

  @doc """
  The TIME and NISTTIME values an entropy object carries, as pointers relative to the
  object, with their class, for SHAPE's check 5 (section 10.2, step 7).
  """
  @callback entropy_times() :: [{Pointer.t(), Instant.class()}]

  @doc "The SOURCES rule of section 10.4 for an entropy object, against one source."
  @callback entropy(Rule.context(), object :: map()) :: Rule.outcome()
end
