# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Rules do
  @moduledoc """
  Helpers for the tests of the rules of SPEC.md section 10.4: a rule context whose reads
  answer from a map of `{kind, params}` to an answer, already in the engine's shape
  (`Truestamp.Verify.Online.Answer`); a read it does not hold is unreachable.
  """

  alias Truestamp.Verify.Online.Rule

  @meta %{source: "test", fetched_at: ~U[2026-10-16 12:00:00Z], cached: false}

  @doc "A context answering from `answers`."
  @spec context(map(), keyword()) :: Rule.context()
  def context(answers, options \\ []) do
    read = fn kind, params -> Map.get(answers, {kind, params}, {:unreachable, :not_scripted}) end

    Rule.new(read,
      part: Keyword.get(options, :part, "/part"),
      top_level?: Keyword.get(options, :top_level?, true)
    )
  end

  @doc "A found answer with `fields`."
  @spec found(map()) :: tuple()
  def found(fields), do: {:found, fields, @meta}

  @doc "A not-found answer."
  @spec not_found() :: tuple()
  def not_found, do: {:not_found, @meta}

  @doc "An unreachable answer."
  @spec unreachable() :: tuple()
  def unreachable, do: {:unreachable, :test}

  @doc "The status and code of an outcome, as `{status, code}`."
  @spec verdict(Rule.Outcome.t()) :: {atom(), atom() | nil}
  def verdict(%Rule.Outcome{status: status, code: code}), do: {status, code}
end
