# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Rules do
  @moduledoc """
  Helpers for the tests of the rules of SPEC.md section 10.4: a rule context whose reads
  answer from a map of `{kind, params}` to an answer, written in the engine's shape
  (`Truestamp.Verify.Online.Answer`); a read it does not hold is unreachable.

  The context is the one a caller outside a run builds: `Truestamp.Verify.Online.Rule.new/2`
  over a reader (`Truestamp.Verify.Test.FakeReader`) whose answers are these, written back
  in a reader's shapes, so every rule test reads through the engine's side of every read.
  """

  alias Truestamp.Verify.Online.Rule
  alias Truestamp.Verify.Test.FakeReader

  @source "test"
  @network "test"
  @meta %{source: @source, fetched_at: ~U[2026-10-16 12:00:00Z], cached: false}

  @doc "A context answering from `answers`."
  @spec context(map(), keyword()) :: Rule.context()
  def context(answers, options \\ []) do
    scripted =
      Map.new(answers, fn {{kind, params}, answer} ->
        {{@source, @network, kind, params}, reader_answer(answer)}
      end)

    Rule.new(FakeReader.new(scripted),
      source: @source,
      network: @network,
      part: Keyword.get(options, :part, "/part"),
      top_level?: Keyword.get(options, :top_level?, true)
    )
  end

  # An answer in the engine's shape, as a reader gives it.
  defp reader_answer({:found, fields, meta}), do: {:ok, fields, meta}
  defp reader_answer({:not_found, meta}), do: {:error, :not_found, meta}
  defp reader_answer({:unreachable, reason}), do: {:error, reason}

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
