# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Rule do
  @moduledoc """
  The frame of one rule of SPEC.md section 10.4 against one source: the reads it makes, in
  order, and the outcome it gives.

  A chain or source module (`Truestamp.Verify.CommitmentChain`,
  `Truestamp.Verify.EntropySource`) writes a rule as a pure function of a context and the
  value the proof carries. It reads through `read/3`, which threads the context so that
  every read and its answer are recorded for the row's `values`, and it ends with `pass/2`,
  `fail/3` or `skip/3`.

  The context's read function belongs to the engine, which binds it to one source and
  enforces what holds for every source alike: one answer
  per read in a run, a deadline over the run, no answer from a cache where the spec requires
  a live read, and no crash: a reader that raises gives an unreachable answer.

  These rules are public so that a caller can judge one commitment entry or entropy object
  against a source without a whole proof: build a context with `new/2`, then call the
  module's rule.
  """

  alias Truestamp.Verify.{Edge, ReasonCodes}
  alias Truestamp.Verify.Online.Answer

  @typedoc "The read function: a read's kind and parameters, to its answer."
  @type read_fun :: (atom(), map() -> Answer.t())

  @typedoc """
  A rule's context: the read function bound to one source, the part of the row, and whether
  the entry is top-level (only a top-level commitment entry gives a candidate, section 11.1).
  """
  @type context :: %__MODULE__{
          read: read_fun(),
          part: String.t(),
          top_level?: boolean(),
          reads: [map()]
        }

  @enforce_keys [:read, :part]
  defstruct [:read, :part, top_level?: true, reads: [], answers: []]

  defmodule Outcome do
    @moduledoc """
    The outcome of one rule against one source: its status and code, its `values`, and its
    candidate for an edge, when it passed and gave one.
    """

    @type t :: %__MODULE__{
            status: :pass | :fail | :skip,
            code: atom() | nil,
            values: map(),
            candidate: Edge.t() | nil,
            answers: [{atom(), map(), term()}]
          }

    @enforce_keys [:status, :code, :values]
    defstruct [:status, :code, :values, candidate: nil, answers: []]
  end

  @type outcome :: Outcome.t()

  @doc "A context whose reads go to `read`, for the row at `part`."
  @spec new(read_fun(), keyword()) :: context()
  def new(read, options) when is_function(read, 2) do
    %__MODULE__{
      read: read,
      part: Keyword.fetch!(options, :part),
      top_level?: Keyword.get(options, :top_level?, true)
    }
  end

  @doc "Makes the read of `kind` with `params`, and records it and its answer."
  @spec read(context(), atom(), map()) :: {Answer.t(), context()}
  def read(%__MODULE__{read: read, reads: reads, answers: answers} = context, kind, params)
      when is_atom(kind) and is_map(params) do
    answer = read.(kind, params)

    record =
      Map.merge(%{"kind" => Atom.to_string(kind), "params" => params}, Answer.to_values(answer))

    {answer, %{context | reads: [record | reads], answers: [{kind, params, answer} | answers]}}
  end

  @doc "The rule passes, with its candidate when it gives one."
  @spec pass(context(), Edge.t() | nil) :: outcome()
  def pass(context, candidate \\ nil) do
    values = values(context, %{})
    values = if candidate, do: Map.put(values, "candidate", Edge.to_map(candidate)), else: values

    %Outcome{
      status: :pass,
      code: nil,
      values: values,
      candidate: candidate,
      answers: Enum.reverse(context.answers)
    }
  end

  @doc "The rule fails with `code`, a contradiction; `values` say what was contradicted."
  @spec fail(context(), ReasonCodes.code(), map()) :: outcome()
  def fail(context, code, values \\ %{}),
    do: %Outcome{
      status: :fail,
      code: code,
      values: values(context, values),
      answers: Enum.reverse(context.answers)
    }

  @doc "The rule settles nothing: a skip with `code`; `values` say why."
  @spec skip(context(), ReasonCodes.code(), map()) :: outcome()
  def skip(context, code, values \\ %{}),
    do: %Outcome{
      status: :skip,
      code: code,
      values: values(context, values),
      answers: Enum.reverse(context.answers)
    }

  defp values(%__MODULE__{reads: reads}, values),
    do: Map.put(values, "reads", Enum.reverse(reads))

  @doc """
  Decides a found answer's checks, contradiction first (section 10.4): each check is
  `{name, result}`, where result is `:ok`, `:contradiction` or `:unusable` (a field it reads
  is missing or in another class). Gives `:ok` when every check holds,
  `{:contradiction, names}` when any field present contradicts the proof, even when another
  is unusable, and `{:unusable, names}` otherwise.
  """
  @spec decide([{String.t(), :ok | :contradiction | :unusable}]) ::
          :ok | {:contradiction, [String.t()]} | {:unusable, [String.t()]}
  def decide(checks) do
    contradictions = for {name, :contradiction} <- checks, do: name
    unusable = for {name, :unusable} <- checks, do: name

    cond do
      contradictions != [] -> {:contradiction, contradictions}
      unusable != [] -> {:unusable, unusable}
      true -> :ok
    end
  end

  @doc """
  One check of `decide/1`: the field read as `{:ok, value}` or `:error`, against the value
  `expected` by `equal`.
  """
  @spec compare({:ok, term()} | :error, term(), (term(), term() -> boolean())) ::
          :ok | :contradiction | :unusable
  def compare(field, expected, equal \\ &===/2)
  def compare(:error, _expected, _equal), do: :unusable

  def compare({:ok, value}, expected, equal),
    do: if(equal.(value, expected), do: :ok, else: :contradiction)
end
