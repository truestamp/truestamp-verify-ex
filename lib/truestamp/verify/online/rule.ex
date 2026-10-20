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

  **A value SHAPE would refuse.** A whole run reaches a rule only after SHAPE has passed, so
  every member the rule reads is present and in its class. A rule called directly can be
  given any JSON value, and it never raises on one: it reads the members it needs through
  `carried/3`, and when any is missing or out of its class it makes no read and fails with
  `shape_invalid`, its values naming those members under `"unshaped"`
  (`Truestamp.Verify.Chains.Bitcoin` gives one more outcome, for a `txoutproof` that is
  hex but not well formed).
  """

  alias Truestamp.Verify.{Edge, ReasonCodes}
  alias Truestamp.Verify.JSON.Pointer
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

  @typedoc """
  The class of a member a rule reads from the value the proof carries: a class of a field
  (`t:Truestamp.Verify.Online.Answer.class/0`), or `:object`, a JSON object, or
  `:hexbytes`, lowercase hex of one or more octets (the schema's HEXBYTES).
  """
  @type carried_class :: Answer.class() | :object | :hexbytes

  @doc """
  The members `members` of `value`, the entry or object the proof carries, each
  `{path, class}` with `path` its segments: `{:ok, values}`, in the order of `members`,
  when every one is present and in its class, or else the outcome `fail shape_invalid`,
  with no read made, its values naming under `"unshaped"` each member missing or out of
  its class, as a pointer relative to `value`. A member's value is the one
  `Truestamp.Verify.Online.Answer.field/3` gives (a TIME's or a NISTTIME's instant in
  milliseconds), the object itself for `:object`, and the octets for `:hexbytes`.
  """
  @spec carried(context(), term(), [{[String.t()], carried_class()}]) ::
          {:ok, [term()]} | outcome()
  def carried(%__MODULE__{} = context, value, members) when is_list(members) do
    read = for {path, class} <- members, do: {path, member(value, path, class)}

    case for({path, :error} <- read, do: Pointer.encode(path)) do
      [] -> {:ok, for({_path, {:ok, member}} <- read, do: member)}
      unshaped -> fail(context, :shape_invalid, %{"unshaped" => unshaped})
    end
  end

  defp member(value, [name], class) when is_map(value), do: in_class(value, name, class)

  defp member(value, [name | rest], class) when is_map(value),
    do: member(value[name], rest, class)

  defp member(_value, _path, _class), do: :error

  defp in_class(value, name, :object) do
    case Map.fetch(value, name) do
      {:ok, object} when is_map(object) and not is_struct(object) -> {:ok, object}
      _other -> :error
    end
  end

  defp in_class(value, name, :hexbytes) do
    with {:ok, hex} when is_binary(hex) <- Map.fetch(value, name),
         true <- Regex.match?(~r/\A(?:[0-9a-f]{2})+\z/, hex) do
      {:ok, Base.decode16!(hex, case: :lower)}
    else
      _other -> :error
    end
  end

  defp in_class(value, name, class), do: Answer.field(value, name, class)

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
