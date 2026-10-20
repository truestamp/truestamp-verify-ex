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

  ## Judging one entry outside a run

  These rules are public so that a caller can judge one commitment entry, `genesis.bitcoin`
  object or entropy object against one source without a whole proof, with the library's own
  judgement, the one a whole run makes. The caller writes a `Truestamp.Verify.Reader`, the
  same behaviour a run's `:reader` option takes, and judges nothing:

  1. once per chain and network, confirm the source's identity with `confirm_identity/2`,
     as a run's step 0 does; a source it leaves unconfirmed gives each entry the outcome
     `unconfirmed/1` returns;
  2. make the offline checks a run makes before it reads (see "What a run checks first");
  3. build a context over the reader with `new/2`, naming the source, the network, the
     entry's pointer and whether it is top-level;
  4. call the rule of the entry's module, and read its `Truestamp.Verify.Online.Rule.Outcome`.

  ```elixir
  alias Truestamp.Verify.{Chains, Check}
  alias Truestamp.Verify.Online.Rule

  reader = {MyApp.ChainReader, state}

  :ok = Rule.confirm_identity(reader, chain: "bitcoin", source: :node, network: "mainnet")

  true =
    Enum.all?(
      Chains.Bitcoin.evidence_checks(["commitments", "bitcoin"], entry),
      &match?(%Check{outcome: :pass}, &1)
    )

  context =
    Rule.new(reader,
      source: :node,
      network: "mainnet",
      part: "/commitments/bitcoin",
      top_level?: true,
      deadline: 10_000
    )

  %Rule.Outcome{status: :pass, candidate: edge} = Chains.Bitcoin.commitment(context, entry)
  ```

  The rule for each value:

  | Value | Rule | `top_level?` |
  |---|---|---|
  | a commitment entry at `/commitments/C` | `c:Truestamp.Verify.CommitmentChain.commitment/2` of `Truestamp.Verify.Chains.Stellar` or `Truestamp.Verify.Chains.Bitcoin` | `true`: it gives a candidate for the submitted-before edge |
  | a commitment entry at `/signing_key_event/commitments/C` | the same | `false`: no candidate read (section 11.1) |
  | a `genesis.bitcoin` object | `c:Truestamp.Verify.CommitmentChain.genesis/2` of `Truestamp.Verify.Chains.Bitcoin` | `false` |
  | an entropy object | `c:Truestamp.Verify.EntropySource.entropy/2` of `Truestamp.Verify.Chains.Nist`, `Stellar` or `Bitcoin` | either: it gives a candidate for the submitted-after edge |

  A context over a reader reads under the same rules as a whole run
  (`Truestamp.Verify.Reader`, "What a reader owns, and what it does not"): the engine
  normalizes every answer, refuses a cached answer where SPEC.md 10.4 requires a live read,
  accepts a cached best-chain Bitcoin block at a height only under the tip its meta names,
  holds the reads to the deadline, and turns a reader that raises, throws or exits into an
  unreachable read, so neither the context nor the rule ever raises on what a reader does.
  Which process makes each read is in `Truestamp.Verify.Reader`, "Processes". For a value
  that passes the checks a run makes first, the outcome is the one a whole run gives that
  source for that entry: its `status` and `code`, its candidate, and in `values` every read
  made, as `read/3` records it. What differs from a run is only what a run adds around the
  rule: SHAPE and DERIVE before it, several sources combined by a policy
  (`Truestamp.Verify.Online.Policy`), the identity confirmation, and one answer per read
  kept across the run's rows. Each call of a rule reads afresh.

  ### What a run checks first

  A run reaches a rule only after SHAPE and DERIVE have passed (SPEC.md section 10.2, the
  external gate). A rule compares what it reads with values the entry carries and checks
  nothing offline, so a caller makes DERIVE's checks of the value itself:

  - **A Bitcoin commitment entry.** Require every check of
    `c:Truestamp.Verify.CommitmentChain.evidence_checks/2` of
    `Truestamp.Verify.Chains.Bitcoin` to pass, as in the example, before `commitment/2`.
    Bitcoin's rule compares the block at the entry's height with the `header_hash` and
    `total_txs` the entry carries, and nothing more: it passes an entry whose transaction
    commits another epoch, or none. Those checks tie the transaction to the header and its
    OP_RETURN to the epoch hash computed from `epoch.record`; the rule then places that
    header on the best chain, and SPEC.md 10.4 takes both to pass a Bitcoin entry.
  - **A Stellar commitment entry.** Its rule computes the epoch hash from `epoch.record`
    itself, and compares the transaction's memo with it.
  - **An entropy object.** Recompute its `entropy_hash` as DERIVE does,
    `Truestamp.Verify.Hash.hash_hex(:entropy_hash, object)`, and compare it with the
    `entropy_hash` that names the object. SOURCES reads only an entropy object whose
    `entropy_hash` was recomputed and matched (SPEC.md section 10.4).

  **A value SHAPE would refuse.** A whole run reaches a rule only after SHAPE has passed, so
  every member the rule reads is present and in its class. A rule called directly can be
  given any JSON value, and it never raises on one: it reads the members it needs through
  `carried/3`, and when any is missing or out of its class it makes no read and fails with
  `shape_invalid`, its values naming those members under `"unshaped"`
  (`Truestamp.Verify.Chains.Bitcoin` gives one more outcome, for a `txoutproof` that is
  hex but not well formed).
  """

  alias Truestamp.Verify.{Chains, Edge, ReasonCodes, Spec}
  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Online.{Answer, Frame, Reads}

  @typedoc "The read function: a read's kind and parameters, to its answer."
  @type read_fun :: (atom(), map() -> Answer.t())

  @typedoc """
  A reader, `{module, state}`, the module implementing `Truestamp.Verify.Reader`: the form
  a run's `:reader` option takes.
  """
  @type reader :: {module(), term()}

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

  @doc """
  A rule's context for the row at `part`, whose reads go to `read`: a reader, or a read
  function.

  **Over a reader** `{module, state}` (`Truestamp.Verify.Reader`), every read goes to one
  of its sources on one network, through the engine's side of every read, as in a whole
  run (see the module doc). Options:

  | Option | Value | Default |
  |---|---|---|
  | `:source` | the source to read, as the reader's `c:Truestamp.Verify.Reader.sources/3` names it | required |
  | `:network` | the network to read, a string as a run's pins name it, such as `"mainnet"`; nil for NIST | required |
  | `:part` | the pointer of the entry or object, which the outcome's candidate names | required |
  | `:top_level?` | whether the entry is top-level (only a top-level commitment entry reads and gives a candidate, section 11.1) | `true` |
  | `:deadline` | milliseconds, from this call, that the rule's reads may take: a read past it is unreachable with the reason `:deadline`, and a read it cuts short is stopped; nil for none | nil |

  An option missing, unknown, or holding a value it cannot take raises: a caller that writes
  its options wrong has a defect, not an outcome. `:source` is any term the reader names.

  With no `:deadline`, each read runs in the calling process; with one, each runs in a task
  the deadline can cut short, its `$callers` holding the caller (`Truestamp.Verify.Reader`,
  "Processes").

  **Over a read function** `(kind, params -> answer)`, the function's answers are taken as
  they come, already in `t:Truestamp.Verify.Online.Answer.t/0`'s shapes, and none of the
  engine's read rules applies: a function that raises raises through the rule, and an
  answer from a cache is judged as if it were live. The caller then owns SPEC.md 10.4's
  rules for those reads. Only `:part`, required, and `:top_level?` are read.
  """
  @spec new(reader() | read_fun(), keyword()) :: context()
  def new(read, options) when is_function(read, 2) do
    %__MODULE__{
      read: read,
      part: Keyword.fetch!(options, :part),
      top_level?: Keyword.get(options, :top_level?, true)
    }
  end

  def new({module, _state} = reader, options) when is_atom(module) do
    options =
      Keyword.validate!(options, [:source, :network, :part, top_level?: true, deadline: nil])

    [source, network, part] =
      for name <- [:source, :network, :part], do: Keyword.fetch!(options, name)

    unless is_binary(part), do: raise(ArgumentError, "part: not a pointer: #{inspect(part)}")

    unless is_binary(network) or is_nil(network),
      do: raise(ArgumentError, "network: not a network's name: #{inspect(network)}")

    unless is_boolean(options[:top_level?]),
      do: raise(ArgumentError, "top_level?: not a boolean: #{inspect(options[:top_level?])}")

    %__MODULE__{
      read: Reads.bind(reader, source, network, %{}, deadline(options[:deadline])),
      part: part,
      top_level?: options[:top_level?]
    }
  end

  @doc """
  Confirms that `source`, a source of `reader`, serves the network the caller pins, as a
  run's step 0 does for every Stellar and Bitcoin source before it reads anything else
  (SPEC.md section 10.2): one live read of the chain's identity, judged against the
  network. It gives:

  - `:ok`: the source serves that network; judge entries with it;
  - `:forbidden`: it shows another network, such as the production identity on a source
    pinned to a test network, or the reverse; a run would be a `configuration_error`, and
    no entry is to be judged with it;
  - `{:unreachable, reason}`: no usable answer, whether the read was unreachable, gave the
    reason `:identity_not_found`, or gave fields that hold no identity
    (`:identity_unusable`); a run reads nothing more from such a source, no entry is to be
    judged with it, and the outcome each of its entries has is `unconfirmed(reason)`.

  Options: `:chain`, `"stellar"` or `"bitcoin"` (NIST has no identity read); `:network`, a
  network `Truestamp.Verify.Spec.networks/0` names for that chain, such as `"mainnet"`; and
  `:source` and `:deadline` as `new/2` takes them. An option missing, unknown or out of its values raises. The read goes
  through the engine's side of every read, so an identity answer marked cached is
  unreachable, and it runs in the calling process or a task, as a read of `new/2` does.

  How often to confirm is the caller's choice. A run confirms each source once, before its
  first read; a caller that judges many entries can confirm each source once per chain and
  network and keep the result for as long as it trusts the source to stay on that network.
  """
  @spec confirm_identity(reader(), keyword()) :: :ok | :forbidden | {:unreachable, term()}
  def confirm_identity({module, _state} = reader, options) when is_atom(module) do
    options = Keyword.validate!(options, [:chain, :source, :network, deadline: nil])

    [name, source, network] =
      for key <- [:chain, :source, :network], do: Keyword.fetch!(options, key)

    chain =
      Chains.commitment_chain(name) ||
        raise ArgumentError, "chain: not a commitment chain: #{inspect(name)}"

    unless network in Map.fetch!(Spec.networks(), name),
      do: raise(ArgumentError, "network: not a network of #{name}: #{inspect(network)}")

    {production, kind} = chain.identity()
    answer = Reads.read(reader, source, network, kind, %{}, deadline(options[:deadline]))
    Frame.judge(chain, answer, network == production)
  end

  @doc """
  The outcome a whole run gives an entry against a source whose identity read left it
  unconfirmed, `{:unreachable, reason}` from `confirm_identity/2`: `skip
  source_unreachable`, with no read made, its `values` naming the reason under
  `"identity"` as `Truestamp.Verify.Online.Answer.describe/1` writes it, such as
  `%{"identity" => "identity_not_found"}`.
  """
  @spec unconfirmed(term()) :: outcome()
  def unconfirmed(reason),
    do: %Outcome{
      status: :skip,
      code: :source_unreachable,
      values: %{"identity" => Answer.describe(reason)}
    }

  defp deadline(nil), do: nil

  defp deadline(milliseconds) when is_integer(milliseconds) and milliseconds >= 0,
    do: System.monotonic_time(:millisecond) + milliseconds

  defp deadline(other),
    do: raise(ArgumentError, "deadline: not a number of milliseconds: #{inspect(other)}")

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
