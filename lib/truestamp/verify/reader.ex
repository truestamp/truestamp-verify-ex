# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Reader do
  @moduledoc """
  The contract between the engine and whatever answers the chain and source reads of
  SPEC.md section 10.4. A reader is given to a run as `{module, state}`, with the `:reader`
  option. Without one the run makes no read and runs offline (section 10.2): each CHAIN and
  SOURCES row is `skip offline`, or `skip prior_failure` when a row before it failed.

  The reads are named exactly as section 13.2's replay files name them, so the contract and
  a replay file match one to one:

  | Kind | Parameters | Fields of a found answer |
  |---|---|---|
  | `:stellar_identity` | | `network_passphrase` |
  | `:stellar_root` | | `elder`, `latest` |
  | `:stellar_transaction` | `hash` | `ledger`, `memo_type`, `successful`, and `memo` (hex) when `memo_type` is `hash` or `return` |
  | `:stellar_ledger` | `sequence` | `closed_at`, `hash` |
  | `:bitcoin_identity` | | `hash` (of the block at height 0) |
  | `:bitcoin_tip` | | `height` |
  | `:bitcoin_block_at_height` | `height` | `hash`, `median_time_past`, `transaction_count` |
  | `:bitcoin_block` | `hash` | `height`, `median_time_past`, `time` |
  | `:nist_pulse` | `chainIndex`, `pulseIndex` | `outputValue`, `timeStamp` |

  Each parameter is spelled as the proof spells the value it comes from. Bitcoin hashes are
  in display order, Bitcoin times are Unix seconds, and a memo is its 32 bytes in lowercase
  hex.

  ## Sources and policies

  A reader names the sources it has for a chain and network with
  `c:Truestamp.Verify.Reader.sources/3`: one, or several under a policy that the engine
  applies to each row (`Truestamp.Verify.Online.Policy`). `"nist"` has no network, and is
  asked with network nil; NIST's Randomness Beacon is one source (section 9). Every source
  of a Stellar or Bitcoin network has its identity read at step 0 (section 10.2), and a
  policy `{:at_least, n}` takes n from 1 to the number of the network's sources; a reader
  that breaks either rule, or names several NIST sources, makes the run a
  `configuration_error`. Each source's answers are its own: the engine keeps one answer per
  read and source, and never lets one source's answer stand as another's.

  ## What a reader owns, and what it does not

  A reader owns its transport: its URLs, timeouts, retries, rate limits, budgets and any
  cache. The engine owns every judgement of section 10.4, the same for every reader: it
  judges each answer on the fields its rule reads at that point, each in its class, refuses
  a cached answer where the spec requires a live read (identity, the Stellar root, the
  Bitcoin tip, and every not-found answer) and a cached best-chain Bitcoin block at a height
  read under a tip that was not final (see "Caches"), keeps one found or not-found answer
  per read for the whole run, and none that was unreachable, enforces the run's deadline,
  and turns a reader that raises, throws or exits into an unreachable read. A reader need
  not, and should not, judge an answer against the proof. The same holds outside a run, for
  one entry judged through `Truestamp.Verify.Online.Rule.new/2` over a reader.

  ## Caches

  A reader that answers from a cache says so with `cached: true` in the answer's meta, and
  the engine decides whether the answer stands (section 10.4):

  | Read | A cached found answer |
  |---|---|
  | `:stellar_identity`, `:bitcoin_identity`, `:stellar_root`, `:bitcoin_tip` | refused: always read live |
  | `:bitcoin_block_at_height`, at height g | kept when its meta carries `tip_height`, the INT height of the source's tip when the block was read, of at least g + BITCOIN_FINALITY (10); refused with no `tip_height`, or a shorter one |
  | `:stellar_transaction`, `:stellar_ledger`, `:bitcoin_block`, `:nist_pulse` | kept: a read by hash, by ledger sequence or by pulse index cannot change |

  A not-found answer marked cached is refused for every read. A refused answer is an
  unreachable read, so a reader whose cache cannot give a fact the engine needs should read
  live instead. A reader's cache answers a read of a source only with an answer that same
  source gave, on that chain and network (section 10.4): the engine cannot tell where a
  cached answer came from, so this rule is the reader's to keep. `tip_height` is the
  reader's report of what its cache recorded, a transport fact; the engine compares it with
  g. The readers this library ships cache nothing: every answer of
  `Truestamp.Verify.Readers.HTTP` and `Truestamp.Verify.Readers.Replay` is `cached: false`,
  with no `tip_height`.

  ## Processes

  A read may run in a process other than the one that asked for it. In a run, the process
  that called `Truestamp.Verify.verify/2`:

  - step 0's identity reads run at once, each in a task of its own, in every online run;
  - in a run with a deadline (the `:deadline` option), every read runs in a task that the
    deadline can cut short.

  Outside a run, through a context of `Truestamp.Verify.Online.Rule.new/2` over a reader or
  through `Truestamp.Verify.Online.Rule.confirm_identity/2`, a read runs in the calling
  process when the call gives no `:deadline`, and in a task the deadline can cut short when
  it gives one.

  Each such task is started with `Task` by the calling process, or by a task it started, so
  its `$callers` holds the calling process and the processes that started it. Whatever
  finds its owner through `$callers` reaches the read: `Req.Test` stubs, Mox expectations
  and NimbleOwnership allowances among them, so a test's stubs apply. Nothing else of the
  calling process does: its process dictionary, its Logger metadata and its mailbox stay
  with it. A reader that needs such state carries it in its `state`, or finds it through
  `$callers`, and so reads the same in a task and out of one. The engine judges every
  answer in the calling process, in the order of section 10.2, so reads made at once change
  no outcome and no row.
  """

  alias Truestamp.Verify.Online.Answer

  @typedoc "A source of a reader, as the reader names it."
  @type source_id :: term()

  @typedoc """
  How several sources of one network combine (`Truestamp.Verify.Online.Policy`): `:first`,
  `{:at_least, n}` or `:all`.
  """
  @type policy :: :first | {:at_least, pos_integer()} | :all

  @doc """
  The sources the reader has for `chain` on `network`, in order, with their policy; or
  `{:error, reason}` when it has none, which makes an online run that pins that network a
  `configuration_error` (section 10.2, step 0).
  """
  @callback sources(state :: term(), chain :: String.t(), network :: String.t() | nil) ::
              {:ok, [source_id(), ...], policy()} | {:error, term()}

  @doc """
  One read of `kind` with `params`, from `source`, on `network` (nil for NIST):

  - `{:ok, fields, meta}`: found;
  - `{:error, :not_found, meta}`: the source answered that it holds no such object;
  - `{:error, reason}`: no usable answer.

  `meta` is `%{source: String.t(), fetched_at: DateTime.t(), cached: boolean()}`, with
  `tip_height` beside them for a cached `:bitcoin_block_at_height` (see "Caches").
  """
  @callback read(
              state :: term(),
              source :: source_id(),
              network :: String.t() | nil,
              kind :: atom(),
              params :: map()
            ) ::
              {:ok, map(), Answer.meta()} | {:error, :not_found, Answer.meta()} | {:error, term()}
end
