# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Reader do
  @moduledoc """
  The contract between the engine and whatever answers the chain and source reads of
  SPEC.md section 10.4. A reader is given to a run as `{module, state}`, with the `:reader`
  option. Without one the run is offline: every CHAIN and SOURCES row is `skip offline`.

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

  A reader names the sources it has for a chain and network with `c:Truestamp.Verify.Reader.sources/3`: one, or
  several under a policy that the engine applies to each row (`Truestamp.Verify.Online.Policy`).
  `"nist"` has no network, and is asked with network nil. Every source of a Stellar or
  Bitcoin network has its identity read at step 0 (section 10.2).

  ## What a reader owns, and what it does not

  A reader owns its transport: its URLs, timeouts, retries, rate limits, budgets and any
  cache. The engine owns every judgement of section 10.4, the same for every reader: it
  checks each field's class, refuses a cached answer where the spec requires a live read
  (identity, the Stellar root, the Bitcoin tip, and every not-found answer), keeps one answer
  per read for the whole run, enforces the run's deadline, and turns a reader that raises,
  throws or exits into an unreachable read. A reader need not, and should not, judge an
  answer against the proof.
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

  `meta` is `%{source: String.t(), fetched_at: DateTime.t(), cached: boolean()}`.
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
