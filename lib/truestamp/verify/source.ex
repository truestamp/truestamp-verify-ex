# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Source do
  @moduledoc """
  The contract of one source of `Truestamp.Verify.Readers.HTTP`: a server that answers some
  of the reads of SPEC.md section 10.4, such as one Horizon, one Esplora or one Bitcoin
  Core.

  A source is `{module, options}`. The module names the read kinds it answers, describes
  itself for a row's values, and makes each read, giving the shapes
  `c:Truestamp.Verify.Reader.read/5` gives: `{:ok, fields, meta}`,
  `{:error, :not_found, meta}`, or `{:error, reason}`.

  A source maps its server's answer onto the fields of the read kind
  (`Truestamp.Verify.Reader`'s table) and judges nothing: the engine checks every field's
  class and compares it with the proof. The bundled sources:

  | Module | Chain | Kinds |
  |---|---|---|
  | `Truestamp.Verify.Sources.Horizon` | Stellar | identity, root, transaction, ledger |
  | `Truestamp.Verify.Sources.Esplora` | Bitcoin | identity, tip, block at height, block |
  | `Truestamp.Verify.Sources.BitcoinCore` | Bitcoin | identity, tip, block at height, block |
  | `Truestamp.Verify.Sources.NistBeacon` | NIST | pulse |

  Any other module that implements this behaviour can serve its chain beside them, such as a
  paid API or an indexer of one's own.
  """

  alias Truestamp.Verify.Online.Answer

  @doc "The read kinds the source answers, such as `[:bitcoin_identity, :bitcoin_tip, ...]`."
  @callback kinds() :: [atom()]

  @doc "The source as a row's values name it, such as `\"esplora https://mempool.space/api\"`."
  @callback describe(options :: keyword()) :: String.t()

  @doc "One read of `kind` with `params`."
  @callback read(options :: keyword(), kind :: atom(), params :: map()) ::
              {:ok, map(), Answer.meta()} | {:error, :not_found, Answer.meta()} | {:error, term()}
end
