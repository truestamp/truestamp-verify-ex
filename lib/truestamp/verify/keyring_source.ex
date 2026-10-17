# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyringSource do
  @moduledoc """
  The contract for reading a keyring online (SPEC.md sections 8.3 and 10.2, step 0): the
  keyring Truestamp publishes at `https://www.truestamp.com/.well-known/keyring.json`, which
  governs an external verifier's online run under `prod` (the `:current_keyring` option), or
  one read from anywhere else (the trust `{:keyring_source, ...}`, the CLI's `--base-url`),
  which is a supplied keyring.

  The channel is the source's own: `Truestamp.Verify.KeyringSources.WellKnown` reads
  `https://<host>/.well-known/keyring.json` over HTTPS. A source for another channel, such
  as DNS or a file a deployment ships, implements this same callback, and gives a supplied
  keyring: only the keyring read from Truestamp's URL attributes a proof to Truestamp
  (section 10.5), so a `:current_keyring` whose `location` is any other is a
  `configuration_error`.

  The engine judges what comes back: the bytes, or the value of a replay, go through the
  load checks of step 0, and any failure, for any reason, is a failed read, so key binding
  fails with `keyring_unavailable` whatever the key (section 8.3). The keyring is the one
  read in this run, so an answer whose `meta` says `cached: true` is a failed read too.
  """

  alias Truestamp.Verify.Online.Answer

  @typedoc "What a read gives: the keyring's bytes, or a JSON value with no bytes of its own."
  @type keyring :: {:bytes, binary()} | {:value, term()}

  @doc """
  Reads the keyring: `{:ok, keyring, location, meta}`, where `location` names where it came
  from (a URL), or `{:error, reason}`.
  """
  @callback fetch(state :: term()) ::
              {:ok, keyring(), location :: String.t(), Answer.meta()} | {:error, term()}
end
