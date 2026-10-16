# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyringSource do
  @moduledoc """
  The contract for reading a keyring online (SPEC.md sections 8.3 and 10.2, step 0): the
  keyring Truestamp publishes, which governs an external verifier's online run under `prod`
  (the `:current_keyring` option), or one read from another origin (the trust
  `{:keyring_source, ...}`, the CLI's `--base-url`).

  The channel is the source's own: `Truestamp.Verify.KeyringSources.WellKnown` reads
  `https://<host>/.well-known/keyring.json` over HTTPS, and a source that read a keyring
  published in DNS, or anywhere else, would implement this same callback.

  The engine judges what comes back: the bytes, or the value of a replay, go through the
  load checks of step 0, and any failure, for any reason, is a failed read, so key binding
  fails with `keyring_unavailable` whatever the key (section 8.3).
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
