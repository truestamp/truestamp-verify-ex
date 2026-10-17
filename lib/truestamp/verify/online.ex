# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Online do
    @moduledoc """
    The options of an online run with the bundled HTTP sources, ready to pass to
    `Truestamp.Verify.verify/2`:

        Truestamp.Verify.verify(proof_bytes, Truestamp.Verify.Online.defaults())

    `defaults/1` gives `:reader`, the compiled-in sources of `Truestamp.Verify.Readers.HTTP`,
    and `:current_keyring`, the keyring Truestamp publishes at
    `https://www.truestamp.com/.well-known/keyring.json`
    (`Truestamp.Verify.KeyringSources.WellKnown`). Its options:

    - `:sources`, sources in place of the defaults, in the form `Readers.HTTP.default/1`
      takes;
    - `:keyring_origin`, another origin for the keyring;
    - any other option of `Truestamp.Verify.verify/2`, such as `:environment` or
      `:deadline`, passed through.

    Needs Req: add `{:req, "~> 0.7"}` to the caller's dependencies.
    """

    alias Truestamp.Verify.KeyringSources.WellKnown
    alias Truestamp.Verify.Readers.HTTP

    @doc "The options of an online run (see the module doc)."
    @spec defaults(keyword()) :: keyword()
    def defaults(options \\ []) do
      {sources, options} = Keyword.pop(options, :sources, [])
      {origin, options} = Keyword.pop(options, :keyring_origin)
      keyring = if origin, do: WellKnown.new(base_url: origin), else: WellKnown.new()
      [reader: HTTP.default(sources), current_keyring: keyring] ++ options
    end
  end
end
