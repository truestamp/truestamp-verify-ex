# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.KeyringSources.WellKnown do
    @moduledoc """
    A `Truestamp.Verify.KeyringSource` that reads `/.well-known/keyring.json` over HTTPS from
    an origin: by default `https://www.truestamp.com`, whose keyring governs an external
    verifier's online run under `prod` (SPEC.md section 8.3), or another origin, as the CLI's
    `--base-url` names one.

    It gives the keyring's bytes as read, which the engine loads through the load checks of
    step 0 and whose SHA-256 is the trust root's digest. Any failure, a status other than 200
    included, is a failed read, and no key binds.

    Options: `:base_url`; `:receive_timeout` in milliseconds (5,000 by default); and
    `:req_options`, further options for Req.
    """

    @behaviour Truestamp.Verify.KeyringSource

    alias Truestamp.Verify.Sources.HTTP

    @default_origin "https://www.truestamp.com"
    @path "/.well-known/keyring.json"

    @doc "The source of the keyring at the origin `options[:base_url]`, Truestamp's by default."
    @spec new(keyword()) :: {module(), keyword()}
    def new(options \\ []), do: {__MODULE__, Keyword.put_new(options, :base_url, @default_origin)}

    @impl true
    def fetch(options) do
      url = Keyword.fetch!(options, :base_url) <> @path

      case HTTP.request(options, url, method: :get, url: @path) do
        {:ok, bytes, meta} -> {:ok, {:bytes, bytes}, url, meta}
        {:error, :not_found, _meta} -> {:error, :not_found}
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
