# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Sources.Esplora do
    @moduledoc """
    A Bitcoin source (`Truestamp.Verify.Source`) that reads an Esplora HTTP API, such as
    Blockstream's or mempool.space's, which serve the same API.

    Options: `:base_url`, or `:preset`, one of the presets below; `:receive_timeout` in
    milliseconds (5,000 by default); and `:req_options`, further options for Req.

    | Preset | Base URL |
    |---|---|
    | `:blockstream` | `https://blockstream.info/api` |
    | `:blockstream_testnet` | `https://blockstream.info/testnet/api` |
    | `:mempool` | `https://mempool.space/api` |
    | `:mempool_testnet` | `https://mempool.space/testnet/api` |
    | `:mempool_testnet4` | `https://mempool.space/testnet4/api` |
    | `:mempool_signet` | `https://mempool.space/signet/api` |

    | Read | Calls | Fields |
    |---|---|---|
    | `:bitcoin_identity` | `GET /block-height/0` | `hash` |
    | `:bitcoin_tip` | `GET /blocks/tip/height` | `height` |
    | `:bitcoin_block_at_height` | `GET /block-height/<height>`, then `GET /block/<hash>` | `hash`, `median_time_past` (`mediantime`), `transaction_count` (`tx_count`) |
    | `:bitcoin_block` | `GET /block/<hash>` | `height`, `median_time_past` (`mediantime`), `time` (`timestamp`) |

    A 404 is not found: for a height above the tip, or a block the server does not hold.

    The block at a height is two calls (SPEC.md section 10.4, "Answers"). When the first
    answers with a hash and the second gives no usable answer or not found, whatever the
    cause (a transport failure, a status, a 404, a body that does not parse or is not an
    object), the read is found with the hash alone, and the first call's meta, and the
    engine judges it on the fields its rule uses. Every body is parsed under J2 to J6 of
    section 10.1 in every member, so a block whose unused `difficulty` is 2^53 or more is no
    usable answer, and leaves the hash alone. This is deliberate, as section 10.4 says.
    """

    @behaviour Truestamp.Verify.Source

    alias Truestamp.Verify.Sources.HTTP

    @presets %{
      blockstream: "https://blockstream.info/api",
      blockstream_testnet: "https://blockstream.info/testnet/api",
      mempool: "https://mempool.space/api",
      mempool_testnet: "https://mempool.space/testnet/api",
      mempool_testnet4: "https://mempool.space/testnet4/api",
      mempool_signet: "https://mempool.space/signet/api"
    }

    @doc "The base URL of each preset."
    @spec presets() :: %{atom() => String.t()}
    def presets, do: @presets

    @impl true
    def kinds, do: [:bitcoin_identity, :bitcoin_tip, :bitcoin_block_at_height, :bitcoin_block]

    @impl true
    def describe(options), do: "esplora " <> base_url(options)

    @impl true
    def read(options, :bitcoin_identity, %{}) do
      with {:ok, body, meta} <- get(options, "/block-height/0"),
           do: {:ok, %{"hash" => text(body)}, meta}
    end

    def read(options, :bitcoin_tip, %{}) do
      with {:ok, body, meta} <- get(options, "/blocks/tip/height"),
           {:ok, height} <- integer(text(body)),
           do: {:ok, %{"height" => height}, meta}
    end

    def read(options, :bitcoin_block_at_height, %{"height" => height}) when is_integer(height) do
      with {:ok, body, meta} <- get(options, "/block-height/#{height}"),
           hash = text(body),
           :ok <- hex64(hash) do
        case block(options, hash) do
          {:ok, block, block_meta} ->
            fields = %{
              "hash" => hash,
              "median_time_past" => block["mediantime"],
              "transaction_count" => block["tx_count"]
            }

            {:ok, fields, block_meta}

          _no_block ->
            {:ok, %{"hash" => hash}, meta}
        end
      end
    end

    def read(options, :bitcoin_block, %{"hash" => hash}) when is_binary(hash) do
      with {:ok, block, meta} <- block(options, hash) do
        fields = %{
          "height" => block["height"],
          "median_time_past" => block["mediantime"],
          "time" => block["timestamp"]
        }

        {:ok, fields, meta}
      end
    end

    defp block(options, hash) do
      with :ok <- hex64(hash),
           {:ok, body, meta} <- get(options, "/block/" <> hash),
           {:ok, %{} = block} <- HTTP.json(body) do
        {:ok, block, meta}
      else
        {:ok, _not_an_object} -> {:error, :malformed_answer}
        other -> other
      end
    end

    # A hash goes into a path only when it is 64 lowercase hex characters.
    defp hex64(hash),
      do: if(hash =~ ~r/\A[0-9a-f]{64}\z/, do: :ok, else: {:error, :malformed_answer})

    defp get(options, path),
      do: HTTP.request(options(options), describe(options), method: :get, url: path)

    defp options(options), do: Keyword.put(options, :base_url, base_url(options))

    defp base_url(options) do
      case {Keyword.get(options, :base_url), Keyword.get(options, :preset)} do
        {url, nil} when is_binary(url) -> url
        {nil, preset} when is_map_key(@presets, preset) -> Map.fetch!(@presets, preset)
        _other -> raise ArgumentError, "an Esplora source needs :base_url or a known :preset"
      end
    end

    defp text(body), do: String.trim(body)

    defp integer(text) do
      case Integer.parse(text) do
        {n, ""} -> {:ok, n}
        _other -> {:error, :malformed_answer}
      end
    end
  end
end
