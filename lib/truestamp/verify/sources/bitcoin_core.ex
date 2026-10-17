# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Sources.BitcoinCore do
    @moduledoc """
    A Bitcoin source (`Truestamp.Verify.Source`) that reads a Bitcoin Core node over its
    JSON-RPC interface. A regtest chain has no public source, so its operator points at a
    node of their own (SPEC.md section 9).

    Options: `:base_url`, the node's RPC URL, such as `http://127.0.0.1:8332`; the
    credentials, either `:user` and `:password`, or `:cookie`, the path of the node's
    `.cookie` file; `:receive_timeout` in milliseconds (5,000 by default); and
    `:req_options`, further options for Req.

    | Read | Calls | Fields |
    |---|---|---|
    | `:bitcoin_identity` | `getblockhash 0` | `hash` |
    | `:bitcoin_tip` | `getblockcount` | `height` |
    | `:bitcoin_block_at_height` | `getblockhash <height>`, then `getblockheader <hash>` | `hash`, `median_time_past` (`mediantime`), `transaction_count` (`nTx`) |
    | `:bitcoin_block` | `getblockheader <hash>` | `height`, `median_time_past` (`mediantime`), `time` |

    The RPC errors -8 (a height out of range) and -5 (a block not found) are not found.
    """

    @behaviour Truestamp.Verify.Source

    alias Truestamp.Verify.JCS
    alias Truestamp.Verify.Sources.HTTP

    # Bitcoin Core's RPC error codes for a height out of range and a block not found.
    @not_found [-8, -5]

    @impl true
    def kinds, do: [:bitcoin_identity, :bitcoin_tip, :bitcoin_block_at_height, :bitcoin_block]

    @impl true
    def describe(options), do: "bitcoin-core " <> Keyword.fetch!(options, :base_url)

    @impl true
    def read(options, :bitcoin_identity, %{}) do
      with {:ok, hash, meta} <- call(options, "getblockhash", [0]),
           do: {:ok, %{"hash" => hash}, meta}
    end

    def read(options, :bitcoin_tip, %{}) do
      with {:ok, height, meta} <- call(options, "getblockcount", []),
           do: {:ok, %{"height" => height}, meta}
    end

    def read(options, :bitcoin_block_at_height, %{"height" => height}) when is_integer(height) do
      with {:ok, hash, _meta} when is_binary(hash) <- call(options, "getblockhash", [height]),
           {:ok, %{} = header, meta} <- call(options, "getblockheader", [hash]) do
        {:ok,
         %{
           "hash" => hash,
           "median_time_past" => header["mediantime"],
           "transaction_count" => header["nTx"]
         }, meta}
      else
        {:ok, _malformed, _meta} -> {:error, :malformed_answer}
        other -> other
      end
    end

    def read(options, :bitcoin_block, %{"hash" => hash}) when is_binary(hash) do
      case call(options, "getblockheader", [hash]) do
        {:ok, %{} = header, meta} ->
          fields = %{
            "height" => header["height"],
            "median_time_past" => header["mediantime"],
            "time" => header["time"]
          }

          {:ok, fields, meta}

        {:ok, _malformed, _meta} ->
          {:error, :malformed_answer}

        other ->
          other
      end
    end

    # One JSON-RPC call: its result, not found for the codes above, or the error.
    defp call(options, method, params) do
      body = JCS.encode(%{"id" => "truestamp-verify", "method" => method, "params" => params})

      # Bitcoin Core answers an RPC error with HTTP 404 or 500 and a JSON body that names it,
      # so those bodies are read as the RPC's answer.
      request = [
        method: :post,
        url: "/",
        body: body,
        headers: [{"content-type", "application/json"}],
        body_statuses: [200, 404, 500]
      ]

      with {:ok, auth} <- auth(options),
           {:ok, bytes, meta} <- HTTP.request(options, describe(options), request ++ auth) do
        answer(HTTP.json(bytes), meta)
      end
    end

    defp answer({:ok, %{"error" => nil, "result" => result}}, meta), do: {:ok, result, meta}

    defp answer({:ok, %{"error" => %{"code" => code}}}, meta) when code in @not_found,
      do: {:error, :not_found, meta}

    defp answer({:ok, %{"error" => error}}, _meta) when error != nil,
      do: {:error, {:rpc_error, error}}

    defp answer(_other, _meta), do: {:error, :malformed_answer}

    defp auth(options) do
      case {Keyword.get(options, :user), Keyword.get(options, :password),
            Keyword.get(options, :cookie)} do
        {user, password, nil} when is_binary(user) and is_binary(password) ->
          {:ok, [auth: {:basic, "#{user}:#{password}"}]}

        {nil, nil, cookie} when is_binary(cookie) ->
          cookie(cookie)

        _other ->
          raise ArgumentError, "a Bitcoin Core source needs :user and :password, or :cookie"
      end
    end

    defp cookie(path) do
      case File.read(path) do
        {:ok, contents} -> {:ok, [auth: {:basic, String.trim(contents)}]}
        {:error, reason} -> {:error, {:cookie, reason}}
      end
    end
  end
end
