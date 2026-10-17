# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Sources.HTTP do
    @moduledoc false
    # What the HTTP sources share: one request through Req, and its answer as a source gives
    # it. Every request:
    #
    # - follows no redirect, since the operator pinned the server, not wherever it points;
    # - retries nothing, since a retry policy belongs to whoever wraps the source;
    # - keeps the body as bytes, which the source reads with the library's strict reader;
    # - takes the source's `:receive_timeout` (5 seconds by default), and any further Req
    #   options under `:req_options`, last, such as a test's `plug:`.
    #
    # A 200 answer, or one of the request's `:body_statuses`, is `{:ok, body, meta}`; a 404 is
    # `{:error, :not_found, meta}`; any other status is `{:error, {:http_status, status}}`,
    # and a transport failure `{:error, {:transport, reason}}`.

    alias Truestamp.Verify.JSON

    @doc false
    @spec request(keyword(), String.t(), keyword()) ::
            {:ok, binary(), map()} | {:error, :not_found, map()} | {:error, term()}
    def request(options, describe, request) do
      base = [
        base_url: Keyword.fetch!(options, :base_url),
        redirect: false,
        retry: false,
        decode_body: false,
        receive_timeout: Keyword.get(options, :receive_timeout, 5_000)
      ]

      {body_statuses, request} = Keyword.pop(request, :body_statuses, [200])
      req = Req.new(base ++ request ++ Keyword.get(options, :req_options, []))

      case Req.request(req) do
        {:ok, %Req.Response{status: status, body: body}} ->
          cond do
            status in body_statuses -> {:ok, body, meta(describe)}
            status == 404 -> {:error, :not_found, meta(describe)}
            true -> {:error, {:http_status, status}}
          end

        {:error, exception} ->
          {:error, {:transport, Exception.message(exception)}}
      end
    end

    @doc false
    # The JSON value of a body, read under the parsing rules of SPEC.md section 10.1; a body
    # that breaks them is no usable answer.
    @spec json(binary()) :: {:ok, term()} | {:error, :malformed_answer}
    def json(body) do
      case JSON.parse(body) do
        {:ok, value} -> {:ok, value}
        {:error, _reason} -> {:error, :malformed_answer}
      end
    end

    @doc false
    @spec meta(String.t()) :: map()
    def meta(describe), do: %{source: describe, fetched_at: DateTime.utc_now(), cached: false}
  end
end
