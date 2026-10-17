# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Sources.NistBeacon do
    @moduledoc """
    A NIST source (`Truestamp.Verify.Source`) that reads the Randomness Beacon's 2.0 API.

    Options: `:base_url`, `https://beacon.nist.gov/beacon/2.0` by default;
    `:receive_timeout` in milliseconds (5,000 by default); and `:req_options`, further
    options for Req.

    | Read | Calls | Fields |
    |---|---|---|
    | `:nist_pulse` | `GET /chain/<chainIndex>/pulse/<pulseIndex>` | `outputValue`, `timeStamp` (of `pulse`) |

    A pulse about another chain or pulse index than the one asked for is no usable answer. A
    404 is not found.
    """

    @behaviour Truestamp.Verify.Source

    alias Truestamp.Verify.Sources.HTTP

    @default_url "https://beacon.nist.gov/beacon/2.0"

    @impl true
    def kinds, do: [:nist_pulse]

    @impl true
    def describe(options), do: "nist " <> base_url(options)

    @impl true
    def read(options, :nist_pulse, %{"chainIndex" => chain, "pulseIndex" => pulse})
        when is_integer(chain) and is_integer(pulse) do
      options = Keyword.put(options, :base_url, base_url(options))

      with {:ok, body, meta} <-
             HTTP.request(options, describe(options),
               method: :get,
               url: "/chain/#{chain}/pulse/#{pulse}"
             ),
           {:ok, %{"pulse" => %{"chainIndex" => ^chain, "pulseIndex" => ^pulse} = read}} <-
             HTTP.json(body) do
        {:ok, %{"outputValue" => read["outputValue"], "timeStamp" => read["timeStamp"]}, meta}
      else
        {:ok, _another} -> {:error, :malformed_answer}
        other -> other
      end
    end

    defp base_url(options), do: Keyword.get(options, :base_url, @default_url)
  end
end
