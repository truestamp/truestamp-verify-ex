# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

if Code.ensure_loaded?(Req) do
  defmodule Truestamp.Verify.Sources.Horizon do
    @moduledoc """
    A Stellar source (`Truestamp.Verify.Source`) that reads a Horizon server.

    Options: `:base_url`, such as `https://horizon.stellar.org` (the network `public`) or
    `https://horizon-testnet.stellar.org` (the network `testnet`); `:receive_timeout` in
    milliseconds (5,000 by default); and `:req_options`, further options for Req.

    | Read | Calls | Fields |
    |---|---|---|
    | `:stellar_identity` | `GET /` | `network_passphrase` |
    | `:stellar_root` | `GET /` | `latest` (`history_latest_ledger`), `elder` (`history_elder_ledger`) |
    | `:stellar_transaction` | `GET /transactions/<hash>` | `successful`, `memo_type`, `ledger`, and `memo` as the lowercase hex of its 32 bytes when `memo_type` is `hash` or `return` |
    | `:stellar_ledger` | `GET /ledgers/<sequence>` | `closed_at`, `hash` |

    Horizon writes a memo in standard base64 with padding; one that is not the canonical
    spelling of 32 bytes is left out, so the engine finds the field missing. An answer about
    another transaction or ledger than the one asked for is no usable answer. A 404 is not
    found.
    """

    @behaviour Truestamp.Verify.Source

    alias Truestamp.Verify.Sources.HTTP

    @impl true
    def kinds, do: [:stellar_identity, :stellar_root, :stellar_transaction, :stellar_ledger]

    @impl true
    def describe(options), do: "horizon " <> Keyword.fetch!(options, :base_url)

    @impl true
    def read(options, :stellar_identity, %{}) do
      with {:ok, root, meta} <- object(options, "/"),
           do: {:ok, %{"network_passphrase" => root["network_passphrase"]}, meta}
    end

    def read(options, :stellar_root, %{}) do
      with {:ok, root, meta} <- object(options, "/") do
        {:ok,
         %{"elder" => root["history_elder_ledger"], "latest" => root["history_latest_ledger"]},
         meta}
      end
    end

    def read(options, :stellar_transaction, %{"hash" => hash}) when is_binary(hash) do
      with :ok <- hex64(hash),
           {:ok, tx, meta} <- object(options, "/transactions/" <> hash),
           :ok <- same(tx["hash"], hash) do
        fields =
          %{
            "ledger" => tx["ledger"],
            "memo_type" => tx["memo_type"],
            "successful" => tx["successful"]
          }
          |> put_memo(tx)

        {:ok, fields, meta}
      end
    end

    def read(options, :stellar_ledger, %{"sequence" => sequence}) when is_integer(sequence) do
      with {:ok, ledger, meta} <- object(options, "/ledgers/#{sequence}"),
           :ok <- same(ledger["sequence"], sequence),
           do: {:ok, %{"closed_at" => ledger["closed_at"], "hash" => ledger["hash"]}, meta}
    end

    # The memo's 32 bytes, as lowercase hex, when Horizon's base64 is their canonical spelling.
    defp put_memo(fields, %{"memo_type" => type, "memo" => memo})
         when type in ["hash", "return"] do
      with true <- is_binary(memo),
           {:ok, <<_::binary-32>> = bytes} <- Base.decode64(memo),
           ^memo <- Base.encode64(bytes) do
        Map.put(fields, "memo", Base.encode16(bytes, case: :lower))
      else
        _not_canonical -> fields
      end
    end

    defp put_memo(fields, _tx), do: fields

    defp object(options, path) do
      with {:ok, body, meta} <- HTTP.request(options, describe(options), method: :get, url: path),
           {:ok, value} <- HTTP.json(body) do
        if is_map(value), do: {:ok, value, meta}, else: {:error, :malformed_answer}
      end
    end

    defp same(value, value), do: :ok
    defp same(_answered, _asked), do: {:error, :answered_another}

    # A hash goes into a path only when it is 64 lowercase hex characters.
    defp hex64(hash),
      do: if(hash =~ ~r/\A[0-9a-f]{64}\z/, do: :ok, else: {:error, :malformed_answer})
  end
end
