# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Sources.HorizonTest do
  @moduledoc "The Horizon source, against a stubbed server (`Req.Test`)."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Sources.Horizon

  @tx String.duplicate("cd", 32)
  @memo_bytes :binary.copy(<<7>>, 32)
  @options [base_url: "https://horizon.test", req_options: [plug: {Req.Test, __MODULE__}]]

  defp stub(routes) do
    Req.Test.stub(__MODULE__, fn conn ->
      case Map.get(routes, conn.request_path) do
        nil -> Plug.Conn.send_resp(conn, 404, "{}")
        body -> Req.Test.json(conn, body)
      end
    end)
  end

  test "describes itself by its base URL" do
    assert Horizon.describe(@options) == "horizon https://horizon.test"
    assert :stellar_root in Horizon.kinds()
  end

  test "the identity and the root, from one call" do
    stub(%{
      "/" => %{
        "network_passphrase" => "Test SDF Network ; September 2015",
        "history_latest_ledger" => 9,
        "history_elder_ledger" => 2
      }
    })

    assert {:ok, %{"network_passphrase" => "Test SDF Network ; September 2015"}, _meta} =
             Horizon.read(@options, :stellar_identity, %{})

    assert {:ok, %{"elder" => 2, "latest" => 9}, _meta} =
             Horizon.read(@options, :stellar_root, %{})
  end

  test "a transaction: its memo as the hex of its 32 bytes" do
    stub(%{
      "/transactions/#{@tx}" => %{
        "hash" => @tx,
        "ledger" => 50,
        "memo_type" => "hash",
        "memo" => Base.encode64(@memo_bytes),
        "successful" => true
      }
    })

    assert {:ok, fields, _meta} = Horizon.read(@options, :stellar_transaction, %{"hash" => @tx})

    assert fields == %{
             "ledger" => 50,
             "memo" => Base.encode16(@memo_bytes, case: :lower),
             "memo_type" => "hash",
             "successful" => true
           }
  end

  test "a memo that is not the canonical base64 of 32 bytes, or of another type, is left out" do
    for memo <- [
          Base.encode64(<<1, 2>>),
          "not base64!",
          7,
          String.replace(Base.encode64(@memo_bytes), "=", "")
        ] do
      stub(%{
        "/transactions/#{@tx}" => %{
          "hash" => @tx,
          "ledger" => 50,
          "memo_type" => "hash",
          "memo" => memo,
          "successful" => true
        }
      })

      assert {:ok, fields, _meta} = Horizon.read(@options, :stellar_transaction, %{"hash" => @tx})
      refute Map.has_key?(fields, "memo"), inspect(memo)
    end

    stub(%{
      "/transactions/#{@tx}" => %{
        "hash" => @tx,
        "ledger" => 50,
        "memo_type" => "text",
        "memo" => "hi",
        "successful" => true
      }
    })

    assert {:ok, fields, _meta} = Horizon.read(@options, :stellar_transaction, %{"hash" => @tx})
    refute Map.has_key?(fields, "memo")
  end

  test "an answer about another transaction or ledger is no usable answer" do
    stub(%{
      "/transactions/#{@tx}" => %{"hash" => String.duplicate("00", 32)},
      "/ledgers/5" => %{"sequence" => 6}
    })

    assert Horizon.read(@options, :stellar_transaction, %{"hash" => @tx}) ==
             {:error, :answered_another}

    assert Horizon.read(@options, :stellar_ledger, %{"sequence" => 5}) ==
             {:error, :answered_another}
  end

  test "a ledger, a ledger not held, a hash not hex, and a body that is no object" do
    stub(%{
      "/ledgers/5" => %{"sequence" => 5, "closed_at" => "2026-09-26T01:48:30Z", "hash" => "ab"},
      "/" => [1]
    })

    assert {:ok, %{"closed_at" => "2026-09-26T01:48:30Z", "hash" => "ab"}, _meta} =
             Horizon.read(@options, :stellar_ledger, %{"sequence" => 5})

    assert {:error, :not_found, _meta} =
             Horizon.read(@options, :stellar_ledger, %{"sequence" => 6})

    assert Horizon.read(@options, :stellar_transaction, %{"hash" => "x/y"}) ==
             {:error, :malformed_answer}

    assert Horizon.read(@options, :stellar_root, %{}) == {:error, :malformed_answer}

    Req.Test.stub(__MODULE__, &Plug.Conn.send_resp(&1, 200, "{,}"))
    assert Horizon.read(@options, :stellar_root, %{}) == {:error, :malformed_answer}
  end
end
