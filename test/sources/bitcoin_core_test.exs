# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Sources.BitcoinCoreTest do
  @moduledoc "The Bitcoin Core source, against a stubbed JSON-RPC server (`Req.Test`)."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.JSON
  alias Truestamp.Verify.Sources.BitcoinCore

  @hash String.duplicate("ab", 32)
  @options [
    base_url: "http://node.test:8332",
    user: "u",
    password: "p",
    req_options: [plug: {Req.Test, __MODULE__}]
  ]

  # Answers each method from `results`: a value, or {:error, code} as Bitcoin Core does, with
  # HTTP 500 and a JSON body.
  defp stub(results) do
    parent = self()

    Req.Test.stub(__MODULE__, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      %{"method" => method, "params" => params} = elem(JSON.parse(body), 1)
      send(parent, {:rpc, method, params, Plug.Conn.get_req_header(conn, "authorization")})

      case Map.get(results, method) do
        {:error, code} ->
          conn
          |> Plug.Conn.put_status(500)
          |> Req.Test.json(%{"result" => nil, "error" => %{"code" => code}})

        {:raw, status, raw} ->
          Plug.Conn.send_resp(conn, status, raw)

        result ->
          Req.Test.json(conn, %{"result" => result, "error" => nil})
      end
    end)
  end

  test "describes itself by its URL" do
    assert BitcoinCore.describe(@options) == "bitcoin-core http://node.test:8332"
    assert :bitcoin_block in BitcoinCore.kinds()
  end

  test "the identity, the tip, with basic authentication" do
    stub(%{"getblockhash" => @hash, "getblockcount" => 840_000})
    assert {:ok, %{"hash" => @hash}, _meta} = BitcoinCore.read(@options, :bitcoin_identity, %{})
    assert_received {:rpc, "getblockhash", [0], ["Basic " <> credentials]}
    assert Base.decode64!(credentials) == "u:p"
    assert {:ok, %{"height" => 840_000}, _meta} = BitcoinCore.read(@options, :bitcoin_tip, %{})
  end

  test "the block at a height, and a block by its hash" do
    stub(%{
      "getblockhash" => @hash,
      "getblockheader" => %{"height" => 5, "mediantime" => 100, "nTx" => 3, "time" => 120}
    })

    assert {:ok, %{"hash" => @hash, "median_time_past" => 100, "transaction_count" => 3}, _meta} =
             BitcoinCore.read(@options, :bitcoin_block_at_height, %{"height" => 5})

    assert {:ok, %{"height" => 5, "median_time_past" => 100, "time" => 120}, _meta} =
             BitcoinCore.read(@options, :bitcoin_block, %{"hash" => @hash})
  end

  test "a height out of range and a block not found are not found; any other error is an error" do
    stub(%{"getblockhash" => {:error, -8}, "getblockheader" => {:error, -5}})

    assert {:error, :not_found, _meta} =
             BitcoinCore.read(@options, :bitcoin_block_at_height, %{"height" => 9})

    assert {:error, :not_found, _meta} =
             BitcoinCore.read(@options, :bitcoin_block, %{"hash" => @hash})

    stub(%{"getblockcount" => {:error, -28}})

    assert {:error, {:rpc_error, %{"code" => -28}}} =
             BitcoinCore.read(@options, :bitcoin_tip, %{})

    stub(%{"getblockcount" => {:raw, 404, ~s({"result": null, "error": {"code": -32601}})}})

    assert {:error, {:rpc_error, %{"code" => -32_601}}} =
             BitcoinCore.read(@options, :bitcoin_tip, %{})
  end

  test "an answer of another shape is no usable answer" do
    stub(%{"getblockhash" => 7, "getblockheader" => "header"})

    assert BitcoinCore.read(@options, :bitcoin_block_at_height, %{"height" => 1}) ==
             {:error, :malformed_answer}

    assert BitcoinCore.read(@options, :bitcoin_block, %{"hash" => @hash}) ==
             {:error, :malformed_answer}

    stub(%{"getblockcount" => {:raw, 200, "not json"}})
    assert BitcoinCore.read(@options, :bitcoin_tip, %{}) == {:error, :malformed_answer}
  end

  @tag :tmp_dir
  test "credentials from the node's cookie file, and none given", %{tmp_dir: dir} do
    cookie = Path.join(dir, ".cookie")
    File.write!(cookie, "__cookie__:secret\n")

    options = [
      base_url: "http://node.test:8332",
      cookie: cookie,
      req_options: [plug: {Req.Test, __MODULE__}]
    ]

    stub(%{"getblockcount" => 1})
    assert {:ok, %{"height" => 1}, _meta} = BitcoinCore.read(options, :bitcoin_tip, %{})
    assert_received {:rpc, "getblockcount", [], ["Basic " <> credentials]}
    assert Base.decode64!(credentials) == "__cookie__:secret"

    assert {:error, {:cookie, :enoent}} =
             BitcoinCore.read(
               Keyword.put(options, :cookie, Path.join(dir, "none")),
               :bitcoin_tip,
               %{}
             )

    assert_raise ArgumentError, fn ->
      BitcoinCore.read([base_url: "http://x"], :bitcoin_tip, %{})
    end
  end
end
