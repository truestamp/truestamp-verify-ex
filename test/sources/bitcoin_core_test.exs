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

  # `getblockhash` answers with the hash, and `getblockheader` with `second`: a result,
  # `{:error, code}`, `{:raw, status, body}` or `:transport`. Each call tells the test when
  # it arrived.
  defp second_call(second) do
    parent = self()

    Req.Test.stub(__MODULE__, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      %{"method" => method} = elem(JSON.parse(body), 1)
      send(parent, {:rpc, method, DateTime.utc_now()})

      case {method, second} do
        {"getblockhash", _second} ->
          Req.Test.json(conn, %{"result" => @hash, "error" => nil})

        {"getblockheader", :transport} ->
          Req.Test.transport_error(conn, :timeout)

        {"getblockheader", {:error, code}} ->
          conn
          |> Plug.Conn.put_status(500)
          |> Req.Test.json(%{"result" => nil, "error" => %{"code" => code}})

        {"getblockheader", {:raw, status, raw}} ->
          Plug.Conn.send_resp(conn, status, raw)

        {"getblockheader", result} ->
          Req.Test.json(conn, %{"result" => result, "error" => nil})
      end
    end)
  end

  test "a block at a height whose getblockheader gives no usable answer is found with the hash alone" do
    # SPEC.md 10.4, "Answers": the read keeps what its first call gave, with that call's meta.
    # 9007199254740992 is 2^53, which J5 refuses in any member, an unused one included. An
    # answer with an error gives none of its result, even a result that holds a header's.
    big =
      ~s({"result": {"mediantime": 100, "nTx": 3, "difficulty": 9007199254740992}, "error": null})

    for second <- [
          :transport,
          {:raw, 503, "busy"},
          {:raw, 500, ~s({"result": {"mediantime": 100, "nTx": 3}, "error": {"code": -1}})},
          {:error, -5},
          {:error, -1},
          {:raw, 200, "not json"},
          "header",
          {:raw, 200, big}
        ] do
      second_call(second)

      assert {:ok, fields, meta} =
               BitcoinCore.read(@options, :bitcoin_block_at_height, %{"height" => 5})

      assert fields == %{"hash" => @hash}, inspect(second)
      assert_received {:rpc, "getblockhash", _first}
      assert_received {:rpc, "getblockheader", second_arrived}
      assert meta.source == "bitcoin-core http://node.test:8332"
      assert DateTime.compare(meta.fetched_at, second_arrived) == :lt, inspect(second)
    end
  end

  test "a block at a height whose header's difficulty is below 2^53 gives all three fields" do
    second_call(%{"mediantime" => 100, "nTx" => 3, "difficulty" => 126_411_437_451_912.2})

    assert {:ok, %{"hash" => @hash, "median_time_past" => 100, "transaction_count" => 3}, meta} =
             BitcoinCore.read(@options, :bitcoin_block_at_height, %{"height" => 5})

    # A header that answers gives its own call's meta.
    assert_received {:rpc, "getblockheader", second_arrived}
    assert DateTime.compare(meta.fetched_at, second_arrived) == :gt
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
