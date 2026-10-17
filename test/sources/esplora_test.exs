# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Sources.EsploraTest do
  @moduledoc "The Esplora source, against a stubbed server (`Req.Test`)."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Sources.Esplora

  @hash String.duplicate("ab", 32)
  @block %{
    "height" => 840_000,
    "mediantime" => 1_713_570_000,
    "timestamp" => 1_713_571_767,
    "tx_count" => 3050
  }

  defp options(extra \\ []),
    do:
      [base_url: "https://esplora.test/api", req_options: [plug: {Req.Test, __MODULE__}]] ++ extra

  defp stub(routes) do
    Req.Test.stub(__MODULE__, fn conn ->
      case Map.get(routes, conn.request_path) do
        nil -> Plug.Conn.send_resp(conn, 404, "not found")
        {status, body} -> Plug.Conn.send_resp(conn, status, body)
        body when is_binary(body) -> Plug.Conn.send_resp(conn, 200, body)
        body -> Req.Test.json(conn, body)
      end
    end)
  end

  test "describes itself by its base URL, and knows its presets" do
    assert Esplora.describe(options()) == "esplora https://esplora.test/api"
    assert Esplora.describe(preset: :mempool) == "esplora https://mempool.space/api"
    assert map_size(Esplora.presets()) == 6
    assert_raise ArgumentError, fn -> Esplora.describe(preset: :nowhere) end
    assert :bitcoin_tip in Esplora.kinds()
  end

  test "the identity and the tip" do
    stub(%{
      "/api/block-height/0" =>
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\n",
      "/api/blocks/tip/height" => "840123"
    })

    assert {:ok, %{"hash" => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
            meta} =
             Esplora.read(options(), :bitcoin_identity, %{})

    assert %{source: "esplora https://esplora.test/api", cached: false, fetched_at: %DateTime{}} =
             meta

    assert {:ok, %{"height" => 840_123}, _meta} = Esplora.read(options(), :bitcoin_tip, %{})
  end

  test "a tip that is not an integer is no usable answer" do
    stub(%{"/api/blocks/tip/height" => "eight"})
    assert Esplora.read(options(), :bitcoin_tip, %{}) == {:error, :malformed_answer}
  end

  test "the block at a height: its hash, then its median time past and transaction count" do
    stub(%{"/api/block-height/840000" => @hash, "/api/block/#{@hash}" => @block})

    assert {:ok,
            %{"hash" => @hash, "median_time_past" => 1_713_570_000, "transaction_count" => 3050},
            _meta} =
             Esplora.read(options(), :bitcoin_block_at_height, %{"height" => 840_000})
  end

  test "a height above the tip, or a block the server lacks, is not found" do
    stub(%{})

    assert {:error, :not_found, _meta} =
             Esplora.read(options(), :bitcoin_block_at_height, %{"height" => 9_999_999})

    assert {:error, :not_found, _meta} =
             Esplora.read(options(), :bitcoin_block, %{"hash" => @hash})
  end

  test "a block by its hash: height, time and median time past" do
    stub(%{"/api/block/#{@hash}" => @block})

    assert {:ok,
            %{"height" => 840_000, "median_time_past" => 1_713_570_000, "time" => 1_713_571_767},
            _meta} =
             Esplora.read(options(), :bitcoin_block, %{"hash" => @hash})
  end

  test "a hash that is not hex, a body that is not an object, a status, or a transport failure" do
    assert Esplora.read(options(), :bitcoin_block, %{"hash" => "../x"}) ==
             {:error, :malformed_answer}

    stub(%{"/api/block/#{@hash}" => "[1]", "/api/block-height/1" => "not-a-hash"})

    assert Esplora.read(options(), :bitcoin_block, %{"hash" => @hash}) ==
             {:error, :malformed_answer}

    assert Esplora.read(options(), :bitcoin_block_at_height, %{"height" => 1}) ==
             {:error, :malformed_answer}

    stub(%{"/api/blocks/tip/height" => {503, "busy"}})
    assert Esplora.read(options(), :bitcoin_tip, %{}) == {:error, {:http_status, 503}}

    stub(%{"/api/blocks/tip/height" => {302, ""}})
    assert Esplora.read(options(), :bitcoin_tip, %{}) == {:error, {:http_status, 302}}

    Req.Test.stub(__MODULE__, &Req.Test.transport_error(&1, :timeout))
    assert {:error, {:transport, _message}} = Esplora.read(options(), :bitcoin_tip, %{})
  end
end
