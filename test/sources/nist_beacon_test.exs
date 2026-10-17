# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Sources.NistBeaconTest do
  @moduledoc "The NIST Beacon source and the well-known keyring source, against stubbed servers."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Keyring
  alias Truestamp.Verify.KeyringSources.WellKnown
  alias Truestamp.Verify.Sources.NistBeacon

  @options [req_options: [plug: {Req.Test, __MODULE__}]]

  test "a pulse: its outputValue and timeStamp" do
    Req.Test.stub(__MODULE__, fn conn ->
      assert conn.request_path == "/beacon/2.0/chain/2/pulse/7"

      Req.Test.json(conn, %{
        "pulse" => %{
          "chainIndex" => 2,
          "pulseIndex" => 7,
          "outputValue" => "AB",
          "timeStamp" => "T"
        }
      })
    end)

    assert {:ok, %{"outputValue" => "AB", "timeStamp" => "T"},
            %{source: "nist https://beacon.nist.gov/beacon/2.0"}} =
             NistBeacon.read(@options, :nist_pulse, %{"chainIndex" => 2, "pulseIndex" => 7})

    assert NistBeacon.kinds() == [:nist_pulse]
  end

  test "a pulse of another index is no usable answer, and one not held is not found" do
    Req.Test.stub(
      __MODULE__,
      &Req.Test.json(&1, %{"pulse" => %{"chainIndex" => 2, "pulseIndex" => 8}})
    )

    assert NistBeacon.read(@options, :nist_pulse, %{"chainIndex" => 2, "pulseIndex" => 7}) ==
             {:error, :malformed_answer}

    Req.Test.stub(__MODULE__, &Plug.Conn.send_resp(&1, 404, ""))

    assert {:error, :not_found, _meta} =
             NistBeacon.read(@options, :nist_pulse, %{"chainIndex" => 2, "pulseIndex" => 7})
  end

  describe "the well-known keyring" do
    test "gives the bytes as read, from Truestamp's origin by default" do
      Req.Test.stub(__MODULE__, fn conn ->
        assert conn.host == "www.truestamp.com"
        assert conn.request_path == "/.well-known/keyring.json"
        Plug.Conn.send_resp(conn, 200, ~s({"keys": [], "version": "1.0"}))
      end)

      {WellKnown, options} = WellKnown.new(@options)

      assert {:ok, {:bytes, ~s({"keys": [], "version": "1.0"})}, location, _meta} =
               WellKnown.fetch(options)

      assert location == Keyring.truestamp_url()
    end

    test "any other answer is a failed read" do
      {WellKnown, options} = WellKnown.new([base_url: "https://other.test"] ++ @options)
      Req.Test.stub(__MODULE__, &Plug.Conn.send_resp(&1, 404, ""))
      assert WellKnown.fetch(options) == {:error, :not_found}
      Req.Test.stub(__MODULE__, &Plug.Conn.send_resp(&1, 500, ""))
      assert WellKnown.fetch(options) == {:error, {:http_status, 500}}
    end
  end
end
