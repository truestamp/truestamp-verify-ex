# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.SpecTest do
  @moduledoc """
  The data of the specification this library compiles in (SPEC.md section 9), and the
  mirror it compiles it from: `priv/spec/` must be byte for byte the `spec/` of the
  truestamp-verification checkout the tests run against, at the commit `priv/spec.source`
  names.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Chains, ReasonCodes, Spec}
  alias Truestamp.Verify.Spec.{Constants, Constructions, Data, Prefixes}
  alias Truestamp.Verify.Steps.ExpectedHash
  alias Truestamp.Verify.Test.Verification

  @priv Path.expand("../priv", __DIR__)

  defp files(dir) do
    dir
    |> Path.join("**")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Map.new(&{Path.relative_to(&1, dir), File.read!(&1)})
  end

  describe "the mirror of spec/" do
    test "is byte for byte the checkout's spec/" do
      assert files(Path.join(@priv, "spec")) == files(Verification.path("spec"))
    end

    test "names the checkout's commit and manifest digest" do
      assert Spec.source().commit == Verification.commit()
      assert Spec.source().manifest_sha256 == Verification.manifest_sha256()
      assert Spec.source().repository == "https://github.com/truestamp/truestamp-verification"
    end

    test "every file of the checkout's spec/ and vectors/ matches MANIFEST.sha256" do
      for line <-
            Verification.path("MANIFEST.sha256") |> File.read!() |> String.split("\n", trim: true) do
        [digest, path] = String.split(line, "  ", parts: 2)

        actual =
          :sha256
          |> :crypto.hash(File.read!(Verification.path(path)))
          |> Base.encode16(case: :lower)

        assert actual == digest, path
      end
    end
  end

  describe "the compiled data" do
    test "the environments, networks and default pins (sections 6.4 and 9)" do
      assert Spec.environments() == ["prod", "dev", "staging", "test"]

      assert Spec.networks() == %{
               "bitcoin" => ["mainnet", "testnet", "regtest"],
               "stellar" => ["public", "testnet"]
             }

      assert Spec.default_pins("dev").entropy == %{"bitcoin" => "mainnet", "stellar" => "testnet"}
    end

    test "the tables read from spec/ at compile time read the same at run time" do
      assert Constants.all() == Data.read!("constants.json")
      assert Data.path("schema.json") == Path.join([@priv, "spec", "schema.json"])

      assert Constructions.accepted() == [
               "c0d70826d7501d5089184d1947bad3dcc33c3172269d425f16fc0025ed07df49"
             ]

      refute Constructions.__mix_recompile__?()
      assert map_size(Prefixes.table()) == length(Prefixes.names())
      assert ReasonCodes.codes() == Enum.map(ReasonCodes.table(), & &1.code)
      assert ReasonCodes.step(:chain_mismatch) == "CHAIN"
      assert Chains.source_names() == ["bitcoin", "nist", "stellar"]
      assert ExpectedHash.hex_characters()["sha256"] == 64
    end

    test "a prefix byte has one spelling, and a file that breaks a parsing rule stops" do
      assert Data.byte!("0x0a") == 10
      assert_raise ArgumentError, fn -> Data.byte!("0x0A") end
      assert_raise ArgumentError, fn -> Data.byte!("10") end
      assert_raise ArgumentError, ~r/spec\/x.json/, fn -> Data.decode!("{,}", "x.json") end
    end

    test "naming a reason code the table lacks stops the build" do
      assert_raise ArgumentError, ~r/not a reason code/, fn ->
        Code.eval_string(
          "require Truestamp.Verify.ReasonCodes; Truestamp.Verify.ReasonCodes.code(:nope)"
        )
      end

      assert {:chain_mismatch, _binding} =
               Code.eval_string(
                 "require Truestamp.Verify.ReasonCodes; Truestamp.Verify.ReasonCodes.code(:chain_mismatch)"
               )
    end
  end
end
