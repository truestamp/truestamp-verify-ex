# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ConfigTest do
  @moduledoc "The two roles' configurations (SPEC.md section 8), and what each refuses."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{Config, Ed25519}
  alias Truestamp.Verify.Messages.English
  alias Truestamp.Verify.Test.{FakeReader, Signing}

  describe "external/1" do
    test "defaults: prod, the default trust, the prod pins, offline" do
      assert {:ok, config} = Config.external()
      assert config.role == :external
      assert config.environment == "prod"
      assert config.trust == :default
      assert config.networks.commitment == %{"bitcoin" => "mainnet", "stellar" => "public"}
      assert config.messages == English
      refute Config.online?(config)
    end

    test "the environment chooses the default pins, which an operator pin replaces one by one" do
      {:ok, config} =
        Config.external(environment: :staging, networks: %{entropy: %{"bitcoin" => "testnet"}})

      assert config.environment == "staging"
      assert config.networks.commitment == %{"bitcoin" => "regtest", "stellar" => "testnet"}
      assert config.networks.entropy == %{"bitcoin" => "testnet", "stellar" => "testnet"}
    end

    test "every trust it takes" do
      for {given, kept} <- [
            {:default, :default},
            {:keyless, :keyless},
            {{:keyring, "{}"}, {:keyring, "{}", nil}},
            {{:keyring, "{}", "here"}, {:keyring, "{}", "here"}},
            {{:keyring_file, "k.json"}, {:keyring_file, "k.json"}},
            {{:keyring_source, {FakeReader, nil}}, {:keyring_source, {FakeReader, nil}}}
          ] do
        assert {:ok, %Config{trust: ^kept}} = Config.external(environment: :test, trust: given)
      end
    end

    test "nil for the optional members, and the other members' values" do
      assert {:ok, config} =
               Config.external(
                 reader: nil,
                 current_keyring: nil,
                 expected_hash: nil,
                 deadline: nil
               )

      assert {:ok, %Config{deadline: 5, expected_hash: "ab", messages: English}} =
               Config.external(deadline: 5, expected_hash: "ab", messages: English)

      assert config.reader == nil
    end

    test "an online run under prod with the default trust needs a source for the current keyring" do
      reader = FakeReader.new(%{})
      assert Config.external(reader: reader) == {:error, {:invalid_option, :current_keyring}}
      assert {:ok, config} = Config.external(reader: reader, current_keyring: {FakeReader, nil})
      assert Config.online?(config)
      assert {:ok, _config} = Config.external(reader: reader, trust: :keyless)
      assert {:ok, _config} = Config.external(reader: reader, environment: :test, trust: :keyless)
    end

    test "refuses an unknown option, a repeated one, and a value its member cannot take" do
      for options <- [
            [bogus: 1],
            [environment: :prod, environment: :test],
            [environment: "prod"],
            [trust: :sometimes],
            [trust: {:keyring, 7}],
            [trust: {:keyring, "{}", 7}],
            [trust: {:keyring_file, 7}],
            [trust: {:key_chain, []}],
            [networks: %{commitment: %{"bitcoin" => "moon"}}],
            [networks: %{commitment: %{"dogecoin" => "mainnet"}}],
            [networks: %{other: %{}}],
            [networks: []],
            [reader: "nope"],
            [expected_hash: 7],
            [messages: nil],
            [messages: "English"],
            [deadline: -1],
            [key_chain: []]
          ] do
        assert {:error, {:invalid_option, _name}} = Config.external(options), inspect(options)
      end

      assert_raise ArgumentError, ~r/:bogus/, fn -> Config.external!(bogus: 1) end
      assert %Config{} = Config.external!([])
    end
  end

  describe "internal/1" do
    test "a verified key chain, or :unavailable" do
      key = Signing.public_key()

      assert {:ok, %Config{role: :internal, trust: {:key_chain, [^key]}}} =
               Config.internal(key_chain: [key])

      assert {:ok, %Config{trust: {:key_chain, :unavailable}}} =
               Config.internal(key_chain: :unavailable)

      assert %Config{} = Config.internal!(key_chain: :unavailable, environment: :dev)
    end

    test "refuses no key chain, a key of another length or a refused key, a repeated key, and the external options" do
      key = Signing.public_key()
      small_order = hd(Ed25519.small_order_keys())

      for options <- [
            [],
            [key_chain: nil],
            [key_chain: ["short"]],
            [key_chain: [small_order]],
            [key_chain: [key, key]],
            [key_chain: [key], trust: :keyless],
            [key_chain: [key], current_keyring: {FakeReader, nil}]
          ] do
        assert {:error, {:invalid_option, _name}} = Config.internal(options), inspect(options)
      end

      assert_raise ArgumentError, fn -> Config.internal!([]) end
    end
  end
end
