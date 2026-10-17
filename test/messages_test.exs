# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.MessagesTest do
  @moduledoc """
  The text of rows and rejections (`Truestamp.Verify.Messages`): the English default renders
  every id the library uses, and a caller's module replaces any of them.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.Messages
  alias Truestamp.Verify.Messages.English
  alias Truestamp.Verify.Test.Verification

  # Assigns that every message accepts; each takes only the ones it names.
  @assigns [
    %{},
    %{status: :fail, part: "/p"},
    %{
      environment: "prod",
      kind: :compiled_pin,
      failure: :key_id,
      chain: "bitcoin",
      network: "regtest",
      limit: 1,
      sub_reason: :syntax,
      marker: "dev",
      type: "item",
      format: "truestamp-proof",
      version: 1,
      part: "/p",
      rule: "r",
      class: "TIME",
      pin: "regtest",
      noun: :value,
      construction: "c",
      member: "m",
      read: :key_event_commitment,
      status: :pass,
      code: nil,
      step: :chain,
      online: true,
      length: 64,
      hash_type: "md5",
      attributed?: true,
      module: nil
    }
  ]

  test "every id renders, with the assigns it names" do
    for id <- English.ids() do
      rendered =
        Enum.find_value(@assigns, fn assigns ->
          try do
            English.message(id, assigns)
          rescue
            FunctionClauseError -> nil
            KeyError -> nil
          end
        end)

      assert is_binary(rendered) and rendered != "", inspect(id)
      refute rendered =~ <<0xE2, 0x80, 0x94>>, "#{id} holds an em dash"
    end
  end

  test "each variant of the messages that vary" do
    for kind <- [:compiled_pin, :current_keyring, :supplied_keyring, :key_chain, :none] do
      assert English.message(:configuration_pass, %{environment: "prod", kind: kind}) =~
               "E_v is prod"
    end

    for kind <- [:compiled_pin, :supplied_keyring, :current_keyring, :key_chain] do
      assert English.message(:key_binding_failed, %{kind: kind}) =~ "not"
    end

    assert English.message(:keyring_unavailable, %{kind: :key_chain}) =~ "key chain"
    assert English.message(:keyring_unavailable, %{kind: :current_keyring}) =~ "could not be read"
    assert English.message(:environment_pass, %{environment: "test"}) =~ "test environment"

    assert English.message(:environment_mismatch_marked_under_prod, %{marker: "dev"}) =~
             "development"

    assert English.message(:environment_mismatch_marked_under_prod, %{marker: "staging"}) =~
             "testing"

    assert English.message(:network_mismatch, %{chain: "c", pin: "p", kind: :entropy}) =~
             "objects"

    assert English.message(:window_not_established, %{online: false}) =~ "made no chain read"
    assert English.message(:expected_hash_pass, %{attributed?: false}) =~ "not attributed"

    assert English.message(:internal_error, %{step: "SHAPE", kind: :error, module: "RuntimeError"}) =~
             "error RuntimeError"

    assert English.message(:internal_error, %{step: "SHAPE", kind: :exit, module: nil}) =~
             "(exit)"

    assert English.message(:key_event_commitment_input, %{status: :skip, part: "/p"}) =~
             "settled nothing"

    for noun <- English.nouns() do
      assert English.message(:value_recomputed, %{noun: noun, part: "/p"}) =~ " at /p equals"
    end

    for read <- [
          {:commitment, "stellar", true},
          {:commitment, "stellar", false},
          {:commitment, "bitcoin", true},
          {:commitment, "bitcoin", false},
          {:genesis, "bitcoin"},
          {:entropy, "nist"},
          {:entropy, "stellar"},
          {:entropy, "bitcoin"},
          :key_event_commitment
        ] do
      assert English.message(:offline, %{read: read}) =~ "Offline: no read was made"
    end

    for {status, code, step} <- [
          {:pass, nil, :chain},
          {:pass, nil, :sources},
          {:fail, :chain_mismatch, :chain},
          {:fail, :entropy_mismatch, :sources},
          {:skip, :source_unreachable, :chain},
          {:skip, :not_held_by_source, :chain},
          {:skip, :not_yet_indexed, :sources},
          {:skip, :chain_not_final, :chain},
          {:skip, :sources_disagree, :chain},
          {:skip, :sources_incomplete, :sources}
        ] do
      assert is_binary(English.message(:read_outcome, %{status: status, code: code, step: step}))
    end
  end

  test "a caller's module replaces the ids it gives, and the English default keeps the rest" do
    defmodule Terse do
      @behaviour Truestamp.Verify.Messages
      @impl true
      def message(:read_pass, _assigns), do: "lu"
      def message(_id, _assigns), do: nil
    end

    assert Messages.render(Terse, :read_pass) == "lu"
    assert Messages.render(Terse, :parse_pass) == English.message(:parse_pass, %{})

    path = Verification.path("vectors/positive/item.proof.json")

    {:ok, report} =
      Verify.verify_file(path,
        environment: :test,
        trust: {:keyring_file, Verification.path("vectors/keyring.test.json")},
        messages: Terse
      )

    assert Enum.find(report.rows, &(&1.step == :read)).message == "lu"
  end
end
