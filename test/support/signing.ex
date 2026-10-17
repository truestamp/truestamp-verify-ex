# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Signing do
  @moduledoc """
  Documents signed here, for the tests that need a run no shared case gives (SPEC.md 13.3):
  a sound proof of `vectors/positive/`, changed and signed again by a key of a seed, with a
  keyring that holds that key, so a run under `prod` binds it and is attributed to
  Truestamp.
  """

  alias Truestamp.Verify.{Base64URL, Hash, JCS, JSON, KeyId}
  alias Truestamp.Verify.Steps.Input
  alias Truestamp.Verify.Test.{StrictJSON, Verification}

  # A seed no file lists: its key is in no keyring of the specification, so a production
  # keyring may hold it (section 9).
  @seed 0x07

  @doc "P of the sound proof `vectors/positive/<name>.proof.json`."
  @spec positive(String.t()) :: map()
  def positive(name) do
    bytes = File.read!(Verification.path("vectors/positive/#{name}.proof.json"))
    {:ok, %{"proof" => proof}} = JSON.decode(bytes)
    proof
  end

  @doc "The Ed25519 key pair of the seed of 32 bytes of `seed`."
  @spec key_pair(byte()) :: {binary(), binary()}
  def key_pair(seed \\ @seed),
    do: :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))

  @doc "The 32-octet public key of `seed`."
  @spec public_key(byte()) :: binary()
  def public_key(seed \\ @seed), do: seed |> key_pair() |> elem(0)

  @doc "The served document of `proof`, signed over its proof_hash by the key of `seed`."
  @spec signed(map(), byte()) :: binary()
  def signed(proof, seed \\ @seed) do
    {public, secret} = key_pair(seed)
    signature = :crypto.sign(:eddsa, :none, Hash.hash(:proof_hash, proof), [secret, :ed25519])

    JCS.encode(%{
      "proof" => proof,
      "signature" => %{
        "alg" => Input.alg(),
        "public_key" => Base64URL.encode(public),
        "value" => Base64URL.encode(signature)
      }
    })
  end

  @doc "The sound proof `name`, unmarked, so a production proof, signed by the key of `seed`."
  @spec production(String.t(), byte()) :: binary()
  def production(name, seed \\ @seed),
    do: name |> positive() |> Map.delete("environment") |> signed(seed)

  @doc "A keyring, in canonical form, whose one key is the key of `seed`."
  @spec keyring(byte()) :: binary()
  def keyring(seed \\ @seed) do
    public = public_key(seed)

    key = %{
      "active" => true,
      "key_id" => KeyId.of(public),
      "public_key" => Base64URL.encode(public),
      "sequence" => 0
    }

    StrictJSON.canonical(%{"keys" => [key], "version" => "1.0"})
  end
end
