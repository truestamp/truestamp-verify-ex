# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec do
  @moduledoc """
  The data of the Truestamp proof specification that this library compiles in, and where it
  came from.

  SPEC.md and its data files live in the truestamp-verification repository. This library
  mirrors that repository's `spec/` under `priv/spec/`, byte for byte, at one commit, which
  `source/0` names together with the digest of that commit's `MANIFEST.sha256`. A claim of
  conformance names exactly that pair (SPEC.md section 13.1).

  The tables live in their own modules:

  | Data | Module |
  |---|---|
  | the constants of section 9 | `Truestamp.Verify.Spec.Constants` |
  | the byte-prefix registry of section 4 | `Truestamp.Verify.Spec.Prefixes` |
  | CONSTRUCTIONS_ACCEPTED (section 7.2) | `Truestamp.Verify.Spec.Constructions` |
  | the reason codes of section 12.1 | `Truestamp.Verify.ReasonCodes` |
  | the exit codes of section 12.2 | `Truestamp.Verify.ExitCode` |
  | the schema of section 9 | `Truestamp.Verify.Schema` |
  | SMALL_ORDER_KEYS | `Truestamp.Verify.Ed25519` |
  | the production keyring and the non-production keys | `Truestamp.Verify.Keyring` |

  This module holds the environments (section 6.4), the networks of each chain and the
  default network pins of each environment (section 9).
  """

  alias Truestamp.Verify.Spec.Data

  @source_path Path.expand("../../../priv/spec.source", __DIR__)
  @external_resource @source_path
  @source (case @source_path |> File.read!() |> Truestamp.Verify.JSON.decode() do
             {:ok, %{"commit" => commit, "manifest_sha256" => manifest, "repository" => repo}} ->
               %{commit: commit, manifest_sha256: manifest, repository: repo}

             other ->
               raise "priv/spec.source is not what scripts/sync_spec.exs writes: #{inspect(other)}"
           end)

  @external_resource Data.path("encodings.json")
  @environments [
    "prod" | Map.fetch!(Map.fetch!(Data.read!("encodings.json"), "ENV"), "values")
  ]

  @external_resource Data.path("networks.json")
  @networks Data.read!("networks.json")

  @external_resource Data.path("network-pins.json")
  @default_pins Map.new(Data.read!("network-pins.json"), fn {environment, row} ->
                  {environment,
                   %{
                     commitment: Map.fetch!(row, "commitment"),
                     entropy: Map.fetch!(row, "entropy")
                   }}
                end)

  if Enum.sort(Map.keys(@default_pins)) != Enum.sort(@environments),
    do: raise("spec/network-pins.json does not hold one row for each environment")

  @typedoc "Where the compiled data came from."
  @type source :: %{commit: String.t(), manifest_sha256: String.t(), repository: String.t()}

  @typedoc "The pins of one kind, commitment or entropy: a network for each chain."
  @type pins :: %{String.t() => String.t()}

  @doc """
  The commit of truestamp-verification whose `spec/` this library compiles in, with the
  SHA-256 of that commit's `MANIFEST.sha256` and the repository's URL.
  """
  @spec source() :: source()
  def source, do: @source

  @doc """
  The values E_v can take (section 6.4): `prod`, and the ENV values of
  `spec/encodings.json`.
  """
  @spec environments() :: [String.t()]
  def environments, do: @environments

  @doc "The networks of each chain, from `spec/networks.json`."
  @spec networks() :: %{String.t() => [String.t()]}
  def networks, do: @networks

  @doc """
  The atom of the environment named `name`, such as `:prod` for `"prod"`, or nil for a name
  that is no environment.
  """
  @spec environment(String.t()) :: atom() | nil
  for name <- @environments do
    def environment(unquote(name)), do: unquote(String.to_atom(name))
  end

  def environment(_name), do: nil

  @doc "The default pins of the environment `environment`: its row of `spec/network-pins.json`."
  @spec default_pins(String.t()) :: %{commitment: pins(), entropy: pins()}
  def default_pins(environment) when environment in @environments,
    do: Map.fetch!(@default_pins, environment)
end
