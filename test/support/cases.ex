# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Cases do
  @moduledoc """
  The cases of `vectors/cases.json` (SPEC.md section 13.2), for the tests that read them
  beyond `test/conformance_test.exs`: every case, every offline case, a case by id, its
  proof's bytes and its options.

  `cases.json` is read with `Truestamp.Verify.Test.StrictJSON`, since it is larger than
  MAX_READ_OCTETS, which binds a document, not a data file; a case's proof is handed to the
  verifier as its bytes, so the verifier's own reader reads it.
  """

  alias Truestamp.Verify.Conformance
  alias Truestamp.Verify.Test.{StrictJSON, Verification}

  @vectors Verification.vectors()

  @doc "The absolute path of `vectors/`."
  @spec vectors() :: Path.t()
  def vectors, do: @vectors

  @doc "The absolute path of `vectors/cases.json`."
  @spec path() :: Path.t()
  def path, do: Path.join(@vectors, "cases.json")

  @doc "Every case, in the file's order."
  @spec all() :: [map()]
  def all, do: StrictJSON.read_data!(path())

  @doc "Every offline case."
  @spec offline() :: [map()]
  def offline, do: Enum.reject(all(), &Conformance.online?/1)

  @doc "Every online case."
  @spec online() :: [map()]
  def online, do: Enum.filter(all(), &Conformance.online?/1)

  @doc "The case whose id is `id`."
  @spec get!(String.t()) :: map()
  def get!(id), do: Enum.find(all(), &(&1["id"] == id)) || raise(ArgumentError, "no case #{id}")

  @doc "The bytes of the case's proof."
  @spec proof(map()) :: binary()
  def proof(%{"proof" => path}), do: File.read!(Path.join(@vectors, path))

  @doc "The options of `Truestamp.Verify.verify/2` that run the case."
  @spec options(map()) :: keyword()
  def options(kase) do
    {:ok, options} = Conformance.options(kase, @vectors)
    options
  end
end
