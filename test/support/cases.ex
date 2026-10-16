# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Cases do
  @moduledoc """
  The cases of `vectors/cases.json` (SPEC.md section 13.2), for the tests that read them
  beyond `test/conformance_test.exs`: every case, every offline case, a case by id, its
  proof's bytes and its options, and where steps 0 to 9 decide it.

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

  @doc """
  Where steps 0 to 6 (the gate, SPEC.md 10.2) decide the case: `:bare` for a bare
  rejection at steps 0 to 3; `:gate` for a report with a failing row at ENVIRONMENT,
  KEY_BINDING or SIGNATURE; `:later` for every other report, whose gate opens.
  """
  @spec gate_class(map()) :: :bare | :gate | :later
  def gate_class(%{"expected" => %{"code" => _code}}), do: :bare

  def gate_class(%{"expected" => %{"rows" => rows}}) do
    failed_at_gate? =
      Enum.any?(rows, fn [_code, _part, status, step] ->
        status == "fail" and step in ~w(ENVIRONMENT KEY_BINDING SIGNATURE)
      end)

    if failed_at_gate?, do: :gate, else: :later
  end
end
