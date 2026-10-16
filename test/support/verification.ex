# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Verification do
  @moduledoc """
  The checkout of truestamp-verification the tests run against: SPEC.md, `spec/` and
  `vectors/` at the commit this library claims conformance to.

  It is the directory `TRUESTAMP_VERIFICATION` names, when set, and otherwise the test-only
  dependency `deps/truestamp_verification`, which `mix deps.get` fetches at the commit
  `mix.exs` pins. Nothing under `vectors/` is copied into this repository.
  """

  @root (case System.get_env("TRUESTAMP_VERIFICATION") do
           nil -> Path.expand("../../deps/truestamp_verification", __DIR__)
           "" -> Path.expand("../../deps/truestamp_verification", __DIR__)
           path -> Path.expand(path)
         end)

  @doc "The absolute path of the checkout."
  @spec root() :: Path.t()
  def root, do: @root

  @doc "The absolute path of `relative` inside the checkout, such as `\"vectors/cases.json\"`."
  @spec path(Path.t()) :: Path.t()
  def path(relative), do: Path.join(@root, relative)

  @doc "The absolute path of `vectors/`."
  @spec vectors() :: Path.t()
  def vectors, do: path("vectors")

  @doc "The commit the checkout is at, as git reports it."
  @spec commit() :: String.t()
  def commit do
    {commit, 0} = System.cmd("git", ["-C", @root, "rev-parse", "HEAD"])
    String.trim(commit)
  end

  @doc "The lowercase hex SHA-256 of the checkout's `MANIFEST.sha256`, the digest a claim cites."
  @spec manifest_sha256() :: String.t()
  def manifest_sha256,
    do:
      :sha256 |> :crypto.hash(File.read!(path("MANIFEST.sha256"))) |> Base.encode16(case: :lower)
end
