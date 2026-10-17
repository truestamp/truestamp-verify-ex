# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/truestamp/truestamp-verify-ex"

  # The commit of truestamp-verification (SPEC.md, spec/ and vectors/) this library conforms
  # to. `priv/spec/` mirrors that commit's spec/ (scripts/sync_spec.exs), and the tests read
  # its vectors/ through the test-only dependency below.
  @verification_ref "f6134106fb233972a658c7e9e6eda356a43e9f9b"

  def project do
    [
      app: :truestamp_verify,
      version: @version,
      # 1.19 or later: 1.19.3 on OTP 28.1.1 is the oldest version CI tests, beside the
      # versions .tool-versions pins.
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description:
        "The reference verifier for Truestamp proofs: every check of the Truestamp proof " <>
          "specification, offline and online, with pluggable chain and entropy sources.",
      package: package(),
      docs: docs(),
      test_coverage: [
        summary: [threshold: 100],
        # The test suite's own helpers are not the library.
        ignore_modules: [~r/^Truestamp\.Verify\.Test\./]
      ],
      # The PLTs live under _build, which CI caches.
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        plt_add_apps: [:mix, :req]
      ],
      source_url: @source_url
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      # The Merkle tree and inclusion proofs of RFC 9162 section 2.1. Pinned to a full
      # commit id until the library is published to Hex.
      {:truestamp_merkle,
       github: "truestamp/truestamp-merkle-elixir",
       ref: "0c08983854eb7bd24c7aaebb4664da4e5a28f2c0",
       depth: 1},
      # The HTTP sources (Truestamp.Verify.Sources.*) compile only when the caller depends
      # on Req too. The engine never needs it.
      {:req, "~> 0.7", optional: true},
      # The conformance data the tests run: SPEC.md's vectors/ and spec/, at the commit this
      # library claims conformance to. Test only, never compiled, never in the package.
      {:truestamp_verification,
       github: "truestamp/truestamp-verification",
       ref: @verification_ref,
       only: :test,
       app: false,
       compile: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:stream_data, "~> 1.4", only: [:dev, :test]},
      # Req.Test stubs need Plug, for the tests of the HTTP sources and the network guard.
      {:plug, "~> 1.19", only: :test}
    ]
  end

  # The package ships the library and the spec data it compiles in; the tests, the vectors
  # and the scripts stay in the repository, which the docs link to.
  defp package do
    [
      files: ~w(lib priv .formatter.exs mix.exs README.md CHANGELOG.md LICENSE),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      source_ref: "v#{@version}",
      groups_for_modules: []
    ]
  end
end
