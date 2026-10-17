# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/truestamp/truestamp-verify-ex"

  # The commit of truestamp-verification (SPEC.md, spec/ and vectors/) this library conforms
  # to. `priv/spec/` mirrors that commit's spec/ (scripts/sync_spec.exs), and the tests read
  # its vectors/ through the test-only dependency below.
  @verification_ref "10dcb7df52bb2b51527b0399e5658f431cfb3ae6"

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
        plt_add_apps: [:mix, :req, :ex_unit]
      ],
      source_url: @source_url,
      aliases: aliases()
    ]
  end

  # `mix truestamp.verify`, `mix truestamp.conformance` and `mix truestamp.agent_lines`
  # compile first with a quiet shell and standard error as the group leader, so a run that
  # compiles, its dependencies included, writes nothing to standard output, which carries
  # only the task's JSON document. `Mix.Tasks.Truestamp.Verify` gives the same alias to a
  # project that depends on this library.
  defp aliases do
    for task <- ~w(truestamp.verify truestamp.conformance truestamp.agent_lines),
        do: {String.to_atom(task), [&quiet_compile/1, task]}
  end

  defp quiet_compile(_args) do
    {shell, group_leader} = {Mix.shell(), Process.group_leader()}
    Mix.shell(Mix.Shell.Quiet)
    Process.group_leader(self(), Process.whereis(:standard_error))

    try do
      Mix.Task.run("compile")
    after
      Process.group_leader(self(), group_leader)
      Mix.shell(shell)
    end
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
      extras: [
        "README.md",
        "guides/getting-started.md",
        "guides/walkthrough.livemd",
        "guides/trust-and-roles.md",
        "guides/reading-the-chains.md",
        "guides/writing-a-source.md",
        "guides/conformance.md",
        "CHANGELOG.md",
        "LICENSE"
      ],
      groups_for_extras: [Guides: ~r{guides/}],
      source_ref: "v#{@version}",
      groups_for_modules: [
        Verifying: [
          Truestamp.Verify,
          Truestamp.Verify.Config,
          Truestamp.Verify.Report,
          Truestamp.Verify.Row,
          Truestamp.Verify.TraceRow,
          Truestamp.Verify.Edge,
          Truestamp.Verify.TrustRoot,
          Truestamp.Verify.Rejection,
          Truestamp.Verify.ReadError,
          Truestamp.Verify.Fault,
          Truestamp.Verify.Run,
          Truestamp.Verify.Step,
          Truestamp.Verify.ExitCode
        ],
        "Reading the chains": [
          Truestamp.Verify.Online,
          Truestamp.Verify.Reader,
          Truestamp.Verify.Readers.HTTP,
          Truestamp.Verify.Readers.Replay,
          Truestamp.Verify.Source,
          Truestamp.Verify.Sources.Horizon,
          Truestamp.Verify.Sources.Esplora,
          Truestamp.Verify.Sources.BitcoinCore,
          Truestamp.Verify.Sources.NistBeacon,
          Truestamp.Verify.KeyringSource,
          Truestamp.Verify.KeyringSources.WellKnown,
          Truestamp.Verify.KeyringSources.Replay,
          Truestamp.Verify.Online.Policy,
          Truestamp.Verify.Online.Answer,
          Truestamp.Verify.Online.Rule,
          Truestamp.Verify.Online.Rule.Outcome
        ],
        Messages: [
          Truestamp.Verify.Messages,
          Truestamp.Verify.Messages.English,
          Truestamp.Verify.CLI.Messages
        ],
        "Command line": [
          Truestamp.Verify.CLI,
          Truestamp.Verify.Conformance,
          Truestamp.Verify.AgentLines
        ],
        Chains: [
          Truestamp.Verify.Chains,
          Truestamp.Verify.Chains.Member,
          Truestamp.Verify.Chains.Bitcoin,
          Truestamp.Verify.Chains.Stellar,
          Truestamp.Verify.Chains.Nist,
          Truestamp.Verify.CommitmentChain,
          Truestamp.Verify.EntropySource
        ],
        Steps: ~r/^Truestamp\.Verify\.Steps\./,
        "Specification data": ~r/^Truestamp\.Verify\.Spec/,
        Primitives: [
          Truestamp.Verify.JSON,
          Truestamp.Verify.JSON.Binary64,
          Truestamp.Verify.JSON.Pointer,
          Truestamp.Verify.JCS,
          Truestamp.Verify.CanonicalForm,
          Truestamp.Verify.Base64URL,
          Truestamp.Verify.Ed25519,
          Truestamp.Verify.KeyId,
          Truestamp.Verify.Hash,
          Truestamp.Verify.Instant,
          Truestamp.Verify.ItemCode,
          Truestamp.Verify.ReasonCodes,
          Truestamp.Verify.Keyring,
          Truestamp.Verify.Schema,
          Truestamp.Verify.Layout,
          Truestamp.Verify.Check,
          Truestamp.Verify.Bitcoin,
          Truestamp.Verify.Bitcoin.Transaction,
          Truestamp.Verify.Bitcoin.MerkleBlock
        ]
      ]
    ]
  end
end
