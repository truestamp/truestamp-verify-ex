# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

alias Truestamp.Verify.Test.{NetworkGuard, Verification}

ExUnit.start(exclude: [:live])

# No test reaches the network: the guard refuses every request that has no stub of its own,
# and it must fire here, before any test runs, or the suite stops. Only `task test-live`
# (`mix test --only live`) leaves it out.
unless :live in Keyword.get(ExUnit.configuration(), :include, []) do
  NetworkGuard.install()

  unless NetworkGuard.fires?() do
    IO.puts(:stderr, "The network guard did not fire, so the suite stops.")
    System.halt(1)
  end
end

# The conformance data this run tests against, as a claim of conformance cites it (SPEC.md
# section 13.1): the commit of truestamp-verification and the digest of its MANIFEST.sha256.
IO.puts(
  "Conformance data: truestamp-verification #{Verification.commit()}, " <>
    "MANIFEST.sha256 #{Verification.manifest_sha256()}"
)
