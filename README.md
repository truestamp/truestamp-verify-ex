<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp.Verify

The reference verifier for Truestamp proofs, in Elixir. It makes every check of the
Truestamp proof specification (SPEC.md, in
[truestamp-verification](https://github.com/truestamp/truestamp-verification)), offline
and online, and passes every one of its conformance cases.

**Status:** under construction. The specification it follows is a draft.

[![Run in Livebook](https://livebook.dev/badge/v1/blue.svg)](https://livebook.dev/run?url=https%3A%2F%2Fgithub.com%2Ftruestamp%2Ftruestamp-verify-ex%2Fblob%2Fmain%2Flivebooks%2Fwalkthrough.livemd) Walk a real proof through every check, in your own Livebook:
[`livebooks/walkthrough.livemd`](livebooks/walkthrough.livemd).

A Truestamp proof is one JSON document, signed by Truestamp, that ties a subject to
Truestamp's chain of blocks and to commitments on public blockchains. Verifying a proof
establishes whether it is intact and who signed it. When the verifier also reads the public
chains and entropy sources, it places the subject's submission in a **submission window**:
after the submitted-after edge and before the submitted-before edge. A proof never
establishes when its data was created, who wrote it, or that any claim in it is true.

## Installing

Depend on it from GitHub, pinned to a commit:

```elixir
def deps do
  [
    {:truestamp_verify, github: "truestamp/truestamp-verify-ex", ref: "<commit id>"},
    # Only for online verification through the bundled HTTP sources:
    {:req, "~> 0.7"}
  ]
end
```

In a Livebook, as `livebooks/walkthrough.livemd` does:

```elixir
Mix.install([
  {:truestamp_verify, github: "truestamp/truestamp-verify-ex", ref: "<commit id>"},
  {:req, "~> 0.7"}
])
```

The library needs Elixir 1.19 or later. Its one runtime dependency is
[truestamp_merkle](https://github.com/truestamp/truestamp-merkle-ex). Req is optional:
without it, the HTTP sources are not compiled, and everything else works.

## Guides

- [Getting started](guides/getting-started.md): the calls most callers need, and what a
  report holds.
- [The walkthrough](livebooks/walkthrough.livemd): a Livebook that runs the verifier over a
  test vector and prints every value each step found, offline and then online from a replay
  file. It installs the library and the vectors, each pinned to a commit, so the **Run in
  Livebook** button above opens it in your own Livebook with nothing else to set up.
- [Trust roots and roles](guides/trust-and-roles.md): which keyring governs a run, and the
  labels each can reach.
- [Reading the chains](guides/reading-the-chains.md): online runs, the bundled HTTP
  sources, several sources per network, and test networks.
- [Writing a source or a reader](guides/writing-a-source.md): your own servers, caches or
  keyring channel.
- [Conformance](guides/conformance.md): the claim, how the cases run, and moving the pin.

## Verifying a proof

```elixir
# Offline, in production, against the keys built into this library: :internally_consistent
# for a sound proof signed by one of them. The compiled pin holds no key yet, so today a
# production proof fails KEY_BINDING offline; check it online, or with a keyring of its key.
{:ok, report} = Truestamp.Verify.verify(File.read!("proof.json"))
report.label

# A test vector of the specification: its environment and the keyring of its keys.
{:ok, report} =
  Truestamp.Verify.verify_file("vectors/positive/item.proof.json",
    environment: :test,
    trust: {:keyring_file, "vectors/keyring.test.json"}
  )

report.label            #=> :supplied_keyring
report.rows             #=> every check and what it found
report.trace            #=> each declared value beside the value the run recomputed
```

A run gives `{:ok, %Truestamp.Verify.Report{}}` whenever the document is a proof envelope,
whatever its label. A failed proof is still `{:ok, report}`, with `label: :failed` and rows
that say which check failed. Anything else is an error: `{:error, %Truestamp.Verify.Rejection{}}`
for a bare rejection (a file too large, malformed JSON, not an envelope, or a
configuration that cannot run), or `{:error, %Truestamp.Verify.ReadError{}}` for a file that
cannot be read.

| Label | Says |
|---|---|
| `:verified` | intact, signed by Truestamp, and its submission placed before an instant read from a public chain in this run |
| `:internally_consistent` | intact and signed by Truestamp, but no read in this run established its submitted-before edge |
| `:supplied_keyring` | intact, signed by a key in the keyring the caller supplied; says nothing about Truestamp |
| `:unattributed` | intact under the key it carries, checked against no keyring |
| `:failed` | a check failed; the rows say which |

## Verifying online

Online, the verifier reads Stellar, Bitcoin and NIST's Randomness Beacon to confirm each
commitment and entropy value, and draws the submission window from what it read:

```elixir
{:ok, report} = Truestamp.Verify.verify(proof_bytes, Truestamp.Verify.Online.defaults())
report.submitted_before   #=> %Truestamp.Verify.Edge{instant: ~U[...], basis: "bitcoin_median_time_read", ...}
```

Every read goes through a `Truestamp.Verify.Reader` the caller gives. Its contract matches
the replay files of the specification read for read, so a reader can be anything: the
bundled HTTP sources (Horizon, Esplora such as mempool.space or Blockstream, Bitcoin Core,
the NIST beacon), a cache, or a replay file for tests. A network can have several sources
under a policy, such as requiring every explorer to agree. The keyring Truestamp publishes is
read through a `Truestamp.Verify.KeyringSource`, so the channel it comes over can change
without touching the engine.

## Truestamp's own verifier

Truestamp's servers verify with their key chain as the trust root, and fail closed while it
is not verified:

```elixir
config =
  Truestamp.Verify.Config.internal!(
    key_chain: verified_keys,      # or :unavailable
    reader: {MyApp.LiveReader, state},
    messages: MyApp.VerifyMessages
  )

{:ok, report} = Truestamp.Verify.verify(proof_bytes, config)
```

## From the command line

The library brings the command of SPEC.md section 12.2 as a Mix task:

```sh
mix truestamp.verify proof.json                       # offline, in production
mix truestamp.verify proof.json --online              # reads the chains; needs Req
mix truestamp.verify vectors/positive/item.proof.json \
  --environment test --keyring vectors/keyring.test.json --trace item.trace.json
```

Standard output carries only the report, one JSON document, and standard error a summary
for people. The exit code is the label's (0 for `verified`, 3 for `failed`, and so on), 4 or
8 for a bare rejection, and 1 or 2 when there is no report. `mix help truestamp.verify` gives
every option. In a project that depends on this library, Mix prints the build of its
dependencies to standard output before the task runs; the task's docs give a two-function
alias that keeps standard output to the report alone.

Two more tasks give what conformance compares: `mix truestamp.conformance CASES_JSON`
writes what the verifier gives for each conformance case, and `mix truestamp.agent_lines
RUNS_JSON` the lines of the agent-sufficiency test. This library's tests hold both to the
files of truestamp-verification, which runs no verifier itself.

## Conformance

This library passes every case of `vectors/cases.json` in truestamp-verification at the
commit `mix.exs` pins (`@verification_ref`), offline and online, comparing labels, every
row, the traces and both edges of the submission window. The tests print the citation a
claim of conformance needs: that commit and the SHA-256 of its `MANIFEST.sha256`.
`Truestamp.Verify.Spec.source/0` gives the same pair at run time.

`priv/spec/` mirrors that commit's `spec/` byte for byte, and the library compiles it in.
The tests read the vectors from a test-only dependency on truestamp-verification, so none
are copied here.

## Developing

With [mise](https://mise.jdx.dev) and [Task](https://taskfile.dev):

```sh
MISE_ERLANG_COMPILE=false mise install
task setup
task check
```

`task check` is the gate CI runs:

- formatting and the house style;
- the spec mirror;
- a compile with warnings as errors;
- credo in strict mode, and dialyzer;
- unused dependencies;
- every test, with coverage that fails under 100%;
- the docs.

CI runs `task check` on a matrix of Erlang/OTP and Elixir versions: the versions
`.tool-versions` pins (Elixir 1.20 on OTP 29), Elixir 1.20 on OTP 28 and on OTP 27, and
Elixir 1.19.3 on OTP 28.1.1, the oldest that `mix.exs` allows. The OTP 27 leg runs every
test without coverage, since OTP 27's cover cannot recompile some of the BEAM files Elixir
1.20 writes; the other legs measure it. A second workflow,
`.github/workflows/upstream.yml`, runs the tests every week, and on demand, against the tip
of truestamp-verification's `main`, so a change to the specification that this library does
not yet follow shows up within a week.

No test reaches the network. A guard refuses every request without a stub of its own, and
it must fire before the suite runs. `task test-live` runs the few tests of the HTTP sources
against the real services.

To test against another checkout of truestamp-verification, such as one with a change to
the specification in progress, set `TRUESTAMP_VERIFICATION=/path/to/checkout`, then mirror
its `spec/` with `task spec-sync`.

## License

Apache-2.0. See `LICENSE`.
