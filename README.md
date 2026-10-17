<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp.Verify

The reference verifier for Truestamp proofs, in Elixir. It makes every check of the
Truestamp proof specification (SPEC.md, in
[truestamp-verification](https://github.com/truestamp/truestamp-verification)), offline
and online, and passes every one of its conformance cases.

**Status:** under construction, and not yet published. The specification it follows is a
draft.

A Truestamp proof is one JSON document, signed by Truestamp, that ties a subject to
Truestamp's chain of blocks and to commitments on public blockchains. Verifying a proof
establishes whether it is intact and who signed it. When the verifier also reads the public
chains and entropy sources, it places the subject's submission in a **submission window**:
after the submitted-after edge and before the submitted-before edge. A proof never
establishes when its data was created, who wrote it, or that any claim in it is true.

## Installing

While the repository is private, depend on it from GitHub:

```elixir
def deps do
  [
    {:truestamp_verify, github: "truestamp/truestamp-verify-ex"},
    # Only for online verification through the bundled HTTP sources:
    {:req, "~> 0.7"}
  ]
end
```

In a Livebook:

```elixir
Mix.install([{:truestamp_verify, github: "truestamp/truestamp-verify-ex"}])
```

The library needs Elixir 1.19 or later. Its one runtime dependency is
[truestamp_merkle](https://github.com/truestamp/truestamp-merkle-elixir). Req is optional:
without it, the HTTP sources are not compiled, and everything else works.

## Verifying a proof

```elixir
# Offline, in production, against the keys built into this library.
{:ok, report} = Truestamp.Verify.verify(File.read!("proof.json"))
report.label
#=> :internally_consistent

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

No test reaches the network. A guard refuses every request without a stub of its own, and
it must fire before the suite runs. `task test-live` runs the few tests of the HTTP sources
against the real services.

To test against another checkout of truestamp-verification, such as one with a change to
the specification in progress, set `TRUESTAMP_VERIFICATION=/path/to/checkout`, then mirror
its `spec/` with `task spec-sync`.

## License

Apache-2.0. See `LICENSE`.
