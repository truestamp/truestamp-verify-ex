<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Getting started

`Truestamp.Verify` checks a Truestamp proof the way SPEC.md section 10 says a verifier
must: steps 0 to 14, in order, each giving rows that say what it found. This guide covers
the calls most callers need. [The walkthrough](../livebooks/walkthrough.livemd) runs them over a real
proof and prints every value along the way.

## A first run

```elixir
{:ok, report} = Truestamp.Verify.verify_file("proof.json")
report.label
```

With no options, the run is offline, under the production environment (`:prod`), with
the keys built into the library, the compiled pin, as the keyring that governs. Pass the
document's bytes to `Truestamp.Verify.verify/2` instead of a path when you already hold
them.

The result is one of:

| Result | When |
|---|---|
| `{:ok, %Truestamp.Verify.Report{}}` | steps 0 to 3 passed: the document is a proof envelope, whatever its label |
| `{:error, %Truestamp.Verify.Rejection{}}` | a bare rejection: a file too large, malformed JSON, not an envelope, or a configuration that cannot run (section 10.2, the gate) |
| `{:error, %Truestamp.Verify.ReadError{}}` | the proof or keyring file could not be read |
| `{:error, %Truestamp.Verify.Fault{}}` | a fault inside the verifier before steps 0 to 3 passed; only a bug gives one |

A proof that fails a check is still `{:ok, report}`, with `label: :failed`. The bang forms,
`Truestamp.Verify.verify!/2` and `Truestamp.Verify.verify_file!/2`, return the report and
raise the error. An option the library cannot take raises `ArgumentError`, since a
configuration written wrong is a defect in the caller, not a verification result.

## Reading a report

| Field | Holds |
|---|---|
| `label` | `:verified`, `:internally_consistent`, `:supplied_keyring`, `:unattributed` or `:failed` |
| `code` | for a failed run, the code of the first row that failed |
| `attribution` | whose key signed the proof, as far as this run can tell |
| `rows` | every check, a `Truestamp.Verify.Row` with its step, status, code, part and message |
| `trace` | each value the proof declares beside the value the run recomputed (section 10.6) |
| `submitted_after`, `submitted_before`, `window` | the submission window an online run draws |

`Truestamp.Verify.verified?/1` says whether the label is `:verified`, and
`Truestamp.Verify.Report.failures/1` gives the rows that failed. `Report.to_json/1` writes
the report as the JSON document of section 10.5, the one `mix truestamp.verify` prints, and
`Report.trace_json/1` writes the trace. `Report.document/1` gives the document as the
verifier parsed it, for a caller that shows a proof's members.

What each label says, in SPEC.md's words:

| Label | Says |
|---|---|
| `:verified` | intact, signed by Truestamp, and its submission placed before an instant read from a public chain in this run |
| `:internally_consistent` | intact and signed by Truestamp, but no read in this run established its submitted-before edge |
| `:supplied_keyring` | intact and signed by a key in the keyring the caller supplied; says nothing about Truestamp |
| `:unattributed` | intact under the key it carries, checked against no keyring |
| `:failed` | a check failed, and its row says which |

A proof never establishes when its data was created, who wrote it, or that any claim in it
is true.

## Checking the hash you hold

When you hold the hash of the data the proof covers, give it as `:expected_hash`, and step
13 compares it with the proof's claims:

```elixir
Truestamp.Verify.verify_file("proof.json", expected_hash: "9f86d0...")
```

To compare a hash after the fact, without verifying again,
`Truestamp.Verify.apply_expected_hash/2` gives the report a fresh run with that hash would
give.

## Test vectors and other environments

A proof from Truestamp's `test`, `dev` or `staging` environment is checked under that
environment, with a keyring that holds its key, or keyless:

```elixir
Truestamp.Verify.verify_file("vectors/positive/item.proof.json",
  environment: :test,
  trust: {:keyring_file, "vectors/keyring.test.json"}
)
```

[Trust roots and roles](trust-and-roles.md) explains which keyring governs a run, and why
the label depends on it.

## Online

An online run reads the public chains and entropy sources the proof names, and draws its
submission window from what it read. It needs Req:

```elixir
Truestamp.Verify.verify(proof_bytes, Truestamp.Verify.Online.defaults())
```

[Reading the chains](reading-the-chains.md) covers the reader, the bundled HTTP sources,
several sources per network, test networks and replay files.

## Messages

Every row's message comes from a message module, English by default. Messages are for
display only: nothing compares them. To translate them, or to word them for your own
product, give a module with `:messages`; `Truestamp.Verify.Messages` shows how.

## From the command line

`mix truestamp.verify FILE` runs the same steps and prints the report as JSON on standard
output, with a summary for people on standard error. `mix help truestamp.verify` lists its
options.
