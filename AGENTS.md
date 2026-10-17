<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Instructions for AI coding agents that change this repository or build on it.

## What this repository is

The reference Elixir verifier for Truestamp proofs. SPEC.md, in truestamp-verification,
governs: where this code and SPEC.md disagree, SPEC.md is right and this code is wrong.
Read the section of SPEC.md a module's doc cites before changing the module.

## Where things are

| Path | Holds |
|---|---|
| `lib/truestamp/verify.ex` | the public API: `verify/2`, `verify_file/2`, `apply_expected_hash/2` |
| `lib/truestamp/verify/steps/` | one module per step of SPEC.md section 10.2, in its order |
| `lib/truestamp/verify/chains/` | one module per commitment chain and entropy source, behind the closed registry `Truestamp.Verify.Chains`; the engine has no branch for any chain |
| `lib/truestamp/verify/online/` | the engine's side of every read: answers, the read memo and its rules, the step-0 frame, multi-source policies |
| `lib/truestamp/verify/readers/`, `keyring_sources/`, `sources/` | the readers and keyring sources this library ships |
| `lib/truestamp/verify/{json,jcs,ed25519,...}.ex` | the building blocks: the strict reader, JCS, strict Ed25519, base64url, hashes, the Bitcoin parsers, the schema checker |
| `priv/spec/` | a byte-for-byte mirror of truestamp-verification's `spec/`; never edit it by hand |
| `livebooks/` | Livebook notebooks, each installing the library at a pinned commit; `walkthrough.livemd` walks a proof through every check, and the README's **Run in Livebook** button opens it |
| `test/` | the tests; `test/conformance_test.exs` runs every case of `vectors/cases.json` |

## Rules

- `task check` is the gate, and it passes before any change is done: formatting, the house
  style, the spec mirror, a compile with warnings as errors, credo strict, dialyzer, no
  unused dependency, every test with coverage of 100%, and the docs.
- Coverage is 100% and stays there. Cover new code with a test of what it means, not a test
  that only runs it; remove code no input can reach rather than test it.
- No test reaches the network. Stub an HTTP source with `Req.Test`; a test that must reach a
  real service is tagged `:live` and runs only with `task test-live`.
- A StreamData property asserts; a `check all` body that ends in a bare boolean never fails.
- Never copy files of `vectors/` here: the tests read them from the test-only dependency
  (`deps/truestamp_verification`, or `TRUESTAMP_VERIFICATION`).
- `priv/spec/` changes only through `elixir scripts/sync_spec.exs` (`task spec-sync`), after
  moving `@verification_ref` in `mix.exs` to the new commit and running `mix deps.get`.
- truestamp-verification is upstream and runs no verifier: this library holds itself to it.
  `.github/workflows/upstream.yml` runs the tests every day against its `main`, leaving out
  those tagged `pinned`, which check the pinned commit itself. When that run fails, follow
  the change: set `TRUESTAMP_VERIFICATION` to a checkout of `main`, run `task spec-sync` and
  `task check`, then move `@verification_ref` to that commit.
- A notebook under `livebooks/` installs the library at a full commit id of this
  repository, and the vectors at `@verification_ref`; `test/walkthrough_test.exs` checks
  both. A commit cannot pin itself, so after a change to the library that a notebook uses,
  push it, then move the notebook's `ref` to that commit in a commit of its own. When
  `@verification_ref` moves, move the notebook's vectors `ref` with it.
- The engine never reads a value from a document to choose what runs: `type` selects the
  composition of checks, and nothing else does (SPEC.md section 10.6).
- A reader owns its transport and the engine owns every judgement of SPEC.md section 10.4.
  Never move a judgement into a reader.
- House style, enforced by `task style`: no em dashes; "commit" and "commitment" for what a
  chain records; "submission window" for the interval a proof establishes; no version number
  in a format's name; the BCP 14 key words in capitals only in SPEC.md.
- Every source file carries the Apache-2.0 header its neighbours carry.
