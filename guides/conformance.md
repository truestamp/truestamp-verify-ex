<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Conformance

SPEC.md, in [truestamp-verification](https://github.com/truestamp/truestamp-verification),
defines what a verifier must do, and `vectors/cases.json` holds the cases that show it:
each a proof and a configuration, with the label, every row, the trace and both edges of
the window a verifier must give (section 13). This library is the reference verifier, and
passes every case, offline and online.

## The claim

A claim of conformance cites the commit of truestamp-verification it was tested against and
the SHA-256 of that commit's `MANIFEST.sha256` (section 13.1). This library pins the commit
in `mix.exs`, as `@verification_ref`, and:

- every `mix test` run prints the citation before the tests;
- `Truestamp.Verify.Spec.source/0` gives it at run time;
- `priv/spec/` mirrors that commit's `spec/` byte for byte, and the library compiles it in,
  so a verifier built from this library always checks against the data of the commit it
  cites.

## How the cases run

The tests read the vectors from a test-only dependency on truestamp-verification at the
pinned commit, so none are copied into this repository. `test/conformance_test.exs` runs
every case and compares, as section 13.1 says, the label, each row reduced to
`(code, part, status, step)`, the trace, and for an online case each edge's instant and
basis. Messages and `values` are never compared. Each online case reads from its replay
file, so the suite never reaches the network.

`mix truestamp.conformance CASES_JSON` prints, for each case, what section 13.1 compares,
as one JSON document, for anyone who wants to diff another verifier's output against the
reference's. `--offline-only` leaves out the online cases, as an offline verifier does.

truestamp-verification runs no verifier: it is upstream of every one, and this library holds
itself to it. CI runs the whole gate on every push against the pinned commit, and
`.github/workflows/upstream.yml` runs the tests every week, and on demand, against the tip
of truestamp-verification's `main`, so a change there that this library does not yet follow
shows up within a week.

## Testing against another checkout

To test against a change to the specification in progress, point the tests at its
checkout and mirror its `spec/`:

```sh
export TRUESTAMP_VERIFICATION=/path/to/truestamp-verification
task spec-sync
task check
```

`task spec-check`, part of `task check`, fails while `priv/spec/` differs from the checkout's
`spec/`, so the library never runs on data other than the data it claims.

## Moving the pin

1. Set `@verification_ref` in `mix.exs` to the new commit, and run `mix deps.get`.
2. Run `task spec-sync` to mirror its `spec/`.
3. Move the `truestamp_verification` `ref` in the first cell of
   `livebooks/walkthrough.livemd` to the same commit. The notebook's library `ref` moves
   separately, after a push.
4. Run `task check`, and fix what the new cases find.
5. Commit them together, so the pin, the mirror, the notebook's vectors `ref` and the code
   that passes them move as one.
