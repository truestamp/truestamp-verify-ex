<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

- The first version: every check of the Truestamp proof specification, offline and online,
  passing every conformance case of truestamp-verification at the pinned commit.
- `livebooks/walkthrough.livemd`, with a **Run in Livebook** button in the README: the
  library and the vectors are each installed at a pinned commit, so it runs in any Livebook.
- Rows and bare rejections keep their message's id and assigns, so a stored one renders
  again through another message module (`Row.render/2`, `Rejection.render/2`); a
  `configuration_error` names the check of step 0 that failed, with its chain and network.
- A message module that faults, and a fault at VERDICT or while the report is written, give
  the documented fault outcome, never a raise; the public chain rules never raise on a value
  SHAPE would refuse; step 0's identity reads run at once.
- The Bitcoin evidence checks fail the OP_RETURN check of an entry with no epoch record
  (the message `bitcoin_no_epoch_record`); a message module's text that is not UTF-8 is a
  fault; `apply_expected_hash/2` on a report whose own EXPECTED_HASH faulted makes the step
  again.
- One commitment entry, `genesis.bitcoin` object or entropy object can be judged outside a
  run with the run's own read rules: `Online.Rule.new/2` takes a reader and its `:source`,
  `:network`, `:part`, `:top_level?` and `:deadline`, and `Online.Rule.confirm_identity/2`
  makes step 0's identity read for one source, its network one the specification names for
  the chain; `Online.Rule.unconfirmed/1` gives the outcome a run gives an entry against a
  source left unconfirmed. Their docs name the offline checks a run makes first.
- A cached best-chain Bitcoin block at a height stands when its meta's `tip_height` is at
  least that height plus BITCOIN_FINALITY, as SPEC.md 10.4 allows; one with no tip, or a
  shorter one, is refused.
- Follows truestamp-verification at 51dbf0343b06cb52d8531dc2fb18f2f728010afc, and passes
  its 482 cases (395 offline, 87 online): `@verification_ref`, `priv/spec.source` and the
  walkthrough's vectors move to that commit. `Conformance.output/2` gives a report's code
  where a case's expected output gives one (`Conformance.output_options/1`), and
  `Conformance.compare/3` compares it. The docs follow its text: a `txoutproof`'s walk
  reaches every flag octet, the bits after the last one used zero; an answer is judged on
  the fields its rule reads at that point; a conformance case names no keyring origin.
- `Readers.Replay` names a network's one source `:replay`, an atom no source name can
  spell, so a source a case names `"replay"` reads only the records that name it.
- `Readers.HTTP.new/1` takes NIST's one source with any number of options, and still
  refuses two NIST sources.
- Esplora's and Bitcoin Core's best-chain block at a height whose second call gives no
  usable answer or not found is found with the first call's hash alone, as SPEC.md 10.4
  says, and with that call's meta; an answer that breaks J2 to J6 in any member, a
  `difficulty` of 2^53 or more among them, is no usable answer.
- A row's `cached` is false, never null, for an outcome or a read with no answer, and its
  `fetched_at` the time the read was tried, by the verifier's clock; an outcome with no
  candidate is settled by the last read made, whatever it answered, and by the identity
  read only for a source asked nothing else. An unreachable reason is an ASCII128 that says
  why, such as `HTTP 503`, never an Elixir term, in each read and in each identity note.
- A run keeps no unreachable answer, as SPEC.md 10.4 says: a later row that needs the same
  read reads again, and uses that answer.
- `Readers.Replay` counts as a source only a named source whose identity read the file
  holds.
