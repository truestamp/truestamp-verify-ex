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
