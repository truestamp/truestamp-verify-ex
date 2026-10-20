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
