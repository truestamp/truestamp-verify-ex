# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Messages.English do
  @moduledoc """
  The default text of every row and rejection, in English (`Truestamp.Verify.Messages`).

  The text is stable: a change to it is a change a caller that keys translations on it can
  see in the changelog. `ids/0` lists every message id, and a test renders each.
  """

  @behaviour Truestamp.Verify.Messages

  alias Truestamp.Verify.Keyring

  @ids ~w(configuration_pass configuration_no_keyring configuration_keyring_refused
          configuration_no_source configuration_identity_forbidden
          configuration_current_keyring_location configuration_invalid_policy
          configuration_nist_sources read_pass input_too_large
          parse_pass malformed_json envelope_pass invalid_envelope environment_pass
          environment_mismatch_unmarked environment_mismatch_marked_under_prod
          environment_mismatch_marked environment_mismatch_unknown_marker keyless
          keyring_unavailable key_binding_failed key_binding_pass signature_pass
          signature_invalid prior_failure_gate shape_pass unsupported_format
          unsupported_version shape_schema shape_witnesses shape_time construction_mismatch_full
          construction_mismatch_reference policy_pass network_mismatch value_recomputed
          value_not_recomputed bitcoin_well_formed bitcoin_not_well_formed bitcoin_no_epoch_record
          bitcoin_order_holds bitcoin_order_violated stellar_order_holds stellar_order_violated
          handover_signature_pass handover_signature_fail key_event_key_bytes_pass
          key_event_key_bytes_fail head_order_holds head_order_violated link_key_event_pass
          link_key_event_fail link_key_event_not_attributable prior_failure_external offline
          read_outcome key_event_commitment_input key_event_commitment_pass
          key_event_commitment_not_attributable window_prior_failure window_inverted
          window_not_established window_pass recorded_time_outside_window
          expected_hash_not_checked expected_hash_no_listed_hash expected_hash_not_hex
          expected_hash_differs expected_hash_weak expected_hash_pass internal_error)a

  @doc "Every message id the library uses."
  @spec ids() :: [atom()]
  def ids, do: @ids

  @impl true
  @spec message(atom(), map()) :: String.t()

  # CONFIGURATION

  def message(:configuration_pass, %{environment: environment, kind: kind}),
    do: "E_v is #{environment}, and #{governs(kind)}."

  def message(:configuration_no_keyring, %{environment: environment}) do
    "A run whose environment is #{environment} checks proofs of that environment against a " <>
      "supplied keyring, and none was given: supply one, or run keyless to check the " <>
      "signature only against the key the document carries."
  end

  def message(:configuration_keyring_refused, %{failure: failure}),
    do:
      "The keyring fails a load check, so the run gives no verdict: #{Keyring.describe(failure)}."

  def message(:configuration_current_keyring_location, %{location: location}) do
    "The current keyring is the one Truestamp publishes at " <>
      "#{Keyring.truestamp_url()}, and this run's source read #{location}. A keyring from " <>
      "another origin is a supplied keyring: give its source as the trust " <>
      "{:keyring_source, source}."
  end

  def message(:configuration_invalid_policy, %{chain: chain, network: network, count: count}) do
    "The source policy of the #{chain} network #{network} asks for a number of sources " <>
      "that is 0 or more than its #{count}; at_least n takes n from 1 to the number of " <>
      "the network's sources."
  end

  def message(:configuration_nist_sources, _assigns),
    do: "This run names several sources for NIST's Randomness Beacon, which is one source."

  def message(:configuration_no_source, %{chain: chain, network: network}),
    do: "This online run pins the #{chain} network #{network}, and has no source for it."

  def message(:configuration_identity_forbidden, %{chain: chain, network: network}) do
    "A source configured for the #{chain} network #{network} is on another network: its " <>
      "identity read does not match the network it is pinned to."
  end

  # READ, PARSE, ENVELOPE

  def message(:read_pass, _assigns), do: "The file is within the read limit."

  def message(:input_too_large, %{limit: limit}),
    do: "The file is larger than #{limit} octets, the most a verifier reads."

  def message(:parse_pass, _assigns),
    do: "The file is one JSON text that every verifier reads alike."

  def message(:malformed_json, _assigns),
    do: "The file is not JSON that every verifier reads alike."

  def message(:envelope_pass, _assigns), do: "The document is a proof envelope."
  def message(:invalid_envelope, _assigns), do: "This file is not a Truestamp proof."

  # ENVIRONMENT

  def message(:environment_pass, %{environment: "prod"}),
    do: "The proof carries no environment marker: a production proof."

  def message(:environment_pass, %{environment: environment}),
    do: "The proof is marked as issued by Truestamp's #{environment} environment."

  def message(:environment_mismatch_unmarked, %{environment: environment}) do
    "This proof carries no environment marker, so it is a production proof, and this run " <>
      "checks proofs of Truestamp's #{environment} environment. To check it as a production " <>
      "proof, run under the prod environment."
  end

  def message(:environment_mismatch_marked_under_prod, %{marker: marker}) do
    "This proof is marked as issued by Truestamp's #{marker} environment, which is for " <>
      "#{purpose(marker)}. It is not a production proof. To check it against the #{marker} " <>
      "keyring, run under the #{marker} environment with that keyring."
  end

  def message(:environment_mismatch_marked, %{marker: marker, environment: environment}) do
    "This proof is marked as issued by Truestamp's #{marker} environment, and this run " <>
      "checks proofs of its #{environment} environment. To check it against the #{marker} " <>
      "keyring, run under the #{marker} environment with that keyring."
  end

  def message(:environment_mismatch_unknown_marker, _assigns),
    do: "This proof carries an environment marker that no Truestamp environment uses."

  # KEY_BINDING, SIGNATURE

  def message(:keyless, _assigns) do
    "Keyless mode: the signature is checked only against the key the document carries, " <>
      "which no keyring binds, so anyone could have made this proof."
  end

  def message(:keyring_unavailable, %{kind: :key_chain}),
    do: "Truestamp's key chain is not verified, so no key binds."

  def message(:keyring_unavailable, _assigns) do
    "The keyring could not be read in this run, so no key binds. An offline run checks only " <>
      "against the keys built into the verifier, and cannot see a key revoked since."
  end

  def message(:key_binding_failed, %{kind: :compiled_pin}) do
    "The key this proof carries is not among the keys built into this verifier. If " <>
      "Truestamp introduced it after this verifier was built, update the verifier, or check " <>
      "the proof online."
  end

  def message(:key_binding_failed, %{kind: :supplied_keyring}),
    do: "The key this proof carries is not in the supplied keyring."

  def message(:key_binding_failed, %{kind: :current_keyring}),
    do: "The key this proof carries is not in the keyring Truestamp publishes."

  def message(:key_binding_failed, %{kind: :key_chain}),
    do: "The key this proof carries is not in Truestamp's key chain."

  def message(:key_binding_pass, _assigns), do: "The key this proof carries is in the keyring."
  def message(:signature_pass, _assigns), do: "The signature verifies under the key."

  def message(:signature_invalid, _assigns),
    do: "The signature does not verify under the key over this proof's proof_hash."

  def message(:prior_failure_gate, _assigns), do: "Not made: a check of an earlier step failed."

  # SHAPE, POLICY

  def message(:shape_pass, %{type: type}),
    do: "The proof has the shape its type, #{type}, gives it."

  def message(:unsupported_format, %{format: format}),
    do: "This proof's format is not \"#{format}\", the only format this verifier reads."

  def message(:unsupported_version, %{version: version}) do
    "This proof's version is not #{version}, the only version this verifier reads; a later " <>
      "format may need a later verifier."
  end

  def message(:shape_schema, %{part: part, rule: rule}),
    do:
      "This proof does not have the layout of a Truestamp proof at #{part}: it breaks the rule #{rule}."

  def message(:shape_witnesses, _assigns),
    do: "The item's witnesses are not exactly the ones its witness_hashes name."

  def message(:shape_time, %{part: part, class: class}),
    do: "The time at #{part} names no instant: it does not write back to itself as #{class}."

  def message(:construction_mismatch_full, _assigns) do
    "This proof carries a constructions text this verifier has not accepted, so it cannot " <>
      "vouch for the proof's explanation of itself."
  end

  def message(:construction_mismatch_reference, _assigns) do
    "This proof names by reference a constructions text this verifier has not accepted, so " <>
      "it cannot vouch for the proof's explanation of itself."
  end

  def message(:policy_pass, %{chain: chain, pin: pin}),
    do: "The #{chain} network is the pinned #{pin}."

  def message(:network_mismatch, %{chain: chain, pin: pin, kind: kind}) do
    "This proof names a #{chain} network other than the #{pin} network this run pins for its " <>
      "#{kind} #{if kind == :commitment, do: "entries", else: "objects"}."
  end

  # DERIVE

  def message(:value_recomputed, %{part: part} = assigns),
    do: "#{noun(assigns)} at #{part} equals the value this run recomputed for it."

  def message(:value_not_recomputed, %{part: part, construction: construction} = assigns) do
    "#{noun(assigns)} at #{part} is not the value this run recomputed for it, by the " <>
      "constructions row #{construction}."
  end

  def message(:bitcoin_well_formed, %{member: member}), do: "The #{member} is well formed."

  def message(:bitcoin_not_well_formed, %{member: member, part: part, rule: rule}),
    do:
      "The #{member} at #{part} is not well formed: it breaks the rule #{String.replace(rule, "_", " ")}."

  def message(:bitcoin_no_epoch_record, %{part: part}) do
    "The OP_RETURN at #{part} cannot be compared with an epoch hash: the entry carries no " <>
      "epoch record that is a JSON object, so this run recomputes none."
  end

  def message(:bitcoin_order_holds, _assigns),
    do: "The Bitcoin entropy's height is at most the committed height."

  def message(:bitcoin_order_violated, _assigns),
    do: "The Bitcoin entropy's height is above the height of the top-level Bitcoin commitment."

  def message(:stellar_order_holds, _assigns),
    do: "The Stellar entropy's sequence is below the committed ledger."

  def message(:stellar_order_violated, _assigns),
    do:
      "The Stellar entropy's sequence is not below the ledger of the top-level Stellar commitment."

  def message(:handover_signature_pass, _assigns),
    do: "The handover signature verifies under the outgoing key."

  def message(:handover_signature_fail, %{part: part}) do
    "The handover signature at #{part} does not verify under the key event's " <>
      "previous_public_key over the handover it signs."
  end

  def message(:key_event_key_bytes_pass, _assigns),
    do: "The key event's public_key passes the checks of a key's bytes."

  def message(:key_event_key_bytes_fail, %{part: part}),
    do: "The key event's public_key at #{part} fails the checks of a key's bytes."

  def message(:head_order_holds, _assigns),
    do: "The witness block's height is below the height of the block."

  def message(:head_order_violated, _assigns) do
    "The witness block, the head of the chain when the item was submitted, is not below the " <>
      "block that includes the item."
  end

  def message(:link_key_event_pass, _assigns),
    do: "The key event at /signing_key_event/block introduced the key that signed this proof."

  def message(:link_key_event_fail, _assigns) do
    "The key event at /signing_key_event/block does not introduce the key that signed this " <>
      "proof."
  end

  def message(:link_key_event_not_attributable, _assigns) do
    "The key event at /signing_key_event/block introduces the key that signed this proof, but " <>
      "this run does not attribute the proof to Truestamp, so it shows no Truestamp key history."
  end

  # CHAIN, SOURCES

  def message(:prior_failure_external, _assigns), do: "Not read: a check before CHAIN failed."

  def message(:offline, %{read: read}),
    do: "Offline: no read was made in this run. " <> would(read)

  def message(:read_outcome, %{status: status, code: code, step: step}),
    do: outcome(status, code, step)

  def message(:key_event_commitment_input, %{status: :fail, part: part}),
    do:
      "The chain read at #{part}, where the signing key's key event was committed, contradicts the proof."

  def message(:key_event_commitment_input, %{status: :skip, part: part}),
    do:
      "The chain read at #{part}, where the signing key's key event was committed, settled nothing in this run."

  def message(:key_event_commitment_pass, _assigns),
    do: "The chain reads show where Truestamp committed the signing key's key event."

  def message(:key_event_commitment_not_attributable, _assigns) do
    "The chain reads show where the signing key's key event was committed, but this run does " <>
      "not attribute the proof to Truestamp, so it shows no Truestamp key history."
  end

  # WINDOW

  def message(:window_prior_failure, _assigns),
    do: "No window is drawn: a check of this run failed."

  def message(:window_inverted, _assigns),
    do:
      "The submitted-after edge is later than the submitted-before edge, so the reads contradict each other."

  def message(:window_not_established, %{online: false}) do
    "No submitted-before edge was drawn: this run made no chain read, so it establishes no " <>
      "submission window."
  end

  def message(:window_not_established, _assigns) do
    "No submitted-before edge was drawn: no chain read in this run confirmed a top-level " <>
      "commitment, so the submission window is not established. Absence is no failure."
  end

  def message(:window_pass, _assigns),
    do: "The submission window is drawn from instants read in this run."

  # SPEC.md 11.5: a time other than an edge is "Recorded by Truestamp" only when the run
  # attributes the proof to Truestamp, and otherwise the signer's declaration.
  def message(:recorded_time_outside_window, %{attributed: true}) do
    "The time inside the subject's id, recorded by Truestamp and not confirmed in this run, " <>
      "lies outside the submission window."
  end

  def message(:recorded_time_outside_window, _assigns) do
    "The time inside the subject's id, declared by the signer (not attributed to Truestamp), " <>
      "lies outside the submission window."
  end

  # EXPECTED_HASH

  def message(:expected_hash_not_checked, _assigns),
    do: "No expected hash was given, so the claims' hash was not compared with one."

  def message(:expected_hash_no_listed_hash, _assigns) do
    "An expected hash was given, and this proof has no hash of a listed type to compare it " <>
      "with: it is not an item, or its claims hold no hash of a listed hash_type."
  end

  def message(:expected_hash_not_hex, %{length: length}),
    do:
      "The expected hash is not hex of #{length} characters, the length of this proof's hash_type."

  def message(:expected_hash_differs, _assigns),
    do: "The expected hash differs from the hash in this proof's claims."

  def message(:expected_hash_weak, %{hash_type: hash_type, attributed?: attributed?}) do
    "The expected hash equals the hash in this proof's claims, but its hash_type is " <>
      "#{hash_type}, whose collisions are practical, so a different file can share it." <>
      attributed(attributed?)
  end

  def message(:expected_hash_pass, %{attributed?: attributed?}),
    do: "The expected hash equals the hash in this proof's claims." <> attributed(attributed?)

  def message(:internal_error, %{step: step, kind: kind, module: module}) do
    what = if module, do: "#{kind} #{module}", else: Atom.to_string(kind)
    "A fault inside the verifier (#{what}) stopped step #{step}, so this run cannot pass."
  end

  defp governs(:compiled_pin), do: "the compiled pin governs key binding"

  defp governs(:current_keyring),
    do: "the keyring Truestamp publishes, read in this run, governs key binding"

  defp governs(:supplied_keyring), do: "the supplied keyring governs key binding"
  defp governs(:key_chain), do: "Truestamp's key chain governs key binding"
  defp governs(:none), do: "the run is keyless: no keyring governs key binding"

  defp purpose("dev"), do: "development"
  defp purpose(_marker), do: "testing"

  defp attributed(true), do: ""
  defp attributed(false), do: " The match is against a document not attributed to Truestamp."

  @nouns %{
    value: "The value",
    op_return: "The epoch hash the transaction's OP_RETURN holds",
    transaction_hash: "The transaction_hash",
    matched_hash: "The transaction hash the txoutproof matches",
    header_hash: "The header_hash",
    header_merkle_root: "The header_merkle_root",
    header_time: "The header_time",
    block_hash: "The block hash",
    genesis_height: "The genesis block's height",
    genesis_previous_block_hash: "The genesis block's previous_block_hash",
    epoch_hash: "The epoch hash",
    claims_hash: "The claims_hash",
    item_hash: "The item_hash",
    entropy_hash: "The entropy_hash",
    observation_hash: "The observation_hash",
    key_event_key_id: "The key event's key_id",
    signing_key_id: "The block record's signing_key_id",
    previous_key_id: "The key event's previous_key_id",
    key_event_height: "The key event's height",
    key_event_previous_block_hash: "The key event's previous_block_hash",
    inclusion_root: "The merkle_root an inclusion proof walks to",
    tree_size: "The tree_size",
    witness_hash: "The witness hash"
  }

  @doc "The nouns a DERIVE row's message names its value by."
  @spec nouns() :: [atom()]
  def nouns, do: Map.keys(@nouns)

  defp noun(%{noun: :inclusion_root, inclusion_proof: at}),
    do: "The merkle_root the inclusion proof at #{at} walks to"

  defp noun(%{noun: noun}), do: Map.fetch!(@nouns, noun)

  defp would({:commitment, "stellar", true}) do
    "The read of this Stellar transaction on the pinned network, and of the ledger it names, " <>
      "would confirm this entry and give its candidate for the submitted-before edge."
  end

  defp would({:commitment, "stellar", false}),
    do: "The read of this Stellar transaction on the pinned network would confirm this entry."

  defp would({:commitment, "bitcoin", true}) do
    "The read of the best-chain Bitcoin block at this entry's height on the pinned network, " <>
      "and at that height + 10, would confirm this entry and give its candidate for the " <>
      "submitted-before edge."
  end

  defp would({:commitment, "bitcoin", false}) do
    "The read of the best-chain Bitcoin block at this entry's height on the pinned network " <>
      "would confirm this entry."
  end

  defp would({:genesis, "bitcoin"}) do
    "The read of the best-chain Bitcoin block at this height on the pinned network would " <>
      "confirm the genesis block's Bitcoin block hash."
  end

  defp would({:entropy, "nist"}) do
    "The read of the NIST Randomness Beacon pulse at this object's chainIndex and pulseIndex " <>
      "would confirm it and give its candidate for the submitted-after edge."
  end

  defp would({:entropy, "stellar"}) do
    "The read of the Stellar ledger at this object's sequence on the pinned network would " <>
      "confirm it and give its candidate for the submitted-after edge."
  end

  defp would({:entropy, "bitcoin"}) do
    "The read of the Bitcoin block with this object's hash on the pinned network would " <>
      "confirm it and give its candidate for the submitted-after edge."
  end

  defp would(:key_event_commitment) do
    "The chain reads of the signing key event's commitment entries would show where the " <>
      "signing key's key event was committed."
  end

  defp outcome(:pass, nil, :chain), do: "The chain read in this run confirms this entry."

  defp outcome(:pass, nil, :sources),
    do: "The source's read in this run confirms this entropy object."

  defp outcome(:fail, :chain_mismatch, _step),
    do: "A chain read in this run contradicts this entry."

  defp outcome(:fail, :entropy_mismatch, _step),
    do: "The source's read in this run differs from this entropy object."

  defp outcome(:skip, :source_unreachable, _step),
    do: "The source gave no usable answer, so this was not confirmed in this run."

  defp outcome(:skip, :not_held_by_source, _step),
    do: "The source does not hold this value; its absence is no contradiction."

  defp outcome(:skip, :not_yet_indexed, _step),
    do: "The value lies beyond what the source has indexed, so it was not confirmed in this run."

  defp outcome(:skip, :chain_not_final, _step),
    do: "The Bitcoin tip is below this entry's height + 10, so its block is not yet final."

  defp outcome(:skip, :sources_disagree, _step) do
    "The sources read in this run disagree with one another, so this was not confirmed. " <>
      "Their outcomes are in this row's values."
  end

  defp outcome(:skip, :sources_incomplete, _step) do
    "Too few of the sources read in this run gave a conclusive answer for this run's source " <>
      "policy, so this was not confirmed."
  end
end
