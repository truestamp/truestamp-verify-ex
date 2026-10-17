# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Signature do
  @moduledoc """
  Step 6 of SPEC.md section 10.2, SIGNATURE: the check of section 6.1, item 2, one row with
  part null. The run computes `proof_hash` = SHA-256(0x50 || JCS(P)) itself, from P as
  parsed, and checks V under K over its 32 octets by the strict rule of section 6.2, else
  `signature_invalid`, which ends the run.

  When it passes, the gate is open, and the run carries its attribution (section 10.5):
  `truestamp` under Truestamp's keys (the key chain, the current keyring or the compiled
  pin), `keyring:<d>` under a supplied keyring, and `unattributed` in keyless mode. A
  supplied keyring answered from a replay has no bytes, so no digest; its attribution is
  then `keyring:` with nothing after it, which conformance never compares (section 13.2).
  """

  alias Truestamp.Verify.{Ed25519, Hash, Row, Run}
  alias Truestamp.Verify.Steps.Gate

  @truestamp_keys [:key_chain, :current_keyring, :compiled_pin]

  @doc "Step 6, SIGNATURE."
  @spec signature(Run.t()) :: Run.t()
  def signature(%Run{proof: proof, public_key: public_key, signature: value} = run) do
    proof_hash = Hash.hash(:proof_hash, proof)
    values = %{"proof_hash" => Base.encode16(proof_hash, case: :lower)}
    run = %{run | proof_hash: proof_hash}

    case Ed25519.verify(public_key, proof_hash, value) do
      :ok ->
        row = Row.pass(:signature, nil, Run.text(run, :signature_pass), values)
        Run.add_row(%{run | attribution: attribution(run.trust_root)}, row)

      {:error, refusal} ->
        values = Map.put(values, "refused", Atom.to_string(refusal))
        message = Run.text(run, :signature_invalid)
        Gate.failure(run, Row.new(:signature, :signature_invalid, nil, message, values))
    end
  end

  defp attribution(%{kind: kind}) when kind in @truestamp_keys, do: "truestamp"
  defp attribution(%{kind: :supplied_keyring, digest: digest}), do: "keyring:" <> (digest || "")
  defp attribution(%{kind: :none}), do: "unattributed"
end
