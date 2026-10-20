# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.ExpectedHash do
  @moduledoc """
  Step 13 of SPEC.md section 10.2, EXPECTED_HASH: the caller's hash (the `:expected_hash`
  option, or the CLI's `--expected-hash HEX`) against `/subject/claims/hash`. The step reports one row.

  - No hash given: `skip expected_hash_not_checked`, part null.
  - A hash given: one row at `/subject/claims/hash`, whatever the proof holds there:
    - `pass` only when the type is `item`, `/subject/claims/hash_type` is a name of the table
      below, `/subject/claims/hash` is a string, and the caller's value, lowercased, is hex
      of that type's length and equals `/subject/claims/hash`;
    - such a match under `md5` or `sha1` is `warn expected_hash_weak_algorithm` in place of
      `pass`;
    - anything else is `fail expected_hash_mismatch`, never a skip, with
      `values` saying why under `reason`: `no_listed_hash` (the proof is not an item, or its
      claims have no `hash` of a listed type), `not_hex_of_length` (the caller's value is not
      hex of that type's length) or `differs`.

  When the attribution is not `truestamp`, the message of a match says that it is against a
  document not attributed to Truestamp. No other member of `claims` is read, and the claims
  are never judged true: the step checks the caller's file against the submitter's
  statement (section 10.6).

  After a failure at the gate or at SHAPE the run has ended, and its EXPECTED_HASH row is
  already `skip prior_failure`, and the step is not made. A failure at POLICY or
  DERIVE does not stop this step.

  **Values** (section 10.5): `expected_hash`, the caller's value lowercased, which the proof
  does not carry; on `not_hex_of_length`, `hex_characters`, the length the table gives; on
  `differs`, `declared`, the `hash` the proof carries, which the failed comparison
  contradicts. A pass or warn row holds no value of the proof.
  """

  alias Truestamp.Verify.{Layout, Row, Run}

  @part "/subject/claims/hash"

  # SPEC.md 10.2, step 13: each hash_type and the length of its hex. A test holds this to
  # SPEC.md's table.
  @hex_characters %{
    "md5" => 32,
    "sha1" => 40,
    "sha224" => 56,
    "sha3_224" => 56,
    "sha256" => 64,
    "sha3_256" => 64,
    "blake2s" => 64,
    "sha384" => 96,
    "sha3_384" => 96,
    "sha512" => 128,
    "sha3_512" => 128,
    "blake2b" => 128
  }

  @weak ["md5", "sha1"]

  @doc "The table of step 13: each `hash_type` and the number of hex characters of its hash."
  @spec hex_characters() :: %{String.t() => pos_integer()}
  def hex_characters, do: @hex_characters

  @doc "Step 13, EXPECTED_HASH: one row."
  @spec expected_hash(Run.t()) :: Run.t()
  def expected_hash(%Run{} = run), do: Run.add_row(run, row(run, run.config.expected_hash))

  @doc """
  The row of step 13 for the caller's hash `given`, or nil for none, in a run that reached
  the step: its type, P and attribution decide it.
  """
  @spec row(Run.t(), String.t() | nil) :: Row.t()
  def row(run, nil),
    do:
      Row.new(
        :expected_hash,
        :expected_hash_not_checked,
        nil,
        Run.message(run, :expected_hash_not_checked)
      )

  def row(run, given) when is_binary(given) do
    expected = String.downcase(given, :ascii)
    compare(run, expected, listed_hash(run.type, run.proof))
  end

  # {hash_type, hash} when the proof is an item whose claims hold a hash of a listed type.
  defp listed_hash("item", proof) do
    hash_type = Layout.get(proof, ["subject", "claims", "hash_type"])
    hash = Layout.get(proof, ["subject", "claims", "hash"])

    if Map.has_key?(@hex_characters, hash_type) and is_binary(hash),
      do: {hash_type, hash},
      else: nil
  end

  defp listed_hash(_type, _proof), do: nil

  defp compare(run, expected, nil),
    do: mismatch(run, :expected_hash_no_listed_hash, %{}, expected, "no_listed_hash", %{})

  defp compare(run, expected, {hash_type, hash}) do
    length = Map.fetch!(@hex_characters, hash_type)

    cond do
      not hex?(expected, length) ->
        mismatch(run, :expected_hash_not_hex, %{length: length}, expected, "not_hex_of_length", %{
          "hex_characters" => length
        })

      expected !== hash ->
        mismatch(run, :expected_hash_differs, %{}, expected, "differs", %{"declared" => hash})

      hash_type in @weak ->
        message =
          Run.message(run, :expected_hash_weak, %{
            hash_type: hash_type,
            attributed?: attributed?(run)
          })

        Row.new(:expected_hash, :expected_hash_weak_algorithm, @part, message, values(expected))

      true ->
        message = Run.message(run, :expected_hash_pass, %{attributed?: attributed?(run)})
        Row.pass(:expected_hash, @part, message, values(expected))
    end
  end

  defp mismatch(run, id, assigns, expected, reason, extra) do
    values = expected |> values() |> Map.put("reason", reason) |> Map.merge(extra)
    Row.new(:expected_hash, :expected_hash_mismatch, @part, Run.message(run, id, assigns), values)
  end

  defp values(expected), do: %{"expected_hash" => expected}

  defp attributed?(run), do: run.attribution == "truestamp"

  defp hex?(value, length), do: byte_size(value) == length and value =~ ~r/\A[0-9a-f]+\z/
end
