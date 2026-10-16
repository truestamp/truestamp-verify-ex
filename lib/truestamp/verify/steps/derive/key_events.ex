# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Derive.KeyEvents do
  @moduledoc """
  The key-event checks of DERIVE (SPEC.md section 10.3, "Key events"): wherever a block
  record carries `metadata.key_event`, at any of the three block positions, the event is
  checked as section 3.3's table requires. With B the block node that carries it and E the
  event's pointer B`/record/metadata/key_event`, every failure is `key_event_mismatch`:

  | Check | Events | Part | Row of 7.3 | Traced |
  |---|---|---|---|---|
  | `public_key` passes the checks of a key's bytes (section 6.2) | `genesis`, `rotation`, `emergency_rotation` | E`/public_key` | `key_event` | no |
  | `key_id` = the key id of `public_key` | the same | E`/key_id` | `key_event` | yes |
  | B`/record/signing_key_id` = the key id of `public_key` | the same | B`/record/signing_key_id` | `key_event` | yes |
  | `previous_key_id` = the key id of `previous_public_key` | `rotation`, `emergency_rotation` | E`/previous_key_id` | `handover` | yes |
  | `height` = B`/record/height` | the same | E`/height` | `handover` | yes |
  | `previous_block_hash` = B`/record/previous_block_hash` | the same | E`/previous_block_hash` | `handover` | yes |
  | `handover_signature` verifies strictly (section 6.2) under `previous_public_key`, over the 32 octets of H(0x62, the event without `handover_signature`) | `rotation`, and `emergency_rotation` when it has one | E`/handover_signature` | `handover` | yes |
  | B`/record/signing_key_id` = `active_key_id` | `prerotation` | B`/record/signing_key_id` | `key_event` | yes |

  A `revocation` introduces no key and is not checked. The key event's `type` chooses only
  among the alternatives the schema lists for its position, and each is checked in full
  (section 10.6, rule 3). A key id is recomputed from a key's 32 octets
  (`Truestamp.Verify.KeyId`), and the ids the event and the record carry are only compared
  with it: the checks read no carried key id in place of its recomputation (rule 4).

  A `public_key` is PREIMAGE (section 3.7), so its row gives no trace row. For the handover
  signature, `recomputed` is the hex of the 32 octets it was verified over, and the status is
  Verify's outcome (section 10.6). A refused key's or signature's failing row also names the
  step of section 6.2 that refused it, under `refused`.
  """

  alias Truestamp.Verify.{Base64URL, Check, Ed25519, Hash, KeyId}
  alias Truestamp.Verify.JSON.Pointer

  @introduces_key ~w(genesis rotation emergency_rotation)
  @handover ~w(rotation emergency_rotation)

  @doc """
  The checks of the key event the block record at `at ++ ["record"]` carries, in the
  table's order; none when it carries no event, or a `revocation`.
  """
  @spec checks(Pointer.t(), map()) :: [Check.t()]
  def checks(at, %{"metadata" => %{"key_event" => event}} = record) do
    record_at = at ++ ["record"]
    event_at = record_at ++ ["metadata", "key_event"]
    event_checks(event["type"], event, event_at, record, record_at)
  end

  def checks(_at, _record), do: []

  defp event_checks(type, event, event_at, record, record_at) when type in @introduces_key do
    key = decode(event["public_key"])
    key_id = KeyId.of(key)
    from_key = [event_at ++ ["public_key"]]

    introduced = [
      key_bytes(event_at, event["public_key"], key),
      Check.equal(event_at ++ ["key_id"], "key_event", from_key, event["key_id"], key_id,
        code: :key_event_mismatch,
        noun: :key_event_key_id
      ),
      Check.equal(
        record_at ++ ["signing_key_id"],
        "key_event",
        from_key,
        record["signing_key_id"],
        key_id,
        code: :key_event_mismatch,
        noun: :signing_key_id
      )
    ]

    if type in @handover,
      do: introduced ++ handover(event, event_at, record, record_at),
      else: introduced
  end

  defp event_checks("prerotation", event, event_at, record, record_at) do
    [
      Check.equal(
        record_at ++ ["signing_key_id"],
        "key_event",
        [event_at ++ ["active_key_id"]],
        record["signing_key_id"],
        event["active_key_id"],
        code: :key_event_mismatch,
        noun: :signing_key_id
      )
    ]
  end

  defp event_checks("revocation", _event, _event_at, _record, _record_at), do: []

  defp handover(event, event_at, record, record_at) do
    previous_key = decode(event["previous_public_key"])

    [
      Check.equal(
        event_at ++ ["previous_key_id"],
        "handover",
        [event_at ++ ["previous_public_key"]],
        event["previous_key_id"],
        KeyId.of(previous_key),
        code: :key_event_mismatch,
        noun: :previous_key_id
      ),
      Check.equal(
        event_at ++ ["height"],
        "handover",
        [record_at ++ ["height"]],
        event["height"],
        record["height"],
        code: :key_event_mismatch,
        noun: :key_event_height
      ),
      Check.equal(
        event_at ++ ["previous_block_hash"],
        "handover",
        [record_at ++ ["previous_block_hash"]],
        event["previous_block_hash"],
        record["previous_block_hash"],
        code: :key_event_mismatch,
        noun: :key_event_previous_block_hash
      )
    ] ++ handover_signature(event, event_at, previous_key)
  end

  # Required in a rotation, and made in an emergency rotation only when it has one; SHAPE has
  # held a rotation to carry one.
  defp handover_signature(%{"handover_signature" => signature} = event, event_at, previous_key) do
    message = Hash.hash(:handover, Map.delete(event, "handover_signature"))
    recomputed = Base.encode16(message, case: :lower)
    part = event_at ++ ["handover_signature"]
    inputs = Pointer.sort_by([event_at, event_at ++ ["previous_public_key"]])

    {outcome, said, values} =
      case Ed25519.verify(previous_key, message, decode_signature(signature)) do
        :ok ->
          {:pass, {:handover_signature_pass, %{}}, %{}}

        {:error, refusal} ->
          {{:fail, :key_event_mismatch},
           {:handover_signature_fail, %{part: Pointer.encode(part)}},
           %{
             "declared" => signature,
             "recomputed" => recomputed,
             "refused" => Atom.to_string(refusal)
           }}
      end

    [
      %Check{
        part: part,
        construction: "handover",
        inputs: inputs,
        declared: signature,
        recomputed: recomputed,
        outcome: outcome,
        traced: true,
        values: values,
        message: said
      }
    ]
  end

  defp handover_signature(_event, _event_at, _previous_key), do: []

  defp key_bytes(event_at, text, key) do
    part = event_at ++ ["public_key"]

    {outcome, said, values} =
      case Ed25519.check_key_bytes(key) do
        :ok ->
          {:pass, {:key_event_key_bytes_pass, %{}}, %{}}

        {:error, refusal} ->
          {{:fail, :key_event_mismatch},
           {:key_event_key_bytes_fail, %{part: Pointer.encode(part)}},
           %{"declared" => text, "refused" => Atom.to_string(refusal)}}
      end

    %Check{
      part: part,
      construction: "key_event",
      inputs: [part],
      declared: text,
      outcome: outcome,
      traced: false,
      values: values,
      message: said
    }
  end

  # SHAPE has held each to B64U32 or B64U64, so each decodes.
  defp decode(text) do
    {:ok, key} = Base64URL.decode(:b64u32, text)
    key
  end

  defp decode_signature(text) do
    {:ok, signature} = Base64URL.decode(:b64u64, text)
    signature
  end
end
