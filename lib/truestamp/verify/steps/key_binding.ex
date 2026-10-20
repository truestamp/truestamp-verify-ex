# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.KeyBinding do
  @moduledoc """
  Step 5 of SPEC.md section 10.2, KEY_BINDING: the check of section 6.1, item 1, one row with
  part null. The run looks for a key of the keyring that governs whose 32 octets equal K's,
  and reads no key id the proof carries.

  | Keyring that governs | Row |
  |---|---|
  | holds K | `pass` |
  | lacks K | `fail key_binding_failed`, and the run ends |
  | cannot be used: a key chain not verified, or a failed online read | `fail keyring_unavailable`, whatever K is, and the run ends |
  | none: keyless mode | `skip key_binding_not_performed` (section 8.3) |
  """

  alias Truestamp.Verify.{KeyId, Keyring, Row, Run}
  alias Truestamp.Verify.Steps.Gate

  @doc "Step 5, KEY_BINDING."
  @spec key_binding(Run.t()) :: Run.t()
  def key_binding(%Run{keyring: nil} = run),
    do:
      Run.add_row(
        run,
        Row.new(:key_binding, :key_binding_not_performed, nil, Run.message(run, :keyless))
      )

  def key_binding(%Run{keyring: :unavailable} = run) do
    message = Run.message(run, :keyring_unavailable, %{kind: run.trust_root.kind})
    Gate.failure(run, Row.new(:key_binding, :keyring_unavailable, nil, message))
  end

  def key_binding(%Run{keyring: keyring, public_key: public_key} = run) do
    values = %{"key_id" => KeyId.of(public_key)}

    case Keyring.find(keyring, public_key) do
      nil ->
        message = Run.message(run, :key_binding_failed, %{kind: run.trust_root.kind})
        Gate.failure(run, Row.new(:key_binding, :key_binding_failed, nil, message, values))

      key ->
        row = Row.pass(:key_binding, nil, Run.message(run, :key_binding_pass), values)
        Run.add_row(%{run | bound_key: key}, row)
    end
  end
end
