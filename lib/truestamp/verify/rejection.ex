# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Rejection do
  @moduledoc """
  A bare rejection (SPEC.md section 10.2, the gate): a failure at steps 0 to 3, which gives
  only `{code, message, sub_reason}`, with no report and no verdict.

  The code is one of the four whose status is "bare" in section 12.1:
  `configuration_error`, `input_too_large`, `malformed_json` or `invalid_envelope`.
  `sub_reason` is present for `malformed_json` and `invalid_envelope` only, and is one of the
  names `Truestamp.Verify.ReasonCodes.sub_reasons/1` lists for the code. `new/3` refuses
  anything else.

  It is an exception, so `Truestamp.Verify.verify!/2` can raise it.
  """

  alias Truestamp.Verify.ReasonCodes

  @type t :: %__MODULE__{
          code: ReasonCodes.code(),
          message: String.t(),
          sub_reason: atom() | nil
        }

  defexception [:code, :message, :sub_reason]

  @doc """
  A bare rejection with `code` and `message`, and `sub_reason` when the code has one.
  Raises `ArgumentError` for a code that is not bare, or a `sub_reason` the code does not
  list, or a missing one.
  """
  @spec new(ReasonCodes.code(), String.t(), atom() | nil) :: t()
  def new(code, message, sub_reason \\ nil) when is_binary(message) do
    unless ReasonCodes.code?(code) and ReasonCodes.status(code) == :bare,
      do: raise(ArgumentError, "#{inspect(code)} is not a bare code of SPEC.md 12.1")

    listed = ReasonCodes.sub_reasons(code)

    unless (listed == [] and is_nil(sub_reason)) or sub_reason in listed,
      do: raise(ArgumentError, "#{inspect(sub_reason)} is not a sub_reason of #{code}")

    %__MODULE__{code: code, message: message, sub_reason: sub_reason}
  end

  @doc """
  The output of a bare rejection (section 10.2): `{code, message, sub_reason}`, with
  `sub_reason` present only for `malformed_json` and `invalid_envelope`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{code: code, message: message, sub_reason: sub_reason}) do
    written = %{"code" => Atom.to_string(code), "message" => message}
    if sub_reason, do: Map.put(written, "sub_reason", Atom.to_string(sub_reason)), else: written
  end
end
