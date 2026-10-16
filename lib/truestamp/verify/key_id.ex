# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyId do
  @moduledoc """
  A key's key id (SPEC.md section 3.3): the hex of the first 4 bytes of
  SHA-256(0x60 || its 32 bytes). It is outside the rule of section 4.1, a hash of the raw
  key bytes, so it does not depend on how the key is written.

  A key id is only an index (section 4.1): a verifier never reads one a document carries to
  choose or to check a signer (section 6.1). It computes one to check a KID the document
  carries (section 10.3) and when it loads a keyring (section 10.2, step 0).
  """

  alias Truestamp.Verify.Spec.Prefixes

  @doc "The key id of the 32-octet public key `key`, as 8 lowercase hex characters (KID)."
  @spec of(<<_::256>>) :: String.t()
  def of(<<_::binary-32>> = key) do
    <<id::binary-4, _rest::binary>> = :crypto.hash(:sha256, [Prefixes.byte(:key_id), key])
    Base.encode16(id, case: :lower)
  end
end
