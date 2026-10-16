# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.TrustRoot do
  @moduledoc """
  The trust root of a run (SPEC.md sections 8 and 10.5): where the keys that govern key
  binding came from, fixed at CONFIGURATION before the document is read.

  | Field | Holds |
  |---|---|
  | `kind` | `:key_chain`, `:current_keyring`, `:compiled_pin`, `:supplied_keyring` or `:none` |
  | `digest` | the lowercase hex SHA-256 of the keyring's bytes, d, or nil where no keyring's bytes were read |
  | `location` | where the keys came from, a URL or a file, or nil |
  """

  @type kind :: :key_chain | :current_keyring | :compiled_pin | :supplied_keyring | :none

  @type t :: %__MODULE__{kind: kind(), digest: String.t() | nil, location: String.t() | nil}

  @enforce_keys [:kind]
  defstruct [:kind, digest: nil, location: nil]

  @doc "The trust root as a report writes it: `{digest, kind, location}`."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = root),
    do: %{
      "digest" => root.digest,
      "kind" => Atom.to_string(root.kind),
      "location" => root.location
    }
end
