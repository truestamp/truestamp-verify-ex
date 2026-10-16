# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Base64URL do
  @moduledoc """
  The base64url pattern classes B64U32 and B64U64 of SPEC.md section 2.4: unpadded
  base64url (RFC 4648 section 5) of 32 and of 64 octets, in the one canonical spelling each
  value has.

  The class of the last character forces the unused bits to zero, so a string that matches
  its class is exactly a canonical encoding. Stock decoders are not canonical (Elixir's
  `Base.url_decode64/2` ignores the unused bits), so `decode/2` matches the class before it
  decodes, as section 2.4 requires.

  The patterns are SPEC.md's, and a test holds them equal to `spec/encodings.json`.
  """

  @typedoc "A base64url pattern class: `:b64u32` is B64U32, `:b64u64` is B64U64."
  @type class :: :b64u32 | :b64u64

  @patterns %{
    b64u32: "[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]",
    b64u64: "[A-Za-z0-9_-]{85}[AQgw]"
  }

  @octets %{b64u32: 32, b64u64: 64}

  @doc "The pattern of `class`, written bare as in SPEC.md section 2.4."
  @spec pattern(class()) :: String.t()
  def pattern(class), do: Map.fetch!(@patterns, class)

  @doc "The number of octets a string of `class` decodes to."
  @spec octets(class()) :: 32 | 64
  def octets(class), do: Map.fetch!(@octets, class)

  @doc """
  Whether `text` is a string that matches `class` in full, as `\\A...\\z` does. Any other
  term, a non-string among them, does not match.
  """
  @spec matches?(class(), term()) :: boolean()
  def matches?(class, text) when is_binary(text) do
    # `\z`, never `$`, which also matches before a final newline (section 2.4).
    Regex.match?(Regex.compile!("\\A" <> pattern(class) <> "\\z"), text)
  end

  def matches?(class, _text) when is_map_key(@patterns, class), do: false

  @doc """
  The octets `text` spells, when it matches `class`: `{:ok, octets}`, else `:error`.
  """
  @spec decode(class(), term()) :: {:ok, binary()} | :error
  def decode(class, text) do
    if matches?(class, text), do: Base.url_decode64(text, padding: false), else: :error
  end

  @doc "The canonical spelling of `octets`: unpadded base64url."
  @spec encode(binary()) :: String.t()
  def encode(octets) when is_binary(octets), do: Base.url_encode64(octets, padding: false)
end
