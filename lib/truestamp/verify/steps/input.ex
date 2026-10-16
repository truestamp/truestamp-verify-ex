# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Input do
  @moduledoc """
  Steps 1 to 3 of SPEC.md section 10.2, the input: READ, PARSE and ENVELOPE. Each that
  passes reports one row, `pass`, with part null; a failure at any of them is a bare
  rejection, with no report and no verdict.

  | Step | Checks | Else |
  |---|---|---|
  | 1 READ | J1: at most MAX_READ_OCTETS octets (section 10.1) | `input_too_large` |
  | 2 PARSE | J2 to J6 (section 10.1) | `malformed_json`, with its `sub_reason` |
  | 3 ENVELOPE | the envelope of section 3.1, and the bytes of K | `invalid_envelope`, with its `sub_reason` |

  ENVELOPE's checks run in this order, and the first that fails names the `sub_reason`:

  1. `document`: the document is an object whose members are exactly `proof` and
     `signature`;
  2. `proof`: `proof` is an object;
  3. `signature`: `signature` is an object whose members are exactly `alg`, `public_key`
     and `value`;
  4. `alg`: `alg` is the string `truestamp-ed25519-sha256-jcs`;
  5. `public_key`: a string that matches B64U32, whose 32 octets K pass the checks of a
     key's bytes (section 6.2);
  6. `value`: a string that matches B64U64.

  A B64U32 or B64U64 string is matched against its class before it is decoded, so every
  spelling but the canonical one fails (section 2.4). A document in any other layout fails
  here, whatever it resembles: the verifier does not try to recognize it.
  """

  alias Truestamp.Verify.{Base64URL, Ed25519, JSON, KeyId, ReasonCodes, Rejection, Row, Run}

  # SPEC.md 3.1: the literal `signature.alg` must equal, compared and never used to select.
  @alg "truestamp-ed25519-sha256-jcs"

  # SPEC.md 10.2, step 3: the checks of ENVELOPE, in order, each named by its sub_reason.
  @envelope_checks [:document, :proof, :signature, :alg, :public_key, :value]

  if @envelope_checks != ReasonCodes.sub_reasons(:invalid_envelope),
    do: raise("the ENVELOPE checks differ from invalid_envelope's sub_reasons")

  @doc "The literal `signature.alg` must equal (section 3.1)."
  @spec alg() :: String.t()
  def alg, do: @alg

  @doc "Steps 1 to 3 over the bytes of a document."
  @spec admit(Run.t(), binary()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def admit(%Run{} = run, bytes) when is_binary(bytes) do
    with {:ok, run} <- read(run, bytes),
         {:ok, run} <- parse(run, bytes),
         do: envelope(run)
  end

  @doc "Step 1, READ: J1 (section 10.1), else `input_too_large`."
  @spec read(Run.t(), binary()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def read(%Run{} = run, bytes) do
    case JSON.read(bytes) do
      :ok ->
        row = Row.pass(:read, nil, Run.text(run, :read_pass), %{"octets" => byte_size(bytes)})
        {:ok, Run.add_row(run, row)}

      {:error, :input_too_large} ->
        {:rejected, input_too_large(run)}
    end
  end

  @doc "The bare rejection `input_too_large`."
  @spec input_too_large(Run.t()) :: Rejection.t()
  def input_too_large(run),
    do:
      Rejection.new(
        :input_too_large,
        Run.text(run, :input_too_large, %{limit: JSON.max_read_octets()})
      )

  @doc "Step 2, PARSE: J2 to J6 (section 10.1), else `malformed_json` with its `sub_reason`."
  @spec parse(Run.t(), binary()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def parse(%Run{} = run, bytes) do
    case JSON.parse(bytes) do
      {:ok, document} ->
        row = Row.pass(:parse, nil, Run.text(run, :parse_pass))
        {:ok, Run.add_row(%{run | document: document}, row)}

      {:error, {:malformed_json, sub_reason}} ->
        message = Run.text(run, :malformed_json, %{sub_reason: sub_reason})
        {:rejected, Rejection.new(:malformed_json, message, sub_reason)}
    end
  end

  @doc "Step 3, ENVELOPE: the document is exactly the envelope of section 3.1."
  @spec envelope(Run.t()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def envelope(%Run{document: document} = run) do
    with :ok <- check(:document, envelope_document?(document)),
         %{"proof" => proof, "signature" => signature} = document,
         :ok <- check(:proof, is_map(proof)),
         :ok <- check(:signature, signature_object?(signature)),
         :ok <- check(:alg, Map.fetch!(signature, "alg") === @alg),
         {:ok, public_key} <- public_key(Map.fetch!(signature, "public_key")),
         {:ok, value} <- decode(:value, :b64u64, Map.fetch!(signature, "value")) do
      row =
        Row.pass(:envelope, nil, Run.text(run, :envelope_pass), %{
          "key_id" => KeyId.of(public_key)
        })

      {:ok, Run.add_row(%{run | proof: proof, public_key: public_key, signature: value}, row)}
    else
      {:error, check} ->
        message = Run.text(run, :invalid_envelope, %{sub_reason: check})
        {:rejected, Rejection.new(:invalid_envelope, message, check)}
    end
  end

  defp check(_name, true), do: :ok
  defp check(name, false), do: {:error, name}

  defp envelope_document?(%{"proof" => _, "signature" => _} = document),
    do: map_size(document) == 2

  defp envelope_document?(_document), do: false

  defp signature_object?(%{"alg" => _, "public_key" => _, "value" => _} = signature),
    do: map_size(signature) == 3

  defp signature_object?(_signature), do: false

  defp public_key(text) do
    with {:ok, octets} <- decode(:public_key, :b64u32, text) do
      case Ed25519.check_key_bytes(octets) do
        :ok -> {:ok, octets}
        {:error, _refusal} -> {:error, :public_key}
      end
    end
  end

  defp decode(name, class, text) do
    case Base64URL.decode(class, text) do
      {:ok, octets} -> {:ok, octets}
      :error -> {:error, name}
    end
  end
end
