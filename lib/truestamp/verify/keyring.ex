# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Keyring do
  @moduledoc """
  A keyring, and the load checks of SPEC.md section 10.2, step 0, which every keyring the
  verifier loads passes before any key in it can bind (sections 8.3 and 9).

  `load/3` reads a keyring's bytes under the parsing rules of section 10.1 (J1 to J6, with
  `Truestamp.Verify.JSON`), then makes exactly these checks, and no others (step 0 says "A
  verifier makes exactly these load checks", so there is, for one, no [L]A check):

  1. the keyring is an object with exactly two members, `keys`, an array, and `version`,
     the string `"1.0"`;
  2. each element of `keys` is an object with exactly `active` (a boolean), `key_id` (KID),
     `public_key` (B64U32) and `sequence` (INT);
  3. each `key_id` is the key id of its `public_key` (section 3.3);
  4. no two keys share a `key_id` or a `public_key`;
  5. each `public_key` passes the checks of a key's bytes (section 6.2): its y is below
     2^255 - 19, and it is not one of SMALL_ORDER_KEYS;
  6. no key is VECTOR_KEY unless E_v is `test`;
  7. in a production keyring, no key is in `spec/keys.nonproduction.json`.

  A production keyring is any keyring loaded in a run whose E_v is `prod`, whatever its
  source, a supplied keyring file included (section 6.4). So check 7 applies exactly when
  the environment `load/3` is given is `prod`.

  The compiled pin, `spec/keyring.production.json` as built into the verifier (section 8.3),
  is `compiled_pin/0`: its bytes, compiled in and loaded at run time through the same checks.
  `spec/keys.nonproduction.json` and VECTOR_KEY are compiled in too.

  The failure a load reports names the check that refused, for the message of
  `configuration_error` (section 12.1), which carries no `sub_reason`.
  """

  alias Truestamp.Verify.{Base64URL, Ed25519, JSON, KeyId}
  alias Truestamp.Verify.Spec.{Constants, Data}

  @typedoc "One key of a loaded keyring, with its public key as its 32 octets."
  @type key :: %{
          active: boolean(),
          key_id: String.t(),
          public_key: <<_::256>>,
          sequence: non_neg_integer()
        }

  @typedoc """
  A loaded keyring: its keys in the file's order, `digest`, the lowercase hex SHA-256 of the
  bytes as read (section 8.3), and `location`, the file or URL it came from, or nil.
  """
  @type t :: %__MODULE__{keys: [key()], digest: String.t() | nil, location: String.t() | nil}

  @typedoc "The check a keyring fails, by the order of the list above."
  @type failure ::
          {:json, :input_too_large | {:malformed_json, JSON.sub_reason()}}
          | :keyring_members
          | :key_members
          | :key_id
          | :repeated_public_key
          | :repeated_key_id
          | Ed25519.key_refusal()
          | :vector_key
          | :nonproduction_key

  @enforce_keys [:keys, :digest, :location]
  defstruct [:keys, :digest, :location]

  @compiled_pin_path Data.path("keyring.production.json")
  @external_resource @compiled_pin_path
  @compiled_pin File.read!(@compiled_pin_path)

  @external_resource Data.path("keys.nonproduction.json")
  @nonproduction_keys (for %{"public_key" => text} <-
                             Map.fetch!(Data.read!("keys.nonproduction.json"), "keys") do
                         {:ok, octets} = Base64URL.decode(:b64u32, text)
                         octets
                       end)

  @external_resource Data.path("encodings.json")
  @kid ~r/\A#{Map.fetch!(Map.fetch!(Data.read!("encodings.json"), "KID"), "pattern")}\z/

  @vector_key Base.decode16!(Constants.vector_key(), case: :lower)

  @keyring_members ["keys", "version"]
  @key_members ["active", "key_id", "public_key", "sequence"]

  @doc "The bytes of the compiled pin, `spec/keyring.production.json` as built in."
  @spec compiled_pin() :: binary()
  def compiled_pin, do: @compiled_pin

  @doc "The 32-octet keys of `spec/keys.nonproduction.json`, in the file's order."
  @spec nonproduction_keys() :: [<<_::256>>]
  def nonproduction_keys, do: @nonproduction_keys

  @doc "VECTOR_KEY (section 9), as its 32 octets."
  @spec vector_key() :: <<_::256>>
  def vector_key, do: @vector_key

  @doc """
  Loads the keyring whose bytes are `bytes` in a run whose E_v is `environment`, with the
  checks above: `{:ok, keyring}`, or `{:error, failure}` naming the first check that fails.
  `location` names where the bytes came from, for `trust_root` (section 10.5).
  """
  @spec load(binary(), String.t(), String.t() | nil) :: {:ok, t()} | {:error, failure()}
  def load(bytes, environment, location \\ nil) when is_binary(bytes) do
    with {:ok, value} <- decode(bytes),
         {:ok, keys} <- check(value, environment) do
      {:ok, %__MODULE__{keys: keys, digest: digest(bytes), location: location}}
    end
  end

  @doc """
  Loads a keyring given as a parsed JSON value, with no bytes of its own, as a replay file
  answers a keyring read (section 13.2): the same checks as `load/3` but the parse, and no
  digest, since there are no bytes to hash.
  """
  @spec load_value(term(), String.t(), String.t() | nil) :: {:ok, t()} | {:error, failure()}
  def load_value(value, environment, location \\ nil) do
    with {:ok, keys} <- check(value, environment),
         do: {:ok, %__MODULE__{keys: keys, digest: nil, location: location}}
  end

  @doc """
  The keyring of Truestamp's own verifier: the 32-octet keys of its verified key chain
  (section 8.2), which the caller has already checked, in a run whose E_v is `environment`.
  A key chain is not a keyring a verifier reads, so the checks of its form do not apply, but
  the checks of the environment do, since no run whose E_v is `prod` can bind a
  non-production key (section 6.4): checks 6 and 7 above. `{:ok, keyring}`, or
  `{:error, failure}` naming the check that refused.
  """
  @spec from_key_chain([<<_::256>>], String.t()) :: {:ok, t()} | {:error, failure()}
  def from_key_chain(keys, environment) when is_list(keys) do
    keys =
      keys
      |> Enum.with_index()
      |> Enum.map(fn {key, sequence} ->
        %{active: true, key_id: KeyId.of(key), public_key: key, sequence: sequence}
      end)

    with :ok <- each_key(keys, &vector_key(&1, environment)),
         :ok <- each_key(keys, &nonproduction_key(&1, environment)),
         do: {:ok, %__MODULE__{keys: keys, digest: nil, location: nil}}
  end

  @doc """
  Where Truestamp publishes its keyring, `https://www.truestamp.com/.well-known/keyring.json`:
  the one location a `current_keyring` reads (sections 8.3 and 10.5). A keyring read from
  anywhere else is a supplied keyring.
  """
  @spec truestamp_url() :: String.t()
  def truestamp_url, do: "https://www.truestamp.com/.well-known/keyring.json"

  # The load checks of section 10.2, step 0, on a parsed keyring.
  defp check(value, environment) do
    with {:ok, keys} <- form(value),
         :ok <- each_key(keys, &key_id/1),
         :ok <- unique(keys),
         :ok <- each_key(keys, &Ed25519.check_key_bytes(&1.public_key)),
         :ok <- each_key(keys, &vector_key(&1, environment)),
         :ok <- each_key(keys, &nonproduction_key(&1, environment)),
         do: {:ok, keys}
  end

  @doc """
  The key of `keyring` whose 32 octets equal `public_key`, or nil. Only the full comparison
  binds (section 6.1): no key id is read.
  """
  @spec find(t(), <<_::256>>) :: key() | nil
  def find(%__MODULE__{keys: keys}, <<_::binary-32>> = public_key),
    do: Enum.find(keys, &(&1.public_key == public_key))

  @doc "The lowercase hex SHA-256 of `bytes`: a keyring's digest d (section 8.3)."
  @spec digest(binary()) :: String.t()
  def digest(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  @doc "A plain sentence saying which load check `failure` names."
  @spec describe(failure()) :: String.t()
  def describe({:json, :input_too_large}),
    do: "it is larger than #{JSON.max_read_octets()} octets"

  def describe({:json, {:malformed_json, rule}}),
    do: "it is not JSON that every verifier reads alike (#{rule})"

  def describe(:keyring_members),
    do: ~s(it is not an object of exactly "keys", an array, and "version", the string "1.0")

  def describe(:key_members),
    do:
      ~s(a key is not an object of exactly "active", "key_id", "public_key" and "sequence", ) <>
        "each of its class"

  def describe(:key_id), do: ~s(a key's "key_id" is not the key id of its "public_key")
  def describe(:repeated_key_id), do: "two keys share a key id"
  def describe(:repeated_public_key), do: "two keys share a public key"
  def describe(:y_not_below_p), do: "a public key's y is not below 2^255 - 19"
  def describe(:small_order_key), do: "a public key is one of SMALL_ORDER_KEYS"

  def describe(:vector_key),
    do: "it holds VECTOR_KEY, whose seed is public, and the run's environment is not test"

  def describe(:nonproduction_key),
    do:
      "it is a production keyring, since the run's environment is prod, and it holds a key " <>
        "of a non-production environment"

  defp decode(bytes) do
    case JSON.decode(bytes) do
      {:ok, value} -> {:ok, value}
      {:error, reason} -> {:error, {:json, reason}}
    end
  end

  # Checks 1 and 2: the members and their classes.
  defp form(%{"keys" => keys, "version" => "1.0"} = keyring) when is_list(keys) do
    if Enum.sort(Map.keys(keyring)) == @keyring_members,
      do: keys |> Enum.map(&key/1) |> all_keys(),
      else: {:error, :keyring_members}
  end

  defp form(_value), do: {:error, :keyring_members}

  defp key(
         %{"active" => active, "key_id" => key_id, "public_key" => text, "sequence" => seq} = key
       )
       when is_boolean(active) and is_binary(key_id) and is_integer(seq) and seq >= 0 do
    with true <- Enum.sort(Map.keys(key)) == @key_members,
         true <- seq <= JSON.max_integer() and Regex.match?(@kid, key_id),
         {:ok, octets} <- Base64URL.decode(:b64u32, text) do
      %{active: active, key_id: key_id, public_key: octets, sequence: seq}
    else
      _refused -> :error
    end
  end

  defp key(_element), do: :error

  defp all_keys(keys) do
    if Enum.member?(keys, :error), do: {:error, :key_members}, else: {:ok, keys}
  end

  defp each_key(keys, check) do
    Enum.find_value(keys, :ok, fn key ->
      case check.(key) do
        :ok -> nil
        {:error, failure} -> {:error, failure}
      end
    end)
  end

  # Check 3.
  defp key_id(key),
    do: if(KeyId.of(key.public_key) == key.key_id, do: :ok, else: {:error, :key_id})

  # Check 4. After check 3, two keys that share a public key share a key id too, so the
  # public key is compared first; two keys share only a key id when their ids collide.
  defp unique(keys) do
    cond do
      not unique?(keys, & &1.public_key) -> {:error, :repeated_public_key}
      not unique?(keys, & &1.key_id) -> {:error, :repeated_key_id}
      true -> :ok
    end
  end

  defp unique?(keys, field), do: Enum.uniq_by(keys, field) == keys

  # Check 6.
  defp vector_key(%{public_key: @vector_key}, environment) when environment != "test",
    do: {:error, :vector_key}

  defp vector_key(_key, _environment), do: :ok

  # Check 7: every keyring loaded under E_v prod is a production keyring (section 6.4).
  defp nonproduction_key(key, "prod") do
    if key.public_key in @nonproduction_keys, do: {:error, :nonproduction_key}, else: :ok
  end

  defp nonproduction_key(_key, _environment), do: :ok
end
