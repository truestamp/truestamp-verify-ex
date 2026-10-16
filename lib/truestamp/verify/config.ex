# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Config do
  @moduledoc """
  A run's configuration: everything step CONFIGURATION (SPEC.md section 10.2, step 0) fixes
  before the file is read. Nothing in a document sets any of it.

  A verifier has one of two roles (section 8), and each has its own constructor, so the
  choice is explicit:

  - `external/1`, every verifier but Truestamp's own: Truestamp's CLI, the reference
    verifiers, and any other (section 8.3). Its trust root is the compiled pin offline, the
    keyring read from Truestamp online, a keyring the caller supplies, or none (keyless).
    `Truestamp.Verify.verify/2` builds this one from its keyword options.
  - `internal/1`, Truestamp's own verifier (section 8.2): its trust root is its key chain,
    the keys its chain's key events introduce, verified before the run. It has no keyless
    mode, accepts no supplied keyring, never falls back to the compiled pin, and fails closed
    while the key chain is not verified. Which key events the key chain accepts is
    Truestamp's own policy (section 3.3), so the caller gives the keys.

  ## Options of both roles

  | Option | Value | Default |
  |---|---|---|
  | `:environment` | E_v (section 6.4): `:prod`, `:dev`, `:staging` or `:test` | `:prod` |
  | `:networks` | operator pins, `%{commitment: %{chain => network}, entropy: %{chain => network}}`; each replaces the default of that one pin (section 9) | the row of `spec/network-pins.json` for E_v |
  | `:reader` | `{module, state}`, a `Truestamp.Verify.Reader` that makes the chain and source reads of section 10.4; nil runs offline | nil |
  | `:expected_hash` | the caller's hash for EXPECTED_HASH (section 10.2, step 13) | nil |
  | `:messages` | a `Truestamp.Verify.Messages` module for the text of rows | `Truestamp.Verify.Messages.English` |
  | `:deadline` | milliseconds the whole online run may take; reads past it are unreachable | nil |

  ## Options of `external/1`

  | Option | Value | Default |
  |---|---|---|
  | `:trust` | the keyring that governs, below | `:default` |
  | `:current_keyring` | `{module, state}`, a `Truestamp.Verify.KeyringSource` for the keyring Truestamp publishes, which governs an online run under `:prod` with the default trust (section 8.3) | nil |

  `:trust` is one of:

  - `:default`: under `:prod`, the compiled pin offline and the keyring that
    `:current_keyring` reads online; under any other environment, no keyring, which is a
    `configuration_error` (section 6.4);
  - `{:keyring, bytes}` or `{:keyring, bytes, location}`: a supplied keyring, given as its
    bytes, with where it came from;
  - `{:keyring_file, path}`: a supplied keyring read from a file;
  - `{:keyring_source, {module, state}}`: a supplied keyring read through a
    `Truestamp.Verify.KeyringSource`, such as one from another origin (the CLI's
    `--base-url`);
  - `:keyless`: no keyring governs, and the signature is checked only against the key the
    document carries (section 8.3).

  ## Options of `internal/1`

  | Option | Value |
  |---|---|
  | `:key_chain` | required: the 32-octet public keys of the verified key chain, or `:unavailable` while it is not verified |

  An option that is unknown, given twice, or holds a value its member cannot take is
  refused with `{:error, {:invalid_option, name}}`, or an `ArgumentError` from the `!`
  forms: a configuration a caller writes wrong is a defect in the caller, not a
  verification result.
  """

  alias Truestamp.Verify.{Ed25519, Spec}
  alias Truestamp.Verify.Messages.English

  @environments Map.new(Spec.environments(), &{String.to_atom(&1), &1})

  @typedoc "A `{module, state}` pair that implements a behaviour."
  @type implementation :: {module(), term()}

  @typedoc "The keyring that governs a run (see the module doc)."
  @type trust ::
          :default
          | {:keyring, binary()}
          | {:keyring, binary(), String.t() | nil}
          | {:keyring_file, Path.t()}
          | {:keyring_source, implementation()}
          | :keyless
          | {:key_chain, [<<_::256>>] | :unavailable}

  @type pins :: %{String.t() => String.t()}

  @type t :: %__MODULE__{
          role: :external | :internal,
          environment: String.t(),
          trust: trust(),
          networks: %{commitment: pins(), entropy: pins()},
          reader: implementation() | nil,
          current_keyring: implementation() | nil,
          expected_hash: String.t() | nil,
          messages: module(),
          deadline: non_neg_integer() | nil
        }

  defstruct role: :external,
            environment: "prod",
            trust: :default,
            networks: Spec.default_pins("prod"),
            reader: nil,
            current_keyring: nil,
            expected_hash: nil,
            messages: English,
            deadline: nil

  @common [:environment, :networks, :reader, :expected_hash, :messages, :deadline]

  @doc "The configuration of an external verifier (see the module doc)."
  @spec external(keyword()) :: {:ok, t()} | {:error, {:invalid_option, atom()}}
  def external(options \\ []) when is_list(options) do
    with {:ok, config} <-
           build(%__MODULE__{role: :external}, options, @common ++ [:trust, :current_keyring]),
         :ok <- current_keyring_given(config),
         do: {:ok, config}
  end

  @doc "As `external/1`, raising `ArgumentError` on an invalid option."
  @spec external!(keyword()) :: t()
  def external!(options \\ []), do: bang(external(options))

  @doc "The configuration of Truestamp's own verifier (see the module doc)."
  @spec internal(keyword()) :: {:ok, t()} | {:error, {:invalid_option, atom()}}
  def internal(options) when is_list(options) do
    with {:ok, key_chain} <- fetch_key_chain(options),
         {:ok, config} <-
           build(%__MODULE__{role: :internal}, Keyword.delete(options, :key_chain), @common),
         do: {:ok, %{config | trust: {:key_chain, key_chain}}}
  end

  @doc "As `internal/1`, raising `ArgumentError` on an invalid option."
  @spec internal!(keyword()) :: t()
  def internal!(options), do: bang(internal(options))

  @doc "Whether the configuration makes chain and source reads: it has a reader."
  @spec online?(t()) :: boolean()
  def online?(%__MODULE__{reader: reader}), do: reader != nil

  defp bang({:ok, config}), do: config

  defp bang({:error, {:invalid_option, name}}),
    do: raise(ArgumentError, "invalid option #{inspect(name)}")

  defp build(config, options, allowed) do
    with :ok <- once_each(options),
         {:ok, config} <- set(config, options, allowed) do
      {:ok, %{config | networks: pins(config.environment, Keyword.get(options, :networks, %{}))}}
    end
  end

  defp once_each(options) do
    options
    |> Keyword.keys()
    |> Enum.reduce_while(MapSet.new(), fn name, seen ->
      if MapSet.member?(seen, name),
        do: {:halt, {:error, {:invalid_option, name}}},
        else: {:cont, MapSet.put(seen, name)}
    end)
    |> case do
      {:error, _reason} = error -> error
      _seen -> :ok
    end
  end

  defp set(config, options, allowed) do
    Enum.reduce_while(options, {:ok, config}, fn {name, value}, {:ok, config} ->
      case name in allowed and value(name, value) do
        {:ok, value} -> {:cont, {:ok, Map.put(config, name, value)}}
        _invalid -> {:halt, {:error, {:invalid_option, name}}}
      end
    end)
  end

  defp value(:environment, value) when is_map_key(@environments, value),
    do: {:ok, Map.fetch!(@environments, value)}

  defp value(:trust, :default), do: {:ok, :default}
  defp value(:trust, :keyless), do: {:ok, :keyless}
  defp value(:trust, {:keyring, bytes}) when is_binary(bytes), do: {:ok, {:keyring, bytes, nil}}

  defp value(:trust, {:keyring, bytes, location} = trust)
       when is_binary(bytes) and (is_nil(location) or is_binary(location)),
       do: {:ok, trust}

  defp value(:trust, {:keyring_file, path} = trust) when is_binary(path), do: {:ok, trust}

  defp value(:trust, {:keyring_source, {module, _state}} = trust) when is_atom(module),
    do: {:ok, trust}

  defp value(name, {module, _state} = implementation)
       when name in [:reader, :current_keyring] and is_atom(module),
       do: {:ok, implementation}

  defp value(name, nil) when name in [:reader, :current_keyring, :expected_hash, :deadline],
    do: {:ok, nil}

  defp value(:expected_hash, value) when is_binary(value), do: {:ok, value}
  defp value(:messages, module) when is_atom(module) and not is_nil(module), do: {:ok, module}

  defp value(:deadline, milliseconds) when is_integer(milliseconds) and milliseconds >= 0,
    do: {:ok, milliseconds}

  defp value(:networks, %{} = networks) do
    if networks?(networks), do: {:ok, networks}, else: :error
  end

  defp value(_name, _value), do: :error

  # Operator pins replace the default of each pin they name (section 9).
  defp networks?(networks) do
    Enum.all?(networks, fn
      {kind, pins} when kind in [:commitment, :entropy] and is_map(pins) ->
        Enum.all?(pins, fn {chain, network} ->
          network in Map.get(Spec.networks(), chain, [])
        end)

      _other ->
        false
    end)
  end

  defp pins(environment, overrides) do
    defaults = Spec.default_pins(environment)

    %{
      commitment: Map.merge(defaults.commitment, Map.get(overrides, :commitment, %{})),
      entropy: Map.merge(defaults.entropy, Map.get(overrides, :entropy, %{}))
    }
  end

  # An online run under prod with the default trust reads the current keyring, so it needs
  # a source for it; a configuration without one cannot run as section 8.3 says.
  defp current_keyring_given(%__MODULE__{
         reader: reader,
         environment: "prod",
         trust: :default,
         current_keyring: nil
       })
       when reader != nil,
       do: {:error, {:invalid_option, :current_keyring}}

  defp current_keyring_given(_config), do: :ok

  defp fetch_key_chain(options) do
    case Keyword.fetch(options, :key_chain) do
      {:ok, :unavailable} ->
        {:ok, :unavailable}

      {:ok, keys} when is_list(keys) ->
        if Enum.all?(keys, &key?/1) and Enum.uniq(keys) == keys,
          do: {:ok, keys},
          else: {:error, {:invalid_option, :key_chain}}

      _missing_or_invalid ->
        {:error, {:invalid_option, :key_chain}}
    end
  end

  # A key of the key chain passes the checks of a key's bytes (section 6.2).
  defp key?(<<_::binary-32>> = key), do: Ed25519.check_key_bytes(key) == :ok
  defp key?(_key), do: false
end
