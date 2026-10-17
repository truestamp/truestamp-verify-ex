# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Steps.Configuration do
  @moduledoc """
  Step 0 of SPEC.md section 10.2, CONFIGURATION, before the file is read: it fixes E_v, the
  network pins, the sources of an online run, and the keyring that governs key binding,
  which the verifier's role decides (section 8).

  | Role and trust | Keyring that governs | `trust_root.kind` |
  |---|---|---|
  | internal, a verified key chain | its keys | `key_chain` |
  | internal, `:unavailable` | none: key binding fails `keyring_unavailable` | `key_chain` |
  | external, `:keyless` | none: keyless mode | `none` |
  | external, `:default`, `prod`, offline | the compiled pin | `compiled_pin` |
  | external, `:default`, `prod`, online | the keyring read in this run from Truestamp; a failed read binds no key | `current_keyring` |
  | external, `:default`, another E_v | `configuration_error` (section 6.4) | |
  | external, a supplied keyring's bytes or file | that keyring | `supplied_keyring` |
  | external, `{:keyring_source, ...}` | the keyring read in this run; a failed read binds no key | `supplied_keyring` |

  Every keyring is loaded through the load checks of step 0 (`Truestamp.Verify.Keyring`). A
  keyring file or a configured keyring that fails one is `configuration_error`; a keyring
  read online that fails, for any reason, is a failed read, never a bare rejection (section
  8.3). A keyring file that cannot be read at all is an input that cannot be read
  (`Truestamp.Verify.ReadError`, exit code 1).

  In an online run, every Stellar and Bitcoin network the run pins must have a source, and
  each source's identity is confirmed, before the file is read; a source on the
  wrong network is `configuration_error`.

  When the step passes it reports one row, `pass`, with part null.
  """

  alias Truestamp.Verify.{Config, JSON, Keyring, ReadError, Rejection, Row, Run, TrustRoot}
  alias Truestamp.Verify.Messages
  alias Truestamp.Verify.Online.Frame

  @doc "Step 0: `{:ok, run}`, a bare rejection, or an input that cannot be read."
  @spec configuration(Config.t()) ::
          {:ok, Run.t()} | {:rejected, Rejection.t()} | {:error, ReadError.t()}
  def configuration(%Config{} = config) do
    deadline = deadline(config)

    with {:ok, keyring, trust_root} <- governing_keyring(config),
         {:ok, frame} <- frame(config, deadline) do
      run = %Run{
        config: config,
        keyring: keyring,
        trust_root: trust_root,
        frame: frame,
        deadline: deadline
      }

      values = %{
        "environment" => config.environment,
        "online" => Config.online?(config),
        "trust_root" => Atom.to_string(trust_root.kind)
      }

      message =
        Run.text(run, :configuration_pass, %{
          environment: config.environment,
          kind: trust_root.kind
        })

      {:ok, Run.add_row(run, Row.pass(:configuration, nil, message, values))}
    end
  end

  defp deadline(%Config{deadline: nil}), do: nil
  defp deadline(%Config{deadline: ms}), do: System.monotonic_time(:millisecond) + ms

  # ---------------------------------------------------------------------------------------
  # The keyring that governs

  defp governing_keyring(%Config{trust: {:key_chain, :unavailable}}),
    do: {:ok, :unavailable, %TrustRoot{kind: :key_chain}}

  defp governing_keyring(%Config{trust: {:key_chain, keys}}),
    do: {:ok, Keyring.from_key_chain(keys), %TrustRoot{kind: :key_chain}}

  defp governing_keyring(%Config{trust: :keyless}), do: {:ok, nil, %TrustRoot{kind: :none}}

  defp governing_keyring(%Config{trust: :default, environment: "prod"} = config) do
    if Config.online?(config),
      do: read_online(config.current_keyring, config, :current_keyring),
      else: load(Keyring.compiled_pin(), config, nil, :compiled_pin)
  end

  defp governing_keyring(%Config{trust: :default} = config),
    do: rejected(config, :configuration_no_keyring, %{environment: config.environment})

  defp governing_keyring(%Config{trust: {:keyring, bytes, location}} = config),
    do: load(bytes, config, location, :supplied_keyring)

  defp governing_keyring(%Config{trust: {:keyring_file, path}} = config) do
    case JSON.read_file(path) do
      {:ok, bytes} -> load(bytes, config, path, :supplied_keyring)
      {:error, :input_too_large} -> refused(config, {:json, :input_too_large})
      {:error, {:unreadable, reason}} -> {:error, ReadError.new(path, reason)}
    end
  end

  defp governing_keyring(%Config{trust: {:keyring_source, source}} = config),
    do: read_online(source, config, :supplied_keyring)

  defp load(bytes, config, location, kind) do
    case Keyring.load(bytes, config.environment, location) do
      {:ok, keyring} ->
        {:ok, keyring, %TrustRoot{kind: kind, digest: keyring.digest, location: location}}

      {:error, failure} ->
        refused(config, failure)
    end
  end

  # A keyring read online: any failure is a failed read, so no key binds (section 8.3).
  defp read_online({module, state}, config, kind) do
    case fetch(module, state) do
      {:ok, keyring, location, _meta} ->
        case load_read(keyring, config.environment, location) do
          {:ok, keyring} ->
            {:ok, keyring, %TrustRoot{kind: kind, digest: keyring.digest, location: location}}

          {:error, _failure} ->
            {:ok, :unavailable, %TrustRoot{kind: kind, location: location}}
        end

      _failed ->
        {:ok, :unavailable, %TrustRoot{kind: kind}}
    end
  end

  defp fetch(module, state) do
    module.fetch(state)
  catch
    _kind, _reason -> {:error, :keyring_source_fault}
  end

  defp load_read({:bytes, bytes}, environment, location) when is_binary(bytes),
    do: Keyring.load(bytes, environment, location)

  defp load_read({:value, value}, environment, location),
    do: Keyring.load_value(value, environment, location)

  defp load_read(_keyring, _environment, _location), do: {:error, :keyring_members}

  defp refused(config, failure),
    do: rejected(config, :configuration_keyring_refused, %{failure: failure})

  defp rejected(%Config{messages: messages}, id, assigns),
    do: {:rejected, Rejection.new(:configuration_error, Messages.render(messages, id, assigns))}

  # ---------------------------------------------------------------------------------------
  # The sources of an online run

  defp frame(config, deadline) do
    case Frame.build(config, deadline) do
      {:ok, frame} ->
        {:ok, frame}

      {:configuration_error, :no_source, assigns} ->
        rejected(config, :configuration_no_source, assigns)

      {:configuration_error, :identity_forbidden, assigns} ->
        rejected(config, :configuration_identity_forbidden, assigns)
    end
  end
end
