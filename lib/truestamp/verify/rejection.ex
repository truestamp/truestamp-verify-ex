# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Rejection do
  @moduledoc """
  A bare rejection (SPEC.md section 10.2, the gate): a failure at steps 0 to 3, which gives
  only `{code, message, sub_reason}`, with no report and no verdict.

  The code is one of the four whose status is "bare" in section 12.1:
  `configuration_error`, `input_too_large`, `malformed_json` or `invalid_envelope`.
  `sub_reason` is present for `malformed_json` and `invalid_envelope` only, and is one of the
  names `Truestamp.Verify.ReasonCodes.sub_reasons/1` lists for the code. `new/4` refuses
  anything else.

  | Field | Holds |
  |---|---|
  | `code` | the bare code, an atom |
  | `message` | for display only, never compared; written by the run's message module |
  | `sub_reason` | for `malformed_json` and `invalid_envelope`, the rule broken; else nil |
  | `message_id`, `assigns` | the id of the message and the assigns it was rendered with, as a row keeps them (`Truestamp.Verify.Row`); nil and empty for a rejection built from text alone |
  | `reason` | for `configuration_error`, which check of step 0 failed (below); else nil |
  | `chain`, `network` | for `configuration_error`, the chain and the network the failed check concerns, or nil when it concerns none |

  **The reason of a configuration error.** Every `configuration_error` a run gives names the
  check of step 0 that failed, one of `configuration_reasons/0`:

  | `reason` | When | `chain`, `network` |
  |---|---|---|
  | `:no_keyring` | the default trust under an environment other than `prod`, which has no keyring (section 6.4) | nil |
  | `:keyring_refused` | a keyring file, a supplied keyring or Truestamp's key chain fails a load check; `assigns.failure` names the check | nil |
  | `:current_keyring_location` | the current keyring's source read a location other than Truestamp's own (section 8.3); `assigns.location` names it | nil |
  | `:no_source` | an online run pins a network it has no source for | the network's |
  | `:identity_forbidden` | a source's identity read gives a value step 0 forbids for its network | the network's |
  | `:invalid_policy` | a source policy `{:at_least, n}` whose n is 0 or above the number of its network's sources, or a policy section 9 does not define | the network's |
  | `:nist_sources` | several sources for NIST's Randomness Beacon, which is one source (section 9) | `"nist"`, nil |

  `message_id`, `assigns`, `reason`, `chain` and `network` are not part of the output of
  section 10.2, so `to_map/1` leaves them out. `render/2` writes the message again through
  another message module.

  It is an exception, so `Truestamp.Verify.verify!/2` can raise it.
  """

  alias Truestamp.Verify.{Messages, ReasonCodes, Row}

  @configuration_reasons [
    :no_keyring,
    :keyring_refused,
    :current_keyring_location,
    :no_source,
    :identity_forbidden,
    :invalid_policy,
    :nist_sources
  ]

  @typedoc "Which check of step 0 a `configuration_error` failed."
  @type configuration_reason ::
          :no_keyring
          | :keyring_refused
          | :current_keyring_location
          | :no_source
          | :identity_forbidden
          | :invalid_policy
          | :nist_sources

  @type t :: %__MODULE__{
          code: ReasonCodes.code(),
          message: String.t(),
          sub_reason: atom() | nil,
          message_id: Messages.id() | nil,
          assigns: map(),
          reason: configuration_reason() | nil,
          chain: String.t() | nil,
          network: String.t() | nil
        }

  defexception [
    :code,
    :message,
    :sub_reason,
    :message_id,
    :reason,
    :chain,
    :network,
    assigns: %{}
  ]

  @doc "The reasons a `configuration_error` can give, in the order of the table above."
  @spec configuration_reasons() :: [configuration_reason()]
  def configuration_reasons, do: @configuration_reasons

  @doc """
  A bare rejection with `code` and `message`, and `sub_reason` when the code has one.
  `message` is text, or `{id, assigns, text}` as `Truestamp.Verify.Messages` rendered it
  (`t:Truestamp.Verify.Row.message/0`). Options, for `configuration_error` only:

  - `:reason`, one of `configuration_reasons/0`, required with either of the others;
  - `:chain` and `:network`, the chain and the network it concerns, strings or nil.

  Raises `ArgumentError` for a code that is not bare, a `sub_reason` the code does not list,
  or a missing one, an option other than these, a reason not listed, or an option given with
  another code.
  """
  @spec new(ReasonCodes.code(), Row.message(), atom() | nil, keyword()) :: t()
  def new(code, message, sub_reason \\ nil, options \\ []) do
    unless ReasonCodes.code?(code) and ReasonCodes.status(code) == :bare,
      do: raise(ArgumentError, "#{inspect(code)} is not a bare code of SPEC.md 12.1")

    listed = ReasonCodes.sub_reasons(code)

    unless (listed == [] and is_nil(sub_reason)) or sub_reason in listed,
      do: raise(ArgumentError, "#{inspect(sub_reason)} is not a sub_reason of #{code}")

    {id, assigns, text} = Messages.parts(message)
    {reason, chain, network} = context(code, options)

    %__MODULE__{
      code: code,
      message: text,
      sub_reason: sub_reason,
      message_id: id,
      assigns: assigns,
      reason: reason,
      chain: chain,
      network: network
    }
  end

  defp context(_code, []), do: {nil, nil, nil}

  defp context(:configuration_error, options) do
    {reason, rest} = Keyword.pop(options, :reason)
    {chain, rest} = Keyword.pop(rest, :chain)
    {network, rest} = Keyword.pop(rest, :network)

    unless rest == [],
      do: raise(ArgumentError, "#{inspect(Keyword.keys(rest))} are not options of a rejection")

    unless reason in @configuration_reasons,
      do: raise(ArgumentError, "#{inspect(reason)} is not a reason of configuration_error")

    unless (is_nil(chain) or is_binary(chain)) and (is_nil(network) or is_binary(network)),
      do: raise(ArgumentError, "a rejection's chain and network are strings or nil")

    {reason, chain, network}
  end

  defp context(code, _options),
    do: raise(ArgumentError, "#{code} takes no reason, chain or network")

  @doc """
  The text `messages`, a message module (`Truestamp.Verify.Messages`), gives `rejection`,
  from its `message_id` and `assigns`: the text a run under that module gives it. A
  rejection built from text alone keeps its text.
  """
  @spec render(t(), module()) :: String.t()
  def render(%__MODULE__{message_id: nil, message: text}, _messages), do: text

  def render(%__MODULE__{message_id: id, assigns: assigns}, messages),
    do: Messages.render(messages, id, assigns)

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
