# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Messages do
  @moduledoc """
  The text of rows and rejections, for display only (SPEC.md sections 10.5 and 12.1: a
  message is never compared, and nothing depends on its wording).

  Every row and every bare rejection names its message by an id, an atom such as
  `:key_binding_failed_compiled_pin`, with assigns that hold the values the text may use.
  A message module turns the two into text. `Truestamp.Verify.Messages.English` is the
  default, and its English is kept stable, so a caller that keys translations on it, as a
  gettext catalogue does, can rely on it.

  A caller gives its own module with the `:messages` option. It implements
  `c:message/2`, and returns nil for any id it leaves to the English default:

      defmodule MyApp.VerifyMessages do
        @behaviour Truestamp.Verify.Messages
        use Gettext, backend: MyApp.Gettext

        @impl true
        def message(:signature_invalid, _assigns),
          do: dgettext("verify", "The signature does not verify under the key.")

        def message(_id, _assigns), do: nil
      end

  `Truestamp.Verify.Messages.English.ids/0` lists every id the library uses.
  """

  alias Truestamp.Verify.Messages.English

  @typedoc "A message id."
  @type id :: atom()

  @doc """
  The text of message `id` with `assigns`, or nil to use the English default for it.
  """
  @callback message(id(), assigns :: map()) :: String.t() | nil

  @doc "The text of `id` with `assigns` from `module`, falling back to the English default."
  @spec render(module(), id(), map()) :: String.t()
  def render(module, id, assigns \\ %{})
      when is_atom(module) and is_atom(id) and is_map(assigns) do
    case module.message(id, assigns) do
      text when is_binary(text) -> text
      nil -> English.message(id, assigns)
    end
  end
end
