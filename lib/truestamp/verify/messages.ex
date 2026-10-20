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

  Every message is rendered in the process that called `Truestamp.Verify.verify/2`,
  `Truestamp.Verify.verify_file/2` or `Truestamp.Verify.apply_expected_hash/2`, never in a
  task, though the identity reads, and every read under a deadline, run in tasks
  (`Truestamp.Verify.Reader`, "Processes"), so process-local state such as a Gettext
  locale applies to every row and every rejection.

  ## Rendering again

  A row (`Truestamp.Verify.Row`) and a bare rejection (`Truestamp.Verify.Rejection`) keep
  the id of their message and the assigns it was rendered with, beside the text, so a caller
  that stores them can render them again later, in another locale or through another
  module, with `Truestamp.Verify.Row.render/2` and `Truestamp.Verify.Rejection.render/2`.
  The assigns are Elixir terms (atoms, tuples, strings, integers), not JSON values, and a
  report's JSON never holds them, so a caller that stores them keeps them as terms.

  ## A message module that faults

  A message module that raises, throws or exits, or gives a value that is neither text (a
  string that is valid UTF-8) nor nil, is a fault inside the verifier (SPEC.md section 10.5),
  with the outcome a fault has where it happens: before steps 0 to 3 have passed, a
  `Truestamp.Verify.Fault` and no report; from ENVIRONMENT to EXPECTED_HASH, one
  `internal_error` row of that step, the run ended as `Truestamp.Verify.Fault` says. The rows
  that record the fault, the `internal_error` row and the `skip prior_failure` rows after it,
  take the English default's text whenever the module faults on them too, so a faulty module
  can never turn a fault into a raise.
  """

  alias Truestamp.Verify.Messages.English

  @typedoc "A message id."
  @type id :: atom()

  @typedoc """
  A message as a row or a rejection keeps it: its id, the assigns it was rendered with, and
  its text.
  """
  @type rendered :: {id(), map(), String.t()}

  @doc """
  The text of message `id` with `assigns`, or nil to use the English default for it.
  """
  @callback message(id(), assigns :: map()) :: String.t() | nil

  @doc """
  The text of `id` with `assigns` from `module`, falling back to the English default. Raises
  `ArgumentError` when `module` gives a value that is neither a valid UTF-8 string nor nil.
  """
  @spec render(module(), id(), map()) :: String.t()
  def render(module, id, assigns \\ %{})
      when is_atom(module) and is_atom(id) and is_map(assigns) do
    case module.message(id, assigns) do
      nil -> English.message(id, assigns)
      text when is_binary(text) -> if String.valid?(text), do: text, else: not_text!(module, id)
      _other -> not_text!(module, id)
    end
  end

  defp not_text!(module, id),
    do: raise(ArgumentError, "#{inspect(module)} gave no UTF-8 text for the message #{id}")

  @doc false
  # The message as a row or a rejection keeps it: `{id, assigns, text}`, the text from
  # `module`.
  @spec rendered(module(), id(), map()) :: rendered()
  def rendered(module, id, assigns), do: {id, assigns, render(module, id, assigns)}

  @doc false
  # The id, the assigns and the text of a row's or a rejection's message, given as text alone
  # (no id, no assigns) or as `rendered/3` gave it.
  @spec parts(String.t() | rendered()) :: {id() | nil, map(), String.t()}
  def parts(text) when is_binary(text), do: {nil, %{}, text}

  def parts({id, assigns, text} = rendered)
      when is_atom(id) and id != nil and is_map(assigns) and is_binary(text),
      do: rendered

  @doc false
  # As `rendered/3`, but with the English default's text when `module` faults on `id` (it
  # raises, throws or exits, or gives a value that is neither UTF-8 text nor nil): for the
  # rows that record a fault, so that a faulty module cannot turn the fault into a raise.
  @spec rendered_or_english(module(), id(), map()) :: rendered()
  def rendered_or_english(module, id, assigns) do
    rendered(module, id, assigns)
  catch
    _kind, _reason -> {id, assigns, English.message(id, assigns)}
  end
end
