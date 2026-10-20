# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.KeyringSources.Replay do
  @moduledoc """
  A `Truestamp.Verify.KeyringSource` that answers the keyring read from a replay file of
  SPEC.md section 13.2: the record whose read is `{"kind": "keyring", "url": url}`.

  A found answer's value is `{"keyring": <the keyring read>}`, a JSON value with no bytes of
  its own, so the keyring it gives has no digest (section 13.2). Any other answer, or none,
  is a failed read.

  A case's `config` names no keyring origin, so every keyring read a conformance case makes
  is of www.truestamp.com, the default `url` here (section 13.2). A keyring read from
  another origin, such as `Truestamp.Verify.Online.defaults/1`'s `:keyring_origin` gives,
  is a supplied keyring (section 8.3); no case can name one, so this library tests that
  option in its own tests.
  """

  @behaviour Truestamp.Verify.KeyringSource

  alias Truestamp.Verify.Readers.Replay

  @default_url "https://www.truestamp.com/.well-known/keyring.json"

  @doc """
  The source of the keyring at `url` in the replay file `replay`, a `Readers.Replay` state;
  by default the keyring Truestamp publishes.
  """
  @spec new(Replay.t(), String.t()) :: {module(), {Replay.t(), String.t()}}
  def new(%Replay{} = replay, url \\ @default_url), do: {__MODULE__, {replay, url}}

  @impl true
  def fetch({%Replay{fetched_at: fetched_at} = replay, url}) do
    case Replay.answer(replay, %{"kind" => "keyring", "url" => url}) do
      %{"outcome" => "found", "value" => %{"keyring" => keyring}} ->
        {:ok, {:value, keyring}, url, %{source: "replay", fetched_at: fetched_at, cached: false}}

      %{"outcome" => outcome} = answer ->
        {:error, {outcome, answer["reason"]}}

      nil ->
        {:error, :not_in_replay}
    end
  end
end
