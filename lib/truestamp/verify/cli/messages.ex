# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CLI.Messages do
  @moduledoc """
  The messages of `mix truestamp.verify`: `Truestamp.Verify.Messages.English`, but where a
  message tells the reader how to run again, it names the command's options. Every other
  message is English's.
  """

  @behaviour Truestamp.Verify.Messages

  @impl true
  def message(:configuration_no_keyring, %{environment: environment}) do
    "A run whose environment is #{environment} checks proofs of that environment against a " <>
      "supplied keyring, and none was given: run again with --keyring FILE, or with " <>
      "--no-keyring to check the signature only against the key the document carries."
  end

  def message(:environment_mismatch_unmarked, %{environment: environment}) do
    "This proof carries no environment marker, so it is a production proof, and this run " <>
      "checks proofs of Truestamp's #{environment} environment. To check it as a production " <>
      "proof, run again without --environment."
  end

  def message(:environment_mismatch_marked_under_prod, %{marker: marker}) do
    "This proof is marked as issued by Truestamp's #{marker} environment, which is for " <>
      "#{purpose(marker)}. It is not a production proof. " <> again(marker)
  end

  def message(:environment_mismatch_marked, %{marker: marker, environment: environment}) do
    "This proof is marked as issued by Truestamp's #{marker} environment, and this run " <>
      "checks proofs of its #{environment} environment. " <> again(marker)
  end

  def message(_id, _assigns), do: nil

  defp purpose("dev"), do: "development"
  defp purpose(_marker), do: "testing"

  # SPEC.md 6.4: a command that works, an offline one, since no public source serves the
  # regtest chain a dev, staging or test proof commits to.
  defp again(marker),
    do:
      "To check it against the #{marker} keyring, run again offline with --environment " <>
        "#{marker} and --keyring FILE."
end
