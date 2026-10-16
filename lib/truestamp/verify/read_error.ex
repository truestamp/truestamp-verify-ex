# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ReadError do
  @moduledoc """
  An input that cannot be read at all, such as a proof or keyring file that is missing or
  is not a file. It is not a verification result: it gives no report, and a command line
  exits 1 for it (SPEC.md sections 10.2, step 0, and 12.2).

  A file that is read and then breaks a rule of section 10.1 is a verification result
  instead: a bare rejection, or `configuration_error` for a keyring.
  """

  @type t :: %__MODULE__{path: Path.t(), reason: term(), message: String.t()}

  defexception [:path, :reason, :message]

  @doc "The error for `path`, which could not be read for `reason`."
  @spec new(Path.t(), term()) :: t()
  def new(path, reason) do
    %__MODULE__{
      path: path,
      reason: reason,
      message: "Cannot read #{path}: #{:file.format_error(reason)}"
    }
  end
end
