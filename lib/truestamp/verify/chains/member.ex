# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Chains.Member do
  @moduledoc """
  What every module of the registry (`Truestamp.Verify.Chains`) has, whatever its roles: its
  name. A module is a commitment chain (`Truestamp.Verify.CommitmentChain`), an entropy
  source (`Truestamp.Verify.EntropySource`), or both.
  """

  @doc """
  The name, as COMMITMENTS, `spec/networks.json` and an entropy object's `source` write it,
  such as `"bitcoin"`.
  """
  @callback name() :: String.t()
end
