# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.NetworkGuard do
  @moduledoc """
  No test reaches the network. `install/0` makes every Req request without a plug of its
  own answer with `Refused`, raised, by setting Req's default options, and `test_helper.exs`
  installs it and proves it fires before any test runs. A test of an HTTP source gives its
  own `Req.Test` stub; only the tests tagged `:live`, run with `task test-live`, leave the
  guard out.
  """

  defmodule Refused do
    @moduledoc "Raised by a request that would have reached the network in a test."
    defexception [:url, message: "a test tried to reach the network"]
  end

  @doc "Installs the guard, as Req's default plug."
  @spec install() :: :ok
  def install do
    Req.default_options(plug: &refuse/1)
    :ok
  end

  @doc "The guard's plug: refuses every request."
  @spec refuse(Plug.Conn.t()) :: no_return()
  def refuse(conn),
    do: raise(Refused, url: "#{conn.scheme}://#{conn.host}#{conn.request_path}")

  @doc "Whether the guard is installed and fires: a request to a real host must raise `Refused`."
  @spec fires?() :: boolean()
  def fires? do
    Req.get!("https://www.truestamp.com/.well-known/keyring.json", retry: false)
    false
  rescue
    Refused -> true
  end
end
