# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Spec.Constants do
  @moduledoc """
  The constants of SPEC.md section 9, as compiled constants, compiled from
  `spec/constants.json`. Each is a function named after the constant in lowercase, such as
  `max_read_octets/0` for MAX_READ_OCTETS, and `all/0` gives the file's object.

  SMALL_ORDER_KEYS has a file of its own and is compiled into
  `Truestamp.Verify.Ed25519`. `Truestamp.Verify.JSON` holds its own copies of
  MAX_READ_OCTETS, MAX_DEPTH and MAX_INTEGER, because this module is compiled with it; a
  test holds those copies equal to these.
  """

  alias Truestamp.Verify.Spec.Data

  @external_resource Data.path("constants.json")

  @constants Data.read!("constants.json")

  @doc "Every constant, by its name in `spec/constants.json`."
  @spec all() :: %{String.t() => non_neg_integer() | String.t()}
  def all, do: @constants

  for {name, value} <- @constants do
    function = name |> String.downcase() |> String.to_atom()
    @doc "#{name} (SPEC.md section 9): `#{inspect(value)}`."
    def unquote(function)(), do: unquote(value)
  end
end
