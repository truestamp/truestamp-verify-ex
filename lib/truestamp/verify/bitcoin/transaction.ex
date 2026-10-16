# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Bitcoin.Transaction do
  @moduledoc """
  A `raw_transaction` and its well-formedness (SPEC.md section 10.2, step 9 (d)). The bytes
  are well formed when, in this order:

  | Rule | Holds when | Else |
  |---|---|---|
  | parse | they parse completely as a transaction serialized without witness data (BIP 144): the version, at least one input, the outputs and the lock time, with every compact size in its shortest form and no byte after the lock time | `:parse` |
  | length | they are not exactly 64 octets long, so they cannot pass for an inner node of a Bitcoin Merkle tree (CVE-2017-12842) | `:length` |
  | op_return | exactly one output script begins with 0x6a, and that script is exactly 0x6a 0x20 followed by 32 bytes | `:op_return` |

  `parse/1` gives the 32 bytes that OP_RETURN script pushes, or the first rule that fails, by
  the names `vectors/corpus/bitcoin/` gives them (section 13.2).

  A transaction serialized with its witness has the marker octet 0x00 where a count of
  inputs stands, so it reads as a transaction with no input and fails `:parse`.
  """

  alias Truestamp.Verify.Bitcoin

  @typedoc "The first rule of a well-formed `raw_transaction` that the bytes break."
  @type rule :: :parse | :length | :op_return

  # One input: the previous output (32-octet hash, 4-octet index), a script, a sequence.
  @outpoint_octets 36
  @sequence_octets 4
  @value_octets 8
  @lock_time_octets 4

  @doc """
  `{:ok, op_return}`, the 32 bytes the one OP_RETURN script pushes, when `bytes` is a
  well-formed `raw_transaction`; otherwise `{:error, rule}`, the first rule it breaks.
  """
  @spec parse(binary()) :: {:ok, <<_::256>>} | {:error, rule()}
  def parse(bytes) when is_binary(bytes) do
    with {:ok, scripts} <- output_scripts(bytes),
         :ok <- not_64_octets(bytes),
         do: op_return(scripts)
  end

  # The version, at least one input, the outputs and the lock time, and nothing after.
  defp output_scripts(<<_version::binary-4, rest::binary>>) do
    with {:ok, inputs, rest} when inputs >= 1 <- Bitcoin.compact_size(rest),
         {:ok, rest} <- skip_inputs(inputs, rest),
         {:ok, outputs, rest} <- Bitcoin.compact_size(rest),
         {:ok, scripts, <<_lock_time::binary-size(@lock_time_octets)>>} <-
           read_outputs(outputs, rest, []) do
      {:ok, scripts}
    else
      _broken -> {:error, :parse}
    end
  end

  defp output_scripts(_bytes), do: {:error, :parse}

  defp skip_inputs(0, rest), do: {:ok, rest}

  defp skip_inputs(n, <<_outpoint::binary-size(@outpoint_octets), rest::binary>>) do
    with {:ok, length, rest} <- Bitcoin.compact_size(rest),
         <<_script::binary-size(^length), _sequence::binary-size(@sequence_octets), rest::binary>> <-
           rest,
         do: skip_inputs(n - 1, rest)
  end

  defp skip_inputs(_n, _rest), do: :error

  defp read_outputs(0, rest, scripts), do: {:ok, Enum.reverse(scripts), rest}

  defp read_outputs(n, <<_value::binary-size(@value_octets), rest::binary>>, scripts) do
    with {:ok, length, rest} <- Bitcoin.compact_size(rest),
         <<script::binary-size(^length), rest::binary>> <- rest,
         do: read_outputs(n - 1, rest, [script | scripts])
  end

  defp read_outputs(_n, _rest, _scripts), do: :error

  defp not_64_octets(bytes) when byte_size(bytes) == 64, do: {:error, :length}
  defp not_64_octets(_bytes), do: :ok

  defp op_return(scripts) do
    case Enum.filter(scripts, &match?(<<0x6A, _::binary>>, &1)) do
      [<<0x6A, 0x20, pushed::binary-32>>] -> {:ok, pushed}
      _none_or_several_or_other -> {:error, :op_return}
    end
  end
end
