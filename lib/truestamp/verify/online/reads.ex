# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.Reads do
  @moduledoc false
  # The engine's side of every read (SPEC.md section 10.4), the same for every reader, in a
  # whole run and in a rule context built over a reader (`Truestamp.Verify.Online.Rule.new/2`):
  #
  # - a reader's answer is normalized to `Truestamp.Verify.Online.Answer`'s three shapes,
  #   and anything else, a raise, a throw or an exit among them, is an unreachable read,
  #   never a fault that could drop a step's rows;
  # - an answer marked cached is refused where the spec requires a live read: every
  #   not-found answer, and every found answer of an identity, the Stellar root or the
  #   Bitcoin tip;
  # - a cached best-chain Bitcoin block at a height g is kept only when its meta carries
  #   `tip_height`, the source's tip it was read under, of at least g + BITCOIN_FINALITY,
  #   and refused otherwise;
  # - one answer per read for the whole run (the spec allows it), kept in the run;
  # - a deadline over the whole online run: a read past it is unreachable.

  alias Truestamp.Verify.Online.Answer
  alias Truestamp.Verify.Spec.Constants

  # Reads whose answer can change, or that the spec requires live (section 10.4).
  @always_live [:stellar_identity, :bitcoin_identity, :stellar_root, :bitcoin_tip]

  @finality Constants.bitcoin_finality()
  @max_integer Constants.max_integer()

  @typedoc "The key of one read in a run's memo."
  @type key :: {term(), String.t() | nil, atom(), map()}

  @doc false
  # The read function a rule uses: reads of `source` on `network`, answered from `memo`
  # when this run has already made them.
  @spec bind({module(), term()}, term(), String.t() | nil, map(), integer() | nil) ::
          (atom(), map() -> Answer.t())
  def bind(reader, source, network, memo, deadline) do
    fn kind, params ->
      key = {source, network, kind, params}

      case Map.fetch(memo, key) do
        {:ok, answer} -> answer
        :error -> read(reader, source, network, kind, params, deadline)
      end
    end
  end

  @doc false
  # Makes one read through `reader`, and normalizes its answer.
  @spec read({module(), term()}, term(), String.t() | nil, atom(), map(), integer() | nil) ::
          Answer.t()
  def read({module, state}, source, network, kind, params, deadline) do
    case remaining(deadline) do
      :expired ->
        {:unreachable, :deadline}

      timeout ->
        {module, state}
        |> call(source, network, kind, params, timeout)
        |> normalize(kind, params)
    end
  end

  defp remaining(nil), do: :infinity

  defp remaining(deadline) do
    left = deadline - System.monotonic_time(:millisecond)
    if left > 0, do: left, else: :expired
  end

  # With no deadline the read runs in this process. With one, it runs in a task the
  # deadline can cut short; the task inherits this process's callers, so a test's stubs
  # still apply.
  defp call({module, state}, source, network, kind, params, :infinity),
    do: guarded(fn -> module.read(state, source, network, kind, params) end)

  defp call({module, state}, source, network, kind, params, timeout) do
    task =
      Task.async(fn -> guarded(fn -> module.read(state, source, network, kind, params) end) end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _timed_out -> {:error, :deadline}
    end
  end

  defp guarded(read) do
    read.()
  catch
    kind, reason -> {:error, {:reader_fault, kind, describe(kind, reason)}}
  end

  defp describe(:error, reason), do: inspect(Exception.normalize(:error, reason, []).__struct__)
  defp describe(_kind, _reason), do: nil

  @doc false
  # A reader's answer to the read of `kind` with `params`, normalized, with the live-read
  # rules applied.
  @spec normalize(term(), atom(), map()) :: Answer.t()
  def normalize({:ok, fields, meta}, kind, params) when is_map(fields) do
    cond do
      not meta?(meta) -> {:unreachable, :malformed_answer}
      not meta.cached -> {:found, fields, meta}
      kind in @always_live -> {:unreachable, :cached_live_read}
      kind == :bitcoin_block_at_height -> final_block(fields, meta, params)
      true -> {:found, fields, meta}
    end
  end

  def normalize({:error, :not_found, meta}, _kind, _params) do
    cond do
      not meta?(meta) -> {:unreachable, :malformed_answer}
      meta.cached -> {:unreachable, :cached_not_found}
      true -> {:not_found, meta}
    end
  end

  def normalize({:error, reason}, _kind, _params), do: {:unreachable, reason}
  def normalize(_other, _kind, _params), do: {:unreachable, :malformed_answer}

  # A cached best-chain block at height g: kept when it was read while the source's tip was
  # at least g + BITCOIN_FINALITY, as its meta's `tip_height`, an INT, says; refused when the
  # meta carries no such tip, or a shorter one.
  defp final_block(fields, %{tip_height: tip} = meta, %{"height" => height})
       when tip in 0..@max_integer and tip >= height + @finality,
       do: {:found, fields, meta}

  defp final_block(_fields, _meta, _params), do: {:unreachable, :cached_not_final}

  defp meta?(%{source: source, fetched_at: %DateTime{}, cached: cached})
       when is_binary(source) and is_boolean(cached),
       do: true

  defp meta?(_meta), do: false
end
