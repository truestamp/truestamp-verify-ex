# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Barrier do
  @moduledoc """
  A barrier for `count` processes: `arrive/2` returns only once `count` processes have
  arrived, so reads that each arrive before they answer can all answer only when they run
  at once. A process that waits longer than its timeout exits, as `GenServer.call/3` does.
  """

  use GenServer

  @doc "A barrier that opens when `count` processes have arrived."
  @spec start_link(pos_integer()) :: GenServer.on_start()
  def start_link(count) when is_integer(count) and count > 0,
    do: GenServer.start_link(__MODULE__, count)

  @doc "Arrives at `barrier`, and waits up to `timeout` ms for it to open: `:open`."
  @spec arrive(pid(), timeout()) :: :open
  def arrive(barrier, timeout), do: GenServer.call(barrier, :arrive, timeout)

  @impl true
  def init(count), do: {:ok, %{count: count, waiting: []}}

  @impl true
  def handle_call(:arrive, from, %{count: count, waiting: waiting} = state) do
    waiting = [from | waiting]

    if length(waiting) == count do
      Enum.each(waiting, &GenServer.reply(&1, :open))
      {:noreply, %{state | waiting: []}}
    else
      {:noreply, %{state | waiting: waiting}}
    end
  end
end
