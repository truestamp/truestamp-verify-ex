# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.Verify do
  @shortdoc "Verifies a Truestamp proof, as SPEC.md section 10 says"

  @moduledoc """
  Verifies a Truestamp proof (SPEC.md sections 10 and 12.2):

      mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME]
                                [--expected-hash HEX] [--trace FILE] [--online]

  Standard output carries one JSON document, written with JCS: the report of section 10.5,
  or a bare rejection's `{code, message, sub_reason}`; on exit 1 or 2 it carries nothing.
  Standard error carries the human output. Both streams are written as raw bytes, so the
  JSON is UTF-8 whatever the locale. The exit code is section 12.2's.
  `Truestamp.Verify.CLI` describes each option and each output.

  The task compiles the project first with a quiet shell, its compiler output on standard
  error, so a run that compiles writes nothing to standard output but the document. In a
  project that depends on this library, Mix compiles the dependencies before it can find the
  task, and writes that build's lines to standard output: where standard output must carry
  only the document, run `mix compile` first, or alias the task in the project's `mix.exs`
  to compile quietly before it runs, as this library's own `mix.exs` does:

      defp aliases do
        for task <- ~w(truestamp.verify truestamp.conformance truestamp.agent_lines),
            do: {String.to_atom(task), [&quiet_compile/1, task]}
      end

      defp quiet_compile(_args) do
        {shell, group_leader} = {Mix.shell(), Process.group_leader()}
        Mix.shell(Mix.Shell.Quiet)
        Process.group_leader(self(), Process.whereis(:standard_error))

        try do
          Mix.Task.run("compile")
        after
          Process.group_leader(self(), group_leader)
          Mix.shell(shell)
        end
      end

  To check a vector of the specification, give its environment and keyring:
  `mix truestamp.verify vectors/positive/item.proof.json --environment test --keyring
  vectors/keyring.test.json`. With no option the run is under E_v `prod`, offline.
  """

  use Mix.Task

  alias Truestamp.Verify.CLI

  @impl Mix.Task
  def run(argv) do
    quiet_start()
    argv |> CLI.main() |> finish()
  end

  @doc """
  Compiles and starts the project with standard output kept for the task's document: a quiet
  shell, standard error as the group leader, and Logger's default handler writing to
  standard error while the build runs.
  """
  @spec quiet_start() :: :ok
  def quiet_start do
    shell = Mix.shell()
    group_leader = Process.group_leader()
    handler = log_to_standard_error()
    Mix.shell(Mix.Shell.Quiet)
    Process.group_leader(self(), Process.whereis(:standard_error))

    try do
      Mix.Task.run("app.start")
    after
      Process.group_leader(self(), group_leader)
      Mix.shell(shell)
      restore_log_handler(handler)
    end

    :ok
  end

  # Logger's default handler writes from its own process, not under this one's group leader,
  # so it is added again with standard error as its device while the build runs.
  defp log_to_standard_error do
    case :logger.get_handler_config(:default) do
      {:ok, %{module: module, config: %{type: :standard_io}} = handler} ->
        :ok = :logger.remove_handler(:default)
        :ok = :logger.add_handler(:default, module, put_in(handler.config.type, :standard_error))
        handler

      _other ->
        nil
    end
  end

  defp restore_log_handler(nil), do: :ok

  defp restore_log_handler(%{module: module} = handler) do
    :ok = :logger.remove_handler(:default)
    :ok = :logger.add_handler(:default, module, handler)
  end

  @doc """
  Writes an outcome `{exit_code, stdout, stderr}`, each stream as raw bytes, then exits with
  its code, or returns `:ok` when the code is 0.
  """
  @spec finish({non_neg_integer(), iodata(), iodata()}) :: :ok
  def finish({code, stdout, stderr}) do
    IO.binwrite(:stdio, stdout)
    IO.binwrite(:stderr, stderr)
    if code == 0, do: :ok, else: exit({:shutdown, code})
  end
end
