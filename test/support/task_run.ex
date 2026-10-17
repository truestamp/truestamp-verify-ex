# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.TaskRun do
  @moduledoc """
  Runs a Mix task of this library two ways: in the test's own process, capturing what it
  writes to each stream and how it ends; and as its own `mix` process on a copy of the test
  build that has to compile, as truestamp-verification's generator runs it.
  """

  import ExUnit.Assertions
  import ExUnit.CaptureIO

  @project Path.expand("../..", __DIR__)

  @doc """
  `{stdout, stderr, ended}` of `fun`, each device capturing in `encoding`; `ended` is what
  `fun` returned, or `{:exit, reason}`.
  """
  @spec capture((-> term()), :unicode | :latin1) :: {binary(), binary(), term()}
  def capture(fun, encoding \\ :unicode) do
    written_err =
      capture_io(:stderr, [encoding: encoding], fn ->
        written_out =
          capture_io([encoding: encoding], fn ->
            ended =
              try do
                fun.()
              catch
                :exit, reason -> {:exit, reason}
              end

            send(self(), {:ended, ended})
          end)

        send(self(), {:stdout, written_out})
      end)

    assert_received {:stdout, written_out}
    assert_received {:ended, ended}
    {written_out, written_err, ended}
  end

  @doc """
  Runs `mix <task> <argv>` as its own process, under the C locale, on a copy of this test
  build in a temporary directory, removed when the test ends, with the project's compile manifest removed, so the project compiles
  again, and with the BEAM files of `modules` removed, so Mix has to compile before it can
  find the task, as on a fresh checkout. Gives `{stdout, exit_status, stderr}` and checks
  that the build compiled the modules again.
  """
  @spec fresh_build(String.t(), [String.t()], [module()]) ::
          {binary(), non_neg_integer(), binary()}
  def fresh_build(task, argv, modules) do
    root = Path.join(System.tmp_dir!(), "truestamp-build-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    ExUnit.Callbacks.on_exit(fn -> File.rm_rf!(root) end)
    build = Path.join(root, "test")
    File.cp_r!(Mix.Project.build_path(), build)
    lib = Path.join(build, "lib/truestamp_verify")
    File.rm!(Path.join(lib, ".mix/compile.elixir"))
    beams = for module <- modules, do: Path.join(lib, "ebin/#{module}.beam")
    Enum.each(beams, &File.rm!/1)
    stderr_file = Path.join(root, "stderr.txt")

    {stdout, exit_status} =
      System.cmd(
        "sh",
        ["-c", ~s(task="$1"; out="$2"; shift 2; exec mix "$task" "$@" 2>"$out"), "sh", task] ++
          [stderr_file | argv],
        cd: @project,
        env: [
          {"MIX_ENV", "test"},
          {"MIX_BUILD_ROOT", root},
          {"MIX_BUILD_PATH", nil},
          {"LC_ALL", "C"},
          {"LANG", nil},
          {"LC_CTYPE", nil}
        ]
      )

    assert Enum.all?(beams, &File.exists?/1)
    {stdout, exit_status, File.read!(stderr_file)}
  end
end
