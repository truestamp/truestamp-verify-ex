# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.VerifyTest do
  @moduledoc """
  `mix truestamp.verify` writes what `Truestamp.Verify.CLI` gives, stdout and stderr, as raw
  bytes, and exits with its code (SPEC.md section 12.2): the same bytes on a latin1 device,
  so the JSON stays UTF-8 whatever the locale; and, run as its own process on a build that
  has to compile, still exactly one JSON document on stdout. Not async: it captures standard
  error.
  """

  use ExUnit.Case, async: false

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verify.{CLI, JCS, JSON}
  alias Truestamp.Verify.Test.{TaskRun, Verification}

  @item Verification.path("vectors/positive/item.proof.json")
  @test_keyring Verification.path("vectors/keyring.test.json")

  test "writes the command's output and exits with its code" do
    argv = [@item, "--environment", "test", "--keyring", @test_keyring]
    {6, stdout, stderr} = CLI.main(argv)
    {written_out, written_err, ended} = TaskRun.capture(fn -> Verify.run(argv) end)
    assert ended == {:exit, {:shutdown, 6}}
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = TaskRun.capture(fn -> Verify.run(["--json"]) end)
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ CLI.usage()
  end

  test "returns for exit code 0 and exits with every other code of 12.2" do
    # No offline case exits 0 (SPEC.md 13.3), so finish/1 is given each code directly.
    for code <- 0..8 do
      {written_out, written_err, ended} =
        TaskRun.capture(fn -> Verify.finish({code, ["out"], "err"}) end)

      assert {written_out, written_err} == {"out", "err"}
      assert ended == if(code == 0, do: :ok, else: {:exit, {:shutdown, code}})
    end
  end

  @tag :tmp_dir
  test "writes raw bytes, so a report naming a non-ASCII path is UTF-8 JSON on a latin1 device",
       %{tmp_dir: tmp_dir} do
    dir = Path.join(tmp_dir, "clés-鍵")
    File.mkdir_p!(dir)
    keyring = Path.join(dir, "k.json")
    File.cp!(@test_keyring, keyring)
    argv = [@item, "--environment", "test", "--keyring", keyring]
    {6, stdout, stderr} = CLI.main(argv)

    {written_out, written_err, {:exit, {:shutdown, 6}}} =
      TaskRun.capture(fn -> Verify.run(argv) end, :latin1)

    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
    assert {:ok, report} = JSON.parse(String.trim_trailing(written_out, "\n"))
    assert report["trust_root"]["location"] == keyring
    assert written_err =~ "from #{keyring}"
  end

  test "quiet_start/0 keeps Logger's default handler on standard error while it builds" do
    {:ok, before} = :logger.get_handler_config(:default)
    assert TaskRun.capture(fn -> Verify.quiet_start() end) == {"", "", :ok}
    assert {:ok, ^before} = :logger.get_handler_config(:default)
  end

  test "quiet_start/0 leaves Logger alone when its default handler is not on standard output" do
    {:ok, %{module: module} = handler} = :logger.get_handler_config(:default)
    :ok = :logger.remove_handler(:default)

    try do
      assert TaskRun.capture(fn -> Verify.quiet_start() end) == {"", "", :ok}
      assert {:error, {:not_found, :default}} = :logger.get_handler_config(:default)
    after
      :ok = :logger.add_handler(:default, module, handler)
    end
  end

  @tag :tmp_dir
  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document",
       %{tmp_dir: tmp_dir} do
    dir = Path.join(tmp_dir, "clés-鍵")
    File.mkdir_p!(dir)
    keyring = Path.join(dir, "k.json")
    File.cp!(@test_keyring, keyring)

    {stdout, exit_status, stderr} =
      TaskRun.fresh_build(
        "truestamp.verify",
        [@item, "--environment", "test", "--keyring", keyring],
        [Mix.Tasks.Truestamp.Verify, Truestamp.Verify.CLI]
      )

    assert exit_status == 6, stderr
    assert String.ends_with?(stdout, "}\n") and length(String.split(stdout, "\n")) == 2, stdout
    assert {:ok, report} = JSON.parse(String.trim_trailing(stdout, "\n")), stdout
    assert JCS.encode(report) <> "\n" == stdout
    assert report["label"] == "supplied-keyring"
    assert report["trust_root"]["location"] == keyring
  end
end
