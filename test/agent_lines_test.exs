# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.AgentLinesTest do
  @moduledoc """
  The lines of the agent-sufficiency test (SPEC.md section 7.4): for every run of
  truestamp-verification's `agent-test/runs.txt`, the fixtures' proofs and their flawed
  copies, the lines this library computes are the expected lines on file, every one but the
  two window lines, which the generator writes itself from the answers it recorded.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify.{AgentLines, JCS, JSON}
  alias Truestamp.Verify.Test.Verification

  @dir Verification.path("agent-test")

  @runs for line <-
              @dir |> Path.join("runs.txt") |> File.read!() |> String.split("\n", trim: true),
            not String.starts_with?(line, "#"),
            [id, proof, keyring | _rest] = String.split(line, " "),
            do: %{"environment" => "test", "id" => id, "keyring" => keyring, "proof" => proof}

  test "every run gives the expected lines, but the window's" do
    assert length(@runs) > 700

    for %{"id" => id} = run <- @runs do
      expected =
        @dir
        |> Path.join("expected/#{id}.txt")
        |> File.read!()
        |> String.split("\n", trim: true)
        |> Enum.reject(&String.starts_with?(&1, ["submitted_after ", "submitted_before "]))

      assert {:ok, lines} = AgentLines.lines(run, @dir), id
      assert Enum.sort(lines) == expected, id
    end
  end

  describe "main/1" do
    @tag :tmp_dir
    test "writes one entry per run, an error for a run it cannot read", %{tmp_dir: dir} do
      File.cp!(
        Path.join(@dir, "fixtures/1-item/item.proof.json"),
        Path.join(dir, "item.proof.json")
      )

      File.cp!(Path.join(@dir, "fixtures/1-item/keyring.json"), Path.join(dir, "keyring.json"))
      File.write!(Path.join(dir, "bad.proof.json"), "{")
      File.write!(Path.join(dir, "shape.proof.json"), shape_broken(dir))

      runs = [
        %{
          "environment" => "test",
          "id" => "a",
          "keyring" => "keyring.json",
          "proof" => "item.proof.json"
        },
        %{
          "environment" => "test",
          "id" => "b",
          "keyring" => "keyring.json",
          "proof" => "bad.proof.json"
        },
        %{
          "environment" => "test",
          "id" => "c",
          "keyring" => "keyring.json",
          "proof" => "missing.proof.json"
        },
        %{
          "environment" => "test",
          "id" => "d",
          "keyring" => "keyring.json",
          "proof" => "shape.proof.json"
        }
      ]

      File.write!(Path.join(dir, "runs.json"), JCS.encode(runs))
      assert {0, stdout, _stderr} = AgentLines.main([Path.join(dir, "runs.json")])
      {:ok, [a, b, c, d]} = JSON.parse(IO.iodata_to_binary(stdout))
      assert "environment test" in a["lines"]
      assert b == %{"error" => "refused: malformed_json", "id" => "b"}
      assert c["error"] =~ "missing.proof.json"
      assert d["error"] =~ "SHAPE fails" and d["error"] =~ "DERIVE cannot read it"
    end

    @tag :tmp_dir
    test "refuses a command line or a runs file it cannot use", %{tmp_dir: dir} do
      assert {1, "", _} = AgentLines.main([])
      assert {1, "", _} = AgentLines.main([<<0xFF>>])
      assert {1, "", _} = AgentLines.main([Path.join(dir, "none.json")])

      for {name, bytes} <- [
            {"bad.json", "{,}"},
            {"object.json", "{}"},
            {"run.json", ~s([{"id": "x"}])},
            {"number.json", "[1]"},
            {"environment.json",
             ~s([{"environment": "moon", "id": "x", "keyring": "k", "proof": "p"}])}
          ] do
        File.write!(Path.join(dir, name), bytes)
        assert {1, "", stderr} = AgentLines.main([Path.join(dir, name)]), name
        assert IO.iodata_to_binary(stderr) =~ "Usage"
      end
    end
  end

  # The fixture's proof with its subject's record taken out, which SHAPE refuses and DERIVE
  # cannot read.
  defp shape_broken(dir) do
    {:ok, document} = dir |> Path.join("item.proof.json") |> File.read!() |> JSON.parse()

    document
    |> update_in(["proof", "subject"], &Map.delete(&1, "record"))
    |> JCS.encode()
  end
end
