# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.ManifestTest do
  # MANIFEST.sha256 at the root covers the conformance data alone (SPEC.md 9 and 13.1): one
  # line per file under spec/ and vectors/, and no other, in the grammar the app's sync
  # reads, sorted by path, each with the SHA-256 of the file's bytes. agent-test/ has a
  # manifest of its own, so a line for any file there, or anywhere but spec/ and vectors/, is
  # a regression this test refuses before the app's sync would.
  use ExUnit.Case, async: true

  @root Truestamp.Verify.Test.Verification.root()

  # This mirrors the app's @manifest_line, in test/truestamp/verification_fixtures_test.exs
  # of the app's repository, the grammar its verification-sync holds each line to: keep the
  # two the same.
  @manifest_line ~r/\A([0-9a-f]{64})  ((?:spec|vectors)(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)+)\z/

  defp manifest, do: File.read!(Path.join(@root, "MANIFEST.sha256"))

  # Every regular file under `dir`, dot files included, by its path from the root.
  defp files(dir) do
    path = Path.join(@root, dir)

    case File.lstat!(path).type do
      :directory -> path |> File.ls!() |> Enum.flat_map(&files(Path.join(dir, &1)))
      :regular -> [dir]
    end
  end

  defp lines, do: manifest() |> String.split("\n") |> Enum.drop(-1)

  test "MANIFEST.sha256 ends in a newline and every line is in the app's grammar" do
    assert String.ends_with?(manifest(), "\n")

    malformed =
      for {line, number} <- Enum.with_index(lines(), 1),
          not Regex.match?(@manifest_line, line),
          do: {number, line}

    assert malformed == []
  end

  test "MANIFEST.sha256 lists exactly the files under spec/ and vectors/, sorted, with their digests" do
    listed =
      for line <- lines(),
          [digest, path] <- [Regex.run(@manifest_line, line, capture: :all_but_first)],
          do: {path, digest}

    paths = Enum.map(listed, &elem(&1, 0))
    assert paths == Enum.sort(paths)
    assert length(listed) == length(lines())
    assert Enum.sort(paths) == Enum.sort(files("spec") ++ files("vectors"))

    wrong =
      for {path, digest} <- listed,
          Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(@root, path))), case: :lower) !=
            digest,
          do: path

    assert wrong == []
  end
end
