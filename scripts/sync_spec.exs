# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Mirrors spec/ of truestamp-verification into priv/spec/, byte for byte, and writes
# priv/spec.source, which records where the mirror came from:
#
#     elixir scripts/sync_spec.exs            # write priv/spec/ and priv/spec.source
#     elixir scripts/sync_spec.exs --check    # fail unless they are already current
#
# The source is the checkout TRUESTAMP_VERIFICATION names, or else the test-only dependency
# under deps/truestamp_verification (`mix deps.get`). Every file is checked against that
# checkout's MANIFEST.sha256 before it is copied, so a mirror never holds a file the
# manifest does not vouch for. The library compiles these files in (Truestamp.Verify.Spec),
# and test/spec_mirror_test.exs fails when the mirror differs from the checkout the tests
# run against.

defmodule SyncSpec do
  @root Path.expand("..", __DIR__)
  @mirror Path.join(@root, "priv/spec")
  @source_file Path.join(@root, "priv/spec.source")
  @repository "https://github.com/truestamp/truestamp-verification"

  def main(args) do
    check? = args == ["--check"]
    unless args in [[], ["--check"]], do: halt("Usage: elixir scripts/sync_spec.exs [--check]")

    source = source()
    manifest = manifest(source)
    files = spec_files(source)

    for {path, bytes} <- files do
      expected = Map.get(manifest, path) || halt("#{path} is not in MANIFEST.sha256.")
      actual = sha256(bytes)
      unless actual == expected, do: halt("#{path} does not match MANIFEST.sha256.")
    end

    record = record(source, files)

    if check?, do: check(files, record), else: write(files, record)
  end

  defp source do
    path =
      System.get_env("TRUESTAMP_VERIFICATION") ||
        Path.join(@root, "deps/truestamp_verification")

    unless File.regular?(Path.join(path, "MANIFEST.sha256")),
      do: halt("No truestamp-verification checkout at #{path}: run mix deps.get.")

    path
  end

  # MANIFEST.sha256, as sha256sum writes it: "<hex>  <path>" per line.
  defp manifest(source) do
    source
    |> Path.join("MANIFEST.sha256")
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Map.new(fn line ->
      [digest, path] = String.split(line, "  ", parts: 2)
      {path, digest}
    end)
  end

  defp spec_files(source) do
    spec = Path.join(source, "spec")

    spec
    |> Path.join("**")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Enum.sort()
    |> Enum.map(&{"spec/" <> Path.relative_to(&1, spec), File.read!(&1)})
  end

  defp record(source, files) do
    {commit, 0} = System.cmd("git", ["-C", source, "rev-parse", "HEAD"])
    manifest_digest = source |> Path.join("MANIFEST.sha256") |> File.read!() |> sha256()

    file_lines =
      Enum.map_join(files, ",\n", fn {path, bytes} ->
        ~s(    "#{path}": "#{sha256(bytes)}")
      end)

    """
    {
      "commit": "#{String.trim(commit)}",
      "files": {
    #{file_lines}
      },
      "manifest_sha256": "#{manifest_digest}",
      "repository": "#{@repository}"
    }
    """
  end

  defp write(files, record) do
    File.rm_rf!(@mirror)

    for {path, bytes} <- files do
      target = Path.join(@mirror, String.replace_prefix(path, "spec/", ""))
      File.mkdir_p!(Path.dirname(target))
      File.write!(target, bytes)
    end

    File.write!(@source_file, record)
    IO.puts("Mirrored #{length(files)} files of spec/ into priv/spec/.")
  end

  defp check(files, record) do
    mirrored =
      @mirror
      |> Path.join("**")
      |> Path.wildcard(match_dot: true)
      |> Enum.filter(&File.regular?/1)
      |> Enum.sort()
      |> Enum.map(&{"spec/" <> Path.relative_to(&1, @mirror), File.read!(&1)})

    cond do
      mirrored != files -> halt("priv/spec/ differs from spec/: run elixir scripts/sync_spec.exs")
      File.read(@source_file) != {:ok, record} -> halt("priv/spec.source is not current.")
      true -> IO.puts("priv/spec/ is current.")
    end
  end

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp halt(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end
end

SyncSpec.main(System.argv())
