# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.VectorsLayoutTest do
  # SPEC.md 13.2's tables of the paths under vectors/ against the files there, as
  # spec_files_test.exs holds section 9's table to spec/: the first table names each entry at
  # the top of vectors/, and the corpus table each entry under vectors/corpus/, and every file
  # is named as the row that holds it says.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.Test.StrictJSON

  @root Truestamp.Verify.Test.Verification.root()
  @spec_md Path.join(@root, "SPEC.md")
  @vectors Path.join(@root, "vectors")
  @files @vectors
         |> Path.join("**/*")
         |> Path.wildcard(match_dot: true)
         |> Enum.filter(&File.regular?/1)
         |> Enum.map(&Path.relative_to(&1, @vectors))
         |> Enum.sort()
  @external_resource @spec_md
  for file <- @files, do: @external_resource(Path.join(@vectors, file))

  # The first cell of each row of the Markdown table whose header row is `header`, unquoted.
  defp first_column(header) do
    [_before, rest] = @spec_md |> File.read!() |> String.split(header <> "\n", parts: 2)

    rest
    |> String.split("\n")
    |> Enum.drop(1)
    |> Enum.take_while(&String.starts_with?(&1, "|"))
    |> Enum.map(fn row ->
      [first | _rest] = row |> String.trim("|") |> String.split(" | ")
      first |> String.trim() |> String.trim("`")
    end)
  end

  # The entry at the top of `path`: its first segment, with a slash when it is a directory.
  defp top(path) do
    case String.split(path, "/", parts: 2) do
      [file] -> file
      [directory, _rest] -> directory <> "/"
    end
  end

  defp under(prefix),
    do:
      for(
        path <- @files,
        String.starts_with?(path, prefix),
        do: String.replace_prefix(path, prefix, "")
      )

  defp read(path) do
    {:ok, value} = @vectors |> Path.join(path) |> File.read!() |> StrictJSON.decode()
    value
  end

  # cases.json is larger than MAX_READ_OCTETS, a bound on a proof file, not on it.
  defp cases, do: @vectors |> Path.join("cases.json") |> StrictJSON.read_data!()

  test "the table of section 13.2 names each entry at the top of vectors/, and nothing else" do
    listed = first_column("| Path | Holds |")

    assert Enum.sort(listed) == @files |> Enum.map(&top/1) |> Enum.uniq() |> Enum.sort()
  end

  test "the corpus table names each entry under corpus/, and nothing else" do
    listed = first_column("| Path under `corpus/` | Holds |")
    present = "corpus/" |> under() |> Enum.map(&top/1) |> Enum.uniq()

    assert Enum.sort(listed) == Enum.sort(present)
  end

  test "positive/ holds a proof and its trace for each name, the proof's type or its type and a variant" do
    names =
      for file <- under("positive/") do
        [name, kind] = String.split(file, ".", parts: 2)
        assert kind in ["proof.json", "trace.json"], file
        name
      end

    for name <- Enum.uniq(names) do
      assert Enum.count(names, &(&1 == name)) == 2, name
      type = read("positive/#{name}.proof.json")["proof"]["type"]
      assert name == type or String.starts_with?(name, type <> "-"), name
    end
  end

  test "negative/ holds only a case's proof or keyring, by the case's id" do
    ids = for c <- cases(), into: MapSet.new(), do: c["id"]

    for file <- under("negative/") do
      [id, kind] = String.split(file, ".", parts: 2)
      assert kind in ["proof.json", "keyring.json"], file
      assert id in ids, file
    end
  end

  test "corpus/jcs/ holds pairs, each an input and its output" do
    names =
      for file <- under("corpus/jcs/") do
        [name, kind] = String.split(file, ".", parts: 2)
        assert kind in ["input.json", "output.json"], file
        name
      end

    assert names != []
    for name <- Enum.uniq(names), do: assert(Enum.count(names, &(&1 == name)) == 2, name)
  end

  test "corpus/bitcoin/ names each file by the network and height it holds" do
    networks = @root |> Path.join("spec/networks.json") |> StrictJSON.read_data!()
    files = under("corpus/bitcoin/")

    assert files != []

    for file <- files do
      %{"network" => network, "height" => height} = read("corpus/bitcoin/" <> file)
      assert network in networks["bitcoin"], file
      assert String.starts_with?(file, "#{network}-#{height}-"), file
      assert String.ends_with?(file, ".json"), file
    end
  end

  test "corpus/replay/ holds the replay file of each online case, by the id of a case that names it, and no other" do
    online =
      for %{"config" => %{"online" => path}, "id" => id} <- cases(), do: {id, path}

    files = for file <- under("corpus/replay/"), do: "corpus/replay/" <> file

    assert files != []
    assert online |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort() == files
    for path <- files, do: assert({Path.basename(path, ".json"), path} in online, path)
  end
end
