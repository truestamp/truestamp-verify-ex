# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Conformance do
  @moduledoc """
  Runs the conformance cases of SPEC.md section 13 (`vectors/cases.json`) and gives what
  section 13.1 compares of each.

  Every case applies to this library: the offline cases run offline, and each online case
  answers its reads from its replay file (`Truestamp.Verify.Readers.Replay`), which stands as
  the operator-pinned source for each network whose identity read it holds.

  **A case's configuration** (section 13.2), as an external verifier takes it (section 13.1):

  | `config` | Run |
  |---|---|
  | `environment` | `:environment` |
  | `keyring` `test` or a path | a supplied keyring file |
  | `keyring` `none` | keyless |
  | `keyring` absent | no keyring option: the compiled pin offline, the replay's keyring online |
  | `keyring` `unavailable` | no keyring option, online under `prod`: the replay fails the keyring read |
  | `networks` | every pin, in place of the defaults |
  | `expected_hash` | `:expected_hash` |
  | `online` | `:reader` and `:current_keyring` from the replay file |
  | `sources` | the several sources of the networks it names, each answering from the replay records that name it, under its policy |

  **What is compared** (section 13.1): for a bare rejection, `code`, and `sub_reason` when
  the code has one; otherwise the report's `label` and every row as
  `[code, part, status, step]`, in order; for a case whose expected output names a trace,
  the trace rows, each without `inputs`; and for an online case, each edge's instant and
  basis, or its absence, instants compared as instants. Messages and `values` are never
  compared.
  """

  alias Truestamp.Verify
  alias Truestamp.Verify.{Fault, Instant, JCS, JSON, ReadError, Rejection, Report, Spec}
  alias Truestamp.Verify.KeyringSources
  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Spec.Data

  @typedoc "A case of `vectors/cases.json`, as parsed."
  @type kase :: map()

  @doc """
  Every case of the cases file at `path`, in its order. The file is read under J2 to J6
  alone: it is a data file, larger than MAX_READ_OCTETS, which binds a document.
  """
  @spec cases(Path.t()) :: {:ok, [kase()]} | {:error, String.t()}
  def cases(path) do
    with {:ok, bytes} <- read(path),
         {:ok, value} <- parse(path, bytes) do
      if is_list(value),
        do: {:ok, value},
        else: {:error, "#{path} is not an array of cases (SPEC.md 13.2)."}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, "#{path} cannot be read: #{:file.format_error(reason)}"}
    end
  end

  defp parse(path, bytes) do
    case JSON.parse(bytes) do
      {:ok, value} -> {:ok, value}
      {:error, {:malformed_json, why}} -> {:error, "#{path} is not JSON a verifier reads: #{why}"}
    end
  end

  @doc "Whether `kase` is online: its configuration names a replay file."
  @spec online?(kase()) :: boolean()
  def online?(%{"config" => config}), do: Map.has_key?(config, "online")

  @doc """
  The options of `Truestamp.Verify.verify/2` that run `kase`, with its paths relative to
  `vectors`: `{:ok, options}`, or `{:error, message}` for a case whose form or configuration
  section 13.2 does not allow.
  """
  @spec options(kase(), Path.t()) :: {:ok, keyword()} | {:error, String.t()}
  def options(
        %{"id" => id, "proof" => proof, "config" => config, "expected" => expected} = kase,
        vectors
      )
      when is_binary(id) and is_binary(proof) and is_map(config) and is_map(expected) and
             map_size(kase) == 4 do
    with :ok <- members(id, config),
         {:ok, environment} <- environment(id, config["environment"]),
         {:ok, networks} <- networks(id, config["networks"]),
         {:ok, sources} <- sources(id, config),
         {:ok, online} <- online(id, config["online"], sources, vectors),
         {:ok, trust} <- trust(id, config["keyring"], vectors, online) do
      options =
        [environment: environment, networks: networks, expected_hash: config["expected_hash"]] ++
          trust ++ online_options(online)

      {:ok, options}
    end
  end

  def options(kase, _vectors),
    do: {:error, "Not a case of SPEC.md 13.2: #{kase |> inspect() |> String.slice(0, 200)}"}

  @members ~w(environment expected_hash keyring networks online sources)

  # A source's name in a case's `sources` is an ASCII16 (sections 2.4 and 13.2).
  @external_resource Data.path("encodings.json")
  @ascii16 "encodings.json" |> Data.read!() |> Map.fetch!("ASCII16") |> Map.fetch!("pattern")

  defp members(id, config) do
    case Map.keys(config) -- @members do
      [] -> :ok
      others -> {:error, "Case #{id}: config holds #{inspect(others)}, which 13.2 does not."}
    end
  end

  defp environment(id, environment) do
    case is_binary(environment) && Spec.environment(environment) do
      atom when is_atom(atom) and atom not in [nil, false] -> {:ok, atom}
      _no_environment -> {:error, "Case #{id}: an invalid environment."}
    end
  end

  defp networks(_id, %{"commitment" => commitment, "entropy" => entropy} = networks)
       when map_size(networks) == 2,
       do: {:ok, %{commitment: commitment, entropy: entropy}}

  defp networks(id, _value), do: {:error, "Case #{id}: an invalid networks."}

  # A case's `sources`, only beside `online` (section 13.2): the several sources of each
  # network that has them, as `Truestamp.Verify.Readers.Replay` takes them. A policy's n is
  # left to the run, whose step 0 refuses one that is 0 or above the number of sources.
  defp sources(_id, config) when not is_map_key(config, "sources"), do: {:ok, %{}}

  defp sources(id, %{"sources" => chains} = config) when is_map(chains) do
    named =
      for {chain, networks} <- chains, is_map(networks), into: %{} do
        {chain, for({network, entry} <- networks, into: %{}, do: {network, policy(entry)})}
      end

    if Map.has_key?(config, "online") and map_size(named) == map_size(chains) and
         Enum.all?(named, fn {_chain, networks} ->
           Enum.all?(networks, &match?({_network, {_policy, _names}}, &1))
         end),
       do: {:ok, named},
       else: invalid_sources(id)
  end

  defp sources(id, _config), do: invalid_sources(id)

  defp invalid_sources(id), do: {:error, "Case #{id}: an invalid sources."}

  defp policy(%{"policy" => "first", "sources" => names} = entry) when map_size(entry) == 2,
    do: named(:first, names)

  defp policy(%{"policy" => "all", "sources" => names} = entry) when map_size(entry) == 2,
    do: named(:all, names)

  defp policy(%{"policy" => "at_least", "required" => n, "sources" => names} = entry)
       when map_size(entry) == 3 and is_integer(n) and n >= 0,
       do: named({:at_least, n}, names)

  defp policy(_entry), do: :invalid

  defp named(policy, [_ | _] = names) do
    ascii16 = Regex.compile!("\\A(?:" <> @ascii16 <> ")\\z")

    if Enum.all?(names, &(is_binary(&1) and Regex.match?(ascii16, &1))) and
         Enum.uniq(names) == names,
       do: {policy, names},
       else: :invalid
  end

  defp named(_policy, _names), do: :invalid

  defp online(_id, nil, _sources, _vectors), do: {:ok, nil}

  defp online(id, path, sources, vectors) when is_binary(path) do
    case Replay.new(Path.join(vectors, path), sources: sources) do
      {:ok, reader} ->
        {:ok, reader}

      {:error, reason} ->
        {:error, "Case #{id}: its replay file cannot be read: #{inspect(reason)}"}
    end
  end

  defp trust(_id, nil, _vectors, _online), do: {:ok, []}
  defp trust(_id, "none", _vectors, _online), do: {:ok, [trust: :keyless]}

  defp trust(_id, "test", vectors, _online),
    do: {:ok, [trust: {:keyring_file, Path.join(vectors, "keyring.test.json")}]}

  # An unverified key chain, for Truestamp's own verifier; for an external one, the default
  # keyring read online, which the replay fails (section 13.2).
  defp trust(_id, "unavailable", _vectors, online) when online != nil, do: {:ok, []}

  defp trust(id, "unavailable", _vectors, nil),
    do: {:error, "Case #{id}: unavailable belongs to an online case."}

  defp trust(_id, path, vectors, _online) when is_binary(path),
    do: {:ok, [trust: {:keyring_file, Path.join(vectors, path)}]}

  defp trust(id, _keyring, _vectors, _online), do: {:error, "Case #{id}: an invalid keyring."}

  defp online_options(nil), do: []

  defp online_options({Replay, state} = reader),
    do: [reader: reader, current_keyring: KeyringSources.Replay.new(state)]

  @doc "Runs `kase`, with its paths relative to `vectors`."
  @spec run(kase(), Path.t()) :: Verify.result() | {:error, String.t()}
  def run(%{"proof" => proof} = kase, vectors) do
    with {:ok, options} <- options(kase, vectors),
         do: Verify.verify_file(Path.join(vectors, proof), options)
  end

  @doc """
  What section 13.1 compares of a result: a bare rejection's `code` and `sub_reason`, or a
  report's `label` and reduced `rows`, its `trace` rows without `inputs` when `trace?`, and
  its edges when `online?`; an `error` for a result that is neither.
  """
  @spec output(Verify.result() | {:error, String.t()}, keyword()) :: map()
  def output(result, options \\ [])

  def output({:error, %Rejection{code: code, sub_reason: sub_reason}}, _options) do
    output = %{"code" => Atom.to_string(code)}
    if sub_reason, do: Map.put(output, "sub_reason", Atom.to_string(sub_reason)), else: output
  end

  def output({:ok, %Report{} = report}, options) do
    reduced = Report.reduce(report, Keyword.get(options, :trace?, false))

    if Keyword.get(options, :online?, false),
      do: reduced,
      else: Map.drop(reduced, ["submitted_after", "submitted_before"])
  end

  def output({:error, %ReadError{message: message}}, _options), do: %{"error" => message}
  def output({:error, %Fault{message: message}}, _options), do: %{"error" => message}
  def output({:error, message}, _options) when is_binary(message), do: %{"error" => message}

  @doc """
  Compares `kase`'s expected output with what `output/2` gave for it, with the trace file
  it names read relative to `vectors`: `:ok`, or `{:error, difference}` naming the first
  difference.
  """
  @spec compare(kase(), map(), Path.t()) :: :ok | {:error, String.t()}
  def compare(%{"expected" => expected}, output, vectors) do
    expected = expected(expected, vectors)

    cond do
      Map.has_key?(output, "error") ->
        {:error, output["error"]}

      Map.drop(output, ["submitted_after", "submitted_before"]) !=
          Map.drop(expected, ["submitted_after", "submitted_before"]) ->
        {:error,
         first_difference(Map.drop(expected, ~w(submitted_after submitted_before)), output)}

      not same_edge?(expected["submitted_after"], output["submitted_after"]) ->
        {:error,
         "submitted_after: expected #{inspect(expected["submitted_after"])}, got #{inspect(output["submitted_after"])}"}

      not same_edge?(expected["submitted_before"], output["submitted_before"]) ->
        {:error,
         "submitted_before: expected #{inspect(expected["submitted_before"])}, got #{inspect(output["submitted_before"])}"}

      true ->
        :ok
    end
  end

  # The expected output as section 13.1 compares it: the trace a case names by path is read,
  # and each of its rows compared without `inputs`.
  defp expected(%{"trace" => path} = expected, vectors) when is_binary(path) do
    {:ok, trace} = vectors |> Path.join(path) |> File.read!() |> JSON.parse()
    Map.put(expected, "trace", Enum.map(trace, &Map.delete(&1, "inputs")))
  end

  defp expected(expected, _vectors), do: expected

  defp same_edge?(nil, nil), do: true

  defp same_edge?(%{"basis" => basis, "instant" => a}, %{"basis" => basis, "instant" => b}),
    do: instant(a) == instant(b)

  defp same_edge?(_expected, _output), do: false

  defp instant(text) do
    case Instant.parse(:time, text) do
      {:ok, seconds} -> seconds * 1000
      {:error, _flaw} -> with({:ok, ms} <- Instant.parse(:nisttime, text), do: ms)
    end
  end

  defp first_difference(expected, output) do
    case {expected["rows"], output["rows"]} do
      {rows, rows} ->
        "expected #{inspect(Map.delete(expected, "rows"))}, got #{inspect(Map.delete(output, "rows"))}"

      {expected_rows, output_rows} when is_list(expected_rows) and is_list(output_rows) ->
        index =
          Enum.find_index(Enum.zip(expected_rows ++ [nil], output_rows ++ [nil]), fn {a, b} ->
            a != b
          end)

        "row #{index}: expected #{inspect(Enum.at(expected_rows, index))}, got #{inspect(Enum.at(output_rows, index))}"

      _other ->
        "expected #{inspect(expected)}, got #{inspect(output)}"
    end
  end

  @usage "Usage: mix truestamp.conformance CASES_JSON [--offline-only]"

  @doc "The usage line of `mix truestamp.conformance`."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc """
  The entry point of `mix truestamp.conformance CASES_JSON [--offline-only]`:
  `{exit_code, stdout, stderr}`, writing to neither stream.

  Standard output carries `document/2` of every case of the file, or of its offline cases
  alone under `--offline-only`, as an offline verifier runs them (section 13.1). The entry
  point compares nothing. The exit code is 0 when the document is written, whatever the
  cases give; 1, with nothing on standard output, for an invalid command line or a cases
  file that cannot be read, is not JSON, or holds a case whose form section 13.2 does not
  allow; and 2, with nothing on standard output, for a fault inside the entry point.
  """
  @spec main([String.t()]) :: {non_neg_integer(), iodata(), iodata()}
  def main(argv) when is_list(argv) do
    with {:ok, path, offline_only?} <- arguments(argv),
         {:ok, cases} <- cases(path),
         :ok <- forms(cases, Path.dirname(path)) do
      chosen = if offline_only?, do: Enum.reject(cases, &online?/1), else: cases
      left_out = length(cases) - length(chosen)
      summary = "Ran #{length(chosen)} cases of #{path}; left out #{left_out} online cases.\n"
      {0, document(chosen, Path.dirname(path)), summary}
    else
      {:error, message} -> {1, "", [message, "\n", @usage, "\n"]}
    end
  catch
    kind, reason ->
      banner = Exception.format_banner(kind, reason, __STACKTRACE__)
      {2, "", ["A fault inside the conformance entry point: ", banner, "\n"]}
  end

  defp arguments([path]), do: utf8_path(path, false)
  defp arguments([path, "--offline-only"]), do: utf8_path(path, true)
  defp arguments(["--offline-only", path]), do: utf8_path(path, true)
  defp arguments(_argv), do: {:error, "Give exactly one cases file."}

  defp utf8_path(path, offline_only?) do
    if String.valid?(path),
      do: {:ok, path, offline_only?},
      else: {:error, "The path is not valid UTF-8."}
  end

  # Every case's form and configuration, before any runs: the first that section 13.2 does
  # not allow refuses the whole file.
  defp forms(cases, vectors) do
    Enum.find_value(cases, :ok, fn kase ->
      case options(kase, vectors) do
        {:ok, _options} -> nil
        {:error, message} -> {:error, message}
      end
    end)
  end

  @doc """
  The output of `mix truestamp.conformance CASES_JSON`: one JSON document, written with JCS
  and a final line feed, an array with one entry per case in the file's order, each
  `{id, output}`, where `output` is what `output/2` gives. Every path a case holds is read
  relative to the directory that holds the cases file.
  """
  @spec document([kase()], Path.t()) :: binary()
  def document(cases, vectors) do
    entries =
      for %{"id" => id, "expected" => expected} = kase <- cases do
        options = [trace?: Map.has_key?(expected, "trace"), online?: online?(kase)]
        %{"id" => id, "output" => kase |> run(vectors) |> output(options)}
      end

    JCS.encode(entries) <> "\n"
  end
end
