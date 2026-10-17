# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CLI do
  @moduledoc """
  The command of SPEC.md section 12.2, which `mix truestamp.verify` runs:

      mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME]
                                [--expected-hash HEX] [--trace FILE] [--online]

  | Option | Sets |
  |---|---|
  | `--keyring FILE` | a supplied keyring, read from FILE (section 8.3) |
  | `--no-keyring` | keyless mode, for this run only (section 8.3) |
  | `--environment NAME` | E_v, `prod` by default (section 6.4) |
  | `--expected-hash HEX` | the caller's hash for EXPECTED_HASH (section 10.2, step 13) |
  | `--trace FILE` | writes the trace of section 10.6 to FILE |
  | `--online` | reads the chains and sources with the bundled HTTP sources, and under `prod` with no keyring option, the keyring Truestamp publishes (`Truestamp.Verify.Online.defaults/1`); needs Req |

  Each option is given at most once, and `--keyring` with `--no-keyring` is refused. A value
  option takes the next argument, or its value after `=`. An argument that is not valid UTF-8
  is refused, as is a `--trace` FILE whose directory does not exist. Nothing else sets the
  run: no configuration file and no environment variable is read, so keyless mode and E_v
  are only ever asked for on the command line (sections 6.4 and 8.3).

  **Output.** Standard output carries the machine output: one JSON document, written with
  JCS and a final line feed, the report of section 10.5 with exactly that section's members,
  or a bare rejection's `{code, message, sub_reason}`. Under `--trace FILE`, whenever
  standard output carries a document, FILE holds the run's trace in the canonical form of
  section 9: an empty list when the run ended before DERIVE, a bare rejection's included.
  Standard error carries the human output: the label and what it says, the attribution, the
  trust root, E_v, keyless mode in words, the type and subject id, the item code beside the
  whole recomputed `item_hash` of an item proof (section 3.9), the edges (never for a
  `failed` run), and every row that does not pass.

  **Exit codes** (`Truestamp.Verify.ExitCode`, section 12.2): the label's code for a report;
  4 for a bare rejection other than `configuration_error`, and 8 for that; 1, with no
  report, for an invalid command line, an input that cannot be read, or a `--trace` FILE that
  cannot be written; and 2, with no report, for a fault that leaves no report.

  `main/1` gives `{exit_code, stdout, stderr}` and writes to neither stream, so a test can
  run it; the only file it writes is the `--trace` FILE.
  """

  alias Truestamp.Verify

  alias Truestamp.Verify.{
    Edge,
    ExitCode,
    Fault,
    ItemCode,
    JCS,
    ReadError,
    Rejection,
    Report,
    Row,
    Step
  }

  alias Truestamp.Verify.CLI.Messages
  alias Truestamp.Verify.Steps.Verdict

  @usage "Usage: mix truestamp.verify FILE [--keyring FILE | --no-keyring] " <>
           "[--environment NAME] [--expected-hash HEX] [--trace FILE] [--online]"

  @value_options %{
    "--keyring" => :keyring,
    "--environment" => :environment,
    "--expected-hash" => :expected_hash,
    "--trace" => :trace
  }
  @flag_options %{"--no-keyring" => :no_keyring, "--online" => :online}
  @environments %{"prod" => :prod, "dev" => :dev, "staging" => :staging, "test" => :test}

  @typedoc "What a run of the command gives: its exit code and what it writes to each stream."
  @type outcome :: {non_neg_integer(), iodata(), iodata()}

  @doc "The usage line."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc "Runs the command over `argv`: `{exit_code, stdout, stderr}`."
  @spec main([String.t()]) :: outcome()
  def main(argv) when is_list(argv) do
    case parse(argv) do
      {:ok, options, path, trace} -> execute(options, path, trace)
      {:error, message} -> {ExitCode.code(:runtime_error), "", [message, "\n", @usage, "\n"]}
    end
  end

  @doc """
  Reads a command line: `{:ok, options, path, trace}`, where `options` are those of
  `Truestamp.Verify.verify_file/2` and `trace` the `--trace` FILE or nil, or
  `{:error, message}` for an invalid one (exit code 1).
  """
  @spec parse([String.t()]) :: {:ok, keyword(), Path.t(), Path.t() | nil} | {:error, String.t()}
  def parse(argv) do
    with :ok <- utf8(argv),
         {:ok, given, paths} <- options(argv, [], []),
         {:ok, path} <- one_path(paths),
         {:ok, trust} <- trust(given),
         {:ok, environment} <- environment(given),
         {:ok, online} <- online(given),
         {:ok, trace} <- trace(given) do
      options = trust ++ environment ++ Keyword.take(given, [:expected_hash]) ++ online
      {:ok, options, path, trace}
    end
  end

  @doc """
  Runs the steps of section 10.2 over the file at `path` with `options` and gives the
  command's outcome, writing the trace to the file `trace` when it is not nil. Its messages
  are `Truestamp.Verify.CLI.Messages`, which name the command's options, unless `options`
  set others. A fault that leaves no report, an invalid option included, gives exit code 2.
  """
  @spec execute(keyword(), Path.t(), Path.t() | nil) :: outcome()
  def execute(options, path, trace \\ nil) do
    path
    |> Verify.verify_file(Keyword.put_new(options, :messages, Messages))
    |> outcome(trace)
  catch
    kind, reason -> fault(Exception.format_banner(kind, reason, __STACKTRACE__))
  end

  # ---------------------------------------------------------------------------------------
  # The command line

  # A file name or hash that is not valid UTF-8 cannot be named in a report (section 10.5).
  defp utf8(argv) do
    if Enum.all?(argv, &String.valid?/1),
      do: :ok,
      else: {:error, "An argument is not valid UTF-8."}
  end

  defp options([], options, paths), do: {:ok, Enum.reverse(options), Enum.reverse(paths)}
  defp options(["--" | rest], options, paths), do: options([], options, Enum.reverse(rest, paths))

  defp options(["--" <> _ = argument | rest], options, paths) do
    with {:ok, name, value, rest} <- option(argument, rest),
         :ok <- once(name, options, argument),
         do: options(rest, [{name, value} | options], paths)
  end

  defp options([path | rest], options, paths), do: options(rest, options, [path | paths])

  defp option(argument, rest) do
    case String.split(argument, "=", parts: 2) do
      [flag] when is_map_key(@flag_options, flag) ->
        {:ok, @flag_options[flag], true, rest}

      [flag, _value] when is_map_key(@flag_options, flag) ->
        {:error, "#{flag} takes no value."}

      [name, value] when is_map_key(@value_options, name) ->
        {:ok, @value_options[name], value, rest}

      [name] when is_map_key(@value_options, name) ->
        next_value(name, rest)

      _unknown ->
        {:error, "Unknown option: #{argument}"}
    end
  end

  defp next_value(name, ["--" <> _ | _rest]), do: {:error, "#{name} needs a value."}
  defp next_value(name, []), do: {:error, "#{name} needs a value."}
  defp next_value(name, [value | rest]), do: {:ok, @value_options[name], value, rest}

  defp once(name, options, argument) do
    if Keyword.has_key?(options, name),
      do: {:error, "#{argument} is given more than once."},
      else: :ok
  end

  defp one_path([path]), do: {:ok, path}
  defp one_path([]), do: {:error, "No proof file was given."}
  defp one_path(_paths), do: {:error, "Give exactly one proof file."}

  defp trust(given) do
    case {Keyword.fetch(given, :keyring), Keyword.has_key?(given, :no_keyring)} do
      {{:ok, _path}, true} -> {:error, "--keyring and --no-keyring cannot both be given."}
      {{:ok, path}, false} -> {:ok, [trust: {:keyring_file, path}]}
      {:error, true} -> {:ok, [trust: :keyless]}
      {:error, false} -> {:ok, []}
    end
  end

  defp environment(given) do
    case Keyword.fetch(given, :environment) do
      :error ->
        {:ok, []}

      {:ok, name} when is_map_key(@environments, name) ->
        {:ok, [environment: @environments[name]]}

      {:ok, _name} ->
        {:error, "--environment takes one of: prod, dev, staging, test."}
    end
  end

  defp online(given) do
    if Keyword.has_key?(given, :online), do: online_defaults(), else: {:ok, []}
  end

  @doc false
  # The options `--online` sets: `module`'s defaults, where `module` is
  # `Truestamp.Verify.Online`, which is compiled only with Req. It is named through a
  # variable, so the command compiles without Req and without a warning.
  @spec online_defaults(module()) :: {:ok, keyword()} | {:error, String.t()}
  def online_defaults(module \\ Truestamp.Verify.Online) do
    if Code.ensure_loaded?(module),
      do: {:ok, module.defaults()},
      else: {:error, "--online needs Req: add {:req, \"~> 0.7\"} to the project's dependencies."}
  end

  # The trace file is an output that cannot be written when its directory does not exist,
  # which is refused before the run; any other failure to write it is found after the run.
  defp trace(given) do
    case Keyword.fetch(given, :trace) do
      :error ->
        {:ok, nil}

      {:ok, file} ->
        if File.dir?(Path.dirname(file)),
          do: {:ok, file},
          else: {:error, "--trace names a file in a directory that does not exist: #{file}"}
    end
  end

  # ---------------------------------------------------------------------------------------
  # The outcome

  @doc """
  The command's outcome for what `Truestamp.Verify.verify_file/2` gave: the exit code, the
  JSON document for standard output, and the human output for standard error, writing the
  trace to the file `trace` whenever standard output carries a document; a trace file that
  cannot be written gives exit code 1 and no report.
  """
  @spec outcome(Verify.result(), Path.t() | nil) :: outcome()
  def outcome({:ok, %Report{} = report} = result, trace),
    do:
      write_trace(
        trace,
        Report.trace_json(report),
        {ExitCode.of(result), Report.to_json(report), human(report)}
      )

  def outcome({:error, %Rejection{} = rejection} = result, trace) do
    output = JCS.encode(Rejection.to_map(rejection)) <> "\n"
    write_trace(trace, "[]\n", {ExitCode.of(result), output, rejected(rejection)})
  end

  def outcome({:error, %ReadError{message: message}} = result, _trace),
    do: {ExitCode.of(result), "", [message, ". No report.\n"]}

  def outcome({:error, %Fault{description: description}}, _trace), do: fault(description)

  defp write_trace(nil, _trace, outcome), do: outcome

  defp write_trace(file, trace, outcome) do
    case File.write(file, trace) do
      :ok ->
        outcome

      {:error, reason} ->
        message = "Cannot write the trace to #{file}: #{:file.format_error(reason)}. No report."
        {ExitCode.code(:runtime_error), "", [message, "\n"]}
    end
  end

  defp fault(description) do
    message = "The verifier stopped on a fault before it could give a report: #{description}"
    {ExitCode.code(:fault), "", [message, "\n"]}
  end

  # ---------------------------------------------------------------------------------------
  # Human output

  defp rejected(%Rejection{code: code, sub_reason: sub_reason, message: message}) do
    reason = if sub_reason, do: " (#{sub_reason})", else: ""
    ["Rejected: #{code}#{reason}. #{message}\n", "No report and no verdict.\n"]
  end

  @doc "The human output of a report: the lines the module doc lists, each ending in a line feed."
  @spec human(Report.t()) :: [String.t()]
  def human(%Report{} = report) do
    environment = Atom.to_string(report.environment)

    List.flatten([
      "Label: #{Verdict.label_name(report.label)}#{beside(environment)}. #{says(report.label)}\n",
      if(report.code, do: "Code: #{report.code}\n", else: []),
      "Attribution: #{report.attribution}\n",
      trust_root_line(report.trust_root),
      environment_line(environment),
      if(report.trust_root.kind == :none,
        do: "Keyless: the signature was checked only against the key the document carries.\n",
        else: []
      ),
      if(report.type,
        do: ["Type: #{report.type}\n", "Subject id: #{report.subject_id}\n"],
        else: []
      ),
      item_code_lines(report),
      window_lines(report),
      rows_lines(report.rows)
    ])
  end

  # SPEC.md 6.4: a non-production E_v is shown beside the verdict.
  defp beside("prod"), do: ""
  defp beside(environment), do: ", under the #{environment} environment, not production"

  defp says(:failed), do: "A check failed, and its row says which."

  defp says(:unattributed),
    do:
      "The proof is intact under the key it carries, which was checked against no keyring, so anyone could have made it."

  defp says(:supplied_keyring),
    do:
      "The proof is intact and signed by a key in the keyring the operator supplied; this says nothing about Truestamp."

  defp says(:internally_consistent),
    do:
      "The proof is intact and signed by Truestamp, but no read in this run established its submitted-before edge."

  defp says(:verified),
    do:
      "The proof is intact, signed by Truestamp, and its submission is placed before an instant read from a public chain in this run."

  defp trust_root_line(%{kind: kind, location: location, digest: digest}) do
    where = if location, do: ", from #{location}", else: ""
    sha = if digest, do: ", SHA-256 #{digest}", else: ""
    "Trust root: #{kind}#{where}#{sha}\n"
  end

  defp environment_line("prod"), do: "Environment: prod\n"

  defp environment_line(environment),
    do: "Environment: #{environment}, not production: this run checks #{environment} proofs.\n"

  # SPEC.md 3.9 and 11.5: from the recomputed item_hash only, beside it, never in its place.
  defp item_code_lines(%Report{type: "item", trace: trace}) do
    with %{recomputed: item_hash} <- Enum.find(trace, &(&1.part == "/subject/item_hash")),
         {:ok, code} <- ItemCode.from_item_hash(item_hash) do
      [
        "item_hash, recomputed: #{item_hash}\n",
        "Item code: #{code} (a short name for this item; only the whole item_hash identifies it)\n"
      ]
    else
      _none -> []
    end
  end

  defp item_code_lines(_report), do: []

  defp window_lines(%Report{label: :failed}), do: []

  defp window_lines(%Report{} = report) do
    window = Enum.find(report.rows, &(&1.step == :window))

    [
      edge_line("Submitted after", report.submitted_after, window, "submitted_after"),
      edge_line("Submitted before", report.submitted_before, window, "submitted_before")
    ]
  end

  defp edge_line(caption, %Edge{} = edge, _window, _name) do
    read =
      if edge.cached,
        do: "read from #{edge.source} at #{DateTime.to_iso8601(edge.fetched_at)}",
        else: "read from #{edge.source} in this run"

    "#{caption}: #{Edge.instant_string(edge)} (#{edge.basis}, #{read})\n"
  end

  # SPEC.md 11.2 and 11.3: WINDOW's reasons for an absent edge are empty exactly when the
  # proof carries nothing that could give one, as a block proof's submitted-after edge.
  defp edge_line(caption, nil, %Row{values: %{"absent" => absent}}, name)
       when is_map_key(absent, name) do
    case Map.fetch!(absent, name) do
      [] ->
        "#{caption}: none. This proof has no #{String.replace(name, "_", "-")} edge: it " <>
          "carries nothing that could give one (SPEC.md section 11).\n"

      reasons ->
        "#{caption}: not established in this run (#{Enum.map_join(reasons, ", ", & &1["code"])}).\n"
    end
  end

  defp edge_line(caption, nil, _window, _name), do: "#{caption}: not established in this run.\n"

  defp rows_lines(rows) do
    counts = Enum.frequencies_by(rows, & &1.status)

    summary =
      Enum.map_join([:pass, :fail, :skip, :warn, :info], ", ", &"#{Map.get(counts, &1, 0)} #{&1}")

    [
      "Rows: #{length(rows)} (#{summary})\n"
      | for(row <- rows, row.status != :pass, do: line(row))
    ]
  end

  defp line(%Row{} = row) do
    at = if row.part, do: " at #{row.part}", else: ""
    "  #{row.status} #{Step.name(row.step)} #{row.code}#{at}: #{row.message}\n"
  end
end
