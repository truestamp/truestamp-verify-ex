# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CLITest do
  @moduledoc """
  The command of SPEC.md section 12.2, `mix truestamp.verify`: its command line, each exit
  path (the five labels, both kinds of bare rejection, an invalid command line, an argument
  that is not UTF-8, an input that cannot be read, a trace file that cannot be written,
  CONFIGURATION before the proof is read, a fault before steps 0 to 3 passed or from
  ENVIRONMENT on, and a fault no step caught), its machine output (the report of section
  10.5 written with JCS, with exactly its members; the trace of section 10.6 in its own file
  under `--trace FILE`; a bare rejection's `{code, message, sub_reason}`), its human output
  (the item code of section 3.9 from the recomputed `item_hash`, beside it and nowhere else,
  section 11.5; keyless mode said in words, section 8.3; a non-production E_v said, section
  6.4; no window for a failed run, section 11.5; no submitted-after edge for a proof that
  carries nothing to give one, section 11.2), and that it reads no environment variable
  (sections 6.4 and 8.3).
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify

  alias Truestamp.Verify.{
    CLI,
    Config,
    Edge,
    ExitCode,
    Hash,
    ItemCode,
    JCS,
    JSON,
    Online,
    Report
  }

  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Test.{Signing, StrictJSON, Verification}

  @report_members ~w(attribution environment label rows subject_id submitted_after
                     submitted_before trust_root type verified window)

  @vectors Verification.vectors()
  @item Path.join(@vectors, "positive/item.proof.json")
  @block Path.join(@vectors, "positive/block.proof.json")
  @test_keyring Path.join(@vectors, "keyring.test.json")
  @replay Path.join(@vectors, "corpus/replay/window-established.json")
  @test_pins %{
    commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
    entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  @source_files ~w(lib/truestamp/verify/cli.ex lib/truestamp/verify/config.ex
                   lib/truestamp/verify/online.ex lib/mix/tasks/truestamp.verify.ex)

  # A command line run: {exit code, stdout as a binary, stderr as a binary}.
  defp main(argv) do
    {code, stdout, stderr} = CLI.main(argv)
    {code, IO.iodata_to_binary(stdout), IO.iodata_to_binary(stderr)}
  end

  defp document(stdout) do
    stdout = IO.iodata_to_binary(stdout)
    assert String.ends_with?(stdout, "\n")
    assert {:ok, value} = JSON.parse(String.trim_trailing(stdout, "\n"))
    value
  end

  defp missing, do: Path.join(System.tmp_dir!(), "truestamp-no-such-file.json")

  defmodule ConfigurationFault do
    @moduledoc false
    @behaviour Truestamp.Verify.Messages

    @impl true
    def message(:configuration_pass, _assigns), do: raise("boom")
    def message(_id, _assigns), do: nil
  end

  defmodule EnvironmentFault do
    @moduledoc false
    @behaviour Truestamp.Verify.Messages

    @impl true
    def message(:environment_pass, _assigns), do: raise(ArgumentError, "a value of the proof")
    def message(_id, _assigns), do: nil
  end

  # ---------------------------------------------------------------------------------------
  # The command line

  describe "the command line" do
    test "sets each option, in either spelling, and nothing else" do
      assert {:ok, options, "proof.json", "t.json"} =
               CLI.parse(
                 ~w(--environment=test proof.json --keyring k.json --expected-hash AB) ++
                   ~w(--trace t.json)
               )

      assert options == [
               trust: {:keyring_file, "k.json"},
               environment: :test,
               expected_hash: "AB"
             ]

      assert CLI.parse(~w(p --no-keyring)) == {:ok, [trust: :keyless], "p", nil}
      assert {:ok, _options, "p", "t.json"} = CLI.parse(~w(p --trace=t.json))
      assert CLI.parse(["p"]) == {:ok, [], "p", nil}
      assert Config.external!([]).environment == "prod"
    end

    test "--online reads with the bundled HTTP sources, and the keyring Truestamp publishes" do
      assert {:ok, options, "p", nil} = CLI.parse(~w(p --online))
      assert options == Online.defaults()

      assert %Config{reader: {_module, _state}, current_keyring: {_source, _options}} =
               Config.external!(options)

      assert {:ok, options, "p", nil} = CLI.parse(~w(p --online --environment test --no-keyring))
      assert %Config{trust: :keyless, environment: "test"} = Config.external!(options)
    end

    test "--online is refused where Truestamp.Verify.Online is not compiled, as without Req" do
      assert {:error, "--online needs Req" <> _} =
               CLI.online_defaults(Truestamp.Verify.NoSuchModule)
    end

    test "takes every argument after -- as a file" do
      assert CLI.parse(["--", "--trace"]) == {:ok, [], "--trace", nil}
    end

    test "refuses --keyring with --no-keyring, in either order" do
      for argv <- [~w(p --keyring k --no-keyring), ~w(p --no-keyring --keyring k)] do
        assert {:error, message} = CLI.parse(argv)
        assert message =~ "--keyring and --no-keyring"
      end
    end

    test "refuses a repeated, unknown, valueless or misvalued option, and no file or two" do
      for argv <- [
            ~w(p --trace --trace),
            ~w(p --environment test --environment test),
            ~w(p --no-keyring --no-keyring),
            ~w(p --online --online),
            ~w(p --keyring a --keyring=b),
            ~w(p --json),
            ~w(p --no-trace),
            ~w(p --no-keyring=true),
            ~w(p --trace),
            ~w(p --keyring),
            ~w(p --keyring --trace),
            ~w(p --environment production),
            ~w(p --environment PROD),
            ~w(--no-keyring),
            ~w(p q)
          ] do
        assert {:error, _message} = CLI.parse(argv), inspect(argv)
        assert {1, "", stderr} = main(argv)
        assert stderr =~ CLI.usage()
      end
    end

    test "refuses a FILE, --keyring or --expected-hash value that is not valid UTF-8" do
      for argv <- [
            [<<0xFF>>, "--no-keyring"],
            [@item, "--environment", "test", "--keyring", <<"k", 0xFF, ".json">>],
            [@item, "--environment", "test", "--no-keyring", "--expected-hash", <<0xFF, 0xFE>>],
            [@item, "--environment", "test", "--no-keyring", "--expected-hash=" <> <<0xFF>>]
          ] do
        assert {1, "", stderr} = main(argv)
        assert stderr =~ "not valid UTF-8" and stderr =~ CLI.usage()
      end
    end

    test "refuses, before the run, a --trace FILE whose directory does not exist" do
      file = Path.join([System.tmp_dir!(), "truestamp-no-such-directory", "t.json"])
      assert {:error, message} = CLI.parse([@item, "--no-keyring", "--trace", file])
      assert message =~ "does not exist"
      assert {1, "", stderr} = main([@item, "--no-keyring", "--trace", file])
      assert stderr =~ CLI.usage()
      refute File.exists?(file)
    end

    test "reads no environment variable and no application configuration (6.4, 8.3)" do
      for file <- @source_files do
        {:ok, ast} = file |> File.read!() |> Code.string_to_quoted()

        {_ast, found} =
          Macro.prewalk(ast, [], fn
            {{:., _, [{:__aliases__, _, [:System]}, fun]}, _, _} = node, found
            when fun in [:get_env, :fetch_env, :fetch_env!] ->
              {node, [fun | found]}

            {{:., _, [{:__aliases__, _, [:Application]}, fun]}, _, _} = node, found
            when fun in [:get_env, :fetch_env, :fetch_env!, :get_all_env, :compile_env] ->
              {node, [fun | found]}

            {{:., _, [:os, :getenv]}, _, _} = node, found ->
              {node, [:getenv | found]}

            node, found ->
              {node, found}
          end)

        assert found == [], file
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # Exit paths (12.2)

  describe "exit codes" do
    test "the label failed exits 3, with the report and its code" do
      {code, stdout, _stderr} = main([@item])
      assert code == 3
      assert %{"label" => "failed", "code" => "environment_mismatch"} = report = document(stdout)

      # The compiled pin's trust root (10.5): the SHA-256 of the pin's bytes, and no location.
      pin = File.read!(Verification.path("spec/keyring.production.json"))
      digest = :sha256 |> :crypto.hash(pin) |> Base.encode16(case: :lower)

      assert report["trust_root"] ==
               %{"digest" => digest, "kind" => "compiled_pin", "location" => nil}
    end

    test "the label unattributed exits 5" do
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert code == 5
      assert %{"label" => "unattributed", "attribution" => "unattributed"} = document(stdout)
    end

    test "the label supplied-keyring exits 6" do
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])
      assert code == 6
      assert %{"label" => "supplied-keyring", "attribution" => "keyring:" <> _} = document(stdout)
    end

    test "the label internally-consistent exits 7, and verified exits 0" do
      bytes = Signing.production_without_key_event("item")
      config = [environment: :prod, networks: @test_pins, key_chain: [Signing.public_key()]]

      {:ok, offline} = Verify.verify(bytes, Config.internal!(config))
      assert {7, stdout, stderr} = CLI.outcome({:ok, offline}, nil)

      assert %{"label" => "internally-consistent", "window" => "not_established"} =
               report = document(stdout)

      assert report["attribution"] == "truestamp"
      assert IO.iodata_to_binary(stderr) =~ "Label: internally-consistent. The proof is intact"

      {:ok, online} =
        Verify.verify(bytes, Config.internal!([reader: Replay.new!(@replay)] ++ config))

      assert {0, stdout, stderr} = CLI.outcome({:ok, online}, nil)

      assert %{"label" => "verified", "verified" => true, "window" => "established"} =
               document(stdout)

      stderr = IO.iodata_to_binary(stderr)
      assert stderr =~ "Label: verified. The proof is intact, signed by Truestamp"

      assert stderr =~
               ~r/Submitted before: \S+ \(stellar_ledger_close_read, read from .* in this run\)/
    end

    test "a bare rejection exits 4, with only {code, message, sub_reason}" do
      dir = tmp()
      path = Path.join(dir, "array.json")
      File.write!(path, "[]")
      trace = Path.join(dir, "trace.json")
      {code, stdout, stderr} = main([path, "--trace", trace])
      assert code == 4
      assert File.read!(trace) == "[]\n"

      assert %{"code" => "invalid_envelope", "sub_reason" => "document", "message" => _} =
               output = document(stdout)

      assert map_size(output) == 3
      assert stderr =~ "Rejected: invalid_envelope (document)."
      assert stderr =~ "No report and no verdict"

      oversized = Path.join(dir, "big.json")
      File.write!(oversized, String.duplicate(" ", 262_145))
      {4, stdout, stderr} = main([oversized])
      assert document(stdout) |> Map.keys() |> Enum.sort() == ~w(code message)
      assert stderr =~ ~r/Rejected: [a-z_]+\. /
    end

    test "configuration_error exits 8: no keyring source, and a keyring failing a load check" do
      {code, stdout, _stderr} = main([@item, "--environment", "test"])
      assert code == 8
      assert %{"code" => "configuration_error"} = document(stdout)

      repeated = Path.join(@vectors, "negative/configuration-keyring-repeated_key.keyring.json")
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--keyring", repeated])
      assert code == 8
      assert %{"code" => "configuration_error"} = document(stdout)

      unparsable = Path.join(tmp(), "keyring.json")
      File.write!(unparsable, "{")

      assert {8, _stdout, _stderr} =
               main([@item, "--environment", "test", "--keyring", unparsable])
    end

    test "CONFIGURATION comes before the proof is read: a missing proof with no keyring source" do
      assert {8, stdout, _stderr} = main([missing(), "--environment", "test"])
      assert %{"code" => "configuration_error"} = document(stdout)

      unparsable = Path.join(tmp(), "keyring.json")
      File.write!(unparsable, "{")

      assert {8, stdout, _stderr} =
               main([missing(), "--environment", "test", "--keyring", unparsable])

      assert %{"code" => "configuration_error"} = document(stdout)
    end

    test "an input that cannot be read exits 1 with no report: the proof, or the keyring" do
      missing = missing()
      assert {1, "", stderr} = main([missing, "--no-keyring"])
      assert stderr =~ "Cannot read" and stderr =~ "No report."

      assert {1, "", _stderr} = main([@item, "--environment", "test", "--keyring", missing])
      directory = tmp()
      assert {1, "", _stderr} = main([@item, "--environment", "test", "--keyring", directory])
      assert {1, "", _stderr} = main([directory, "--no-keyring"])
    end

    test "a trace file that cannot be written after the run exits 1 with no report" do
      directory = tmp()
      argv = [@item, "--environment", "test", "--no-keyring", "--trace", directory]
      assert {1, "", stderr} = main(argv)
      assert stderr =~ "Cannot write the trace to #{directory}" and stderr =~ "No report"
    end

    test "a fault before steps 0 to 3 passed exits 2 with no report" do
      assert {2, "", stderr} = CLI.execute([environment: :nowhere], @item)
      assert IO.iodata_to_binary(stderr) =~ "stopped on a fault"

      assert {2, "", stderr} = CLI.execute([trust: :keyless, messages: ConfigurationFault], @item)
      assert IO.iodata_to_binary(stderr) =~ "stopped on a fault"
    end

    test "a fault no step caught, while the report is written, exits 2 with no report (12.2)" do
      # No command line makes these options: main/1 refuses such a hash (exit 1). The run
      # passes every step, and the report then cannot be written, since EXPECTED_HASH's
      # values echo the caller's value.
      options = [environment: :test, trust: :keyless, expected_hash: <<0xFF>>]
      assert {:ok, %Report{label: :failed}} = Verify.verify_file(@item, options)
      trace = Path.join(tmp(), "trace.json")
      assert {2, "", stderr} = CLI.execute(options, @item, trace)
      assert IO.iodata_to_binary(stderr) =~ "stopped on a fault before it could give a report"
      refute File.exists?(trace)
    end

    test "a fault caught from ENVIRONMENT on is an internal_error row and exits 3" do
      options = [environment: :test, trust: :keyless, messages: EnvironmentFault]
      {code, stdout, _stderr} = CLI.execute(options, @item)
      assert code == 3
      report = document(stdout)
      assert report["code"] == "internal_error"

      assert Enum.find(report["rows"], &(&1["code"] == "internal_error"))
             |> Map.take(~w(part step)) ==
               %{"part" => nil, "step" => "ENVIRONMENT"}
    end

    test "each exit code comes from spec/exit-codes.json" do
      assert ExitCode.code(:fault) == 2 and ExitCode.code(:runtime_error) == 1
      assert ExitCode.code(:bare_rejection) == 4 and ExitCode.code(:configuration_error) == 8
    end
  end

  # ---------------------------------------------------------------------------------------
  # Output

  describe "the machine output" do
    test "is the report, written with JCS; --trace FILE writes the trace in canonical form" do
      argv = [@item, "--environment", "test", "--keyring", @test_keyring]
      {6, plain, _stderr} = main(argv)
      trace = Path.join(tmp(), "item.trace.json")
      {6, traced, _stderr} = main(argv ++ ["--trace", trace])

      report = document(plain)
      assert plain == JCS.encode(report) <> "\n"
      assert traced == plain
      assert report |> Map.keys() |> Enum.sort() == @report_members

      expected = File.read!(Path.join(@vectors, "positive/item.trace.json"))
      assert File.read!(trace) == expected
      assert StrictJSON.canonical(StrictJSON.read_data!(trace)) == expected
    end

    test "a run that ended before DERIVE writes an empty trace under --trace FILE" do
      trace = Path.join(tmp(), "trace.json")
      {3, stdout, _stderr} = main([@item, "--trace", trace])
      refute Map.has_key?(document(stdout), "trace")
      assert File.read!(trace) == "[]\n"
    end
  end

  describe "the human output" do
    test "prints the item code beside the whole recomputed item_hash, and nowhere else" do
      proof = Signing.positive("item")
      item_hash = Hash.hash_hex(:item_hash, proof["subject"]["record"])
      {:ok, item_code} = ItemCode.from_item_hash(item_hash)

      {6, stdout, stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])

      lines = String.split(stderr, "\n")

      code_line = Enum.find_index(lines, &String.starts_with?(&1, "Item code: #{item_code}"))
      assert code_line
      assert Enum.at(lines, code_line - 1) == "item_hash, recomputed: #{item_hash}"
      assert Enum.count(lines, &String.contains?(&1, item_code)) == 1
      refute Enum.at(lines, code_line) =~ ~r/\b(pass|fail|skip|warn|info)\b/

      refute stdout =~ item_code
      refute Map.has_key?(document(stdout), "item_code")
    end

    test "computes the item code from the recomputed item_hash, never the declared one" do
      path = Path.join(@vectors, "negative/declared-item_hash.proof.json")
      argv = [path, "--environment", "test", "--keyring", @test_keyring]

      {:ok, report} =
        Verify.verify_file(path, environment: :test, trust: {:keyring_file, @test_keyring})

      %{declared: declared, recomputed: recomputed} =
        Enum.find(report.trace, &(&1.part == "/subject/item_hash"))

      assert declared != recomputed
      {:ok, code} = ItemCode.from_item_hash(recomputed)
      {:ok, declared_code} = ItemCode.from_item_hash(declared)

      {3, _stdout, stderr} = main(argv)
      lines = String.split(stderr, "\n")
      index = Enum.find_index(lines, &(&1 == "item_hash, recomputed: #{recomputed}"))
      assert index
      assert Enum.at(lines, index + 1) =~ "Item code: #{code} "
      refute stderr =~ declared_code
      refute stderr =~ declared
    end

    test "prints no item code for a proof that is not an item, or one that ended before DERIVE" do
      {5, _stdout, stderr} = main([@block, "--environment", "test", "--no-keyring"])
      refute stderr =~ "Item code"

      {3, _stdout, stderr} = main([@item])
      refute stderr =~ "Item code"
    end

    test "says keyless mode in words, and a non-production environment beside the verdict" do
      {5, _stdout, stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert stderr =~ "Label: unattributed, under the test environment, not production."
      assert stderr =~ "checked only against the key the document carries"
      assert stderr =~ "Environment: test, not production"

      {6, _stdout, stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])
      refute stderr =~ "checked only against the key the document carries"
      assert stderr =~ "Trust root: supplied_keyring, from #{@test_keyring}, SHA-256 "
    end

    test "names the command's options where a message says how to run again" do
      {3, stdout, _stderr} = main([@item])

      assert Enum.find(document(stdout)["rows"], &(&1["code"] == "environment_mismatch"))[
               "message"
             ] =~ "run again offline with --environment test and --keyring FILE."

      staging = Path.join(tmp(), "staging.proof.json")

      File.write!(
        staging,
        "item" |> Signing.positive() |> Map.put("environment", "staging") |> Signing.signed()
      )

      {3, stdout, _stderr} = main([staging, "--environment", "dev", "--no-keyring"])
      assert stdout =~ "this run checks proofs of its dev environment. To check it against"

      dev = "item" |> Signing.positive() |> Map.put("environment", "dev") |> Signing.signed()
      {3, stdout, _stderr} = main([write(dev)])
      assert stdout =~ "environment, which is for development. It is not a production proof."

      {3, stdout, _stderr} =
        main([
          Signing.production_without_key_event("item") |> then(&write(&1)),
          "--environment",
          "test",
          "--no-keyring"
        ])

      assert stdout =~ "run again without --environment."

      {8, stdout, _stderr} = main([@item, "--environment", "test"])
      assert document(stdout)["message"] =~ "run again with --keyring FILE, or with --no-keyring"
    end

    test "says keyless mode in words when the run fails at the gate, before KEY_BINDING runs" do
      {3, _stdout, stderr} = main([@item, "--no-keyring"])
      assert stderr =~ "Code: environment_mismatch"
      assert stderr =~ "Environment: prod\n"
      assert stderr =~ "the signature was checked only against the key the document carries"
    end

    test "shows no window for a failed run, and an absent one otherwise" do
      {3, _stdout, stderr} = main([@item])
      refute stderr =~ "Submitted"
      assert stderr =~ "Label: failed. A check failed"

      {5, _stdout, stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert stderr =~ "Submitted after: not established in this run ("
      assert stderr =~ "Submitted before: not established in this run ("
      refute stderr =~ "has no submitted-after edge"
    end

    test "says a proof with nothing to give a submitted-after edge has none (11.2)" do
      for name <- ~w(block beacon-empty) do
        path = Path.join(@vectors, "positive/#{name}.proof.json")
        {5, _stdout, stderr} = main([path, "--environment", "test", "--no-keyring"])
        assert stderr =~ "Submitted after: none. This proof has no submitted-after edge", name
        refute stderr =~ "Submitted after: not established", name
        assert stderr =~ "Submitted before: not established", name
      end
    end

    test "says when an edge's read was cached, and an edge no WINDOW row explains" do
      {:ok, report} =
        Verify.verify_file(@item, environment: :test, trust: {:keyring_file, @test_keyring})

      fetched_at = ~U[2026-09-26 02:00:00Z]

      edge = %Edge{
        instant: ~U[2026-09-26 01:48:30Z],
        precision: :second,
        basis: "stellar_ledger_close_read",
        assumption: Edge.assumption("stellar_ledger_close_read", :before),
        part: "/commitments/stellar",
        source: "horizon https://horizon.stellar.org",
        cached: true,
        fetched_at: fetched_at
      }

      lines =
        %{report | submitted_before: edge, rows: Enum.reject(report.rows, &(&1.step == :window))}
        |> CLI.human()
        |> IO.iodata_to_binary()

      assert lines =~
               "(stellar_ledger_close_read, read from horizon https://horizon.stellar.org " <>
                 "at 2026-09-26T02:00:00Z)"

      assert lines =~ "Submitted after: not established in this run.\n"
    end
  end

  defp write(bytes) do
    path = Path.join(tmp(), "proof.json")
    File.write!(path, bytes)
    path
  end

  defp tmp do
    dir = Path.join(System.tmp_dir!(), "truestamp-cli-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end
end
