# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.WalkthroughTest do
  @moduledoc """
  `guides/walkthrough.livemd`, the notebook that prints every value the trace of SPEC.md
  section 10.6 holds, each declared value beside the value the verifier recomputes for it,
  then the reads and the window of an online run answered from a replay file. Its Elixir
  cells run here as Livebook runs them, in order and in one binding, all but the first,
  whose `Mix.install` this project already satisfies. Every sound proof under
  `vectors/positive/` runs through it, and what each cell prints is held to that proof's
  trace file, its conformance case and SPEC.md's own words. It also runs over proofs that
  end before DERIVE, in keyless mode, with each input the cells refuse, and with the live
  section switched on, which the network guard keeps off the network.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Truestamp.Verify
  alias Truestamp.Verify.{Config, Report}
  alias Truestamp.Verify.Steps.Verdict
  alias Truestamp.Verify.Test.{Cases, StrictJSON, Verification}

  @notebook Path.expand("../guides/walkthrough.livemd", __DIR__)
  @external_resource @notebook
  @spec_md Verification.path("SPEC.md")
  @lib Path.expand("../lib", __DIR__)
  @verification Verification.root()
  @vectors Verification.vectors()
  @positive Path.join(@vectors, "positive")
  @keyring Path.join(@vectors, "keyring.test.json")
  @names @positive
         |> Path.join("*.proof.json")
         |> Path.wildcard()
         |> Enum.map(&Path.basename(&1, ".proof.json"))
         |> Enum.sort()

  # Where SPEC.md defines each construction's check, pinned here so that a wrong citation in
  # the notebook's own table fails.
  @sections %{
    "claims_hash" => "10.2 step 9 (a)",
    "item_hash" => "10.2 step 9 (a)",
    "entropy_hash" => "10.2 step 9 (a)",
    "observation_hash" => "10.2 step 9 (a)",
    "block_hash" => "10.2 step 9 (b)",
    "genesis" => "10.2 step 9 (b)",
    "key_event" => "10.3, key events",
    "handover" => "10.3, key events",
    "epoch_hash" => "10.2 step 9 (c)",
    "bitcoin" => "10.2 step 9 (d)",
    "inclusion" => "10.3, LINK_INCLUSION",
    "witnesses" => "10.3, LINK_WITNESS"
  }

  # The declared-value vector the edit section's last cell runs for each type, and the sound
  # proof the generator changed to make it (generator/lib/cases/derive.exs); any other type
  # takes the first.
  @declared %{
    "item" => {"declared-item_hash", "item"},
    "block" => {"declared-block_hash-block", "block"},
    "beacon" => {"declared-observation_hash-observation-nist", "beacon"},
    "entropy_nist" => {"declared-observation_hash-subject", "entropy_nist"}
  }

  # The sound proofs whose trace lacks the part their type's vector changes, so that the edit
  # cell falls back to the first 64-hex trace value.
  @edit_fallback ~w(beacon-empty entropy_bitcoin entropy_stellar)

  @gate ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE)
  @after_signature ~w(SHAPE POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH)
  @after_derive ~w(CHAIN SOURCES WINDOW EXPECTED_HASH)
  # The configuration cell's line that names the checkout of truestamp-verification.
  @checkout ~s|verification = Path.expand("../deps/truestamp_verification", __DIR__)\n|

  @keyless "Keyless      the signature was checked only against the key the document " <>
             "carries (SPEC.md 8.3)\n"

  # A module of the verifier's own primitives, a test-only helper, a JSON decoder, or an
  # Erlang primitive, named in a code cell.
  @primitive ~r/:crypto|:public_key|:json\b|:erlang\.(md5|crc32|phash2?)\b|\b(JCS|Hash|Ed25519|Merkle|Prefixes|KeyId|ItemCode|Base64URL|Binary64|Bitcoin|Signing|StrictJSON|Jason|JSON)\b|\.Test\./
  # A call or a capture of a function whose name says it hashes, signs, verifies or decodes,
  # with or without a prefix (`url_decode64`, `block_hash`, `&Base.decode16!/1`). A call
  # through apply/3 names no function, so the scan covers calls by name only.
  @hash_call ~r/\b\w*(sha|md5|blake2|hmac|hash|digest|sign|verify|decode)\w*!?\s*(\(|\/\d)/i
  # The library's own entry points, which run the verifier, the one thing a cell may do; the
  # scan for calls that verify skips them.
  @entry_points ~r/\bTruestamp\.Verify\.(verify|verify_file|verified\?)\(/

  test "holds the eleven sound proofs it is run over" do
    assert length(@names) == 11
    assert "item" in @names
  end

  test "its first cell installs this checkout of the library, with Req, and only it calls Mix.install" do
    [{_line, setup} | rest] = cells()

    assert setup ==
             "Mix.install([\n  {:truestamp_verify, path: Path.expand(\"..\", __DIR__)},\n" <>
               "  {:req, \"~> 0.7\"}\n])\n"

    assert Mix.Project.config()[:app] == :truestamp_verify
    assert Path.expand("..", Path.dirname(@notebook)) == Path.dirname(Mix.Project.project_file())
    refute Enum.any?(rest, fn {_line, code} -> code =~ "Mix.install" end)
  end

  test "its configuration cell reads the vectors of the checkout `mix deps.get` fetches" do
    [_setup, {_line, configuration} | _rest] = cells()
    assert configuration =~ @checkout

    assert Path.expand("../deps/truestamp_verification", Path.dirname(@notebook)) ==
             Path.join(Path.dirname(Mix.Project.project_file()), "deps/truestamp_verification")
  end

  test "each cell is as mix format writes it" do
    for {line, code} <- cells() do
      assert formatted?(code), "the cell at line #{line} is not as mix format writes it"
    end

    refute formatted?("x =   1\n")
  end

  test "its text names no hash, signature, Merkle or JCS function, and its cells call none" do
    text = File.read!(@notebook)

    refute text =~ ":crypto"

    for {line, code} <- cells() do
      refute forbidden?(code), "the cell at line #{line} computes something of its own"
    end

    # The patterns catch what they are for, and pass the library's entry points only.
    for mutant <- [
          ":crypto.hash(:sha256, bytes)",
          "Truestamp.Verify.JCS.encode(proof)",
          "Truestamp.Merkle.walk(leaf, path, root)",
          "Truestamp.Verify.Hash.hash(:block_hash, record)",
          "Truestamp.Verify.Ed25519.verify(k, m, v)",
          "sha256(bytes)",
          ":erlang.md5(bytes)",
          "Truestamp.Verify.Test.Signing.signed(proof, 0x42)",
          "signed(proof, 0x42)",
          "Jason.decode!(File.read!(proof_file))",
          "JSON.decode!(File.read!(proof_file))",
          ":json.decode(File.read!(proof_file))",
          "Base.decode16!(hex, case: :lower)",
          "Base.url_decode64(signature, padding: false)",
          ":base64.mime_decode(bytes)",
          "Base.hex_decode32(bytes)",
          "record_hash(record)",
          "verify_strict(k, m, v)",
          "Enum.map(values, &Base.decode16!/1)",
          "&:binary.decode_hex/1",
          "Truestamp.Verify.Steps.Signature.verify(run)",
          "verify(bytes, config)"
        ] do
      assert forbidden?(mutant), mutant
    end

    refute forbidden?("Truestamp.Verify.verify_file(proof_file, config)")
    refute forbidden?("Truestamp.Verify.verify(bytes, config)")
  end

  test "its cells name only modules of Elixir, Erlang/OTP and the library" do
    for {line, code} <- cells() do
      assert foreign_modules(code) == [], "the cell at line #{line} names a module Livebook lacks"
    end

    # A module only the tests have, or a dependency's, is one a Livebook session lacks.
    assert foreign_modules("Truestamp.Verify.Test.Signing.signed(p, 0x42)") ==
             [Truestamp.Verify.Test.Signing]

    assert foreign_modules("Truestamp.Verify.Test.StrictJSON.read_data!(f)") ==
             [Truestamp.Verify.Test.StrictJSON]

    assert foreign_modules("Plug.Conn.send_resp(conn)") == [Plug.Conn]
    assert foreign_modules("Enum.map(Truestamp.Verify.Config.external!(), & &1)") == []
  end

  test "its label meanings are SPEC.md 10.5's own words, one for each label" do
    {binding, _outputs} = evaluate()

    assert Enum.sort(Map.keys(binding[:meaning])) ==
             Enum.sort(Enum.map(Verdict.labels(), &Verdict.label_name/1))

    assert binding[:meaning] == spec_meanings()
  end

  test "as it stands, it walks the sound item proof top to bottom" do
    {binding, outputs} = evaluate()

    assert binding[:proof_file] == Path.join(@positive, "item.proof.json")
    assert_sound_walkthrough("item", binding, outputs)
  end

  for name <- @names do
    @name name

    test "pointed at #{name}.proof.json, it runs top to bottom and shows every trace row" do
      {binding, outputs} = evaluate(proof_file: Path.join(@positive, @name <> ".proof.json"))
      assert_sound_walkthrough(@name, binding, outputs)
    end
  end

  test "pointed at a declared-value vector, it prints the failing trace row, the failing DERIVE row and every skip after it" do
    proof_file = Path.join(@vectors, "negative/declared-item_hash.proof.json")
    {binding, outputs} = evaluate(proof_file: proof_file)
    {trace, _number, _failing} = vector_trace("item")

    assert_walkthrough(case_of("declared-item_hash"), trace, binding, outputs)
  end

  test "an edit of a value that ends in 0 makes it end in 1" do
    vector = "declared-witness_hashes-entropy_stellar"
    proof_file = Path.join(@vectors, "negative/#{vector}.proof.json")
    {binding, outputs} = evaluate([proof_file: proof_file], edited_part: "/block/block_hash")
    declared = get_in(StrictJSON.read_data!(proof_file), ~w(proof block block_hash))

    assert String.ends_with?(declared, "0")
    assert output(outputs, "hex64? =") == changed("/block/block_hash", declared)
    assert get_in(binding[:edited_document], ~w(proof block block_hash)) =~ ~r/1\z/
    assert_signature_section(outputs, case_of(vector))
  end

  test "in keyless mode, every verdict it prints says the signature was checked only against the key the document carries" do
    config = Config.external!(environment: :test, trust: :keyless)
    {_binding, outputs} = evaluate(config: config)

    assert output(outputs, "verify_file(proof_file, config)") =~
             "Label        unattributed\nEnvironment  test\n" <> @keyless

    [_rows, trust] = String.split(output(outputs, "gate = ~w("), "\n\n")

    assert trust ==
             "Trust root   none\n  digest     null\n  location   null\n" <>
               "Attribution  unattributed\n"

    assert output(outputs, "meaning = %{") =~
             "Label        unattributed (SPEC.md 10.5): " <>
               spec_meanings()["unattributed"] <>
               "\nEnvironment  test\nAttribution  unattributed\n"

    assert String.ends_with?(
             output(outputs, "meaning = %{"),
             "\nWindow       not_established\n" <> @keyless
           )

    assert String.ends_with?(
             output(outputs, "signature_report ="),
             "\nCode         signature_invalid\nEnvironment  test\n" <> @keyless
           )

    # The declared-value vector and the online run use the notebook's keyring, so neither is
    # keyless.
    refute output(outputs, "vector_file =") =~ "Keyless"
    refute output(outputs, "replay_file =") =~ "Keyless"
  end

  test "under the production configuration, over a test proof, it says the run ended at ENVIRONMENT and that there is nothing to change" do
    {binding, outputs} = evaluate(config: Config.external!())
    ended = no_derive("ENVIRONMENT", "environment_mismatch")

    assert binding[:report].label == :failed

    assert String.ends_with?(
             output(outputs, "verify_file(proof_file, config)"),
             "Label        failed\nCode         environment_mismatch\nEnvironment  prod\n"
           )

    assert output(outputs, "if report.trace == [] do") == ended <> "\n"
    assert output(outputs, "hex64? =") == ended <> "\n"
    assert output(outputs, "signature_report =") == ended <> "\n"
    assert binding[:edited_document] == nil
    assert_vector(outputs, "item")
  end

  test "over a proof that fails at SHAPE, it says the run ended there and that there is nothing to change" do
    proof_file = Path.join(@vectors, "negative/shape-constructions-byte_changed.proof.json")
    {_binding, outputs} = evaluate(proof_file: proof_file)
    ended = no_derive("SHAPE", "construction_mismatch")

    assert output(outputs, "verify_file(proof_file, config)") =~
             "Label        failed\nCode         construction_mismatch\nEnvironment  test\n"

    assert output(outputs, "if report.trace == [] do") == ended <> "\n"
    assert output(outputs, "hex64? =") == ended <> "\n"
    assert output(outputs, "signature_report =") == ended <> "\n"

    # With no type, the edit section's last cell takes the item's vector.
    assert_vector(outputs, nil)
  end

  test "a file that cannot be read gets its own message, not the gate's" do
    missing = Path.join(@positive, "no-such-proof.proof.json")

    error = assert_raise RuntimeError, fn -> evaluate(proof_file: missing) end
    assert error.message =~ "Cannot read #{missing}: no such file or directory."
    assert error.message =~ "That is a runtime error outside verification"
    assert error.message =~ "(SPEC.md 12.2, exit code 1)"
    refute error.message =~ "10.2"
  end

  test "a bare rejection says so, with its code and sub_reason" do
    proof_file = Path.join(@vectors, "negative/parse-byte-order-mark.proof.json")

    error = assert_raise RuntimeError, fn -> evaluate(proof_file: proof_file) end
    assert error.message =~ "is a bare rejection: malformed_json (syntax)."
    assert error.message =~ "(SPEC.md 10.2, the gate)"
  end

  test "edited_part changes another 64-hex value it is set to" do
    {binding, outputs} = evaluate([], edited_part: "/block/block_hash")
    trace = StrictJSON.read_data!(Path.join(@positive, "item.trace.json"))
    row = Enum.find(trace, &(&1["part"] == "/block/block_hash"))

    assert output(outputs, "hex64? =") == changed("/block/block_hash", row["declared"])
    assert binding[:edited_part] == "/block/block_hash"
    assert_signature_section(outputs, case_of("sound-item"))
  end

  for part <- [
        "/commitments/bitcoin/header_time",
        "/commitments/bitcoin/inclusion_proof/tree_size",
        "/block/record/leaf_count"
      ] do
    @part part

    test "edited_part refuses #{part}, which is not a 64-hex trace value" do
      error = assert_raise ArgumentError, fn -> evaluate([], edited_part: @part) end

      assert error.message ==
               "edited_part must be the part of a trace row above whose declared value is 64 " <>
                 "lowercase hex digits, and #{inspect(@part)} is not"
    end
  end

  test "its online section gives the rows, the reads and both edges of the case window-established" do
    {binding, outputs} = evaluate()
    kase = case_of("window-established")
    expected = kase["expected"]
    report = binding[:online_report]

    assert binding[:online_proof_file] == Path.join(@vectors, kase["proof"])
    assert binding[:replay_file] == Path.join(@vectors, kase["config"]["online"])
    assert Report.reduce(report)["rows"] == expected["rows"]

    [rows, reads, edges, label] = String.split(output(outputs, "replay_file ="), "\n\n")
    assert printed_rows(rows) == rows_of(expected["rows"], ~w(CHAIN SOURCES WINDOW))

    # One line for each CHAIN and SOURCES row, then each read it made and its candidate.
    reads = String.split(reads, "\n", trim: true)
    read_rows = for row <- report.rows, row.step in [:chain, :sources], do: row

    assert Enum.filter(reads, &(not String.starts_with?(&1, "  "))) ==
             Enum.map(read_rows, fn row ->
               "#{Verify.Step.name(row.step)} #{row.part}: #{row.status} #{row.code || "-"}"
             end)

    assert Enum.filter(reads, &String.starts_with?(&1, "  read ")) ==
             for(
               row <- read_rows,
               read <- row.values["reads"] || [],
               do:
                 "  read #{read["kind"]}" <>
                   Enum.map_join(read["params"], fn {name, value} -> " #{name}=#{value}" end) <>
                   ": #{read["outcome"]}"
             )

    assert "  read bitcoin_block_at_height height=222: found" in reads

    for row <- read_rows,
        %{"instant" => instant, "basis" => basis} <- [row.values["candidate"]] do
      assert "  candidate #{instant} (#{basis})" in reads
    end

    # Each edge is the case's, with its stated assumption, part and source.
    for name <- ~w(submitted_after submitted_before) do
      %{"instant" => instant, "basis" => basis} = expected[name]
      edge = Map.fetch!(report, String.to_existing_atom(name))
      assert edges =~ "#{name}: #{instant}\n  basis       #{basis}\n"
      assert edges =~ "  assumption  #{edge.assumption}\n  part        #{edge.part}\n"
      assert edges =~ "  source      replay\n"
    end

    assert String.ends_with?(edges, "window: established")

    assert label ==
             "Label        #{expected["label"]}\nEnvironment  test\n"
  end

  test "its live section runs nothing until it names a proof" do
    {_binding, outputs} = evaluate()

    assert output(outputs, "live_proof_file = nil") ==
             "Set live_proof_file to the path of a production proof to verify it online.\n"
  end

  test "its live section, given a proof, prints the run or why there is none, and reads nothing here" do
    # Under the network guard, no request reaches the network.
    {_binding, outputs} =
      evaluate([], live_proof_file: Path.join(@positive, "item.proof.json"))

    printed = output(outputs, "live_proof_file =")

    assert printed =~
             "Label        failed\nCode         environment_mismatch\nEnvironment  prod\n"

    refute printed =~ "candidate "

    missing = Path.join(@positive, "no-such-proof.proof.json")
    {_binding, outputs} = evaluate([], live_proof_file: missing)

    assert output(outputs, "live_proof_file =") ==
             "No report: Cannot read #{missing}: no such file or directory\n"
  end

  # ---------------------------------------------------------------------------------------
  # The notebook's cells

  # Each ```elixir fence, in order, as {line, code}: Livebook's code cells.
  defp cells do
    text = File.read!(@notebook)

    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(text, capture: :all_but_first, return: :index)
    |> Enum.map(fn [{start, length}] ->
      {text |> binary_part(0, start) |> String.split("\n") |> length(),
       binary_part(text, start, length)}
    end)
  end

  defp formatted?(code), do: IO.iodata_to_binary(Code.format_string!(code)) <> "\n" == code

  defp forbidden?(code) do
    scanned = String.replace(code, @entry_points, "")
    code =~ @primitive or scanned =~ @hash_call
  end

  # Every module a cell names, by alias or as an Erlang module it calls, that is neither
  # Elixir's nor Erlang/OTP's nor defined under lib/: a module a Livebook session, which
  # builds only the library, would not have.
  defp foreign_modules(code) do
    {_ast, modules} =
      code
      |> Code.string_to_quoted!()
      |> Macro.prewalk([], fn
        {:__aliases__, _, parts} = node, acc when is_list(parts) ->
          if Enum.all?(parts, &is_atom/1),
            do: {node, [Module.concat(parts) | acc]},
            else: {node, acc}

        {:., _, [module, _function]} = node, acc when is_atom(module) ->
          {node, [module | acc]}

        node, acc ->
          {node, acc}
      end)

    modules |> Enum.uniq() |> Enum.reject(&available?/1) |> Enum.sort()
  end

  defp available?(module) do
    case :code.which(module) do
      path when is_list(path) ->
        path = List.to_string(path)
        standard = [List.to_string(:code.root_dir()), Path.dirname(:code.lib_dir(:elixir))]
        Enum.any?(standard, &String.starts_with?(path, &1 <> "/")) or in_lib?(module)

      :preloaded ->
        true

      # `mix test --cover` loads the library's modules from cover's own compilation.
      :cover_compiled ->
        in_lib?(module)

      _missing ->
        false
    end
  end

  defp in_lib?(module) do
    source = module.module_info(:compile)[:source]
    is_list(source) and String.starts_with?(List.to_string(source), @lib <> "/")
  end

  # Runs every cell but the first in one binding, as Livebook does, and gives the binding and
  # what each cell printed, as {code, output} in order. The configuration cell reads the
  # checkout these tests run against. Each of `overrides` replaces a binding of the
  # configuration cell, as a reader who edits that cell does; `edited_part` and
  # `live_proof_file` set the line of the cell that picks each. No cell may give a compiler
  # warning, and every cell after the configuration cell that runs to its end must give :ok,
  # since Livebook shows a cell's last value under its output.
  defp evaluate(overrides \\ [], options \\ []) do
    [_setup, {line, configuration} | rest] = cells()
    configuration = checkout(configuration)

    rest =
      Enum.map(rest, fn {line, code} ->
        code =
          code
          |> pick("edited_part", options[:edited_part])
          |> pick("live_proof_file", options[:live_proof_file])

        {line, code}
      end)

    {{binding, outputs}, diagnostics} =
      Code.with_diagnostics(fn ->
        {_configuration, binding} = eval(configuration, line, [])

        binding
        |> override(overrides)
        |> eval_each(rest)
      end)

    assert diagnostics == []
    {binding, outputs}
  end

  defp checkout(configuration) do
    assert length(String.split(configuration, @checkout)) == 2
    String.replace(configuration, @checkout, "verification = #{inspect(@verification)}\n")
  end

  defp override(binding, overrides) do
    Enum.reduce(overrides, binding, fn {name, value}, binding ->
      Keyword.replace!(binding, name, value)
    end)
  end

  # Each cell in one binding, with what it printed. Livebook shows a cell's last value under
  # its output, so each cell ends with :ok rather than a stray value.
  defp eval_each(binding, cells) do
    Enum.reduce(cells, {binding, []}, fn {line, code}, {binding, outputs} ->
      {{value, binding}, output} = with_io(fn -> eval(code, line, binding) end)

      assert value == :ok,
             "the cell at line #{line} of guides/walkthrough.livemd gives " <>
               "#{inspect(value, limit: 5, printable_limit: 80)}, not :ok, and Livebook " <>
               "shows that value under the cell's output"

      {binding, outputs ++ [{code, output}]}
    end)
  end

  defp pick(code, _name, nil), do: code

  defp pick(code, name, value) do
    line = "#{name} = nil\n"
    assert length(String.split(code, line)) <= 2
    String.replace(code, line, "#{name} = #{inspect(value)}\n")
  end

  defp eval(code, line, binding),
    do: Code.eval_string(code, binding, file: @notebook, line: line)

  # What the one cell whose code holds `snippet` printed.
  defp output(outputs, snippet) do
    [output] = for {code, output} <- outputs, code =~ snippet, do: output
    output
  end

  # ---------------------------------------------------------------------------------------
  # What it must print

  defp assert_sound_walkthrough(name, binding, outputs) do
    trace = StrictJSON.read_data!(Path.join(@positive, name <> ".trace.json"))
    assert_walkthrough(case_of("sound-" <> name), trace, binding, outputs)
  end

  # The walk of the proof of case `kase`, whose trace is `trace`: what each cell prints, held
  # to the case's rows and label and to that trace.
  defp assert_walkthrough(kase, trace, binding, outputs) do
    rows = kase["expected"]["rows"]
    label = kase["expected"]["label"]
    code_line = code_line(rows)
    {:ok, report} = Verify.verify_file(Path.join(@vectors, kase["proof"]), binding[:config])
    report = Report.to_map(report)

    # The run: its summary lines.
    assert output(outputs, "verify_file(proof_file, config)") ==
             "Proof        vectors/#{kase["proof"]}\n" <>
               "Type         #{report["type"]}\n" <>
               "Subject id   #{report["subject_id"]}\n" <>
               "Rows         #{length(rows)}\n" <>
               "Trace rows   #{length(trace)}\n" <>
               "Label        #{label}\n" <> code_line <> "Environment  test\n"

    # Each step's rows, exactly and in order.
    [gate_rows, trust] = String.split(output(outputs, "gate = ~w("), "\n\n")
    assert printed_rows(gate_rows) == rows_of(rows, @gate)

    assert trust ==
             "Trust root   supplied_keyring\n" <>
               "  digest     #{report["trust_root"]["digest"]}\n" <>
               "  location   #{@keyring}\n" <>
               "Attribution  #{report["attribution"]}\n"

    assert printed_rows(output(outputs, "~w(SHAPE POLICY)")) == rows_of(rows, ~w(SHAPE POLICY))

    # Every trace row, in order, with its number, construction, status, SPEC citation, part,
    # declared and recomputed values and inputs.
    assert Enum.all?(trace, &Map.has_key?(binding[:spec_section], &1["construction"]))

    assert output(outputs, "if report.trace == [] do") ==
             trace |> Enum.with_index(1) |> Enum.map_join(&trace_block/1)

    assert printed_rows(output(outputs, "print_rows.(rows_of.(report, ~w(DERIVE)))")) ==
             rows_of(rows, ~w(DERIVE))

    # CHAIN, SOURCES and WINDOW, then each edge with the rows that could have given it.
    [chain_rows, edges] = String.split(output(outputs, "window_row ="), "\n\n")
    assert printed_rows(chain_rows) == rows_of(rows, ~w(CHAIN SOURCES WINDOW))
    assert edges == edge_lines(report) <> "window: not_established\n"

    # EXPECTED_HASH, then the verdict with SPEC.md 10.5's meaning of its label.
    [expected_rows, verdict] = String.split(output(outputs, "meaning = %{"), "\n\n")
    assert printed_rows(expected_rows) == rows_of(rows, ~w(EXPECTED_HASH))

    assert verdict ==
             "Label        #{label} (SPEC.md 10.5): #{spec_meanings()[label]}\n" <>
               "Environment  test\n" <>
               "Attribution  #{report["attribution"]}\n" <>
               "Verified     false\n" <>
               "Window       not_established\n" <> code_line

    assert_edit(kase, report["type"], binding, outputs, trace)
    assert_vector(outputs, report["type"])
  end

  # The in-memory edit: by default the part the type's vector changes, where the trace has
  # it, and otherwise the first 64-hex trace value, its last digit changed; then the run of
  # the edited proof, which fails SIGNATURE and skips the rest.
  defp assert_edit(kase, type, binding, outputs, trace) do
    hex_rows =
      Enum.filter(trace, &(is_binary(&1["declared"]) and &1["declared"] =~ ~r/\A[0-9a-f]{64}\z/))

    {vector, _sound} = Map.get(@declared, type, @declared["item"])
    [[_code, vector_part, _status, _step]] = failing_rows(case_of(vector)["expected"]["rows"])
    row = Enum.find(hex_rows, &(&1["part"] == vector_part))

    assert row == nil ==
             kase["id"] in Enum.map(@edit_fallback, &("sound-" <> &1))

    row = row || List.first(hex_rows)
    part = row["part"]
    assert binding[:edited_part] == part
    assert output(outputs, "hex64? =") == changed(part, row["declared"])

    path = ["proof" | part |> String.split("/") |> tl()]
    edited = get_in(binding[:edited_document], path)
    assert edited == flip_last(row["declared"])

    assert binding[:edited_document] ==
             put_in(Report.document(binding[:report]), path, edited)

    assert_signature_section(outputs, kase)
  end

  defp assert_signature_section(outputs, kase) do
    before_signature = rows_of(kase["expected"]["rows"], @gate -- ["SIGNATURE"])

    expected =
      before_signature ++
        [["signature_invalid", nil, "fail", "SIGNATURE"]] ++
        for(step <- @after_signature, do: ["prior_failure", nil, "skip", step])

    [rows, label] = String.split(output(outputs, "signature_report ="), "\n\n")
    assert printed_rows(rows) == expected

    assert label ==
             "Label        failed\nCode         signature_invalid\nEnvironment  test\n"
  end

  # The trace of the declared-value vector of `type`: the trace of the sound proof it was made
  # from, with the row at the changed part declaring the file's value and failing; and that
  # row with its number.
  defp vector_trace(type) do
    {vector, sound} = Map.get(@declared, type, @declared["item"])

    [["derivation_mismatch", part, "fail", "DERIVE"]] =
      failing_rows(case_of(vector)["expected"]["rows"])

    sound_trace = StrictJSON.read_data!(Path.join(@positive, sound <> ".trace.json"))
    number = Enum.find_index(sound_trace, &(&1["part"] == part)) + 1
    sound_row = Enum.at(sound_trace, number - 1)

    proof = StrictJSON.read_data!(Path.join(@vectors, "negative/#{vector}.proof.json"))
    declared = get_in(proof, ["proof" | part |> String.split("/") |> tl()])
    assert declared != sound_row["declared"]

    failing = %{sound_row | "declared" => declared, "status" => "fail"}
    {List.replace_at(sound_trace, number - 1, failing), number, failing}
  end

  # The declared-value vector of `type`: its failing trace row, with the changed value
  # declared and the sound proof's value recomputed, then ENVIRONMENT to SHAPE, the failing
  # DERIVE row and every row after DERIVE, as its case gives them, and the label and code.
  defp assert_vector(outputs, type) do
    {vector, sound} = Map.get(@declared, type, @declared["item"])
    rows = case_of(vector)["expected"]["rows"]
    [[_code, part, _status, _step]] = failing_rows(rows)
    {_trace, number, failing} = vector_trace(type)

    [heading, trace_text, table, label] =
      String.split(output(outputs, "vector_file ="), "\n\n")

    assert heading ==
             "Proof        vectors/negative/#{vector}.proof.json\nType         #{sound}"

    assert trace_text <> "\n" == "The failing trace rows:\n" <> trace_block({failing, number})

    [caption, rows_text] = String.split(table, "\n", parts: 2)

    assert caption ==
             "ENVIRONMENT to SHAPE, the failing DERIVE rows, and every step after DERIVE:"

    assert printed_rows(rows_text) ==
             rows_of(rows, ~w(ENVIRONMENT KEY_BINDING SIGNATURE SHAPE)) ++
               [["derivation_mismatch", part, "fail", "DERIVE"]] ++ rows_of(rows, @after_derive)

    assert Enum.any?(rows_of(rows, @after_derive), &(Enum.at(&1, 0) == "prior_failure"))

    assert label ==
             "Label        failed\nCode         derivation_mismatch\nEnvironment  test\n"
  end

  defp case_of(id), do: Cases.get!(id)

  defp failing_rows(rows), do: Enum.filter(rows, &(Enum.at(&1, 2) == "fail"))

  # The line that prints the run's code, the code of its first failing row, or none.
  defp code_line(rows) do
    case failing_rows(rows) do
      [] -> ""
      [[code | _] | _] -> "Code         #{code}\n"
    end
  end

  defp changed(part, declared),
    do: "Changed  #{part}\n  from   #{declared}\n  to     #{flip_last(declared)}\n"

  defp flip_last(hex) do
    {head, last} = String.split_at(hex, -1)
    head <> if(last == "0", do: "1", else: "0")
  end

  defp no_derive(step, code) do
    "This run ended at #{step} with #{code} (SPEC.md 10.2), before DERIVE compared any " <>
      "declared value, so the trace is empty: there is no DERIVE value to show or change."
  end

  # Each edge's line, then the rows that could have given it, or that none could.
  defp edge_lines(report) do
    window = Enum.find(report["rows"], &(&1["step"] == "WINDOW"))

    Enum.map_join(~w(submitted_after submitted_before), fn edge ->
      reasons =
        case window["values"]["absent"][edge] do
          nil ->
            ""

          [] ->
            "  no row could give it: the proof carries nothing that could (SPEC.md 11.2)\n"

          reasons ->
            Enum.map_join(reasons, &"  #{&1["code"]} at #{&1["part"]}\n")
        end

      "#{edge}: null\n" <> reasons
    end)
  end

  defp trace_block({row, number}) do
    String.pad_leading("#{number}", 3) <>
      "  " <>
      String.pad_trailing(row["construction"], 18) <>
      String.pad_trailing(row["status"], 6) <>
      "SPEC.md #{Map.fetch!(@sections, row["construction"])}\n" <>
      "    part        #{row["part"]}\n" <>
      "    declared    #{text(row["declared"])}\n" <>
      "    recomputed  #{text(row["recomputed"])}\n" <>
      "    inputs      #{Enum.join(row["inputs"], ", ")}\n"
  end

  defp rows_of(rows, steps), do: Enum.filter(rows, &(List.last(&1) in steps))

  # The rows of a table `print_rows` printed, as [code, part, status, step], read by the
  # columns its header sets, so a row out of its column fails.
  defp printed_rows(text) do
    [header | lines] = String.split(text, "\n", trim: true)
    code_at = 22
    part_at = :binary.match(header, "part") |> elem(0)

    assert String.starts_with?(header, "step           status code")
    assert String.trim_trailing(binary_part(header, code_at, part_at - code_at)) == "code"

    for line <- lines do
      step = column(line, 0, 15)
      status = column(line, 15, code_at - 15)
      code = column(line, code_at, part_at - code_at)
      part = binary_part(line, part_at, byte_size(line) - part_at)

      refute part =~ " "

      [
        if(code == "-", do: nil, else: code),
        if(part == "null", do: nil, else: part),
        status,
        step
      ]
    end
  end

  defp column(line, at, width) do
    field = binary_part(line, at, width)
    value = String.trim_trailing(field)
    assert value != "" and not String.contains?(value, " "), "not aligned: #{inspect(line)}"
    value
  end

  defp text(nil), do: "null"
  defp text(value) when is_binary(value), do: value
  defp text(value) when is_integer(value), do: Integer.to_string(value)

  # SPEC.md 10.5's labels table: each label and what it says.
  defp spec_meanings do
    [_before, section] = String.split(File.read!(@spec_md), "\n### 10.5 ", parts: 2)
    [section | _] = String.split(section, "\n### ", parts: 2)
    [_before, table] = String.split(section, "| `label` | When | What it says |\n", parts: 2)

    table
    |> String.split("\n")
    |> Enum.take_while(&String.starts_with?(&1, "|"))
    |> Enum.drop(1)
    |> Map.new(fn line ->
      [_, label, _when, says] = Regex.run(~r/^\| `([a-z-]+)` \| (.*) \| (.*) \|$/, line)
      {label, says}
    end)
  end
end
