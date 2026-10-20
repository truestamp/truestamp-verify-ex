# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.RenderingTest do
  @moduledoc """
  Rows and bare rejections keep their message's id and assigns (`Truestamp.Verify.Row`,
  `Truestamp.Verify.Rejection`), so a caller renders a stored one again through another
  message module, and neither field reaches the output of SPEC.md sections 10.2 and 10.5.
  A `configuration_error` names the check of step 0 that failed, with its chain and network.
  """

  use ExUnit.Case, async: true

  alias Truestamp.Verify
  alias Truestamp.Verify.{Config, Keyring, Messages, Rejection, Report, Row}
  alias Truestamp.Verify.Readers.Replay
  alias Truestamp.Verify.Test.{FakeReader, Signing, Verification}

  @item Verification.path("vectors/positive/item.proof.json")
  @keyring Verification.path("vectors/keyring.test.json")
  @replay Verification.path("vectors/corpus/replay/window-established.json")
  @pins %{
    commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
    entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  # A second message module, whose text for every id spells the id and the assigns, so text
  # it gives can only come from both.
  defmodule Echo do
    @behaviour Truestamp.Verify.Messages
    @impl true
    def message(id, assigns), do: "#{id} #{inspect(assigns)}"
  end

  defp options(extra), do: [environment: :test, trust: {:keyring_file, @keyring}] ++ extra

  # Two sources, "a" and "b", for each pinned network, and "a" for NIST.
  @sources %{
    {"stellar", "testnet"} => {:ok, ["a", "b"], {:at_least, 2}},
    {"bitcoin", "regtest"} => {:ok, ["a", "b"], :first},
    {"nist", nil} => {:ok, ["a"], :first}
  }

  # An online run whose reader serves its sources from the replay file, with `sources` in
  # place of those above.
  defp online(sources) do
    source_map = Map.merge(@sources, sources)
    reader = FakeReader.from_replay(@replay, sources: ["a", "b"], source_map: source_map)
    options(reader: reader, networks: @pins)
  end

  describe "a stored row" do
    test "renders again as another module gives it in a run, the report unchanged" do
      for run <- [options([]), online(%{}), options(expected_hash: "00")] do
        {:ok, english} = Verify.verify_file(@item, run)
        {:ok, echoed} = Verify.verify_file(@item, Keyword.put(run, :messages, Echo))

        assert length(english.rows) == length(echoed.rows)

        for {row, echoed_row} <- Enum.zip(english.rows, echoed.rows) do
          assert row.message_id in Messages.English.ids()
          assert Row.render(row, Echo) == echoed_row.message
          assert Row.render(row, Messages.English) == row.message
        end

        # The id and the assigns are not part of the row section 10.5 writes.
        assert Report.to_map(english) |> Map.delete("rows") ==
                 Report.to_map(echoed) |> Map.delete("rows")

        for row <- english.rows do
          assert Map.keys(Row.to_map(row)) -- ["code"] ==
                   ~w(message part status step values)

          assert Row.to_map(%{row | message_id: :other, assigns: %{any: 1}}) == Row.to_map(row)
          assert Row.reduce(%{row | message_id: :other}) == Row.reduce(row)
        end

        changed = %{english | rows: Enum.map(english.rows, &%{&1 | assigns: %{}})}
        assert Report.to_json(changed) == Report.to_json(english)
        assert Report.trace_json(changed) == Report.trace_json(english)
      end

      # The online run read its sources, so its CHAIN and SOURCES rows are among those above.
      {:ok, report} = Verify.verify_file(@item, online(%{}))
      assert Enum.any?(report.rows, &(&1.step == :sources and &1.status == :pass))
      assert Enum.any?(report.rows, &(&1.step == :chain and &1.message_id == :read_outcome))
    end

    test "every step's rows keep their id, the internal_error row's among them" do
      defmodule FaultAtWindow do
        @behaviour Truestamp.Verify.Messages
        @impl true
        def message(:window_not_established, _assigns), do: raise("no")
        def message(_id, _assigns), do: nil
      end

      {:ok, report} = Verify.verify_file(@item, options(messages: FaultAtWindow))
      steps = report.rows |> Enum.map(& &1.step) |> Enum.uniq()
      assert :derive in steps and :window in steps and :expected_hash in steps
      assert Enum.all?(report.rows, &(&1.message_id != nil))

      fault = Enum.find(report.rows, &(&1.code == :internal_error))
      assert fault.message_id == :internal_error
      assert fault.assigns == %{step: "WINDOW", kind: :error, module: "RuntimeError"}
      assert Row.render(fault, Echo) =~ "internal_error"

      skip = List.last(report.rows)
      assert {skip.step, skip.message_id} == {:expected_hash, :prior_failure_gate}
    end

    test "a row built from text alone keeps its text" do
      row = Row.pass(:read, nil, "m")
      assert {row.message_id, row.assigns} == {nil, %{}}
      assert Row.render(row, Echo) == "m"

      row = Row.new(:read, nil, nil, {:read_pass, %{n: 1}, "t"})
      assert {row.message_id, row.assigns, row.message} == {:read_pass, %{n: 1}, "t"}
      assert Row.render(row, Echo) == "read_pass %{n: 1}"
    end
  end

  describe "a stored rejection" do
    test "of steps 1 to 3 keeps its id and assigns, and gives no reason" do
      {:error, rejection} = Verify.verify("{", options([]))
      {:error, echoed} = Verify.verify("{", options(messages: Echo))

      assert {rejection.message_id, rejection.assigns} ==
               {:malformed_json, %{sub_reason: :syntax}}

      assert {rejection.reason, rejection.chain, rejection.network} == {nil, nil, nil}
      assert Rejection.render(rejection, Echo) == echoed.message
      assert Rejection.to_map(rejection) == Rejection.to_map(%{rejection | assigns: %{}})

      assert Map.keys(Rejection.to_map(rejection)) == ~w(code message sub_reason)
    end

    test "built from text alone keeps its text" do
      rejection = Rejection.new(:configuration_error, "why")
      assert {rejection.message_id, rejection.reason} == {nil, nil}
      assert Rejection.render(rejection, Echo) == "why"
    end

    test "refuses a reason, chain or network it cannot carry" do
      assert %Rejection{reason: :no_source, chain: "stellar", network: "testnet"} =
               Rejection.new(:configuration_error, "m", nil,
                 reason: :no_source,
                 chain: "stellar",
                 network: "testnet"
               )

      assert_raise ArgumentError, ~r/takes no reason/, fn ->
        Rejection.new(:malformed_json, "m", :syntax, reason: :no_source)
      end

      assert_raise ArgumentError, ~r/not a reason of configuration_error/, fn ->
        Rejection.new(:configuration_error, "m", nil, reason: :elsewhere)
      end

      assert_raise ArgumentError, ~r/not a reason of configuration_error/, fn ->
        Rejection.new(:configuration_error, "m", nil, chain: "stellar")
      end

      assert_raise ArgumentError, ~r/strings or nil/, fn ->
        Rejection.new(:configuration_error, "m", nil, reason: :no_source, chain: :stellar)
      end

      assert_raise ArgumentError, ~r/strings or nil/, fn ->
        Rejection.new(:configuration_error, "m", nil, reason: :no_source, network: 1)
      end

      assert_raise ArgumentError, ~r/not options of a rejection/, fn ->
        Rejection.new(:configuration_error, "m", nil, reason: :no_source, why: 1)
      end
    end
  end

  describe "a configuration_error names the check that failed" do
    defmodule KeyringAt do
      @behaviour Truestamp.Verify.KeyringSource
      @impl true
      def fetch(location), do: {:ok, {:bytes, Signing.keyring()}, location, FakeReader.meta()}
    end

    defp forbidden_identity do
      reader =
        FakeReader.from_replay(@replay,
          overrides: %{
            {:stellar_identity, %{}} =>
              FakeReader.found(%{
                "network_passphrase" => "Public Global Stellar Network ; September 2015"
              })
          }
        )

      options(reader: reader, networks: @pins)
    end

    # Each reason, the run that gives it, and what it concerns.
    defp reasons do
      [
        {:no_keyring, fn -> Verify.verify_file(@item, environment: :test) end, nil, nil,
         %{environment: "test"}},
        {:keyring_refused,
         fn ->
           Verify.verify_file(@item, environment: :test, trust: {:keyring, "{\"keys\": 1}"})
         end, nil, nil, nil},
        {:current_keyring_location,
         fn ->
           Verify.verify(Signing.production_without_key_event("item"),
             networks: @pins,
             reader: Replay.new!(@replay),
             current_keyring: {KeyringAt, "https://keys.example.net/keyring.json"}
           )
         end, nil, nil, %{location: "https://keys.example.net/keyring.json"}},
        {:no_source,
         fn ->
           Verify.verify_file(@item, online(%{{"bitcoin", "regtest"} => {:error, :none}}))
         end, "bitcoin", "regtest", %{chain: "bitcoin", network: "regtest"}},
        {:identity_forbidden, fn -> Verify.verify_file(@item, forbidden_identity()) end,
         "stellar", "testnet", %{chain: "stellar", network: "testnet"}},
        {:invalid_policy,
         fn ->
           Verify.verify_file(
             @item,
             online(%{{"stellar", "testnet"} => {:ok, ["a", "b"], {:at_least, 3}}})
           )
         end, "stellar", "testnet", %{chain: "stellar", network: "testnet", count: 2}},
        {:nist_sources,
         fn ->
           Verify.verify_file(@item, online(%{{"nist", nil} => {:ok, ["a", "b"], :first}}))
         end, "nist", nil, %{}}
      ]
    end

    test "each reason, with its chain, its network and its message's id and assigns" do
      for {reason, run, chain, network, assigns} <- reasons() do
        assert {:error, %Rejection{code: :configuration_error} = rejection} = run.()
        assert {rejection.reason, rejection.chain, rejection.network} == {reason, chain, network}
        assert Atom.to_string(rejection.message_id) == "configuration_#{reason}"
        if assigns, do: assert(rejection.assigns == assigns)

        assert rejection.message ==
                 Messages.English.message(rejection.message_id, rejection.assigns)

        assert Rejection.render(rejection, Echo) =~ "configuration_#{reason} "
        assert Map.keys(Rejection.to_map(rejection)) == ~w(code message)
      end

      assert Enum.map(reasons(), &elem(&1, 0)) == Rejection.configuration_reasons()
    end

    test "a keyring refused names its load check in the assigns" do
      assert {:error, %Rejection{reason: :keyring_refused, assigns: %{failure: failure}}} =
               Verify.verify_file(@item, environment: :test, trust: {:keyring, "{\"keys\": 1}"})

      assert failure != nil

      assert {:error, %Rejection{reason: :keyring_refused}} =
               Verify.verify(
                 Signing.production_without_key_event("item"),
                 Config.internal!(environment: :prod, key_chain: [Keyring.vector_key()])
               )
    end
  end

  describe "every message is rendered in the calling process" do
    # A message module that reads the calling process's dictionary, as a Gettext locale is
    # read, and leaves every id to English when the value is not there.
    defmodule CallerLocale do
      @behaviour Truestamp.Verify.Messages
      @impl true
      def message(id, assigns) do
        case Process.get(:rendering_test_locale) do
          nil -> nil
          locale -> "[#{locale}] " <> Messages.English.message(id, assigns)
        end
      end
    end

    defp in_locale?(text), do: String.starts_with?(text, "[xx] ")

    # Kills the mutant that makes each step of ENVIRONMENT to EXPECTED_HASH in a task, and the
    # one that makes steps 0 to 3 in a task: under either, the rows or the rejection that
    # step renders are in English.
    test "in an online run with identity reads and a deadline, and in apply_expected_hash/2" do
      Process.put(:rendering_test_locale, "xx")

      for extra <- [[], [deadline: 30_000]] do
        run = online(%{}) ++ [messages: CallerLocale] ++ extra
        {:ok, report} = Verify.verify_file(@item, run)
        assert report.trust_root.kind == :supplied_keyring
        assert Enum.any?(report.rows, &(&1.step == :chain and &1.status == :pass))
        assert Enum.all?(report.rows, &in_locale?(&1.message)), inspect(extra)

        applied = Verify.apply_expected_hash(report, "00")

        assert %Row{step: :expected_hash, message_id: :expected_hash_not_hex} =
                 List.last(applied.rows)

        assert Enum.all?(applied.rows, &in_locale?(&1.message)), inspect(extra)

        forbidden = Keyword.merge(forbidden_identity(), [messages: CallerLocale] ++ extra)

        assert {:error, %Rejection{reason: :identity_forbidden} = rejection} =
                 Verify.verify_file(@item, forbidden)

        assert in_locale?(rejection.message), inspect(extra)
      end
    end
  end
end
