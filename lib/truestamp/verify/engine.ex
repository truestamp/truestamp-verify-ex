# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Engine do
  @moduledoc false
  # The steps of SPEC.md section 10.2, in order, one module per step (the table is in
  # `Truestamp.Verify`'s moduledoc), and fault capture.
  #
  # Faults (sections 10.5 and 12.2). A fault the verifier catches from ENVIRONMENT on is a
  # `fail` row with the code `internal_error`, never a pass or a skip: each of steps 4 to 13
  # runs guarded, and when one raises, throws or exits, the run as it stood before that step
  # gets one `internal_error` row of that step, part null, and ends as a failure at the gate
  # does. A fault at ENVIRONMENT, KEY_BINDING or SIGNATURE is a failure of that step, so the
  # attribution is `none`. The row's `values` hold only the fault's `kind` and, for an error,
  # the `module` of its exception, so no value the proof carries reaches the report. A fault
  # caught before steps 0 to 3 passed has no report to hold its row (`Truestamp.Verify.Fault`).
  # VERDICT is not guarded: a fault there gives no report either.

  alias Truestamp.Verify.{Config, Fault, JSON, ReadError, Rejection, Row, Run, Step}
  alias Truestamp.Verify.Steps

  @typedoc "The input of a run: a document's bytes, or a file read after CONFIGURATION."
  @type input :: {:bytes, binary()} | {:file, Path.t()}

  @typedoc "What a run gives."
  @type result ::
          {:ok, Run.t()}
          | {:rejected, Rejection.t()}
          | {:error, ReadError.t()}
          | {:fault, Fault.t()}

  # The steps whose failure gives the attribution `none` (section 10.5).
  @gate_steps [:environment, :key_binding, :signature]

  @doc "Steps 4 to 13, each in section 10.2's order, as `{step, function}`."
  @spec steps() :: [{Step.t(), (Run.t() -> Run.t())}]
  def steps do
    [
      environment: &Steps.Environment.environment/1,
      key_binding: &Steps.KeyBinding.key_binding/1,
      signature: &Steps.Signature.signature/1,
      shape: &Steps.Shape.shape/1,
      policy: &Steps.Policy.policy/1,
      derive: &Steps.Derive.derive/1,
      chain: &Steps.Chain.chain/1,
      sources: &Steps.Sources.sources/1,
      window: &Steps.Window.window/1,
      expected_hash: &Steps.ExpectedHash.expected_hash/1
    ]
  end

  @doc """
  The steps over `input` under `config`. With `until: step`, the run stops after `step`, one
  of steps 4 to 13, with no later row and no label: a run cut short, for a test or a tool.
  """
  @spec run(Config.t(), input(), keyword()) :: result()
  def run(%Config{} = config, input, options \\ []) do
    case admitted(fn -> admit(config, input) end) do
      {:ok, run} -> {:ok, after_admission(run, Keyword.get(options, :until))}
      other -> other
    end
  end

  # Steps 0 to 3.
  defp admit(config, input) do
    with {:ok, run} <- Steps.Configuration.configuration(config),
         {:ok, bytes} <- bytes(run, input),
         do: Steps.Input.admit(run, bytes)
  end

  defp bytes(_run, {:bytes, bytes}) when is_binary(bytes), do: {:ok, bytes}

  # The file is read only after CONFIGURATION, at most MAX_READ_OCTETS + 1 octets of it.
  defp bytes(run, {:file, path}) do
    case JSON.read_file(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, :input_too_large} -> {:rejected, Steps.Input.input_too_large(run)}
      {:error, {:unreadable, reason}} -> {:error, ReadError.new(path, reason)}
    end
  end

  defp admitted(admit) do
    admit.()
  catch
    kind, reason -> {:fault, Fault.new(kind, reason, __STACKTRACE__)}
  end

  defp after_admission(run, nil),
    do: steps() |> Enum.reduce(run, &step/2) |> Steps.Verdict.verdict()

  defp after_admission(run, until) do
    unless Keyword.has_key?(steps(), until),
      do: raise(ArgumentError, "until: #{inspect(until)} is not a step 4 to 13")

    steps()
    |> Enum.take_while(fn {name, _function} -> name != until end)
    |> Kernel.++([{until, Keyword.fetch!(steps(), until)}])
    |> Enum.reduce(run, &step/2)
  end

  @doc """
  Makes `step` by `function` on `run`, catching a fault: when `function` raises, throws or
  exits, the result is `run` with one `internal_error` row of `step`, part null, and the run
  ended. A run that has already ended passes through unchanged.
  """
  @spec step({Step.t(), (Run.t() -> Run.t())}, Run.t()) :: Run.t()
  def step(_step, %Run{ended: true} = run), do: run

  def step({name, function}, %Run{} = run) do
    function.(run)
  catch
    kind, reason -> fault(run, name, kind, fault_module(kind, reason, __STACKTRACE__))
  end

  defp fault(run, name, kind, module) do
    message = Run.text(run, :internal_error, %{step: Step.name(name), kind: kind, module: module})
    values = %{"kind" => Atom.to_string(kind), "module" => module}
    row = Row.new(name, :internal_error, nil, message, values)
    run = if name in @gate_steps, do: %{run | attribution: "none"}, else: run
    run |> Run.add_row(row) |> Run.end_run()
  end

  # The module of an error's exception, never its message or the terms it holds, which can
  # be values of the proof; a throw or an exit has none.
  defp fault_module(:error, reason, stacktrace),
    do: inspect(Exception.normalize(:error, reason, stacktrace).__struct__)

  defp fault_module(_kind, _reason, _stacktrace), do: nil
end
