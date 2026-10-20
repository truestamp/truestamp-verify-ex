# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify do
  @moduledoc """
  Verifies Truestamp proofs, as the Truestamp proof specification (SPEC.md, in the
  truestamp-verification repository) defines them: every check of its section 10, offline
  and online, and the submission window of its section 11.

  A Truestamp proof is one JSON document, signed by Truestamp, that ties a subject to
  Truestamp's chain of blocks and to commitments on public blockchains. A run establishes
  whether the proof is intact and who signed it, and, when it reads public chains and
  entropy sources, places the subject's submission in a submission window. It never
  establishes when the data was created, who wrote it, or that any claim in it is true.

  ## Verifying

      # Offline, in production, against the keys built into this library: the label is
      # :internally_consistent for a sound proof signed by one of them. The compiled pin
      # holds no key yet, so today a production proof fails KEY_BINDING offline.
      {:ok, report} = Truestamp.Verify.verify(proof_bytes)
      report.label

      # A test vector: its environment, and the keyring of its keys.
      {:ok, report} =
        Truestamp.Verify.verify_file("vectors/positive/item.proof.json",
          environment: :test,
          trust: {:keyring_file, "vectors/keyring.test.json"}
        )

      # Online, reading Stellar, Bitcoin and NIST, and the keyring Truestamp publishes.
      {:ok, report} = Truestamp.Verify.verify(proof_bytes, Truestamp.Verify.Online.defaults())
      report.submitted_before

  `verify/2` takes the options of `Truestamp.Verify.Config.external/1`, or a
  `Truestamp.Verify.Config` built with `Truestamp.Verify.Config.external/1` or, for
  Truestamp's own verifier, `Truestamp.Verify.Config.internal/1`. It gives:

  | Result | When |
  |---|---|
  | `{:ok, %Truestamp.Verify.Report{}}` | steps 0 to 3 passed, so there is a report, whatever its label |
  | `{:error, %Truestamp.Verify.Rejection{}}` | a bare rejection at steps 0 to 3, `configuration_error` included |
  | `{:error, %Truestamp.Verify.ReadError{}}` | a file that cannot be read at all |
  | `{:error, %Truestamp.Verify.Fault{}}` | a fault that leaves no report: before steps 0 to 3 passed, at VERDICT, or while the report is written |

  A report labelled `:failed` is still `{:ok, report}`: the run worked, and its rows say
  which check failed. Only `:verified` says that Truestamp signed the proof and that its
  submission window is established. `Truestamp.Verify.ExitCode` gives the exit code of
  section 12.2 for any result.

  ## The steps

  | Step | Module |
  |---|---|
  | 0 CONFIGURATION | `Truestamp.Verify.Steps.Configuration` |
  | 1 to 3 READ, PARSE, ENVELOPE | `Truestamp.Verify.Steps.Input` |
  | 4 ENVIRONMENT | `Truestamp.Verify.Steps.Environment` |
  | 5 KEY_BINDING | `Truestamp.Verify.Steps.KeyBinding` |
  | 6 SIGNATURE | `Truestamp.Verify.Steps.Signature` |
  | 7 SHAPE | `Truestamp.Verify.Steps.Shape` |
  | 8 POLICY | `Truestamp.Verify.Steps.Policy` |
  | 9 DERIVE | `Truestamp.Verify.Steps.Derive` |
  | 10 CHAIN | `Truestamp.Verify.Steps.Chain` |
  | 11 SOURCES | `Truestamp.Verify.Steps.Sources` |
  | 12 WINDOW | `Truestamp.Verify.Steps.Window` |
  | 13 EXPECTED_HASH | `Truestamp.Verify.Steps.ExpectedHash` |
  | 14 VERDICT | `Truestamp.Verify.Steps.Verdict` |

  Each chain and entropy source the specification defines lives in a module of its own
  (`Truestamp.Verify.Chains`), and every read goes through a `Truestamp.Verify.Reader` the
  caller gives, so the engine holds no transport and no branch for any one chain.
  """

  alias Truestamp.Verify.{Config, Engine, Fault, ReadError, Rejection, Report, Row, Run}
  alias Truestamp.Verify.Steps.ExpectedHash

  @typedoc "What a verification gives."
  @type result :: {:ok, Report.t()} | {:error, Rejection.t() | ReadError.t() | Fault.t()}

  @typedoc """
  The options of `Truestamp.Verify.Config.external/1`, plus `:until`, a step from
  `:environment` to `:expected_hash` after which the run stops, for a test or a tool that
  cuts a run short; or a configuration.
  """
  @type options :: keyword() | Config.t()

  @doc """
  Verifies the proof whose bytes are `bytes`. Raises `ArgumentError` for an option that is
  unknown, given twice, or holds a value it cannot take.
  """
  @spec verify(binary(), options()) :: result()
  def verify(bytes, options \\ []) when is_binary(bytes), do: run({:bytes, bytes}, options)

  @doc """
  Verifies the proof in the file at `path`, which is read only after step 0 has fixed the
  configuration, at most MAX_READ_OCTETS + 1 octets of it. Options as `verify/2`.
  """
  @spec verify_file(Path.t(), options()) :: result()
  def verify_file(path, options \\ []) when is_binary(path), do: run({:file, path}, options)

  @doc "As `verify/2`, but gives the report itself, and raises the error of any other result."
  @spec verify!(binary(), options()) :: Report.t()
  def verify!(bytes, options \\ []), do: bang(verify(bytes, options))

  @doc "As `verify_file/2`, but gives the report itself, and raises the error of any other result."
  @spec verify_file!(Path.t(), options()) :: Report.t()
  def verify_file!(path, options \\ []), do: bang(verify_file(path, options))

  @doc "Whether `report`'s label is `:verified`."
  @spec verified?(Report.t()) :: boolean()
  defdelegate verified?(report), to: Report

  @doc """
  The report a fresh run would give with the caller's hash `expected_hash` (step 13 of
  SPEC.md section 10.2), from a finished report, without making its reads again: its
  EXPECTED_HASH row, its label, its run's code and its edges all follow the step order, as
  the specification requires of a verifier that runs this step on a finished report.
  `expected_hash` nil removes the comparison.

  The step runs guarded, as in a run: a fault in it, one in the report's message module
  among them, is an `internal_error` row of EXPECTED_HASH, as a fresh run gives; and when
  the report's own EXPECTED_HASH faulted, that row is dropped and the step made again, so
  the report is the one a fresh run with `expected_hash` gives. Raises
  `ArgumentError` for a report cut short with `:until`, and `Truestamp.Verify.Fault` for a
  fault at VERDICT or while the report is written, which no report `verify/2` gave causes.
  """
  @spec apply_expected_hash(Report.t(), String.t() | nil) :: Report.t()
  def apply_expected_hash(%Report{__run__: %{label: label} = run}, expected_hash)
      when label != nil and (is_nil(expected_hash) or is_binary(expected_hash)) do
    run = before_expected_hash(%{run | config: %{run.config | expected_hash: expected_hash}})
    run = Engine.step({:expected_hash, &ExpectedHash.expected_hash/1}, run)

    case Engine.conclude(run) do
      {:ok, report} -> report
      {:fault, fault} -> raise fault
    end
  end

  def apply_expected_hash(%Report{}, _expected_hash),
    do: raise(ArgumentError, "a report cut short with :until has no EXPECTED_HASH step to apply")

  # The run as it stood before EXPECTED_HASH: with no EXPECTED_HASH row, and, when the run's
  # own EXPECTED_HASH faulted, not ended, since that fault ended it; a run ended before
  # EXPECTED_HASH keeps its `skip prior_failure` row there.
  defp before_expected_hash(%Run{ended: false, rows: rows} = run),
    do: %{run | rows: Enum.reject(rows, &(&1.step == :expected_hash))}

  defp before_expected_hash(%Run{rows: rows} = run) do
    case List.last(rows) do
      %Row{step: :expected_hash, code: :internal_error} ->
        %{run | rows: Enum.drop(rows, -1), ended: false}

      _skip_prior_failure ->
        run
    end
  end

  defp run(input, %Config{} = config), do: config |> Engine.run(input) |> result()

  defp run(input, options) when is_list(options) do
    {until, options} = Keyword.pop(options, :until)
    config = Config.external!(options)
    config |> Engine.run(input, until: until) |> result()
  end

  defp result({:ok, %Report{} = report}), do: {:ok, report}
  defp result({:rejected, %Rejection{} = rejection}), do: {:error, rejection}
  defp result({:error, %ReadError{} = error}), do: {:error, error}
  defp result({:fault, %Fault{} = fault}), do: {:error, fault}

  defp bang({:ok, report}), do: report
  defp bang({:error, exception}), do: raise(exception)
end
