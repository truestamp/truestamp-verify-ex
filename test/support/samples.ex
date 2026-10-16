# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.Samples do
  @moduledoc """
  Envelopes that satisfy SPEC.md part 1's layouts, for testing the files under `spec/`: one
  of every type, and variants that put every kind of key event at every block position. Their
  hashes and signatures are well-formed but not computed, so they exercise the shapes only.
  """

  @doc "Every sample, by name."
  @spec all() :: %{String.t() => map()}
  def all do
    base()
    |> Map.merge(block_variants())
    |> Map.merge(limit_variants())
  end

  @doc "One sample of each type, between them holding every kind of key event."
  @spec base() :: %{String.t() => map()}
  def base do
    %{
      "item" => item(),
      "entropy_nist" => entropy("nist"),
      "entropy_stellar" => entropy("stellar"),
      "entropy_bitcoin" => entropy("bitcoin"),
      "block" => block_proof(),
      "beacon" => beacon(),
      "beacon_empty" => beacon_empty()
    }
  end

  # The other environments, and values at the length limits of their classes.
  defp limit_variants do
    reason = ["proof", "signing_key_event", "block", "record", "metadata", "key_event", "reason"]
    version = ["proof", "witnesses", "entropy_nist", "payload", "pulse", "version"]

    %{
      "entropy_nist in dev" => put_in(entropy("nist"), ["proof", "environment"], "dev"),
      "entropy_stellar in test" => put_in(entropy("stellar"), ["proof", "environment"], "test"),
      "item with a 128-character reason" => put_in(item(), reason, String.duplicate("r", 128)),
      "item with a 16-character NIST version" =>
        put_in(item(), version, String.duplicate("v", 16)),
      "item with a one-leaf inclusion proof" =>
        put_in(item(), ["proof", "subject", "inclusion_proof"], %{
          "leaf_index" => 0,
          "path" => [],
          "tree_size" => 1
        })
    }
  end

  # A block node of each kind at /block and /witnesses/block, and of each kind a signing key
  # event may introduce at /signing_key_event/block, each inside an item proof.
  defp block_variants do
    kinds = ~w(plain genesis rotation emergency_rotation prerotation revocation)

    at_block =
      for kind <- kinds,
          pos <- [["proof", "block"], ["proof", "witnesses", "block"]],
          into: %{} do
        {"item #{kind} at /#{Enum.join(tl(pos), "/")}", put_in(item(), pos, block(kind, 7))}
      end

    at_key_event =
      for kind <- ~w(genesis rotation emergency_rotation), into: %{} do
        pos = ["proof", "signing_key_event", "block"]
        {"item #{kind} at /signing_key_event/block", put_in(item(), pos, block(kind, 8))}
      end

    Map.merge(at_block, at_key_event)
  end

  @doc "A hex SHA-256 of `seed`, a stand-in for any HEX64 value."
  @spec hex64(String.t()) :: String.t()
  def hex64(seed), do: Base.encode16(:crypto.hash(:sha256, seed), case: :lower)

  defp kid(seed), do: binary_part(hex64(seed), 0, 8)
  defp b64u(bytes), do: Base.url_encode64(bytes, padding: false)
  defp key(seed), do: b64u(:crypto.hash(:sha256, seed))
  defp sig(seed), do: b64u(:crypto.hash(:sha512, seed))

  defp uuid7(n),
    do: "01920000-0000-7000-8000-" <> String.pad_leading(Integer.to_string(n), 12, "0")

  defp proof_path(index, size, nodes),
    do: %{
      "leaf_index" => index,
      "path" => Enum.map(1..nodes//1, &hex64("node #{&1}")),
      "tree_size" => size
    }

  defp key_event("genesis") do
    %{
      "key_id" => kid("k1"),
      "prerotation_commitment" => hex64("next k2"),
      "public_key" => key("k1"),
      "sequence" => 0,
      "type" => "genesis"
    }
  end

  defp key_event("rotation") do
    %{
      "handover_signature" => sig("handover k2"),
      "key_id" => kid("k2"),
      "prerotation_commitment" => hex64("next k3"),
      "previous_key_id" => kid("k1"),
      "previous_public_key" => key("k1"),
      "public_key" => key("k2"),
      "reason" => "scheduled rotation",
      "sequence" => 1,
      "type" => "rotation"
    }
  end

  defp key_event("emergency_rotation") do
    %{
      "key_id" => kid("k3"),
      "previous_key_id" => kid("k2"),
      "previous_public_key" => key("k2"),
      "public_key" => key("k3"),
      "reason" => "key lost",
      "sequence" => 2,
      "type" => "emergency_rotation"
    }
  end

  defp key_event("prerotation"),
    do: %{
      "active_key_id" => kid("k3"),
      "prerotation_commitment" => hex64("next k4"),
      "type" => "prerotation"
    }

  defp key_event("revocation"), do: %{"revoked_key_id" => kid("k0"), "type" => "revocation"}

  defp metadata("plain"), do: %{}

  defp metadata("genesis") do
    %{
      "genesis" => %{
        "bitcoin" => %{
          "header_hash" => hex64("genesis header"),
          "height" => 900_000,
          "network" => "mainnet"
        }
      },
      "key_event" => key_event("genesis")
    }
  end

  defp metadata(kind), do: %{"key_event" => key_event(kind)}

  defp block(kind, n) do
    # A genesis or key-event block includes nothing, so its tree is empty (SPEC.md 5.4).
    {leaf_count, merkle_root} =
      if kind == "plain",
        do: {8, hex64("root #{n}")},
        else: {0, Base.encode16(:crypto.hash(:sha256, ""), case: :lower)}

    record = %{
      "height" => if(kind == "genesis", do: 0, else: 525_600 + n),
      "id" => uuid7(n),
      "leaf_count" => leaf_count,
      "merkle_root" => merkle_root,
      "metadata" => metadata(kind),
      "previous_block_hash" => hex64("previous #{n}"),
      "signing_key_id" => kid("k1")
    }

    %{"block_hash" => hex64("block #{n}"), "record" => bind_position(record)}
  end

  # A rotation event carries the height and previous_block_hash of its block (SPEC.md 3.3).
  defp bind_position(%{"metadata" => %{"key_event" => %{"type" => type}}} = record)
       when type in ~w(rotation emergency_rotation) do
    update_in(
      record,
      ["metadata", "key_event"],
      &Map.merge(&1, Map.take(record, ~w(height previous_block_hash)))
    )
  end

  defp bind_position(record), do: record

  defp epoch(n) do
    %{
      "epoch_hash" => hex64("epoch #{n}"),
      "record" => %{"leaf_count" => 64, "merkle_root" => hex64("epoch root #{n}")}
    }
  end

  defp bitcoin_commitment(n) do
    %{
      "epoch" => epoch(n),
      "header_hash" => hex64("header #{n}"),
      "header_merkle_root" => hex64("header root #{n}"),
      "header_time" => "2026-09-25T12:00:00Z",
      "height" => 968_496,
      "inclusion_proof" => proof_path(33, 64, 6),
      "network" => "mainnet",
      "raw_transaction" => String.duplicate("ab", 137),
      "transaction_hash" => hex64("transaction #{n}"),
      "txoutproof" => String.duplicate("cd", 506)
    }
  end

  defp stellar_commitment(n) do
    %{
      "epoch" => epoch(n + 100),
      "inclusion_proof" => proof_path(9, 16, 4),
      "ledger" => 12_345_678,
      "network" => "public",
      "transaction_hash" => hex64("stellar transaction #{n}")
    }
  end

  defp entropy_object("nist") do
    pulse = %{
      "chainIndex" => 1,
      "outputValue" => String.duplicate("A1", 64),
      "pulseIndex" => 1_234_567,
      "timeStamp" => "2026-09-25T12:00:00.000Z",
      "version" => "2.0"
    }

    %{"payload" => %{"pulse" => pulse}, "source" => "nist"}
  end

  defp entropy_object("stellar") do
    payload = %{
      "closed_at" => "2026-09-25T11:59:55Z",
      "hash" => hex64("ledger"),
      "sequence" => 12_345_600
    }

    %{"network" => "public", "payload" => payload, "source" => "stellar"}
  end

  defp entropy_object("bitcoin") do
    payload = %{"hash" => hex64("bitcoin block"), "height" => 968_400, "time" => 1_790_309_788}
    %{"network" => "mainnet", "payload" => payload, "source" => "bitcoin"}
  end

  defp observation(source) do
    %{
      "entropy" => entropy_object(source),
      "inclusion_proof" => proof_path(5, 8, 3),
      "observation_hash" => hex64("observation #{source}"),
      "record" => %{"entropy_hash" => hex64("entropy #{source}"), "id" => uuid7(40)}
    }
  end

  defp envelope(proof) do
    signature = %{
      "alg" => "truestamp-ed25519-sha256-jcs",
      "public_key" => key("k1"),
      "value" => sig("proof")
    }

    %{"proof" => proof, "signature" => signature}
  end

  defp common(type, block_kind) do
    %{
      "block" => block(block_kind, 1),
      "commitments" => %{"bitcoin" => bitcoin_commitment(1), "stellar" => stellar_commitment(1)},
      "format" => "truestamp-proof",
      "type" => type,
      "version" => 1
    }
  end

  defp item do
    witness_hashes = %{
      "block" => hex64("witness block"),
      "entropy_bitcoin" => hex64("witness bitcoin"),
      "entropy_nist" => hex64("witness nist"),
      "entropy_stellar" => hex64("witness stellar")
    }

    subject = %{
      "claims" => %{
        "hash" => hex64("claims"),
        "hash_type" => "sha256",
        "location" => [37.7749, 1.0e-7, nil]
      },
      "inclusion_proof" => proof_path(5, 8, 3),
      "item_hash" => hex64("item"),
      "record" => %{
        "claims_hash" => hex64("claims hash"),
        "id" => uuid7(30),
        "witness_hashes" => witness_hashes
      }
    }

    witnesses = %{
      "block" => block("plain", 3),
      "entropy_bitcoin" => entropy_object("bitcoin"),
      "entropy_nist" => entropy_object("nist"),
      "entropy_stellar" => entropy_object("stellar")
    }

    "item"
    |> common("plain")
    |> Map.merge(%{
      "constructions" => %{"block_hash" => "SHA-256(0x31 || JCS(record))"},
      "signing_key_event" => %{
        "block" => block("rotation", 2),
        "commitments" => %{"stellar" => stellar_commitment(2)}
      },
      "subject" => subject,
      "witnesses" => witnesses
    })
    |> envelope()
  end

  defp entropy(source) do
    url = "https://www.truestamp.com/.well-known/constructions-" <> hex64("text") <> ".json"

    "entropy_#{source}"
    |> common("prerotation")
    |> Map.merge(%{
      "constructions" => url,
      "environment" => "staging",
      "subject" => observation(source)
    })
    |> envelope()
  end

  defp block_proof do
    "block"
    |> common("genesis")
    |> Map.put("signing_key_event", %{
      "block" => block("genesis", 4),
      "commitments" => %{"bitcoin" => bitcoin_commitment(4)}
    })
    |> envelope()
  end

  defp beacon do
    observations = Map.new(~w(bitcoin nist stellar), &{"entropy_#{&1}", observation(&1)})

    "beacon"
    |> common("revocation")
    |> Map.merge(%{
      "observations" => observations,
      "signing_key_event" => %{
        "block" => block("emergency_rotation", 5),
        "commitments" => %{"stellar" => stellar_commitment(5)}
      }
    })
    |> envelope()
  end

  defp beacon_empty,
    do: "beacon" |> common("emergency_rotation") |> Map.put("observations", %{}) |> envelope()
end
