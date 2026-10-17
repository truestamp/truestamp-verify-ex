<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Reading the chains

Offline, a run checks everything the proof carries but cannot place the proof in time: no
timestamp the proof carries is an edge of its submission window (SPEC.md section 11). An
online run reads the public chains and entropy sources the proof names: step 10, CHAIN,
confirms each commitment entry on its pinned network, step 11, SOURCES, confirms each
entropy object at its source, and step 12, WINDOW, draws the window from instants those
reads gave.

## The reader

Every read goes through a `Truestamp.Verify.Reader`, given with the `:reader` option. The
engine owns every judgement: it checks each field of each answer, refuses a cached answer
where the spec requires a live read, keeps one answer per read for the whole run, and turns
a reader that crashes into an unreachable read. A reader only fetches.

The reads are named as the replay files of section 13.2 name them, so a reader can be
anything that can answer them: the bundled HTTP sources, a cache in front of them, an
indexer of your own, or a replay file.

## The bundled HTTP sources

With Req in your dependencies, `Truestamp.Verify.Online.defaults/1` gives a reader of public
servers and the keyring Truestamp publishes:

```elixir
Truestamp.Verify.verify(proof_bytes, Truestamp.Verify.Online.defaults())
```

`Truestamp.Verify.Readers.HTTP` reads each network through a `Truestamp.Verify.Source`:

| Source | Serves |
|---|---|
| `Truestamp.Verify.Sources.Horizon` | Stellar |
| `Truestamp.Verify.Sources.Esplora` | Bitcoin, through any Esplora API: Blockstream, mempool.space (presets for mainnet, testnet, testnet4 and signet), or your own |
| `Truestamp.Verify.Sources.BitcoinCore` | Bitcoin, through a node's JSON-RPC |
| `Truestamp.Verify.Sources.NistBeacon` | NIST's Randomness Beacon |

Choose sources per network with `:sources`, in the form `Readers.HTTP.new/1` takes; each
replaces the default of its own network only:

```elixir
alias Truestamp.Verify.Sources

Truestamp.Verify.Online.defaults(
  sources: [bitcoin: %{"mainnet" => {Sources.Esplora, preset: :mempool}}]
)
```

## Production by default, test networks by choice

A run's environment chooses the networks it reads, through the network pins of
`spec/network-pins.json` (section 9). A run under `:prod` reads Stellar `public` and Bitcoin
`mainnet`, and nothing else. A run under `:test` pins test networks, and the `:networks`
option replaces any pin of any run. A source for a test network is used only by a run that
pins that network, so listing one never sends a production run to it. Under `:test`,
which pins Bitcoin `regtest`, a run reads your own node:

```elixir
Truestamp.Verify.verify(proof_bytes,
  environment: :test,
  trust: {:keyring_file, "keyring.test.json"},
  reader:
    Truestamp.Verify.Readers.HTTP.default(
      bitcoin: %{
        "regtest" =>
          {Truestamp.Verify.Sources.BitcoinCore,
           base_url: "http://127.0.0.1:18443", user: "rpc", password: "rpc"}
      }
    )
)
```

Every source of a Stellar or Bitcoin network has its identity read at step 0: a source on
another network than the one it is listed for makes the run a `configuration_error`, before
any read of the proof. An online run that pins a network the reader has no source for is a
`configuration_error` too.

## Several sources for one network

A network can have several sources under a policy, so that no single server decides a row:

```elixir
bitcoin: %{
  "mainnet" =>
    {:all,
     [
       {Sources.Esplora, preset: :mempool},
       {Sources.Esplora, preset: :blockstream}
     ]}
}
```

| Policy | A row passes when |
|---|---|
| `:first` | the first source to give a conclusive outcome passes |
| `{:at_least, n}` | at least n sources pass alike, and none conflicts |
| `:all` | every source passes alike |

Sources are combined per row, not per read, so explorers that lag one another, with a tip
a block behind or a shorter history, do not count as disagreeing. A row whose sources pass
and fail, or pass with different instants, is `skip sources_disagree`; a row whose sources
do not all answer, so the policy cannot be met, is `skip sources_incomplete`. Neither is a
failure. Under `:all`, a faulty or hostile source beside honest ones can keep a row from
passing but cannot fail it; under `{:at_least, n}`, it takes n sources failing alike to
fail a row; and under `:first`, the first conclusive source decides alone, so list the one
you trust most first. `Truestamp.Verify.Online.Policy` gives the rules in full.

Only Stellar and Bitcoin networks take several sources; NIST's Randomness Beacon is one
(SPEC.md section 9). A policy `{:at_least, n}` takes n from 1 to the number of the
network's sources. Either mistake makes the run a `configuration_error` at step 0, before
the proof is read, and so does a source whose identity read shows another network,
whatever the network's other sources show.

Every CHAIN and SOURCES row of an online run says what it read (section 10.4), in its
`values`: the network's `policy` and `required`, the n it asks for, and in `outcomes` one
object for each source the row asked, with that source's status, code, candidate and every
read made of it. An edge drawn from several sources names each of them in `sources`, and
the command's summary says which it was read from.

## Deadlines and caching

`:deadline` caps the whole online run in milliseconds; a read past it is unreachable, and
its row says so. Each source takes `:receive_timeout` and `:req_options` for its own
transport. A reader may answer from a cache, and each answer says whether it was cached and
when it was fetched, but the engine refuses a cached answer to the reads that must be live:
identity, the Stellar root, the Bitcoin tip, and every not-found answer (section 10.4). It
refuses a cached best-chain Bitcoin block at a height too: the spec allows one only when it
was read while the source's tip was at least that height plus BITCOIN_FINALITY, and no
answer says what the tip was. A Bitcoin time that no TIME can write, past the year 9999, is
an unusable answer, so its row is `skip source_unreachable`.

## Replay files

`Truestamp.Verify.Readers.Replay` answers every read from a replay file of section 13.2:
answers recorded once, played back so a run reads no network and gives the same rows each
time. The online conformance cases run this way, and so does the walkthrough's online
section. It is also the simplest way to test code that verifies online.
