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
engine owns every judgement: it judges each answer on the fields its rule reads at that
point (SPEC.md section 10.4), refuses a cached answer where the spec requires a live read,
keeps one answer per read for the whole run, and turns a reader that crashes into an
unreachable read. A reader only fetches.

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
identity, the Stellar root, the Bitcoin tip, and every not-found answer (section 10.4). A
cached best-chain Bitcoin block at a height g stands only when its meta also carries
`tip_height`, the source's tip when the block was read, of at least g + 10
(BITCOIN_FINALITY); with no tip, or a shorter one, it is refused, so a cache in front of a
Bitcoin source keeps the tip it read each block under (`Truestamp.Verify.Reader`,
"Caches"). The bundled readers cache nothing. A Bitcoin time that no TIME can write, past
the year 9999, is an unusable answer, so its row is `skip source_unreachable`.

## One entry, outside a run

A service that stores commitments, or checks them before it signs, can judge one entry
against one source with the library's own rules, without a proof. It writes a
`Truestamp.Verify.Reader`, the same one a run takes, and judges nothing itself:

```elixir
alias Truestamp.Verify.Chains
alias Truestamp.Verify.Online.Rule

reader = {MyApp.ChainReader, state}

case Rule.confirm_identity(reader, chain: "stellar", source: :horizon, network: "public") do
  :ok ->
    context =
      Rule.new(reader,
        source: :horizon,
        network: "public",
        part: "/commitments/stellar",
        top_level?: true,
        deadline: 10_000
      )

    Chains.Stellar.commitment(context, entry)

  {:unreachable, reason} ->
    Rule.unconfirmed(reason)

  :forbidden ->
    {:error, :another_network}
end
```

`Truestamp.Verify.Online.Rule.confirm_identity/2` is step 0's identity read for one
source: `:ok`, `:forbidden` for a source on another network, or `{:unreachable, reason}`,
for which `Truestamp.Verify.Online.Rule.unconfirmed/1` gives the outcome a run gives each
of that source's entries, `skip source_unreachable`. Judge no entry with a source that is
forbidden or unconfirmed. Confirm once per chain and network, before the first entry; how
long to trust that answer is yours to choose. The network is one the specification names
for the chain, such as `"public"`, and anything else raises.
`Truestamp.Verify.Online.Rule.new/2` binds a context to the reader, a source and a network,
with every read rule of a run: answers normalized, the cache rules above, the deadline, and
a reader that raises, throws or exits turned into an unreachable read. With no `:deadline`
each read runs in the calling process, and with one in a task whose `$callers` holds the
caller (`Truestamp.Verify.Reader`, "Processes").

A run reaches a rule only after SHAPE and DERIVE pass. A rule computes offline only the
values its reads are compared with: Stellar's computes the epoch hash from `epoch.record`,
and Bitcoin's parses the `txoutproof`, refusing one that is not well formed, for its header
and `total_txs`. So make DERIVE's other checks of the value first:

- for a Bitcoin commitment entry, require every check of
  `c:Truestamp.Verify.CommitmentChain.evidence_checks/2` of `Truestamp.Verify.Chains.Bitcoin`
  to pass before `commitment/2`. The rule compares the best-chain block at the entry's
  height with the hash of the header inside the entry's `txoutproof` and with that
  `txoutproof`'s `total_txs` (SPEC.md section 10.4), and nothing more: it reads neither the
  `header_hash` the entry carries nor its `raw_transaction`, so alone it passes an entry
  whose transaction commits another epoch, or none;
- a Stellar commitment entry needs no such step: its rule computes the epoch hash from
  `epoch.record` and compares the memo with it;
- for an entropy object, recompute its `entropy_hash` as DERIVE does,
  `Truestamp.Verify.Hash.hash_hex(:entropy_hash, object)`, and compare it with the
  `entropy_hash` that names the object; SOURCES reads only an object whose hash matched.

```elixir
alias Truestamp.Verify.Check

Enum.all?(
  Chains.Bitcoin.evidence_checks(["commitments", "bitcoin"], entry),
  &match?(%Check{outcome: :pass}, &1)
)
```

For a value that passes them, the rule gives a `Truestamp.Verify.Online.Rule.Outcome`: the
status, the code and the candidate a run gives that source for that entry, and every read
made, in `values`. The rules are `commitment/2` of `Truestamp.Verify.Chains.Stellar` and
`Truestamp.Verify.Chains.Bitcoin` for a commitment entry (`top_level?: false` for one under
`signing_key_event`), `genesis/2` of `Truestamp.Verify.Chains.Bitcoin` for `genesis.bitcoin`
(`top_level?: false`), and `entropy/2` of each source for an entropy object (`network: nil`
for NIST).

## Replay files

`Truestamp.Verify.Readers.Replay` answers every read from a replay file of section 13.2:
answers recorded once, played back so a run reads no network and gives the same rows each
time. The online conformance cases run this way, and so does the walkthrough's online
section. It is also the simplest way to test code that verifies online.
