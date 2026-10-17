<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Writing a source or a reader

The library reads public chains through contracts, so you can swap in your own servers
without touching the engine. Pick the smallest contract that fits:

| To | Implement |
|---|---|
| read a chain from another kind of server, beside the bundled ones | `Truestamp.Verify.Source`, used through `Truestamp.Verify.Readers.HTTP` |
| answer reads from anything else: a cache, a database, a queue | `Truestamp.Verify.Reader` |
| read a keyring over another channel, as a supplied keyring | `Truestamp.Verify.KeyringSource` |

## A source

A source answers some of the read kinds of `Truestamp.Verify.Reader`'s table for one chain.
It maps its server's answer onto the fields of the read kind and judges nothing: the engine
checks every field's class and compares it with the proof.

```elixir
defmodule MyApp.BitcoinIndexer do
  @behaviour Truestamp.Verify.Source

  @impl true
  def kinds, do: [:bitcoin_identity, :bitcoin_tip, :bitcoin_block_at_height, :bitcoin_block]

  @impl true
  def describe(options), do: "my-indexer #{options[:base_url]}"

  @impl true
  def read(options, :bitcoin_tip, _params) do
    case MyApp.Indexer.tip(options[:base_url]) do
      {:ok, height} -> {:ok, %{"height" => height}, meta(options)}
      {:error, reason} -> {:error, reason}
    end
  end

  # ... one clause for each other kind ...

  defp meta(options),
    do: %{source: describe(options), fetched_at: DateTime.utc_now(), cached: false}
end
```

Each read gives one of three shapes:

- `{:ok, fields, meta}`: the server holds the object, with the fields the read kind names;
- `{:error, :not_found, meta}`: the server answered that it holds no such object;
- `{:error, reason}`: no usable answer, such as a timeout, a rate limit or a body that does
  not parse. The row says the read was unreachable.

Hashes are lowercase hex in display order, Bitcoin times are Unix seconds, and a Stellar
memo is its 32 bytes in hex. Then give the source to the HTTP reader for its network, alone
or beside others under a policy:

```elixir
Truestamp.Verify.Readers.HTTP.default(
  bitcoin: %{
    "mainnet" =>
      {{:at_least, 2},
       [
         {MyApp.BitcoinIndexer, base_url: "https://indexer.example"},
         {Truestamp.Verify.Sources.Esplora, preset: :mempool},
         {Truestamp.Verify.Sources.Esplora, preset: :blockstream}
       ]}
  }
)
```

## A reader

A reader answers every read itself. It has two callbacks: `sources/3` names the sources it
has for a chain and network, with their policy, and `read/5` makes one read from one of
them. The engine calls `read/5` once per read and source, keeps the answer for the rest of
the run, and turns a reader that raises, throws or exits into an unreachable read, so a
reader need not guard against its own failures.

`Truestamp.Verify.Readers.Replay` is a complete, short reader, and a good model.

## A keyring source

A keyring source has one callback, `fetch/1`, which gives the keyring's bytes, or its
decoded value, with where it came from and the meta of the read. The engine loads it
through the load checks of step 0. A keyring that fails one, a fetch that fails, and an
answer marked cached are each a failed read, so no key binds and KEY_BINDING fails with
`keyring_unavailable`.

`Truestamp.Verify.KeyringSources.WellKnown` reads `/.well-known/keyring.json` over HTTPS.
One for DNS, or for a file your deployment ships, takes a few lines, and gives a supplied
keyring: pass it as the trust `{:keyring_source, source}`. Only the keyring read from
`https://www.truestamp.com/.well-known/keyring.json` attributes a proof to Truestamp, so a
source given as `:current_keyring` that reports another location makes the run a
`configuration_error`.

## Testing it

Run your source against the conformance replay files' answers, or record your own: a
replay file is the read-level contract, so a source that gives the same fields for the
same reads gives the same rows. For HTTP, `Req.Test` stubs a server without the network.
