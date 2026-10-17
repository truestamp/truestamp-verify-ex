<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Trust roots and roles

A signature only means something once you know whose key made it. Step 5 of SPEC.md
section 10.2, KEY_BINDING, looks for the proof's key in the keyring that governs the run,
and that keyring, the run's **trust root**, decides the best label the run can reach. This
guide says which keyring governs, and how to choose it.

## Two roles

A verifier has one of two roles (section 8), and `Truestamp.Verify.Config` has one
constructor for each, so the choice is always explicit:

- **External**, `Truestamp.Verify.Config.external/1`: every verifier but Truestamp's own,
  your application included. `Truestamp.Verify.verify/2` builds this one from its keyword
  options.
- **Internal**, `Truestamp.Verify.Config.internal/1`: Truestamp's own servers, whose trust
  root is their verified key chain.

## The trust root of an external run

The `:trust` option chooses it:

| `:trust` | Keyring that governs | Best label |
|---|---|---|
| `:default`, under `:prod`, offline | the compiled pin, the keys built into this library | `:internally_consistent` |
| `:default`, under `:prod`, online | the keyring Truestamp publishes, read through `:current_keyring` | `:verified` |
| `{:keyring_file, path}`, `{:keyring, bytes}` or `{:keyring_source, source}` | the keyring you supply | `:supplied_keyring` |
| `:keyless` | none: the signature is checked only against the key the proof carries | `:unattributed` |

Only a run whose keyring is Truestamp's can attribute a proof to Truestamp, and only an
online run can draw the submitted-before edge that `:verified` needs. So an offline run
under the compiled pin ends `:internally_consistent` at best, and a run under a keyring you
supply ends `:supplied_keyring` at best, however sound the proof: that label says the proof
is intact and signed by a key in your keyring, and nothing about Truestamp.

Under an environment other than `:prod` there is no default keyring (section 6.4), so a run
must supply one or be keyless; otherwise it is a `configuration_error`.

The compiled pin, `spec/keyring.production.json`, holds no key yet, so a production proof
fails KEY_BINDING under it. Until it holds one, check a production proof online, or with a
keyring that holds its key.

Every keyring passes the load checks of step 0 before any proof is read. A keyring you give
as bytes or a file that fails one makes the run a `configuration_error`; a keyring read
online that fails one, or that cannot be read, or that its source marks cached, is a failed
read, so no key binds and KEY_BINDING fails with `keyring_unavailable` (section 8.3). The
report's `trust_root` names the kind of keyring, where it came from, and the SHA-256 of its
bytes.

## The keyring Truestamp publishes

An online run under `:prod` with the default trust reads the keyring that governs it from
Truestamp, through a `Truestamp.Verify.KeyringSource`. `Truestamp.Verify.Online.defaults/1`
gives `Truestamp.Verify.KeyringSources.WellKnown`, which reads
`https://www.truestamp.com/.well-known/keyring.json`, and only a keyring read from that
URL attributes a proof to Truestamp (section 10.5): a `:current_keyring` source that reads
any other location makes the run a `configuration_error`.

A keyring read from anywhere else, another origin's `/.well-known/keyring.json`, a DNS
record, a file your deployment ships, is a supplied keyring. Give its source as the trust
`{:keyring_source, source}`, a module that implements `c:Truestamp.Verify.KeyringSource.fetch/1`;
`Truestamp.Verify.Online.defaults(keyring_origin: url)` does this for another origin.

## Keyless mode

`trust: :keyless` checks that the proof is intact under the key it carries, and nothing
more: anyone could have made such a proof. Every surface says so beside the verdict
(section 8.3).

## The internal role

Truestamp's own verifier gives its verified key chain:

```elixir
config =
  Truestamp.Verify.Config.internal!(
    key_chain: verified_public_keys,   # or :unavailable while it is not verified
    reader: {MyApp.LiveReader, state}
  )

Truestamp.Verify.verify(proof_bytes, config)
```

The internal role has no keyless mode, accepts no supplied keyring, and never falls back to
the compiled pin. While the key chain is not verified, every run fails closed at
KEY_BINDING with `keyring_unavailable`.

A key chain is not a keyring a verifier reads, so the load checks of its form do not
apply, but those of the environment do: no run under `:prod` binds a non-production key
(section 6.4), so a key chain that holds one of `spec/keys.nonproduction.json`, or VECTOR_KEY
outside `:test`, makes the run a `configuration_error`.
