# Sealr evidence format and verifier

This repository holds the **evidence format**, its reference implementation, and
`sealr-verify` — the tool that checks a `.seal` bundle offline.

It exists so that verification does not depend on Sealr. If someone hands you a
`.seal` file, you can confirm what it does and does not prove using only what is
here: no account, no network, no cooperation from the vendor or from whoever
produced the bundle.

Licensed under [Apache-2.0](LICENSE). The guards, the recorder and the Console
live in a separate repository under different terms; nothing in this one depends
on them.

## Verify a bundle

```bash
cargo build --release --bin sealr-verify
./target/release/sealr-verify bundle.seal
./target/release/sealr-verify bundle.seal --json
./target/release/sealr-verify bundle.seal --root root.pem   # a root you obtained out of band
```

Exit codes: `0` pass · `10` pass with findings · `11` fail.

## Check that the verifier catches what it claims

`testdata/vectors` holds a valid bundle and one per fault class — a tampered
record, a reordering, a gap, a forged checkpoint, a revoked key, a corrupted
timestamp token, a fork, a truncated tail. `expected.json` states the verdict
each must produce.

```bash
cargo test
```

That test reads the committed vectors, so it checks the same artefacts you can
download rather than something regenerated at test time.

## What a report asserts, and what it does not

Every report prints its own limits. In short:

- **Tamper-evident, not tamper-proof.** It proves the integrity, ordering,
  timing and origin of the recorded stream. It cannot prove that unrecorded
  events did not happen.
- **Coverage is a deployment property.** Only operations that passed through a
  recorder are in the stream.
- **Proven time comes from anchors.** A record existed no later than its
  earliest anchor; "no earlier than" is bounded by the previous anchor and
  monotonic clock deltas.
- **Attribution is as recorded.** Each record states whether the human principal
  was attributed, inferred, or unattributed; the verifier does not independently
  prove identity.

[SPEC.md](SPEC.md) is the normative specification — enough to implement an
independent verifier without reading this code.

## Layout

| Path | What it is |
|---|---|
| `crates/evidence` | Records, BLAKE3 hash chain, Merkle checkpoints, signatures, X.509 identity, commitments |
| `crates/bundle` | The `.seal` container: deterministic reader and writer |
| `crates/verify` | The verifier and its report |
| `testdata/vectors` | Conformance vectors and their expected verdicts |

Generated from the Sealr monorepo. Report issues and send patches here; they are
applied upstream and republished.
