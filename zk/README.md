# ZK verifier

A deliberately small browser-side Groth16 verifier for GitHub Pages.

## Hard boundary

This page is **verification only**.

- It accepts public inputs and a proof (π).
- It must never ask for the secret seed.
- It does not generate proofs.
- Runtime scripts are served from this repository; there is no CDN dependency.
- The page intentionally refuses to return VALID until a real `verification_key.json` is committed.

## Vendored dependency

`vendor/snarkjs.min.js` is copied from the official iden3/snarkjs **v0.7.6** tag.
snarkjs is GPL-3.0 licensed. The repository already carries a GPL license.

## Next cryptographic step

Freeze the exact statement to be proved first. Only then generate the circuit, proving key and verification key. Do not replace `verification_key.json` with a key from a different circuit.
