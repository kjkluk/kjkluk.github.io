# ZK verifier

This directory contains:

- `index.html`: public browser verifier.
- `app.js`: dependency-free Schnorr/Fiat–Shamir verification logic.
- `prover.html`: a single-file prover that deliberately refuses to operate unless opened from `file://`.

## Flow

1. Offline prover generates secret `x`.
2. First email sends only `Y = g^x mod p`.
3. Later, the prover creates a proof package `{context,t,s}`.
4. Recipient pastes the old `Y` and the proof package into the public verifier.
5. On the first successful verification, treat `Y` as spent.

No recipient-generated nonce is required.

## Important freshness limit

Without a verifier challenge, an exact proof package can be replayed. Therefore this design is intentionally **one-shot**: the first accepted proof consumes the anchor. A party that intercepts the first proof before the recipient and races the same proof cannot be distinguished cryptographically without adding either an interactive challenge or an external freshness source.

## Runtime boundaries

Verifier:
- no CDN
- no external JavaScript
- no network requests
- never sees secret x

Prover:
- single local HTML file
- refuses to run over http/https
- no network requests
