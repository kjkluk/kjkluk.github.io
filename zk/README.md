# ZK verifier

A small, dependency-free browser verifier for a Schnorr proof of knowledge.

## What is public

- `Y = g^x mod p` — the anchor sent in the first email.
- a fresh challenge/nonce chosen for the later verification.
- proof `π = {t, s}`.

## What stays secret

- `x`.
- If a human-memorable or random `seed` is used, derive `x` from it offline. The verifier must never receive the seed.

## Verification equation

The page computes

`c = SHA256("ZK-ID-SCHNORR-v1" || Y || t || nonce) mod q`

and accepts exactly when

`g^s = t * Y^c (mod p)`.

The group is RFC 3526 MODP Group 14 (2048-bit safe prime), using the q-order subgroup.

## Runtime properties

- no CDN
- no external JavaScript
- no network requests from the verifier page
- no proof generation
- no seed/private-key input

The verifier proves knowledge of the secret corresponding to Y. It does not establish personhood, uniqueness, or legal identity.
