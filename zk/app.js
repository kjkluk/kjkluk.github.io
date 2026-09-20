"use strict";

// RFC 3526 MODP Group 14 (2048-bit safe prime), generator g = 2.
// Schnorr proof in the prime-order subgroup q=(p-1)/2.
const P = BigInt("0x" +
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA051015" +
  "728E5A8AACAA68FFFFFFFFFFFFFFFF");
const Q = (P - 1n) / 2n;
const G = 2n;
const DOMAIN = "ZK-ID-SCHNORR-v1";

const yEl = document.getElementById("publicY");
const nonceEl = document.getElementById("nonce");
const proofEl = document.getElementById("proof");
const button = document.getElementById("verify");
const result = document.getElementById("result");

function modPow(base, exp, mod) {
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return out;
}

function parseHexInt(value, name) {
  const s = String(value).trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(s)) throw new Error(name + " 不是合法十六进制。");
  return BigInt("0x" + s);
}

function hexCanonical(n) {
  return n.toString(16);
}

async function challengeScalar(y, t, nonce) {
  const msg = DOMAIN + "\n" + hexCanonical(y) + "\n" + hexCanonical(t) + "\n" + nonce;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
  const bytes = new Uint8Array(digest);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n % Q;
}

function setResult(text, kind = "") {
  result.textContent = text;
  result.className = kind;
}

button.addEventListener("click", async () => {
  button.disabled = true;
  setResult("正在验证…");
  try {
    const y = parseHexInt(yEl.value, "Y");
    const nonce = nonceEl.value;
    const proof = JSON.parse(proofEl.value);
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
      throw new Error("π 必须是 JSON 对象。");
    }

    const t = parseHexInt(proof.t, "t");
    const s = parseHexInt(proof.s, "s");

    if (nonce.length === 0) throw new Error("challenge 不能为空。");
    if (!(y > 1n && y < P - 1n)) throw new Error("Y 超出群范围。");
    if (!(t > 1n && t < P - 1n)) throw new Error("t 超出群范围。");
    if (!(s >= 0n && s < Q)) throw new Error("s 超出标量范围。");

    // Ensure public elements lie in the q-order subgroup.
    if (modPow(y, Q, P) !== 1n) throw new Error("Y 不在预期子群。");
    if (modPow(t, Q, P) !== 1n) throw new Error("t 不在预期子群。");

    const c = await challengeScalar(y, t, nonce);

    // Schnorr verification:
    // g^s == t * y^c (mod p)
    const left = modPow(G, s, P);
    const right = (t * modPow(y, c, P)) % P;

    if (left === right) {
      setResult("VALID ✓\n证明通过：当前证明者知道与旧锚 Y 对应的秘密。", "valid");
    } else {
      setResult("INVALID ✗\n证明未通过。", "invalid");
    }
  } catch (err) {
    setResult("INVALID / 输入错误\n" + String(err?.message ?? err), "invalid");
  } finally {
    button.disabled = false;
  }
});
