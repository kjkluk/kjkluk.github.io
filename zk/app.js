"use strict";

const publicSignalsEl = document.getElementById("publicSignals");
const proofEl = document.getElementById("proof");
const verifyButton = document.getElementById("verify");
const resultEl = document.getElementById("result");

let verificationKey = null;

function setResult(text, kind = "") {
  resultEl.textContent = text;
  resultEl.className = kind;
}

async function loadVerificationKey() {
  if (!globalThis.snarkjs?.groth16?.verify) {
    throw new Error("本地 snarkjs 验证库没有载入。");
  }

  const response = await fetch("./verification_key.json", {
    cache: "no-store",
    credentials: "same-origin"
  });
  if (!response.ok) {
    throw new Error("找不到 verification_key.json。");
  }

  const candidate = await response.json();
  if (candidate?._configured === false) {
    setResult("尚未配置验证密钥：页面故意拒绝给出 VALID。");
    return;
  }

  verificationKey = candidate;
  verifyButton.disabled = false;
  setResult("验证器已就绪。");
}

verifyButton.addEventListener("click", async () => {
  if (!verificationKey) {
    setResult("验证器尚未配置。", "invalid");
    return;
  }

  verifyButton.disabled = true;
  setResult("正在验证…");

  try {
    const publicSignals = JSON.parse(publicSignalsEl.value);
    const proof = JSON.parse(proofEl.value);

    if (!Array.isArray(publicSignals)) {
      throw new Error("公开输入必须是 JSON 数组。");
    }
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
      throw new Error("π 必须是 proof JSON 对象。");
    }

    const ok = await globalThis.snarkjs.groth16.verify(
      verificationKey,
      publicSignals,
      proof
    );

    if (ok) {
      setResult("VALID ✓\n零知识证明验证通过。", "valid");
    } else {
      setResult("INVALID ✗\n证明未通过。", "invalid");
    }
  } catch (error) {
    setResult("INVALID / 输入格式错误\n" + String(error?.message ?? error), "invalid");
  } finally {
    verifyButton.disabled = false;
  }
});

loadVerificationKey().catch((error) => {
  verifyButton.disabled = true;
  setResult("验证器初始化失败：\n" + String(error?.message ?? error), "invalid");
});
