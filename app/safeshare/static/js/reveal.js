(function () {
  "use strict";
  const C = window.SafeShareCrypto;
  const $ = (id) => document.getElementById(id);
  const SECTIONS = ["loading", "unavailable", "ready", "retry", "secret"];

  const secretId = location.pathname.split("/").pop();
  const keyB64 = location.hash.slice(1);
  let revealToken = null;
  let fetched = null; // ciphertext kept in memory only, to allow passphrase retries after burn

  function show(name) {
    SECTIONS.forEach((s) => ($(s).hidden = s !== name));
  }
  function showError(msg) {
    $("error").textContent = msg;
    $("error").hidden = !msg;
  }
  function stripFragment() {
    // Remove the key from the address bar / history once it is no longer needed.
    history.replaceState(null, "", location.pathname);
  }

  async function init() {
    if (!C.isValidKey(keyB64)) {
      show("unavailable");
      showError("Link jest niekompletny – brakuje klucza po znaku #. Skopiuj cały link.");
      return;
    }
    revealToken = await C.revealToken(keyB64);
    const resp = await fetch(`/api/v1/secrets/${encodeURIComponent(secretId)}`, {
      headers: { "X-Reveal-Token": revealToken },
    });
    if (!resp.ok) {
      show("unavailable");
      stripFragment();
      return;
    }
    const meta = await resp.json();
    $("expires-at").textContent = new Date(meta.expires_at * 1000).toLocaleString("pl-PL");
    $("pass-box").hidden = !meta.passphrase;
    show("ready");
  }

  async function reveal() {
    showError("");
    $("reveal-btn").disabled = true;
    const resp = await fetch(`/api/v1/secrets/${encodeURIComponent(secretId)}/reveal`, {
      method: "POST",
      headers: { "X-Reveal-Token": revealToken },
    });
    if (!resp.ok) {
      show("unavailable");
      stripFragment();
      return;
    }
    fetched = await resp.json();
    await tryDecrypt($("passphrase").value);
  }

  async function tryDecrypt(passphrase) {
    try {
      const payload = await C.decryptPayload(fetched, keyB64, passphrase || null);
      fetched = null;
      stripFragment();
      render(payload);
    } catch (e) {
      if (fetched && fetched.salt) {
        show("retry");
        showError("Nieprawidłowe hasło dodatkowe.");
        $("passphrase-retry").value = "";
        $("passphrase-retry").focus();
      } else {
        show("unavailable");
        showError("Nie udało się odszyfrować danych (uszkodzony lub zmieniony link).");
        stripFragment();
      }
    }
  }

  function render(payload) {
    showError("");
    show("secret");
    if (payload.type === "file") {
      const bytes = C.b64ToBytes(payload.data);
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const a = $("download-link");
      a.href = URL.createObjectURL(blob);
      a.download = payload.name || "secret.bin";
      $("file-name").textContent = payload.name || "secret.bin";
      $("file-size").textContent = `${(bytes.length / 1024).toFixed(1)} KiB`;
      $("secret-file-box").hidden = false;
    } else {
      $("secret-text").value = payload.text;
      $("secret-text-box").hidden = false;
    }
  }

  $("reveal-btn").addEventListener("click", reveal);
  $("retry-btn").addEventListener("click", () => tryDecrypt($("passphrase-retry").value));
  $("passphrase-retry").addEventListener("keydown", (e) => e.key === "Enter" && tryDecrypt(e.target.value));
  $("copy-btn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("secret-text").value);
      $("copy-btn").textContent = "Skopiowano";
    } catch {
      $("secret-text").select();
    }
  });

  init().catch(() => {
    show("unavailable");
    showError("Błąd połączenia z serwerem.");
  });
})();
