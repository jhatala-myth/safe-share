(function () {
  "use strict";
  const C = window.SafeShareCrypto;
  const $ = (id) => document.getElementById(id);
  const maxBytes = parseInt(document.body.dataset.maxBytes, 10);
  let mode = "text";
  let lastSecret = null; // {id, deleteToken}

  function setMode(m) {
    mode = m;
    $("tab-text").classList.toggle("active", m === "text");
    $("tab-file").classList.toggle("active", m === "file");
    $("tab-text").setAttribute("aria-selected", String(m === "text"));
    $("tab-file").setAttribute("aria-selected", String(m === "file"));
    $("pane-text").hidden = m !== "text";
    $("pane-file").hidden = m !== "file";
  }

  function showError(msg) {
    $("create-error").textContent = msg;
    $("create-error").hidden = !msg;
  }

  function readFile(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(new Uint8Array(r.result));
      r.onerror = () => reject(r.error);
      r.readAsArrayBuffer(file);
    });
  }

  async function buildPayload() {
    if (mode === "text") {
      const text = $("secret-text").value;
      if (!text) throw new Error("Wpisz sekret.");
      if (new TextEncoder().encode(text).length > maxBytes) throw new Error("Sekret jest za duży.");
      return { type: "text", text };
    }
    const file = $("secret-file").files[0];
    if (!file) throw new Error("Wybierz plik.");
    if (file.size > maxBytes) throw new Error(`Plik jest za duży (max ${Math.floor(maxBytes / 1024)} KiB).`);
    const bytes = await readFile(file);
    return { type: "file", name: file.name, mime: file.type || "application/octet-stream", data: C.bytesToB64(bytes) };
  }

  async function create() {
    showError("");
    const btn = $("create-btn");
    btn.disabled = true;
    try {
      const payload = await buildPayload();
      const passphrase = $("passphrase").value;
      const { request, keyB64 } = await C.encryptPayload(payload, passphrase);
      request.ttl = parseInt($("ttl").value, 10);

      const resp = await fetch("/api/v1/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
        credentials: "same-origin",
      });
      if (resp.status === 413) throw new Error("Sekret jest za duży.");
      if (resp.status === 429) throw new Error("Zbyt wiele żądań – spróbuj za chwilę.");
      if (resp.status === 403) throw new Error("Brak uprawnień do tworzenia sekretów.");
      if (!resp.ok) throw new Error("Nie udało się utworzyć sekretu (" + resp.status + ").");
      const data = await resp.json();

      lastSecret = { id: data.id, deleteToken: data.delete_token };
      $("share-link").value = `${location.origin}${data.path}#${keyB64}`;
      $("expires-at").textContent = new Date(data.expires_at * 1000).toLocaleString("pl-PL");
      $("pass-note").hidden = !passphrase;
      $("revoke-status").textContent = "";
      $("revoke-btn").disabled = false;

      // Wipe inputs.
      $("secret-text").value = "";
      $("secret-file").value = "";
      $("file-info").textContent = "";
      $("passphrase").value = "";

      $("form-section").hidden = true;
      $("result-section").hidden = false;
      $("share-link").select();
    } catch (e) {
      showError(e.message || String(e));
    } finally {
      btn.disabled = false;
    }
  }

  async function copyLink() {
    const v = $("share-link").value;
    try {
      await navigator.clipboard.writeText(v);
      $("copy-btn").textContent = "Skopiowano";
      setTimeout(() => ($("copy-btn").textContent = "Kopiuj"), 2000);
    } catch {
      $("share-link").select();
    }
  }

  async function revoke() {
    if (!lastSecret) return;
    $("revoke-btn").disabled = true;
    const resp = await fetch(`/api/v1/secrets/${encodeURIComponent(lastSecret.id)}`, {
      method: "DELETE",
      headers: { "X-Delete-Token": lastSecret.deleteToken },
    });
    $("revoke-status").textContent =
      resp.status === 204 ? "Sekret usunięty. Link jest już bezużyteczny." : "Sekretu już nie ma (odczytany lub wygasły).";
  }

  function reset() {
    lastSecret = null;
    $("share-link").value = "";
    $("result-section").hidden = true;
    $("form-section").hidden = false;
  }

  $("tab-text").addEventListener("click", () => setMode("text"));
  $("tab-file").addEventListener("click", () => setMode("file"));
  $("secret-file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    $("file-info").textContent = f ? `${f.name} – ${(f.size / 1024).toFixed(1)} KiB` : "";
  });
  $("create-btn").addEventListener("click", create);
  $("copy-btn").addEventListener("click", copyLink);
  $("revoke-btn").addEventListener("click", revoke);
  $("new-btn").addEventListener("click", reset);
})();
