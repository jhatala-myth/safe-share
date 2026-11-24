#!/usr/bin/env python3
"""Safe Share CLI – create and read one-time secrets from the command line / CI.

Encryption is done locally (same format v1 as the web UI), so the server never
sees plaintext. Requires: pip install cryptography

Examples:
  echo -n 'S3cr3t!' | safeshare_cli.py create --url https://share.example.com --ttl 3600
  safeshare_cli.py create --url https://share.example.com --file client.p12 --passphrase
  safeshare_cli.py get 'https://share.example.com/s/<id>#<key>'            # prints secret
  safeshare_cli.py get '<link>' --json                                      # prints JSON payload
  safeshare_cli.py get '<link>' --out client.p12                            # saves file
  safeshare_cli.py revoke '<link>' --delete-token <token>
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import mimetypes
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

AAD = b"safeshare-v1"
REVEAL_LABEL = b"safeshare-v1:reveal:"
PBKDF2_ITERATIONS = 600_000
VERSION = 1


# ---------------------------------------------------------------- crypto (v1)
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_key(key: bytes, passphrase: str | None, salt: bytes | None) -> bytes:
    if not passphrase:
        return key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(key + passphrase.encode())


def reveal_token(key: bytes) -> str:
    return b64url(hashlib.sha256(REVEAL_LABEL + key).digest())


def encrypt_payload(payload: dict, passphrase: str | None = None) -> tuple[dict, str]:
    """Returns (api_request_without_ttl, key_b64url)."""
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    salt = secrets.token_bytes(16) if passphrase else None
    ct = AESGCM(derive_key(key, passphrase, salt)).encrypt(iv, json.dumps(payload).encode(), AAD)
    req = {
        "v": VERSION,
        "ciphertext": b64url(ct),
        "iv": b64url(iv),
        "salt": b64url(salt) if salt else None,
        "reveal_token": reveal_token(key),
    }
    return req, b64url(key)


def decrypt_payload(resp: dict, key_b64: str, passphrase: str | None = None) -> dict:
    salt = from_b64url(resp["salt"]) if resp.get("salt") else None
    if salt and not passphrase:
        raise ValueError("passphrase_required")
    aes = AESGCM(derive_key(from_b64url(key_b64), passphrase if salt else None, salt))
    pt = aes.decrypt(from_b64url(resp["iv"]), from_b64url(resp["ciphertext"]), AAD)
    return json.loads(pt)


# ---------------------------------------------------------------- HTTP
class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status


def _ssl_ctx(ca_bundle: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def http(method: str, url: str, *, body: dict | None = None, headers: dict | None = None,
         ca_bundle: str | None = None, timeout: int = 30) -> tuple[int, dict | None]:
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Accept": "application/json", "User-Agent": "safeshare-cli/1"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    ctx = _ssl_ctx(ca_bundle) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode(errors="replace")) from None


def parse_link(link: str) -> tuple[str, str, str]:
    """Returns (base_url, secret_id, key)."""
    parts = urlsplit(link)
    segs = parts.path.rstrip("/").split("/")
    if len(segs) < 2 or segs[-2] != "s" or not parts.fragment:
        raise SystemExit("Nieprawidłowy link – oczekiwano https://host/s/<id>#<klucz>")
    return f"{parts.scheme}://{parts.netloc}", segs[-1], parts.fragment


# ---------------------------------------------------------------- commands
def cmd_create(a: argparse.Namespace) -> int:
    if a.file:
        p = Path(a.file)
        data = p.read_bytes()
        payload = {"type": "file", "name": p.name,
                   "mime": mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                   "data": base64.b64encode(data).decode()}
    else:
        if sys.stdin.isatty():
            print("Wpisz sekret, zakończ Ctrl-D:", file=sys.stderr)
        data = sys.stdin.buffer.read()
        payload = {"type": "text", "text": data.decode()}
    if len(data) > a.max_bytes:
        raise SystemExit(f"Sekret za duży ({len(data)} B > {a.max_bytes} B)")

    passphrase = None
    if a.passphrase:
        passphrase = os.environ.get("SAFESHARE_PASSPHRASE") or getpass.getpass("Hasło dodatkowe: ")

    req, key = encrypt_payload(payload, passphrase)
    req["ttl"] = a.ttl
    base = a.url.rstrip("/")
    _, resp = http("POST", f"{base}/api/v1/secrets", body=req, ca_bundle=a.ca_bundle,
                   headers=_auth_headers(a))
    link = f"{base}{resp['path']}#{key}"
    if a.json:
        print(json.dumps({"link": link, "id": resp["id"], "expires_at": resp["expires_at"],
                          "delete_token": resp["delete_token"]}))
    else:
        print(link)
        print(f"delete_token: {resp['delete_token']}", file=sys.stderr)
    return 0


def cmd_get(a: argparse.Namespace) -> int:
    base, sid, key = parse_link(a.link)
    hdr = {"X-Reveal-Token": reveal_token(from_b64url(key))}
    try:
        _, resp = http("POST", f"{base}/api/v1/secrets/{sid}/reveal", headers=hdr, ca_bundle=a.ca_bundle)
    except ApiError as e:
        if e.status == 404:
            raise SystemExit("Sekret nie istnieje, wygasł albo został już odczytany.")
        raise

    passphrase = os.environ.get("SAFESHARE_PASSPHRASE")
    for attempt in range(3):
        if resp.get("salt") and not passphrase:
            passphrase = getpass.getpass("Hasło dodatkowe: ")
        try:
            payload = decrypt_payload(resp, key, passphrase)
            break
        except Exception:
            if not resp.get("salt"):
                raise SystemExit("Nie udało się odszyfrować (uszkodzony link).")
            print("Nieprawidłowe hasło.", file=sys.stderr)
            passphrase = None
    else:
        raise SystemExit("Przekroczono liczbę prób – sekret został już usunięty z serwera.")

    if a.json:
        print(json.dumps(payload))
    elif payload["type"] == "file":
        out = Path(a.out or payload["name"])
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(base64.b64decode(payload["data"]))
        print(f"Zapisano: {out}", file=sys.stderr)
    elif a.out:
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload["text"])
    else:
        sys.stdout.write(payload["text"])
    return 0


def cmd_revoke(a: argparse.Namespace) -> int:
    base, sid, _ = parse_link(a.link)
    try:
        http("DELETE", f"{base}/api/v1/secrets/{sid}", headers={"X-Delete-Token": a.delete_token},
             ca_bundle=a.ca_bundle)
    except ApiError as e:
        if e.status == 404:
            raise SystemExit("Sekretu już nie ma (odczytany, wygasły lub zły token).")
        raise
    print("Sekret usunięty.", file=sys.stderr)
    return 0


def _auth_headers(a: argparse.Namespace) -> dict:
    # Optional: e.g. basic auth / bearer token if creation is protected in nginx.
    token = os.environ.get("SAFESHARE_AUTH_HEADER")
    return {"Authorization": token} if token else {}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Safe Share CLI")
    p.add_argument("--ca-bundle", help="CA bundle (PEM) for an internal CA")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="create a secret (stdin or --file)")
    c.add_argument("--url", required=True, help="base URL, e.g. https://share.example.com")
    c.add_argument("--ttl", type=int, default=86400, help="seconds; must be allowed by the server")
    c.add_argument("--file", help="share a file instead of stdin")
    c.add_argument("--passphrase", action="store_true",
                   help="protect with an extra passphrase (prompt or $SAFESHARE_PASSPHRASE)")
    c.add_argument("--max-bytes", type=int, default=1_048_576)
    c.add_argument("--json", action="store_true", help="print JSON result")
    c.set_defaults(func=cmd_create)

    g = sub.add_parser("get", help="reveal (and burn) a secret")
    g.add_argument("link")
    g.add_argument("--json", action="store_true", help="print decrypted payload as JSON")
    g.add_argument("--out", help="write to file (mode 0600, must not exist)")
    g.set_defaults(func=cmd_get)

    r = sub.add_parser("revoke", help="delete a secret before it is read")
    r.add_argument("link")
    r.add_argument("--delete-token", required=True)
    r.set_defaults(func=cmd_revoke)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
