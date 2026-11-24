"""Safe Share – one-time, client-side encrypted secret sharing.

Zero-knowledge design: the browser (or CLI) encrypts with AES-256-GCM using a
random key that lives only in the URL fragment (#...), which is never sent to
the server. The server stores ciphertext with a Redis TTL and deletes it
atomically on first successful reveal.
"""
from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import redis.asyncio as redis
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import Settings, settings as default_settings
from .storage import SecretStore

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")  # base64url of 32 bytes, no padding
FORMAT_VERSION = 1

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; manifest-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "require-trusted-types-for 'script'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}

NOT_FOUND = {"detail": "not_found"}


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class CreateSecret(BaseModel):
    model_config = ConfigDict(extra="forbid")

    v: int = Field(FORMAT_VERSION, description="Crypto format version")
    ciphertext: str = Field(..., min_length=24)
    iv: str
    salt: str | None = Field(None, description="PBKDF2 salt; present only when a passphrase is used")
    reveal_token: str = Field(..., description="base64url(SHA-256('safeshare-v1:reveal:' || key))")
    ttl: int

    @field_validator("v")
    @classmethod
    def _version(cls, v: int) -> int:
        if v != FORMAT_VERSION:
            raise ValueError("unsupported version")
        return v

    @field_validator("ciphertext")
    @classmethod
    def _ct(cls, v: str) -> str:
        if not B64URL_RE.match(v):
            raise ValueError("ciphertext must be base64url")
        return v

    @field_validator("iv")
    @classmethod
    def _iv(cls, v: str) -> str:
        if not B64URL_RE.match(v) or len(_b64url_decode(v)) != 12:
            raise ValueError("iv must be 12 bytes base64url")
        return v

    @field_validator("salt")
    @classmethod
    def _salt(cls, v: str | None) -> str | None:
        if v is not None and (not B64URL_RE.match(v) or len(_b64url_decode(v)) != 16):
            raise ValueError("salt must be 16 bytes base64url")
        return v

    @field_validator("reveal_token")
    @classmethod
    def _rt(cls, v: str) -> str:
        if not TOKEN_RE.match(v):
            raise ValueError("invalid reveal_token")
        return v


class Templates:
    """Tiny renderer: injects SRI hashes and config into static HTML templates."""

    _SRI_RE = re.compile(r"\{\{\s*sri\s+([\w./-]+)\s*\}\}")

    def __init__(self, cfg: Settings) -> None:
        options = "".join(
            f'<option value="{t}"{" selected" if t == cfg.default_ttl else ""}>{html.escape(_ttl_label(t))}</option>'
            for t in cfg.ttl_options
        )
        self._pages: dict[str, str] = {}
        for name in ("create.html", "reveal.html"):
            text = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
            text = self._SRI_RE.sub(lambda m: self._sri(m.group(1)), text)
            text = text.replace("{{ ttl_options }}", options)
            text = text.replace("{{ max_bytes }}", str(cfg.max_plaintext_bytes))
            self._pages[name] = text

    @staticmethod
    def _sri(rel: str) -> str:
        path = (STATIC_DIR / rel).resolve()
        if STATIC_DIR not in path.parents:
            raise ValueError(rel)
        digest = hashlib.sha384(path.read_bytes()).digest()
        return "sha384-" + base64.b64encode(digest).decode()

    def render(self, name: str) -> HTMLResponse:
        return HTMLResponse(self._pages[name])


def _ttl_label(seconds: int) -> str:
    if seconds % 86400 == 0:
        d = seconds // 86400
        return f"{d} {'dzień' if d == 1 else 'dni'}"
    if seconds % 3600 == 0:
        h = seconds // 3600
        return f"{h} godz."
    return f"{seconds // 60} min"


def create_app(cfg: Settings = default_settings, redis_client: redis.Redis | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = redis_client or redis.from_url(cfg.redis_url, decode_responses=True)
        app.state.store = SecretStore(client, cfg.key_prefix)
        yield
        if redis_client is None:
            await client.aclose()

    app = FastAPI(
        title="Safe Share",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    templates = Templates(cfg)
    max_body = cfg.max_ciphertext_chars + 4096

    @app.middleware("http")
    async def security(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > max_body):
            resp: Response = JSONResponse({"detail": "payload_too_large"}, status_code=413)
        else:
            resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    def store(request: Request) -> SecretStore:
        return request.app.state.store

    # ---------- pages ----------
    @app.get("/", include_in_schema=False)
    async def page_create() -> HTMLResponse:
        return templates.render("create.html")

    @app.get("/s/{secret_id}", include_in_schema=False)
    async def page_reveal(secret_id: str) -> HTMLResponse:
        # Never touches storage: link-preview bots that GET this page burn nothing.
        return templates.render("reveal.html")

    # ---------- API ----------
    @app.post("/api/v1/secrets", status_code=201)
    async def create_secret(body: CreateSecret, request: Request) -> dict:
        if body.ttl not in cfg.ttl_options:
            raise HTTPException(422, detail=f"ttl must be one of {cfg.ttl_options}")
        if len(body.ciphertext) > cfg.max_ciphertext_chars:
            raise HTTPException(413, detail="payload_too_large")

        delete_token = secrets.token_urlsafe(32)
        now = int(time.time())
        record = {
            "v": body.v,
            "ct": body.ciphertext,
            "iv": body.iv,
            "salt": body.salt,
            "rh": _sha256_hex(body.reveal_token),
            "dh": _sha256_hex(delete_token),
            "created": now,
            "expires": now + body.ttl,
        }
        st = store(request)
        for _ in range(3):
            secret_id = secrets.token_urlsafe(24)
            if await st.put(secret_id, record, body.ttl):
                break
        else:  # pragma: no cover - astronomically unlikely
            raise HTTPException(500, detail="id_collision")

        return {
            "id": secret_id,
            "path": f"/s/{secret_id}",
            "expires_at": record["expires"],
            "delete_token": delete_token,
        }

    def _check_ids(secret_id: str, token: str | None) -> str:
        if not ID_RE.match(secret_id) or not token or not TOKEN_RE.match(token):
            raise HTTPException(404, detail="not_found")
        return _sha256_hex(token)

    @app.get("/api/v1/secrets/{secret_id}")
    async def secret_status(
        secret_id: str,
        request: Request,
        x_reveal_token: Annotated[str | None, Header()] = None,
    ) -> dict:
        """Metadata only (no ciphertext, no deletion)."""
        rh = _check_ids(secret_id, x_reveal_token)
        rec = await store(request).peek(secret_id, rh)
        if rec is None:
            raise HTTPException(404, detail="not_found")
        return {"id": secret_id, "expires_at": rec["expires"], "passphrase": rec["salt"] is not None}

    @app.post("/api/v1/secrets/{secret_id}/reveal")
    async def reveal_secret(
        secret_id: str,
        request: Request,
        x_reveal_token: Annotated[str | None, Header()] = None,
    ) -> dict:
        """Returns the ciphertext and deletes it atomically. Decryption happens on the client."""
        rh = _check_ids(secret_id, x_reveal_token)
        rec = await store(request).take(secret_id, rh)
        if rec is None:
            raise HTTPException(404, detail="not_found")
        return {"v": rec["v"], "ciphertext": rec["ct"], "iv": rec["iv"], "salt": rec["salt"]}

    @app.delete("/api/v1/secrets/{secret_id}", status_code=204)
    async def revoke_secret(
        secret_id: str,
        request: Request,
        x_delete_token: Annotated[str | None, Header()] = None,
    ) -> Response:
        dh = _check_ids(secret_id, x_delete_token)
        if not await store(request).revoke(secret_id, dh):
            raise HTTPException(404, detail="not_found")
        return Response(status_code=204)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(STATIC_DIR / "img" / "favicon.ico", media_type="image/x-icon")

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request) -> dict:
        try:
            await store(request).ping()
        except Exception:
            raise HTTPException(503, detail="redis_unavailable")
        return {"status": "ok"}

    @app.exception_handler(404)
    async def _nf(request: Request, exc):  # uniform 404 for everything
        return JSONResponse(NOT_FOUND, status_code=404)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
