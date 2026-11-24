"""Redis storage with atomic, token-checked read-and-delete.

Each secret is one Redis string (JSON) with a native TTL. The server only ever
stores ciphertext plus SHA-256 hashes of the reveal / delete tokens.
"""
from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis

# Returns the record only if the token hash matches; optionally deletes it in
# the same atomic step. A mismatching token leaves the record untouched, so a
# party knowing only the ID (e.g. from a log) cannot burn the secret.
_CHECK_SCRIPT = """
local v = redis.call('GET', KEYS[1])
if not v then return false end
local ok, o = pcall(cjson.decode, v)
if not ok then return false end
if o[ARGV[1]] ~= ARGV[2] then return false end
if ARGV[3] == '1' then redis.call('DEL', KEYS[1]) end
return v
"""


class SecretStore:
    def __init__(self, client: redis.Redis, prefix: str) -> None:
        self._r = client
        self._prefix = prefix
        self._check = client.register_script(_CHECK_SCRIPT)

    def _key(self, secret_id: str) -> str:
        return f"{self._prefix}{secret_id}"

    async def put(self, secret_id: str, record: dict[str, Any], ttl: int) -> bool:
        return bool(await self._r.set(self._key(secret_id), json.dumps(record), ex=ttl, nx=True))

    async def _run(self, secret_id: str, field: str, token_hash: str, delete: bool) -> dict[str, Any] | None:
        raw = await self._check(keys=[self._key(secret_id)], args=[field, token_hash, "1" if delete else "0"])
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    async def peek(self, secret_id: str, reveal_hash: str) -> dict[str, Any] | None:
        return await self._run(secret_id, "rh", reveal_hash, delete=False)

    async def take(self, secret_id: str, reveal_hash: str) -> dict[str, Any] | None:
        return await self._run(secret_id, "rh", reveal_hash, delete=True)

    async def revoke(self, secret_id: str, delete_hash: str) -> bool:
        return await self._run(secret_id, "dh", delete_hash, delete=True) is not None

    async def ttl(self, secret_id: str) -> int:
        return int(await self._r.ttl(self._key(secret_id)))

    async def ping(self) -> bool:
        return bool(await self._r.ping())
