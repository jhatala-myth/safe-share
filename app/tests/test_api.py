import sys
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli"))
sys.path.insert(0, str(ROOT / "app"))

import safeshare_cli as cli  # noqa: E402
from safeshare.config import Settings  # noqa: E402
from safeshare.main import create_app  # noqa: E402


@pytest.fixture
def client():
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    app = create_app(Settings(redis_url="redis://unused"), redis_client=r)
    with TestClient(app) as c:
        c.redis = r
        yield c


def _create(client, payload, passphrase=None, ttl=3600):
    req, key = cli.encrypt_payload(payload, passphrase)
    req["ttl"] = ttl
    r = client.post("/api/v1/secrets", json=req)
    assert r.status_code == 201, r.text
    return r.json(), key


def _rt(key):
    return {"X-Reveal-Token": cli.reveal_token(cli.from_b64url(key))}


def test_roundtrip_one_time(client):
    data, key = _create(client, {"type": "text", "text": "hunter2"})
    assert client.get(data["path"]).status_code == 200  # page GET burns nothing
    st = client.get(f"/api/v1/secrets/{data['id']}", headers=_rt(key))
    assert st.status_code == 200 and st.json()["passphrase"] is False

    r = client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key))
    assert r.status_code == 200
    assert cli.decrypt_payload(r.json(), key) == {"type": "text", "text": "hunter2"}

    # second read fails
    assert client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key)).status_code == 404
    assert client.get(f"/api/v1/secrets/{data['id']}", headers=_rt(key)).status_code == 404


def test_wrong_reveal_token_does_not_burn(client):
    data, key = _create(client, {"type": "text", "text": "x"})
    _, other = cli.encrypt_payload({"type": "text", "text": "y"})
    assert client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(other)).status_code == 404
    assert client.post(f"/api/v1/secrets/{data['id']}/reveal").status_code == 404  # no token
    assert client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key)).status_code == 200


def test_passphrase(client):
    data, key = _create(client, {"type": "text", "text": "pem"}, passphrase="correct horse")
    assert client.get(f"/api/v1/secrets/{data['id']}", headers=_rt(key)).json()["passphrase"] is True
    resp = client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key)).json()
    with pytest.raises(Exception):
        cli.decrypt_payload(resp, key, "wrong")
    assert cli.decrypt_payload(resp, key, "correct horse")["text"] == "pem"


def test_revoke(client):
    data, key = _create(client, {"type": "text", "text": "x"})
    assert client.delete(f"/api/v1/secrets/{data['id']}", headers={"X-Delete-Token": "A" * 43}).status_code == 404
    assert client.delete(f"/api/v1/secrets/{data['id']}",
                         headers={"X-Delete-Token": data["delete_token"]}).status_code == 204
    assert client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key)).status_code == 404


def test_ttl_applied_and_validated(client):
    import asyncio
    data, _ = _create(client, {"type": "text", "text": "x"}, ttl=300)
    ttl = asyncio.run(client.redis.ttl(f"safeshare:secret:{data['id']}"))
    assert 0 < ttl <= 300
    req, _ = cli.encrypt_payload({"type": "text", "text": "x"})
    req["ttl"] = 999999
    assert client.post("/api/v1/secrets", json=req).status_code == 422


def test_server_stores_no_plaintext_or_tokens(client):
    import asyncio
    data, key = _create(client, {"type": "text", "text": "TOPSECRET-123"})
    raw = asyncio.run(client.redis.get(f"safeshare:secret:{data['id']}"))
    assert "TOPSECRET" not in raw
    assert key not in raw
    assert data["delete_token"] not in raw
    assert cli.reveal_token(cli.from_b64url(key)) not in raw


def test_validation_and_limits(client):
    bad = {"v": 1, "ciphertext": "not base64!!" * 3, "iv": "AAAA", "reveal_token": "x", "ttl": 3600}
    assert client.post("/api/v1/secrets", json=bad).status_code == 422
    req, _ = cli.encrypt_payload({"type": "text", "text": "x"})
    req["ttl"] = 3600
    req["extra"] = 1
    assert client.post("/api/v1/secrets", json=req).status_code == 422
    r = client.post("/api/v1/secrets", content=b"x", headers={"content-length": "99999999"})
    assert r.status_code == 413


def test_uniform_404_and_headers(client):
    for url in ["/api/v1/secrets/../../etc", "/api/v1/secrets/short", "/nope"]:
        r = client.get(url)
        assert r.status_code == 404 and r.json() == {"detail": "not_found"}
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"].startswith("no-store")
    assert r.headers["referrer-policy"] == "no-referrer"
    assert 'integrity="sha384-' in r.text and "{{" not in r.text


def test_file_payload(client):
    import base64
    blob = bytes(range(256)) * 100
    data, key = _create(client, {"type": "file", "name": "c.p12", "mime": "application/x-pkcs12",
                                 "data": base64.b64encode(blob).decode()})
    resp = client.post(f"/api/v1/secrets/{data['id']}/reveal", headers=_rt(key)).json()
    assert base64.b64decode(cli.decrypt_payload(resp, key)["data"]) == blob


def test_icons_and_illustrations(client):
    assert client.get("/favicon.ico").headers["content-type"] == "image/x-icon"
    for f in ["icon.svg", "create.svg", "reveal.svg", "gone.svg", "apple-touch-icon.png", "icon-192.png", "icon-512.png"]:
        assert client.get(f"/static/img/{f}").status_code == 200, f
    assert client.get("/static/manifest.json").json()["short_name"] == "Safe Share"
    assert "manifest-src 'self'" in client.get("/").headers["content-security-policy"]
