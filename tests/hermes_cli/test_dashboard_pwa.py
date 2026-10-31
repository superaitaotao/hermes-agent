"""PWA install support for the dashboard SPA.

The manifest and service worker exist so Chrome can offer "Install app" on the dashboard
origin: installability requires a manifest with name + 192/512 icons + start_url, and a
registered service worker with a fetch handler. Both must follow an ``X-Forwarded-Prefix``
reverse proxy and must never cache the token-injected index.html.
"""

import json

from fastapi import FastAPI
from starlette.testclient import TestClient

from hermes_cli import web_server


def _mounted(tmp_path, monkeypatch):
    dist = tmp_path / "web_dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "pwa").mkdir(parents=True)
    for name in ("icon-192.png", "icon-512.png"):
        (dist / "pwa" / name).write_bytes(b"\x89PNG\r\n\x1a\n")
    (dist / "index.html").write_text(
        "<html><head></head><body>Dashboard</body></html>", encoding="utf-8"
    )
    monkeypatch.setattr(web_server, "WEB_DIST", dist)
    monkeypatch.delenv("HERMES_SERVE_HEADLESS", raising=False)
    app = FastAPI()
    web_server.mount_spa(app)
    return TestClient(app)


def test_manifest_declares_an_installable_app(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)

    response = client.get("/manifest.webmanifest")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/manifest+json")
    manifest = response.json()
    assert manifest["name"] and manifest["short_name"]
    assert manifest["start_url"] == "/"
    assert manifest["scope"] == "/"
    assert manifest["display"] == "standalone"
    sizes = {icon["sizes"] for icon in manifest["icons"]}
    assert {"192x192", "512x512"} <= sizes
    assert all(icon["type"] == "image/png" for icon in manifest["icons"])


def test_manifest_icons_are_served_from_the_dist(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)

    manifest = client.get("/manifest.webmanifest").json()

    for icon in manifest["icons"]:
        served = client.get(icon["src"])
        assert served.status_code == 200, icon["src"]
        assert served.headers["content-type"] == "image/png"


def test_manifest_and_worker_follow_the_forwarded_prefix(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)
    headers = {"X-Forwarded-Prefix": "/hermes"}

    manifest = client.get("/manifest.webmanifest", headers=headers).json()
    worker = client.get("/sw.js", headers=headers)

    assert manifest["start_url"] == "/hermes/"
    assert manifest["scope"] == "/hermes/"
    assert all(icon["src"].startswith("/hermes/pwa/") for icon in manifest["icons"])
    # Scope must be allowed from where the worker is served.
    assert worker.headers["service-worker-allowed"] == "/hermes/"


def test_service_worker_handles_fetch_without_caching(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)

    response = client.get("/sw.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert "no-cache" in response.headers["cache-control"]
    body = response.text
    # A fetch handler is what makes the worker installable; nothing may be cached, because
    # the dashboard serves a per-session token inside index.html.
    assert "addEventListener('fetch'" in body
    assert "respondWith" not in body
    assert "caches.open" not in body


def test_index_declares_the_manifest_and_registers_the_worker(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)

    html = client.get("/chat").text

    assert '<link rel="manifest" href="/manifest.webmanifest"' in html
    assert "navigator.serviceWorker.register('/sw.js'" in html


def test_manifest_and_worker_are_reachable_without_a_session():
    # Chrome fetches the manifest, the icons and the worker script on its own schedule, and a
    # gated fetch answers with the login page — which fails the manifest parse and the worker
    # registration, so the app never becomes installable. None of these carry data.
    from hermes_cli.dashboard_auth.middleware import _path_is_public

    assert _path_is_public("/manifest.webmanifest")
    assert _path_is_public("/sw.js")
    assert _path_is_public("/pwa/icon-192.png")
    # The gate still holds everywhere else.
    assert not _path_is_public("/sessions")
    assert not _path_is_public("/api/sessions")


def test_index_registration_follows_the_forwarded_prefix(tmp_path, monkeypatch):
    client = _mounted(tmp_path, monkeypatch)

    html = client.get("/chat", headers={"X-Forwarded-Prefix": "/hermes"}).text

    assert '<link rel="manifest" href="/hermes/manifest.webmanifest"' in html
    assert "navigator.serviceWorker.register('/hermes/sw.js'" in html
    assert "scope:'/hermes/'" in html
