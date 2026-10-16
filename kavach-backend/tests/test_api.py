from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.auth import access_token, make_session
from app.models import Scan, User
from app.services import message_analysis, url_audit


def register(client, email="person@example.com"):
    return client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "display_name": "Person",
            "password": "test-password-123",
        },
    )


def test_account_login_rotation_and_logout(client):
    account = register(client)
    assert account.status_code == 201
    tokens = account.json()
    headers = {"Authorization": "Bearer " + tokens["access_token"]}
    assert client.get("/api/v1/auth/me", headers=headers).json()["email"] == "person@example.com"
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "person@example.com", "password": "wrong"}
        ).status_code
        == 401
    )
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != tokens["refresh_token"]
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refreshed.json()["refresh_token"]}
        ).status_code
        == 401
    )


def test_password_change_revokes_sessions(client):
    tokens = register(client).json()
    headers = {"Authorization": "Bearer " + tokens["access_token"]}
    response = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={
            "current_password": "test-password-123",
            "new_password": "replacement-password-456",
        },
    )
    assert response.status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "person@example.com", "password": "test-password-123"}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "person@example.com", "password": "replacement-password-456"}
        ).status_code
        == 200
    )


def test_duplicate_accounts_and_password_hashing(client, db_session):
    assert register(client).status_code == 201
    assert register(client, "PERSON@example.com").status_code == 409
    user = db_session.scalar(select(User))
    assert user.password_hash.startswith("$argon2")
    assert "test-password-123" not in user.password_hash


def test_late_old_password_login_cannot_restore_a_revoked_generation(client, db_session):
    tokens = register(client).json()
    headers = {"Authorization": "Bearer " + tokens["access_token"]}
    user = db_session.scalar(select(User))
    stale_login = User(id=user.id, auth_version=user.auth_version)
    response = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={
            "current_password": "test-password-123",
            "new_password": "replacement-password-456",
        },
    )
    assert response.status_code == 204
    late_session, late_refresh = make_session(db_session, stale_login)
    db_session.commit()
    late_headers = {"Authorization": "Bearer " + access_token(late_session)}
    assert client.get("/api/v1/auth/me", headers=late_headers).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": late_refresh}).status_code == 401


def test_history_requires_explicit_opt_in_and_is_owner_scoped(client, auth_headers, monkeypatch):
    async def fake_audit(url):
        return {"url": url, "trust_score": 6.0, "verdict": "caution", "checks": []}

    monkeypatch.setattr(url_audit, "audit_url", fake_audit)
    anonymous = client.post("/api/v1/audits/url", json={"url": "https://example.com"})
    assert anonymous.status_code == 200
    assert anonymous.json()["id"] is None
    assert (
        client.post(
            "/api/v1/audits/url", json={"url": "https://example.com", "save_history": True}
        ).status_code
        == 401
    )
    saved = client.post(
        "/api/v1/audits/url",
        headers=auth_headers,
        json={"url": "https://example.com/private?token=secret", "save_history": True},
    )
    assert saved.status_code == 200
    scan_id = saved.json()["id"]
    items = client.get("/api/v1/history", headers=auth_headers).json()
    assert items["total"] == 1
    assert items["items"][0]["label"] == "example.com"
    other = register(client, "other@example.com").json()
    other_headers = {"Authorization": "Bearer " + other["access_token"]}
    assert client.get(f"/api/v1/history/{scan_id}", headers=other_headers).status_code == 404
    assert client.delete(f"/api/v1/history/{scan_id}", headers=other_headers).status_code == 404
    assert client.delete(f"/api/v1/history/{scan_id}", headers=auth_headers).status_code == 204
    assert client.get("/api/v1/history", headers=auth_headers).json()["total"] == 0


def test_expired_history_is_removed(client, auth_headers, db_session):
    user = db_session.scalar(select(User))
    db_session.add(
        Scan(
            user_id=user.id,
            kind="message",
            label="Old message",
            result={},
            created_at=datetime.now(UTC) - timedelta(days=31),
        )
    )
    db_session.commit()
    assert client.get("/api/v1/history", headers=auth_headers).json()["total"] == 0


def test_private_and_unsupported_urls_are_rejected(client):
    for url in [
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "http://example.com:8080",
    ]:
        response = client.post("/api/v1/audits/url", json={"url": url})
        assert response.status_code == 422, (url, response.text)


def test_message_endpoint_and_history_label(client, auth_headers, monkeypatch):
    async def fake_message(text, channel, raw_headers, inspect_links):
        assert not inspect_links
        return {"risk_score": 80, "verdict": "high_risk", "signals": []}

    monkeypatch.setattr(message_analysis, "analyze_message", fake_message)
    response = client.post(
        "/api/v1/audits/message",
        headers=auth_headers,
        json={"text": "private message content", "channel": "sms", "save_history": True},
    )
    assert response.status_code == 200
    summary = client.get("/api/v1/history", headers=auth_headers).json()["items"][0]
    assert summary["label"] == "Sms analysis"
    assert "private message" not in str(summary)


def test_body_limit_validation_and_security_headers(client):
    response = client.post(
        "/api/v1/audits/message",
        content=b"x" * 131073,
        headers={"Content-Type": "application/json", "Origin": "http://localhost:3000"},
    )
    assert response.status_code == 413
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    secret = "sensitive-short-password"
    response = client.post("/api/v1/auth/register", json={"email": "invalid", "password": secret})
    assert response.status_code == 422
    assert secret not in response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Request-ID"]
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/health", headers={"Host": "attacker.example"}).status_code == 400


def test_login_rate_limit(client):
    for _ in range(15):
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": "none@example.com", "password": "wrong"}
            ).status_code
            == 401
        )
    response = client.post("/api/v1/auth/login", json={"email": "none@example.com", "password": "wrong"})
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0
