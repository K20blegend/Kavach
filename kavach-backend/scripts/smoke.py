"""Exercise a running local API, including an actual public website audit."""

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = "http://127.0.0.1:8000"


def request(path: str, payload: dict | None = None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(BASE + path, data=body, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=35) as response:
        return json.load(response)


def main():
    assert request("/health/ready")["status"] == "ready"
    schema = request("/openapi.json")
    assert "/api/v1/audits/url" in schema["paths"]
    website = request("/api/v1/audits/url", {"url": "https://example.com", "save_history": False})
    assert website["id"] is None
    report = website["result"]
    assert len(report["checks"]) == 6
    assert 0 <= report["trust_score"] <= 10
    message = request("/api/v1/audits/message", {
        "channel": "sms",
        "text": "Urgent: your bank account will be blocked. Send your OTP now to verify your account.",
    })
    assert message["result"]["verdict"] == "high_risk"
    scenarios = request("/api/v1/training/scenarios")
    assert scenarios["total"] >= 10
    try:
        request("/api/v1/audits/url", {"url": "http://127.0.0.1"})
    except HTTPError as exc:
        assert exc.code == 422
    else:
        raise AssertionError("Private network request was accepted")
    print(json.dumps({
        "status": "passed",
        "website": {"verdict": report["verdict"], "trust_score": report["trust_score"],
                    "coverage": report["coverage"],
                    "checks": {check["name"]: check["status"] for check in report["checks"]}},
        "message_risk_score": message["result"]["risk_score"],
        "training_scenarios": scenarios["total"],
        "openapi_paths": len(schema["paths"]),
    }, indent=2))


if __name__ == "__main__":
    main()
