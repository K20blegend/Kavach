import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services import url_audit
from app.services.network import FetchResult, UnsafeTarget, normalize_url


def passed(name):
    return url_audit._check(name, "pass", "Observed passing evidence.")


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    monkeypatch.setattr(url_audit, "get_settings", lambda: SimpleNamespace(dnsbl_zones=[]))
    monkeypatch.setattr(url_audit, "_BOOTSTRAP", None)


@pytest.mark.asyncio
async def test_missing_live_evidence_never_becomes_a_safe_verdict(monkeypatch):
    async def unavailable(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(url_audit, "resolve_public_host", unavailable)
    monkeypatch.setattr(url_audit, "_domain_age_check", unavailable)
    monkeypatch.setattr(url_audit, "_http_check", unavailable)
    result = await url_audit.audit_url("https://example.com/")
    assert result["verdict"] == "unknown"
    assert result["coverage"] == {"completed": 1, "total": 6}
    assert result["trust_score"] == 8
    assert all(check["status"] == "unknown" for check in result["checks"] if check["name"] != "hostname")
    assert result["trust_score"] == 10 - sum(check["penalty"] for check in result["checks"])


@pytest.mark.asyncio
async def test_successful_core_checks_report_coverage_and_optional_dnsbl(monkeypatch):
    async def resolve(hostname):
        return ["93.184.216.34"]

    async def age(*args):
        return passed("domain_age")

    async def tls(*args):
        return passed("tls")

    async def http(*args):
        return passed("http")

    monkeypatch.setattr(url_audit, "resolve_public_host", resolve)
    monkeypatch.setattr(url_audit, "_domain_age_check", age)
    monkeypatch.setattr(url_audit, "_tls_check", tls)
    monkeypatch.setattr(url_audit, "_http_check", http)
    result = await url_audit.audit_url("https://example.com/")
    assert result["verdict"] == "low_risk"
    assert result["trust_score"] == 10
    assert result["coverage"] == {"completed": 5, "total": 6}
    blocklist = next(check for check in result["checks"] if check["name"] == "dnsbl")
    assert blocklist["status"] == "unknown"
    assert blocklist["evidence"]["reason"] == "not_configured"


@pytest.mark.parametrize("hostname", ["paypa1.com", "gogle.com", "googel.com", "xn--ypal-43d9g.com"])
def test_known_lookalike_patterns_are_explained(hostname):
    result = url_audit._hostname_check(hostname)
    assert result["status"] == "fail"
    assert result["penalty"] > 0
    assert result["evidence"]["brand_matches"] or result["evidence"]["mixed_scripts"]


def test_known_official_domain_does_not_match_its_own_brand():
    assert url_audit._hostname_check("accounts.paypal.com")["status"] == "pass"


def test_unrecognised_public_suffix_is_not_misreported_as_an_ip():
    result = url_audit._hostname_check("example.unknownsuffix")
    assert result["status"] == "unknown"
    assert result["evidence"]["reason"] == "unrecognised_suffix"


def test_brand_in_subdomain_does_not_establish_ownership():
    result = url_audit._hostname_check("paypal.login.example.com")
    assert result["status"] == "warn"
    assert result["evidence"]["registered_domain"] == "example.com"
    assert result["evidence"]["brands_in_subdomain"] == ["paypal"]


@pytest.mark.asyncio
async def test_rdap_uses_registration_event_for_registered_domain(monkeypatch):
    calls = []
    recent = (datetime.now(UTC) - timedelta(days=7)).isoformat()

    async def fetch(url, **kwargs):
        calls.append(url)
        if "iana.org" in url:
            data = {"services": [[["com"], ["https://rdap.registry.com/"]]]}
        else:
            data = {
                "events": [
                    {"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": recent},
                ]
            }
        return FetchResult(url, 200, {}, json.dumps(data).encode(), [url])

    monkeypatch.setattr(url_audit, "safe_fetch", fetch)
    result = await url_audit._domain_age_check("login.accounts.example.com")
    assert result["status"] == "fail"
    assert result["evidence"]["age_days"] == 7
    assert calls[-1] == "https://rdap.registry.com/domain/example.com"
    # The bootstrap directory is reused, while registration evidence is refreshed.
    await url_audit._domain_age_check("example.com")
    assert sum("iana.org" in url for url in calls) == 1


@pytest.mark.asyncio
async def test_absent_rdap_registration_date_is_unknown(monkeypatch):
    async def fetch(url, **kwargs):
        data = (
            {"services": [[["com"], ["https://rdap.registry.com/"]]]} if "iana.org" in url else {"events": []}
        )
        return FetchResult(url, 200, {}, json.dumps(data).encode(), [url])

    monkeypatch.setattr(url_audit, "safe_fetch", fetch)
    result = await url_audit._domain_age_check("example.com")
    assert result["status"] == "unknown"


@pytest.mark.asyncio
async def test_http_detects_insecure_credentials_and_cross_domain_redirect(monkeypatch):
    async def fetch(url, **kwargs):
        return FetchResult(
            "https://other.com/login",
            200,
            {"content-type": "text/html"},
            b'<form action="http://other.com/submit"><input type="password"></form>',
            [url, "https://other.com/login"],
        )

    monkeypatch.setattr(url_audit, "safe_fetch", fetch)
    result = await url_audit._http_check("https://example.com/")
    assert result["status"] == "fail"
    assert result["evidence"]["cross_domain_redirect"] is True
    assert result["evidence"]["insecure_password_forms"] == 1
    assert result["penalty"] >= 3


@pytest.mark.asyncio
async def test_html_base_tag_is_used_when_inspecting_form_destination(monkeypatch):
    async def fetch(url, **kwargs):
        return FetchResult(
            url,
            200,
            {"content-type": "text/html"},
            b'<base href="http://other.com/"><form action="submit"><input type="password"></form>',
            [url],
        )

    monkeypatch.setattr(url_audit, "safe_fetch", fetch)
    result = await url_audit._http_check("https://example.com/")
    assert result["evidence"]["external_password_forms"] == 1
    assert result["evidence"]["insecure_password_forms"] == 1


@pytest.mark.asyncio
async def test_provider_error_codes_are_not_treated_as_blocklist_listings(monkeypatch):
    monkeypatch.setattr(
        url_audit, "get_settings", lambda: SimpleNamespace(dnsbl_zones=["blocklist.example.com"])
    )

    class Resolver:
        async def resolve(self, *args, **kwargs):
            return ["127.255.255.254"]

    monkeypatch.setattr(url_audit.dns.asyncresolver, "Resolver", Resolver)
    result = await url_audit._dnsbl_check(["93.184.216.34"])
    assert result["status"] == "unknown"
    assert result["penalty"] == 0


@pytest.mark.asyncio
async def test_real_listing_is_reported_with_provider_evidence(monkeypatch):
    monkeypatch.setattr(
        url_audit, "get_settings", lambda: SimpleNamespace(dnsbl_zones=["blocklist.example.com"])
    )
    queries = []

    class Resolver:
        async def resolve(self, name, *args, **kwargs):
            queries.append(name)
            return ["127.0.0.2"]

    monkeypatch.setattr(url_audit.dns.asyncresolver, "Resolver", Resolver)
    result = await url_audit._dnsbl_check(["93.184.216.34"])
    assert result["status"] == "fail"
    assert result["evidence"]["observations"][0]["listed"] is True
    assert queries == ["34.216.184.93.blocklist.example.com"]


@pytest.mark.asyncio
async def test_unsafe_http_redirect_propagates_to_request_validation(monkeypatch):
    async def resolve(hostname):
        return ["93.184.216.34"]

    async def age(*args):
        return passed("domain_age")

    async def tls(*args):
        return passed("tls")

    async def unsafe(*args):
        raise UnsafeTarget("Redirect attempted to reach a private IP")

    monkeypatch.setattr(url_audit, "resolve_public_host", resolve)
    monkeypatch.setattr(url_audit, "_domain_age_check", age)
    monkeypatch.setattr(url_audit, "_tls_check", tls)
    monkeypatch.setattr(url_audit, "_http_check", unsafe)
    with pytest.raises(UnsafeTarget):
        await url_audit.audit_url("https://example.com/")


def test_unicode_homograph_is_accepted_as_url_but_flagged_as_a_signal():
    url = normalize_url("https://раypal.com/")
    result = url_audit._hostname_check(url.split("/")[2])
    assert result["status"] == "fail"
    assert result["evidence"]["mixed_scripts"] == ["CYRILLIC", "LATIN"]
