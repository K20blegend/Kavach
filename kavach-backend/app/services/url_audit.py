# URL security audit service - checks DNS, reputation blocklists, TLS certs, and typosquatting

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import time
import unicodedata
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.resolver
import idna
import tldextract

from app.config import get_settings
from app.services.network import UnsafeTarget, normalize_url, resolve_public_host, safe_fetch

_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_BOOTSTRAP: tuple[float, dict] | None = None
_BRANDS = {
    "fitgirl-repacks": {"fitgirl-repacks.site"},
    "dodi-repacks": {"dodi-repacks.site"},
    "1337x": {"1337x.to"},
    "thepiratebay": {"thepiratebay.org"},
    "yts": {"yts.mx", "yts.rs", "yts.do"},
    "steamcommunity": {"steamcommunity.com"},
    "steampowered": {"steampowered.com"},
    "epicgames": {"epicgames.com"},
    "roblox": {"roblox.com"},
    "google": {"google.com", "google.co.in", "google.co.uk"},
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "github": {"github.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "telegram": {"telegram.org", "t.me"},
    "discord": {"discord.com", "discord.gg"},
    "twitter": {"twitter.com", "x.com"},
    "reddit": {"reddit.com"},
    "spotify": {"spotify.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
}
_HIGH_RISK_TLDS = {
    "to", "top", "xyz", "buzz", "click", "rest", "surf", "cfd", "sbs",
    "icu", "fit", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "work", "cam"
}
_SUSPICIOUS_STEMS = {
    "repack", "crack", "keygen", "warez", "download", "login", "signin",
    "verify", "secure", "update", "banking", "wallet", "airdrop", "claim"
}
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ӏ": "l",
        "ԁ": "d",
        "һ": "h",
        "ԛ": "q",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ν": "v",
        "ι": "i",
        "κ": "k",
        "τ": "t",
        "0": "o",
        "1": "l",
    }
)


def _check(name: str, status: str, summary: str, evidence: dict | None = None, penalty: float = 0) -> dict:
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "evidence": evidence or {},
        "penalty": penalty,
    }


def _unknown(name: str, summary: str, reason: str = "unavailable") -> dict:
    return _check(name, "unknown", summary, {"reason": reason}, 0 if name == "dnsbl" else 0.5)


def _registered_domain(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        extracted = _SUFFIXES(hostname)
        return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix and extracted.domain else None


def _distance(left: str, right: str) -> int:
    # quick damerau-levenshtein for typos and character swaps
    previous = list(range(len(right) + 1))
    before_previous = None
    for index, a in enumerate(left, 1):
        current = [index]
        for offset, b in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[offset] + 1, previous[offset - 1] + (a != b)))
            if before_previous is not None and offset > 1 and a == right[offset - 2] and left[index - 2] == b:
                current[-1] = min(current[-1], before_previous[offset - 2] + 1)
        before_previous = previous
        previous = current
    return previous[-1]


def _hostname_check(hostname: str) -> dict:
    registered = _registered_domain(hostname)
    if registered is None:
        try:
            ipaddress.ip_address(hostname)
            return _check("hostname", "warn", "The URL uses a raw IP address instead of a domain.", {"hostname": hostname}, 3.0)
        except ValueError:
            return _unknown("hostname", "The hostname has no recognised public suffix.", "unrecognised_suffix")

    decoded = idna.decode(hostname)
    ext = _SUFFIXES(hostname)
    label = idna.decode(ext.domain)
    tld = ext.suffix.lower()

    skeleton = "".join(
        char
        for char in unicodedata.normalize("NFKD", label.casefold().translate(_CONFUSABLES))
        if not unicodedata.combining(char)
    )
    clean_label = skeleton.replace("-", "").lower()
    raw_label = label.casefold().replace("-", "")
    collapsed_label = re.sub(r"(.)\1+", r"\1", raw_label)

    scripts = set()
    for char in label:
        if char.isalpha():
            for script in ("LATIN", "CYRILLIC", "GREEK"):
                if script in unicodedata.name(char, ""):
                    scripts.add(script)
    mixed = len(scripts) > 1

    matches = []
    penalty = 8.0 if mixed else 0.0
    status = "fail" if mixed else "pass"
    summary = "No brand lookalike or suspicious naming patterns found."

    for brand, domains in _BRANDS.items():
        if registered in domains:
            continue
        clean_brand = brand.replace("-", "").lower()
        brand_skeleton = "".join(
            char
            for char in unicodedata.normalize("NFKD", clean_brand.translate(_CONFUSABLES))
            if not unicodedata.combining(char)
        )
        collapsed_brand = re.sub(r"(.)\1+", r"\1", clean_brand)
        official_str = ", ".join(sorted(domains))

        # 1. Exact brand match on unauthorized domain/TLD (e.g. fitgirl-repacks.to vs .site)
        if raw_label == clean_brand or clean_label == brand_skeleton:
            matches.append({"brand": brand, "type": "unauthorized_clone", "official": sorted(domains)})
            penalty = max(penalty, 8.5)
            status = "fail"
            summary = f"Impostor clone detected: unauthorized mirror of '{brand}' (official: {official_str})."
            break

        # 2. Character duplication / clone (e.g. 13377x.com -> 1337x, gooogle.com -> google)
        if len(clean_brand) >= 4 and collapsed_label == collapsed_brand:
            matches.append({"brand": brand, "type": "character_duplication_clone", "official": sorted(domains)})
            penalty = max(penalty, 8.5)
            status = "fail"
            summary = f"Typosquatting clone detected: duplicated characters mimicking '{brand}' (official: {official_str})."
            break

        # 3. Typosquatting (distance <= 1 on raw or confusable skeleton)
        dist = min(_distance(raw_label, clean_brand), _distance(clean_label, brand_skeleton))
        if len(clean_brand) >= 4 and dist <= 1:
            matches.append({"brand": brand, "type": "typosquatting", "distance": dist, "official": sorted(domains)})
            penalty = max(penalty, 8.0)
            status = "fail"
            summary = f"Typosquatting detected: resembles '{brand}' (official: {official_str})."
            break

        # 4. Brand embedded with prefixes/suffixes (e.g. paypal-verify.com)
        if len(clean_brand) >= 4 and (
            clean_brand in raw_label or brand_skeleton in clean_label or any(part == brand for part in label.split("-"))
        ):
            matches.append({"brand": brand, "type": "impersonation", "official": sorted(domains)})
            penalty = max(penalty, 7.5)
            status = "fail"
            summary = f"Brand impersonation: uses protected brand '{brand}' without authorization."
            break

    subdomain = ext.subdomain
    embedded_sub = [b for b, doms in _BRANDS.items() if b in subdomain.split(".") and registered not in doms]
    if embedded_sub:
        penalty = max(penalty, 6.0)
        status = "fail"
        summary = f"Deceptive subdomain: brand '{embedded_sub[0]}' used in subdomain to disguise domain."

    if status == "pass" and tld in _HIGH_RISK_TLDS and any(stem in clean_label for stem in _SUSPICIOUS_STEMS):
        penalty = max(penalty, 4.0)
        status = "warn"
        summary = f"High-risk TLD (.{tld}) paired with suspicious keyword pattern."

    if status == "pass" and (label.count("-") >= 3 or len(label) > 35):
        penalty = max(penalty, 2.5)
        status = "warn"
        summary = "Unusually long or excessively hyphenated domain name."

    if mixed:
        summary = "Mixed-script homograph detected (uses lookalike Cyrillic/Greek characters)."

    return _check(
        "hostname",
        status,
        summary,
        {
            "unicode_hostname": decoded,
            "registered_domain": registered,
            "mixed_scripts": sorted(scripts) if mixed else [],
            "matches": matches,
            "high_risk_tld": tld in _HIGH_RISK_TLDS,
        },
        penalty,
    )


async def _domain_age_check(hostname: str) -> dict:
    global _BOOTSTRAP
    domain = _registered_domain(hostname)
    if domain is None:
        return _unknown(
            "domain_age",
            "No registrable domain was identified for a registration-age lookup.",
            "not_applicable",
        )
    if _BOOTSTRAP is None or time.monotonic() - _BOOTSTRAP[0] > 86400:
        response = await safe_fetch("https://data.iana.org/rdap/dns.json", max_bytes=1048576, timeout=3)
        if response.status != 200:
            return _unknown("domain_age", "The RDAP registry directory was unavailable.")
        bootstrap = json.loads(response.body)
        if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("services"), list):
            raise ValueError("Invalid RDAP bootstrap response")
        _BOOTSTRAP = time.monotonic(), bootstrap
    suffix = domain.rsplit(".", 1)[-1]
    bases = [
        base
        for names, urls in _BOOTSTRAP[1]["services"]
        if suffix in names
        for base in urls
        if isinstance(base, str) and base.startswith("https://")
    ]
    if not bases:
        return _unknown("domain_age", "This domain suffix has no supported RDAP registry.")
    response = await safe_fetch(
        urljoin(bases[0].rstrip("/") + "/", "domain/" + domain), max_bytes=262144, timeout=4
    )
    if response.status == 404:
        return _check(
            "domain_age",
            "fail",
            f"Domain '{domain}' is not registered in the authoritative registry (404 Not Found).",
            {"registered_domain": domain, "reason": "unregistered_domain"},
            5.0,
        )
    if response.status != 200:
        return _unknown(
            "domain_age",
            "The registry did not provide a domain registration record.",
            f"rdap_http_{response.status}",
        )
    record = json.loads(response.body)
    registrations = []
    for event in record.get("events", []):
        if event.get("eventAction") == "registration":
            date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            registrations.append(date.replace(tzinfo=UTC) if date.tzinfo is None else date)
    if not registrations:
        return _unknown("domain_age", "The registry record omits the original registration date.")
    registered = min(registrations)
    age = (datetime.now(UTC) - registered).days
    if age < 0:
        return _unknown("domain_age", "The registry supplied an inconsistent registration date.")
    status, penalty = ("fail", 5.0) if age < 30 else ("warn", 3.0) if age < 90 else ("warn", 1.5) if age < 180 else ("pass", 0)
    return _check(
        "domain_age",
        status,
        f"The domain was registered {age} days ago.",
        {
            "registered_domain": domain,
            "registration_date": registered.isoformat(),
            "age_days": age,
            "source": response.url,
        },
        penalty,
    )


async def _dnsbl_check(hostname: str, addresses: list[str]) -> dict:
    registered = _registered_domain(hostname) or hostname
    resolver = dns.asyncresolver.Resolver()

    # 1. Free security threat resolvers (Quad9 & Cloudflare Security)
    sec_threats = []
    for sec_ip, sec_name in [("9.9.9.9", "Quad9"), ("1.1.1.2", "Cloudflare Security")]:
        try:
            r = dns.asyncresolver.Resolver()
            r.nameservers = [sec_ip]
            ans = await r.resolve(hostname, "A", lifetime=1.5)
            ips = [str(a) for a in ans]
            if any(ip in {"0.0.0.0", "127.0.0.1"} for ip in ips):
                sec_threats.append(f"{sec_name} sinkhole ({ips[0]})")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            sec_threats.append(f"{sec_name} blocked")
        except Exception:
            pass

    if sec_threats:
        return _check(
            "dnsbl",
            "fail",
            f"Blocked by threat intelligence resolvers: {', '.join(sec_threats)}.",
            {"threat_resolvers": sec_threats},
            9.0,
        )

    # 2. Domain blocklists (Spamhaus DBL, SURBL)
    dbl_hits = []
    for dbl in ["dbl.spamhaus.org", "multi.surbl.org"]:
        try:
            ans = await resolver.resolve(f"{registered}.{dbl}", "A", lifetime=1.5)
            codes = [str(a) for a in ans]
            if any(c.startswith("127.") and not c.startswith("127.255.") for c in codes):
                dbl_hits.append({"zone": dbl, "codes": codes})
        except Exception:
            pass

    if dbl_hits:
        return _check(
            "dnsbl",
            "fail",
            f"Domain is listed on {dbl_hits[0]['zone']} threat blocklist.",
            {"dbl_hits": dbl_hits},
            8.5,
        )

    # 3. IP blocklists (Spamhaus ZEN, SpamCop)
    zones = get_settings().dnsbl_zones or ["zen.spamhaus.org", "bl.spamcop.net"]
    ipv4 = [address for address in addresses if ipaddress.ip_address(address).version == 4][:2]

    async def query_ip(address: str, zone: str):
        name = ".".join(reversed(address.split("."))) + "." + zone.strip().rstrip(".")
        try:
            answers = await resolver.resolve(name, "A", lifetime=1.5)
            codes = [str(answer) for answer in answers]
            listed = any(code.startswith("127.0.0.") and int(code.rsplit(".", 1)[-1]) >= 2 for code in codes)
            return {"ip": address, "zone": zone, "listed": listed, "codes": codes}
        except Exception:
            return {"ip": address, "zone": zone, "listed": False, "codes": []}

    ip_results = await asyncio.gather(*(query_ip(ip, z) for ip in ipv4 for z in zones[:2]), return_exceptions=True)
    ip_hits = [r for r in ip_results if isinstance(r, dict) and r.get("listed")]
    if ip_hits:
        return _check(
            "dnsbl",
            "fail",
            f"Host IP ({ip_hits[0]['ip']}) is listed on {ip_hits[0]['zone']}.",
            {"ip_hits": ip_hits},
            8.0,
        )

    return _check(
        "dnsbl",
        "pass",
        "Passed security resolvers (Quad9, Cloudflare) and domain/IP blocklists.",
        {"clean": True, "queried_ipv4": ipv4},
        0,
    )


def _inspect_tls(hostname: str, address: str, port: int) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=2) as connection:
        connection.settimeout(2)
        with context.wrap_socket(connection, server_hostname=hostname) as secured:
            certificate = secured.getpeercert()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), UTC)
            days = (expires - datetime.now(UTC)).days
            issuer = ", ".join(
                f"{key}={value}" for group in certificate.get("issuer", ()) for key, value in group
            )
            return _check(
                "tls",
                "warn" if days < 14 else "pass",
                f"The certificate validates for this hostname and expires in {days} days.",
                {
                    "expires_at": expires.isoformat(),
                    "days_remaining": days,
                    "issuer": issuer,
                    "protocol": secured.version(),
                    "hostname_verified": True,
                },
                1.5 if days < 14 else 0,
            )


async def _tls_check(url: str, addresses: list[str]) -> dict:
    parts = urlsplit(url)
    if parts.scheme == "http":
        return _check("tls", "warn", "The submitted URL uses unencrypted HTTP.", {"scheme": "http"}, 4.0)
    if not addresses:
        return _check("tls", "fail", "Certificate inspection failed: host has no public IP.", {"error": "no_address"}, 6.0)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_inspect_tls, parts.hostname or "", addresses[0], parts.port or 443), 4.5
        )
    except ssl.SSLCertVerificationError as exc:
        return _check(
            "tls",
            "fail",
            "The server certificate failed hostname or trust validation.",
            {"verification_code": exc.verify_code, "reason": exc.verify_message},
            6.0,
        )
    except Exception as exc:
        return _check(
            "tls",
            "fail",
            f"TLS handshake failed: {type(exc).__name__}",
            {"reason": str(exc)},
            5.0,
        )


class _PageSignals(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self.form: dict | None = None
        self.refresh = False
        self.base: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        values = dict(attrs)
        if tag == "form":
            self.form = {"action": values.get("action") or "", "password": False}
            self.forms.append(self.form)
        elif tag == "input" and (values.get("type") or "").lower() == "password" and self.form is not None:
            self.form["password"] = True
        elif tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            self.refresh = True
        elif tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]

    def handle_endtag(self, tag: str):
        if tag == "form":
            self.form = None


async def _http_check(url: str) -> dict:
    response = await safe_fetch(url, timeout=7)
    chain = response.redirect_chain
    domains = list(
        dict.fromkeys(
            _registered_domain(urlsplit(item).hostname or "") or urlsplit(item).hostname for item in chain
        )
    )
    downgrade = any(
        urlsplit(a).scheme == "https" and urlsplit(b).scheme == "http" for a, b in zip(chain, chain[1:])
    )
    penalty = 2 if downgrade else 0
    findings = []
    if downgrade:
        findings.append("A redirect downgraded HTTPS to HTTP.")
    if len(domains) > 1:
        findings.append("The redirect chain crosses registered domains.")
        penalty += 0.75
    parser = _PageSignals()
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type or response.body.lstrip()[:15].lower().startswith(
        (b"<!doctype html", b"<html")
    ):
        parser.feed(response.body.decode("utf-8", errors="replace"))
    insecure_forms = 0
    external_forms = 0
    page_host = urlsplit(response.url).hostname or ""
    page_identity = _registered_domain(page_host) or page_host
    for form in parser.forms:
        if not form["password"]:
            continue
        base = urljoin(response.url, parser.base) if parser.base else response.url
        action = urlsplit(urljoin(base, form["action"]))
        if action.scheme != "https":
            insecure_forms += 1
        if action.hostname and (_registered_domain(action.hostname) or action.hostname) != page_identity:
            external_forms += 1
    if insecure_forms:
        findings.append("A password form submits without HTTPS.")
        penalty += 3
    if external_forms:
        findings.append("A password form submits to a different registered domain.")
        penalty += 1
    if parser.refresh:
        findings.append("The page contains a browser-level refresh; its destination was not visited.")
    if response.status >= 400:
        findings.append(f"The server returned HTTP {response.status}; page inspection is limited.")
    status = "fail" if insecure_forms else "warn" if findings else "pass"
    return _check(
        "http",
        status,
        " ".join(findings) or "The bounded HTTP inspection found no configured redirect or form warning.",
        {
            "http_status": response.status,
            "final_url": response.url,
            "redirect_chain": chain,
            "cross_domain_redirect": len(domains) > 1,
            "https_downgrade": downgrade,
            "password_forms": sum(bool(form["password"]) for form in parser.forms),
            "insecure_password_forms": insecure_forms,
            "external_password_forms": external_forms,
            "meta_refresh": parser.refresh,
            "body_bytes_inspected": len(response.body),
            "body_limit_bytes": 262144,
        },
        min(5, penalty),
    )


async def _observe(name: str, operation, timeout: float = 8) -> dict:
    try:
        async with asyncio.timeout(timeout):
            return await operation
    except UnsafeTarget:
        raise
    except (TimeoutError, OSError, ValueError, KeyError, TypeError, ssl.SSLError) as exc:
        return _unknown(
            name, f"The {name.replace('_', ' ')} check could not be completed.", type(exc).__name__
        )
    except Exception as exc:
        # fallback for any weird network/parser exceptions
        return _unknown(
            name, f"The {name.replace('_', ' ')} check could not be completed.", type(exc).__name__
        )


async def audit_url(url: str) -> dict:
    url = normalize_url(url)
    hostname = urlsplit(url).hostname or ""
    addresses: list[str] = []
    dns_failed = False
    try:
        addresses = await resolve_public_host(hostname)
        dns_check = _check(
            "dns", "pass", f"Resolved to public IP: {addresses[0]}", {"addresses": addresses}
        )
    except UnsafeTarget:
        raise
    except (OSError, TimeoutError) as exc:
        dns_failed = True
        dns_check = _check(
            "dns",
            "fail",
            f"Domain '{hostname}' does not exist or has no DNS records (host unreachable).",
            {"error": type(exc).__name__, "hostname": hostname},
            10.0,
        )

    if dns_failed:
        # Non-existent or dead domain: score is 0.0 and verdict is high_risk
        checks = [
            dns_check,
            _check("dnsbl", "fail", "Cannot query blacklists: host does not resolve.", {"status": "unresolvable"}, 0),
            _check("domain_age", "fail", "Domain registration is missing, deleted, or unresolvable.", {"status": "unresolvable"}, 0),
            _check("tls", "fail", "TLS connection impossible: host does not resolve.", {"status": "unresolvable"}, 0),
            _hostname_check(hostname),
            _check("http", "fail", "HTTP connection impossible: host does not resolve.", {"status": "unresolvable"}, 0),
        ]
        return {
            "url": url,
            "hostname": hostname,
            "trust_score": 0.0,
            "verdict": "high_risk",
            "coverage": {"completed": 6, "total": 6},
            "checks": checks,
            "recommendations": [
                f"Domain '{hostname}' does not exist or has been taken down.",
                "Do not open, rely on, or enter credentials on unresolvable domains.",
                "If this was sent to you via message or email, it is likely a dead phishing link or spoofed URL."
            ],
            "limitations": [
                "Domain failed public DNS resolution (NXDOMAIN or network unreachable)."
            ],
        }

    results = await asyncio.gather(
        _observe("dnsbl", _dnsbl_check(hostname, addresses)),
        _observe("domain_age", _domain_age_check(hostname)),
        _observe("tls", _tls_check(url, addresses)),
        _observe("http", _http_check(url)),
    )
    checks = [dns_check, results[0], results[1], results[2], _hostname_check(hostname), results[3]]
    completed = sum(check["status"] != "unknown" for check in checks)

    score = round(max(0.0, 10.0 - sum(check["penalty"] for check in checks)), 2)
    has_fails = any(check["status"] == "fail" for check in checks)
    has_warns = any(check["status"] == "warn" for check in checks)

    # Any failed security check strictly caps the score at 2.5 max (high risk)
    if has_fails:
        score = min(score, 2.5)

    if score < 5.0 or has_fails:
        verdict = "high_risk"
    elif score < 7.5 or has_warns:
        verdict = "caution"
    elif completed >= 4:
        verdict = "low_risk"
    else:
        verdict = "unknown"
    recommendations = []
    if verdict in {"high_risk", "caution"}:
        recommendations.append(
            "Open the organisation's known official website yourself before entering credentials or making a payment."
        )
    if checks[4]["status"] != "pass":
        recommendations.append(
            "Compare the registered domain with a trusted bookmark; a brand name in a subdomain does not prove ownership."
        )
    if checks[3]["status"] in {"fail", "warn"}:
        recommendations.append(
            "Do not send passwords or payment details over HTTP or bypass certificate warnings."
        )
    if any(check["status"] == "unknown" for check in checks):
        recommendations.append(
            "Review the unavailable checks and repeat the inspection before relying on the result."
        )
    if not recommendations:
        recommendations.append(
            "Keep checking the destination and context before sharing sensitive information."
        )
    return {
        "url": url,
        "hostname": hostname,
        "trust_score": score,
        "verdict": verdict,
        "coverage": {"completed": completed, "total": len(checks)},
        "checks": checks,
        "recommendations": recommendations,
        "limitations": [
            "Heuristic risk score based on observed network signals, not an absolute guarantee.",
            "Lookalike detection checks high-profile targets and confusable characters; novel variations may vary.",
            "Inspection operates on static HTML (up to 256KB) and does not execute dynamic client JavaScript.",
        ],
    }
