# message security analyzer - heuristics, header inspection, and link safety

from __future__ import annotations

import asyncio
import html
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import idna
import tldextract

_extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
_DEFANGED_URL = re.compile(r"\bhxxps?://[^\s<>\"']+", re.IGNORECASE)
_ANCHOR = re.compile(
    r"<a\b[^>]{0,4096}\bhref\s*=\s*(?P<quote>[\"'])(?P<href>.{0,8192}?)(?P=quote)[^>]{0,4096}>"
    r"(?P<label>.{0,8192}?)</a\s*>",
    re.IGNORECASE | re.DOTALL,
)
_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "shorturl.at",
    "rebrand.ly",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
}
_MAX_LINKS = 20
_MAX_LINK_INSPECTIONS = 3
_MAX_URL_LENGTH = 2048
_FREE_WEBMAILS = {
    "gmail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "mail.ru",
    "yandex.com",
    "yandex.ru",
    "gmx.com",
    "gmx.net",
    "icloud.com",
    "me.com",
    "zoho.com",
}


@dataclass(frozen=True)
class _Rule:
    category: str
    label: str
    severity: str
    explanation: str
    weight: int
    pattern: re.Pattern[str]


def _rule(category: str, label: str, severity: str, explanation: str, weight: int, pattern: str) -> _Rule:
    return _Rule(category, label, severity, explanation, weight, re.compile(pattern, re.IGNORECASE))


_RULES = (
    _rule(
        "urgency",
        "Pressure to act quickly",
        "low",
        "Time pressure can discourage verification; ordinary promotions also use it.",
        8,
        r"\b(?:urgent(?:ly)?|immediately|act now|last chance|limited[- ]time|"
        r"within\s+\d+\s+(?:minutes?|hours?)|expires?\s+(?:today|soon|in\s+\d+\s+(?:minutes?|hours?)))\b",
    ),
    _rule(
        "account_threat",
        "Threat to an account or service",
        "high",
        "The message links an account restriction to taking action. Check through the official service.",
        22,
        r"\b(?:your\s+)?(?:account|card|wallet|access|service)\b[^.!?\n]{0,65}"
        r"\b(?:suspend(?:ed)?|block(?:ed)?|terminat(?:ed|ion)|clos(?:e|ed)|lock(?:ed)?|deactivat(?:e|ed))\b",
    ),
    _rule(
        "credential_request",
        "Request for a password, code, or recovery secret",
        "high",
        "Passwords, one-time codes, and wallet recovery phrases should not be shared with a sender.",
        35,
        r"\b(?:send|share|provide|enter|confirm|verify|disclose|reply\s+with|give(?:\s+us)?)\b"
        r"[^.!?\n]{0,65}\b(?:password|passcode|otp|one[- ]time\s+(?:password|code)|"
        r"verification\s+code|security\s+code|pin|seed\s+phrase|recovery\s+phrase|private\s+key)\b",
    ),
    _rule(
        "financial_data",
        "Request for sensitive financial details",
        "high",
        "Requests for full card or banking credentials require independent verification.",
        30,
        r"\b(?:send|share|provide|enter|confirm|verify|reply\s+with)\b[^.!?\n]{0,65}"
        r"\b(?:cvv|card\s+number|bank\s+(?:login|credentials)|online\s+banking\s+(?:password|details))\b",
    ),
    _rule(
        "authority_claim",
        "Claim of official authority",
        "medium",
        "The sender invokes an institution or support team; the text cannot establish that identity.",
        8,
        r"\b(?:official\s+(?:notice|notification|warning)|security\s+(?:team|department)|"
        r"(?:bank|microsoft|apple|google|paypal|amazon)\s+(?:support|security|verification)\s*(?:team|department)?|"
        r"income\s+tax\s+(?:department|office)|federal\s+(?:bureau|police)|police\s+(?:department|officer)|"
        r"government\s+(?:agency|department|notice))\b",
    ),
    _rule(
        "financial_lure",
        "Prize or unusually easy profit",
        "medium",
        "Unexpected winnings and guaranteed returns are common incentives in scams.",
        18,
        r"\b(?:you(?:'ve|\s+have)?\s+(?:won|been\s+selected)|lottery\s+(?:winner|prize)|"
        r"(?:cash|grand)\s+prize|guaranteed\s+(?:profit|returns?|income)|"
        r"risk[- ]free\s+(?:investment|returns?)|double\s+your\s+money)\b",
    ),
    _rule(
        "lottery_lure",
        "Lottery or jackpot winning lure",
        "high",
        "Unsolicited claims of winning a jackpot, lottery, or random drawing are classic advance-fee hooks.",
        35,
        r"\b(?:mega\s+millions|powerball|euro\s*millions|jackpot\s+winner|won\s+the\s+jackpot|"
        r"lottery\s+(?:winner|prize|drawing|draw|ticket|jackpot)|random\s+drawing|"
        r"(?:email|ticket|entry|name)\s+(?:was|has\s+been)\s+(?:selected|chosen)|"
        r"randomly\s+selected|lucky\s+(?:winner|number)|sweepstakes\s+(?:winner|prize))\b",
    ),
    _rule(
        "donation_scam",
        "Philanthropic donation or grant scam",
        "high",
        "Claims of multi-million dollar charitable donations or surprise cash grants are fraudulent.",
        35,
        r"\b(?:chosen\s+to\s+donate|donate\s+(?:a\s+total\s+of\s+)?(?:[$€£]|usd|eur|gbp|\d+\s*million)|"
        r"donation\s+(?:code|fund|grant|program|claim)|charity\s+(?:grant|donation|fund)|"
        r"grant\s+(?:of|award)\s+(?:[$€£]|usd|eur|\d)|philanthropic\s+donation|"
        r"unclaimed\s+(?:grant|lottery|funds?|inheritance)|humanitarian\s+(?:donation|grant|aid\s+fund))\b",
    ),
    _rule(
        "claim_instructions",
        "Instructions to claim funds or respond with code",
        "medium",
        "Prompts to reply with a verification/donation code or contact an unknown agent to claim money are standard advance-fee procedures.",
        25,
        r"\b(?:reply\s+with\s+(?:the\s+|your\s+)?(?:donation\s+code|claim\s+code|winning\s+code|code|details|information)|"
        r"reply\s+(?:to\s+this\s+email\s+)?to\s+(?:claim|receive|proceed|collect)|"
        r"contact\s+(?:our|my|the)\s+(?:agent|lawyer|barrister|fiduciary|manager|bank|representative)\s+to\s+proceed|"
        r"provide\s+your\s+(?:full\s+name|delivery\s+address|phone\s+number)\s+to\s+claim)\b",
    ),
    _rule(
        "inheritance_scam",
        "Inheritance or dormant fund claim",
        "high",
        "Unsolicited messages concerning an inheritance from an unknown deceased individual or dormant bank deposit are fraudulent.",
        35,
        r"\b(?:next\s+of\s+kin|deceased\s+(?:client|customer|relative|patron)|dormant\s+(?:account|funds?|deposit)|"
        r"unclaimed\s+(?:inheritance|estate|fortune|assets?)|consignment\s+(?:box|trunk|delivery)|"
        r"diplomatic\s+courier|safe[- ]deposit\s+box)\b",
    ),
    _rule(
        "package_delivery",
        "Package delivery or parcel exception",
        "medium",
        "Fake failed delivery or customs fee notices (FedEx, USPS, DHL) are common smishing/phishing hooks.",
        25,
        r"\b(?:package|parcel|shipment|delivery)\b[^.!?\n]{0,65}\b(?:on\s+hold|pending|delayed|undelivered|"
        r"incomplete\s+address|missing\s+house\s+number|pay\s+(?:customs|redelivery|shipping)\s+fee)\b",
    ),
    _rule(
        "payment_request",
        "Request to transfer money",
        "medium",
        "Verify unexpected payment instructions through a contact method you already trust.",
        18,
        r"\b(?:wire\s+(?:the\s+)?(?:money|funds)|(?:send|transfer)\s+(?:the\s+|us\s+)?(?:money|funds|payment)|"
        r"pay\s+(?:by|via|using|with)\s+(?:upi|bitcoin|crypto(?:currency)?|gift\s+cards?|wire\s+transfer)|"
        r"buy\s+(?:\w+\s+){0,2}gift\s+cards?)\b",
    ),
    _rule(
        "advance_fee",
        "Fee requested before a promised benefit",
        "high",
        "A fee to release a prize, loan, or payout is a strong warning sign, especially when unsolicited.",
        28,
        r"\b(?:(?:processing|release|activation|clearance|verification)\s+(?:fee|charge)s?|"
        r"pay\b[^.!?\n]{0,60}\b(?:to|before\s+you\s+can)\s+(?:receive|claim|unlock|release)\b"
        r"[^.!?\n]{0,35}\b(?:prize|winnings|loan|payout|funds|reward))\b",
    ),
    _rule(
        "secrecy",
        "Instruction to keep the request secret",
        "high",
        "Secrecy isolates the recipient from people who could help verify the request.",
        22,
        r"\b(?:keep\s+(?:this|it|the\s+(?:request|transaction))\s+(?:a\s+secret|confidential|secret)|"
        r"(?:do\s+not|don't|never)\s+(?:tell\s+(?:anyone|anybody|your\s+family)|contact\s+your\s+bank)|"
        r"do\s+not\s+discuss\s+this)\b",
    ),
    _rule(
        "legal_threat",
        "Threat of arrest or legal action",
        "high",
        "Threats of immediate punishment are often used to force a rushed payment or disclosure.",
        22,
        r"\b(?:arrest\s+warrant|you\s+will\s+be\s+arrested|legal\s+action\s+(?:will|shall)|"
        r"avoid\s+(?:arrest|prosecution)|criminal\s+charges\s+(?:will|shall))\b",
    ),
)


def _evidence(match: re.Match[str]) -> dict:
    return {"start": match.start(), "end": match.end(), "text": match.group()}


def _negated_request(text: str, match: re.Match[str]) -> bool:
    prefix = text[max(0, match.start() - 45) : match.start()]
    return bool(
        re.search(
            r"\b(?:never|not|don't|do\s+not|won't|will\s+not|would\s+not|should\s+not|"
            r"shouldn't|must\s+not|avoid)\s+(?:ever\s+)?(?:ask\s+you\s+to\s+)?$",
            prefix,
            re.IGNORECASE,
        )
    )


def _text_signals(text: str) -> tuple[list[dict], int, set[str]]:
    signals, score, categories = [], 0, set()
    for rule in _RULES:
        matches = []
        for match in rule.pattern.finditer(text):
            if rule.category in {
                "credential_request",
                "financial_data",
                "payment_request",
            } and _negated_request(text, match):
                continue
            matches.append(_evidence(match))
            if len(matches) == 8:
                break
        if matches:
            signals.append(
                {
                    "category": rule.category,
                    "label": rule.label,
                    "severity": rule.severity,
                    "explanation": rule.explanation,
                    "matches": matches,
                }
            )
            score += rule.weight
            categories.add(rule.category)
    if "urgency" in categories and categories & {
        "credential_request",
        "financial_data",
        "payment_request",
        "account_threat",
        "legal_threat",
    }:
        score += 15
    if "authority_claim" in categories and categories & {
        "credential_request",
        "financial_data",
        "account_threat",
        "legal_threat",
    }:
        score += 12
    if categories & {"financial_lure", "lottery_lure", "donation_scam", "inheritance_scam"} and categories & {
        "advance_fee",
        "claim_instructions",
        "payment_request",
    }:
        score += 20
    return signals, score, categories


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
        return idna.encode(host.rstrip("."), uts46=True).decode("ascii").lower() if host else None
    except (ValueError, idna.IDNAError):
        return None


def _organization(domain: str) -> str:
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        result = _extract_domain(domain)
        return f"{result.domain}.{result.suffix}" if result.suffix else domain


def _trim_url(value: str) -> str:
    value = value.rstrip(".,;:!")
    extra_closing = max(0, value.count(")") - value.count("("))
    trailing_closing = len(value) - len(value.rstrip(")"))
    trim = min(extra_closing, trailing_closing)
    if trim:
        value = value[:-trim]
    return value


def _links_and_signals(text: str) -> tuple[list[dict], list[dict], int]:
    links, signals, score = [], [], 0
    seen_spans = set()
    anchors = []
    for match in _ANCHOR.finditer(text):
        href = html.unescape(match.group("href")).strip()
        if not re.match(r"^https?://", href, re.IGNORECASE):
            continue
        label = html.unescape(re.sub(r"<[^>]*>", "", match.group("label"))).strip()[:300]
        anchors.append((match.start("href"), match.end("href"), label, href))
        if len(anchors) == _MAX_LINKS:
            break
    candidates = []
    for pattern, source in ((_URL, "body"), (_DEFANGED_URL, "defanged")):
        for match in pattern.finditer(text):
            candidates.append((match, source))
            if sum(candidate_source == source for _, candidate_source in candidates) == _MAX_LINKS:
                break
    candidates.sort(key=lambda candidate: candidate[0].start())
    for match, source in candidates[:_MAX_LINKS]:
        full_original = _trim_url(match.group())
        truncated = len(full_original) > _MAX_URL_LENGTH
        original = full_original[:_MAX_URL_LENGTH]
        url = html.unescape(original)
        if source == "defanged":
            url = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE).replace("[.]", ".")
        start, end = match.start(), match.start() + len(original)
        if (start, end) in seen_spans:
            continue
        seen_spans.add((start, end))
        link = {
            "url": url,
            "start": start,
            "end": end,
            "source": source,
            "inspection": {"status": "not_requested"},
        }
        if truncated:
            link["truncated"] = True
        for a_start, a_end, label, href in anchors:
            if a_start <= start < a_end:
                link.update(source="html_href", display_text=label, url=href[:_MAX_URL_LENGTH])
                if len(href) > _MAX_URL_LENGTH:
                    link["truncated"] = True
                if (
                    re.match(r"^https?://", label, re.IGNORECASE)
                    and _host(label)
                    and _host(label) != _host(href)
                ):
                    signals.append(
                        {
                            "category": "link_mismatch",
                            "label": "Displayed link differs from its destination",
                            "severity": "high",
                            "explanation": "The visible URL names a different host from the HTML link target.",
                            "matches": [{"start": start, "end": end, "text": text[start:end]}],
                        }
                    )
                    score += 25
                break
        links.append(link)
    links.sort(key=lambda link: link["start"])
    shortener_matches, credential_matches, malformed_matches = [], [], []
    for link in links:
        try:
            parsed = urlsplit(link["url"])
        except ValueError:
            malformed_matches.append(
                {"start": link["start"], "end": link["end"], "text": text[link["start"] : link["end"]]}
            )
            continue
        if _host(link["url"]) in _SHORTENERS:
            shortener_matches.append(
                {"start": link["start"], "end": link["end"], "text": text[link["start"] : link["end"]]}
            )
        if parsed.username is not None:
            credential_matches.append(
                {"start": link["start"], "end": link["end"], "text": text[link["start"] : link["end"]]}
            )
    if shortener_matches:
        signals.append(
            {
                "category": "shortened_link",
                "label": "A shortened link conceals the destination",
                "severity": "low",
                "explanation": "Short links are used by both legitimate senders and scammers. Their destination is not visible in the message.",
                "matches": shortener_matches[:8],
            }
        )
        score += 6
    if credential_matches:
        signals.append(
            {
                "category": "misleading_link",
                "label": "A link contains a user-information prefix",
                "severity": "high",
                "explanation": "Text before an @ in a web address is not the destination host and can make a link misleading.",
                "matches": credential_matches[:8],
            }
        )
        score += 22
    if malformed_matches:
        signals.append(
            {
                "category": "malformed_link",
                "label": "A web address could not be parsed",
                "severity": "low",
                "explanation": "The message contains an incomplete or malformed address. Its destination cannot be established from the text.",
                "matches": malformed_matches[:8],
            }
        )
        score += 6
    return links, signals, min(score, 45)


def _address(value: str | None) -> str | None:
    if not value:
        return None
    try:
        addresses = [address for _, address in getaddresses([value]) if "@" in address]
    except (ValueError, IndexError):
        return None
    return addresses[0][:320] if len(addresses) == 1 else None


def _address_domain(address: str | None) -> str | None:
    if not address:
        return None
    try:
        domain = address.rsplit("@", 1)[1].rstrip(".")
        domain = idna.encode(domain, uts46=True).decode("ascii").lower()
        if (
            len(domain) > 253
            or "." not in domain
            or any(not label or len(label) > 63 for label in domain.split("."))
        ):
            return None
        return domain
    except (ValueError, idna.IDNAError):
        return None


async def _resolve_txt(name: str) -> tuple[str, list[str]]:
    try:
        resolver = dns.asyncresolver.Resolver()
        answer = await resolver.resolve(name, "TXT", lifetime=2.5)
        records = [b"".join(record.strings).decode("utf-8", "replace")[:2000] for record in answer]
        return "found", records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "not_found", []
    except (dns.exception.DNSException, OSError, ValueError):
        return "unknown", []


async def _dns_policies(domain: str) -> dict:
    organization = _organization(domain)
    names = [domain, f"_dmarc.{domain}"]
    if organization != domain:
        names.append(f"_dmarc.{organization}")
    tasks = [asyncio.create_task(_resolve_txt(name)) for name in names]
    try:
        responses = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=3)
    except TimeoutError:
        responses = []
        for task in tasks:
            if task.done() and not task.cancelled() and task.exception() is None:
                responses.append(task.result())
            else:
                responses.append(("unknown", []))
    answers = {
        name: result if isinstance(result, tuple) else ("unknown", [])
        for name, result in zip(names, responses)
    }

    def policy_result(name: str, prefix: str) -> dict:
        status, records = answers.get(name, ("unknown", []))
        selected = [record for record in records if record.strip().lower().startswith(prefix)]
        return {
            "domain": name,
            "status": "present" if selected else "unknown" if status == "unknown" else "not_found",
            "record_count": len(selected),
        }

    spf = policy_result(domain, "v=spf1")
    dmarc = policy_result(f"_dmarc.{domain}", "v=dmarc1")
    if dmarc["status"] == "not_found" and organization != domain:
        dmarc = policy_result(f"_dmarc.{organization}", "v=dmarc1")
        dmarc["organizational_fallback"] = True
    else:
        dmarc["organizational_fallback"] = False
    return {"spf": spf, "dmarc": dmarc}


async def _sender_analysis(raw_headers: str | None) -> tuple[dict, list[dict], int]:
    sender = {
        "authenticity": "unverified",
        "from_address": None,
        "reply_to": None,
        "domain": None,
        "dns_policies": None,
        "authentication_results": {"verified": False, "source": "pasted_headers", "claims": []},
        "routing": {"received_hops": 0, "timestamps_observed": 0, "chronological_order_consistent": None},
    }
    if not raw_headers:
        return sender, [], 0
    try:
        headers = Parser(policy=policy.default).parsestr(raw_headers, headersonly=True)
        sender["from_address"] = _address(str(headers.get("From", "")))
        sender["reply_to"] = _address(str(headers.get("Reply-To", "")))
        sender["domain"] = _address_domain(sender["from_address"])
        subject = str(headers.get("Subject", "")).strip()
        if subject:
            sender["subject"] = subject
        received = headers.get_all("Received", [])
        auth_results = headers.get_all("Authentication-Results", [])
    except (ValueError, IndexError, TypeError):
        sender["parse_status"] = "malformed_headers"
        return sender, [], 0
    signals, score = [], 0
    from_domain, reply_domain = sender["domain"], _address_domain(sender["reply_to"])
    if from_domain and reply_domain and _organization(from_domain) != _organization(reply_domain):
        is_corp_to_free = from_domain not in _FREE_WEBMAILS and reply_domain in _FREE_WEBMAILS
        if is_corp_to_free:
            signals.append(
                {
                    "category": "reply_to_free_webmail",
                    "label": "Corporate sender redirects replies to free personal webmail",
                    "severity": "high",
                    "explanation": f"The message was sent from domain '{from_domain}', but directs replies to personal webmail '{sender['reply_to']}'. This is a strong indicator of advance-fee fraud or compromised email accounts.",
                    "matches": [],
                }
            )
            score += 35
        else:
            signals.append(
                {
                    "category": "reply_to_mismatch",
                    "label": "Replies go to a different organization",
                    "severity": "medium",
                    "explanation": f"From ({from_domain}) and Reply-To ({reply_domain}) use different organizational domains. Mailing services can do this legitimately; verify unexpected requests.",
                    "matches": [],
                }
            )
            score += 20

    from_raw = str(headers.get("From", ""))
    name_match = re.search(r'["\']?([^"\'<]+)["\']?\s*<([^>]+)>', from_raw)
    if name_match:
        disp_name = name_match.group(1).strip().lower()
        addr = sender["from_address"] or ""
        local_part = addr.split("@")[0].lower() if "@" in addr else ""
        if len(disp_name) >= 3 and disp_name not in local_part and local_part not in disp_name:
            signals.append(
                {
                    "category": "display_name_spoofing",
                    "label": "Sender display name does not match email mailbox",
                    "severity": "medium",
                    "explanation": f"The displayed sender name '{name_match.group(1).strip()}' does not match the actual mailbox '{addr}'.",
                    "matches": [],
                }
            )
            score += 15
    if len(headers.get_all("From", [])) > 1:
        signals.append(
            {
                "category": "ambiguous_sender",
                "label": "Multiple From headers",
                "severity": "medium",
                "explanation": "Multiple sender headers make the displayed identity ambiguous.",
                "matches": [],
            }
        )
        score += 15
    claims = []
    for value in auth_results[:5]:
        for mechanism, result in re.findall(
            r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
            str(value),
            re.IGNORECASE,
        ):
            claim = {"mechanism": mechanism.lower(), "result": result.lower()}
            if claim not in claims:
                claims.append(claim)
    sender["authentication_results"]["claims"] = claims[:15]
    if any(claim["result"] in {"fail", "softfail", "permerror"} for claim in claims):
        signals.append(
            {
                "category": "authentication_failure_claim",
                "label": "Pasted header reports an authentication problem",
                "severity": "medium",
                "explanation": "An Authentication-Results field reports failure, but pasted fields can be forged. This service has not independently authenticated the message.",
                "matches": [],
            }
        )
        score += 15
    dates: list[datetime] = []
    for value in received[:30]:
        try:
            parsed = parsedate_to_datetime(str(value).rsplit(";", 1)[1].strip())
            if parsed.tzinfo is not None:
                dates.append(parsed)
        except (ValueError, TypeError, IndexError, OverflowError):
            continue
    consistent = (
        all((newer - older).total_seconds() >= -1200 for newer, older in zip(dates, dates[1:]))
        if len(dates) >= 2
        else None
    )
    sender["routing"] = {
        "received_hops": len(received),
        "timestamps_observed": len(dates),
        "chronological_order_consistent": consistent,
    }
    if consistent is False:
        signals.append(
            {
                "category": "routing_anomaly",
                "label": "Routing timestamps appear out of order",
                "severity": "low",
                "explanation": "Received header timestamps are inconsistent. Clock errors and forged headers can both cause this; pasted routes are unverified.",
                "matches": [],
            }
        )
        score += 5
    if from_domain:
        sender["dns_policies"] = await _dns_policies(from_domain)
    return sender, signals, score


async def _inspect_link(link: dict) -> None:
    from app.services.network import UnsafeTarget, normalize_url, safe_fetch

    if link.get("truncated"):
        link["inspection"] = {
            "status": "skipped",
            "reason": "The address exceeds the 2048-character inspection limit.",
        }
        return
    if link["source"] == "defanged":
        link["inspection"] = {"status": "skipped", "reason": "Defanged links remain inert."}
        return
    try:
        target = normalize_url(link["url"])
        result = await safe_fetch(target, max_redirects=4, max_bytes=32768, timeout=6)
        link["inspection"] = {
            "status": "complete",
            "final_url": result.url,
            "http_status": result.status,
            "redirect_chain": result.redirect_chain,
        }
    except UnsafeTarget:
        link["inspection"] = {
            "status": "blocked",
            "reason": "The destination or a redirect is not a permitted public web address.",
        }
    except (TimeoutError, OSError, ValueError):
        link["inspection"] = {
            "status": "unknown",
            "reason": "The destination could not be inspected within the request limits.",
        }
    except Exception:
        link["inspection"] = {"status": "unknown", "reason": "Link inspection was unavailable."}


async def _inspect_links(links: list[dict]) -> None:
    tasks = [asyncio.create_task(_inspect_link(link)) for link in links[:_MAX_LINK_INSPECTIONS]]
    if tasks:
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=8)
        except TimeoutError:
            for link in links[:_MAX_LINK_INSPECTIONS]:
                if link["inspection"]["status"] == "not_requested":
                    link["inspection"] = {"status": "unknown", "reason": "Link inspection timed out."}
    for link in links[_MAX_LINK_INSPECTIONS:]:
        link["inspection"] = {
            "status": "skipped",
            "reason": "Only the first three links are inspected per request.",
        }


async def analyze_message(
    text: str, channel: str = "email", raw_headers: str | None = None, inspect_links: bool = False
) -> dict:
    # aggregate text signals, headers and embedded urls
    sender_task = asyncio.create_task(_sender_analysis(raw_headers))
    sender, sender_signals, sender_score = await sender_task

    analysis_text = f"{sender.get('subject', '')}\n\n{text}" if sender.get("subject") else text
    signals, score, categories = _text_signals(analysis_text)
    links, link_signals, link_score = _links_and_signals(analysis_text)
    if inspect_links:
        await _inspect_links(links)
    signals.extend(link_signals)
    signals.extend(sender_signals)
    score = min(100, score + link_score + sender_score)
    has_high = any(s.get("severity") == "high" for s in signals)
    verdict = "high_risk" if (score >= 45 or (has_high and score >= 35)) else "caution" if score >= 20 else "low_risk"
    recommendations = []
    if verdict == "high_risk":
        recommendations.append(
            "Pause before clicking, replying, or making a payment. Verify the request through the service's official app or a contact you already trust."
        )
    elif verdict == "caution":
        recommendations.append(
            "Verify unexpected requests independently before following instructions in this message."
        )
    else:
        recommendations.append(
            "No strong combination of scam patterns was found. Still verify unexpected requests independently."
        )
    if categories & {"credential_request", "financial_data"}:
        recommendations.append(
            "Do not send passwords, one-time codes, card security codes, or wallet recovery phrases to another person."
        )
    if categories & {"advance_fee", "payment_request", "financial_lure"}:
        recommendations.append(
            "Confirm the recipient and purpose before paying; do not pay a fee to release unexpected winnings."
        )
    if any(signal["category"] == "reply_to_mismatch" for signal in sender_signals):
        recommendations.append(
            "Check the full From and Reply-To addresses against an independently verified contact."
        )
    if links:
        recommendations.append(
            "Open the organization's known website or app directly when a message asks you to sign in."
        )
    limitations = [
        "Heuristic pattern detection; evaluate suspicious messages in full context.",
        "SPF/DMARC presence indicates domain policy, not that unverified pasted headers passed authentication.",
    ]
    if not raw_headers:
        limitations.append("Raw email headers were not provided; sender routing was skipped.")
    if links and not inspect_links:
        limitations.append("Embedded links extracted without scanning remote destinations.")
    return {
        "channel": channel,
        "risk_score": score,
        "verdict": verdict,
        "signals": signals,
        "links": links,
        "sender": sender,
        "recommendations": recommendations,
        "limitations": limitations,
    }
