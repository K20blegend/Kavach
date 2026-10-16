from types import SimpleNamespace

import pytest

from app.services import message_analysis as messages


@pytest.mark.asyncio
async def test_credential_threat_has_original_case_offsets():
    text = "URGENT: Your account will be suspended. SHARE your OTP immediately with our security team."
    report = await messages.analyze_message(text, "sms")
    assert report["verdict"] == "high_risk"
    assert report["risk_score"] >= 55
    for signal in report["signals"]:
        for match in signal["matches"]:
            assert text[match["start"] : match["end"]] == match["text"]
    assert report["sender"]["authenticity"] == "unverified"


@pytest.mark.asyncio
async def test_marketing_urgency_alone_does_not_imply_scam():
    report = await messages.analyze_message(
        "Last chance! Limited time offer on our autumn collection.", "social"
    )
    assert report["verdict"] == "low_risk"
    assert report["risk_score"] <= 15


@pytest.mark.asyncio
async def test_do_not_share_warning_is_not_a_credential_request():
    report = await messages.analyze_message(
        "We will never ask you to share your password. Do not send your OTP to anyone."
    )
    assert "credential_request" not in {signal["category"] for signal in report["signals"]}
    assert report["risk_score"] == 0


@pytest.mark.asyncio
async def test_prize_with_advance_fee_is_high_risk():
    report = await messages.analyze_message(
        "You have won a cash prize. Pay a processing fee to claim your winnings."
    )
    assert report["verdict"] == "high_risk"
    assert {"financial_lure", "advance_fee"} <= {signal["category"] for signal in report["signals"]}


@pytest.mark.asyncio
async def test_extracts_links_and_does_not_visit_by_default(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError("Network inspection must be opt-in")

    monkeypatch.setattr(messages, "_inspect_links", fail_if_called)
    text = "Read (https://example.org/article?q=test). https://bit.ly/abc hxxps://training[.]example/login"
    report = await messages.analyze_message(text)
    assert [link["url"] for link in report["links"]] == [
        "https://example.org/article?q=test",
        "https://bit.ly/abc",
        "https://training.example/login",
    ]
    assert all(link["inspection"]["status"] == "not_requested" for link in report["links"])


@pytest.mark.asyncio
async def test_html_display_destination_mismatch():
    text = '<a href="https://fraud.example/pay?x=1&amp;y=2">https://bank.example/login</a>'
    report = await messages.analyze_message(text)
    assert any(signal["category"] == "link_mismatch" for signal in report["signals"])
    assert report["links"][0]["url"] == "https://fraud.example/pay?x=1&y=2"
    assert report["verdict"] == "caution"


@pytest.mark.asyncio
async def test_pasted_pass_and_dns_presence_are_not_authentication(monkeypatch):
    async def fake_txt(name):
        return "found", ["v=DMARC1; p=reject" if name.startswith("_dmarc") else "v=spf1 -all"]

    monkeypatch.setattr(messages, "_resolve_txt", fake_txt)
    report = await messages.analyze_message(
        "Meeting notes attached.",
        raw_headers=(
            "From: Support <support@example.com>\n"
            "Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass\n"
        ),
    )
    sender = report["sender"]
    assert sender["authenticity"] == "unverified"
    assert sender["dns_policies"]["spf"]["status"] == "present"
    assert sender["authentication_results"]["verified"] is False
    assert len(sender["authentication_results"]["claims"]) == 3
    assert report["risk_score"] == 0


@pytest.mark.asyncio
async def test_header_findings_contribute_to_risk_score(monkeypatch):
    async def fake_txt(name):
        return "not_found", []

    monkeypatch.setattr(messages, "_resolve_txt", fake_txt)
    report = await messages.analyze_message(
        "Please review.",
        raw_headers=(
            "From: Bank <support@bank.example.com>\n"
            "Reply-To: collector@different.example.org\n"
            "Authentication-Results: mx.example; spf=fail; dmarc=fail\n"
        ),
    )
    assert report["risk_score"] == 35
    assert report["verdict"] == "caution"
    assert all(not signal["matches"] for signal in report["signals"])


@pytest.mark.asyncio
async def test_dmarc_falls_back_to_organizational_domain(monkeypatch):
    queries = []

    async def fake_txt(name):
        queries.append(name)
        if name == "_dmarc.example.co.uk":
            return "found", ["v=DMARC1; p=reject"]
        return "not_found", []

    monkeypatch.setattr(messages, "_resolve_txt", fake_txt)
    report = await messages.analyze_message("Hello", raw_headers="From: sender@mail.example.co.uk\n")
    dmarc = report["sender"]["dns_policies"]["dmarc"]
    assert dmarc["status"] == "present"
    assert dmarc["organizational_fallback"] is True
    assert dmarc["domain"] == "_dmarc.example.co.uk"
    assert len(queries) == 3


@pytest.mark.asyncio
async def test_link_inspection_is_bounded_and_failures_are_unknown(monkeypatch):
    from app.services import network

    calls = []

    async def fake_fetch(url, **kwargs):
        calls.append(url)
        if "second" in url:
            raise OSError("unavailable")
        return SimpleNamespace(url=url + "/final", status=200, redirect_chain=[url, url + "/final"])

    monkeypatch.setattr(network, "safe_fetch", fake_fetch)
    report = await messages.analyze_message(
        "https://first.example.org https://second.example.org https://third.example.org https://fourth.example.org",
        inspect_links=True,
    )
    assert len(calls) == 3
    assert [link["inspection"]["status"] for link in report["links"]] == [
        "complete",
        "unknown",
        "complete",
        "skipped",
    ]


@pytest.mark.asyncio
async def test_private_destination_is_blocked_without_fetch(monkeypatch):
    from app.services import network

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("Private destination must not be fetched")

    monkeypatch.setattr(network, "safe_fetch", fail_if_called)
    report = await messages.analyze_message("https://127.0.0.1/secret", inspect_links=True)
    assert report["links"][0]["inspection"]["status"] == "blocked"


@pytest.mark.asyncio
async def test_bad_dns_is_unknown_and_body_is_not_echoed(monkeypatch):
    async def broken_dns(name):
        raise RuntimeError("resolver unavailable")

    monkeypatch.setattr(messages, "_resolve_txt", broken_dns)
    text = "Private meeting description with a sensitive reference 1234567."
    report = await messages.analyze_message(text, raw_headers="From: sender@example.com\n")
    assert report["sender"]["dns_policies"]["spf"]["status"] == "unknown"
    assert text not in str(report)


@pytest.mark.asyncio
async def test_malformed_url_does_not_crash_analysis():
    report = await messages.analyze_message("A broken link: https://[invalid/path")
    assert report["links"][0]["inspection"]["status"] == "not_requested"
    assert any(signal["category"] == "malformed_link" for signal in report["signals"])


@pytest.mark.asyncio
async def test_many_links_are_bounded_in_original_message_order():
    text = "hxxps://first[.]example/path " + " ".join(f"https://example.org/{index}" for index in range(500))
    report = await messages.analyze_message(text)
    assert len(report["links"]) == 20
    assert report["links"][0]["url"] == "https://first.example/path"
    assert report["links"][-1]["url"] == "https://example.org/18"


@pytest.mark.asyncio
async def test_oversized_link_is_truncated_and_never_visited(monkeypatch):
    from app.services import network

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("An incomplete address must not be visited")

    monkeypatch.setattr(network, "safe_fetch", fail_if_called)
    report = await messages.analyze_message("https://example.org/" + "a" * 10000, inspect_links=True)
    link = report["links"][0]
    assert len(link["url"]) == 2048
    assert link["truncated"] is True
    assert link["inspection"]["status"] == "skipped"


def test_unbalanced_trailing_punctuation_is_trimmed_in_one_pass():
    assert messages._trim_url("https://example.org/path" + ")" * 25000) == "https://example.org/path"
    assert messages._trim_url("https://example.org/a(b)") == "https://example.org/a(b)"
