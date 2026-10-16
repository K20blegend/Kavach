"""Training content and persisted, single-submission exercises."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.database import Base


class TrainingAttempt(Base):
    __tablename__ = "training_attempts"
    __table_args__ = (UniqueConstraint("user_id", "scenario_id", name="uq_training_user_scenario"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(64))
    scenario_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    selected_indicator_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    xp_earned: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


def _element(element_id: str, kind: str, label: str, text: str, **details: Any) -> dict[str, Any]:
    return {"id": element_id, "type": kind, "label": label, "text": text, **details}


def _scenario(
    scenario_id: str,
    title: str,
    difficulty: str,
    channel: str,
    category: str,
    description: str,
    context: str,
    elements: list[dict[str, Any]],
    indicators: dict[str, str],
    lesson: str,
    safe_elements: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": scenario_id,
        "version": 1,
        "title": title,
        "difficulty": difficulty,
        "channel": channel,
        "category": category,
        "description": description,
        "estimated_minutes": {"easy": 2, "medium": 3, "hard": 4}[difficulty],
        "context": context,
        "elements": elements,
        "indicators": indicators,
        "safe_elements": safe_elements or {},
        "lesson": lesson,
    }


SCENARIOS: dict[str, dict[str, Any]] = {
    item["id"]: item
    for item in [
        _scenario(
            "bank-account-review",
            "An account review notice",
            "easy",
            "email",
            "account_security",
            "Review a message about access to a bank account.",
            "Your bank's official website is riverbank.example. Select every element that gives evidence of fraud.",
            [
                _element(
                    "sender", "sender", "From", "River Bank Security <security@riverbank-check.example>"
                ),
                _element("subject", "subject", "Subject", "Your account will be suspended in 30 minutes"),
                _element("greeting", "body", "Greeting", "Dear customer,"),
                _element(
                    "otp-request",
                    "body",
                    "Verification instructions",
                    "Reply with the OTP sent to your phone to stop the suspension.",
                ),
                _element("footer", "body", "Footer", "River Bank customer support"),
            ],
            {
                "sender": "The sender uses riverbank-check.example, a different domain from the bank's stated riverbank.example domain.",
                "subject": "The 30-minute suspension threat pressures you to act before checking the request.",
                "otp-request": "An OTP authorizes access or a transaction. A support message asking you to send it back is a credential theft attempt.",
            },
            "Open the bank's saved app or type its known address yourself. Never share an OTP with someone who contacts you.",
            {
                "greeting": "A generic greeting alone is weak evidence; legitimate bulk notices may use one.",
                "footer": "A company name in a footer can be copied, but is not independent evidence of fraud.",
            },
        ),
        _scenario(
            "delivery-fee",
            "A delivery update",
            "easy",
            "sms",
            "payments",
            "Decide whether a parcel text is safe to act on.",
            "You receive this text without expecting a delivery. Select the suspicious elements.",
            [
                _element("sender", "sender", "Sender", "+91 90000 00000"),
                _element("delivery", "body", "Delivery notice", "Your parcel is held at our sorting centre."),
                _element(
                    "deadline",
                    "body",
                    "Payment request",
                    "Pay a ₹5 redelivery fee within 15 minutes or the parcel will be destroyed.",
                ),
                _element(
                    "payment-link",
                    "link",
                    "Redelivery link",
                    "https://parcel-fee-support.example/pay",
                    href="https://parcel-fee-support.example/pay",
                ),
            ],
            {
                "deadline": "A tiny fee combined with a destruction threat and short deadline is a common card-harvesting lure.",
                "payment-link": "The payment domain does not identify a courier and was sent in an unexpected message; do not enter card details there.",
            },
            "Check the tracking number in the courier's official app or website before paying a delivery charge.",
            {
                "sender": "A telephone number alone does not establish fraud; delivery firms sometimes use ordinary numbers.",
                "delivery": "A parcel status statement by itself is not proof of a scam.",
            },
        ),
        _scenario(
            "cloud-sign-in",
            "A cloud account sign-in",
            "medium",
            "browser",
            "website_identity",
            "Inspect a sign-in screen reached from a shared document.",
            "Your organisation uses northcloud.example. Select suspicious elements on this simulated page.",
            [
                _element("address", "address", "Browser address", "https://n0rthcloud.example/signin"),
                _element("lock", "browser_chrome", "Connection", "Connection is encrypted"),
                _element("logo", "body", "Page branding", "Northcloud — Sign in"),
                _element("password", "form", "Password field", "Enter your work password"),
                _element(
                    "recovery", "form", "Additional verification", "Enter all recovery codes to continue"
                ),
            ],
            {
                "address": "n0rthcloud.example replaces the letter 'o' with zero. It is a different domain from northcloud.example.",
                "recovery": "Recovery codes bypass normal account verification. A sign-in page asking for all of them is trying to take over the account.",
            },
            "Check the complete domain before signing in. Encryption protects transport but does not establish who owns a website.",
            {
                "lock": "An encrypted connection is normal on both legitimate and fraudulent sites; the lock is not proof of identity.",
                "logo": "Branding is easy to copy and does not establish ownership on its own.",
                "password": "A password field is expected on a sign-in screen. The wrong domain and unusual recovery-code request provide the decisive evidence.",
            },
        ),
        _scenario(
            "upi-refund",
            "A marketplace refund",
            "easy",
            "chat",
            "payments",
            "Inspect instructions from a marketplace buyer.",
            "Someone claims they need to refund you ₹2,000 through UPI. Select each unsafe request.",
            [
                _element("greeting", "body", "Message", "Hello, I am sending your refund now."),
                _element(
                    "collect",
                    "body",
                    "Refund instructions",
                    "Accept my collect request for ₹2,000 to receive your money.",
                ),
                _element(
                    "pin",
                    "body",
                    "PIN instructions",
                    "Enter your UPI PIN and send a screenshot showing the PIN.",
                ),
                _element("reference", "body", "Order reference", "Order reference: MARKET-1042"),
            ],
            {
                "collect": "Accepting a collect request authorizes a payment from you; it is not a way to receive a refund.",
                "pin": "A UPI PIN authorizes money leaving your account. Never disclose it or enter it to receive money.",
            },
            "Receive money using your UPI ID without sharing a PIN. Verify refunds in the marketplace's own order history.",
            {
                "greeting": "A refund claim alone needs checking, but this sentence contains no specific unsafe instruction.",
                "reference": "An order reference can be genuine or invented and is not independent proof of fraud.",
            },
        ),
        _scenario(
            "investment-group",
            "An investment group invitation",
            "medium",
            "chat",
            "investment",
            "Examine an offer shared in a group chat.",
            "A new group member posts an investment offer. Select all concrete warning signs.",
            [
                _element(
                    "offer", "body", "Returns", "Guaranteed 8% profit every day with absolutely no risk."
                ),
                _element(
                    "deposit",
                    "body",
                    "Deposit instructions",
                    "Send the joining deposit to the administrator's personal UPI ID.",
                ),
                _element(
                    "deadline",
                    "body",
                    "Offer deadline",
                    "Only ten spots left. Transfer in the next 20 minutes; do not discuss this outside the group.",
                ),
                _element(
                    "graphic",
                    "attachment",
                    "Attachment",
                    "A colourful chart of rising prices",
                    filename="returns.png",
                ),
            ],
            {
                "offer": "Guaranteed high daily returns and a claim of no risk are inconsistent with how investments work.",
                "deposit": "A personal payment destination offers no verification that money is reaching a regulated investment service.",
                "deadline": "The deadline and secrecy demand are pressure tactics that prevent independent checks.",
            },
            "Independently check an investment provider and its registration, and seek advice before transferring money.",
            {"graphic": "A chart can be manipulated, but its appearance alone does not establish fraud."},
        ),
        _scenario(
            "shared-document",
            "A document sharing email",
            "hard",
            "email",
            "sender_authentication",
            "Compare sender details, routing information and a document link.",
            "Your colleague uses meadow.example. These are simulated headers and link details; select the mismatches that show impersonation.",
            [
                _element("from", "sender", "From", "Priya Sharma <priya@meadow.example>"),
                _element("reply-to", "header", "Reply-To", "priya@meadow-docs.example"),
                _element(
                    "auth",
                    "header",
                    "Authentication-Results",
                    "mx.meadow.example; spf=pass smtp.mailfrom=mailer.other.example; dmarc=fail header.from=meadow.example",
                ),
                _element(
                    "link",
                    "link",
                    "Open document",
                    "https://docs.meadow.example/report",
                    href="https://meadow-files.example/session",
                ),
                _element("subject", "subject", "Subject", "Please review the quarterly report"),
            ],
            {
                "reply-to": "Replies go to meadow-docs.example, not the colleague's meadow.example domain.",
                "auth": "SPF passed for a different sender domain, while DMARC failed for the visible From domain. SPF pass alone does not authenticate the displayed sender.",
                "link": "The displayed document URL and actual destination differ; the destination is meadow-files.example.",
            },
            "Inspect link destinations and authenticated domain alignment. Confirm an unexpected document through a separate known contact method.",
            {
                "from": "The visible From address matches the stated organisation, but this field can be spoofed; compare it with authenticated headers.",
                "subject": "An ordinary work subject is not independent evidence of impersonation.",
            },
        ),
        _scenario(
            "kyc-video-support",
            "A support call follow-up",
            "medium",
            "sms",
            "account_security",
            "Review an account verification request following a phone call.",
            "A caller claiming to be bank support sends these instructions. Select unsafe elements.",
            [
                _element(
                    "claim",
                    "body",
                    "Introduction",
                    "This is the account support team following up on our call.",
                ),
                _element(
                    "app",
                    "link",
                    "Support app",
                    "Install the remote-control app at https://assist-bank.example/help",
                    href="https://assist-bank.example/help",
                ),
                _element(
                    "access",
                    "body",
                    "Access request",
                    "Enable screen sharing and tell us the access code while your banking app is open.",
                ),
                _element(
                    "threat",
                    "body",
                    "Verification deadline",
                    "If you disconnect this call, your account will be blocked immediately.",
                ),
            ],
            {
                "app": "An unsolicited bank caller directing you to a remote-control app can gain control of your device.",
                "access": "Screen sharing and access codes can expose account details and allow someone else to operate your device.",
                "threat": "Threatening immediate blocking if you disconnect pressures you to avoid an independent call to the bank.",
            },
            "End unsolicited support calls and call the number printed on your card or inside the bank's official app.",
            {"claim": "A support claim must be verified, but the statement alone does not prove fraud."},
        ),
        _scenario(
            "password-change-notice",
            "A password change notice",
            "hard",
            "email",
            "account_security",
            "Evaluate an account notification using all available evidence.",
            "You changed your password five minutes ago. Your service's official domain is cedar.example. A scenario may contain no fraudulent elements.",
            [
                _element("from", "sender", "From", "Cedar Security <security@cedar.example>"),
                _element(
                    "auth",
                    "header",
                    "Authentication-Results",
                    "mx.example; spf=pass smtp.mailfrom=cedar.example; dkim=pass header.d=cedar.example; dmarc=pass header.from=cedar.example",
                ),
                _element(
                    "body",
                    "body",
                    "Notification",
                    "Your password was changed five minutes ago. If this was you, no action is needed.",
                ),
                _element(
                    "help",
                    "body",
                    "If this was not you",
                    "Open your saved Cedar app and review account activity. We will never ask for your password or verification codes by email.",
                ),
            ],
            {},
            "Use context and several signals together. This expected notification has aligned authentication and requests no secrets or risky action; no elements needed selecting.",
            {
                "from": "The sender domain matches the known service domain.",
                "auth": "The supplied authentication results show SPF, DKIM and DMARC aligned with cedar.example.",
                "body": "The timing matches an action you took and the message does not pressure you to act.",
                "help": "Opening your existing saved app is a safe way to check activity without following an unsolicited link.",
            },
        ),
        _scenario(
            "order-receipt",
            "An online store receipt",
            "medium",
            "email",
            "shopping",
            "Review a receipt after a purchase.",
            "You just bought a ₹799 book from willowbooks.example. A scenario may contain no fraudulent elements.",
            [
                _element("from", "sender", "From", "Willow Books <receipts@willowbooks.example>"),
                _element(
                    "order", "body", "Order details", "Order WB-4821: one book, total ₹799. Payment received."
                ),
                _element(
                    "link",
                    "link",
                    "Order status",
                    "https://willowbooks.example/orders/WB-4821",
                    href="https://willowbooks.example/orders/WB-4821",
                ),
                _element(
                    "support",
                    "body",
                    "Support note",
                    "For help, open the Support section in your Willow Books account. No additional payment is required.",
                ),
            ],
            {},
            "This receipt matches the purchase context and known domain, and asks for no additional payment or secrets. Avoid treating every ordinary link or receipt as fraud.",
            {
                "from": "The sender uses the known shop domain.",
                "order": "The amount and order details match your recent purchase.",
                "link": "The displayed URL and actual destination both use the stated official shop domain.",
                "support": "The message directs you to your account and does not ask for extra payment.",
            },
        ),
        _scenario(
            "invoice-attachment",
            "An invoice from a supplier",
            "hard",
            "email",
            "attachments",
            "Inspect a supplier email and its attachment instructions.",
            "You work with orbit-supplies.example and were expecting a PDF invoice. Select evidence of a dangerous request.",
            [
                _element("sender", "sender", "From", "Billing <billing@orbit-supplies.example>"),
                _element(
                    "attachment",
                    "attachment",
                    "Invoice attachment",
                    "Invoice_1047.pdf.html",
                    filename="Invoice_1047.pdf.html",
                ),
                _element(
                    "instruction",
                    "body",
                    "Viewing instructions",
                    "Open the attached file and enter your work email password to unlock the invoice.",
                ),
                _element(
                    "protection",
                    "body",
                    "Troubleshooting",
                    "If your browser blocks the file, disable its protection and try again.",
                ),
                _element("reference", "body", "Reference", "Supplier order ORB-1047"),
            ],
            {
                "attachment": "The final extension is .html, so the attachment is a web page disguised as a PDF and differs from the expected document type.",
                "instruction": "A supplier invoice should not need your work email password; this request can steal your credentials.",
                "protection": "Asking you to disable browser protection removes a security barrier to opening a potentially dangerous file.",
            },
            "Check full filenames, keep browser protection enabled, and verify unusual requests through a known supplier contact.",
            {
                "sender": "A familiar visible sender alone does not prove authenticity; the account may be spoofed or compromised.",
                "reference": "A matching order reference provides context but does not make unsafe instructions safe.",
            },
        ),
    ]
}

XP_BY_DIFFICULTY = {"easy": 40, "medium": 60, "hard": 90}
XP_PER_LEVEL = 200


def scenario_metadata(scenario: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "id",
        "version",
        "title",
        "description",
        "difficulty",
        "channel",
        "category",
        "estimated_minutes",
    )
    return {field: scenario[field] for field in fields}


def public_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        **scenario_metadata(scenario),
        "context": scenario["context"],
        "elements": deepcopy(scenario["elements"]),
        "instructions": "Select all elements that provide evidence of fraud. Submit an empty selection if none do. Each scenario awards XP once; your first submission is final.",
        "maximum_xp": XP_BY_DIFFICULTY[scenario["difficulty"]],
    }


def get_or_create_attempt(
    db: Session, user_id: str, scenario: dict[str, Any]
) -> tuple[TrainingAttempt, bool]:
    statement = select(TrainingAttempt).where(
        TrainingAttempt.user_id == user_id, TrainingAttempt.scenario_id == scenario["id"]
    )
    existing = db.scalar(statement)
    if existing is not None:
        return existing, False
    attempt = TrainingAttempt(
        user_id=user_id, scenario_id=scenario["id"], scenario_version=scenario["version"]
    )
    db.add(attempt)
    try:
        db.commit()
        db.refresh(attempt)
        return attempt, True
    except IntegrityError:
        db.rollback()
        existing = db.scalar(statement)
        if existing is None:
            raise
        return existing, False


def grade(scenario: dict[str, Any], selected_ids: list[str]) -> dict[str, Any]:
    selected = set(selected_ids)
    expected = set(scenario["indicators"])
    true_positives = selected & expected
    false_positives = selected - expected
    missed = expected - selected
    # The Jaccard score deducts both missed indicators and false alarms.
    union = selected | expected
    score = round(100 * len(true_positives) / len(union)) if union else 100
    xp_earned = round(XP_BY_DIFFICULTY[scenario["difficulty"]] * score / 100)
    labels = {element["id"]: element["label"] for element in scenario["elements"]}
    return {
        "score": score,
        "xp_earned": xp_earned,
        "maximum_xp": XP_BY_DIFFICULTY[scenario["difficulty"]],
        "correct_count": len(true_positives),
        "missed_count": len(missed),
        "false_positive_count": len(false_positives),
        "correct_indicator_ids": sorted(expected),
        "missed_indicator_ids": sorted(missed),
        "indicators": [
            {
                "id": indicator_id,
                "label": labels[indicator_id],
                "selected": indicator_id in selected,
                "explanation": explanation,
            }
            for indicator_id, explanation in scenario["indicators"].items()
        ],
        "false_positives": [
            {
                "id": element_id,
                "label": labels[element_id],
                "explanation": scenario["safe_elements"].get(
                    element_id,
                    "This element alone does not provide concrete evidence of fraud in this scenario.",
                ),
            }
            for element_id in sorted(false_positives)
        ],
        "lesson": scenario["lesson"],
        "scoring": "100 × correctly selected indicators / (all actual indicators + false positives). An empty selection scores 100 when there are no indicators.",
    }


def submit_attempt(
    db: Session, attempt: TrainingAttempt, selected_ids: list[str]
) -> tuple[TrainingAttempt, bool]:
    """Compare-and-set keeps concurrent submissions from changing a recorded result."""
    normalized = sorted(set(selected_ids))
    if attempt.submitted_at is not None:
        return attempt, normalized == sorted(attempt.selected_indicator_ids)
    scenario = SCENARIOS[attempt.scenario_id]
    result = grade(scenario, normalized)
    changed = db.execute(
        update(TrainingAttempt)
        .where(
            TrainingAttempt.id == attempt.id,
            TrainingAttempt.user_id == attempt.user_id,
            TrainingAttempt.submitted_at.is_(None),
        )
        .values(
            submitted_at=datetime.now(timezone.utc),
            selected_indicator_ids=normalized,
            score=result["score"],
            xp_earned=result["xp_earned"],
            result=result,
        )
        .execution_options(synchronize_session=False)
    ).rowcount
    db.commit()
    db.refresh(attempt)
    return attempt, bool(changed) or normalized == sorted(attempt.selected_indicator_ids)


def serialize_attempt(attempt: TrainingAttempt) -> dict[str, Any]:
    return {
        "id": attempt.id,
        "scenario_id": attempt.scenario_id,
        "scenario_version": attempt.scenario_version,
        "status": "submitted" if attempt.submitted_at else "in_progress",
        "created_at": attempt.created_at,
        "submitted_at": attempt.submitted_at,
        "selected_indicator_ids": attempt.selected_indicator_ids,
        "result": attempt.result if attempt.submitted_at else None,
    }


def user_progress(db: Session, user_id: str) -> dict[str, Any]:
    attempts = list(
        db.scalars(
            select(TrainingAttempt)
            .where(TrainingAttempt.user_id == user_id)
            .order_by(TrainingAttempt.created_at)
        )
    )
    completed = [attempt for attempt in attempts if attempt.submitted_at is not None]
    xp = sum(attempt.xp_earned for attempt in completed)
    level = 1 + xp // XP_PER_LEVEL
    earned_this_level = xp % XP_PER_LEVEL
    return {
        "total_xp": xp,
        "level": level,
        "xp_in_current_level": earned_this_level,
        "xp_to_next_level": XP_PER_LEVEL - earned_this_level,
        "xp_per_level": XP_PER_LEVEL,
        "completed_scenarios": len(completed),
        "total_scenarios": len(SCENARIOS),
        "in_progress_scenarios": len(attempts) - len(completed),
        "average_accuracy": round(sum(attempt.score or 0 for attempt in completed) / len(completed), 1)
        if completed
        else None,
        "perfect_scenarios": sum(attempt.score == 100 for attempt in completed),
        "completed_scenario_ids": [attempt.scenario_id for attempt in completed],
        "attempts": [serialize_attempt(attempt) for attempt in attempts],
    }
