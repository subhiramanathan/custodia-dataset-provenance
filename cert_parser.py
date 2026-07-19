"""
cert_parser.py

Normalizes raw crt.sh records into the fields relevant to provenance
auditing, and produces a stable fingerprint per certificate.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def normalize_cert_record(raw: dict) -> dict:
    return {
        "id": raw.get("id"),
        "common_name": (raw.get("common_name") or "").strip(),
        "issuer_name": (raw.get("issuer_name") or "").strip(),
        "issuer_ca_id": raw.get("issuer_ca_id"),
        "not_before": raw.get("not_before"),
        "not_after": raw.get("not_after"),
        "entry_type": raw.get("entry_type"),
        "name_value": raw.get("name_value", ""),
        "fingerprint": _fingerprint(raw),
    }


def _fingerprint(raw: dict) -> str:
    key_fields = "|".join(
        [
            str(raw.get("id", "")),
            raw.get("common_name", "") or "",
            raw.get("issuer_name", "") or "",
            raw.get("not_before", "") or "",
            raw.get("not_after", "") or "",
        ]
    )
    return hashlib.sha256(key_fields.encode()).hexdigest()


def extract_sans(name_value: str) -> list:
    return [s.strip() for s in (name_value or "").replace("\n", " ").split() if s.strip()]


def is_recently_issued(not_before_str: str, days: int = 7) -> bool:
    if not not_before_str:
        return False
    try:
        not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - not_before
        return 0 <= delta.days <= days
    except Exception:
        return False
