"""
ct_auditor.py

Stage 1: source trust. Answers "were the domains that served this training
data legitimate at collection time?" by diffing live CT-log state against a
stored baseline of known-good certificates.

THREAT MODEL (explicit, so scope isn't hand-wavy):

  Caught:
    - UNKNOWN_ISSUER   -- a new cert for the domain from a CA never seen in
                          the baseline (e.g. a misissued or fraudulently
                          obtained cert used to impersonate the source).
    - RECENTLY_ISSUED   -- a brand-new cert appearing outside the baseline
                          window, worth a manual look even if the issuer is
                          known (an attacker can also use a "known" CA).
    - UNEXPECTED_SANS   -- a cert covering hostnames that don't belong to the
                          audited domain, which can indicate a look-alike or
                          a cert that was issued too broadly.

  Out of scope (named, not solved):
    - Plain-HTTP sources: no cert exists to log, so CT gives no signal.
    - Misissuance that happened BEFORE the baseline was captured -- the
      baseline itself has to be trusted (trust-on-first-use).
    - A malicious but validly-certificated curator serving poisoned data
      over a perfectly legitimate cert -- this layer only checks
      *identity*, not *content*. Content trust is Stage 2's job.
"""

from __future__ import annotations

import json
import os

from cert_parser import extract_sans, is_recently_issued, normalize_cert_record
from ct_client import fetch_certificates

BASELINE_DIR = "data/baselines"


def load_baseline(domain: str) -> dict:
    path = os.path.join(BASELINE_DIR, f"{domain}.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def save_baseline(domain: str, records: dict) -> None:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = os.path.join(BASELINE_DIR, f"{domain}.json")
    with open(path, "w") as f:
        json.dump(records, f, indent=2)


def build_baseline(domain: str) -> dict:
    """
    Fetch and persist a baseline. If the fetch fails outright (crt.sh
    timeout/rate-limit), an existing saved baseline is left untouched rather
    than being overwritten with an empty result -- a failed fetch is not
    the same fact as "this domain has zero certificates."
    """
    raw_certs = fetch_certificates(domain)
    if raw_certs is None:
        existing = load_baseline(domain)
        if existing:
            return existing
        raise RuntimeError(
            f"could not fetch CT data for {domain} and no existing baseline to fall back on"
        )
    normalized = {r["fingerprint"]: r for r in (normalize_cert_record(c) for c in raw_certs)}
    save_baseline(domain, normalized)
    return normalized


def audit_domain(domain: str, recently_issued_days: int = 7) -> dict:
    """
    Returns {"status": "CLEAN"|"ANOMALIES"|"NO_BASELINE"|"FETCH_FAILED", "alerts": [...]}
    """
    baseline = load_baseline(domain)
    if not baseline:
        return {"status": "NO_BASELINE", "alerts": []}

    known_issuers = {r["issuer_ca_id"] for r in baseline.values()}
    known_fingerprints = set(baseline.keys())

    raw_certs = fetch_certificates(domain)
    if raw_certs is None:
        return {"status": "FETCH_FAILED", "alerts": []}
    alerts = []

    for raw in raw_certs:
        record = normalize_cert_record(raw)
        fp = record["fingerprint"]
        if fp in known_fingerprints:
            continue

        anomalies = []
        if record["issuer_ca_id"] not in known_issuers:
            anomalies.append("UNKNOWN_ISSUER")
        if is_recently_issued(record.get("not_before", ""), days=recently_issued_days):
            anomalies.append("RECENTLY_ISSUED")

        sans = extract_sans(record.get("name_value", ""))
        unexpected = [s for s in sans if domain not in s]
        if unexpected:
            anomalies.append(f"UNEXPECTED_SANS:{unexpected}")

        if anomalies:
            alerts.append({**record, "domain": domain, "anomalies": anomalies})

    return {"status": "ANOMALIES" if alerts else "CLEAN", "alerts": alerts}
