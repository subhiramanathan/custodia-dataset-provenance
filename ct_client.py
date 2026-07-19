"""
ct_client.py

Stage 1 data source: queries crt.sh, which aggregates Certificate
Transparency log entries from all major CT logs (Google Argon, Cloudflare
Nimbus, DigiCert, etc.) into one queryable interface.
"""

from __future__ import annotations

import time

import requests

CT_SH_BASE = "https://crt.sh/"


def fetch_certificates(domain: str, include_subdomains: bool = True):
    """
    Query crt.sh for all certificates associated with a domain.

    Returns a list on success (possibly empty -- crt.sh genuinely has no
    records for the domain) or None if the fetch itself failed (timeout,
    HTTP error, non-JSON response from an overloaded/rate-limited crt.sh).
    Callers MUST distinguish "no certs" from "couldn't ask" -- crt.sh is a
    free public service that rate-limits and times out under load, and
    silently treating a failed fetch as "zero certs" would make a transient
    network hiccup look like a real anomaly (or worse, silently wipe a
    saved baseline).
    """
    query = f"%.{domain}" if include_subdomains else domain
    params = {"q": query, "output": "json"}

    for attempt in range(3):
        try:
            response = requests.get(CT_SH_BASE, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            time.sleep(2 ** attempt)
        except (requests.exceptions.JSONDecodeError, ValueError):
            # crt.sh returns an empty body (not "[]") when a query is in
            # progress/rate-limited -- retry rather than treating as zero.
            time.sleep(2 ** attempt)
        except requests.exceptions.RequestException:
            time.sleep(2 ** attempt)
    return None
