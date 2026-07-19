"""
main.py

Runs the full three-layer dataset-custody auditor end to end, against a live
domain from config.yaml:

  Stage 1 (ct_auditor.py)        -- is the source domain CT-clean?
  Stage 2 (pipeline_fidelity.py) -- did every curation hop's declared action
                                     match its actual, verifiable effect, and
                                     does the chain trace back only to a
                                     Stage-1-clean source?
  Stage 3 (provenance_manifest.py) -- seal the final dataset + both audit
                                       results under one curator signature.
"""

from __future__ import annotations

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ct_auditor
from pipeline_fidelity import audit_chain, build_pipeline
from provenance_manifest import ProvenanceManifest, hash_record, sign_manifest, verify_manifest


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    domain = config["watchlist"][0]["domain"]
    days = config["audit"]["recently_issued_threshold_days"]
    root_spec = config["root_spec"]

    print(f"=== Stage 1: CT audit for {domain} ===")
    try:
        baseline = ct_auditor.build_baseline(domain)
        print(f"  baseline: {len(baseline)} certificate records captured")
    except RuntimeError as e:
        print(f"  {e}")
        baseline = {}
    stage1_result = ct_auditor.audit_domain(domain, recently_issued_days=days)
    print(f"  status: {stage1_result['status']} ({len(stage1_result['alerts'])} alerts)")
    source_audit = {domain: {"status": stage1_result["status"]}}

    print(f"\n=== Stage 2: pipeline fidelity for a curation run sourced from {domain} ===")
    sk = Ed25519PrivateKey.generate()
    chain, final_records = build_pipeline(sk, source_domain=domain)
    stage2_result = audit_chain(chain, source_audit, root_spec)
    print(f"  status: {stage2_result['status']}")
    print(f"  hops: {[e.step_id for e in chain]}")
    print(f"  final record count: {len(final_records)}")

    print("\n=== Stage 3: seal the dataset ===")
    leaves = [hash_record(r) for r in final_records]
    manifest = ProvenanceManifest(
        dataset_id=f"{domain}-curated-v1",
        record_hashes=leaves,
        source_audit=source_audit,
        pipeline_audit=stage2_result,
    ).finalize()
    curator_sk = Ed25519PrivateKey.generate()
    signed = sign_manifest(manifest, curator_sk)
    print(f"  merkle_root: {manifest.merkle_root[:16]}...")

    verification = verify_manifest(signed, leaves)
    print(f"  verification: {verification}")

    overall = (
        "CLEAN"
        if stage1_result["status"] == "CLEAN"
        and stage2_result["status"] == "CLEAN"
        and verification["provenance_ok"]
        and verification["integrity_ok"]
        else "REVIEW_NEEDED"
    )
    print(f"\n=== Overall: {overall} ===")


if __name__ == "__main__":
    main()
