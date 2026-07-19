"""
eval_pipeline_fidelity.py

Real measurement, not an assertion: randomly tamper with one hop of a
4-stage pipeline in one of three ways and check whether audit_chain() catches
it. Reports actual detection counts per tamper type over N trials.
"""

from __future__ import annotations

import json
import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipeline_fidelity import (
    PipelineEnvelope,
    _records,
    audit_chain,
    build_pipeline,
    sign_envelope,
    state_hash,
)

N_TRIALS = 200


def tamper_action_mismatch(chain, sk):
    """Pick a non-genesis hop and make its declared action lie about its effect."""
    i = random.randint(1, len(chain) - 1)
    env = chain[i]
    forged = PipelineEnvelope(
        step_id=env.step_id,
        declared_action=env.declared_action,
        actor=env.actor,
        input_count=env.input_count,
        output_count=env.input_count,  # claim no change happened
        input_hash=env.input_hash,
        output_hash=env.input_hash,  # ...and no hash change either
        prev_envelope_hash=env.prev_envelope_hash,
    )
    sign_envelope(forged, sk)
    chain[i] = forged
    return chain, i


def tamper_input_mismatch(chain, sk):
    """A hop lies about what it received (data silently substituted upstream)."""
    i = random.randint(1, len(chain) - 1)
    env = chain[i]
    forged = PipelineEnvelope(
        step_id=env.step_id,
        declared_action=env.declared_action,
        actor=env.actor,
        input_count=env.input_count,
        output_count=env.output_count,
        input_hash=state_hash(_records(env.input_count, "swapped")),
        output_hash=env.output_hash,
        prev_envelope_hash=env.prev_envelope_hash,
    )
    sign_envelope(forged, sk)
    chain[i] = forged
    return chain, i


def tamper_untrusted_source(chain, sk, source_audit):
    """The COLLECT hop's declared source domain isn't Stage-1-clean."""
    env = chain[0]
    forged = PipelineEnvelope(
        step_id=env.step_id,
        declared_action=env.declared_action,
        actor=env.actor,
        input_count=env.input_count,
        output_count=env.output_count,
        input_hash=env.input_hash,
        output_hash=env.output_hash,
        prev_envelope_hash=env.prev_envelope_hash,
        source_domain="untrusted-mirror.example",
    )
    sign_envelope(forged, sk)
    chain[0] = forged
    return chain, 0


TAMPER_FNS = {
    "ACTION_MISMATCH": tamper_action_mismatch,
    "INPUT_MISMATCH": tamper_input_mismatch,
    "UNTRUSTED_SOURCE": tamper_untrusted_source,
}


def build_varied_clean_chain(sk, n_records, dedupe_keep_frac, filter_keep_frac, domain):
    """A genuinely honest chain, but with different scale/ratios each call --
    used to check for false positives across VARIATION, not just one fixed
    scenario replayed with a new key."""
    collected = _records(n_records, "raw")
    e1 = PipelineEnvelope(
        step_id="v1_collect",
        declared_action="COLLECT",
        actor="crawler-x",
        input_count=0,
        output_count=len(collected),
        input_hash=state_hash([]),
        output_hash=state_hash(collected),
        prev_envelope_hash="",
        source_domain=domain,
    )
    sign_envelope(e1, sk)

    n_deduped = max(1, round(n_records * dedupe_keep_frac))
    deduped = collected[:n_deduped]
    e2 = PipelineEnvelope(
        step_id="v2_dedupe",
        declared_action="DEDUPE",
        actor="dedupe-x",
        input_count=len(collected),
        output_count=len(deduped),
        input_hash=state_hash(collected),
        output_hash=state_hash(deduped),
        prev_envelope_hash=e1.chain_hash(),
    )
    sign_envelope(e2, sk)

    n_filtered = max(1, round(n_deduped * filter_keep_frac))
    filtered = deduped[:n_filtered]
    e3 = PipelineEnvelope(
        step_id="v3_filter",
        declared_action="FILTER_PII",
        actor="pii-x",
        input_count=len(deduped),
        output_count=len(filtered),
        input_hash=state_hash(deduped),
        output_hash=state_hash(filtered),
        prev_envelope_hash=e2.chain_hash(),
    )
    sign_envelope(e3, sk)

    transformed = [dict(r, text=r["text"] + " [normalized]") for r in filtered]
    e4 = PipelineEnvelope(
        step_id="v4_transform",
        declared_action="TRANSFORM",
        actor="norm-x",
        input_count=len(filtered),
        output_count=len(transformed),
        input_hash=state_hash(filtered),
        output_hash=state_hash(transformed),
        prev_envelope_hash=e3.chain_hash(),
    )
    sign_envelope(e4, sk)
    return [e1, e2, e3, e4]


def run_false_positive_sweep():
    source_audit = {"commoncrawl.org": {"status": "CLEAN"}, "huggingface.co": {"status": "CLEAN"}}
    sk = Ed25519PrivateKey.generate()

    record_counts = [10, 50, 100, 500, 1000]
    dedupe_keep_fracs = [1.0, 0.95, 0.8, 0.6]
    filter_keep_fracs = [0.99, 0.9, 0.7, 0.5]
    domains = ["commoncrawl.org", "huggingface.co"]

    trials = 0
    skipped_degenerate = 0
    false_positives = []
    for n in record_counts:
        for dk in dedupe_keep_fracs:
            for fk in filter_keep_fracs:
                for domain in domains:
                    n_deduped = max(1, round(n * dk))
                    n_filtered = max(1, round(n_deduped * fk))
                    if n_filtered >= n_deduped:
                        # rounding at small n means this "filter" would remove
                        # zero records -- not a genuine FILTER_PII claim, so
                        # it's not a valid clean scenario to test at all.
                        skipped_degenerate += 1
                        continue
                    chain = build_varied_clean_chain(sk, n, dk, fk, domain)
                    root_spec = {"allowed_source_domains": [domain], "max_total_records": n}
                    result = audit_chain(chain, source_audit, root_spec)
                    trials += 1
                    if result["status"] != "CLEAN":
                        false_positives.append(
                            {
                                "n": n,
                                "dedupe_keep": dk,
                                "filter_keep": fk,
                                "domain": domain,
                                "result": result,
                            }
                        )

    print(
        f"False-positive sweep: {trials} distinct honest configurations "
        f"(record counts {record_counts}, dedupe/filter ratios varied, 2 source domains; "
        f"{skipped_degenerate} degenerate rounding-only configs excluded)"
    )
    print(f"False positives: {len(false_positives)}/{trials}")
    if false_positives:
        print(json.dumps(false_positives[:3], indent=2))
    return trials, len(false_positives)


def run_eval():
    source_audit = {
        "commoncrawl.org": {"status": "CLEAN"},
        "untrusted-mirror.example": {"status": "ANOMALIES"},
    }
    root_spec = {"allowed_source_domains": ["commoncrawl.org"], "max_total_records": 500}
    sk = Ed25519PrivateKey.generate()

    # sanity: clean chain must produce zero alerts
    clean_chain, _ = build_pipeline(sk)
    clean_result = audit_chain(clean_chain, source_audit, root_spec)
    assert clean_result["status"] == "CLEAN", f"false positive on clean chain: {clean_result}"

    detected = {name: 0 for name in TAMPER_FNS}
    caught_by = {name: {} for name in TAMPER_FNS}

    for name, fn in TAMPER_FNS.items():
        for _ in range(N_TRIALS):
            chain, _ = build_pipeline(sk)
            if name == "UNTRUSTED_SOURCE":
                chain, idx = fn(chain, sk, source_audit)
            else:
                chain, idx = fn(chain, sk)
            result = audit_chain(chain, source_audit, root_spec)
            if result["status"] == "ANOMALIES":
                detected[name] += 1
                for check_name in ("chain_fidelity", "action_grounding", "transitive_fidelity"):
                    if result[check_name]:
                        caught_by[name][check_name] = caught_by[name].get(check_name, 0) + 1

    print(f"Clean-chain false positive check: {clean_result['status']} (expect CLEAN)")
    print(f"\nDetection over {N_TRIALS} trials per tamper type:")
    for name in TAMPER_FNS:
        rate = detected[name] / N_TRIALS * 100
        print(
            f"  {name}: {detected[name]}/{N_TRIALS} ({rate:.1f}%) -- caught by: {caught_by[name]}"
        )


if __name__ == "__main__":
    run_false_positive_sweep()
    print()
    run_eval()
