"""
pipeline_fidelity.py

Stage 2: pipeline custody. Stage 1 (ct_auditor.py) asks "was the SOURCE
legitimate at collection time?" Stage 3 (provenance_manifest.py) asks "does
the FINAL dataset match what the curator signed?" Neither one can see INSIDE
the curation pipeline -- so a step that claims "deduped" but actually
injected records, or a "PII filter" that silently did nothing, passes both
checks undetected as long as the final signature is honest about the final
state. This module closes that gap.

PATTERN CREDIT: the idea of chaining signed, per-hop claims about "what this
step did" and verifying each hop against (a) the previous hop's actual
output and (b) the hop's declared action type is adapted from research on
detecting *intent laundering* in multi-agent delegation chains (an agent
mis-using legitimate authority at each individually-valid hop). This module
is an independent reimplementation of that pattern for data-curation
pipelines rather than agent tool calls -- no code was copied, and the
domain, schema, and rule set below are new.

Every curation step (collect / dedupe / filter / merge / transform) emits a
signed PipelineEnvelope claiming what it did. Three checks, mirroring the
three-stage structure of the source pattern:

  1. CHAIN FIDELITY     -- does this hop's signature verify, and does its
                            claimed input actually match the previous hop's
                            actual output? Catches a hop being reordered,
                            dropped, or fed swapped-in data.
  2. ACTION GROUNDING    -- does the hop's *observable effect* (record-count
                            delta, hash delta) match what its *declared*
                            action type is allowed to produce? Catches a step
                            that claims to filter/dedupe but actually did
                            something else (or nothing).
  3. TRANSITIVE FIDELITY -- does the whole chain still trace back only to
                            Stage-1-CLEAN sources, and does the final record
                            count stay within the declared root spec? Catches
                            drift from the ORIGINAL intent even when every
                            individual hop looks locally fine.

Out of scope (named, not solved): this only checks that declared actions are
*consistent* with their observable effects -- it cannot tell whether a
DEDUPE step deduped *correctly*, only that it didn't increase the record
count while claiming to. Content-level correctness is not addressed here.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from provenance_manifest import hash_record, merkle_root

# --------------------------- action rule table ------------------------------

MAX_FILTER_DROP_FRACTION = 0.5  # a filter dropping >50% of records in one hop is suspicious


def _rule_collect(ic, oc, ih, oh):
    return ic == 0 and oc > 0


def _rule_dedupe(ic, oc, ih, oh):
    return oc <= ic


def _rule_filter(ic, oc, ih, oh):
    if oc > ic or oh == ih:
        return False
    dropped_fraction = (ic - oc) / ic if ic else 0.0
    return dropped_fraction <= MAX_FILTER_DROP_FRACTION


def _rule_transform(ic, oc, ih, oh):
    return oc == ic and oh != ih


def _rule_noop(ic, oc, ih, oh):
    return oc == ic and oh == ih


ACTION_RULES = {
    "COLLECT": _rule_collect,
    "DEDUPE": _rule_dedupe,
    "FILTER_PII": _rule_filter,
    "FILTER_LANG": _rule_filter,
    "TRANSFORM": _rule_transform,
    "NOOP": _rule_noop,
    # MERGE is checked separately (needs merged_batch_count, see check_action_grounding)
}

# Which actor roles are provisioned to perform which action types. This is
# deliberately separate from ACTION_RULES: that table checks WHAT effect an
# action had; this checks WHO was allowed to claim it, regardless of whether
# the numbers look plausible. A compromised actor with a valid signing key
# can still satisfy ACTION_RULES perfectly while having no business
# performing that action at all.
DEFAULT_AUTHORIZATION_POLICY = {
    "COLLECT": ["crawler-*"],
    "DEDUPE": ["dedupe-*"],
    "FILTER_PII": ["*pii-filter*", "*pii*filter*"],
    "FILTER_LANG": ["*lang-filter*"],
    "TRANSFORM": ["normalize-*", "*normalize*"],
    "MERGE": ["merge-*"],
    "NOOP": ["*"],
}


# ------------------------------- envelope ------------------------------------


@dataclass
class PipelineEnvelope:
    step_id: str
    declared_action: str
    actor: str
    input_count: int
    output_count: int
    input_hash: str
    output_hash: str
    prev_envelope_hash: str
    source_domain: Optional[str] = None
    merged_batch_count: int = 0
    created_at: float = field(default_factory=time.time)
    signature: str = ""
    signer_pubkey: str = ""

    def payload(self) -> bytes:
        d = {k: v for k, v in self.__dict__.items() if k not in ("signature", "signer_pubkey")}
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    def chain_hash(self) -> str:
        """Hash of this envelope INCLUDING its signature -- what the next hop links to."""
        return hashlib.sha256(self.payload() + self.signature.encode()).hexdigest()


def sign_envelope(env: PipelineEnvelope, sk: Ed25519PrivateKey) -> PipelineEnvelope:
    env.signature = sk.sign(env.payload()).hex()
    env.signer_pubkey = (
        sk.public_key()
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        .hex()
    )
    return env


EMPTY_STATE_HASH = hashlib.sha256(b"EMPTY_DATASET_STATE").hexdigest()


def state_hash(records: list) -> str:
    """Merkle root over a list of dataset records -- reuses Stage 3's primitive
    so a pipeline envelope's output_hash is directly comparable to a Stage 3
    manifest's committed root. Empty input (genesis hop) uses a fixed sentinel
    since a Merkle tree isn't defined over zero leaves."""
    if not records:
        return EMPTY_STATE_HASH
    return merkle_root([hash_record(r) for r in records])


# ------------------------------- checks --------------------------------------


def check_chain_fidelity(chain: list) -> list:
    violations = []
    for i, env in enumerate(chain):
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env.signer_pubkey))
            pk.verify(bytes.fromhex(env.signature), env.payload())
        except Exception:
            violations.append({"step_id": env.step_id, "reason": "BAD_SIGNATURE"})
            continue

        if i == 0:
            if env.prev_envelope_hash != "":
                violations.append({"step_id": env.step_id, "reason": "GENESIS_HAS_PARENT"})
            continue

        prev = chain[i - 1]
        if env.prev_envelope_hash != prev.chain_hash():
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "CHAIN_LINK_BROKEN",
                    "detail": "prev_envelope_hash does not match actual previous envelope",
                }
            )
        if env.input_hash != prev.output_hash:
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "INPUT_MISMATCH",
                    "detail": (
                        "this hop's declared input does not match the previous hop's actual output"
                    ),
                }
            )
    return violations


def check_action_grounding(chain: list) -> list:
    violations = []
    for env in chain:
        if env.declared_action == "MERGE":
            ok = (
                env.output_count == env.input_count + env.merged_batch_count
                and env.output_hash != env.input_hash
            )
        else:
            rule = ACTION_RULES.get(env.declared_action)
            if rule is None:
                violations.append(
                    {"step_id": env.step_id, "reason": f"UNKNOWN_ACTION:{env.declared_action}"}
                )
                continue
            ok = rule(env.input_count, env.output_count, env.input_hash, env.output_hash)

        if not ok:
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "ACTION_MISMATCH",
                    "detail": (
                        f"declared={env.declared_action} in={env.input_count} "
                        f"out={env.output_count} "
                        f"hash_changed={env.input_hash != env.output_hash}"
                    ),
                }
            )
    return violations


def check_transitive_fidelity(chain: list, source_audit: dict, root_spec: dict) -> list:
    """
    root_spec = {"allowed_source_domains": [...], "max_total_records": int}
    source_audit = Stage 1 output, e.g. {"commoncrawl.org": {"status": "CLEAN", ...}, ...}
    """
    violations = []
    allowed = set(root_spec.get("allowed_source_domains", []))

    for env in chain:
        if env.declared_action != "COLLECT":
            continue
        domain = env.source_domain
        if domain not in allowed:
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "SOURCE_NOT_IN_ROOT_SPEC",
                    "detail": f"domain={domain} not in original allowed-source list",
                }
            )
            continue
        status = source_audit.get(domain, {}).get("status")
        if status != "CLEAN":
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "SOURCE_NOT_CT_CLEAN",
                    "detail": f"domain={domain} Stage-1 CT status={status!r}, not CLEAN",
                }
            )

    if chain:
        final_count = chain[-1].output_count
        max_allowed = root_spec.get("max_total_records")
        if max_allowed is not None and final_count > max_allowed:
            violations.append(
                {
                    "step_id": chain[-1].step_id,
                    "reason": "RECORD_COUNT_EXCEEDS_ROOT_SPEC",
                    "detail": f"final_count={final_count} > max_total_records={max_allowed}",
                }
            )
    return violations


def check_actor_authorization(chain: list, policy: dict = None) -> list:
    """
    Checks WHO was allowed to make a claim, independent of whether the claim's
    numbers are internally consistent. Kept as a standalone check (not folded
    into audit_chain) rather than a 4th key in that result dict, so adding it
    can't silently change the already-measured detection/false-positive
    numbers for the other three checks.
    """
    policy = policy if policy is not None else DEFAULT_AUTHORIZATION_POLICY
    violations = []
    for env in chain:
        allowed_patterns = policy.get(env.declared_action, [])
        if not any(fnmatch(env.actor, p) for p in allowed_patterns):
            violations.append(
                {
                    "step_id": env.step_id,
                    "reason": "UNAUTHORIZED_ACTOR",
                    "detail": f"actor={env.actor} is not provisioned for {env.declared_action}",
                }
            )
    return violations


def audit_chain(chain: list, source_audit: dict, root_spec: dict) -> dict:
    result = {
        "chain_fidelity": check_chain_fidelity(chain),
        "action_grounding": check_action_grounding(chain),
        "transitive_fidelity": check_transitive_fidelity(chain, source_audit, root_spec),
    }
    result["status"] = "CLEAN" if not any(result.values()) else "ANOMALIES"
    return result


# --------------------------------- demo --------------------------------------


def _records(n: int, tag: str, start: int = 0) -> list:
    return [{"id": start + i, "tag": tag, "text": f"{tag} record {start + i}"} for i in range(n)]


def build_pipeline(sk: Ed25519PrivateKey, source_domain: str = "commoncrawl.org"):
    """A realistic 4-hop pipeline: collect -> dedupe -> filter_pii -> transform.
    Returns (chain, final_records) so callers (e.g. Stage 3 sealing) can act
    on the actual output records, not just the envelope metadata."""
    chain = []
    prev_hash = ""

    collected = _records(500, "raw")
    e1 = PipelineEnvelope(
        step_id="s1_collect",
        declared_action="COLLECT",
        actor="crawler-job-17",
        input_count=0,
        output_count=len(collected),
        input_hash=state_hash([]),
        output_hash=state_hash(collected),
        prev_envelope_hash=prev_hash,
        source_domain=source_domain,
    )
    sign_envelope(e1, sk)
    chain.append(e1)
    prev_hash = e1.chain_hash()

    deduped = collected[:480]  # simulate removing 20 dupes
    e2 = PipelineEnvelope(
        step_id="s2_dedupe",
        declared_action="DEDUPE",
        actor="dedupe-job-3",
        input_count=len(collected),
        output_count=len(deduped),
        input_hash=state_hash(collected),
        output_hash=state_hash(deduped),
        prev_envelope_hash=prev_hash,
    )
    sign_envelope(e2, sk)
    chain.append(e2)
    prev_hash = e2.chain_hash()

    filtered = deduped[:430]  # simulate dropping 50 PII-flagged records
    e3 = PipelineEnvelope(
        step_id="s3_filter_pii",
        declared_action="FILTER_PII",
        actor="pii-filter-job-1",
        input_count=len(deduped),
        output_count=len(filtered),
        input_hash=state_hash(deduped),
        output_hash=state_hash(filtered),
        prev_envelope_hash=prev_hash,
    )
    sign_envelope(e3, sk)
    chain.append(e3)
    prev_hash = e3.chain_hash()

    transformed = [
        dict(r, text=r["text"] + " [normalized]") for r in filtered
    ]  # actually mutates content
    e4 = PipelineEnvelope(
        step_id="s4_transform",
        declared_action="TRANSFORM",
        actor="normalize-job-9",
        input_count=len(filtered),
        output_count=len(transformed),
        input_hash=state_hash(filtered),
        output_hash=state_hash(transformed),
        prev_envelope_hash=prev_hash,
    )
    sign_envelope(e4, sk)
    chain.append(e4)

    return chain, transformed


def _verdict(violations: list) -> None:
    """Plain-English summary line, printed before the JSON detail -- so the
    result reads at a glance even without narration or repo access."""
    if not violations:
        print("  VERDICT: CLEAN -- no violations")
        return
    for v in violations:
        detail = v.get("detail", "")
        print(f"  VERDICT: CAUGHT -- {v['reason']}: {detail}")


if __name__ == "__main__":
    sk = Ed25519PrivateKey.generate()
    source_audit = {
        "commoncrawl.org": {"status": "CLEAN"},
        "sketchy-mirror.example": {"status": "ANOMALIES"},
    }
    root_spec = {"allowed_source_domains": ["commoncrawl.org"], "max_total_records": 500}

    print("=== 1. Clean pipeline ===")
    chain, _ = build_pipeline(sk)
    result_1 = audit_chain(chain, source_audit, root_spec)
    print(
        "  VERDICT: CLEAN -- no violations"
        if result_1["status"] == "CLEAN"
        else "  VERDICT: ANOMALIES FOUND"
    )
    print(json.dumps(result_1, indent=2))

    print("\n=== 2. Laundered step: FILTER_PII declared, nothing actually filtered ===")
    laundered, _ = build_pipeline(sk)
    bad = laundered[2]
    bad.output_count = bad.input_count  # claims filtering happened, count unchanged
    bad.output_hash = bad.input_hash  # ...and nothing was actually removed
    result_2 = check_action_grounding(laundered)
    _verdict(result_2)
    print(json.dumps(result_2, indent=2))

    print("\n=== 3. Broken chain link: a hop's input doesn't match prior hop's real output ===")
    broken, _ = build_pipeline(sk)
    honest = broken[3]
    lying = PipelineEnvelope(
        step_id=honest.step_id,
        declared_action=honest.declared_action,
        actor=honest.actor,
        input_count=honest.input_count,
        output_count=honest.output_count,
        input_hash=state_hash(_records(430, "swapped-in")),  # false claim about what it received
        output_hash=honest.output_hash,
        prev_envelope_hash=honest.prev_envelope_hash,
    )
    sign_envelope(lying, sk)  # actor still holds a valid key -- signature alone can't catch this
    broken[3] = lying
    result_3 = check_chain_fidelity(broken)
    _verdict(result_3)
    print(json.dumps(result_3, indent=2))

    print("\n=== 4. Untrusted source: COLLECT from a domain Stage 1 did NOT clear ===")
    untrusted, _ = build_pipeline(sk)
    untrusted[0].source_domain = "sketchy-mirror.example"
    result_4 = check_transitive_fidelity(untrusted, source_audit, root_spec)
    _verdict(result_4)
    print(json.dumps(result_4, indent=2))

    print("\n=== 5. Unauthorized actor: right numbers, wrong role ===")
    unauthorized, _ = build_pipeline(sk)
    imposter_hop = unauthorized[2]  # the FILTER_PII hop
    imposter = PipelineEnvelope(
        step_id=imposter_hop.step_id,
        declared_action=imposter_hop.declared_action,
        actor="crawler-job-17",  # a COLLECT actor, never provisioned to filter PII
        input_count=imposter_hop.input_count,
        output_count=imposter_hop.output_count,
        input_hash=imposter_hop.input_hash,
        output_hash=imposter_hop.output_hash,
        prev_envelope_hash=imposter_hop.prev_envelope_hash,
    )
    sign_envelope(imposter, sk)  # a valid signature -- the numbers alone don't reveal the problem
    unauthorized[2] = imposter
    ag_result = check_action_grounding(unauthorized)
    print(f"  action_grounding: {ag_result} (numbers check out -- no violation here)")
    auth_result = check_actor_authorization(unauthorized)
    _verdict(auth_result)
    print(json.dumps(auth_result, indent=2))
