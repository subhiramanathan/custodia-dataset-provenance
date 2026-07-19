"""
Unit tests for the pure, high-value functions: Merkle commitment/proof
(Stage 3) and per-hop action grounding, including MERGE, which was defined
but never exercised by any demo or eval trial before this file existed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from pipeline_fidelity import (  # noqa: E402
    PipelineEnvelope,
    check_action_grounding,
    check_chain_fidelity,
    sign_envelope,
    state_hash,
)
from provenance_manifest import (  # noqa: E402
    hash_record,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

# ------------------------------- Stage 3: Merkle ------------------------------


def test_merkle_root_is_deterministic():
    records = [{"id": i, "text": f"record {i}"} for i in range(5)]
    leaves = [hash_record(r) for r in records]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_merkle_root_changes_if_any_record_changes():
    records = [{"id": i, "text": f"record {i}"} for i in range(5)]
    leaves_a = [hash_record(r) for r in records]
    tampered = [dict(r) for r in records]
    tampered[2]["text"] = "tampered"
    leaves_b = [hash_record(r) for r in tampered]
    assert merkle_root(leaves_a) != merkle_root(leaves_b)


def test_merkle_root_rejects_empty_dataset():
    import pytest

    with pytest.raises(ValueError):
        merkle_root([])


def test_inclusion_proof_verifies_for_correct_leaf_and_fails_for_wrong_one():
    records = [
        {"id": i, "text": f"record {i}"} for i in range(7)
    ]  # odd count -> exercises duplication
    leaves = [hash_record(r) for r in records]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    assert verify_inclusion(leaves[3], proof, root) is True
    assert verify_inclusion(leaves[4], proof, root) is False  # wrong leaf, same proof


# ------------------------- Stage 2: action grounding --------------------------


def _sk():
    return Ed25519PrivateKey.generate()


def test_filter_action_passes_when_drop_is_within_bounds():
    sk = _sk()
    before = [{"id": i} for i in range(100)]
    after = before[:80]  # drop 20%, under the 50% suspicion threshold
    env = PipelineEnvelope(
        step_id="f1",
        declared_action="FILTER_PII",
        actor="pii-filter-1",
        input_count=100,
        output_count=80,
        input_hash=state_hash(before),
        output_hash=state_hash(after),
        prev_envelope_hash="",
    )
    sign_envelope(env, sk)
    assert check_action_grounding([env]) == []


def test_filter_action_flagged_when_it_is_actually_a_noop():
    """The bug this catches: a step claims FILTER_PII but count and hash are unchanged."""
    sk = _sk()
    before = [{"id": i} for i in range(100)]
    env = PipelineEnvelope(
        step_id="f2",
        declared_action="FILTER_PII",
        actor="pii-filter-1",
        input_count=100,
        output_count=100,
        input_hash=state_hash(before),
        output_hash=state_hash(before),
        prev_envelope_hash="",
    )
    sign_envelope(env, sk)
    violations = check_action_grounding([env])
    assert len(violations) == 1
    assert violations[0]["reason"] == "ACTION_MISMATCH"


def test_merge_action_passes_when_output_count_matches_declared_merge():
    """MERGE was defined in the rule table but never exercised anywhere before this test."""
    sk = _sk()
    before = [{"id": i} for i in range(80)]
    merged_in = [{"id": 1000 + i} for i in range(20)]
    after = before + merged_in
    env = PipelineEnvelope(
        step_id="m1",
        declared_action="MERGE",
        actor="merge-job-1",
        input_count=80,
        output_count=100,
        merged_batch_count=20,
        input_hash=state_hash(before),
        output_hash=state_hash(after),
        prev_envelope_hash="",
    )
    sign_envelope(env, sk)
    assert check_action_grounding([env]) == []


def test_merge_action_flagged_when_actor_lies_about_merged_batch_count():
    """MERGE gap, continued: actor claims it merged in 20 records but the count only grew by 5."""
    sk = _sk()
    before = [{"id": i} for i in range(80)]
    after = before + [{"id": 1000 + i} for i in range(5)]  # only 5 actually added
    env = PipelineEnvelope(
        step_id="m2",
        declared_action="MERGE",
        actor="merge-job-1",
        input_count=80,
        output_count=85,
        merged_batch_count=20,  # lied: claims 20
        input_hash=state_hash(before),
        output_hash=state_hash(after),
        prev_envelope_hash="",
    )
    sign_envelope(env, sk)
    violations = check_action_grounding([env])
    assert len(violations) == 1
    assert violations[0]["reason"] == "ACTION_MISMATCH"


# --------------------------- Stage 2: chain fidelity ---------------------------


def test_chain_fidelity_passes_for_two_honestly_linked_hops():
    sk = _sk()
    r0 = [{"id": i} for i in range(10)]
    r1 = r0[:8]
    e1 = PipelineEnvelope(
        step_id="c1",
        declared_action="DEDUPE",
        actor="dedupe-1",
        input_count=10,
        output_count=8,
        input_hash=state_hash(r0),
        output_hash=state_hash(r1),
        prev_envelope_hash="",
    )
    sign_envelope(e1, sk)
    e2 = PipelineEnvelope(
        step_id="c2",
        declared_action="DEDUPE",
        actor="dedupe-1",
        input_count=8,
        output_count=8,
        input_hash=state_hash(r1),
        output_hash=state_hash(r1),
        prev_envelope_hash=e1.chain_hash(),
    )
    sign_envelope(e2, sk)
    assert check_chain_fidelity([e1, e2]) == []


def test_chain_fidelity_catches_a_hop_lying_about_its_input():
    sk = _sk()
    r0 = [{"id": i} for i in range(10)]
    r1 = r0[:8]
    e1 = PipelineEnvelope(
        step_id="c1",
        declared_action="DEDUPE",
        actor="dedupe-1",
        input_count=10,
        output_count=8,
        input_hash=state_hash(r0),
        output_hash=state_hash(r1),
        prev_envelope_hash="",
    )
    sign_envelope(e1, sk)
    e2 = PipelineEnvelope(
        step_id="c2",
        declared_action="DEDUPE",
        actor="dedupe-1",
        input_count=8,
        output_count=8,
        input_hash=state_hash([{"id": "swapped"}]),  # doesn't match e1's real output
        output_hash=state_hash(r1),
        prev_envelope_hash=e1.chain_hash(),
    )
    sign_envelope(e2, sk)
    violations = check_chain_fidelity([e1, e2])
    assert any(v["reason"] == "INPUT_MISMATCH" for v in violations)
