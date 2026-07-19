"""
provenance_manifest.py

Stage 2 of the dataset-custody auditor: a signed, hash-linked provenance
manifest for a training dataset.

Where Stage 1 (the CT-log auditor) answers "were the SOURCES that served this
data trustworthy at crawl time?", Stage 2 answers "has the data been altered as
it moved through the pipeline, and can a downstream consumer VERIFY that?"

Design (all standard, well-understood primitives -- no ZKP required):
  * Each record is hashed (SHA-256).
  * Records are combined into a Merkle tree; the Merkle root commits to the
    entire dataset in a single hash. Any change to any record changes the root.
  * The manifest binds: dataset id, the CT-audit result per source (Stage 1
    output), the Merkle root, and a timestamp.
  * The curator SIGNS the manifest with an Ed25519 key (attestation of
    provenance -- "I, this curator, vouch for exactly this dataset").
  * A verifier checks (a) the signature (provenance / who) and (b) that the data
    still matches the Merkle root (integrity / unaltered), and can produce a
    Merkle inclusion proof for any single record without revealing the rest.

Honest limit (the senior point to narrate): a signature proves CUSTODY and
INTEGRITY, not CLEANLINESS. A curator can sign a genuinely-poisoned dataset and
every check passes. Attestation moves trust from the data to the curator; it
does not manufacture trust. Closing that gap needs multi-party attestation,
reputation, or content-level checks -- future work.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# ----------------------------- hashing helpers -----------------------------


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_record(record: dict) -> str:
    """Deterministic hash of a single dataset record."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return _h(canonical)


# ----------------------------- Merkle tree ---------------------------------


def _merkle_parent(left: str, right: str) -> str:
    return _h(bytes.fromhex(left) + bytes.fromhex(right))


def build_merkle(leaves: list[str]) -> list[list[str]]:
    """
    Build a Merkle tree from leaf hashes. Returns the full tree as a list of
    levels, level[0] = leaves ... level[-1] = [root]. Odd nodes are duplicated.
    """
    if not leaves:
        raise ValueError("cannot build a Merkle tree over zero records")
    tree = [leaves[:]]
    while len(tree[-1]) > 1:
        cur = tree[-1]
        if len(cur) % 2 == 1:
            cur = cur + [cur[-1]]  # duplicate last if odd
        nxt = [_merkle_parent(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
        tree.append(nxt)
    return tree


def merkle_root(leaves: list[str]) -> str:
    return build_merkle(leaves)[-1][0]


def inclusion_proof(leaves: list[str], index: int) -> list[dict]:
    """
    Produce a Merkle inclusion proof for the leaf at `index`: the sibling hashes
    needed to recompute the root. Lets a verifier confirm one record is in the
    committed dataset WITHOUT being given the whole dataset.
    """
    tree = build_merkle(leaves)
    proof = []
    idx = index
    for level in tree[:-1]:
        lvl = level[:]
        if len(lvl) % 2 == 1:
            lvl = lvl + [lvl[-1]]
        sib = idx ^ 1  # sibling index
        proof.append({"hash": lvl[sib], "position": "right" if sib > idx else "left"})
        idx //= 2
    return proof


def verify_inclusion(leaf: str, proof: list[dict], root: str) -> bool:
    cur = leaf
    for step in proof:
        if step["position"] == "right":
            cur = _merkle_parent(cur, step["hash"])
        else:
            cur = _merkle_parent(step["hash"], cur)
    return cur == root


# ----------------------------- manifest ------------------------------------


@dataclass
class ProvenanceManifest:
    dataset_id: str
    record_hashes: list[str]
    source_audit: dict  # <-- Stage 1 (CT auditor) result plugs in here
    pipeline_audit: dict = field(
        default_factory=dict
    )  # <-- Stage 2 (pipeline fidelity) result plugs in here
    merkle_root: str = ""
    created_at: float = field(default_factory=time.time)

    def finalize(self) -> "ProvenanceManifest":
        self.merkle_root = merkle_root(self.record_hashes)
        return self

    def signing_payload(self) -> bytes:
        """Exact bytes that get signed -- binds root + sources + pipeline chain + identity."""
        return json.dumps(
            {
                "dataset_id": self.dataset_id,
                "merkle_root": self.merkle_root,
                "n_records": len(self.record_hashes),
                "source_audit": self.source_audit,
                "pipeline_audit": self.pipeline_audit,
                "created_at": self.created_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign_manifest(m: ProvenanceManifest, sk: Ed25519PrivateKey) -> dict:
    sig = sk.sign(m.signing_payload())
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    return {
        "manifest": json.loads(m.signing_payload()),
        "signature": sig.hex(),
        "curator_pubkey": pk.hex(),
    }


def verify_manifest(signed: dict, record_hashes: list[str]) -> dict:
    """
    Full verification:
      1. provenance -- signature valid under the claimed curator key?
      2. integrity  -- do the actual records still hash to the committed root?
    """
    result = {"provenance_ok": False, "integrity_ok": False, "notes": []}

    # 1. provenance
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["curator_pubkey"]))
        payload = json.dumps(signed["manifest"], sort_keys=True, separators=(",", ":")).encode()
        pk.verify(bytes.fromhex(signed["signature"]), payload)
        result["provenance_ok"] = True
    except Exception as e:
        result["notes"].append(f"signature check failed: {e}")

    # 2. integrity
    recomputed = merkle_root(record_hashes)
    if recomputed == signed["manifest"]["merkle_root"]:
        result["integrity_ok"] = True
    else:
        result["notes"].append(
            f"merkle root mismatch: recomputed {recomputed[:12]}.. != "
            f"committed {signed['manifest']['merkle_root'][:12]}.."
        )
    return result


# ----------------------------- demo ----------------------------------------

if __name__ == "__main__":
    # A tiny "dataset" -- in reality these come from the audited sources.
    dataset = [
        {"id": 0, "source": "commoncrawl.org", "text": "sample record zero"},
        {"id": 1, "source": "huggingface.co", "text": "sample record one"},
        {"id": 2, "source": "pile.eleuther.ai", "text": "sample record two"},
        {"id": 3, "source": "laion.ai", "text": "sample record three"},
    ]

    # Stage 1 output would populate this; mocked here for the demo.
    source_audit = {
        "commoncrawl.org": "CLEAN",
        "huggingface.co": "CLEAN",
        "pile.eleuther.ai": "CLEAN",
        "laion.ai": "CLEAN",
    }

    leaves = [hash_record(r) for r in dataset]
    curator_sk = Ed25519PrivateKey.generate()

    manifest = ProvenanceManifest("demo-dataset-v1", leaves, source_audit).finalize()
    signed = sign_manifest(manifest, curator_sk)

    print("=== 1. Clean verification ===")
    print(verify_manifest(signed, leaves))

    print("\n=== 2. Tamper with record 2, re-verify ===")
    tampered = [dict(r) for r in dataset]
    tampered[2]["text"] = "POISONED payload injected here"
    tampered_leaves = [hash_record(r) for r in tampered]
    res = verify_manifest(signed, tampered_leaves)
    print(res)
    # pinpoint which record changed
    changed = [i for i, (a, b) in enumerate(zip(leaves, tampered_leaves)) if a != b]
    print(f"integrity check localizes tampering to record(s): {changed}")

    print("\n=== 3. Inclusion proof for record 1 (no full dataset needed) ===")
    proof = inclusion_proof(leaves, 1)
    print("proof valid:", verify_inclusion(leaves[1], proof, manifest.merkle_root))
    print("proof size:", len(proof), "hashes (vs", len(leaves), "full records)")

    print("\n=== 4. The honest limit: signed-but-poisoned ===")
    # Curator signs a dataset that is validly signed but contains poison.
    poisoned = [dict(r) for r in dataset]
    poisoned[0]["text"] = "backdoor trigger phrase :: obey hidden instruction"
    poisoned_leaves = [hash_record(r) for r in poisoned]
    poisoned_manifest = ProvenanceManifest(
        "demo-dataset-v1", poisoned_leaves, source_audit
    ).finalize()
    poisoned_signed = sign_manifest(poisoned_manifest, curator_sk)
    print(verify_manifest(poisoned_signed, poisoned_leaves))
    print("--> provenance_ok AND integrity_ok are both True, yet the data is poisoned.")
    print("--> Attestation proves custody, not cleanliness. This is the gap.")
