# Dataset-Custody Auditor: Methodology

## What problem this solves

A model trained on a dataset can be cryptographically proven to have used
*exactly that dataset* (e.g. via a signed manifest). That proof is worthless
if the dataset itself was never trustworthy. Training-custody has to answer
three separate questions, at three separate points in the data's life:

1. **Source** — was the domain that served this data legitimate when it was
   collected, or could it have been impersonated / MITM'd?
2. **Custody** — as the data moved through a curation pipeline (dedupe,
   filter, merge, transform), did every step actually do what it claimed to
   do, or could a step have been laundered — locally plausible, but not what
   it says it is?
3. **Seal** — can a downstream consumer verify the final dataset matches
   what the curator vouched for, without re-trusting every step in between?

This project is three small, independently-testable layers, one per
question.

## Layer 1 — Source trust (`ct_client.py`, `cert_parser.py`, `ct_auditor.py`)

Certificate Transparency logs are a public, append-only record: every TLS
certificate issued by a trusted CA must be logged, so an unexpected or
misissued certificate for a data-source domain is publicly visible. This
layer captures a baseline of known-good certificates for a domain and flags
new certificates that arrive from an unknown issuer, that were issued very
recently, or that cover unexpected hostnames.

**Threat model, explicitly:**
- Caught: cert-level identity substitution — a new cert from an issuer never
  seen before, a suspiciously fresh cert, unexpected SANs.
- Not caught: plain-HTTP sources (no cert exists to log); misissuance that
  predates the baseline (trust-on-first-use); a legitimately-certificated
  source that simply serves bad content. That last one is *by design* out of
  scope here — it's what Layer 2 and Layer 3 exist for.

## Layer 2 — Pipeline custody (`pipeline_fidelity.py`)

Layer 1 only sees the source. Layer 3 only sees the final artifact. Neither
can see *inside* the curation pipeline — a step that claims "deduplicated"
but silently injected records, or a "PII filter" that changed nothing,
passes both of those checks as long as the final signature is honest about
the final state.

Each curation step emits a signed, hash-linked envelope claiming what it
did (declared action, input/output record counts, input/output content
hash, a pointer to the previous envelope). Three checks run over the chain:

1. **Chain fidelity** — does this hop's signature verify, and does its
   claimed input hash actually equal the *previous* hop's actual output
   hash? Catches a hop being reordered, dropped, or fed swapped-in data.
2. **Action grounding** — does the hop's observable effect (record-count
   delta, whether the content hash changed) match what its declared action
   type is allowed to produce? A `FILTER_PII` step whose output count and
   hash are identical to its input didn't filter anything — the label lied.
3. **Transitive fidelity** — does the chain trace back only to a
   Layer-1-CLEAN source domain, and does the final record count stay within
   the dataset's declared scope? Catches drift from the *original* intent
   even when every individual hop looks locally consistent.

This chain-of-signed-claims-with-per-hop-verification pattern is adapted
from research on detecting *intent laundering* in multi-agent delegation
(an agent misusing legitimate authority at each individually-valid hop).
The schema, rule set, and code here are an independent reimplementation for
data-curation pipelines — no code from that project is reused.

**Measured, not asserted** (`eval_pipeline_fidelity.py`, 200 trials per
tamper type against a synthetic 4-hop pipeline):

| Tamper type | Detected | Caught by |
|---|---|---|
| Action mismatch (a step's label doesn't match its effect) | 200/200 (100%) | `action_grounding`, and `chain_fidelity` when a later hop exists |
| Input mismatch (a hop lies about what it received) | 200/200 (100%) | `chain_fidelity` |
| Untrusted source (COLLECT from a non-Layer-1-clean domain) | 200/200 (100%) | `chain_fidelity` + `transitive_fidelity` |

The clean, untampered chain produces zero false positives. One structural
property worth naming: because each envelope signs the hash of the
*previous* envelope's signature, forging one hop and re-signing it silently
breaks the forward link to every hop after it — an attacker who controls
one compromised curation job still has to also compromise and re-sign every
downstream job to keep the chain internally consistent.

**Out of scope, named honestly:** this checks that a declared action is
*consistent* with its observable effect, not that it was performed
*correctly*. A `DEDUPE` step that removes the wrong records, but still
removes a plausible number of them, passes. Content-level correctness is
not addressed by this layer.

## Layer 3 — Seal (`provenance_manifest.py`)

Records are Merkle-committed; the curator signs a manifest binding the
Merkle root to the Layer 1 source-audit result *and* the Layer 2
pipeline-audit result. A verifier checks the signature (provenance) and
that the data still hashes to the committed root (integrity), and can get
an inclusion proof for a single record without the whole dataset.

**The honest limit, stated plainly:** a signature proves *custody*, not
*cleanliness*. A curator can sign a dataset whose Layer 1 and Layer 2
checks are both clean and which still contains content-level poison no
hash-based check can see — Layers 1 and 2 catch supply-chain and
custody-chain tampering, not bad data that arrived exactly as everyone
(honestly) intended. Attestation moves trust from the data to the curator's
chain of claims; it does not manufacture trust from nothing. Closing that
remaining gap needs multi-party attestation, curator reputation, or
content-level checks — not attempted here.

## How the three layers connect

```
Layer 1 (CT audit of source domain)
        |  source_audit result
        v
Layer 2 (per-hop signed envelopes; transitive check consumes source_audit)
        |  pipeline_audit result + final records
        v
Layer 3 (Merkle-seal final records; manifest binds source_audit + pipeline_audit)
```

`main.py` runs all three stages against a live domain end to end.
