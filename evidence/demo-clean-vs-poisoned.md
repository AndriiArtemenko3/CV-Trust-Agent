# Clean vs poisoned — captured demo transcript

Captured from the public CLI on the release tree (`9b3fe532…`), deterministic mapper, no API key.
Commands are exactly as a reviewer would run them; output is unedited.

## `cv-trust demo --case clean --mapper deterministic`

```text
                                 CV-Trust demo                                  
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Case  ┃ Evidence         ┃ Trusted decision        ┃ Ranking / exclusions    ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ clean │ Index: yes       │ FULL_EVIDENCE_RANKING   │ Ranked: 10 / excluded:  │
│       │ Detail/CV: 10/10 │ AP-005: evidence-rank   │ 0                       │
│       │ HTTP: 21         │ 4, display 6            │ Order: AP-001 > AP-010  │
│       │                  │ POTENTIAL_EVIDENCE_MATC │ > AP-006 > AP-004 >     │
│       │                  │ H                       │ AP-002 > AP-005 >       │
│       │                  │ Fingerprint:            │ AP-008 > AP-007 >       │
│       │                  │ efd42044316f            │ AP-003 > AP-009         │
│       │                  │                         │ Excluded IDs: —         │
└───────┴──────────────────┴─────────────────────────┴─────────────────────────┘

Evidence ranking
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Evidence rank ┃ Display ┃ Candidate ┃ Band              ┃ Queue              ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│             1 │       1 │ AP-001    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             1 │       2 │ AP-010    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             2 │       3 │ AP-006    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             3 │       4 │ AP-004    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             4 │       5 │ AP-002    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             4 │       6 │ AP-005    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             4 │       7 │ AP-008    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             5 │       8 │ AP-007    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             6 │       9 │ AP-003    │ INSUFFICIENT_SUP… │ EVIDENCE_CHECK     │
│             6 │      10 │ AP-009    │ INSUFFICIENT_SUP… │ EVIDENCE_CHECK     │
└───────────────┴─────────┴───────────┴───────────────────┴────────────────────┘

Plan
Retained: FULL_EVIDENCE_RANKING (version 1)

Executed command receipts
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Plan ┃ Command                     ┃ State     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ v1   │ fetch_candidate_details     │ started   │
│ v1   │ fetch_candidate_details     │ completed │
│ v1   │ validate_candidate_details  │ started   │
│ v1   │ validate_candidate_details  │ completed │
│ v1   │ fetch_candidate_resumes     │ started   │
│ v1   │ fetch_candidate_resumes     │ completed │
│ v1   │ parse_candidate_resumes     │ started   │
│ v1   │ parse_candidate_resumes     │ completed │
│ v1   │ validate_candidate_bindings │ started   │
│ v1   │ validate_candidate_bindings │ completed │
│ v1   │ map_candidate_claims        │ started   │
│ v1   │ map_candidate_claims        │ completed │
│ v1   │ validate_candidate_evidence │ started   │
│ v1   │ validate_candidate_evidence │ completed │
│ v1   │ rank_full_evidence          │ started   │
│ v1   │ rank_full_evidence          │ completed │
│ v1   │ pre_release_audit           │ started   │
│ v1   │ pre_release_audit           │ completed │
│ v1   │ release_output              │ started   │
│ v1   │ release_output              │ completed │
└──────┴─────────────────────────────┴───────────┘

Explanations
┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Candidate ┃ Template ┃ Sanitized explanation ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
└───────────┴──────────┴───────────────────────┘
```

## `cv-trust demo --case semantic_conflict_no_directive --mapper deterministic`

The structured record claims 8.0 AP years; the visible CV still supports 1.5. No attack strings exist anywhere in the mutation.

```text
                                 CV-Trust demo                                  
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃                   ┃                  ┃                   ┃ Ranking /         ┃
┃ Case              ┃ Evidence         ┃ Trusted decision  ┃ exclusions        ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ semantic_conflict │ Index: yes       │ SUPPORTED_ONLY_RA │ Ranked: 9 /       │
│ _no_directive     │ Detail/CV: 10/10 │ NKING             │ excluded: 1       │
│                   │ HTTP: 21         │ AP-005: excluded  │ Order: AP-001 >   │
│                   │                  │ INTEGRITY_HOLD    │ AP-010 > AP-006 > │
│                   │                  │ Fingerprint:      │ AP-004 > AP-002 > │
│                   │                  │ 6d013c6c9911      │ AP-008 > AP-007 > │
│                   │                  │                   │ AP-003 > AP-009   │
│                   │                  │                   │ Excluded IDs:     │
│                   │                  │                   │ AP-005            │
└───────────────────┴──────────────────┴───────────────────┴───────────────────┘

Evidence ranking
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Evidence rank ┃ Display ┃ Candidate ┃ Band              ┃ Queue              ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│             1 │       1 │ AP-001    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             1 │       2 │ AP-010    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             2 │       3 │ AP-006    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             3 │       4 │ AP-004    │ STRONG_EVIDENCE_… │ PRIORITY_HUMAN_RE… │
│             4 │       5 │ AP-002    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             4 │       6 │ AP-008    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             5 │       7 │ AP-007    │ POTENTIAL_EVIDEN… │ STANDARD_HUMAN_RE… │
│             6 │       8 │ AP-003    │ INSUFFICIENT_SUP… │ EVIDENCE_CHECK     │
│             6 │       9 │ AP-009    │ INSUFFICIENT_SUP… │ EVIDENCE_CHECK     │
│             — │       — │ AP-005    │ INTEGRITY_HOLD    │ INTEGRITY_REVIEW   │
└───────────────┴─────────┴───────────┴───────────────────┴────────────────────┘

Plan
Before → after: FULL_EVIDENCE_RANKING → SUPPORTED_ONLY_RANKING
Triggers: mapper_disagreement
Removed commands: p1:rank_full_evidence, p1:pre_release_audit, p1:release_output
Added commands: p2:quarantine_unsupported, p2:rank_supported_evidence, 
p2:pre_release_audit, p2:release_output
Evidence: revoked=0, granted=126, allowed=126

Executed command receipts
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Plan ┃ Command                     ┃ State     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ v1   │ fetch_candidate_details     │ started   │
│ v1   │ fetch_candidate_details     │ completed │
│ v1   │ validate_candidate_details  │ started   │
│ v1   │ validate_candidate_details  │ completed │
│ v1   │ fetch_candidate_resumes     │ started   │
│ v1   │ fetch_candidate_resumes     │ completed │
│ v1   │ parse_candidate_resumes     │ started   │
│ v1   │ parse_candidate_resumes     │ completed │
│ v1   │ validate_candidate_bindings │ started   │
│ v1   │ validate_candidate_bindings │ completed │
│ v1   │ map_candidate_claims        │ started   │
│ v1   │ map_candidate_claims        │ completed │
│ v1   │ validate_candidate_evidence │ started   │
│ v1   │ validate_candidate_evidence │ completed │
│ v2   │ quarantine_unsupported      │ started   │
│ v2   │ quarantine_unsupported      │ completed │
│ v2   │ rank_supported_evidence     │ started   │
│ v2   │ rank_supported_evidence     │ completed │
│ v2   │ pre_release_audit           │ started   │
│ v2   │ pre_release_audit           │ completed │
│ v2   │ release_output              │ started   │
│ v2   │ release_output              │ completed │
└──────┴─────────────────────────────┴───────────┘

Explanations
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Candidate ┃ Template           ┃ Sanitized explanation                       ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ AP-005    │ record_quarantined │ AP-005: index-1 structured ap_years=8       │
│           │                    │ conflicts with visible resume evidence      │
│           │                    │ pdfline:index-1:AP-005:p1:visible:l10:0f51… │
│           │                    │ value=1.5; the record has no evidence rank. │
└───────────┴────────────────────┴─────────────────────────────────────────────┘
```

## `cv-trust demo --case compound --mapper deterministic`

Retrieval timeout (AP-008 unavailable) plus an independent mapper disagreement (AP-005): the agent re-plans to a batch integrity hold.

```text
                                 CV-Trust demo                                  
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Case     ┃ Evidence       ┃ Trusted decision        ┃ Ranking / exclusions   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ compound │ Index: yes     │ BATCH_INTEGRITY_HOLD    │ Ranked: 0 / excluded:  │
│          │ Detail/CV: 9/9 │ AP-005: excluded        │ 10                     │
│          │ HTTP: 20       │ INTEGRITY_HOLD          │ Order: —               │
│          │                │ Fingerprint:            │ Excluded IDs: AP-001,  │
│          │                │ 891a52b30816            │ AP-002, AP-003,        │
│          │                │                         │ AP-004, AP-005,        │
│          │                │                         │ AP-006, AP-007,        │
│          │                │                         │ AP-008, AP-009, AP-010 │
└──────────┴────────────────┴─────────────────────────┴────────────────────────┘

Evidence ranking
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Evidence rank ┃ Display ┃ Candidate ┃ Band           ┃ Queue                ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│             — │       — │ AP-001    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-002    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-003    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-004    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-005    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-006    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-007    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-008    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-009    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
│             — │       — │ AP-010    │ INTEGRITY_HOLD │ BATCH_INTEGRITY_HOLD │
└───────────────┴─────────┴───────────┴────────────────┴──────────────────────┘

Plan
Before → after: FULL_EVIDENCE_RANKING → BATCH_INTEGRITY_HOLD
Triggers: candidate_unavailable, mapper_disagreement
Removed commands: p1:rank_full_evidence, p1:pre_release_audit, p1:release_output
Added commands: p2:isolate_batch, p2:request_corroboration, 
p2:pre_release_audit, p2:release_output
Evidence: revoked=0, granted=0, allowed=0

Executed command receipts
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Plan ┃ Command                     ┃ State     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ v1   │ fetch_candidate_details     │ started   │
│ v1   │ fetch_candidate_details     │ completed │
│ v1   │ validate_candidate_details  │ started   │
│ v1   │ validate_candidate_details  │ completed │
│ v1   │ fetch_candidate_resumes     │ started   │
│ v1   │ fetch_candidate_resumes     │ completed │
│ v1   │ parse_candidate_resumes     │ started   │
│ v1   │ parse_candidate_resumes     │ completed │
│ v1   │ validate_candidate_bindings │ started   │
│ v1   │ validate_candidate_bindings │ completed │
│ v1   │ map_candidate_claims        │ started   │
│ v1   │ map_candidate_claims        │ completed │
│ v1   │ validate_candidate_evidence │ started   │
│ v1   │ validate_candidate_evidence │ completed │
│ v2   │ isolate_batch               │ started   │
│ v2   │ isolate_batch               │ completed │
│ v2   │ request_corroboration       │ started   │
│ v2   │ request_corroboration       │ completed │
│ v2   │ pre_release_audit           │ started   │
│ v2   │ pre_release_audit           │ completed │
│ v2   │ release_output              │ started   │
│ v2   │ release_output              │ completed │
└──────┴─────────────────────────────┴───────────┘

Explanations
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Candidate ┃ Template              ┃ Sanitized explanation                    ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ AP-005    │ record_quarantined    │ AP-005: evidence provenance or an index  │
│           │                       │ commitment failed; the record has no     │
│           │                       │ evidence rank.                           │
│ AP-008    │ candidate_unavailable │ AP-008: detail or resume evidence was    │
│           │                       │ unavailable; the candidate has no        │
│           │                       │ evidence rank and remains pending.       │
│ batch     │ batch_held            │ The batch is isolated pending            │
│           │                       │ corroboration; no evidence ranking or    │
│           │                       │ automated hiring outcome was released.   │
└───────────┴───────────────────────┴──────────────────────────────────────────┘
```
