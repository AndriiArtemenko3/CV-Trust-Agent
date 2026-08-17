# Research foundations and engineering traceability

This project is a bounded engineering adaptation of published prompt-injection and résumé-ranking
research. It does **not** reproduce any paper in full and it does not claim universal prompt-
injection security. The public claim is narrower: within this application, untrusted source text
cannot directly select policy, commands, ranking rules, or release actions; evidence must survive
typed provenance and consistency checks before trusted code can use it.

## Review record

Six official arXiv PDF snapshots were reviewed from first page through references and every
appendix present: 233 pages in total. The PDFs are retained locally for research reproducibility
and intentionally excluded from the public repository. This file records official links,
snapshot date, and SHA-256 digests so the exact reviewed versions can be identified without
redistributing them.

| Flag | Paper/version record | Pages reviewed | Snapshot | Reviewed PDF SHA-256 |
| --- | --- | ---: | --- | --- |
| `R-CAMEL` | [*Defeating Prompt Injections by Design* (arXiv:2503.18813)](https://arxiv.org/abs/2503.18813) | 125/125 | 2026-08-16 | `c3719f6ce73eecf45e3764debef8a3d8ff8c9233b37d128c558b694ec3790cc7` |
| `R-PATTERNS` | [*Design Patterns for Securing LLM Agents against Prompt Injections* (arXiv:2506.08837)](https://arxiv.org/abs/2506.08837) | 32/32 | 2026-08-16 | `c202a240f8f03c93cfafd157f218ec790c9e503beeaf80e229fb5e1645ab7f9c` |
| `R-ARGUS` | [*ARGUS: Defending LLM Agents Against Context-Aware Prompt Injection* (arXiv:2605.03378)](https://arxiv.org/abs/2605.03378) | 18/18 | 2026-08-16 | `7d7598fecd71fffc3027138ad2b24a2b950ec3dfd79a3c43faa07751ae72ec30` |
| `R-FORMAL` | [*Formalizing and Benchmarking Prompt Injection Attacks and Defenses* (arXiv:2310.12815)](https://arxiv.org/abs/2310.12815) | 27/27 | 2026-08-16 | `61dc260eaada4836711d856478f2803c37ba00cefdcbbd26a8941731234a0779` |
| `R-MEASURE` | [*Measuring Real-World Prompt Injection Attacks in LLM-based Resume Screening* (arXiv:2605.28999)](https://arxiv.org/abs/2605.28999) | 19/19 | 2026-08-16 | `3d9febdcb114d5ba70c53ea9dc26286188df5f741a0c7dd6d0373a41fdbd7a1b` |
| `R-RANKING` | [*Prompt Injection in Automated Résumé Screening with Large Language Models: Single and Multi-Injection Settings* (arXiv:2606.27287)](https://arxiv.org/abs/2606.27287) | 12/12 | 2026-08-16 | `31a298255bcea126ea14b16f3d653001f58a4236b7e0dc585dcd8d688b58727d` |

The arXiv identifiers and PDF digests are the version record. Paper findings may change in later
revisions; re-check the official pages before repeating or extending the research.

## What was adopted

### `R-CAMEL`: trusted control, untrusted data, and complete mediation

CaMeL motivates separating control flow from values originating in model or retrieved content,
tracking provenance transitively, and checking authority before consequential actions. This
project adapts those ideas as:

- closed, code-owned `PlanCommand` kinds and an executor rather than model-authored workflow;
- a run-scoped `StageVault` whose single-use handles mediate provenance-bound values;
- a bounded support graph from evidence to facts to rank/route;
- a release command that is the only route by which a ranking may leave the system.

The project does **not** implement CaMeL's full interpreter, formal capability model, policy
language, or its general-purpose agent architecture. The accurate phrase is “CaMeL-inspired
control/data separation.”

### `R-PATTERNS`: least authority and per-document reduction

The design-pattern work motivates processing each untrusted document in a constrained context,
minimising shared context, using typed intermediate representations, and performing consequential
reduction in deterministic trusted code. This project adapts those ideas as:

- one candidate per mapper call;
- no mapper tools, memory, queue fields, strategy fields, or ranking authority;
- exact evidence identifiers rather than free-form mapper reasoning;
- deterministic validation, ranking, strategy selection, and release;
- the same controls for CV prose and structured JSON notes.

The mapper is still fallible. A type-valid mapper output is a proposal, not a trusted fact.

### `R-ARGUS`: bounded evidence-to-action support

ARGUS motivates checking whether an action is supported by relevant evidence and enforcing
task-level invariants before an action crosses a boundary. This project adapts those ideas into a
small `DecisionSupportGraph`:

```text
EvidenceRef -> SupportedFact -> DerivedFeature -> RankKey/Band/Queue -> CandidateRoute
```

The release authorizer checks closure and admissibility before releasing routes. This is **not** a
reproduction of ARGUS's general contextual reasoning or causal verification; it is an
ARGUS-inspired bounded support graph for one fixed domain.

### `R-FORMAL`: explicit threat models and fixed evaluation oracles

The formalisation work motivates separating threat-model assumptions from measurements,
including structured-field attacks and combined attacks, preserving clean utility, and fixing the
evaluation oracle outside the system under test. This project adapts those lessons as:

- an attacker-knowledge ladder rather than treating every injection as equally realistic;
- strict minimal pairs in both PDF text and structured JSON notes;
- an `evaluation/` package that owns expected outcomes while runtime code emits outcomes only;
- clean-utility, safety, availability, and rank-change metrics kept distinct.

The repository evaluator is a transparent self-check, not an independent benchmark.

### `R-MEASURE`: résumé-specific hidden evidence and localisation

The résumé measurement study motivates testing factual-looking hidden claims, retaining document
position/presentation provenance, and not relying on a generic prompt-injection phrase detector.
This project adapts those lessons as:

- visible, low-contrast, off-page, metadata, and microtext evidence classes;
- a single evidence-admissibility rule across all concealment fixtures;
- structured-note fabricated facts that require matching visible evidence;
- explicit limits on what the lightweight PDF analysis can establish.

The project does not implement a full vision-language discrepancy detector, OCR, occlusion
analysis, arbitrary background analysis, or universal PDF forensics.

### `R-RANKING`: rank movement, randomisation, and near-threshold effects

The résumé-ranking work motivates measuring changes in rank rather than only whether a target
reaches first place, controlling presentation order, and treating near-threshold cases carefully.
This project adapts those lessons as:

- paired clean/attack presentation permutations;
- rank gain, top-K crossing, pairwise inversions, unaffected-order change, and failure counts;
- dense `evidence_rank` for equal evidence keys, separate from deterministic
  `display_position`;
- held-out, fictional CV layouts for a bounded live-mapper utility smoke.

No attack-success percentage from a paper is transferred to this corpus or model.

## Research limits carried into the design

| Source | Limitation relevant here |
| --- | --- |
| `R-CAMEL` | Architectural separation depends on complete mediation and correct policy/provenance handling; adopting the idea does not inherit the paper's full guarantees. |
| `R-PATTERNS` | Patterns are composable and application-specific, not a universal detector or proof that mapped content is true. |
| `R-ARGUS` | An evidence-to-action check is only as complete as its evidence graph, task invariants, and interception boundary. |
| `R-FORMAL` | Benchmark findings depend on the stated attacker knowledge, model, task, prompts, corpus, and oracle. |
| `R-MEASURE` | Résumé-specific hidden-span findings do not imply that a lightweight parser detects every visual or semantic manipulation. |
| `R-RANKING` | Ranking is stochastic and near-threshold effects matter; small-sample rank changes cannot be generalized as population rates. |

## Code-change attribution

The `C01`–`C14` identifiers are the hardening work packages used throughout the project docs.

| Change | Engineering decision | Research lineage |
| --- | --- | --- |
| `C01` | Execute a finite plan through closed commands and receipts | `R-CAMEL` §§4–5.4; `R-PATTERNS` §3.1; `R-ARGUS` §4.3; finite-state dispatcher is original |
| `C02` | Gate every value before downstream consumption | `R-CAMEL` §§5.2–5.4 and §7; `R-ARGUS` §4.3; the run-scoped single-use `StageVault` is an original typed adaptation |
| `C03` | Compose retrieval and mapper faults through the ordinary CLI | Original reproducibility design |
| `C04` | Bind identity and close evidence-to-route dependencies | `R-CAMEL` §§5.3–5.4; `R-ARGUS` §§4.2–4.3 and §6.2; AP timeline/field invariants are original |
| `C05` | Authorize release independently from ranking | `R-ARGUS` §§4.2–4.3; `R-PATTERNS` §3 and Appendix A; concrete verifier is original |
| `C06` | Add structured-note directives, fabricated facts, benign controls, and combined poison | `R-FORMAL` §§3–4.2; `R-PATTERNS` §4.7; `R-MEASURE` §6.3 |
| `C07` | Keep a canonical fixture adapter and separately test a bounded live mapper | `R-PATTERNS` §§3.1 and 4.7; `R-ARGUS` §4.2; `R-MEASURE` §§3.2–3.4; `R-RANKING` §2 and Appendix B; held-out corpus is original |
| `C08` | Move expected outcomes outside runtime | `R-FORMAL` §6.1; repository boundary is original |
| `C09` | Counterbalance trials and emit auditable synthetic-only artifacts | `R-FORMAL` §6.1; `R-RANKING` §2 and Appendix B; artifact manifest is original |
| `C10` | Bound resources and retain PDF presentation provenance | `R-MEASURE` §§3.2.1–3.4; `R-PATTERNS` Appendix A; numerical demo limits are original |
| `C11` | Disable retries and expose bounded deadlines | `R-CAMEL` §7 typed-result lesson; concrete policy is original |
| `C12` | Separate evidence rank from display position | `R-RANKING` §§2–3; dense-rank semantics are original |
| `C13` | Simplify modules and add property/package gates | `R-PATTERNS` §5 application-specific simplicity; implementation gates are original |
| `C14` | Bind claims, docs, evidence, video, and release to one checkout | All six papers for attribution; delivery protocol is original |

### V2.1 follow-up mappings

| V2.1 change | Engineering decision | Research lineage |
| --- | --- | --- |
| Complete mapper mediation | Validate identity, revision, commitments, URL/catalog ownership and document hash before making a mapper-eligible request | `R-CAMEL` complete mediation and provenance; `R-PATTERNS` least-authority mapper |
| Single-use stage vault | Store allowed values behind atomic, run-bound, nonce-bearing handles | `R-CAMEL` capability separation; concrete vault protocol is original |
| Snapshot and categorical release checks | Recompute allow-listed canonical values and hashes and reject stale/mixed snapshots | `R-ARGUS` evidence-to-action support; bounded normalization rules are original |
| Process-isolated PDF intake | Spawn one resource-bounded parser worker per document with bounded JSON IPC and no retry | `R-MEASURE` presentation provenance; isolation and budgets are original |
| Independent semantic harness | Reconstruct canonical decisions, derive every verdict after capture, and prevent producer-written pass fields from entering release | `R-FORMAL` fixed oracles; `R-ARGUS` independent support verification |
| Unseen canonical cohort | Freeze a separately authored ten-CV same-contract cohort and test renaming, order and value metamorphisms | `R-FORMAL` clean utility and fixed oracles; `R-RANKING` permutation controls; cohort design is original |
| Release capture environment binding | Require the evaluator, generated console script, venv interpreter, and imported runtime to resolve to the one hashed checkout before capture | Original release-evidence control |

### V2.2 follow-up mappings

| V2.2 change | Engineering decision | Research lineage |
| --- | --- | --- |
| Exact evidence-disposition inventory | Carry one typed inventory from mapping unchanged into provenance; bind seven typed/null structured anchors and typed/hash-bound mapped values; content-address JSON IDs and commit them through trusted receipts; group multi-citation comparisons; retain conflicting/unsupported pairs across ranked/unranked/drift paths; validate terminal survival separately | `R-CAMEL` transitive provenance and complete mediation; `R-ARGUS` evidence-to-action support; concrete state machine is original |
| Separate action and audit digests | Bind released effects separately from the complete causal trace while validating both domains and trusting neither producer digest | `R-FORMAL` non-self-scoring evaluation; `R-ARGUS` action support; domain split is original |
| Strict mapper wire contract | Use a discriminated provider-facing union, bounded literals/scalars, total code-owned conversion, and closed stage/code diagnostics | `R-PATTERNS` typed least-authority reduction; concrete wire schema and diagnostic taxonomy are original |
| Hash-chained provider-slot ledgers | Pre-authorize and durably start each of 84 secure and 32 naïve slots, terminalize exactly once, and bind both chains into the manifest | `R-FORMAL` fixed protocol and retained failures; interruption/replay ledger is original |
| Integrity/release separation | Permit a manifest to preserve a complete red observation while requiring every semantic hard gate for `release_green` and rendering | `R-FORMAL` non-self-scoring evaluation; release-state split is original |

## Deliberately rejected or deferred practices

The repository stays bounded by explicitly declining techniques that do not close an assessment
requirement or cannot be defended in the available scope. The hardened implementation is not
described as small: its explicit gates, evaluator, synthetic corpus, and evidence tooling add
substantial review surface.

| Practice | Decision and reason |
| --- | --- |
| Prompt-injection keyword blacklist | Rejected. It would miss semantic attacks and create benign false positives. |
| General LLM “is this an attack?” judge | Rejected as a primary control. It would add another untrusted, probabilistic decision point. |
| Model-authored plans, scores, or queues | Rejected. They grant source-influenced text unnecessary authority. |
| Full CaMeL or ARGUS reproduction | Out of scope. This project implements only the named bounded adaptations. |
| Full VLM/PDF-forensics pipeline | Deferred. The current HCD-lite evidence classes are demonstrative, not forensic proof. |
| OCR and production ATS ingestion | Deferred. Held-out CVs remain fictional and text based. |
| Database, vector store, web UI, or general agent framework | Rejected as unnecessary surface area for this build. |
| Inferring truth from internal consistency | Rejected. Consistency is evidence support, not authenticity. |
| Transferring paper attack rates to this system | Rejected. Model, prompts, corpus, sampling, and threat model differ. |

## Original contribution, stated narrowly

The original contribution is the combination of a typed trust ledger, a closed finite workflow,
a bounded transitive support graph, identity-bound evidence ranking, and release authorization in
a synthetic résumé-routing demonstration. Novelty is not claimed for the individual techniques.
The value is the coherent, inspectable integration and its explicit failure behaviour.
