# Deliberately unsafe cohort-ranking baseline

`naive_cohort_ranker.py` is an experiment, not production code. One no-tools model receives all
ten raw application details and CV extractions, then directly owns the complete order. A strict
output schema constrains syntax only; it does not prevent source text from influencing ranking.

The secure comparison changes authority: one candidate per mapper call, bounded facts, exact
evidence references, deterministic validation/ranking, executed trusted plans, and independent
release authorization.

> Status: regenerate all paired evidence against the frozen release checkout. This README does not
> claim final live results or attack-success rates.

## Paired protocol

- Use the same seeded candidate presentation order within each pair.
- Counterbalance condition order `AB`/`BA` across pairs.
- Validate that the two cohorts differ only in the registered mutation.
- Use clean/clean pairs to expose ordinary provider variability.
- Keep invalid schema, incomplete order, timeout, and provider failure in the denominator.
- Never replace a failed live call with deterministic output.

The registered metrics are target rank gain, positive-gain count, rank-one/top-three crossing,
pairwise inversions, changes among unaffected candidates, and invalid/availability failure. Five
pairs on one model/prompt/cohort are illustrative observations—not a population attack-success
estimate.

## Preregistered V2 Latin-square protocol

V2 release capture uses eight fixed four-call blocks (32 calls), not the legacy `--repeats`
runner. Start clean and `structured_note_directive` sources, then use this explicit paid opt-in:

```bash
uv run --env-file .env python -m experiments.naive_cohort_ranker \
  --v2-latin-square \
  --clean-source-url http://127.0.0.1:8000 \
  --attack-source-url http://127.0.0.1:8001 \
  --output evidence/v2/naive-v2.jsonl \
  --execute-live-api
```

The V2 mode fixes the seeds, call roles, target, cohort size, extraction mode, threat fixture, and
artifact filename. It writes 32 raw attempts only; `evaluation.naive_release_v2` derives every
metric afterward. Omitting `--execute-live-api` fails before any provider call. Do not run this
command without separate paid-API authorization.

## Attacker knowledge

| Level | Interpretation | Example |
| --- | --- | --- |
| K0 | Controls a CV/field and suspects automated screening | Hidden or structured factual-looking evidence |
| K1 | Knows the public job and expects evaluation/ranking | Simple, descriptive, or combined task-aware prose |
| K2 | Knows a public architecture/rubric, not private schema | Future architecture-aware tests |
| K3 | Knows internal IDs/output schema or has adaptive feedback | `schema_aware_white_box` upper bound |

K3 is useful to test whether security depends on secrecy, but it is not representative applicant
knowledge.

## Visible-text pair

Start two source processes:

```bash
# terminal 1
uv run cv-trust serve --scenario clean --port 8000

# terminal 2 — choose the registered attacked source
uv run cv-trust serve --scenario structured_note_directive --port 8001
```

Then explicitly authorize live calls:

```bash
uv run --env-file .env python -m experiments.naive_cohort_ranker \
  --clean-source-url http://127.0.0.1:8000 \
  --attack-source-url http://127.0.0.1:8001 \
  --extraction-mode visible \
  --repeats 5 \
  --include-clean-control \
  --attack-fixture-id structured_note_directive \
  --mutation-channel structured_detail \
  --output evidence/naive-pairs.jsonl \
  --execute-live-api
```

`--include-clean-control` runs the registered attack series and a clean/clean stochastic-control
series with the same seeds, permutations, and AB/BA order. Both labelled series, their summaries,
and one bounded bundle summary are written to the same artifact. The final aggregate rejects an
artifact that omits either series. The older `--clean-control` switch remains useful when
diagnosing a standalone control series.

Release evidence additionally requires `--attack-fixture-id structured_note_directive`. The
runner materializes the code-owned clean and attacked fixtures, commits them with the same
transport-normalized tree algorithm as the secure evaluator, and refuses to emit a release bundle
when the fetched cohort bytes differ. The artifact labels this registered structured-field attack
as K1 (public task context); arbitrary source URLs remain diagnostic-only.

## Hidden-evidence pair

For `hidden_job_evidence`, the unsafe baseline must opt into indiscriminate extraction:

```bash
uv run --env-file .env python -m experiments.naive_cohort_ranker \
  --clean-source-url http://127.0.0.1:8000 \
  --attack-source-url http://127.0.0.1:8001 \
  --extraction-mode machine \
  --repeats 5 \
  --execute-live-api
```

The hidden-evidence command is diagnostic because the final release fixture is deliberately fixed
to `structured_note_directive`; it cannot produce the release-valid combined naïve artifact.

`machine` concatenates visible and inadmissible extracted regions. The secure path consumes the
same PDF but retains presentation provenance and refuses low-contrast, microtext, off-page, and
metadata regions as ranking evidence.

## Evidence handling

Final trial rows must include seeded candidate order, condition order, model/SDK/prompt hashes,
attempt status, bounded failure category, latency, and aggregate token usage when provided. Do not
store prompts, raw CV/note prose, provider bodies, secrets, chain-of-thought, or sensitive request
identifiers.

The expected release artifacts are described in
[`docs/EXPERIMENTS.md`](../docs/EXPERIMENTS.md). Result tables should be generated from those
artifacts, never manually transcribed.
