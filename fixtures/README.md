# Generated source fixtures

The external source generates its fixtures at runtime so every scenario can be
reproduced from code without committing binary PDFs. A generated root has this
shape:

```text
applications.json
details/
  AP-001.json ... AP-010.json
resumes/
  AP-001.pdf ... AP-010.pdf
```

`applications.json` is the untrusted batch index and content commitments. Each
detail and CV is fetched independently through its own endpoint. Generated data
never contains scenario names, expected bands/ranks, validator answers, or other
gold labels. Expected outcomes live only in tests/evaluation.

Generate a root by calling `materialize_fixture_root(...)` from
`cv_trust_agent.dataset`, or start the source process with:

```bash
uv run python -m cv_trust_agent.source \
  --scenario clean \
  --fixture-root ./work/source-fixtures
```

The source process also accepts `CV_TRUST_SCENARIO`,
`CV_TRUST_FIXTURE_ROOT`, `CV_TRUST_TIMEOUT_DELAY_SECONDS`, and
`CV_TRUST_SOURCE_BASE_URL`.

The runtime enforces a maximum of 50 candidates, a 256 KiB index, 64 KiB per
detail, and 5 MiB/10 pages/100,000 extracted characters per PDF. The generated
ten-candidate corpus is a synthetic security fixture, not a real-CV benchmark.
