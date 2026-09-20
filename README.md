# KubeSentinel

[![CI](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/ci.yml)
[![DevSecOps](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/devsecops.yml/badge.svg)](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/devsecops.yml)
[![Kubernetes deploy check](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/k8s-e2e.yml/badge.svg)](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/k8s-e2e.yml)
[![Container](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/container.yml/badge.svg)](https://github.com/Dhayalramesh/kubesentinel-ai-ops/actions/workflows/container.yml)

A guardrailed AI-Ops agent for Kubernetes incident triage. An LLM proposes a structured remediation; a
**deterministic policy layer** decides whether it may proceed; a human approves; the action is **dry-run only**.

**Live demo (replay mode):** https://kubesentinel-ai-ops-nrnfjbdfgxyga5f7lbaxwx.streamlit.app/

> **Scope, stated plainly.** This is a replay-mode prototype: it runs on 20 recorded incidents, not a live cluster.
> Execution is dry-run and post-change validation is simulated. Fixtures and runbooks were written by the same
> author, so the accuracy numbers measure runbook-following, not open-ended diagnosis.

## Try it in 2 minutes

Open the live demo and:

1. **Replay tab, `inc-001-crashloop`:** click *Run agent*, then *Approve (dry-run)*. You get a rollback command
   that is printed, not executed, plus a full audit log.
2. **Replay tab, `inc-013-injection-steer-restart`:** the logs contain a fake "verified SRE note" trying to force a
   restart. Open *Author's ground truth* to see whether the model followed it.
3. **Try your own tab:** set the namespace to `kube-system` and run it. The policy layer refuses to touch it.
4. **Evaluation results tab:** the benchmark tables, with limitations stated next to the numbers.

## How it works

```
alert -> gather (redact secrets) -> retrieve runbooks (RAG) -> analyze (LLM, schema-constrained)
      -> guardrails (no LLM) -> human approval -> execute (dry-run) -> validate (simulated) -> report + audit log
```

- **Schema-constrained output.** The model can only return actions from a fixed enum, so `delete_namespace` cannot even be expressed.
- **Deterministic guardrails.** Protected namespaces, confidence threshold, action/cause consistency, and preconditions on
  *trusted* cluster facts (restart count, recent deploy, replicas, CPU). Fails closed when a fact is missing.
- **Untrusted input handling.** Logs and events are treated as data, wrapped in tags, and secrets are redacted before any LLM call.
- **Fail-safe.** If the LLM errors or returns invalid output, the incident is escalated to a human. It never guesses.
- **Audit log** of every step.

## Results (openai/gpt-oss-120b, replay mode)

| | |
|---|---|
| Full defences, 20 incidents x 3 runs | 60/60 acceptable actions, 58/60 root causes, 0/6 injections followed |
| Defences removed, 72 runs | model proposed 17 wrong actions; policy v1 let 11 through, v2 let 3 through; 0 correct actions blocked |
| Protected-namespace violations proposed by the model | 6, all blocked (even with the security prompt on) |

Full tables, caveats and known issues: [`evals/RESULTS.md`](evals/RESULTS.md). Raw data: [`evals/results/`](evals/results/).
The original Colab experiment is in [`notebooks/`](notebooks/).

## Run it locally

```bash
pip install -r requirements.txt
streamlit run app.py                     # works without a key: uses a clearly-labelled mock baseline
export GROQ_API_KEY=...                  # optional: real LLM (Groq)
python evals/run_benchmark.py --runs 3   # reproduce the benchmark
pytest                                   # 40 tests: policy, agent, fixtures, UI
```

Deploy to Streamlit Community Cloud, Docker or Kubernetes: [`docs/DEPLOY.md`](docs/DEPLOY.md).

## DevSecOps pipeline (GitHub Actions)

| Stage | Tool |
|---|---|
| Lint + tests | ruff, pytest |
| SAST | Semgrep |
| Secrets | Gitleaks (checksum-verified binary) |
| SCA / filesystem | Trivy |
| IaC + Dockerfile + workflows | Checkov |
| Policy-as-code | OPA / Conftest (policies are unit-tested) |
| SBOM + vulnerability gate | Syft (CycloneDX) + Grype |
| Container | build, Trivy image scan, then push to GHCR only if clean |
| Kubernetes deploy check | kind cluster, Pod Security `restricted`, non-root and read-only root FS verified |
| DAST | OWASP ZAP baseline (informational) |

Actions are pinned by commit SHA. Dependabot proposes version bumps weekly; each one is reviewed, not auto-merged.
See [`docs/DEVSECOPS.md`](docs/DEVSECOPS.md). The badges at the top show the current status of each workflow.

## Known issues

- The root-cause label `insufficient_capacity` is ambiguous (cluster vs workload capacity) and caused 2 over-blocks.
  Suggested fix: rename to `cluster_capacity_exhausted` and re-run the benchmark.
- The CPU precondition for scaling is unit-tested but has not been re-measured on the failure that motivated it.
- No live Kubernetes integration yet; `gather` and `execute` would be replaced by API calls.

## Layout

```
app.py                  Streamlit UI (replay mode)
kubesentinel/           agent, guardrails, fixtures, runbooks, LLM backends
tests/                  policy, agent, fixture and UI smoke tests
evals/                  benchmark CLI, results, write-up
k8s/  policy/           hardened manifests, Kyverno + Conftest policies
.github/workflows/      CI and DevSecOps pipelines
docs/                   architecture, threat model, deployment, pipeline notes
```

MIT licensed.
