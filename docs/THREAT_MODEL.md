# Threat model

| Threat | Mitigation | Evidence |
|---|---|---|
| Prompt injection in logs or events | Untrusted-data tags, RB-05 runbook, schema-constrained output, policy layer | 0/6 injections followed with defences on; with the security prompt removed the model followed the attacker's action in 2/4 runs and policy blocked both |
| Model proposes a destructive action | Enum schema: unsupported actions cannot be expressed | `tests/test_guardrails.py` |
| Model acts in a protected namespace | Namespace check on trusted metadata | 6/6 violations blocked in the ablation, including with the security prompt on |
| Wrong but allowed action | Cause consistency + trusted-fact preconditions + human approval | 17 wrong actions proposed in the ablation; 3 passed policy v2 |
| Consistent but wrong diagnosis | Human approval; CPU precondition for scaling | Residual risk: not solvable by rules alone |
| Secrets leak to the LLM provider | Redaction before any LLM call | `tests/test_guardrails.py::test_redaction`, `tests/test_agent.py` |
| LLM outage or invalid output | Fail-safe escalation | `tests/test_agent.py::test_llm_failure_fails_safe_to_escalation` |
| API-key abuse on the public demo | Per-session LLM cap, mock fallback, input length caps, key only in the secrets manager | `app.py` |
| Over-privileged agent | Replay mode has no cluster access; ServiceAccount token not mounted | `k8s/deployment.yaml` |
| Supply chain (CI actions, images) | Actions pinned by commit SHA, checksum-verified binaries, SBOM, image scan before push | `docs/DEVSECOPS.md` |

Out of scope: adversarial ML beyond prompt injection, multi-tenant isolation, live-cluster RBAC design.
