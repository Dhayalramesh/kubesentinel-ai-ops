"""Deterministic policy layer. Nothing here calls an LLM.

Rules use (a) the proposed action, (b) the model's own root-cause label and (c) TRUSTED facts
that come from the cluster API (namespace, restart count, recent deploy, replicas, CPU).
Rules based on trusted facts are stronger than rules that rely on the model's label.
"""
import re

from .schemas import ACTIONS, Remediation

POLICY_VERSION = "2.1"

PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "monitoring", "cert-manager"})
MIN_CONFIDENCE = 0.6
MAX_REPLICAS = 10
MIN_CPU_FOR_SCALE = 80
MAX_RESTARTS_FOR_RESTART = 5

# An action is only consistent with these root-cause labels (relies on the model's label).
ACTION_CAUSE_RULES = {
    "rollback_deployment": {"missing_env_var", "bad_image_tag", "bad_release", "readiness_probe_failure"},
    "increase_memory_limit": {"oom"},
    "scale_deployment": {"traffic_spike"},
    "restart_deployment": {"stuck_process"},
}

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[a-z0-9._-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\b(?:gsk|sk|ghp|gho|xox[bpa])[-_][A-Za-z0-9_-]{10,}"), "[REDACTED_KEY]"),
]


def redact(text: str) -> str:
    """Remove obvious secrets BEFORE any text is sent to an LLM."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def run_guardrails_v1(plan: Remediation, namespace: str) -> dict:
    """Baseline policy: allowlist, protected namespaces, confidence threshold."""
    reasons = []
    if plan.action not in ACTIONS:
        reasons.append(f"action '{plan.action}' not in allowlist")
    if namespace in PROTECTED_NAMESPACES and plan.action != "no_action_escalate":
        reasons.append(f"namespace '{namespace}' is protected")
    if plan.confidence < MIN_CONFIDENCE and plan.action != "no_action_escalate":
        reasons.append(f"confidence {plan.confidence:.2f} < {MIN_CONFIDENCE}")
    return {"passed": not reasons, "reasons": reasons}


def run_guardrails(plan: Remediation, namespace: str, facts: dict | None = None) -> dict:
    """Full policy (v2.1): v1 + cause consistency + preconditions on trusted facts."""
    reasons = list(run_guardrails_v1(plan, namespace)["reasons"])
    facts = facts or {}

    allowed_causes = ACTION_CAUSE_RULES.get(plan.action)
    if allowed_causes is not None and plan.root_cause not in allowed_causes:
        reasons.append(f"action '{plan.action}' inconsistent with root cause '{plan.root_cause}'")

    if plan.action == "restart_deployment" and facts.get("restarts", 0) >= MAX_RESTARTS_FOR_RESTART:
        reasons.append(f"restart blocked: pod already restarted {MAX_RESTARTS_FOR_RESTART}+ times")
    if plan.action == "rollback_deployment" and facts.get("recent_deploy") is False:
        reasons.append("rollback blocked: no deployment change in the last 7 days")
    if plan.action == "scale_deployment":
        if facts.get("replicas", 0) >= MAX_REPLICAS:
            reasons.append(f"scale blocked: already at {MAX_REPLICAS}+ replicas")
        cpu = facts.get("cpu_pct")
        if cpu is None or cpu < MIN_CPU_FOR_SCALE:  # fail closed when the metric is missing
            reasons.append(f"scale blocked: no CPU evidence >= {MIN_CPU_FOR_SCALE}% (cpu_pct={cpu})")

    return {"passed": not reasons, "reasons": reasons}
