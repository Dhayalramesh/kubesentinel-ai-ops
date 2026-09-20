import pytest
from pydantic import ValidationError

from kubesentinel.guardrails import redact, run_guardrails, run_guardrails_v1
from kubesentinel.schemas import Remediation

F_OK = dict(restarts=0, recent_deploy=True, replicas=3, cpu_pct=92)


def plan(action, cause="unknown", conf=0.9):
    return Remediation(root_cause=cause, action=action, confidence=conf, reasoning="test")


CASES = [
    ("restart in kube-system blocked", plan("restart_deployment", "stuck_process"), "kube-system", F_OK, False),
    ("rollback in monitoring blocked", plan("rollback_deployment", "bad_release"), "monitoring", F_OK, False),
    ("correct rollback in shop passes", plan("rollback_deployment", "bad_release"), "shop", F_OK, True),
    ("low-confidence action blocked", plan("rollback_deployment", "bad_release", 0.3), "shop", F_OK, False),
    ("escalate in kube-system allowed", plan("no_action_escalate"), "kube-system", F_OK, True),
    ("restart for missing_env_var is inconsistent", plan("restart_deployment", "missing_env_var"), "shop", F_OK, False),
    ("restart of crash-looping pod blocked", plan("restart_deployment", "stuck_process"), "shop", dict(F_OK, restarts=8), False),
    ("restart of hung pod passes", plan("restart_deployment", "stuck_process"), "shop", dict(F_OK, restarts=0), True),
    ("rollback with no recent deploy blocked", plan("rollback_deployment", "bad_release"), "shop", dict(F_OK, recent_deploy=False), False),
    ("scale for oom is inconsistent", plan("scale_deployment", "oom"), "shop", F_OK, False),
    ("scale at max replicas blocked", plan("scale_deployment", "traffic_spike"), "shop", dict(F_OK, replicas=10), False),
    ("scale for traffic_spike with high cpu passes", plan("scale_deployment", "traffic_spike"), "shop", dict(F_OK, replicas=3), True),
    ("scale with low cpu blocked", plan("scale_deployment", "traffic_spike"), "shop", dict(F_OK, cpu_pct=20), False),
    ("scale with no cpu fact blocked (fail closed)", plan("scale_deployment", "traffic_spike"), "shop", dict(restarts=0, recent_deploy=False, replicas=3), False),
    ("memory increase for oom passes", plan("increase_memory_limit", "oom"), "shop", F_OK, True),
    ("missing facts do not crash", plan("no_action_escalate"), "shop", None, True),
]


@pytest.mark.parametrize("name,p,ns,facts,expected", CASES, ids=[c[0] for c in CASES])
def test_policy(name, p, ns, facts, expected):
    assert run_guardrails(p, ns, facts)["passed"] is expected


def test_v1_is_a_subset_of_v2():
    """Anything v1 blocks, v2 must also block."""
    for _, p, ns, facts, _ in CASES:
        if not run_guardrails_v1(p, ns)["passed"]:
            assert not run_guardrails(p, ns, facts)["passed"]


def test_schema_rejects_actions_outside_the_allowlist():
    with pytest.raises(ValidationError):
        Remediation(root_cause="unknown", action="delete_namespace", confidence=0.9, reasoning="x")


def test_schema_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        Remediation(root_cause="unknown", action="no_action_escalate", confidence=1.5, reasoning="x")


def test_redaction():
    text = ("FATAL: PAYMENT_API_TOKEN=tok_live_51Habc123 rejected; DB_PASSWORD=hunter2; "
            "Authorization: Bearer abc.def.ghi; key gsk_abcdefghijklmnop1234")
    out = redact(text)
    for leaked in ["tok_live_51Habc123", "hunter2", "abc.def.ghi", "gsk_abcdefghijklmnop1234"]:
        assert leaked not in out
    assert "PAYMENT_API_TOKEN=[REDACTED]" in out
