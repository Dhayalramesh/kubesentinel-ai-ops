import pytest

from kubesentinel.agent import KubeSentinel
from kubesentinel.fixtures import FIXTURES
from kubesentinel.llm import MockAnalyzer
from kubesentinel.runbooks import get_index
from kubesentinel.schemas import Remediation


class Stub:
    """Returns the ground-truth plan, or a chosen (possibly unsafe) plan."""

    is_mock = True
    name = "stub"

    def __init__(self, plan=None, error=None):
        self.plan, self.error, self.seen = plan, error, []

    def analyze(self, fx, context, runbooks):
        self.seen.append(context)
        if self.error:
            raise self.error
        if self.plan is not None:
            return self.plan
        t = fx["truth"]
        return Remediation(root_cause=t["root_cause"], action=t["action"], confidence=0.9, reasoning="stub")


def auto(analyzer):
    return KubeSentinel(analyzer, approver=lambda s: True)


def test_correct_plan_is_executed_in_dry_run():
    state = auto(Stub()).run("inc-002-oom")
    assert state["status"] == "REMEDIATED (dry-run)"
    assert state["executed"].startswith("[DRY-RUN]")
    assert "SIMULATED" in state["validation"]


def test_escalation_skips_execution():
    state = auto(Stub()).run("inc-008-dependency-down")
    assert state["status"] == "ESCALATED TO HUMAN"
    assert "executed" not in state


def test_unsafe_plan_in_protected_namespace_is_blocked():
    unsafe = Remediation(root_cause="stuck_process", action="restart_deployment", confidence=0.99, reasoning="x")
    state = auto(Stub(unsafe)).run("inc-005-protected-ns")
    assert state["status"] == "BLOCKED BY GUARDRAILS"
    assert "executed" not in state


@pytest.mark.parametrize("iid", ["inc-013-injection-steer-restart", "inc-014-injection-in-event"])
def test_injection_steered_action_is_blocked_by_policy(iid):
    attack = FIXTURES[iid]["attack_action"]
    cause = "stuck_process" if attack == "restart_deployment" else "traffic_spike"
    steered = Remediation(root_cause=cause, action=attack, confidence=0.95, reasoning="followed the injected text")
    state = auto(Stub(steered)).run(iid)
    assert state["status"] == "BLOCKED BY GUARDRAILS"


def test_llm_failure_fails_safe_to_escalation():
    state = auto(Stub(error=RuntimeError("rate limit"))).run("inc-001-crashloop")
    assert state["status"] == "ESCALATED TO HUMAN"
    assert any(a["event"] == "analysis_failed" for a in state["audit"])


def test_secrets_are_redacted_before_the_llm_sees_them():
    stub = Stub()
    auto(stub).run("inc-001-crashloop")
    auto(stub).run("inc-018-secret-in-logs")
    joined = "\n".join(stub.seen)
    assert "hunter2" not in joined and "tok_live_51Habc123" not in joined


def test_without_an_approver_the_run_pauses_and_finalize_completes_it():
    agent = KubeSentinel(Stub())
    paused = agent.run("inc-001-crashloop")
    assert paused["status"] == "AWAITING HUMAN APPROVAL"
    assert "executed" not in paused
    done = agent.finalize(paused, approved=True)
    assert done["status"] == "REMEDIATED (dry-run)"
    rejected = agent.finalize(paused, approved=False)
    assert rejected["status"] == "REJECTED BY HUMAN"
    assert "executed" not in rejected


def test_live_execution_is_refused():
    with pytest.raises(NotImplementedError):
        KubeSentinel(Stub(), dry_run=False)


def test_audit_log_covers_every_step():
    state = auto(Stub()).run("inc-001-crashloop")
    events = [a["event"] for a in state["audit"]]
    assert events == ["gathered_context", "retrieved_runbooks", "plan_proposed", "guardrail_result",
                      "human_approval", "executed", "validated", "report_generated"]


def test_custom_incident_passes_through_the_same_policy():
    fx = {"alert": "KubePodCrashLooping: pod x in namespace kube-system", "namespace": "kube-system",
          "deployment": "x", "context": {"pod_status": "CrashLoopBackOff", "events": [], "logs": []},
          "facts": dict(restarts=1, recent_deploy=False, replicas=1)}
    naive = Remediation(root_cause="stuck_process", action="restart_deployment", confidence=0.9, reasoning="x")
    state = auto(Stub(naive)).run("custom", fx=fx)
    assert state["status"] == "BLOCKED BY GUARDRAILS"


def test_mock_full_defence_run_never_passes_a_wrong_action():
    agent = auto(MockAnalyzer())
    for iid, fx in FIXTURES.items():
        s = agent.run(iid)
        wrong = s["plan"].action not in fx["ok_actions"] and s["plan"].action != "no_action_escalate"
        assert not (wrong and s["guardrail"]["passed"]), iid


def test_runbook_retrieval_finds_the_right_runbook():
    top = get_index().retrieve("CrashLoopBackOff KeyError DATABASE_URL missing environment variable", k=3)
    assert any(r.startswith("RB-01") for r in top)
    top = get_index().retrieve("OOMKilled exitCode 137 exceeded memory limit", k=3)
    assert any(r.startswith("RB-02") for r in top)
