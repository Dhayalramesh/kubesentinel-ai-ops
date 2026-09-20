"""LangGraph agent: gather -> retrieve -> analyze -> guardrail -> (approve -> execute -> validate) -> report.

Replay mode: ``gather`` reads a recorded incident, ``execute`` only prints a dry-run command and
``validate`` is SIMULATED. Live mode would swap those three for Kubernetes/Prometheus API calls.
"""
import json
import operator
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, TypedDict

from langgraph.graph import END, StateGraph

from .fixtures import get_fixture
from .guardrails import redact, run_guardrails
from .runbooks import get_index
from .schemas import Remediation


class State(TypedDict, total=False):
    incident_id: str
    fx: dict
    context: str
    runbooks: list[str]
    plan: Remediation
    guardrail: dict
    approved: bool | None
    executed: str
    validation: str
    status: str
    report: str
    audit: Annotated[list, operator.add]


def _entry(incident_id: str, event: str, detail) -> dict:
    return {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "incident": incident_id,
        "event": event,
        "detail": detail if isinstance(detail, str) else json.dumps(detail, default=str),
    }


def _command(action: str, deployment: str, namespace: str) -> str:
    return {
        "rollback_deployment": f"kubectl rollout undo deployment/{deployment} -n {namespace}",
        "restart_deployment": f"kubectl rollout restart deployment/{deployment} -n {namespace}",
        "scale_deployment": f"kubectl scale deployment/{deployment} --replicas=+1 -n {namespace}",
        "increase_memory_limit": f"kubectl set resources deployment/{deployment} --limits=memory=<2x current> -n {namespace}",
    }[action]


class KubeSentinel:
    def __init__(self, analyzer, approver: Callable[[State], bool] | None = None, dry_run: bool = True):
        """``approver=None`` pauses after the guardrail (status AWAITING HUMAN APPROVAL); call
        :meth:`finalize` with the human's decision. ``approver=lambda s: True`` auto-approves."""
        if not dry_run:
            raise NotImplementedError("Replay mode is dry-run only. Live execution is not implemented.")
        self.analyzer = analyzer
        self.approver = approver
        self.dry_run = dry_run
        self.graph = self._build()

    # ---- nodes -------------------------------------------------------------------------------
    def _gather(self, state: State) -> dict:
        fx = state.get("fx") or get_fixture(state["incident_id"])
        context = redact(json.dumps(fx["context"], indent=2))  # redact BEFORE any LLM call
        return {"fx": fx, "context": context, "audit": [_entry(state["incident_id"], "gathered_context", fx["alert"])]}

    def _retrieve(self, state: State) -> dict:
        runbooks = get_index().retrieve(state["fx"]["alert"] + " " + state["context"])
        names = [r.split(":")[0] for r in runbooks]
        return {"runbooks": runbooks, "audit": [_entry(state["incident_id"], "retrieved_runbooks", names)]}

    def _analyze(self, state: State) -> dict:
        iid = state["incident_id"]
        audit = []
        try:
            plan = self.analyzer.analyze(state["fx"], state["context"], state["runbooks"])
        except Exception as exc:  # invalid or unsafe output, rate limit, network: escalate, never guess
            audit.append(_entry(iid, "analysis_failed", f"{type(exc).__name__}: {str(exc)[:200]}"))
            plan = Remediation(root_cause="unknown", action="no_action_escalate", confidence=0.0,
                               reasoning=f"analysis failed: {type(exc).__name__}")
        audit.append(_entry(iid, "plan_proposed", plan.model_dump()))
        return {"plan": plan, "audit": audit}

    def _guardrail(self, state: State) -> dict:
        fx = state["fx"]
        result = run_guardrails(state["plan"], fx["namespace"], fx.get("facts"))
        return {"guardrail": result, "audit": [_entry(state["incident_id"], "guardrail_result", result)]}

    def _approve(self, state: State) -> dict:
        ok = bool(self.approver(state)) if self.approver else False
        return {"approved": ok, "audit": [_entry(state["incident_id"], "human_approval", "approved" if ok else "rejected")]}

    def _execute(self, state: State) -> dict:
        fx, plan = state["fx"], state["plan"]
        cmd = _command(plan.action, fx["deployment"], fx["namespace"])
        out = f"[DRY-RUN] would run: {cmd}"
        return {"executed": out, "audit": [_entry(state["incident_id"], "executed", out)]}

    def _validate(self, state: State) -> dict:
        text = "SIMULATED: a live post-change check would compare pod status, restarts and error rate"
        return {"validation": text, "audit": [_entry(state["incident_id"], "validated", text)]}

    def _report(self, state: State) -> dict:
        plan, guard = state["plan"], state["guardrail"]
        if plan.action == "no_action_escalate":
            status = "ESCALATED TO HUMAN"
        elif not guard["passed"]:
            status = "BLOCKED BY GUARDRAILS"
        elif state.get("approved") is False:
            status = "REJECTED BY HUMAN"
        elif "executed" not in state:
            status = "AWAITING HUMAN APPROVAL"
        else:
            status = "REMEDIATED (dry-run)"
        text = (
            f"## Incident {state['incident_id']} - {status}\n"
            f"- Alert: {state['fx']['alert']}\n"
            f"- Root cause: {plan.root_cause} (confidence {plan.confidence:.2f})\n"
            f"- Proposed action: {plan.action}\n"
            f"- Guardrails: {guard}\n"
            f"- Executed: {state.get('executed', 'n/a')}\n"
            f"- Validation: {state.get('validation', 'n/a')}\n"
            f"- Reasoning: {plan.reasoning}"
        )
        return {"status": status, "report": text, "audit": [_entry(state["incident_id"], "report_generated", status)]}

    # ---- routing -----------------------------------------------------------------------------
    def _after_guardrail(self, state: State) -> str:
        if not state["guardrail"]["passed"] or state["plan"].action == "no_action_escalate":
            return "report"
        return "approve" if self.approver else "report"  # no approver: pause for a human

    @staticmethod
    def _after_approval(state: State) -> str:
        return "execute" if state["approved"] else "report"

    def _build(self):
        g = StateGraph(State)
        for name, fn in [("gather", self._gather), ("retrieve", self._retrieve), ("analyze", self._analyze),
                         ("guardrail", self._guardrail), ("approve", self._approve), ("execute", self._execute),
                         ("validate", self._validate), ("report", self._report)]:
            g.add_node(name, fn)
        g.set_entry_point("gather")
        g.add_edge("gather", "retrieve")
        g.add_edge("retrieve", "analyze")
        g.add_edge("analyze", "guardrail")
        g.add_conditional_edges("guardrail", self._after_guardrail, {"report": "report", "approve": "approve"})
        g.add_conditional_edges("approve", self._after_approval, {"execute": "execute", "report": "report"})
        g.add_edge("execute", "validate")
        g.add_edge("validate", "report")
        g.add_edge("report", END)
        return g.compile()

    # ---- public API --------------------------------------------------------------------------
    def run(self, incident_id: str, fx: dict | None = None) -> State:
        init: State = {"incident_id": incident_id}
        if fx is not None:
            init["fx"] = fx
        return self.graph.invoke(init)

    def finalize(self, state: State, approved: bool) -> State:
        """Continue a paused run after the human decision (execute -> validate -> report)."""
        merged: dict = dict(state)
        merged["approved"] = approved
        audit = list(state.get("audit", [])) + [
            _entry(state["incident_id"], "human_approval", "approved" if approved else "rejected")
        ]
        steps = [self._execute, self._validate] if approved else []
        for step in steps + [self._report]:
            update = step(merged)
            audit += update.pop("audit", [])
            merged.update(update)
        merged["audit"] = audit
        return merged  # type: ignore[return-value]
