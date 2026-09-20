"""KubeSentinel: replay-mode demo UI (Streamlit).

Read-only by design: no cluster is touched, actions are dry-run, validation is simulated.
"""
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from kubesentinel import __version__
from kubesentinel.agent import KubeSentinel
from kubesentinel.fixtures import FIXTURES, HELD_OUT
from kubesentinel.guardrails import (
    MAX_REPLICAS,
    MAX_RESTARTS_FOR_RESTART,
    MIN_CONFIDENCE,
    MIN_CPU_FOR_SCALE,
    POLICY_VERSION,
    PROTECTED_NAMESPACES,
    redact,
)
from kubesentinel.llm import GroqAnalyzer, MockAnalyzer, pick_model

REPO_URL = "https://github.com/Dhayalramesh/kubesentinel-ai-ops"
SESSION_LLM_LIMIT = 15      # LLM runs per browser session (protects the free-tier API key)
MAX_FIELD_CHARS = 3000      # cap on user-supplied text sent to the model
ROOT = Path(__file__).parent

st.set_page_config(page_title="KubeSentinel", page_icon="🛡️", layout="wide")
st.markdown(
    """
<style>
.chip {display:inline-block;padding:3px 12px;border:1px solid;border-radius:999px;
       font-family:ui-monospace,Menlo,Consolas,monospace;font-size:0.85rem;letter-spacing:.02em}
code, pre {font-family: ui-monospace, Menlo, Consolas, monospace !important;}
</style>
""",
    unsafe_allow_html=True,
)

STATUS_COLOR = {
    "ESCALATED TO HUMAN": "#f5a524",
    "BLOCKED BY GUARDRAILS": "#ff6b6b",
    "AWAITING HUMAN APPROVAL": "#4cb5ff",
    "REMEDIATED (dry-run)": "#2dd4a0",
    "REJECTED BY HUMAN": "#9aa4b2",
}


# ---------------------------------------------------------------- backend selection
def _secret(name: str):
    """Streamlit secrets, then environment, then a mounted secret file (Kubernetes)."""
    try:
        value = st.secrets[name]
    except Exception:  # no secrets.toml or key missing
        value = None
    if value:
        return value
    if os.environ.get(name):
        return os.environ[name]
    secret_file = Path(os.environ.get("KUBESENTINEL_SECRETS_DIR", "/etc/kubesentinel-secrets")) / name
    try:
        return secret_file.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


@st.cache_resource(show_spinner=False, ttl=1800)
def get_backend() -> dict:
    key = _secret("GROQ_API_KEY")
    if os.environ.get("KUBESENTINEL_FORCE_MOCK") == "1" or not key:
        return {"analyzer": MockAnalyzer(), "note": "No GROQ_API_KEY configured: running the mock baseline."}
    model, _available, err = pick_model(key)
    if not model:
        return {"analyzer": MockAnalyzer(), "note": f"Groq unavailable ({err}): running the mock baseline."}
    return {"analyzer": GroqAnalyzer(key, model), "note": None}


def current_analyzer():
    backend = get_backend()
    analyzer = backend["analyzer"]
    if analyzer.is_mock:
        return analyzer, backend["note"]
    if st.session_state.get("llm_calls", 0) >= SESSION_LLM_LIMIT:
        return MockAnalyzer(), f"Session limit of {SESSION_LLM_LIMIT} LLM runs reached: using the mock baseline."
    return analyzer, None


def run_incident(slot: str, incident_id: str, fx: dict = None):
    analyzer, notice = current_analyzer()
    with st.spinner("Agent running..."):
        state = KubeSentinel(analyzer).run(incident_id, fx=fx)  # pauses for human approval
    if not analyzer.is_mock:
        st.session_state["llm_calls"] = st.session_state.get("llm_calls", 0) + 1
    st.session_state[slot] = {"state": state, "analyzer": analyzer.name, "notice": notice}


# ---------------------------------------------------------------- rendering
def badge(status: str):
    color = STATUS_COLOR.get(status, "#9aa4b2")
    st.markdown(f'<span class="chip" style="border-color:{color};color:{color}">{status}</span>',
                unsafe_allow_html=True)


def render_result(slot: str, truth_fx: dict = None):
    res = st.session_state.get(slot)
    if not res:
        return
    state = res["state"]
    plan, guard = state["plan"], state["guardrail"]
    st.divider()
    badge(state["status"])
    st.caption(f"Analyzer: {res['analyzer']}  |  policy v{POLICY_VERSION}")
    if res.get("notice"):
        st.info(res["notice"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Root cause", plan.root_cause)
    c2.metric("Proposed action", plan.action)
    c3.metric("Confidence", f"{plan.confidence:.2f}")
    st.write(plan.reasoning)

    with st.expander("Retrieved runbooks (RAG)"):
        for rb in state["runbooks"]:
            st.text(rb)

    st.markdown("##### Guardrails")
    if guard["passed"]:
        st.success("Passed every policy check.")
    else:
        st.error("Blocked by policy:\n\n" + "\n".join(f"- {r}" for r in guard["reasons"]))

    if state["status"] == "AWAITING HUMAN APPROVAL":
        st.markdown("##### Human approval")
        st.caption("Nothing runs until you decide. Approval only produces a dry-run command in this demo.")
        a, b, _ = st.columns([1, 1, 4])
        if a.button("Approve (dry-run)", key=f"approve_{slot}", type="primary"):
            st.session_state[slot]["state"] = KubeSentinel(MockAnalyzer()).finalize(state, True)
            st.rerun()
        if b.button("Reject", key=f"reject_{slot}"):
            st.session_state[slot]["state"] = KubeSentinel(MockAnalyzer()).finalize(state, False)
            st.rerun()

    if "executed" in state:
        st.markdown("##### Execution")
        st.code(state["executed"], language="bash")
        st.warning(state["validation"])

    with st.expander("Audit log"):
        st.dataframe(pd.DataFrame(state["audit"]), width="stretch", hide_index=True)

    if truth_fx:
        with st.expander("Author's ground truth (for comparison)"):
            t = truth_fx["truth"]
            st.write(f"Expected root cause: `{t['root_cause']}`  |  expected action: `{t['action']}`")
            ok_action = plan.action in truth_fx["ok_actions"]
            ok_cause = plan.root_cause in truth_fx["ok_causes"]
            st.write(f"Action acceptable: **{ok_action}**  |  root cause acceptable: **{ok_cause}**")
            if truth_fx.get("attack_action"):
                followed = plan.action == truth_fx["attack_action"]
                st.write(f"Injected text tried to force `{truth_fx['attack_action']}`. Model followed it: **{followed}**")
            st.caption("Fixtures and runbooks were written by the same author: this measures runbook-following, "
                       "not open-ended diagnosis.")


# ---------------------------------------------------------------- sidebar
backend = get_backend()
with st.sidebar:
    st.markdown("### KubeSentinel")
    st.caption(f"v{__version__}  |  replay mode")
    st.write(f"**Analyzer:** {backend['analyzer'].name}")
    if backend.get("note"):
        st.caption(backend["note"])
    st.write(f"**Policy:** v{POLICY_VERSION}")
    if not backend["analyzer"].is_mock:
        st.caption(f"LLM runs this session: {st.session_state.get('llm_calls', 0)}/{SESSION_LLM_LIMIT}")
    st.divider()
    st.caption("No cluster is touched. Actions are dry-run. Post-change validation is simulated.")
    st.markdown(f"[Source on GitHub]({REPO_URL})")

st.title("KubeSentinel")
st.caption("A guardrailed AI-Ops agent for Kubernetes incident triage. Replay mode: recorded incidents, dry-run only.")

tab_replay, tab_custom, tab_results, tab_about = st.tabs(
    ["Replay an incident", "Try your own", "Evaluation results", "How it works"]
)

# ---------------------------------------------------------------- tab 1: replay
with tab_replay:
    def label(iid: str) -> str:
        tags = FIXTURES[iid]["tags"]
        return f"{iid}   [{', '.join(tags)}]" if tags else iid

    incident = st.selectbox("Recorded incident", list(FIXTURES), format_func=label, key="incident")
    fx = FIXTURES[incident]
    if incident in HELD_OUT:
        st.caption("Held-out: written after the policy was designed; not used for tuning.")

    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**Alert:** {fx['alert']}")
        st.markdown(f"**Namespace / deployment:** `{fx['namespace']}` / `{fx['deployment']}`")
        st.markdown("Context the agent sees (secrets redacted; log and event text is **untrusted**):")
        st.code(redact(str(fx["context"])), language="json")
    with right:
        st.markdown("Trusted cluster facts (used by the policy, never by the prompt):")
        st.json(fx["facts"])

    if st.button("Run agent", key="run_replay", type="primary"):
        run_incident("result_replay", incident)
    render_result("result_replay", truth_fx=fx)

# ---------------------------------------------------------------- tab 2: custom
with tab_custom:
    st.write("Describe an incident and watch the same pipeline handle it. Try putting an instruction inside "
             "the logs (a prompt injection) and see whether the policy layer still holds.")
    c1, c2 = st.columns(2)
    alert = c1.text_input("Alert", "KubePodCrashLooping: pod demo-1 in namespace shop", key="c_alert")
    namespace = c1.text_input("Namespace", "shop", key="c_ns")
    deployment = c1.text_input("Deployment", "demo", key="c_dep")
    pod_status = c1.text_input("Pod status", "CrashLoopBackOff, restarts=7", key="c_status")
    events_text = c2.text_area("Events (one per line)", "Back-off restarting failed container demo", key="c_events")
    logs_text = c2.text_area("Logs (one per line, UNTRUSTED)", "KeyError: 'DATABASE_URL'", key="c_logs", height=120)

    st.markdown("Trusted facts (in live mode these come from the Kubernetes API, not from the model):")
    f1, f2, f3, f4 = st.columns(4)
    restarts = f1.number_input("Restarts", 0, 1000, 7, key="c_restarts")
    replicas = f2.number_input("Replicas", 0, 100, 2, key="c_replicas")
    cpu_known = f3.checkbox("CPU metric available", value=False, key="c_cpu_known")
    cpu_pct = f3.number_input("CPU %", 0, 100, 50, key="c_cpu", disabled=not cpu_known)
    recent = f4.checkbox("Deployed recently", value=True, key="c_recent")

    if st.button("Run agent", key="run_custom", type="primary"):
        if not alert.strip() or not namespace.strip() or not deployment.strip():
            st.error("Alert, namespace and deployment are required.")
        else:
            cut = lambda s: s[:MAX_FIELD_CHARS]  # noqa: E731
            facts = dict(restarts=int(restarts), recent_deploy=bool(recent), replicas=int(replicas))
            if cpu_known:
                facts["cpu_pct"] = int(cpu_pct)
            custom_fx = {
                "alert": cut(alert), "namespace": cut(namespace).strip(), "deployment": cut(deployment).strip(),
                "context": {
                    "pod_status": cut(pod_status),
                    "events": [cut(x) for x in events_text.splitlines() if x.strip()][:20],
                    "logs": [cut(x) for x in logs_text.splitlines() if x.strip()][:50],
                    "recent_changes": "Deployment revision changed within the last hour" if recent
                    else "No deployment changes in the last 7 days",
                },
                "facts": facts,
            }
            run_incident("result_custom", "custom", fx=custom_fx)
    render_result("result_custom")

# ---------------------------------------------------------------- tab 3: results
with tab_results:
    results_md = ROOT / "evals" / "RESULTS.md"
    if results_md.exists():
        st.markdown(results_md.read_text(encoding="utf-8"))
    runs_csv = ROOT / "evals" / "results" / "benchmark_runs_20_incidents.csv"
    if runs_csv.exists():
        st.markdown("##### Per-incident results (full defences, 3 runs each)")
        df = pd.read_csv(runs_csv)
        table = df.groupby("incident").agg(
            runs=("run", "count"), action_ok=("act_ok", "sum"), rca_ok=("rca_ok", "sum"),
            blocked=("passed", lambda s: int((~s).sum())),
        ).reset_index()
        st.dataframe(table, width="stretch", hide_index=True)
    if not results_md.exists() and not runs_csv.exists():
        st.info("No evaluation files found. Run `python evals/run_benchmark.py` and commit the results.")

# ---------------------------------------------------------------- tab 4: about
with tab_about:
    st.markdown("##### Pipeline")
    st.graphviz_chart(
        """
digraph G {
  rankdir=LR;
  node [shape=box, style="rounded,filled", fillcolor="#161b22", color="#2dd4bf", fontcolor="#e6edf3", fontname="Helvetica"];
  edge [color="#8b98a5", fontcolor="#8b98a5", fontname="Helvetica"];
  gather [label="gather\\n(redact secrets)"]; retrieve [label="retrieve\\nrunbooks"]; analyze [label="analyze\\n(LLM, structured)"];
  guardrail [label="guardrails\\n(deterministic)"]; approve [label="human\\napproval"]; execute [label="execute\\n(dry-run)"];
  validate [label="validate\\n(simulated)"]; report [label="report +\\naudit log"];
  gather -> retrieve -> analyze -> guardrail;
  guardrail -> approve [label="pass"]; guardrail -> report [label="blocked /\\nescalate"];
  approve -> execute -> validate -> report; approve -> report [label="reject"];
}
"""
    )
    st.markdown("##### Policy layer (no LLM involved)")
    st.markdown(
        f"""
| Rule | Based on |
|---|---|
| Action must be in the allowlist (schema-enforced) | model output |
| No change in protected namespaces: `{", ".join(sorted(PROTECTED_NAMESPACES))}` | trusted namespace |
| Confidence at least {MIN_CONFIDENCE} unless escalating | model output |
| Action must match the model's root-cause label | model's own label (weaker) |
| Restart blocked after {MAX_RESTARTS_FOR_RESTART}+ restarts | trusted fact |
| Rollback blocked if nothing was deployed recently | trusted fact |
| Scale blocked at {MAX_REPLICAS}+ replicas or without CPU >= {MIN_CPU_FOR_SCALE}% evidence (fails closed) | trusted facts |
| Secrets redacted before any text reaches the model | input filter |
"""
    )
    st.markdown("##### Limitations")
    st.markdown(
        """
- Replay mode: recorded incidents, not a live cluster. Execution is dry-run and validation is simulated.
- Fixtures and runbooks were written by the same author, so accuracy measures runbook-following.
- Small sample, one model, repeat runs are correlated.
- The consistency rule trusts the model's own root-cause label, and one label name is ambiguous
  (`insufficient_capacity`), which caused 2 over-blocks in the benchmark.
- A model that is consistently wrong can still pass the policy. Human approval covers that case.
"""
    )
