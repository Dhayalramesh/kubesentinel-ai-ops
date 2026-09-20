"""KubeSentinel: replay-mode demo UI (Streamlit).

Read-only by design: no cluster is touched, actions are dry-run, validation is simulated.
"""
import json
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


@st.cache_resource(show_spinner=False, ttl=600)
def _build_backend(key: str | None) -> dict:
    """Cached per key value, so adding or changing the secret takes effect without a manual cache clear."""
    if os.environ.get("KUBESENTINEL_FORCE_MOCK") == "1" or not key:
        return {"analyzer": MockAnalyzer(), "key_found": bool(key),
                "note": "No GROQ_API_KEY configured: running the mock baseline."}
    model, _available, err = pick_model(key)
    if not model:
        return {"analyzer": MockAnalyzer(), "key_found": True,
                "note": f"Groq unavailable ({err}): running the
