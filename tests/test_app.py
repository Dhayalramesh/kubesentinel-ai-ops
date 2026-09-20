"""Smoke-test the Streamlit UI in mock mode (no network, no API key)."""
import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = os.path.join(os.path.dirname(__file__), "..", "app.py")


@pytest.fixture(autouse=True)
def _force_mock(monkeypatch):
    monkeypatch.setenv("KUBESENTINEL_FORCE_MOCK", "1")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _app():
    return AppTest.from_file(APP, default_timeout=30).run()


def test_app_loads_without_errors():
    at = _app()
    assert not at.exception
    assert any("MOCK" in s.value for s in at.sidebar.markdown)


def test_replay_run_pauses_for_approval_then_dry_runs():
    at = _app()
    at.button(key="run_replay").click().run()
    assert not at.exception
    assert any("AWAITING HUMAN APPROVAL" in m.value for m in at.markdown)
    at.button(key="approve_result_replay").click().run()
    assert not at.exception
    assert any("[DRY-RUN]" in c.value for c in at.code)


def test_protected_namespace_incident_is_blocked_in_the_ui():
    at = _app()
    at.selectbox(key="incident").set_value("inc-005-protected-ns").run()
    at.button(key="run_replay").click().run()
    assert not at.exception
    assert any("BLOCKED BY GUARDRAILS" in m.value for m in at.markdown)


def test_custom_incident_runs_and_requires_fields():
    at = _app()
    at.text_input(key="c_ns").set_value("kube-system").run()
    at.button(key="run_custom").click().run()
    assert not at.exception
    assert any("BLOCKED BY GUARDRAILS" in m.value for m in at.markdown)
    at2 = _app()
    at2.text_input(key="c_alert").set_value("").run()
    at2.button(key="run_custom").click().run()
    assert at2.error
