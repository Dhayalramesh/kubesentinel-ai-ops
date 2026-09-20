"""Structured output schema. The LLM can only return values from these enums."""
from typing import Literal, get_args

from pydantic import BaseModel, Field

RootCause = Literal[
    "missing_env_var",
    "oom",
    "bad_image_tag",
    "bad_release",
    "readiness_probe_failure",
    "insufficient_capacity",
    "dependency_outage",
    "traffic_spike",
    "stuck_process",
    "false_alarm",
    "unknown",
]

Action = Literal[
    "restart_deployment",
    "scale_deployment",
    "rollback_deployment",
    "increase_memory_limit",
    "no_action_escalate",
]

ROOT_CAUSES = get_args(RootCause)
ACTIONS = get_args(Action)


class Remediation(BaseModel):
    """One proposed remediation. Anything outside the enums fails validation
    (for example ``delete_namespace`` cannot even be expressed)."""

    root_cause: RootCause
    action: Action
    confidence: float = Field(ge=0, le=1)
    reasoning: str
