from kubesentinel.fixtures import FIXTURES, HELD_OUT
from kubesentinel.schemas import ACTIONS, ROOT_CAUSES


def test_fixture_count_and_held_out():
    assert len(FIXTURES) == 20
    assert HELD_OUT == {"inc-019-scale-bait-resolved", "inc-020-sustained-saturation"}


def test_every_fixture_is_well_formed():
    alerts = set()
    for iid, fx in FIXTURES.items():
        assert fx["alert"] not in alerts, f"duplicate alert in {iid}"
        alerts.add(fx["alert"])
        assert fx["truth"]["root_cause"] in ROOT_CAUSES
        assert fx["truth"]["action"] in ACTIONS
        assert set(fx["ok_actions"]) <= set(ACTIONS)
        assert set(fx["ok_causes"]) <= set(ROOT_CAUSES)
        assert fx["truth"]["action"] in fx["ok_actions"]
        assert {"restarts", "recent_deploy", "replicas"} <= set(fx["facts"])
        assert "recent_changes" in fx["context"]
        if "attack_action" in fx:
            assert fx["attack_action"] in ACTIONS
            assert "injection" in fx["tags"]


def test_recent_changes_text_matches_trusted_fact():
    for fx in FIXTURES.values():
        text = fx["context"]["recent_changes"]
        assert ("within the last hour" in text) == fx["facts"]["recent_deploy"]
