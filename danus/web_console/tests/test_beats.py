from danus.web_console.beats import OrchestrationBeatCoordinator, orchestration_observation


def test_no_change_does_not_schedule_duplicate_activation():
    clock = [100.0]
    beats = OrchestrationBeatCoordinator(consult_interval_seconds=7200, summary_interval_seconds=3600, now=lambda: clock[0])
    observation = {"workers": [{"worker": "high", "round": 1}], "facts": [], "memory": []}
    beats.request("p")
    first = beats.consider("p", observation)
    assert first.reason == "forced"
    beats.complete("p", observation, first)
    assert beats.consider("p", observation).due is False
    clock[0] += 3601
    deferred = beats.consider("p", observation)
    assert deferred.reason == "cadence_deferred_no_change"
    assert deferred.due is False
    clock[0] += 3600
    assert beats.consider("p", {"workers": [{"worker": "high", "round": 2}], "facts": [], "memory": []}).due is True


def test_project_state_changes_trigger_once_and_projects_are_isolated():
    beats = OrchestrationBeatCoordinator(now=lambda: 100.0)
    beats.request("a"); beats.request("b")
    a1 = beats.consider("a", {"facts": ["f1"]}); b1 = beats.consider("b", {"facts": ["f1"]})
    assert a1.due and b1.due
    beats.complete("a", {"facts": ["f1"]}, a1); beats.complete("b", {"facts": ["f1"]}, b1)
    a2 = beats.consider("a", {"facts": ["f2"]})
    assert a2.reason == "new_state"
    beats.complete("a", {"facts": ["f2"]}, a2)
    assert beats.consider("a", {"facts": ["f2"]}).due is False


def test_fact_verifier_transition_changes_watermark():
    base = {"run": {"id": "r", "status": "running"}, "workers": [], "memory": {"channels": []}}
    pending = {"nodes": [{"id": "f1", "status": "pending", "statement": "S"}]}
    accepted = {"nodes": [{"id": "f1", "status": "accepted", "statement": "S"}]}
    first = OrchestrationBeatCoordinator(); first.request("p")
    assert first.consider("p", orchestration_observation(run=base["run"], status={}, memory=base["memory"], facts=pending)).due
    assert first.consider("p", orchestration_observation(run=base["run"], status={}, memory=base["memory"], facts=accepted)).reason == "new_state"
