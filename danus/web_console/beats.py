"""Host-owned, project-scoped Main Agent orchestration beat coordination."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any, Callable



def orchestration_observation(*, run: dict[str, Any], status: dict[str, Any],
                              memory: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, cheap watermark inputs that represent genuine Worker state."""
    workers = [{
        key: worker.get(key) for key in (
            "worker", "state", "round", "assigned", "stop_requested", "process_identity",
        )
    } for worker in status.get("workers", [])]
    worker_memory = []
    for channel in memory.get("channels", []) or []:
        kind = str(channel.get("kind") or "")
        for entry in channel.get("entries", []) or []:
            if str(entry.get("author") or "").lower() == "main_agent" or kind in {"master_guidance", "elaboration"}:
                continue
            worker_memory.append({
                "kind": kind, "id": entry.get("id"), "status": entry.get("status"),
                "timestamp_utc": entry.get("timestamp_utc"), "claim": entry.get("claim"),
            })
    return {
        "run": {"id": run.get("id"), "status": run.get("status"), "deadline": run.get("deadline")},
        "workers": sorted(workers, key=lambda row: str(row.get("worker") or "")),
        "worker_memory": sorted(worker_memory, key=lambda row: (str(row.get("kind")), str(row.get("id")))),
        "facts": sorted(({
            "id": str(node.get("id")),
            "status": node.get("status") or node.get("verdict") or node.get("verification_status"),
            "statement": node.get("statement"),
            "proof": node.get("proof"),
        } for node in facts.get("nodes", []) if node.get("id")), key=lambda row: row["id"]),
    }

@dataclass(frozen=True)
class BeatDecision:
    project_id: str
    reason: str
    fingerprint: str
    due: bool
    consult_due: bool = False
    summary_due: bool = False


class OrchestrationBeatCoordinator:
    """Deduplicate observations so unchanged state never spends a Main Agent turn."""

    def __init__(self, *, consult_interval_seconds: float = 2 * 3600,
                 summary_interval_seconds: float = 3600, now: Callable[[], float] | None = None):
        self.consult_interval_seconds = max(1.0, float(consult_interval_seconds))
        self.summary_interval_seconds = max(1.0, float(summary_interval_seconds))
        self._now = now or time.time
        self._state: dict[str, tuple[str, float, float, float]] = {}
        self._pending: set[str] = set()
        self._failures: dict[str, tuple[int, float]] = {}

    @staticmethod
    def fingerprint(observation: dict[str, Any]) -> str:
        stable = json.dumps(observation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(stable.encode()).hexdigest()

    def request(self, project_id: str) -> None:
        self._pending.add(project_id)

    def retry_allowed(self, project_id: str) -> bool:
        failures, next_at = self._failures.get(project_id, (0, 0.0))
        now = self._now()
        return now >= next_at

    def record_failure(self, project_id: str) -> int:
        failures, _ = self._failures.get(project_id, (0, 0.0))
        failures += 1
        self._failures[project_id] = (failures, self._now() + min(300.0, 2.0 ** failures))
        return failures

    def record_success(self, project_id: str) -> None:
        self._failures.pop(project_id, None)

    def cancel_request(self, project_id: str) -> None:
        self._pending.discard(project_id)

    def seed(self, project_id: str, *, fingerprint: str, last_beat_at: float,
             last_consult_at: float, last_summary_at: float) -> None:
        self._state.setdefault(project_id, (fingerprint, last_beat_at, last_consult_at, last_summary_at))

    def consider(self, project_id: str, observation: dict[str, Any], *, force: bool = False) -> BeatDecision:
        now = self._now()
        fingerprint = self.fingerprint(observation)
        previous = self._state.get(project_id)
        requested = project_id in self._pending
        self._pending.discard(project_id)
        changed = previous is None or previous[0] != fingerprint
        consult_due = previous is not None and now - previous[2] >= self.consult_interval_seconds
        summary_due = previous is not None and now - previous[3] >= self.summary_interval_seconds
        due = bool(force or requested or changed)
        if force or requested:
            reason = "forced"
        elif changed:
            reason = "new_state"
        elif consult_due or summary_due:
            reason = "cadence_deferred_no_change"
        else:
            reason = "no_change"
        return BeatDecision(project_id, reason, fingerprint, due, consult_due, summary_due)

    def defer_cadence(self, project_id: str, *, consult_due: bool, summary_due: bool) -> tuple[float, float]:
        """Report debt without clearing it; a later genuine beat must carry it."""
        previous = self._state.get(project_id)
        if previous is None:
            now = self._now()
            return now, now
        return previous[2], previous[3]

    def settle(self, project_id: str, observation: dict[str, Any]) -> tuple[str, float, float, float]:
        now = self._now()
        previous = self._state.get(project_id)
        state = (self.fingerprint(observation), now, previous[2] if previous else now, previous[3] if previous else now)
        self._state[project_id] = state
        self.cancel_request(project_id)
        self.record_success(project_id)
        return state

    def complete(self, project_id: str, observation: dict[str, Any], decision: BeatDecision) -> tuple[str, float, float, float]:
        fingerprint = self.fingerprint(observation)
        previous = self._state.get(project_id)
        now = self._now()
        last_consult = now if decision.consult_due or previous is None else previous[2]
        last_summary = now if decision.summary_due or previous is None else previous[3]
        state = (fingerprint, now, last_consult, last_summary)
        self._state[project_id] = state
        return state

    def forget(self, project_id: str) -> None:
        self._state.pop(project_id, None)
