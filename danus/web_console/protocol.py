"""Typed normalized Main Agent provider protocol.

Provider JSONL is decoded at this boundary. Consumers receive a typed
``NormalizedEnvelope`` and must not inspect or decode the original JSON again.
This keeps progress events and the final trace on the same interpretation of a
provider envelope.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import json
import re
from typing import Any, Iterable


MAX_DETAIL = 4000


class EventKind(str, Enum):
    SESSION_STARTED = "session.started"
    PROCESS_STARTED = "process.started"
    TURN_STARTED = "turn.started"
    AGENT_PROGRESS = "agent.progress"
    AGENT_MESSAGE = "agent.message"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TURN_RETRY = "turn.retry"
    TURN_COMPLETED = "turn.completed"
    TURN_FAILED = "turn.failed"


class ProtocolEnvelopeError(ValueError):
    pass


@dataclass(frozen=True)
class ProviderEnvelope:
    """One successfully decoded provider JSONL object."""

    kind: str
    payload: dict[str, Any]
    item: dict[str, Any]
    response: dict[str, Any]
    response_output: tuple[dict[str, Any], ...]
    session_id: str | None
    raw: dict[str, Any] = field(repr=False)
    shape_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class NormalizedEvent:
    kind: EventKind
    session_id: str | None = None
    process_id: str | None = None
    turn_id: str | None = None
    call_id: str | None = None
    tool: str | None = None
    detail: str = ""
    status: str | None = None
    payload: dict[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        out = {"type": self.kind.value, "detail": self.detail[:MAX_DETAIL]}
        for key in ("session_id", "process_id", "turn_id", "call_id", "tool", "status"):
            value = getattr(self, key)
            if value is not None:
                out[key] = str(value)[:200]
        return out


@dataclass(frozen=True)
class NormalizedEnvelope:
    """Provider-neutral meaning derived from exactly one decoded envelope."""

    source: ProviderEnvelope
    events: tuple[NormalizedEvent, ...] = ()
    reply: str | None = None
    terminal_state: str | None = None
    failure: tuple[str | None, str] | None = None
    tool_activity: bool = False
    parse_uncertain: bool = False


@dataclass(frozen=True)
class NormalizedTrace:
    session_id: str | None
    reply: str
    terminal_state: str | None
    failure: tuple[str | None, str] | None
    tool_activity: bool
    parse_uncertain: bool
    identity_conflict: tuple[str, str] | None = None


_TOOL_CALL_TYPES = {
    "function_call", "custom_tool_call", "tool_search_call", "web_search_call",
    "mcp_tool_call", "tool_call",
}
_TOOL_OUTPUT_TYPES = {
    "function_call_output", "custom_tool_call_output", "tool_search_output",
}
_TRACE_TOOL_TYPES = _TOOL_CALL_TYPES | _TOOL_OUTPUT_TYPES | {
    "command_execution", "file_change",
}
_PASSIVE_KINDS = {"session_meta", "world_state", "turn_context"}
_TRANSIENT_ERROR = re.compile(r"^\s*reconnecting(?:\.{3}|\b)", re.IGNORECASE)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str | None:
    rendered = str(value or "")
    return rendered or None


def _failure(value: Any) -> tuple[str | None, str]:
    if isinstance(value, dict):
        code = _string(value.get("codex_error_info") or value.get("code"))
        return code, str(value.get("message") or value)
    return None, str(value or "provider error")


def _tool_output_failed(obj: dict[str, Any]) -> bool:
    if obj.get("is_error") or obj.get("error"):
        return True
    result = obj.get("output") if obj.get("output") is not None else obj.get("result")
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (TypeError, json.JSONDecodeError):
            result = None
    return bool(isinstance(result, dict) and (
        result.get("is_error") or result.get("error")
        or str(result.get("status") or "").lower() in {"failed", "error", "rejected"}
        or result.get("accepted") is False
    ))


def _message_text(obj: dict[str, Any]) -> str:
    for key in ("message", "text", "content", "output_text"):
        text = _text_value(obj.get(key))
        if text:
            return text
    return ""


def _text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_text_value(part) for part in value)
    if isinstance(value, dict):
        for key in ("text", "value", "output_text", "message", "content"):
            text = _text_value(value.get(key))
            if text:
                return text
    return ""


def _shape_errors(
    kind: str, raw: dict[str, Any], payload_value: Any, item_value: Any,
    response_value: Any, session_id: str | None,
) -> tuple[str, ...]:
    """Validate the required structural shape of known provider envelopes."""

    errors: list[str] = []
    if kind == "thread.started" and not session_id:
        errors.append("thread.started.thread_id")
    elif kind == "session_meta" and not session_id:
        errors.append("session_meta.session_id")
    elif kind in {"event_msg", "response_item"}:
        if not isinstance(payload_value, dict):
            errors.append(f"{kind}.payload")
        elif not isinstance(payload_value.get("type"), str) or not payload_value.get("type"):
            errors.append(f"{kind}.payload.type")
    elif kind in {"item.started", "item.completed"}:
        if not isinstance(item_value, dict):
            errors.append(f"{kind}.item")
        elif not isinstance(item_value.get("type"), str) or not item_value.get("type"):
            errors.append(f"{kind}.item.type")
    elif kind == "response.completed":
        if not isinstance(response_value, dict):
            errors.append("response.completed.response")
        elif not isinstance(response_value.get("output"), list):
            errors.append("response.completed.response.output")
        elif any(
            not isinstance(obj, dict) or not isinstance(obj.get("type"), str) or not obj.get("type")
            for obj in response_value["output"]
        ):
            errors.append("response.completed.response.output.item")
    elif kind == "response.failed":
        response_error = response_value.get("error") if isinstance(response_value, dict) else None
        if not (response_error or raw.get("error") or raw.get("message")):
            errors.append("response.failed.response.error")
    elif kind == "turn.failed" and not (
        raw.get("error") or raw.get("message")
        or (payload_value.get("error") if isinstance(payload_value, dict) else None)
    ):
        errors.append("turn.failed.error")
    elif kind == "error" and not (raw.get("error") or raw.get("message")):
        errors.append("error.message")
    return tuple(errors)


def parse_provider_line(line: str) -> ProviderEnvelope | None:
    """Decode one provider line once and return its typed structural shape."""

    try:
        raw = json.loads(line)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    payload_value = raw.get("payload")
    item_value = raw.get("item")
    payload = _dict(payload_value)
    item = _dict(item_value)
    response_value = raw.get("response")
    if response_value is None and isinstance(payload_value, dict):
        response_value = payload_value.get("response")
    response = _dict(response_value)
    output = response.get("output")
    response_output = tuple(obj for obj in output if isinstance(obj, dict)) if isinstance(output, list) else ()
    session_id = _string(
        raw.get("thread_id") or payload.get("thread_id") or payload.get("session_id")
        or raw.get("session_id")
    )
    return ProviderEnvelope(
        kind=str(raw.get("type") or ""), payload=payload, item=item,
        response=response, response_output=response_output, session_id=session_id,
        shape_errors=_shape_errors(
            str(raw.get("type") or ""), raw, payload_value, item_value,
            response_value, session_id,
        ), raw=raw,
    )


def _object_events(
    obj: dict[str, Any], *, phase: str, session_id: str | None,
    process_id: str | None, turn_id: str | None,
) -> tuple[list[NormalizedEvent], str | None, bool, bool]:
    """Normalize one response/item object."""

    item_type = str(obj.get("type") or "")
    common = {
        "session_id": session_id, "process_id": process_id, "turn_id": turn_id,
        "payload": {"item_type": item_type, "phase": phase, "object": obj},
    }
    events: list[NormalizedEvent] = []
    reply: str | None = None
    tool_activity = item_type in _TRACE_TOOL_TYPES
    uncertain = False

    if item_type == "reasoning":
        events.append(NormalizedEvent(
            EventKind.AGENT_PROGRESS, detail=str(obj.get("summary") or ""), **common,
        ))
    elif item_type in {"agent_message", "message"}:
        if str(obj.get("role") or "assistant") == "assistant":
            reply = _message_text(obj)
            if reply:
                events.append(NormalizedEvent(EventKind.AGENT_MESSAGE, detail=reply, **common))
    elif item_type in _TOOL_CALL_TYPES:
        tool = _string(obj.get("name") or obj.get("tool") or item_type)
        completed = phase == "completed"
        error = obj.get("error")
        status = str(obj.get("status") or "").lower()
        failed = bool(error or status in {"failed", "error", "rejected"})
        detail = (
            error or obj.get("result") or obj.get("output") or ""
            if completed else obj.get("arguments") or obj.get("input") or obj.get("query") or ""
        )
        events.append(NormalizedEvent(
            EventKind.TOOL_COMPLETED if completed else EventKind.TOOL_STARTED,
            call_id=_string(obj.get("call_id") or obj.get("id")),
            tool=tool, detail=str(detail),
            status="failed" if failed else "completed" if completed else "started", **common,
        ))
    elif item_type in _TOOL_OUTPUT_TYPES:
        failed = _tool_output_failed(obj)
        events.append(NormalizedEvent(
            EventKind.TOOL_COMPLETED, call_id=_string(obj.get("call_id") or obj.get("id")),
            tool="tool result", detail=str(obj.get("output") or obj.get("result") or ""),
            status="failed" if failed else "completed", **common,
        ))
    elif item_type == "command_execution":
        completed = phase == "completed"
        exit_code = obj.get("exit_code")
        error = obj.get("error")
        detail = (
            error or obj.get("aggregated_output") or obj.get("output") or ""
            if completed else obj.get("command") or obj.get("cmd") or ""
        )
        events.append(NormalizedEvent(
            EventKind.TOOL_COMPLETED if completed else EventKind.TOOL_STARTED,
            call_id=_string(obj.get("id") or obj.get("call_id")), tool="exec_command",
            detail=str(detail),
            status=("failed" if exit_code or error else "completed") if completed else "started",
            **common,
        ))
    elif item_type == "file_change":
        completed = phase == "completed"
        error = obj.get("error")
        events.append(NormalizedEvent(
            EventKind.TOOL_COMPLETED if completed else EventKind.TOOL_STARTED,
            tool="file_change",
            status="failed" if error else "completed" if completed else "started", **common,
        ))
    elif item_type:
        uncertain = True
    return events, reply, tool_activity, uncertain


def normalize_provider_envelope(
    line_or_envelope: str | ProviderEnvelope, *, session_id: str | None = None,
    process_id: str | None = None, turn_id: str | None = None,
    session_is_new: bool = True,
) -> NormalizedEnvelope | None:
    """Return the sole semantic normalization for one provider envelope."""

    envelope = (
        parse_provider_line(line_or_envelope)
        if isinstance(line_or_envelope, str) else line_or_envelope
    )
    if envelope is None:
        return None

    kind = envelope.kind
    payload = envelope.payload
    sid = envelope.session_id or session_id
    events: list[NormalizedEvent] = []
    reply: str | None = None
    terminal: str | None = None
    failure: tuple[str | None, str] | None = None
    tool_activity = False
    uncertain = bool(envelope.shape_errors)

    common = {"session_id": sid, "process_id": process_id, "turn_id": turn_id}
    if kind == "thread.started":
        if session_is_new and sid:
            events.append(NormalizedEvent(
                EventKind.SESSION_STARTED, detail="Main Agent Session available", **common,
            ))
    elif kind == "turn.started":
        events.append(NormalizedEvent(
            EventKind.TURN_STARTED, detail="Main Agent Turn started", **common,
        ))
    elif kind == "event_msg":
        event_type = str(payload.get("type") or "")
        if event_type in {"agent_message", "message"}:
            reply = _message_text(payload)
            if reply:
                events.append(NormalizedEvent(EventKind.AGENT_MESSAGE, detail=reply, payload=payload, **common))
        elif event_type == "task_complete":
            error = payload.get("error")
            if payload.get("last_agent_message"):
                reply = str(payload["last_agent_message"])
            if error:
                failure = _failure(error)
                terminal = "failed"
                events.append(NormalizedEvent(
                    EventKind.TURN_FAILED, detail=failure[1], status="failed", payload=payload, **common,
                ))
            else:
                terminal = "completed"
                events.append(NormalizedEvent(
                    EventKind.TURN_COMPLETED, detail="Main Agent 已完成本次回复",
                    status="completed", payload=payload, **common,
                ))
        elif event_type and "tool_call" in event_type:
            completed = event_type.endswith(("end", "completed"))
            error = payload.get("error")
            detail = (
                payload.get("result") or payload.get("output") or error or ""
                if completed else payload.get("arguments") or payload.get("input") or ""
            )
            events.append(NormalizedEvent(
                EventKind.TOOL_COMPLETED if completed else EventKind.TOOL_STARTED,
                call_id=_string(payload.get("call_id") or payload.get("id")),
                tool=_string(payload.get("tool") or payload.get("name") or "MCP tool"),
                detail=str(detail),
                status="failed" if error else "completed" if completed else "started",
                payload={"event_type": event_type, "object": payload}, **common,
            ))
            tool_activity = True
        elif event_type:
            uncertain = True
    elif kind == "response_item":
        obj_events, reply, tool_activity, uncertain = _object_events(
            payload, phase="announced", session_id=sid,
            process_id=process_id, turn_id=turn_id,
        )
        uncertain = uncertain or bool(envelope.shape_errors)
        events.extend(obj_events)
    elif kind in {"item.started", "item.completed"}:
        obj_events, reply, tool_activity, uncertain = _object_events(
            envelope.item, phase="completed" if kind == "item.completed" else "started",
            session_id=sid, process_id=process_id, turn_id=turn_id,
        )
        uncertain = uncertain or bool(envelope.shape_errors)
        events.extend(obj_events)
    elif kind == "response.completed":
        for obj in envelope.response_output:
            obj_events, object_reply, object_tool, object_uncertain = _object_events(
                obj, phase="announced", session_id=sid,
                process_id=process_id, turn_id=turn_id,
            )
            events.extend(obj_events)
            reply = object_reply or reply
            tool_activity = tool_activity or object_tool
            uncertain = uncertain or object_uncertain
    elif kind == "turn.completed":
        terminal = "completed"
        reply = _string(envelope.raw.get("last_agent_message"))
        events.append(NormalizedEvent(
            EventKind.TURN_COMPLETED, detail="Main Agent 已完成本次回复",
            status="completed", payload=envelope.raw, **common,
        ))
    elif kind in {"turn.failed", "response.failed"}:
        failure = _failure(
            envelope.response.get("error")
            or envelope.raw.get("error") or envelope.raw.get("message")
            or payload.get("error") or payload.get("message") or payload
        )
        terminal = "failed"
        events.append(NormalizedEvent(
            EventKind.TURN_FAILED, detail=failure[1], status="failed",
            payload=envelope.raw, **common,
        ))
    elif kind == "error":
        error_value = envelope.raw.get("error") or envelope.raw.get("message") or payload
        error_message = _failure(error_value)[1]
        # Codex 0.148 reconnect notices are transport progress, not terminal.
        if not _TRANSIENT_ERROR.match(error_message):
            failure = _failure(error_value)
            terminal = "failed"
            events.append(NormalizedEvent(
                EventKind.TURN_FAILED, detail=failure[1], status="failed",
                payload=envelope.raw, **common,
            ))
    elif kind == "response.output_text.done":
        reply = _string(envelope.raw.get("text") or payload.get("text"))
    elif kind not in _PASSIVE_KINDS:
        uncertain = True

    return NormalizedEnvelope(
        source=envelope, events=tuple(events), reply=reply,
        terminal_state=terminal, failure=failure,
        tool_activity=tool_activity, parse_uncertain=uncertain,
    )


def normalize_provider_line(
    line: str, *, session_id: str | None = None, process_id: str | None = None,
    turn_id: str | None = None, session_is_new: bool = True,
) -> list[NormalizedEvent]:
    normalized = normalize_provider_envelope(
        line, session_id=session_id, process_id=process_id, turn_id=turn_id,
        session_is_new=session_is_new,
    )
    return list(normalized.events) if normalized is not None else []


class NormalizedTraceBuilder:
    """Reduce already-normalized envelopes into one stable turn trace."""

    def __init__(
        self, *, session_id: str | None = None, process_id: str | None = None,
        turn_id: str | None = None, session_is_new: bool | None = None,
    ) -> None:
        self._session_id = session_id
        self._process_id = process_id
        self._turn_id = turn_id
        self._session_is_new = (session_id is None) if session_is_new is None else session_is_new
        self._session_event_emitted = False
        self._identity_conflict: tuple[str, str] | None = None
        self._reply = ""
        self._terminal_state: str | None = None
        self._failure: tuple[str | None, str] | None = None
        self._tool_activity = False
        self._parse_uncertain = False
        self.line_count = 0
        self.envelope_count = 0

    def consume_line(self, line: str) -> NormalizedEnvelope | None:
        self.line_count += 1
        envelope = parse_provider_line(line)
        if envelope is None:
            self._parse_uncertain = True
            return None
        return self.consume_envelope(envelope)

    def consume_envelope(self, envelope: ProviderEnvelope) -> NormalizedEnvelope:
        observed_id = envelope.session_id
        conflict_now = False
        if observed_id:
            if self._session_id is None:
                self._session_id = observed_id
            elif observed_id != self._session_id:
                if self._identity_conflict is None:
                    self._identity_conflict = (self._session_id, observed_id)
                conflict_now = True

        normalized = normalize_provider_envelope(
            envelope, session_id=self._session_id, process_id=self._process_id,
            turn_id=self._turn_id,
            session_is_new=self._session_is_new and not self._session_event_emitted,
        )
        assert normalized is not None
        self.envelope_count += 1
        self._parse_uncertain = self._parse_uncertain or normalized.parse_uncertain

        # Once identity diverges, the canonical Session stays locked and the
        # mismatching envelope plus everything after it is excluded from the
        # progress/audit sink and trace reduction.
        if conflict_now or self._identity_conflict is not None:
            self._parse_uncertain = True
            return replace(normalized, events=())

        events = list(normalized.events)
        if (
            observed_id and self._session_is_new and not self._session_event_emitted
            and not any(event.kind == EventKind.SESSION_STARTED for event in events)
        ):
            events.insert(0, NormalizedEvent(
                EventKind.SESSION_STARTED, session_id=self._session_id,
                process_id=self._process_id, turn_id=self._turn_id,
                detail="Main Agent Session available",
            ))
        if any(event.kind == EventKind.SESSION_STARTED for event in events):
            self._session_event_emitted = True

        # A failed turn is terminal for publication as well as final reduction:
        # never persist a later completion, message or tool event for it. Tool
        # activity and parse uncertainty still accumulate fail-closed because
        # they determine whether an operator may safely retry the failed turn.
        if self._terminal_state == "failed":
            self._tool_activity = self._tool_activity or normalized.tool_activity
            self._parse_uncertain = self._parse_uncertain or normalized.parse_uncertain
            return replace(normalized, events=())
        published = replace(normalized, events=tuple(events))
        self._reduce(published)
        return published

    def _reduce(self, normalized: NormalizedEnvelope) -> None:
        if normalized.reply:
            self._reply = normalized.reply
        self._tool_activity = self._tool_activity or normalized.tool_activity
        self._parse_uncertain = self._parse_uncertain or normalized.parse_uncertain

        # Terminal failure is sticky. Reconnect notices are not failures, so a
        # transient error followed by completion still succeeds.
        if normalized.terminal_state == "failed":
            self._terminal_state = "failed"
            self._failure = normalized.failure or (None, "provider error")
        elif normalized.terminal_state == "completed" and self._terminal_state != "failed":
            self._terminal_state = "completed"
            self._failure = None

    def trace(self) -> NormalizedTrace:
        return NormalizedTrace(
            self._session_id, self._reply, self._terminal_state, self._failure,
            self._tool_activity, self._parse_uncertain, self._identity_conflict,
        )


def normalize_trace(
    stdout: str, *, session_id: str | None = None,
) -> NormalizedTrace:
    builder = NormalizedTraceBuilder(session_id=session_id)
    for line in (stdout or "").splitlines():
        builder.consume_line(line)
    return builder.trace()


def normalize_envelopes(
    lines: Iterable[str], *, session_id: str | None = None,
    process_id: str | None = None, turn_id: str | None = None,
) -> tuple[list[NormalizedEnvelope], NormalizedTrace]:
    """Normalize a fixture/stream once and return its envelopes and trace."""

    builder = NormalizedTraceBuilder(
        session_id=session_id, process_id=process_id, turn_id=turn_id,
    )
    envelopes: list[NormalizedEnvelope] = []
    for line in lines:
        normalized = builder.consume_line(line)
        if normalized is not None:
            envelopes.append(normalized)
    return envelopes, builder.trace()
