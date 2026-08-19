"""Typed normalized Main Agent provider protocol."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any

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

class ProtocolEnvelopeError(ValueError): pass

@dataclass(frozen=True)
class NormalizedEvent:
    kind: EventKind
    session_id: str | None = None
    process_id: str | None = None
    turn_id: str | None = None
    call_id: str | None = None
    detail: str = ""
    status: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out = {"type": self.kind.value, "detail": self.detail[:MAX_DETAIL]}
        for key in ("session_id", "process_id", "turn_id", "call_id", "status"):
            value = getattr(self, key)
            if value is not None: out[key] = str(value)[:200]
        return out

def parse_provider_line(line: str) -> dict[str, Any] | None:
    try: item = json.loads(line)
    except (TypeError, json.JSONDecodeError): return None
    return item if isinstance(item, dict) else None

def normalize_provider_line(line: str, *, session_id: str | None = None, process_id: str | None = None, turn_id: str | None = None) -> list[NormalizedEvent]:
    item = parse_provider_line(line)
    if item is None: return []
    kind = str(item.get("type") or "")
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    sid = str(item.get("thread_id") or payload.get("thread_id") or session_id or "") or None
    events: list[NormalizedEvent] = []
    if kind == "thread.started": events.append(NormalizedEvent(EventKind.SESSION_STARTED, session_id=sid, process_id=process_id, turn_id=turn_id, detail="Main Agent Session available"))
    elif kind == "turn.started": events.append(NormalizedEvent(EventKind.TURN_STARTED, session_id=sid, process_id=process_id, turn_id=turn_id, detail="Main Agent Turn started"))
    elif kind == "event_msg":
        typ = str(payload.get("type") or "")
        if typ in {"agent_message", "message"}: events.append(NormalizedEvent(EventKind.AGENT_MESSAGE, session_id=sid, process_id=process_id, turn_id=turn_id, detail=str(payload.get("message") or payload.get("text") or "")))
        elif typ == "task_complete": events.append(NormalizedEvent(EventKind.TURN_FAILED if payload.get("error") else EventKind.TURN_COMPLETED, session_id=sid, process_id=process_id, turn_id=turn_id, status="failed" if payload.get("error") else "completed", detail=str(payload.get("error") or "")))
    elif kind in {"item.started", "item.completed"}:
        obj = item.get("item") if isinstance(item.get("item"), dict) else {}
        typ = str(obj.get("type") or "")
        if typ in {"command_execution", "file_change", "function_call", "mcp_tool_call", "tool_call"}:
            events.append(NormalizedEvent(EventKind.TOOL_STARTED if kind.endswith("started") else EventKind.TOOL_COMPLETED, session_id=sid, process_id=process_id, turn_id=turn_id, call_id=str(obj.get("call_id") or "") or None, detail=str(obj.get("command") or obj.get("name") or typ)))
    return events

@dataclass(frozen=True)
class NormalizedTrace:
    session_id: str | None
    reply: str
    terminal_state: str | None
    failure: tuple[str | None, str] | None
    tool_activity: bool
    parse_uncertain: bool

def normalize_trace(stdout: str) -> NormalizedTrace:
    session_id = None; reply = ""; terminal = None; failure = None; tool = False; uncertain = False
    passive = {"thread.started", "turn.started", "session_meta", "world_state", "turn_context"}
    for line in (stdout or "").splitlines():
        item = parse_provider_line(line)
        if item is None: uncertain = True; continue
        kind = str(item.get("type") or ""); payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        session_id = str(item.get("thread_id") or payload.get("thread_id") or payload.get("session_id") or item.get("session_id") or session_id or "") or None
        if kind == "event_msg":
            typ = str(payload.get("type") or "")
            if typ in {"agent_message", "message"}: reply = str(payload.get("message") or payload.get("text") or reply)
            if typ == "task_complete":
                error = payload.get("error"); terminal = "failed" if error else "completed"
                if payload.get("last_agent_message"): reply = str(payload["last_agent_message"])
                if isinstance(error, dict): failure = (str(error.get("codex_error_info") or error.get("code") or "") or None, str(error.get("message") or error))
        elif kind in {"item.started", "item.completed"}:
            obj = item.get("item") if isinstance(item.get("item"), dict) else {}
            typ = str(obj.get("type") or "")
            if typ in {"command_execution", "file_change", "function_call", "function_call_output", "mcp_tool_call", "tool_call", "tool_search_call", "tool_search_output", "custom_tool_call", "custom_tool_call_output"}: tool = True
            elif typ in {"agent_message", "message"} and str(obj.get("role") or "assistant") == "assistant":
                content = obj.get("content")
                if isinstance(content, list): reply = "".join(str(part.get("text") or "") for part in content if isinstance(part, dict)) or reply
                elif isinstance(content, str): reply = content
                else: reply = str(obj.get("text") or obj.get("message") or obj.get("output_text") or reply)
            elif typ not in {"reasoning", ""}: uncertain = True
        elif kind == "response.completed":
            response = item.get("response") if isinstance(item.get("response"), dict) else payload.get("response") if isinstance(payload.get("response"), dict) else {}
            output = response.get("output") if isinstance(response.get("output"), list) else []
            for obj in output:
                typ = str(obj.get("type") or "") if isinstance(obj, dict) else ""
                if typ in {"function_call", "function_call_output", "mcp_tool_call", "tool_call", "tool_search_call", "tool_search_output"}: tool = True
                elif typ not in {"message", "reasoning", ""}: uncertain = True
        elif kind == "turn.completed":
            terminal = "completed"; failure = None
            if item.get("last_agent_message"): reply = str(item["last_agent_message"])
        elif kind in {"turn.failed", "response.failed", "error"}:
            error = item.get("error") or item.get("message") or payload.get("error") or payload.get("message") or payload
            if isinstance(error, dict): failure = (str(error.get("codex_error_info") or error.get("code") or "") or None, str(error.get("message") or error))
            else: failure = (None, str(error or "provider error"))
            terminal = "failed"
        elif kind not in passive and kind not in {"response.completed", "response.output_text.done"}: uncertain = True
    return NormalizedTrace(session_id, reply, terminal, failure, tool, uncertain)
