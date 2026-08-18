"""Static Web Console regressions for layout and worker observability."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess


STATIC = Path(__file__).resolve().parents[1] / "static"


def _asset(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")




def _javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated JavaScript function: {name}")


def _render_markdown(value: str) -> str:
    source = _asset("app.js")
    script = "\n".join((
        _javascript_function(source, "esc"),
        source[source.index("function inlineMarkdown("):source.index("function renderProjectList(")],
        f"console.log(JSON.stringify(renderMarkdown({json.dumps(value)})));",
    ))
    result = subprocess.run(
        ["node", "-e", script], check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def test_desktop_layout_prioritizes_main_conversation_width():
    css = _asset("style.css")

    assert "--project-rail-width: clamp(200px, 12vw, 232px);" in css
    assert "--worker-rail-width: clamp(224px, 14vw, 260px);" in css
    assert "--conversation-max: 1180px;" in css
    assert "grid-template-columns: minmax(0, 1fr) 7px var(--worker-rail-width)" in css
    assert "width: min(100%, var(--conversation-max))" in css
    assert "width: var(--project-rail-width); min-width: 0; max-width: var(--project-rail-width)" in css
    assert "height: 100%; min-height: 100dvh" in css

    # Regressions from the old narrow center-column bottleneck.
    assert "width: min(100%, 820px)" not in css
    assert "max-width: min(100%, 730px)" not in css


def test_worker_observability_is_structured_and_uses_markdown_transcripts():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function workerCurrentAction",
        "function workerRoundLogGroups",
        "worker-card-action",
        "worker-card-fields",
        "worker-state-panel",
        "worker-checkpoint",
        "worker-metadata",
        "metadataWasOpen",
        "local_memory_count",
        "renderWorkerRoundTranscript(groups, selectedRound, worker)",
    ):
        assert token in app

    for token in (
        "function latestWorkerEvent",
        "function isMeaningfulWorkerEvent",
        "Latest event",
        "worker-card-latest",
    ):
        assert token not in app
    assert ".worker-card-latest" not in css

    assert "function renderTranscript" in app
    assert '["exec", "apply patch"].includes(lower)' in app
    assert "/^(web search:|patch:\\s)/i" in app
    assert "renderMarkdown(block.text)" in app
    assert ".map(normalizeLogLine)" in app
    assert ".filter(Boolean)" in app
    assert "<code>${esc(line)}</code>" not in app
    assert ".worker-state.terminal" in css
    assert ".worker-checkpoint" in css
    assert ".worker-metadata" in css
    assert ".trace-markdown" in css


def test_markdown_tables_render_as_safe_structured_tables():
    app = _asset("app.js")
    css = _asset("style.css")

    assert "function markdownTableCells" in app
    assert "function isMarkdownTableDivider" in app
    assert 'class="markdown-table-wrap"' in app
    assert "<table><thead><tr>" in app
    assert "tableHead.map((cell) => `<th>${inlineMarkdown(cell)}</th>`)" in app
    assert ".markdown-table-wrap table" in css
    assert ".markdown-table-wrap th" in css


def test_fact_graph_loads_exact_local_cytoscape_distribution_and_license():
    html = _asset("index.html")
    app = _asset("app.js")
    distribution = _asset("vendor/cytoscape/3.34.0/cytoscape.min.js")
    license_text = _asset("vendor/cytoscape/3.34.0/LICENSE")
    package_config = (STATIC.parents[2] / "pyproject.toml").read_text(encoding="utf-8")

    local_script = '<script src="/static/vendor/cytoscape/3.34.0/cytoscape.min.js"></script>'
    assert local_script in html
    assert html.index(local_script) < html.index('<script src="/static/app.js"></script>')
    assert "https://unpkg.com" not in html
    assert "https://cdn.jsdelivr.net" not in html
    assert 'style="' not in app
    assert "3.34.0" in distribution
    assert len(distribution) > 400_000
    assert "The Cytoscape Consortium" in license_text
    assert "Permission is hereby granted, free of charge" in license_text
    assert '"static/vendor/cytoscape/3.34.0/*.js"' in package_config
    assert '"static/vendor/cytoscape/3.34.0/LICENSE"' in package_config


def test_fact_graph_maps_real_directed_data_with_deterministic_numbering_and_controls():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function renderFacts",
        "function pendingFactVerifications",
        "function factNodeOrder",
        "function numberedFacts",
        "function factGraphElements",
        'group: "nodes"',
        'group: "edges"',
        "source: edge.source, target: edge.target",
        'visibleNumber: `F${String(index + 1).padStart(digits, "0")}`',
        'label: `${visibleNumber} · D${depth}',
        'name: "breadthfirst"',
        "directed: true",
        'state.factCy.on("tap", "node"',
        'data-fact-control="zoom-in"',
        'data-fact-control="zoom-out"',
        'data-fact-control="fit"',
        'data-fact-control="reset-layout"',
        "fact-overview",
        "个 Fact 正在验证",
    ):
        assert token in app
    assert ".insight-card-fact" in css
    assert ".insight-card[open] { grid-column: 1 / -1" in css
    assert ".fact-graph-canvas" in css
    assert ".fact-graph-controls" in css
    assert ".fact-legend" in css
    assert ".fact-pipeline" in css

    # The prior vertically stacked disclosure list is gone.
    assert '<details class="fact-node">' not in app
    assert ".fact-node-body" not in css


def test_fact_inspector_feedback_and_accessible_real_node_navigation():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function factInspectorMarkup",
        "renderMarkdown(node.statement)",
        "renderMarkdown(node.proof)",
        "renderMarkdown(node.intuition)",
        "glossary_introduces",
        "factReferencesMarkup(references)",
        "Predecessor facts",
        'data-fact-select="${esc(id)}"',
        "Immutable ID",
        "向 Main Agent 反馈",
        "复制引用",
        "function factFeedbackPrefix",
        "不可变 ID：${entry.node.id}",
        'const composer = $("message")',
        "composer.focus()",
        "navigator.clipboard.writeText(reference)",
        'id="fact-node-picker"',
        'role="application" tabindex="0"',
        "handleFactGraphKeydown",
    ):
        assert token in app

    assert ".fact-inspector" in css
    assert ".fact-inspector-body" in css
    assert ".fact-predecessor-chip" in css
    assert ".fact-glossary" in css
    assert ".fact-references" in css
    assert ".sr-only" in css
    assert "return `关于 ${factReferenceText(factId)}的反馈：\\n`;" in app


def test_fact_graph_refresh_preserves_signature_selection_and_has_readable_fallback():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "factGraphSignature: null",
        "selectedFactId: null",
        "function factGraphSignature",
        "signature === state.factGraphSignature",
        "updateFactPipeline(verifying, verifyingCount)",
        "const retainedSelection = state.selectedFactId",
        "state.selectedFactId = retainedSelection",
        "function syncFactSelection",
        'selected.closedNeighborhood()',
        'removeClass("is-selected is-neighbor is-dimmed")',
        'typeof window.cytoscape !== "function"',
        "function showFactGraphFallback",
        'id="fact-graph-fallback"',
        "下方保留全部真实 Fact 的可读列表与检查器",
    ):
        assert token in app

    assert ".fact-fallback-list" in css
    assert ".fact-fallback-node.is-selected" in css
    assert ".fact-explorer" in css


def test_shared_memory_and_verifier_pending_states_remain_observable():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function renderMemory",
        "共享记忆",
        "/memory`",
        "last_error",
        "consecutive_failures",
        "next_retry_at",
        "排队等待可用 API 槽位",
        "还没有已验证 Fact",
        "个 Fact 正在验证",
    ):
        assert token in app
    assert ".memory-row" in css
    assert ".memory-evidence" in css
    assert ".fact-pipeline" in css


def test_architecture_correct_main_agent_and_project_configuration_are_visible():
    html = _asset("index.html")
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        'id="project-rail-resizer"',
        'id="max-parallel-workers"',
        "Worker 模型",
        "Main Agent / Strategy",
    ):
        assert token in html
    for token in (
        'api("/api/config")',
        "function bindRailResizer",
        "function renderMainAgentControl",
        "STRATEGIC ORCHESTRATOR",
        "master_guidance",
        "mainAgentInitializationMessage",
        "configuredStrategyTransport",
        "不要调用 consult",
        "max_parallel_workers",
        "worker.assigned",
        "/orchestration`",
    ):
        assert token in app
    assert "danus:rail-widths:v1" in app
    assert ".main-agent-control" in css
    assert ".rail-resizer" in css
    assert ".orchestration-warning" in css


def test_worker_trace_separates_output_and_collapses_tool_calls():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function transcriptBlocks",
        "function toolTitle",
        "function renderWorkerMessage",
        'class="message-row assistant worker-message',
        'class="trace-tool',
        'data-trace-id="',
        "rememberDrawerView",
        "openTools",
        "followTail",
        "followBottom ? trace.scrollHeight",
    ):
        assert token in app
    assert "<details class=\"trace-tool" in app
    assert ".worker-message .message-bubble" in css
    assert ".trace-tool > summary" in css
    assert ".trace-tool-body" in css


def test_worker_round_history_is_complete_numeric_selectable_and_scroll_aware():
    app = _asset("app.js")
    css = _asset("style.css")

    assert ".slice(-80)" not in app
    assert "tail 80" not in app
    for token in (
        "function workerRoundLogGroups",
        'String(item.name || "").match(/^round_(\\d+)\\.log$/)',
        "groups.set(round, { round, entries: [], lines: [] })",
        "group.lines.push(...(item.lines || []))",
        "return [...groups.values()].sort((left, right) => left.round - right.round)",
        "function latestWorkerRoundSelection",
        "groups[groups.length - 1].round",
        "const selectedRound = latestWorkerRoundSelection(workerName)",
        "[selectedRound]: { scrollTop: 0, followTail: true, forceBottom: true, openTools: [] }",
        'const roundTabs = [{ value: "all", label: "全部轮次" }',
        'data-worker-round="${esc(tab.value)}"',
        "function renderWorkerRoundTranscript",
        'selectedRound === "all" ? groups : groups.filter',
        'class="round-transcript-group" data-round="${esc(group.round)}"',
        "第 ${esc(group.round)} 轮",
        "function isTraceNearBottom",
        "followTail: isTraceNearBottom(trace)",
        "const followBottom = saved.forceBottom || saved.followTail",
        "trace.scrollTop = followBottom ? trace.scrollHeight : Math.min(saved.scrollTop || 0",
        "saved.forceBottom = false",
    ):
        assert token in app

    for token in (
        ".worker-round-tabs",
        ".worker-round-tab.is-active",
        ".round-transcript-group + .round-transcript-group",
        ".round-transcript-heading",
    ):
        assert token in css


def test_worker_panel_floats_over_unchanged_layout_and_preserves_direct_transcript():
    app = _asset("app.js")
    css = _asset("style.css")

    assert "has-worker-panel" not in app
    assert "has-worker-panel" not in css
    assert ".project-view { position: relative;" in css
    assert ".conversation-layout { display: grid; grid-template-columns: minmax(0, 1fr) 7px var(--worker-rail-width); width: 100%; height: 100%; }" in css
    assert ".rail-resizer-right { grid-column: 2; grid-row: 1; }" in css
    assert ".worker-rail { grid-column: 3; grid-row: 1; }" in css
    assert ".worker-drawer { position: absolute; z-index: 30; top: 12px; right: 12px; bottom: 12px; display: flex; width: calc(50% - 18px);" in css
    assert "border: 1px solid var(--line-strong); border-radius: 18px" in css
    assert "box-shadow: 0 24px 70px rgba(30,45,33,.18); backdrop-filter: blur(18px)" in css
    assert "grid-template-columns: minmax(0, 1fr) minmax(0, 1fr)" not in css
    assert "const groups = workerRoundLogGroups(worker.worker)" in app
    assert "renderWorkerRoundTranscript(groups, selectedRound, worker)" in app
    assert "worker?.assigned === true" in app
    assert 'kind: "assignment"' in app
    assert "text: worker.task" in app
    assert 'visible.unshift({ id: "assignment", kind: "assignment", text: worker.task })' in app
    assert 'blocks.filter((block) => block.kind !== "user")' in app
    assert 'renderWorkerMessage("main-agent", block.text, worker)' in app
    assert 'renderWorkerMessage("worker", block.text, worker)' in app
    assert 'fromMainAgent ? "Main Agent"' in app
    assert 'fromMainAgent ? "Delegated task" : "Worker"' in app
    assert '<div class="message-bubble">${renderMarkdown(text)}</div>' in app
    assert '<div class="trace-list">${renderWorkerRoundTranscript(groups, selectedRound, worker)}</div>' in app
    assert "还没有任务或运行记录。" in app
    assert "Main Agent 分配任务或 Worker 开始运行后" in app
    assert "Main Agent assignment" not in app


def test_main_agent_retry_status_is_polled_and_execution_events_are_visible():
    app = _asset("app.js")
    css = _asset("style.css")

    assert "pendingTimer: null" in app
    assert "mainAgentEvents: []" in app
    assert "function currentPendingMessage()" in app
    assert "function renderMainAgentEvents(messageId)" in app
    assert "main-agent-events" in app
    assert "执行过程" in app
    assert '"tool.started"' in app
    assert "async function refreshPendingMessages()" in app
    assert "state.pendingTimer = window.setInterval" in app
    assert 'retrying: "上游模型繁忙，正在自动续接"' in app
    assert 'message.status === "retrying"' in app
    assert "data-main-agent-continue" not in app

def test_main_agent_polling_recovers_inflight_turns_and_is_project_scoped():
    app = _asset("app.js")

    for token in (
        "refreshingProject: null",
        "pendingRefreshingProject: null",
        "state.refreshingProject === projectAtStart",
        "state.pendingRefreshingProject === projectAtStart",
        "const restoredPending = state.messages.slice().reverse().find",
        "persisted: true",
        "if (restoredPending) startPendingPolling()",
        "const hasTerminalEvent = state.mainAgentEvents.some",
        "const hasFollowingAssistant = state.messages.some",
        "persistedTurnTerminal && (hasTerminalEvent || hasFollowingAssistant)",
        "if (state.current === projectAtStart)",
        "const followTail = !scroll ||",
        "scroll.scrollTop = followTail ? scroll.scrollHeight : previousScrollTop",
    ):
        assert token in app

    assert 'notify(localMessage.error || "Main Agent 暂时不可用", "error");' in app


def test_run_controls_record_intent_then_activate_main_agent_through_chat_flow():
    app = _asset("app.js")

    start_body = app.split("async function startRun()", 1)[1].split("async function stopRun()", 1)[0]
    stop_body = app.split("async function stopRun()", 1)[1].split("async function handleUpload", 1)[0]

    assert "/runs`" in start_body
    assert "await sendMessageText(" in start_body
    assert start_body.index("/runs`") < start_body.index("await sendMessageText(")
    assert 'const START_RUN_MESSAGE = "' in app
    assert "danus-web-agent start" in app

    assert "/stop`" in stop_body
    assert "await sendMessageText(STOP_RUN_MESSAGE)" in stop_body
    assert stop_body.index("/stop`") < stop_body.index("await sendMessageText(STOP_RUN_MESSAGE)")
    assert 'const STOP_RUN_MESSAGE = "' in app
    assert "danus-web-agent stop" in app

def test_truthful_graceful_stop_progress_and_worker_process_identity_are_rendered():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function runtimeProgress",
        "state.runtime.progress",
        "activeRun.stop_pending_workers",
        "Graceful stop in progress",
        "finishing current round",
        "stopped",
        'worker.process_identity === "mismatch"',
        "worker.stop_requested",
        "worker.pause_requested",
        "重试状态已过期",
        "worker-process-row",
        "PID",
        "Process identity",
        "Desired state",
    ):
        assert token in app

    assert 'stateName === "stale" ? persistedState : stateName' in app
    assert ".process-identity.mismatch" in css
    assert ".worker-desired-state" in css


def test_workers_and_logs_entry_point_remains_accessible_on_narrow_and_desktop_layouts():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        'id="workers-logs-open"',
        "Workers / Logs",
        "function setWorkerRailOpen",
        'classList.toggle("is-open", open)',
        'aria-label="关闭 Workers / Logs"',
    ):
        assert token in app

    assert ".workers-logs-button" in css
    assert ".worker-rail.is-open" in css
    assert "@media (max-width: 860px)" in css
    assert ".rail-resizer-right, .worker-rail { display: none; }" not in css


def test_worker_drawer_keeps_structured_transcript_and_exposes_bounded_raw_logs():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "function workerLogEntries",
        'entry.name === "loop.log"',
        "function renderRawWorkerLog",
        "renderWorkerRoundTranscript(groups, selectedRound, worker)",
        "data-worker-log",
        "data-refresh-worker-log",
        "returned_lines",
        "modified_at",
        "truncated",
        "fetched_at",
        "max_bytes",
        "日志文件存在，但当前为空",
        "日志获取失败",
        "本轮日志存在，但 transcript parser 没有可显示消息",
        "async function refreshWorkerLogs",
        "tail=200&max_bytes=65536",
    ):
        assert token in app

    assert "logWorkerAtStart\n        ? api(workerLogUrl" in app
    assert "else if (logWorkerAtStart)" in app
    assert ".raw-log-panel" in css
    assert ".raw-log-tabs" in css
    assert ".log-fetch-error" in css


def test_main_agent_timeline_shows_every_safe_emitted_event_and_polling_keeps_operations_live():
    app = _asset("app.js")

    for token in (
        'events.slice().sort((left, right) => Number(left.id || 0) - Number(right.id || 0))',
        'data-event-id="${esc(event.id)}"',
        "function mainAgentEventMeta",
        "main_agent_session_id",
        "event.run_id",
        "event.call_id",
        "Emitted progress + tool trace",
        "private chain-of-thought is not exposed",
        'api(`/api/projects/${projectAtStart}/workers`)',
        'api(`/api/projects/${projectAtStart}/runtime`)',
        "pendingLogRequest(projectAtStart)",
        "renderWorkers();",
        "renderWorkerDrawer();",
    ):
        assert token in app


def test_lifecycle_recovery_controls_call_only_host_safety_endpoints_with_confirmation():
    app = _asset("app.js")
    css = _asset("style.css")

    for token in (
        "Pause after round",
        "Resume",
        "Graceful stop",
        "Force stop now",
        "Reclaim dry-run",
        'lifecycleRequest("pause"',
        'lifecycleRequest("resume"',
        'lifecycleRequest("force-stop"',
        '/reclaim`',
        "function forceStopSafety",
        'worker.process_identity !== "matched"',
        "输入项目名",
        "confirmation_token",
        "safe_to_execute",
        "remaining_project_processes",
        "function renderReclaimPlan",
        "worker?.reclaim_candidate === true",
    ):
        assert token in app

    assert ".lifecycle-controls" in css
    assert ".reclaim-plan" in css
    assert "function lifecycleIntentMessage" in app
    assert 'sendMessageText(lifecycleIntentMessage("pause", worker))' in app
    assert 'sendMessageText(lifecycleIntentMessage("resume", worker))' in app
    assert "authenticated host lifecycle broker" in app
    assert "data-direct-worker-assignment" not in app
    assert "data-direct-strategy" not in app


def test_run_start_records_intent_then_activates_main_agent_instead_of_browser_orchestration():
    app = _asset("app.js")
    assert "Run intent 已记录；Main Agent 正在启动" in app
    assert "danus-web-agent start" in app
    assert "Do not claim success for a partial fleet" in app
    assert 'notify("Worker fleet 已启动"' not in app

def test_main_agent_polling_does_not_rebuild_unchanged_chat_or_replay_entry_animation():
    app = _asset("app.js")
    css = _asset("style.css")

    assert "function replaceMarkupIfChanged" in app
    assert "if (!replaceMarkupIfChanged(chat, markup)) return;" in app
    message_rule = css[css.index(".message-row {"):css.index("}", css.index(".message-row {"))]
    assert "animation:" not in message_rule


def test_project_lifecycle_bar_only_exposes_simple_project_wide_controls():
    app = _asset("app.js")

    assert 'id="lifecycle-worker-target"' not in app
    assert 'id="run-stop"' not in app
    assert 'id="run-reclaim"' not in app
    assert 'id="run-pause"' in app
    assert 'id="run-resume"' in app
    assert 'id="run-force-stop"' in app
    assert "当前项目的全部 Workers" in app


def test_main_agent_progress_is_left_aligned_and_markdown_lists_share_message_styles():
    css = _asset("style.css")

    assert ".message-row.user .main-agent-events" in css
    assert "text-align: left" in css
    assert ".main-agent-event-message ul" in css
    assert ".main-agent-event-message ol" in css
    assert ".main-agent-event-message li" in css


def test_markdown_lists_support_common_markers_nesting_and_continuation_lines():
    rendered = _render_markdown(
        "- 第一项\n"
        "  续行说明\n"
        "  - 子项 A\n"
        "+ 第二项\n"
        "• 第三项\n"
        "1) 有序一\n"
        "2、 有序二"
    )

    assert "<ul><li>第一项<br>续行说明<ul><li>子项 A</li></ul></li>" in rendered
    assert "<li>第二项</li><li>第三项</li></ul>" in rendered
    assert "<ol><li>有序一</li><li>有序二</li></ol>" in rendered
