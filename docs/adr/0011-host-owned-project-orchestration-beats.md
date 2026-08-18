# ADR 0011: Host-owned Project orchestration beats

- Status: Accepted
- Date: 2026-08-18

## Context

Workers can advance while the browser is closed and the Main Agent Session is
inactive. Browser polling cannot safely own strategic authority, while unchanged
state must not create repeated paid activations.

## Decision

The Web host observes a stable, Project-scoped watermark of active Run, Worker
round/state, worker-authored memory, and Fact IDs. A changed watermark activates
the same resumable Main Agent Session used by manual messages. The Main Agent may
update guidance, re-task Workers, request lifecycle operations through the host
supervisor, gracefully stop verified-complete work, and publish its reply as an
operator notification. The handled watermark and cadence status are persisted and
projected. Main-Agent-authored guidance/elaboration are excluded from the trigger
watermark to prevent feedback loops. No-change cadence is recorded but does not
activate a model.

## Consequences

Orchestration continues without a resident browser, while project isolation,
session continuity, lifecycle authority, restart deduplication, and spend control
remain explicit.
