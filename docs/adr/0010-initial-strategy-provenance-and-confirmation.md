# ADR 0010: Initial strategy provenance and confirmation

- Status: Accepted
- Date: 2026-08-18

## Context

A project can run with an enabled strategy consult transport or with `off`, where
the Main Agent forms direction itself. Treating both outputs as if they were
consult replies hides an important operator-visible distinction. Starting Workers
before the initial direction is understood also makes the browser appear to be an
orchestrator.

## Decision

At first activation, the Main Agent presents the direction and preserves the
operator-selected Worker roster. Enabled transports produce
`master_guidance` with `guidance-source: consult-derived`; `off` produces
`master_guidance` with `guidance-source: offline-main-agent`. The Web Console projects
that provenance and waits for explicit operator confirmation before assignment or
start. The browser records and displays intent; only the Main Agent performs
dispatch.

## Consequences

Operators can distinguish advisor-derived from offline guidance, and the contract
no longer silently chooses between contradictory initialization interpretations.
Offline deployments remain usable without pretending that their strategy came from
an external consult.
