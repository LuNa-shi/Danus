# ADR 0013: Typed Main Agent event protocol

- Status: Accepted
- Date: 2026-08-18

Provider JSONL is normalized at one boundary into typed Session, Process, Turn,
tool, progress and terminal events. `thread.started` means Session identity is
available; every Web activation emits `process.started`; provider `turn.started`
remains a distinct Turn event. Unknown/malformed envelopes are fail-closed for
automatic retry safety. Persistence accepts only normalized event kinds and bounded
fields, and the browser uses the same glossary labels.
