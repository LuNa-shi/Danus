# ADR 0012: Project artifacts and explicit publication forks

- Status: Accepted
- Date: 2026-08-18

The Web Console exposes canonical TARGET.md, report, paper/papers, reports, and
outputs through a project-root-contained, symlink-rejecting, bounded projection.
Authenticated view/download routes accept only paths returned by that projection.
Finalize validates verified Fact IDs and requires CSRF; suggestion mode writes
nothing. Human-summary and write-paper remain explicit operator-confirmed forks,
including language, paper ID, and stop-workers choice.
