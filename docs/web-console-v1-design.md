# Danus Web Console V1 Design

## Scope

V1 is a simple authenticated web console for two trusted operators running Danus mathematical-research projects. Both operators share access to all Projects. The deployment uses an application password and a temporary Cloudflare Quick Tunnel; the public URL may change.

## Product surface

The project page has four areas:

- left: Projects and the Project File Library;
- center: natural-language conversation with the Project Main Agent;
- right: Workers and their current tasks/status;
- bottom: Fact Graph, logs, stage reports, and stop control.

The console never directly edits Worker assignments or the Fact Graph. Direction changes and questions are expressed as natural-language Main Agent Messages; the Main Agent retains Danus' strategic authority and verifier boundaries.

## Project isolation

A Project owns its problem, Project Context Directory, Project File Library, Main Agent Session, Workers, memory, Fact Graph, logs, reports, and outputs. Actions on one Project must not affect another.

Each Project Main Agent runs with that Project Context Directory as its working directory. The Web Console adapter explicitly supplies the Danus Main Agent contract, project state, tools, and Project File Manifest rather than relying on repository-root auto-discovery.

## Main Agent lifecycle

Each Project has one persistent logical Main Agent Session. Its Claude Code process is activated or resumed only for a Main Agent Message and may exit after the turn, leaving the Session inactive while Workers continue. The Web Console is a thin Control Plane, not a second research agent: it handles authentication, files, session launch/resume, run limits, lifecycle controls, persistence, and state projection.

## Project files

V1 supports PDF and LaTeX material. Uploading or updating a file only changes the Project File Library; it does not activate or interrupt the Main Agent. On activation, the Main Agent receives the Project File Manifest. Files selected alongside a message are Conversation Attachments and should be read first. File presence never implies successful reading.

Files are deduplicated by exact content within a Project. Explicitly versioned names such as `report-v1.pdf` and `report-v2.pdf` are separate files. For a same-name conflict with different bytes, the user chooses Replace, Create new version, or cancel. Replace permanently deletes the old external-material bytes; Create new version keeps both.

PDFs are preserved in original form and read on demand by project-scoped Claude Code. Read failures must be visible. V1 does not require OCR or a searchable-text extraction pipeline.

## Run controls

A Project Run has an operator-selected wall-clock duration, for example 12 hours, converted into an enforced absolute Run Deadline. Manual graceful stop is available before the deadline and affects only the current Project. Main Agent turn timeout, Worker round timeout, and optional monetary/API budget are distinct controls; V1 treats wall-clock duration as the primary user-facing budget.

The start form exposes essential project choices such as problem description, Worker roster, and run duration. Provider credentials, executable paths, internal ports, and low-level environment variables remain server-side configuration.

## State and persistence

Danus runtime files and actual processes remain authoritative for Workers, memory, Fact Graph, and run state. The Web Console persists only the metadata it owns, including authentication/session data, Project/file metadata, chat records, Claude Code session IDs, Project Run configuration, and audit events. It must not claim success unless the underlying Danus action was verified.

## Deployment boundary

The Web Console is the only service exposed through the Quick Tunnel. Danus verify, dashboard, MCP, and other internal services remain loopback-only. Quick Tunnel does not provide Cloudflare Access; authentication is enforced by the application.
