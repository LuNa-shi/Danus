## Problem Statement

Mathematics students should be able to use Danus without operating it through the command line. The current Danus repository provides the proof-search engine, Main Agent orchestration contract, Worker swarm, verifier, Fact Graph, memory, reports, and a read-only single-Project dashboard, but it does not provide an authenticated Web Console.

For V1, two trusted operators need a simple browser interface that can run isolated mathematical-research Projects on the server. Each Project must remain a first-class isolation boundary: its problem, Project Context Directory, Project File Library, Main Agent Session, Workers, memory, Fact Graph, logs, reports, and outputs must not leak into or affect another Project. Users need to upload research documents, converse with the Main Agent, see Worker progress, inspect outputs, and stop a run without directly editing strategy or truth data from the browser.

The deployment should be reachable through a temporary Cloudflare Quick Tunnel. Because Quick Tunnel does not provide a documented Cloudflare Access binding, V1 needs application-level password authentication at the Web Console boundary.

## Solution

Build a new Danus Web Console consisting of a simple browser frontend and a thin Web Console Control Plane backend. The Control Plane is not a second research agent: it authenticates operators, persists Web Console-owned metadata, manages the Project File Library, starts or resumes the Project Main Agent Process, enforces Project Run controls, invokes existing Danus lifecycle commands, and projects actual Danus runtime state into the UI.

The project page has four regions:

- **Left:** Project list and the current Project File Library.
- **Center:** natural-language conversation with the current Project's Main Agent.
- **Right:** Worker roster, current tasks, liveness, rounds, and status.
- **Bottom:** Fact Graph, logs, stage reports, and graceful stop control.

The Project Main Agent retains Danus' strategic orchestration authority. An operator's request to “adjust direction” is a natural-language Main Agent Message; the Web Console never directly rewrites Worker assignments. The browser also never directly mutates the Fact Graph; Fact correctness remains behind Danus' existing verifier boundary.

Each Project has one persistent logical Main Agent Session, represented by a Claude Code session identity. The underlying Main Agent Process is launched or resumed on demand with the Project Context Directory as its working directory when the operator sends a chat message. It may exit after the turn and leave the Session inactive while Workers continue. On activation, the adapter provides the Main Agent contract, Project state, and Project File Manifest explicitly rather than relying on repository-root auto-discovery.

Uploaded PDF and LaTeX documents are stored in the Project's isolated Project Context Directory. Uploading or updating a file does not activate or interrupt the Main Agent. A user explicitly selects a stored file version as a Conversation Attachment when sending a natural-language message; the Main Agent should read selected attachments first. File existence or upload success must never be presented as proof that the Main Agent read or adopted the document.

A Project Run has an operator-selected wall-clock Run Budget, such as 12 hours. At start, the Control Plane converts it into an enforced absolute Run Deadline using Danus' existing deadline mechanism. The operator can request graceful stop before the deadline. At the deadline, the Control Plane stops accepting new work and begins graceful shutdown for that Project only. Per-turn Main Agent timeout, per-round Worker timeout, and optional monetary/API limits remain separate controls; wall-clock duration is the V1 user-facing hard bound.

## User Stories

1. As a trusted operator, I want to authenticate with the Web Console using an application password, so that the temporary public Quick Tunnel does not expose Danus without access control.
2. As a trusted operator, I want my authenticated browser session to use a secure cookie, so that the password is not repeatedly sent in URLs or exposed to frontend JavaScript.
3. As a trusted operator, I want failed login attempts to be rate-limited, so that a temporary public endpoint is not trivially brute-forced.
4. As a trusted operator, I want to see every Project in one shared Project list, so that the two V1 operators can collaborate without invitation or per-Project authorization setup.
5. As a trusted operator, I want to create a Project with a name and problem description, so that Danus can work on a clearly identified mathematical problem.
6. As a trusted operator, I want a Project to own its own problem description, so that Main Agent interactions and research state cannot silently refer to another Project's problem.
7. As a trusted operator, I want to open a Project and see only its Project Context Directory, Project File Library, Main Agent Session, Workers, memory, Fact Graph, logs, reports, and outputs, so that Project isolation is visible in the UI.
8. As a trusted operator, I want actions on one Project to leave other Projects running and intact, so that experiments can proceed independently.
9. As a trusted operator, I want to upload a PDF into the currently selected Project, so that research material is stored on the server rather than sent to an unrelated global directory.
10. As a trusted operator, I want to upload a LaTeX file into the currently selected Project, so that mathematical source material can be used in the Project conversation.
11. As a trusted operator, I want the UI to reject unsupported file types, so that the Project File Library contains only V1-supported PDF, LaTeX, Markdown, and common plain-text material.
12. As a trusted operator, I want the original uploaded bytes preserved, so that the Main Agent can access the source document rather than only a transformed derivative.
13. As a trusted operator, I want each Project's files physically stored below its Project Context Directory, so that Claude Code can work from the Project boundary and one Project cannot automatically read another Project's files.
14. As a trusted operator, I want file writes to complete atomically, so that Claude Code cannot read a partially uploaded document.
15. As a trusted operator, I want the Web Console to compute exact content identity for an upload, so that an identical file is not stored twice under the same Project.
16. As a trusted operator, I want an identical same-name upload to reuse the existing file, so that duplicate uploads do not create confusing duplicate versions.
17. As a trusted operator, I want the UI to show a conflict when a same-name upload has different contents, so that the system never silently discards or overwrites research material.
18. As a trusted operator, I want a **Replace** choice for a same-name conflict, so that I can use familiar file-system semantics when old external material is no longer wanted.
19. As a trusted operator, I want Replace to permanently delete the old external-material bytes, so that the result is a genuine replacement rather than an undisclosed backup.
20. As a trusted operator, I want a **Create new version** choice for a same-name conflict, so that I can retain both the old and new material when the distinction matters.
21. As a trusted operator, I want explicitly versioned names such as `report-v1.pdf` and `report-v2.pdf` retained as separate files, so that intentional versioning is not collapsed by the file library.
22. As a trusted operator, I want to cancel a same-name conflict, so that neither the current file nor the incoming file is changed unintentionally.
23. As a trusted operator, I want the Project File Library to show original filename, type, upload time, content identity, and retained version information, so that I can understand exactly what material exists.
24. As a trusted operator, I want to select a particular Project-owned file version in the chat composer, so that I can explicitly tell the Main Agent which material to consider.
25. As a trusted operator, I want a Conversation Attachment to be sent together with a natural-language Main Agent Message, so that file context and my instruction arrive as one interaction.
26. As a trusted operator, I want adding or updating a file in the Project File Library not to activate or interrupt the Main Agent, so that file transfer is independent from conversation and research execution.
27. As a trusted operator, I want a Main Agent activation to receive the current Project File Manifest, so that the Main Agent knows what Project material is available without reading every document automatically.
28. As a trusted operator, I want the Project File Manifest to distinguish file availability from file-reading success, so that the UI never claims a document was understood merely because it exists.
29. As a trusted operator, I want a PDF-reading failure to be visible, so that an encrypted, malformed, oversized, or otherwise unreadable PDF is not mistaken for successfully ingested research.
30. As a trusted operator, I want PDFs preserved and read on demand by the Project Main Agent, so that V1 can avoid building an OCR or searchable-text pipeline while retaining honest failure states.
31. As a trusted operator, I want to send a natural-language message to the Project Main Agent, so that I can use Danus without a command-line workflow.
32. As a trusted operator, I want to ask the Main Agent questions about progress, so that I can understand the current research state.
33. As a trusted operator, I want to request a Direction Adjustment in natural language, so that the Main Agent can reconsider the strategy without the browser directly rewriting Worker tasks.
34. As a trusted operator, I want to describe a potentially wrong claim in natural language, so that the Main Agent can decide whether to investigate it using Danus' existing research and verifier mechanisms.
35. As a trusted operator, I want the Main Agent to retain authority over Worker coordination, so that a casual browser control cannot damage the overall research strategy.
36. As a trusted operator, I want the browser to expose no direct Worker-task editing operation, so that Web Console code cannot accidentally replace a Worker assignment behind the Main Agent's back.
37. As a trusted operator, I want the browser to expose no direct Fact Graph mutation operation, so that only Danus' existing verifier-governed paths can establish or alter mathematical truth.
38. As a trusted operator, I want the Project Main Agent Session to become active when I send a message, so that inactive Projects do not consume a continuously running Main Agent process.
39. As a trusted operator, I want the Main Agent Session to return to inactive after its turn completes, so that the session remains resumable without requiring a permanent Claude Code process.
40. As a trusted operator, I want a resumed Session to retain its Claude Code session identity and Web Console chat history, so that the Project conversation can continue rather than starting from zero.
41. As a trusted operator, I want the Main Agent Process to run with the current Project Context Directory as its working directory, so that file access follows Project isolation.
42. As a trusted operator, I want the adapter to provide Danus' Main Agent contract and Project state explicitly, so that the Project Main Agent does not depend on repository-root auto-discovery that could expose unrelated context.
43. As a trusted operator, I want to see each Worker's current task, liveness, round, and latest status, so that I can understand what the Main Agent has delegated.
44. As a trusted operator, I want to see Worker logs, so that I can diagnose progress and failures without opening a terminal.
45. As a trusted operator, I want to see the Project Fact Graph, so that verified mathematical results and their relationships are visible in the Project page.
46. As a trusted operator, I want to see stage reports and persisted outputs, so that I can follow research progress beyond the live Worker list.
47. As a trusted operator, I want displayed Worker and run state to come from Danus runtime files and actual processes, so that the Web Console cannot claim success when Danus did not perform the action.
48. As a trusted operator, I want the Web Console to refresh runtime projections through simple polling, so that V1 can show changing status without requiring a complex realtime transport.
49. As a trusted operator, I want to start a Project Run with a chosen wall-clock duration, so that I can bound how long the research may continue.
50. As a trusted operator, I want to choose a 12-hour Run Budget, so that a long research run can continue without requiring a terminal process to remain attended.
51. As a trusted operator, I want the chosen Run Budget converted to an enforced absolute Run Deadline, so that the duration is a real stop condition rather than a label.
52. As a trusted operator, I want the start form to expose essential run choices such as the problem description, Worker roster, and duration, so that I can configure a Project without editing environment variables.
53. As a trusted operator, I want provider credentials, executable paths, internal ports, and low-level environment variables kept server-side, so that the browser never receives secrets or unsafe infrastructure controls.
54. As a trusted operator, I want the deadline to affect only its Project Run, so that one Project's time limit cannot stop another Project.
55. As a trusted operator, I want to stop a Project Run before its deadline, so that I can interrupt an unproductive or no-longer-needed research process.
56. As a trusted operator, I want the normal stop action to be graceful, so that Workers can finish their current round and persisted research state is not corrupted.
57. As a trusted operator, I want an in-progress Main Agent reply to complete normally during a graceful stop, so that I do not lose a partial response merely because I stopped the Worker swarm.
58. As a trusted operator, I want a stopped Project to be restartable from its persisted state, so that stopping does not erase memory, the Fact Graph, files, reports, or outputs.
59. As a trusted operator, I want to delete a Project only after it has stopped, so that an active Project cannot be removed while its processes are writing state.
60. As a trusted operator, I want Project deletion to remove only that Project's Web Console metadata, files, Main Agent Session data, and Danus runtime data, so that other Projects remain untouched.
61. As a trusted operator, I want a destructive deletion confirmation, so that I do not erase a mathematical research Project accidentally.
62. As a trusted operator, I want an audit record for authentication, file conflict decisions, chat requests, run starts, stops, and deletions, so that important control-plane actions are traceable.
63. As a trusted operator, I want the Web Console to expose only itself through the Quick Tunnel, so that verify, MCP, dashboard, and other internal Danus services remain inaccessible from the public endpoint.
64. As a future self-hosting operator, I want the Web Console to keep its Danus integration in an adapter boundary, so that the console can be packaged for local deployment without rewriting the verifier or Fact Graph core.

## Implementation Decisions

- Add a Web Console Control Plane backend and browser frontend as a separate integration surface. The Control Plane owns authentication, Project metadata, file metadata, chat records, Main Agent session identity, Project Run configuration, and audit events.
- Use an application-password authentication flow for V1. Store only a password hash; issue a secure session cookie; apply login throttling. V1 deliberately treats the two trusted operators as sharing access to all Projects and does not implement invitations, per-Project authorization, or individual identity management.
- Keep the Web Console's HTTP surface as the highest test seam. It should expose authenticated Project, file, chat, run-control, and read-only projection operations while hiding Danus internal services and subprocess details behind adapters.
- Use a Danus runtime adapter to invoke existing Project and Worker lifecycle operations and to read actual status, logs, Fact Graph, memory, reports, and outputs. Runtime files and actual processes remain authoritative for Danus-owned state; Web Console metadata must not override them.
- Use a Project Main Agent adapter separate from the existing stateless strategy consult transport. Persist one logical Main Agent Session per Project, including the Claude Code session identity and Web Console conversation history. Start or resume a Main Agent Process only for a Main Agent Message, run it from the Project Context Directory, and return it to inactive after the turn.
- Provide the Main Agent contract, Project state, required tools/capabilities, and Project File Manifest explicitly at activation. Do not rely on repository-root CLAUDE.md, MCP, or skill discovery for the Project Main Agent. Preserve Main Agent Authority: the adapter transports requests and renders outcomes but never makes research strategy decisions.
- Represent Project files through a Project File Library backed by an isolated Project Context Directory. V1 accepts PDF, LaTeX, Markdown, and common plain-text research files. Preserve original bytes and expose original filename, type, timestamps, content identity, retained versions, and processing/read status.
- Deduplicate identical uploads by exact content within one Project. A same-name upload with identical bytes reuses the existing file. A same-name upload with different bytes requires an explicit choice: Replace, Create new version, or Cancel. Replace permanently deletes the old external-material bytes; Create new version retains both and makes the new version current; explicitly versioned filenames remain separate files.
- Treat adding/updating a file as storage-only. It must not activate, interrupt, or send an independent notification to the Main Agent or Workers. A Conversation Attachment is a selected Project file version sent together with one natural-language Main Agent Message; selected attachments are supplied as paths/context and should be read first.
- Preserve PDF originals and read them on demand through the Project Main Agent's local file-reading capability. V1 does not require OCR or a searchable-text extraction pipeline. Any read or processing failure must be represented explicitly and must never become a false successful-read state. LaTeX is stored as project material without a V1-specific compilation workflow.
- Expose read-only projections for Worker status/current task, logs, Fact Graph, stage reports, and outputs. Do not expose direct browser operations for Worker assignment replacement, Fact Graph mutation, verifier calls, or arbitrary filesystem paths.
- Model each bounded research execution interval as a Project Run. The start form exposes problem description, Worker roster, and wall-clock Run Budget. The Control Plane converts duration to an absolute Run Deadline and enforces it through Danus' existing deadline mechanism; a 12-hour choice must be a real deadline.
- Keep limits separate: Project Run Deadline bounds the overall run; Main Agent turn timeout bounds one chat activation; existing Worker round hard timeout and round backstop remain lower-level controls; optional monetary/API budget is not the primary V1 guarantee and should only be exposed when the underlying runtime can enforce it reliably.
- Make manual Project Run stop graceful by default. The Control Plane requests the existing Danus stop behavior and projects stopping/stopped state. It must not force-kill an in-progress Main Agent response in V1. Restart resumes persisted Project state; deletion is allowed only after stop, requires confirmation, and permanently removes only the selected Project's data.
- Use simple HTTP polling for live projections in V1 rather than introducing WebSockets, Redis, or a distributed event bus.
- Keep the Web Console deployable behind a temporary Cloudflare Quick Tunnel. The Quick Tunnel is transport only; application authentication remains the security boundary. Only the Web Console is tunnel-exposed; verify, MCP, dashboard, and other internal services remain loopback-only.
- Keep frontend framework and visual styling implementation choices open, provided the four-region Project page and the HTTP seam remain intact.

## Testing Decisions

- The primary test seam is the authenticated Web Console HTTP boundary. Tests should exercise observable request/response behavior, persisted effects, and state projections rather than private classes, database queries, subprocess construction, or frontend component internals.
- Use temporary filesystem roots for Project Context Directories and Danus runtime state, and a temporary SQLite database for Web Console metadata. Use fake Danus runtime and Main Agent adapters at the HTTP boundary so tests remain deterministic and do not invoke Claude Code, Codex, verifier services, or external Cloudflare infrastructure.
- Authentication tests should cover successful login, invalid credentials, secure session behavior, throttling, unauthenticated access denial, and protection of every read/write Project operation.
- Project isolation tests should create at least two Projects and verify that files, manifests, chat history, Main Agent session IDs, Workers, logs, Fact Graph data, reports, run deadlines, deletion, and stop operations never cross Project boundaries.
- File-library tests should cover supported PDF, LaTeX, Markdown, and common plain-text files, unsupported types, atomic completion visibility, exact-content deduplication, same-name identical reuse, same-name differing-content conflict choices, destructive Replace, retained Create new version, explicit versioned filenames, cancellation, attachment selection, and read-status honesty.
- Main Agent adapter tests should cover first activation, session resume, inactive-to-active-to-inactive transitions, Project Context Directory working-directory enforcement, manifest delivery, attachment delivery, reply persistence, failure persistence, timeouts, and behavior when a session identity is unavailable.
- Run-control tests should cover duration-to-deadline conversion, 12-hour deadlines, prevention of new work after deadline, project-scoped deadline enforcement, graceful stop, restart from persisted state, stop isolation, deletion guardrails, and audit records.
- Projection tests should verify that displayed Worker status, logs, Fact Graph, reports, and outputs reflect fake Danus runtime state and do not claim an action succeeded merely because a Web Console request was accepted.
- Use existing pytest conventions and adapter-style fakes already used by Danus tests for subprocess-backed strategy, execution, orchestration, observability, and service modules. Add a small number of lower-level adapter contract tests only where the HTTP seam cannot express a safety invariant.
- Frontend tests should focus on user-visible flows at the highest practical browser or HTTP seam: Project switching, file conflict resolution, attachment selection, chat submission, run start/stop, polling updates, authentication transitions, and visible failure states. Avoid snapshot-heavy tests of static layout.
- A deployment smoke test may verify loopback binding and a manually started Quick Tunnel configuration, but production Cloudflare connectivity is outside the deterministic automated suite.

## Out of Scope

- Multi-tenant organizations, invitations, per-Project authorization, individual user identities, or role-based access control.
- Cloudflare Access, Named/Remotely-managed Tunnels, custom domains, fixed public IPs, or production SLA for the public URL.
- Direct browser editing of Worker assignments, direct Fact Graph mutation, direct verifier calls, fact deletion/revocation controls, or a second Web Console strategy agent.
- Replacing Danus' verifier, Fact Graph, Worker proof loop, Main Agent contract, or truth-store authority.
- A general-purpose research assistant outside Danus mathematical proof search.
- image uploads, image OCR, PDF OCR, mandatory searchable-text extraction, or a separate document-ingestion/indexing pipeline beyond honest file/read status.
- Automatic activation of the Main Agent on file upload, independent Worker file-notification protocol, or browser-driven Worker behavior changes caused solely by file transfer.
- Multi-tab collaboration, concurrent browser composition, collaborative editing, WebSocket realtime transport, Redis, distributed queues, and horizontal scaling.
- Token-based or monetary Project-level budget enforcement as the primary V1 control, model-provider billing aggregation, or arbitrary low-level environment configuration in the browser.
- Force-kill as the normal stop operation, pause/resume semantics distinct from stop/start, and automatic Project Run deadline extension on restart.
- Automatic backups, undelete, rollback, or hidden retention of old external-material bytes after an explicit Replace choice.
- Mobile-specific UI, public self-service onboarding, and polished ChatGPT-level feature parity.

## Further Notes

- The repository currently contains no Web Console backend, frontend, upload endpoint, or persistent Main Agent HTTP/session service; the feature adds these as a new integration surface.
- The installed Claude Code CLI can create/resume sessions by explicit session identity and read local PDFs under an allowed working directory, but Danus' existing Claude Code strategy transport is intentionally stateless, uses a temporary working directory, and exposes web-only tools. The new Main Agent adapter must not route Project material through that consult transport.
- Claude Code PDF handling is model/version dependent. Long, encrypted, malformed, oversized, or scanned PDFs may fail; V1 must show the actual failure and preserve the original file. The current host lacks Poppler helpers, so no deterministic long-PDF extraction guarantee should be assumed.
- Project Run wall-clock duration is the primary user-facing budget. A 12-hour choice should be stored as an absolute deadline and enforced, while Main Agent turn and Worker round limits remain separate.
- Existing accepted ADRs 0001 through 0009 define the Project-scoped Main Agent Session, isolated Project Context Directory, explicit Project File Manifest and Conversation Attachment, shared V1 Project Access, Main Agent Authority, filesystem-style file conflicts, and the thin Control Plane/run-deadline boundary. This spec follows those decisions.
