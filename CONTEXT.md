# Danus Web Console

The domain language for operating isolated Danus research projects through a simple web interface. V1 serves two trusted operators; a later packaged form may support self-hosted deployments by other mathematics students.

## Language

**Project**:
The isolation boundary for one research problem. A project owns its materials, agent activity, workers, memory, fact graph, reports, and results; its lifecycle cannot affect another project.
_Avoid_: Workspace, tenant, session

**Main Agent**:
The strategic orchestrator for a Project and the only agent-facing conversational counterpart exposed to the operator. It decides how a research direction is translated into Worker work and responds to the operator's questions or concerns about the research.
_Avoid_: Worker, chatbot

**Main Agent Session**:
A Project's bounded interaction context for its Main Agent. It can be inactive between operator interactions while the Project's Workers continue their work.
_Avoid_: Global chat, Worker process

**Worker**:
An agent assigned by the Main Agent to pursue a bounded research task within exactly one Project.
_Avoid_: Main Agent, project session

**Direction Adjustment**:
An operator request asking the Main Agent to reconsider the Project's strategy. It is not a direct edit to one or more Worker assignments.
_Avoid_: Worker override, direct reassignment

**Main Agent Message**:
A natural-language message from the operator to the Project's Main Agent. It may ask a question, request a direction adjustment, or raise a concern about research, and may explicitly include selected Material Files as context. The console does not expose separate direct Fact or Worker editing operations.
_Avoid_: Fact edit, Worker command

**Main Agent Authority**:
Within one Project, the Main Agent retains Danus' strategic orchestration capabilities: it can inspect project state and truth stores, record strategy, and decide how Workers should be coordinated. The Web Console presents these capabilities through conversation rather than making independent strategy decisions.
_Avoid_: Web strategy, operator Worker override


**Main Agent Turn**:
One bounded request/response attempt within an activated Main Agent Process. A Turn
belongs to the persistent Project Session but does not create a new Session.
_Avoid_: Session, Process

**Main Agent Process**:
The Claude Code process activated to handle a Main Agent Session interaction. It is not a Worker and need not remain running while the Session is inactive.
_Avoid_: Main Agent Session, Worker

**Web Console Control Plane**:
The non-strategic backend layer that authenticates operators, stores Project metadata and files, starts or resumes the Main Agent Process, enforces run controls, and projects Danus runtime state. It does not decide research strategy or assign Workers.
_Avoid_: Second Main Agent, strategy agent, core researcher

**Project Run**:
One bounded execution interval for a Project's Worker swarm and Main Agent control. A Project can be stopped and started again; each run resumes the Project's persisted research state and has its own run controls.
_Avoid_: Main Agent Process, permanent session

**Run Budget**:
The operator-selected wall-clock limit for one Project Run, expressed as a duration such as 12 hours. The Web Console turns it into an enforced Run Deadline; it is not merely a label in the UI.
_Avoid_: Token budget, vague timeout

**Run Deadline**:
The absolute time at which a Project Run must stop accepting new work and begin its stop procedure. It is distinct from a per-process timeout and from an optional monetary API limit.
_Avoid_: Main Agent timeout, spend ceiling

**Project Access**:
In V1, both trusted operators can view and operate every Project, including its files, Main Agent Session, Workers, logs, Fact Graph, and outputs.
_Avoid_: Project ownership, invitation

**Project Context Directory**:
The Project-owned directory on the server where its current research context and uploaded Material Files are stored. The Project's Main Agent runs with this directory as its working context; the directory is isolated from other Projects. The Web Console explicitly supplies the Main Agent contract, project state, and required capabilities rather than relying on repository-root discovery.
_Avoid_: Global uploads, shared context

**Project File Library**:
The logical collection of source documents belonging to exactly one Project, backed by that Project's Context Directory. It stores current Material Files and only the versions the operator explicitly chooses to retain; adding or updating a document is storage-only and does not activate or interrupt the Main Agent.
_Avoid_: Global upload, shared drive

**File Conflict**:
An upload whose logical filename already exists in the same Project. If the bytes are identical, the existing file is reused; if they differ, the operator chooses **Replace**, **Create new version**, or cancels the upload. Explicitly versioned names such as `report-v1.pdf` and `report-v2.pdf` are retained as separate files.
_Avoid_: Silent overwrite, automatic merge

**File Replacement**:
A deliberate replacement of a Project File Library file in which the old external-material bytes are permanently deleted. **Create new version** is the explicit choice that retains both old and new files.
_Avoid_: Silent overwrite, automatic backup

**Project File Manifest**:
The current inventory of a Project File Library presented to the Main Agent when its Session is activated. It identifies available file versions and their processing states; seeing a manifest does not mean the Main Agent has read the file contents.
_Avoid_: File contents, read receipt

**Material File**:
A versioned source document stored in a Project File Library. A Material File is available to the Project's Main Agent through the Project Context Directory and is not available to other Projects by default.
_Avoid_: Global file, temporary upload

**Conversation Attachment**:
A Material File version explicitly selected alongside one natural-language Main Agent Message. It identifies which project-owned file the operator wants the Main Agent to consider in that interaction; the upload itself is not a Conversation Attachment until selected for a message.
_Avoid_: Global upload, implicit file use

**Fact Graph**:
A Project's dependency graph of verifier-accepted claims. It is isolated to that Project and is the authoritative source of verified results; the console may display it but does not directly mutate it.
_Avoid_: Memory, notes


**Guidance Provenance**:
The operator-visible origin of a Main Agent strategic direction: `consult-derived`
when produced by the configured strategy transport, or `offline-main-agent` when
formed by Main Agent judgment while consult is off.
_Avoid_: consult result for offline guidance

**Initial Direction Confirmation**:
The operator's explicit approval of the Main Agent's first strategic direction
before Worker assignment or start.
_Avoid_: browser approval of individual Worker tasks


**Orchestration Beat**:
A host-triggered activation of one Project's resumable Main Agent Session after a
stable Worker/memory/Fact-Graph watermark changes. A Beat may update strategy,
re-task Workers, request supervisor lifecycle actions, stop verified-complete work,
and produce a due human summary.
_Avoid_: Browser poll, cron-owned strategy, Worker heartbeat

**Human-Summary Cadence**:
The auditable target interval for Main Agent progress summaries. If no project state
has changed when the interval becomes due, the summary remains due but does not
create a paid Main Agent activation.
_Avoid_: Unconditional hourly model call


**Canonical Artifact**:
A Project-owned TARGET.md, report, paper workspace, verification ledger, or
output returned by the server's allowlisted artifact projection. It can be viewed
or downloaded through an authenticated Project-scoped route.
_Avoid_: arbitrary filesystem file
