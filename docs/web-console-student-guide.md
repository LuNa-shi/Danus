# Danus Web Console: a student guide

Danus is a project-scoped proof-search console. You provide a mathematical problem, and the Main Agent coordinates Workers; the verifier, not the chat, decides which mathematical claims become facts.

## 1. Start and sign in

For a local loopback deployment, configure a password hash and start the console:

```bash
source scripts/env.sh
export DANUS_WEB_PASSWORD_HASH="<scrypt-hash>"
export DANUS_WEB_COOKIE_SECURE=false
export DANUS_WEB_ALLOWED_ORIGINS=http://127.0.0.1:8080
export DANUS_WEB_MAIN_AGENT_BACKEND=codex
bin/danus-web-console
```

Open `http://127.0.0.1:8080/`. Keep `DANUS_WEB_COOKIE_SECURE=true` when the console is served through HTTPS. The browser never receives provider credentials.

The Web Console uses **Codex** as its Main Agent backend by default. The supplied OpenAI-compatible endpoint belongs in the server-side `config/codex.env` and is not an Anthropic `/v1/messages` endpoint; do not point Claude Code at it. To use Claude Code instead, set `DANUS_WEB_MAIN_AGENT_BACKEND=claude` only after `claude -p` succeeds with a valid Claude/Anthropic login.

## 2. Create a Project

Enter a short Project name, the exact problem statement, and the Worker roster. Keep the statement precise: define notation, the target theorem, and what counts as a human-checkable proof. Each Project has isolated files, Workers, memory, Fact Graph, logs, and outputs.

## 3. Add materials

Upload supported PDF, LaTeX, Markdown, or plain-text files. Uploading only stores the original bytes; it does not start the Main Agent. If the same filename already exists, choose **Replace**, **Create new version**, or **Cancel**. Select a particular retained version as a Conversation Attachment when you want the Main Agent to consider it.

A file being present does not mean it was read. The UI should show read status only when the Main Agent reports that it actually read the attachment.

## 4. Start a bounded Run

Set the duration in seconds. For a one-hour experiment use:

```text
3600
```

Click **Start Run**. The console converts that duration into an absolute Project Run Deadline. It starts only that Project's Workers. Use **Graceful Stop** to request a round-boundary shutdown; restarting later resumes persisted state.

## 5. Talk to the Main Agent

Send requests such as:

- “Summarize the current verified facts and open gaps.”
- “Split the upper and lower bounds into independent Worker tasks.”
- “Audit this proposed lemma and do not treat it as verified until the verifier accepts it.”

The Main Agent Session is Project-scoped and resumable. Its strategic notes and Fact Graph oversight use the Project-scoped Danus MCP gateway. The browser has no direct Worker-task or Fact Graph editing controls.

## 6. Read the Project page

The page polls and displays:

- Project File Library and selected attachments
- Main Agent conversation
- Worker liveness, state, round, and latest status
- Fact Graph nodes and predecessor edges
- Worker logs, reports, and outputs
- Run status and deadline

A `starting` or `running` label means a process was observed. It is not proof that the theorem is complete. A theorem is complete only when the Fact Graph contains the verifier-accepted facts and their predecessor chain closes the target.

## 7. Stop or delete

Stop a Run before deleting its Project. Deletion requires typing the exact Project name and removes only that Project's Web Console metadata and Danus runtime tree.

## A good first experiment

Use a theorem with independent subgoals and a concrete verifier target. For example, ask for `R(3,3)=6`: prove every red/blue coloring of the edges of `K6` contains a monochromatic triangle, and give a 2-coloring of `K5` with no monochromatic triangle. Require explicit predecessor links and reject computational-only claims.

## Interpreting results

- **available**: the file is stored and can be attached.
- **read**: the Main Agent explicitly reported reading it.
- **accepted fact**: the verifier accepted the statement and proof, and the Fact Graph stored it.
- **starting/running**: the Runtime observed a Worker process.
- **stopped/expired/failed**: a lifecycle result, not a mathematical conclusion.
