# danus/execution — the Worker swarm

This package owns Worker layout, scaffolding, lifecycle, and the per-Worker
continuation loop. `danus/orchestration` is the operator-facing layer; production
process authority lives here and requires a systemd user manager plus cgroup v2.

```
danus/execution/
  layout.py             paths, names, and WorkerLayout
  scaffold.py           project/Worker creation and lifecycle handoff
  systemd_scope.py      transient Worker service/slice and provider service proofs
  security.py           provider filesystem, environment, runtime, and gateway policy
  worker_entry.py       isolated absolute entry for the Worker service
  provider_launcher.py  framed provider bootstrap inside the outer sandbox
  loop.py               rounds, pause/stop/deadline handling, status, safe logs
  __main__.py           `python -m danus.execution <worker_dir>`
```

## Runtime boundaries

Every Worker loop runs as a validated transient systemd user service in its own
transient slice. The Project-external ledger binds the canonical Worker path to
the service and slice invocation IDs, cgroup paths, properties, and pinned
cgroup inode identities. Start, inspect, stop, and recovery fail closed when
those identities disagree. Stopping the slice and observing its pinned
`cgroup.events` become empty covers descendants that call `setsid()` or
double-fork; numeric PID/PGID identity is never sufficient authority.

Each round starts the official pinned Codex runtime in a second transient
provider service inside the Worker slice. The provider receives a minimal
environment and a private, Project-external `CODEX_HOME`; model-created commands
cannot read that authentication state. The outer systemd sandbox and enforced
Codex permission profile expose only the Worker workspace and explicitly named
shared Project material. Provider output passes through a bounded streaming
scrubber before it is persisted.

The Worker MCP path is deliberately credential-free:

```
Codex stdio ↔ fixed bridge ↔ one-shot UDS ↔ host-owned broker/gateway
                                             │
                                             └─ fresh scoped verifier capability
```

The random UDS is bind-mounted into only the provider service. Before accepting
the bridge, the broker verifies its uid, executable, exact argv, namespace
identities, ancestry, and membership in the pinned provider cgroup. The broker,
not the provider or bridge, owns the Project/Worker scope and verifier signing
key. `fact_submit` mints a fresh one-use capability; `danus.verify` checks its
scope, expiry, signature, and replay ledger before running a verifier.

There is no direct-process or plain stdio-gateway production fallback. Failure
to establish any service, cgroup, runtime, bridge, broker, or verifier-capability
proof aborts the round.

## Persistent layout and rounds

`<agents_root>/<project>/` contains `global_memory/`, `fact_graph/`, and
`project.json`. Each `workers/<worker>/` is a Codex cwd with the Worker contract,
skills, `TASK.md`, private `local_memory/`, a writable `workspace/`, round logs,
and lifecycle markers/status. `DANUS_AGENTS_ROOT` defaults to
`runtime/projects`.

A round is one `codex exec` continuation session, not one reasoning increment.
Pause, stop, deadline, round-limit, and consecutive-failure conditions are
handled at round boundaries. `.status.json` is written atomically.
Resumability comes from memory and the fact graph, not process state: a fresh
start reconstructs context from the persisted stores. The loop never writes the
truth stores directly; accepted facts travel through `fact_submit` and it only
records the returned `fact_id` for status.

## Tests

`python -m pytest danus/execution/` runs offline seams plus opt-in systemd
boundary integration coverage.
