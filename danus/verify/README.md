# `danus.verify` — the sole Fact Graph write gate

`danus.verify` is an informal LLM proof verifier behind a small authenticated
HTTP interface. A Worker claim enters the Fact Graph only when this service
returns `verdict: "correct"`. It is not a formal proof assistant, and important
research results still need expert review.

## HTTP interface

```text
POST /verify
  Authorization: Bearer <one-use capability>
  X-Danus-Project: <canonical Project name>
  X-Danus-Worker: <canonical Worker name>
  body: {"statement": <nonempty str>, "proof": <nonempty str>}

  200  verification result (`correct` or `wrong`)
  400  deterministic proof precheck rejection
  401  missing bearer
  403  malformed, cross-scope, expired, or replayed bearer
  422  invalid request schema
  500  provider/output failure
  503  authorization, storage, provider configuration, or supervisor unavailable
  504  bounded provider timeout

GET /health -> {"status": "ok", "pid": <serving pid>}
```

Capabilities are HMAC-signed canonical payloads containing an exact
Project/Worker pair, random nonce, issuance time, and bounded expiry. Acceptance
atomically creates a private replay marker, so exactly one concurrent request can
consume a token. The host-owned gateway broker must mint a fresh token for every
HTTP request; a token must never be reused for a whole Worker round. The signing
key is never given to the Codex provider or credential-free MCP bridge.

## Provider execution

There is no direct `subprocess` production fallback. `launcher.py` creates one
`VerifierRunRequest` and crosses the single `TrustedVerifierRunner.run` seam.
Without an installed production adapter, verification fails closed with 503.

The provider request has these properties:

- The only transient-unit argv is the lexical venv entry
  `python -I <absolute danus/verify/trusted_entry.py>`; its working directory is
  `/`. The adapter separately pins the resolved live `/proc/<pid>/exe` identity.
- Provider argv, the minimal credential environment, and the complete prompt are
  length-delimited on private stdin. Statement and proof never enter argv, unit
  properties, environment properties, or the journal; multi-megabyte candidates
  do not hit `ARG_MAX`.
- Codex runs with `--ignore-user-config`, `--ignore-rules`, `--strict-config`,
  `approval_policy="never"`, and a high-precedence `danus_verifier` permission
  profile. There is no `--dangerously-bypass-approvals-and-sandbox` flag.
- Model commands can read only minimal runtime/contract material and write only
  the current run directory. They cannot read `/proc` or the isolated provider
  `CODEX_HOME`, and command network access is disabled. The read-only verifier
  MCP uses a separate absolute `python -I` entry that clears inherited
  credentials before importing Danus.
- Production provider selection is pinned to the provisioned official
  `@openai/codex` package and its matching native binary/bundled bubblewrap;
  arbitrary `DANUS_CODEX_BIN` paths are rejected. Offline tests use an explicit
  private test-binary parameter and cannot alter production selection. API
  deployments pass only the explicit provider credential/routing allowlist.
  Subscription deployments copy `auth.json` into a private verifier-only
  `CODEX_HOME`; the host's general Codex home and config are not inherited.
- The service, trusted entry, and MCP entry are nondumpable and have core dumps
  disabled.

Each run directory is mode 0700. Provider stdout/stderr is discarded after
hashing. `run.json` is mode 0600 and contains only `run_id`, input hash, return
code, duration, stdout hash/byte count, and schema. It never contains the prompt,
provider output, credential, path to a secret, or full command. `verification.json`
is read back through a size-bounded, no-symlink private-file operation.

## Production runner adapter contract

The host transient-service adapter must treat `VerifierRunRequest` as the full
filesystem/process contract:

1. Accept only the exact `entry_argv` returned by `trusted_entry_argv()` and
   `cwd == "/"`. Put no request field other than that fixed argv/cwd into unit
   properties or the journal.
2. Send `wire.encode_request(...)` over a private stdin pipe. Do not place the
   provider argv, provider environment, prompt, capability, or HMAC key in the
   service-manager environment.
3. Grant outer read access only to `read_only_paths`, and read/write access only
   to `read_write_paths`. The latter is exactly the current run directory plus
   the verifier-only provider home. Do not expose a Project, Worker directory,
   host home, Web/GitHub/Cloudflare state, or lifecycle/artifact/HMAC secrets.
4. Use a fresh transient service/cgroup with control-group kill semantics. Pin
   its invocation and cgroup identity before releasing the provider, enforce the
   timeout, and stop/kill the complete cgroup on success, failure, timeout, or an
   adapter exception.
5. Read the pinned `cgroup.events` until `populated 0` (or an equally strong
   kernel proof) before returning. `descendants_empty=True` is permitted only
   after this proof, including double-fork and `setsid()` descendants.
6. Parse only the trusted entry's metadata frame. Return
   `VerifierRunResult`; raise the typed redacted timeout/unavailable errors for
   every other outcome.

The in-test direct adapter exercises framing and provider plumbing but is not a
production adapter and deliberately cannot replace the cgroup proof.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `VERIFY_HOST` / `VERIFY_PORT` | `127.0.0.1` / `8091` | HTTP bind address |
| `VERIFY_AGENT_HOME` | `danus/verify/agent` | trusted verifier contract/skills home |
| `VERIFIER_RESULTS_DIR` | `danus/verify/runs` | private per-run output root |
| `DANUS_VERIFY_PROVIDER_HOME` | `<runtime>/verifier-codex-state` | isolated provider `CODEX_HOME` |
| `DANUS_VERIFY_CAPABILITY_SECRET_FILE` | `<runtime>/secrets/verify-capability.key` | private HMAC key |
| `DANUS_VERIFY_CAPABILITY_TTL_SECONDS` | `300` (allowed 5–600) | one-use bearer lifetime |
| `DANUS_VERIFY_MODEL` / `DANUS_VERIFY_EFFORT` | shared Codex defaults | verifier model settings |
| `CODEX_TIMEOUT_SECONDS` | `900` via `python -m danus.verify` | provider deadline (`0` in library use means none) |
| `VERIFY_MIN_STATEMENT_CHARS`, `VERIFY_MIN_PROOF_CHARS`, `VERIFY_MIN_PROOF_WORDS` | `10`, `30`, `5` | vacuity thresholds |

Run the HTTP process with `python -m danus.verify`; this entry point installs the
systemd/cgroup-v2 `TrustedVerifierRunner` before binding the port. If the user
manager, fixed entry, native Codex package, or cgroup proof is unavailable, the
service fails closed with a typed 503 rather than falling back to a direct
subprocess.
