"""Launch the authenticated Web Console on loopback."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from .app import AppSettings, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Danus authenticated Web Console")
    def positive_int_env(*names: str, default: int) -> int:
        for name in names:
            raw = os.environ.get(name)
            if raw:
                try:
                    value = int(raw)
                except ValueError:
                    continue
                if value >= 1:
                    return value
        return default

    parser.add_argument("--host", default=os.environ.get("DANUS_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DANUS_WEB_PORT", "8080")))
    runtime_root = Path(os.environ.get("DANUS_RUNTIME", "runtime")).resolve()
    parser.add_argument("--database", default=os.environ.get("DANUS_WEB_DATABASE", str(runtime_root / "web-console.sqlite3")))
    parser.add_argument("--password-hash", default=os.environ.get("DANUS_WEB_PASSWORD_HASH"))
    parser.add_argument("--cookie-secure", choices=("true", "false"), default=os.environ.get("DANUS_WEB_COOKIE_SECURE", "true").lower())
    parser.add_argument("--main-agent-backend", choices=("codex", "claude"), default=os.environ.get("DANUS_WEB_MAIN_AGENT_BACKEND", "codex"))
    parser.add_argument("--agents-root", default=os.environ.get("DANUS_AGENTS_ROOT", str(runtime_root / "projects")))
    parser.add_argument("--max-file-bytes", type=int, default=int(os.environ.get("DANUS_WEB_MAX_FILE_BYTES", str(25 * 1024 * 1024))))
    parser.add_argument("--default-max-parallel-workers", type=int, default=positive_int_env("DANUS_WEB_DEFAULT_MAX_PARALLEL_WORKERS", "DANUS_MAX_PARALLEL_WORKERS", default=1))
    args = parser.parse_args()
    password_hash = args.password_hash
    if not password_hash:
        raise SystemExit("DANUS_WEB_PASSWORD_HASH is required (store a hash, never a plaintext password)")
    import uvicorn
    allowed = {origin.strip() for origin in os.environ.get("DANUS_WEB_ALLOWED_ORIGINS", "").split(",") if origin.strip()}
    if not allowed:
        allowed = {f"http://{args.host}:{args.port}"}
    cookie_secure = args.cookie_secure == "true"
    if args.cookie_secure == "true" and args.host in {"127.0.0.1", "localhost"} and not os.environ.get("DANUS_WEB_PUBLIC_HTTPS", ""):
        cookie_secure = False
    from .main_agent import MainAgentAdapter
    from .runtime import DanusRuntimeAdapter
    app = create_app(
        settings=AppSettings(database_path=Path(args.database).resolve(), password_hash=password_hash,
                             cookie_secure=cookie_secure, allowed_origins=allowed,
                             max_file_bytes=args.max_file_bytes,
                             default_max_parallel_workers=args.default_max_parallel_workers,
                             lifecycle_base_url=f"http://127.0.0.1:{args.port}"),
        runtime=DanusRuntimeAdapter(Path(args.agents_root).resolve()),
        main_agent=MainAgentAdapter(backend=args.main_agent_backend),
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
