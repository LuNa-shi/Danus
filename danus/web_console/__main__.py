"""Launch the authenticated Web Console on loopback."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from .app import AppSettings, create_app
from .security import hash_password


def main() -> None:
    parser = argparse.ArgumentParser(description="Danus authenticated Web Console")
    parser.add_argument("--host", default=os.environ.get("DANUS_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DANUS_WEB_PORT", "8080")))
    parser.add_argument("--database", default=os.environ.get("DANUS_WEB_DATABASE", "runtime/web-console.sqlite3"))
    parser.add_argument("--password-hash", default=os.environ.get("DANUS_WEB_PASSWORD_HASH"))
    args = parser.parse_args()
    password_hash = args.password_hash
    if not password_hash:
        raise SystemExit("DANUS_WEB_PASSWORD_HASH is required (store a hash, never a plaintext password)")
    import uvicorn
    allowed = {origin.strip() for origin in os.environ.get("DANUS_WEB_ALLOWED_ORIGINS", "").split(",") if origin.strip()}
    app = create_app(settings=AppSettings(database_path=Path(args.database), password_hash=password_hash, allowed_origins=allowed))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
