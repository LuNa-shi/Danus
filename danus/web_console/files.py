"""Project-scoped, atomic material-file storage for the Web Console."""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Any


class FileValidationError(ValueError):
    pass


_EXTENSIONS: dict[str, tuple[str, str]] = {
    ".pdf": ("application/pdf", "pdf"),
    ".tex": ("text/x-tex", "latex"),
    ".latex": ("text/x-tex", "latex"),
    ".ltx": ("text/x-tex", "latex"),
    ".md": ("text/markdown", "markdown"),
    ".markdown": ("text/markdown", "markdown"),
    ".txt": ("text/plain", "text"),
    ".text": ("text/plain", "text"),
    ".rst": ("text/plain", "text"),
    ".csv": ("text/csv", "text"),
}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def normalize_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise FileValidationError("filename is required")
    filename = unicodedata.normalize("NFC", filename)
    if not filename or len(filename) > 255 or _CONTROL_RE.search(filename):
        raise FileValidationError("invalid filename")
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise FileValidationError("filename must be a single path segment")
    if filename.startswith("."):
        raise FileValidationError("hidden filenames are not supported")
    suffix = Path(filename).suffix.lower()
    if suffix not in _EXTENSIONS:
        raise FileValidationError("unsupported file type")
    return filename


def file_type(filename: str) -> tuple[str, str]:
    filename = normalize_filename(filename)
    return _EXTENSIONS[Path(filename).suffix.lower()]


def validate_bytes(kind: str, data: bytes) -> None:
    if kind == "pdf":
        if not data.startswith(b"%PDF-"):
            raise FileValidationError("PDF content signature is invalid")
        return
    if b"\x00" in data:
        raise FileValidationError("text material contains binary data")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FileValidationError("text material must be UTF-8") from exc


def material_root(context_dir: Path) -> Path:
    root = Path(context_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    materials = (root / "materials").resolve()
    if materials.parent != root:
        raise FileValidationError("invalid project context directory")
    materials.mkdir(mode=0o700, exist_ok=True)
    return materials


def stream_to_pending(upload: Any, materials: Path, max_bytes: int) -> tuple[Path, str, int]:
    """Stream an UploadFile-like object into a same-filesystem temp file."""
    fd, name = tempfile.mkstemp(prefix=".pending-", suffix=".tmp", dir=materials)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as output:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise FileValidationError("file exceeds maximum size")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        return Path(name), digest.hexdigest(), size
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(name).unlink(missing_ok=True)
        raise


def promote_pending(pending: Path, materials: Path, sha256: str) -> tuple[str, bool]:
    """Move a completed pending file into its content-addressed blob name."""
    blob_name = sha256
    destination = materials / blob_name
    if destination.exists():
        pending.unlink(missing_ok=True)
        return blob_name, False
    os.replace(pending, destination)
    return blob_name, True


def remove_blob(materials: Path, storage_name: str) -> None:
    candidate = (materials / storage_name).resolve()
    if candidate.parent != materials.resolve():
        raise FileValidationError("invalid stored material path")
    candidate.unlink(missing_ok=True)


def metadata(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"], "filename": row["logical_name"],
        "content_type": row["content_type"], "kind": row["kind"],
        "size": row["size"], "sha256": row["sha256"],
        "uploaded_at": row["uploaded_at"], "version": row["version"],
        "current": bool(row["is_current"]),
        "processing_status": row["processing_status"],
        "read_status": row["read_status"],
    }
