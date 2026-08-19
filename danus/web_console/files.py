"""Project-scoped, atomic material-file storage for the Web Console."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import quote_from_bytes, unquote_to_bytes


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
_STAGING_NAME_RE = re.compile(r"\.staged-[0-9a-f]{64}")
_UPLOAD_HEADER_RE = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


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


def encode_upload_filename(filename: str) -> str:
    """Encode one normalized filename into an ASCII-only HTTP header value."""
    normalized = normalize_filename(filename)
    return quote_from_bytes(normalized.encode("utf-8"), safe="-._~")


def decode_upload_filename(value: Any) -> str:
    """Strictly decode the canonical percent-encoded upload preflight name."""
    if not isinstance(value, str) or not value or len(value) > 3072:
        raise FileValidationError("upload filename header is required")
    if any(ord(character) > 127 for character in value):
        raise FileValidationError("upload filename header must be ASCII")
    if _UPLOAD_HEADER_RE.fullmatch(value) is None:
        raise FileValidationError("upload filename header is invalid")
    try:
        encoded = unquote_to_bytes(value)
        decoded = encoded.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise FileValidationError("upload filename header is invalid") from exc
    normalized = normalize_filename(decoded)
    # Reject alternate encodings (including NFD Unicode, lower-case escapes,
    # escaped unreserved bytes, or malformed percent sequences) so one logical
    # name has exactly one wire value.
    if quote_from_bytes(normalized.encode("utf-8"), safe="-._~") != value:
        raise FileValidationError("upload filename header is not canonical")
    return normalized


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


def _private_directory(path: Path) -> Path:
    try:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise FileValidationError("control-plane staging path is not a directory")
        if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
            raise FileValidationError("control-plane staging directory has an invalid owner")
        os.chmod(path, 0o700, follow_symlinks=False)
        after = path.lstat()
    except OSError as exc:
        raise FileValidationError("control-plane staging directory is unavailable") from exc
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise FileValidationError("control-plane staging directory changed during validation")
    if not stat.S_ISDIR(after.st_mode) or stat.S_IMODE(after.st_mode) != 0o700:
        raise FileValidationError("control-plane staging directory is not private")
    if hasattr(os, "geteuid") and after.st_uid != os.geteuid():
        raise FileValidationError("control-plane staging directory has an invalid owner")
    return path.resolve()


def control_staging_root(context_dir: Path, materials: Path | None = None) -> Path:
    """Return the private per-Project staging root outside Worker context."""
    context = Path(context_dir).resolve()
    materials = material_root(context) if materials is None else Path(materials).resolve()
    if materials.parent != context:
        raise FileValidationError("invalid Project materials directory")
    shared = _private_directory(context.parent / ".danus-web-control-staging")
    if shared.parent != context.parent or shared == context or context in shared.parents:
        raise FileValidationError("control-plane staging must be outside Project context")
    project_key = hashlib.sha256(os.fsencode(str(context))).hexdigest()
    staging = _private_directory(shared / project_key)
    try:
        if staging.stat().st_dev != materials.stat().st_dev:
            raise FileValidationError("control-plane staging must share the materials filesystem")
    except OSError as exc:
        raise FileValidationError("control-plane staging filesystem is unavailable") from exc
    return staging


def staging_blob(staging: Path, staging_name: Any, *, require_regular: bool = True) -> Path:
    if not isinstance(staging_name, str) or not _STAGING_NAME_RE.fullmatch(staging_name):
        raise FileValidationError("invalid staged material locator")
    candidate = Path(staging) / staging_name
    if candidate.parent.resolve() != Path(staging).resolve() or candidate.name != staging_name:
        raise FileValidationError("invalid staged material locator")
    if require_regular:
        try:
            info = candidate.lstat()
        except FileNotFoundError as exc:
            raise FileValidationError("staged material is unavailable") from exc
        if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise FileValidationError("staged material is not a regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise FileValidationError("staged material permissions are not private")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise FileValidationError("staged material has an invalid owner")
    return candidate


def stream_to_pending(upload: Any, staging: Path, max_bytes: int) -> tuple[Path, str, int]:
    """Stream an UploadFile-like object into a private random staging file."""
    fd = -1
    path: Path | None = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(128):
        name = f".staged-{secrets.token_hex(32)}"
        path = Path(staging) / name
        try:
            fd = os.open(path, flags, 0o600)
            break
        except FileExistsError:
            continue
    if fd < 0 or path is None:
        raise FileValidationError("could not allocate private material staging")
    digest = hashlib.sha256()
    size = 0
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
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
        return path, digest.hexdigest(), size
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        path.unlink(missing_ok=True)
        raise


def fsync_directory(directory: Path) -> None:
    descriptor = os.open(
        directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def staged_file_matches(
    path: Path, sha256: str, size: int, *, require_private: bool = False,
) -> bool:
    """Verify one no-follow regular file through a stable open descriptor."""
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != size:
            return False
        if require_private and (
            stat.S_IMODE(opened.st_mode) != 0o600
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
        ):
            return False
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        ):
            return False
        return secrets.compare_digest(digest.hexdigest(), sha256)
    except OSError:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def promote_pending(
    pending: Path, materials: Path, sha256: str, size: int,
) -> tuple[str, bool]:
    """Move a completed pending file into its content-addressed blob name."""
    if _SHA256_RE.fullmatch(sha256) is None:
        raise FileValidationError("invalid material digest")
    if not staged_file_matches(pending, sha256, size, require_private=True):
        raise FileValidationError("pending material integrity check failed")
    blob_name = sha256
    destination = materials / blob_name
    if (
        (destination.exists() or destination.is_symlink())
        and not staged_file_matches(destination, sha256, size)
    ):
        raise FileValidationError("existing material destination failed integrity verification")
    # Even a verified destination can be swapped after inspection by a process
    # with access to materials. Replace it with the already-verified private
    # source instead of blindly reusing its pathname.
    os.replace(pending, destination)
    os.chmod(destination, 0o600, follow_symlinks=False)
    fsync_directory(materials)
    if pending.parent != materials:
        fsync_directory(pending.parent)
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
