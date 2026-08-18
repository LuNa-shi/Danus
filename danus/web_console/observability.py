"""One bounded redaction policy for operator-visible events and logs."""
from __future__ import annotations

import re

_ANSI_RE = re.compile(
    r"(?:\x1B\][^\x07]*(?:\x07|\x1B\\)|\x1B[@-_][0-?]*[ -/]*[@-~])"
)
_SECRET_NAME = r"(?:api[_-]?key|token|secret|password|authorization|auth[_-]?token|session|cookie|credential|private[_-]?key|access[_-]?key|refresh[_-]?token)"


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", str(text))


def redact_text(
    text: str, *, limit: int = 16_384, replacement: str = "[REDACTED]",
) -> str:
    """Strip controls and redact shared secret shapes before projection."""
    value = strip_ansi(text)
    value = re.sub(
        r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
        replacement, value,
    )
    # A bounded tail may begin or end inside a PEM block. Fail closed on either
    # unmatched boundary rather than returning key material without its marker.
    value = re.sub(
        r"(?is)\A.*?-----END [^-\r\n]*PRIVATE KEY-----",
        replacement, value,
    )
    value = re.sub(
        r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*\Z",
        replacement, value,
    )
    value = re.sub(
        r"(?im)^(\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTHORIZATION|COOKIE|SESSION|CREDENTIAL)[A-Z0-9_]*\s*=).*$",
        lambda match: match.group(1) + replacement, value,
    )
    value = re.sub(
        r"(?i)((?:-u|--user)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)",
        lambda match: match.group(1) + replacement, value,
    )
    value = re.sub(
        r"(?i)([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@",
        lambda match: match.group(1) + replacement + "@", value,
    )
    value = re.sub(
        r"(?i)((?:authorization|cookie|set-cookie|x-session)\s*[:=]\s*)(?:bearer\s+)?[^\r\n]+",
        lambda match: match.group(1) + replacement, value,
    )
    value = re.sub(
        rf"(?i)([\"']?{_SECRET_NAME}[\"']?\s*[:=]\s*)([\"']?)[^\s,\"';}}]+\2",
        lambda match: match.group(1) + replacement, value,
    )
    value = re.sub(
        rf"(?i)([?&]{_SECRET_NAME}=)[^&#\s]+",
        lambda match: match.group(1) + replacement, value,
    )
    for pattern in (
        r"(?i)\b(?:sk|rk)-[A-Za-z0-9_-]{8,}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{12,}\b",
        r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        r"\bAIza[0-9A-Za-z_-]{20,}\b",
        r"\b(?:hf|npm)_[A-Za-z0-9_-]{20,}\b",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b",
    ):
        value = re.sub(pattern, replacement, value)
    if len(value) > limit:
        return value[:limit] + "…[truncated]"
    return value
