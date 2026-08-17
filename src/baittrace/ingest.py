"""Reading input safely.

The size bound is applied while reading rather than after, so a 4 GB file or an
endless stdin pipe is refused before it is resident in memory. This is the
first thing that runs on attacker-controlled input and the cheapest place to
stop an exhaustion attempt.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

from .errors import IngestError, LimitExceeded
from .limits import Limits

CHUNK = 64 * 1024
STDIN_SENTINEL = "-"
_UNSUPPORTED_SUFFIXES = {".msg", ".mbox", ".mbx", ".pst", ".ost"}
_DEMO = "baittrace scan corpus/malicious/instructor-demo.eml"
_SAVE_AS_EML = "Save the message as .eml (Gmail: menu then Download message) and try again."


@dataclass(frozen=True, slots=True)
class RawInput:
    """Bytes plus provenance, before any parsing has happened."""

    data: bytes
    source: str
    sha256: str

    @property
    def size(self) -> int:
        return len(self.data)


def _bounded_read(stream: object, limit: int, source: str) -> bytes:
    read = getattr(stream, "read", None)
    if read is None:  # pragma: no cover - defensive
        raise IngestError(f"{source} is not readable")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = read(CHUNK)
        if not chunk:
            break
        if not isinstance(chunk, bytes):  # pragma: no cover - defensive
            raise IngestError(f"{source} did not yield bytes")
        total += len(chunk)
        if total > limit:
            raise LimitExceeded("max_bytes", limit, f"{total}+")
        chunks.append(chunk)
    return b"".join(chunks)


def read_stdin(limits: Limits | None = None) -> RawInput:
    bounds = limits or Limits()
    data = _bounded_read(sys.stdin.buffer, bounds.max_bytes, "<stdin>")
    if not data.strip():
        raise IngestError("no data on stdin")
    return RawInput(data=data, source="<stdin>", sha256=hashlib.sha256(data).hexdigest())


def display_source(path: Path) -> str:
    """A path that does not encode the machine it was scanned on.

    Golden tests and CI compare reports byte-for-byte, so an absolute path
    under ``/Users/...`` would make every report a per-laptop artefact. Corpus
    and test fixtures collapse to a repo-relative form; anything else stays as
    the caller wrote it, or as a path relative to the current working directory
    when that is shorter and still unambiguous.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return str(path)

    parts = resolved.parts
    for marker in ("corpus", "tests"):
        if marker in parts:
            index = parts.index(marker)
            return "/".join(parts[index:])

    try:
        return resolved.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(path)


def _reject_unsupported_format(path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix not in _UNSUPPORTED_SUFFIXES:
        return
    kind = suffix.lstrip(".")
    raise IngestError(
        f"{path} is {kind} format, which is not supported. "
        "Export or save the message as .eml and scan that file."
    )


def _directory_error(path: Path) -> IngestError:
    found = sorted(p.name for p in path.glob("*.eml"))
    extra = ""
    if found:
        shown = found[:5]
        extra = f"; found: {', '.join(shown)}"
        if len(found) > 5:
            extra += ", ..."
    return IngestError(f"{path} is a directory; pass a single message file{extra}")


def read_path(path: Path, limits: Limits | None = None) -> RawInput:
    bounds = limits or Limits()

    _reject_unsupported_format(path)

    if not path.exists():
        raise IngestError(f"no such file: {path}. {_SAVE_AS_EML} Demo: {_DEMO}")
    if path.is_dir():
        raise _directory_error(path)

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IngestError(f"could not stat {path}: {exc}") from exc

    if size > bounds.max_bytes:
        raise LimitExceeded("max_bytes", bounds.max_bytes, size)

    try:
        with path.open("rb") as handle:
            data = _bounded_read(handle, bounds.max_bytes, str(path))
    except OSError as exc:
        raise IngestError(f"could not read {path}: {exc}") from exc

    if not data.strip():
        raise IngestError(f"{path} is empty")

    return RawInput(data=data, source=display_source(path), sha256=hashlib.sha256(data).hexdigest())


def read_input(target: str | Path, limits: Limits | None = None) -> RawInput:
    """Read from a path, or from stdin when the target is ``-``."""
    if isinstance(target, str) and target == STDIN_SENTINEL:
        return read_stdin(limits)
    return read_path(Path(target), limits)
