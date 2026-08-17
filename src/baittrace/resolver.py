"""The network boundary.

Only a resolver may perform I/O during analysis, and it is injected. The
default is :class:`NullResolver`, which answers ``UNAVAILABLE`` to everything.
:class:`LiveResolver` is constructed only when the operator passes ``--online``
or ``--follow-redirects``.

The three-valued :class:`Answer` matters: an analyzer must never confuse "the
lookup failed" with "the record does not exist". That distinction is what
stops a rotated DKIM selector from being reported as an invalid signature.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, Protocol, TypeVar
from urllib.parse import urlsplit

T = TypeVar("T")

ONLINE_INSTALL_HINT = (
    "online verification requires the optional extra: pip install 'baittrace[online]'"
)

_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_REDIRECT_BYTES = 2048
_TIMEOUT = 3.0


class AnswerState(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Answer(Generic[T]):
    state: AnswerState
    value: T | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state is AnswerState.OK

    @classmethod
    def found(cls, value: T) -> Answer[T]:
        return cls(AnswerState.OK, value)

    @classmethod
    def unavailable(cls, detail: str = "offline") -> Answer[T]:
        return cls(AnswerState.UNAVAILABLE, None, detail)

    @classmethod
    def error(cls, detail: str) -> Answer[T]:
        return cls(AnswerState.ERROR, None, detail)


class Resolver(Protocol):
    """Everything that touches the network goes through this."""

    @property
    def online(self) -> bool: ...

    def txt(self, name: str) -> Answer[list[str]]: ...

    def a(self, name: str) -> Answer[list[str]]: ...

    def ptr(self, ip: str) -> Answer[str]: ...

    def trace_redirects(self, url: str, max_hops: int = 5) -> Answer[list[str]]: ...


class NullResolver:
    """Answers nothing. The default."""

    __slots__ = ()

    @property
    def online(self) -> bool:
        return False

    def txt(self, name: str) -> Answer[list[str]]:
        return Answer.unavailable("offline: no DNS lookups performed")

    def a(self, name: str) -> Answer[list[str]]:
        return Answer.unavailable("offline: no DNS lookups performed")

    def ptr(self, ip: str) -> Answer[str]:
        return Answer.unavailable("offline: no DNS lookups performed")

    def trace_redirects(self, url: str, max_hops: int = 5) -> Answer[list[str]]:
        return Answer.unavailable("offline: redirect tracing is off")


def online_dependencies_available() -> bool:
    try:
        import dkim  # noqa: F401
        import dns.resolver  # noqa: F401
    except ImportError:
        return False
    return True


def is_blocked_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return any(addr in network for network in _BLOCKED_NETWORKS)


def _blocked_host(host: str) -> str | None:
    """Return a reason if this host must not be contacted, else None."""
    host = host.strip().strip("[]").lower()
    if not host:
        return "empty host"
    if host in {"localhost", "metadata.google.internal"}:
        return f"blocked name {host}"
    if is_blocked_ip(host):
        return f"blocked address {host}"
    return None


class LiveResolver:
    """DNS (optional extra) and SSRF-hardened redirect tracing (stdlib)."""

    __slots__ = ("_timeout",)

    def __init__(self, timeout: float = _TIMEOUT) -> None:
        self._timeout = timeout

    @property
    def online(self) -> bool:
        return online_dependencies_available()

    def txt(self, name: str) -> Answer[list[str]]:
        try:
            import dns.resolver
        except ImportError:
            return Answer.unavailable(ONLINE_INSTALL_HINT)
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=self._timeout)
        except dns.resolver.NXDOMAIN:
            return Answer.found([])
        except dns.resolver.NoAnswer:
            return Answer.found([])
        except Exception as exc:  # noqa: BLE001 - DNS libraries raise many types
            return Answer.error(str(exc))
        texts: list[str] = []
        for rdata in answers:
            strings = getattr(rdata, "strings", None)
            if strings:
                texts.append(b"".join(strings).decode("utf-8", errors="replace"))
            else:
                texts.append(str(rdata).strip('"'))
        return Answer.found(texts)

    def a(self, name: str) -> Answer[list[str]]:
        blocked = _blocked_host(name)
        if blocked:
            return Answer.error(blocked)
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return Answer.error(str(exc))
        addresses: list[str] = []
        for info in infos:
            addr = info[4][0]
            if not isinstance(addr, str):
                continue
            if is_blocked_ip(addr):
                return Answer.error(f"resolved to blocked address {addr}")
            if addr not in addresses:
                addresses.append(addr)
        return Answer.found(addresses)

    def ptr(self, ip: str) -> Answer[str]:
        try:
            name, _aliases, _ = socket.gethostbyaddr(ip)
        except (OSError, socket.herror, socket.gaierror) as exc:
            return Answer.error(str(exc))
        return Answer.found(name)

    def trace_redirects(self, url: str, max_hops: int = 5) -> Answer[list[str]]:
        chain: list[str] = []
        current = url
        for _ in range(max(1, max_hops)):
            reason = self._preflight(current)
            if reason is not None:
                return Answer.error(reason)
            chain.append(current)
            status, location = self._head(current)
            if status is None:
                return Answer.error(location)
            if status in {301, 302, 303, 307, 308} and location:
                current = location
                continue
            break
        return Answer.found(chain)

    def _preflight(self, url: str) -> str | None:
        try:
            split = urlsplit(url)
        except ValueError:
            return "unparseable URL"
        scheme = (split.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            return f"scheme {scheme!r} is not allowed"
        host = (split.hostname or "").lower()
        blocked = _blocked_host(host)
        if blocked:
            return blocked
        resolved = self.a(host)
        if not resolved.ok:
            return resolved.detail or "DNS failed"
        return None

    def _head(self, url: str) -> tuple[int | None, str]:
        request = urllib.request.Request(  # noqa: S310 - scheme allowlisted in _preflight
            url,
            method="HEAD",
            headers={"User-Agent": "BaitTrace/0.1 (+https://github.com/JobayerBhuiyan/baittrace)"},
        )

        class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
                return None

        opener = urllib.request.build_opener(_RefuseRedirect)
        try:
            with opener.open(request, timeout=self._timeout) as response:
                response.read(_MAX_REDIRECT_BYTES)
                location = response.headers.get("Location", "")
                return int(getattr(response, "status", 200) or 200), location
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "") if exc.headers else ""
            return int(exc.code), location
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
