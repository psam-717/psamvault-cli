"""What may be written to ``entries.*.allow_hosts``.

The MCP reads that list and sends a stored secret only to those hosts (plus
the entry's own site or service). This module is the CLI's copy of that
check, used before a human grants a host and again when ``policy.json`` is
loaded.

Two modes, because a file a human already edited is not the same as a new grant:

* **Load** (``strict=False``) accepts what the MCP accepts. A URL or
  ``host:port`` is the hostname inside it. A loopback, private, or link-local
  address is reported and not treated as allowed — the MCP blocks those even
  when they are listed. A bare public suffix is reported too.
* **Grant** (``strict=True``) wants a hostname. A scheme, a path, and a port
  are refused so the confirmation names the host that will be saved. An IP
  literal is refused. A leading ``*.`` is the only wildcard, matching the MCP.

Nothing here reads or returns a secret.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import public_suffix

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Names the MCP's SSRF check refuses before allow_hosts is consulted.
_INTERNAL_NAMES = frozenset({"localhost", "localhost.localdomain"})


@dataclass(frozen=True)
class HostVerdict:
    """A normalised allow_hosts value, and why it cannot be granted."""

    normalized: str | None
    problem: str | None


def judge(value: str, *, strict: bool) -> HostVerdict:
    """Classify one allow_hosts value. Never raises."""
    text = (value or "").strip().lower()
    if not text:
        return HostVerdict(None, "A host is required.")
    if any(character.isspace() for character in text):
        return HostVerdict(None, f"{value!r} is not a hostname.")

    shape = _shape_problem(text) if strict else None
    normalized = normalize_allow_spec(text)
    if shape:
        return HostVerdict(normalized, shape)
    if not normalized:
        return HostVerdict(None, _unparsed_problem(text))
    safety = _safety_problem(normalized, strict=strict)
    if safety:
        return HostVerdict(normalized, safety)
    return HostVerdict(normalized, None)


def same_host(stored: str, query: str) -> bool:
    """True when both strings are the same host the MCP would store."""
    left = str(stored).strip()
    right = str(query).strip()
    if left.casefold() == right.casefold():
        return True
    return _equal_specs(normalize_allow_spec(left), normalize_allow_spec(right))


def normalize_allow_spec(value: str) -> str | None:
    """``*.example.com`` or one host, the way the MCP stores it.

    None when the value is not a host. A URL and a ``host:port`` reduce to
    the hostname. This does not apply the safety rules — callers do.
    """
    text = (value or "").strip().lower()
    if not text:
        return None
    wildcard = text.startswith("*.")
    body = text[2:] if wildcard else text
    if "*" in body:
        return None
    host = extract_host(body)
    if not host:
        return None
    return f"*.{host}" if wildcard else host


def extract_host(value: str) -> str | None:
    """Hostname from a URL, a host, or ``host:port``. None when it is not one."""
    text = (value or "").strip()
    if not text or any(character.isspace() for character in text):
        return None
    if "://" in text or text.startswith("//"):
        parsed = urlparse(text if "://" in text else "https:" + text)
        host = parsed.hostname
    elif "/" in text:
        host = urlparse("https://" + text).hostname
    else:
        host = text
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif host.count(":") == 1 and not _is_ip(host):
            host = host.split(":", 1)[0]
    if not host:
        return None
    host = host.strip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if _is_ip(host) or _is_dns_host(host):
        return host
    return None


def _shape_problem(text: str) -> str | None:
    """Grant-only: the human types a hostname, not a URL and not a port."""
    if "*" in text and not (text.startswith("*.") and "*" not in text[2:]):
        return (
            f"{text!r} is not an accepted wildcard. "
            "Only a leading '*.' is accepted, for example '*.ghcr.io'."
        )
    body = text[2:] if text.startswith("*.") else text
    if "://" in body or body.startswith("//") or "/" in body or "\\" in body or "@" in body:
        suggestion = normalize_allow_spec(text)
        extra = f" The hostname would be {suggestion}." if suggestion else ""
        return f"Pass the hostname only, not a URL.{extra}"
    if _has_port(body):
        suggestion = normalize_allow_spec(text)
        extra = f" The hostname would be {suggestion}." if suggestion else ""
        return f"Pass the hostname only, not a port.{extra}"
    return None


def _has_port(body: str) -> bool:
    if body.startswith("[") and "]:" in body:
        return True
    if body.count(":") != 1:
        return False
    host, _, port = body.partition(":")
    return bool(host) and port.isdigit() and not _is_ip(host)


def _unparsed_problem(text: str) -> str:
    body = text[2:] if text.startswith("*.") else text
    bare = body.strip(".")
    if bare in _INTERNAL_NAMES:
        return (
            f"{text!r} is an internal name. Loopback, private and link-local "
            "targets are always blocked, and allow_hosts cannot override that."
        )
    if bare and "." not in bare and "*" not in bare and "/" not in bare and ":" not in bare:
        if _is_bare_suffix(bare):
            return (
                f"{text!r} is a bare public suffix, not a host. "
                "Name a hostname under that suffix, not the suffix itself."
            )
    if "*" in text and not text.startswith("*."):
        return (
            f"{text!r} is not an accepted wildcard. "
            "Only a leading '*.' is accepted, for example '*.ghcr.io'."
        )
    return (
        f"{text!r} is not a hostname. "
        "Pass a name such as api.example.com, or *.example.com for that domain and its subdomains."
    )


def _safety_problem(normalized: str, *, strict: bool) -> str | None:
    base = normalized[2:] if normalized.startswith("*.") else normalized
    address = _address_problem(base, display=normalized, strict=strict)
    if address:
        return address
    if base in _INTERNAL_NAMES or base.endswith(".local") or base.endswith(".internal"):
        return (
            f"{normalized!r} is an internal name (.local, .internal, or localhost). "
            "allow_hosts cannot override that block."
        )
    if _is_bare_suffix(base):
        return (
            f"{normalized!r} is a public suffix, not a site. "
            "Name a hostname under that suffix, not the suffix itself."
        )
    return None


def _address_problem(host: str, *, display: str, strict: bool) -> str | None:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified:
        kind = "loopback"
    elif addr.is_link_local:
        kind = "link-local"
    elif addr.is_multicast:
        kind = "multicast"
    elif addr.is_private or addr.is_reserved:
        kind = "private"
    else:
        kind = None
    if kind == "loopback":
        return (
            f"{display!r} is a loopback address. Loopback, private and link-local "
            "targets are always blocked, and allow_hosts cannot override that."
        )
    if kind == "link-local":
        return (
            f"{display!r} is a link-local address. Loopback, private and link-local "
            "targets are always blocked, and allow_hosts cannot override that."
        )
    if kind == "private":
        return (
            f"{display!r} is a private address. Loopback, private and link-local "
            "targets are always blocked, and allow_hosts cannot override that."
        )
    if kind == "multicast":
        return f"{display!r} is not a hostname allow_hosts can grant."
    if strict:
        return f"{display!r} is an IP address. allow_hosts takes a hostname, not an IP literal."
    return None


def _is_bare_suffix(host: str) -> bool:
    """True when ``host`` has no registrable domain (``com``, ``co.uk``, ``github.io``).

    An IP is not a suffix. A missing public-suffix list fails closed: a grant
    must not assume a suffix is a site because the list could not be read.
    """
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    try:
        return public_suffix.registrable_domain(host) is None
    except OSError:
        return True


def _equal_specs(left: str | None, right: str | None) -> bool:
    return bool(left and right and left == right)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_dns_host(host: str) -> bool:
    if not host or len(host) > 253 or "." not in host:
        return False
    return all(_HOST_LABEL.match(label) for label in host.split("."))
