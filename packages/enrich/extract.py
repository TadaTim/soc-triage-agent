"""Deterministic IoC extraction from raw alert payloads.

Extraction runs over a defanged-normalized copy of the payload (`hxxp` ->
`http`, `[.]` -> `.`) while a per-character index map translates match spans
back into offsets in the ORIGINAL payload, so `IoC.raw` is always the exact
substring an analyst would see in the raw alert.

Extraction order matters: URLs, hashes, emails, CVEs, IPs, files, then
domains — earlier (more specific) matches consume their spans so later
patterns cannot re-interpret parts of them (e.g. the domain inside a URL is
emitted once, as the URL's host; a filename's extension never becomes a
"domain").
"""

from __future__ import annotations

import ipaddress
import re

from packages.schemas.models import IoC, IoCType

_URL_RE = re.compile(r"https?://[^\s'\"<>\]\)]+", re.IGNORECASE)
_SHA256_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64}(?![0-9A-Za-z])")
_SHA1_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{40}(?![0-9A-Za-z])")
_MD5_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32}(?![0-9A-Za-z])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_FILE_RE = re.compile(r"[A-Za-z0-9_.\-]+\.(?:exe|dll|scr|ps1|bat|vbs|js|jar|msi)", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9@.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![A-Za-z0-9\-])",
    re.IGNORECASE,
)
_FILE_TLDS = {"exe", "dll", "scr", "ps1", "bat", "vbs", "js", "jar", "msi", "txt", "log", "bin"}


def _defang_normalize(text: str) -> tuple[str, list[int]]:
    """Return (normalized_text, index_map) where index_map[i] is the offset
    in the original text of normalized character i."""
    out: list[str] = []
    index_map: list[int] = []
    i = 0
    lowered = text.lower()
    while i < len(text):
        if lowered.startswith("[.]", i) or lowered.startswith("(.)", i):
            out.append(".")
            index_map.append(i)
            i += 3
        elif lowered.startswith("hxxps", i):
            out.append("https")
            index_map.extend(range(i, i + 5))
            i += 5
        elif lowered.startswith("hxxp", i):
            out.append("http")
            index_map.extend(range(i, i + 4))
            i += 4
        else:
            out.append(text[i])
            index_map.append(i)
            i += 1
    return "".join(out), index_map


def _orig_span(index_map: list[int], start: int, end: int) -> tuple[int, int]:
    return index_map[start], index_map[end - 1] + 1


def extract_iocs(payload: str) -> list[IoC]:
    normalized, index_map = _defang_normalize(payload)
    consumed: list[tuple[int, int]] = []  # spans in normalized coordinates
    found: list[IoC] = []
    seen: set[tuple[IoCType, str]] = set()

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in consumed)

    def emit(type_: IoCType, value: str, n_start: int, n_end: int, *, consume: bool = True) -> None:
        key = (type_, value)
        if key in seen:
            return
        seen.add(key)
        o_start, o_end = _orig_span(index_map, n_start, n_end)
        found.append(
            IoC(type=type_, value=value, raw=payload[o_start:o_end], start=o_start, end=o_end)
        )
        if consume:
            consumed.append((n_start, n_end))

    # URLs (and their hosts).
    for match in _URL_RE.finditer(normalized):
        raw_url = match.group(0).rstrip(".,;:")
        end = match.start() + len(raw_url)
        if overlaps(match.start(), end):
            continue
        emit(IoCType.URL, raw_url, match.start(), end)
        hostport = raw_url.split("://", 1)[1].split("/", 1)[0]
        host = hostport.split(":", 1)[0].lower()
        host_start = match.start() + raw_url.lower().index(host)
        host_end = host_start + len(host)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) and _valid_ipv4(host):
            emit(IoCType.IPV4, host, host_start, host_end, consume=False)
        elif "." in host:
            emit(IoCType.DOMAIN, host, host_start, host_end, consume=False)

    # Hashes, longest first so a SHA256 is never re-read as SHA1/MD5.
    for regex, type_ in (
        (_SHA256_RE, IoCType.SHA256),
        (_SHA1_RE, IoCType.SHA1),
        (_MD5_RE, IoCType.MD5),
    ):
        for match in regex.finditer(normalized):
            if not overlaps(match.start(), match.end()):
                emit(type_, match.group(0).lower(), match.start(), match.end())

    for match in _EMAIL_RE.finditer(normalized):
        if not overlaps(match.start(), match.end()):
            emit(IoCType.EMAIL, match.group(0).lower(), match.start(), match.end())

    for match in _CVE_RE.finditer(normalized):
        if not overlaps(match.start(), match.end()):
            emit(IoCType.CVE, match.group(0).lower(), match.start(), match.end())

    for match in _IPV4_RE.finditer(normalized):
        candidate = match.group(0)
        if _valid_ipv4(candidate) and not overlaps(match.start(), match.end()):
            emit(IoCType.IPV4, candidate, match.start(), match.end())

    for match in _IPV6_RE.finditer(normalized):
        candidate = match.group(0)
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if not overlaps(match.start(), match.end()):
            emit(IoCType.IPV6, candidate.lower(), match.start(), match.end())

    # Files before domains: "update.exe" is a file, not a domain.
    for match in _FILE_RE.finditer(normalized):
        if not overlaps(match.start(), match.end()):
            emit(IoCType.FILE, match.group(0).lower(), match.start(), match.end())

    for match in _DOMAIN_RE.finditer(normalized):
        raw_candidate = match.group(0)
        candidate = raw_candidate.lower()
        if candidate.rsplit(".", 1)[-1] in _FILE_TLDS:
            continue
        # Dotted CamelCase identifiers (e.g. the .NET class Net.WebClient in
        # a command line) are code, not domains: an uppercase letter beyond
        # the first character of any label gives them away.
        if any(any(ch.isupper() for ch in label[1:]) for label in raw_candidate.split(".")):
            continue
        if not overlaps(match.start(), match.end()):
            emit(IoCType.DOMAIN, candidate, match.start(), match.end())

    found.sort(key=lambda ioc: ioc.start)
    return found


def _valid_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
    return True
