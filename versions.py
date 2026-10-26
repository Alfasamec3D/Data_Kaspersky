"""Version comparison and comparison and defining version vulnerabilities"""

from typing import Iterable, Sequence, Tuple

VersionTuple = Tuple[int, ...]


def parse_version(text: str) -> VersionTuple:
    """'2.41.0.2' -> (2, 41, 0, 2). non numeric tails thrown away"""
    parts = []
    for chunk in text.strip().split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or (0,)


def normalize(v: VersionTuple) -> VersionTuple:
    """(7, 0, 0) == (7,) zero tails thrown away"""
    parts = list(v)
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def compare(a: VersionTuple, b: VersionTuple) -> int:
    a, b = normalize(a), normalize(b)
    return (a > b) - (a < b)


def version_key(text: str) -> str:
    """string sort key (for versions.version_key)"""
    return ".".join(f"{n:010d}" for n in parse_version(text))


def _common_prefix(a: VersionTuple, b: VersionTuple) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def matching_ranges(
    version: str, ranges: Sequence[Tuple[str, str]]
) -> Sequence[Tuple[str, str]]:
    v = parse_version(version)
    parsed = [(s, f, parse_version(s), parse_version(f)) for s, f in ranges]
    if not parsed:
        return []

    best = max(_common_prefix(v, f) for _, _, _, f in parsed)
    if best >= 1:
        candidates = [p for p in parsed if _common_prefix(v, p[3]) == best]
    else:
        earliest = min(parsed, key=lambda p: normalize(p[3]))
        candidates = [earliest]

    hits = []
    for s, f, sv, fv in candidates:
        if compare(v, sv) >= 0 and compare(v, fv) < 0:
            hits.append((s, f))
    return hits


def sort_versions(versions: Iterable[str]) -> list:
    return sorted(versions, key=lambda x: normalize(parse_version(x)))
