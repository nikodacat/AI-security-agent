"""Debian version comparison (the dpkg algorithm), used to check apt pins.

compare("1.0-1", "1.0-2") -> -1, equal -> 0, greater -> 1.
Format: [epoch:]upstream[-revision]. Letters sort before digits' gaps, "~" sorts
before everything (even the end of the string), as in deb-version(7).
"""

from __future__ import annotations

import re


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a: str, b: str) -> int:
    while a or b:
        # compare the non-digit prefixes character by character
        na = re.match(r"\D*", a).group(0)
        nb = re.match(r"\D*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            ca = _order(na[i]) if i < len(na) else 0
            cb = _order(nb[i]) if i < len(nb) else 0
            if ca != cb:
                return -1 if ca < cb else 1
        # then the digit runs as numbers
        da = re.match(r"\d*", a).group(0)
        db = re.match(r"\d*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def _split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    m = re.match(r"^(\d+):(.*)$", v)
    if m:
        epoch, v = int(m.group(1)), m.group(2)
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def compare(a: str, b: str) -> int:
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)
