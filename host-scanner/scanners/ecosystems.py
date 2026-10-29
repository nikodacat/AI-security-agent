"""Application-layer inventory the OS package manager never sees (A3 + A4).

dpkg lists the OS; it does not list a WordPress install, its plugins, the PHP
libraries under vendor/, a Java app's log4j jar, or pip/npm packages. Those are
where a lot of real-world KEV entries live (WordPress core and plugins,
PHPMailer/PHPUnit, Log4j, Spring, ...).

This module reads them without executing anything: it only walks a bounded set
of directories and parses file NAMES and small metadata files (WordPress
headers, composer installed.json, package.json, *.dist-info directory names,
jar file names). Results are shaped like the software scanner's
``installed_apps`` rows so cve-matcher treats them like any other package.

Vendor is left empty on purpose (cve-matcher then matches on product alone),
except for WordPress core where KEV uses vendor "WordPress" / product "Core".
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable

MAX_PER_ECOSYSTEM = 400
MAX_WALK_DEPTH = 6
HEADER_BYTES = 8192

WEB_ROOTS = ("/var/www", "/usr/share/nginx", "/srv", "/opt", "/app", "/usr/src")
APP_ROOTS = ("/opt", "/srv", "/app", "/usr/local", "/var/lib", "/usr/share", "/home")
PY_SITE_GLOBS = ("/usr/local/lib",)  # pip installs outside dpkg's dist-packages

# jar artifact name -> KEV product spelling
JAR_PRODUCTS = {
    "log4j-core": "Log4j2",
    "log4j": "Log4j",
    "struts2-core": "Struts",
    "struts-core": "Struts 1",
    "spring-core": "Spring Framework",
    "spring-webmvc": "Spring Framework",
    "spring-cloud-function-context": "Spring Cloud Function",
    "spring-cloud-gateway-server": "Spring Cloud Gateway",
    "tomcat-embed-core": "Tomcat",
    "catalina": "Tomcat",
    "commons-text": "Commons Text",
    "commons-collections": "Commons Collections",
    "jackson-databind": "Jackson-databind",
    "fastjson": "Fastjson",
}


# --------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------


def _row(name: str, version: str, product: str, source: str, path: str,
         publisher: str = "") -> dict:
    return {
        "DisplayName": name, "DisplayVersion": version, "Publisher": publisher,
        "InstallDate": "", "Product": product, "Source": source, "Path": path,
    }


def parse_wp_core_version(text: str) -> str:
    m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", text or "")
    return m.group(1) if m else ""


def parse_wp_header(text: str) -> dict:
    """Plugin/theme header fields: Plugin Name / Theme Name, Version, Author."""
    head = (text or "")[:HEADER_BYTES]

    def field_(label: str) -> str:
        m = re.search(rf"^[ \t/*#@]*{label}\s*:\s*(.+?)\s*$", head, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else ""

    return {
        "name": field_("Plugin Name") or field_("Theme Name"),
        "version": field_("Version"),
        "author": field_("Author"),
    }


def parse_composer_installed(text: str) -> list[tuple[str, str]]:
    """(name, version) pairs from vendor/composer/installed.json (v1 and v2 layouts)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    pkgs = data.get("packages", data) if isinstance(data, dict) else data
    out = []
    for p in pkgs if isinstance(pkgs, list) else []:
        if isinstance(p, dict) and p.get("name") and p.get("version"):
            out.append((p["name"], str(p["version"]).lstrip("v")))
    return out


_JAR_RE = re.compile(r"^(?P<artifact>.+?)-(?P<ver>\d+(?:\.\d+)+(?:[.-][A-Za-z0-9]+)*)\.jar$")


def parse_jar_name(filename: str) -> tuple[str, str] | None:
    """('log4j-core', '2.14.1') from 'log4j-core-2.14.1.jar'; None if no version."""
    m = _JAR_RE.match(filename)
    if not m:
        return None
    return m.group("artifact"), m.group("ver")


def parse_package_json(text: str) -> tuple[str, str] | None:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(d, dict) and d.get("name") and d.get("version"):
        return str(d["name"]), str(d["version"])
    return None


_DIST_INFO_RE = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-]*)\.(?:dist-info|egg-info)$")


def parse_dist_info(dirname: str) -> tuple[str, str] | None:
    m = _DIST_INFO_RE.match(dirname)
    return (m.group("name").replace("_", "-"), m.group("ver")) if m else None


# --------------------------------------------------------------------------
# Machine access (injectable)
# --------------------------------------------------------------------------


@dataclass
class Fs:
    # (root, max_depth) -> iterator of (dirpath, dirnames, filenames)
    walk: Callable[[str, int], list[tuple[str, list[str], list[str]]]]
    read: Callable[[str], str]            # path -> text ("" on failure)
    listdir: Callable[[str], list[str]]   # dir -> names ([] on failure)
    isdir: Callable[[str], bool]
    isfile: Callable[[str], bool]


@dataclass
class EcosystemResult:
    apps: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    _seen: dict = field(default_factory=dict, repr=False)


def _add(result: EcosystemResult, kind: str, row: dict) -> None:
    # Same package+version at several paths (e.g. /usr/src/wordpress and the
    # live copy) is one inventory item; extra paths are kept, not re-reported,
    # so cve-matcher does not emit duplicate findings.
    key = (kind, row["DisplayName"], row["DisplayVersion"])
    first = result._seen.get(key)
    if first is not None:
        first.setdefault("OtherPaths", []).append(row["Path"])
        return
    result._seen[key] = row
    n = result.counts.get(kind, 0)
    if n >= MAX_PER_ECOSYSTEM:
        if n == MAX_PER_ECOSYSTEM:
            result.notes.append(f"{kind} truncated at {MAX_PER_ECOSYSTEM}")
            result.counts[kind] = n + 1
        return
    result.counts[kind] = n + 1
    result.apps.append(row)


def _join(*parts: str) -> str:
    return "/".join(p.strip("/") if i else p.rstrip("/") for i, p in enumerate(parts))


def _collect_wordpress(fs: Fs, result: EcosystemResult) -> None:
    for root in WEB_ROOTS:
        for dirpath, _dirs, files in fs.walk(root, MAX_WALK_DEPTH):
            if not dirpath.endswith("wp-includes") or "version.php" not in files:
                continue
            wp = os.path.dirname(dirpath)
            version = parse_wp_core_version(fs.read(_join(dirpath, "version.php")))
            if version:
                _add(result, "wordpress-core",
                     _row("wordpress", version, "Core", "wordpress-core", wp, publisher="WordPress"))
            for kind, sub in (("wordpress-plugin", "wp-content/plugins"),
                              ("wordpress-theme", "wp-content/themes")):
                base = _join(wp, sub)
                for entry in fs.listdir(base):
                    d = _join(base, entry)
                    if not fs.isdir(d):
                        continue
                    candidates = ([f"{entry}.php"] if kind == "wordpress-plugin" else ["style.css"])
                    for fn in candidates + (fs.listdir(d) if kind == "wordpress-plugin" else []):
                        if not fn.endswith((".php", ".css")):
                            continue
                        hdr = parse_wp_header(fs.read(_join(d, fn)))
                        if hdr["name"] and hdr["version"]:
                            _add(result, kind, _row(entry, hdr["version"], hdr["name"], kind, d))
                            break


def _collect_composer(fs: Fs, result: EcosystemResult) -> None:
    for root in WEB_ROOTS:
        for dirpath, _dirs, files in fs.walk(root, MAX_WALK_DEPTH):
            if dirpath.endswith("vendor/composer") and "installed.json" in files:
                src = os.path.dirname(os.path.dirname(dirpath))
                for name, ver in parse_composer_installed(fs.read(_join(dirpath, "installed.json"))):
                    product = name.split("/")[-1]
                    _add(result, "composer", _row(name, ver, product, "composer", src))


def _collect_jars(fs: Fs, result: EcosystemResult) -> None:
    seen: set[tuple[str, str]] = set()
    for root in APP_ROOTS:
        for dirpath, _dirs, files in fs.walk(root, MAX_WALK_DEPTH):
            for fn in files:
                if not fn.endswith(".jar"):
                    continue
                parsed = parse_jar_name(fn)
                if not parsed:
                    continue
                artifact, ver = parsed
                if (artifact, ver) in seen:
                    continue
                seen.add((artifact, ver))
                product = JAR_PRODUCTS.get(artifact)
                if product:  # only artifacts we can map to a KEV product
                    _add(result, "jar", _row(artifact, ver, product, "jar", _join(dirpath, fn)))


def _collect_npm(fs: Fs, result: EcosystemResult) -> None:
    roots = ["/usr/local/lib/node_modules", *WEB_ROOTS]
    for root in roots:
        for dirpath, dirs, files in fs.walk(root, MAX_WALK_DEPTH):
            # top-level node_modules only (nested ones are transitive copies)
            if os.path.basename(dirpath) == "node_modules" and dirpath.count("/node_modules") == 1:
                for entry in fs.listdir(dirpath):
                    pj = _join(dirpath, entry, "package.json")
                    if fs.isfile(pj):
                        parsed = parse_package_json(fs.read(pj))
                        if parsed:
                            _add(result, "npm", _row(parsed[0], parsed[1], parsed[0], "npm", dirpath))
                dirs[:] = []  # do not descend into nested node_modules


def _collect_pip(fs: Fs, result: EcosystemResult) -> None:
    for root in PY_SITE_GLOBS:
        for dirpath, dirs, _files in fs.walk(root, 4):
            if os.path.basename(dirpath) == "site-packages":
                for entry in fs.listdir(dirpath):
                    parsed = parse_dist_info(entry)
                    if parsed:
                        _add(result, "pip", _row(parsed[0], parsed[1], parsed[0], "pip", dirpath))
                dirs[:] = []


def collect(fs: Fs) -> EcosystemResult:
    result = EcosystemResult()
    for fn in (_collect_wordpress, _collect_composer, _collect_jars, _collect_npm, _collect_pip):
        try:
            fn(fs, result)
        except Exception as e:  # one broken ecosystem must not hide the others
            result.notes.append(f"{fn.__name__} failed: {type(e).__name__}: {e}")
    return result


# --------------------------------------------------------------------------
# Real (Linux) filesystem
# --------------------------------------------------------------------------


def _walk_linux(root: str, max_depth: int):
    if not os.path.isdir(root):
        return
    base = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count("/") - base >= max_depth:
            dirnames[:] = []
        yield dirpath, dirnames, filenames


def _read_linux(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(1_000_000).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _listdir_linux(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def linux_fs() -> Fs:
    return Fs(walk=_walk_linux, read=_read_linux, listdir=_listdir_linux,
              isdir=os.path.isdir, isfile=os.path.isfile)
