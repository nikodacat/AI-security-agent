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

import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Callable

from . import catalog

MAX_PER_ECOSYSTEM = 400
MAX_WALK_DEPTH = 6
HEADER_BYTES = 8192

WEB_ROOTS = ("/var/www", "/usr/share/nginx", "/srv", "/opt", "/app", "/usr/src")
APP_ROOTS = ("/opt", "/srv", "/app", "/usr/local", "/var/lib", "/usr/share", "/home",
             # Apps run straight from Maven's cache in many images (Vulhub's Struts2 does),
             # and the layout org/apache/<group>/<artifact>/<ver>/ is too deep to reach from /root.
             "/root/.m2/repository")
PY_SITE_GLOBS = ("/usr/local/lib",)  # pip installs outside dpkg's dist-packages
MAX_LIBRARIES = 2000          # per scan; OSV is queried once per (ecosystem, name, version)
MAX_NESTED_JAR_BYTES = 30_000_000  # a bundled jar is read into memory to find its pom.properties
NESTED_LIB_DIRS = ("WEB-INF/lib/", "BOOT-INF/lib/")  # war / Spring Boot fat jar
# The whole-filesystem pass: bounded so a big host cannot make the scan run away.
EVERYWHERE_DEPTH = 16
MAX_WALK_DIRS = 300_000
MAX_JARS_OPENED = 5000
_PRUNE_AT_ROOT = {"proc", "sys", "dev", "run"}
_PRUNE_NAMES = {"jvm", ".git", "__pycache__"}
_JDK_PREFIXES = ("jdk", "openjdk", "jre")  # the JDK's own jars are not the application's

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
         publisher: str = "", cpe: str = "") -> dict:
    row = {
        "DisplayName": name, "DisplayVersion": version, "Publisher": publisher,
        "InstallDate": "", "Product": product, "Source": source, "Path": path,
    }
    if cpe:
        row["Cpe"] = cpe  # NVD "vendor:product", known to the catalog entry that recognised this
    return row


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


def parse_pom_properties(text: str) -> tuple[str, str, str] | None:
    """(groupId, artifactId, version) from a META-INF/maven/<g>/<a>/pom.properties body."""
    kv = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip()
    g, a, v = kv.get("groupId"), kv.get("artifactId"), kv.get("version")
    return (g, a, v) if g and a and v else None


def maven_coords(zf: zipfile.ZipFile) -> list[tuple[str, str, str]]:
    """Every Maven coordinate recorded in an open jar (a shaded jar carries several)."""
    out = []
    for name in zf.namelist():
        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
            try:
                c = parse_pom_properties(zf.read(name)[:4096].decode("utf-8", "replace"))
            except (KeyError, zipfile.BadZipFile, OSError):
                continue
            if c:
                out.append(c)
    return out[:50]


def parse_package_json(text: str) -> tuple[str, str] | None:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(d, dict) and d.get("name") and d.get("version"):
        return str(d["name"]), str(d["version"])
    return None


_GEMSPEC_RE = re.compile(
    r"^(?P<name>.+?)-(?P<ver>\d[\w.]*?)(?:-(?:x86_64|x86|java|universal|arm64|aarch64|mswin|mingw)[\w.-]*)?\.gemspec$")


def parse_gemspec_filename(filename: str) -> tuple[str, str] | None:
    """'actionpack-5.0.7.gemspec' -> ('actionpack', '5.0.7'); platform gems drop the platform."""
    m = _GEMSPEC_RE.match(filename)
    return (m.group("name"), m.group("ver")) if m else None


def parse_pkg_info(text: str) -> tuple[str, str] | None:
    """(Name, Version) from the header of a PKG-INFO / METADATA file, or None."""
    name = re.search(r"^Name:\s*(\S+)", text or "", re.MULTILINE)
    ver = re.search(r"^Version:\s*(\S+)", text or "", re.MULTILINE)
    return (name.group(1), ver.group(1)) if name and ver else None


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
    # jar/war path -> [(groupId, artifactId, version)]; default finds none (fake filesystems in tests)
    jar_coords: Callable[[str], list[tuple[str, str, str]]] = lambda _p: []
    # (jar path, member name) -> member text ("" when absent)
    jar_read: Callable[[str, str], str] = lambda _p, _m: ""


@dataclass
class EcosystemResult:
    apps: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # Package coordinates in a public advisory database's own naming (OSV): unlike `apps`, not
    # limited to what we can map to a KEV product. [{ecosystem, name, version, path}]
    libraries: list[dict] = field(default_factory=list)
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


def _add_library(result: EcosystemResult, ecosystem: str, name: str, version: str, path: str) -> None:
    key = ("lib", ecosystem, name, version)
    if key in result._seen or len(result.libraries) >= MAX_LIBRARIES:
        if len(result.libraries) == MAX_LIBRARIES and "libraries truncated" not in result.notes:
            result.notes.append("libraries truncated")
        return
    result._seen[key] = True
    result.libraries.append({"ecosystem": ecosystem, "name": name, "version": version, "path": path})


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
                    _add_library(result, "Packagist", name, ver, src)


def _collect_jars(fs: Fs, result: EcosystemResult) -> None:
    seen: set[tuple[str, str]] = set()
    # "/" itself, one level: images often drop the app jar at the filesystem root.
    for root, depth in [(r, MAX_WALK_DEPTH) for r in APP_ROOTS] + [("/", 1)]:
        for dirpath, _dirs, files in fs.walk(root, depth):
            for fn in files:
                if fn.endswith((".jar", ".war")):
                    for g, a, v in fs.jar_coords(_join(dirpath, fn)):
                        _add_library(result, "Maven", f"{g}:{a}", v, _join(dirpath, fn))
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
                            _add_library(result, "npm", parsed[0], parsed[1], dirpath)
                dirs[:] = []  # do not descend into nested node_modules


def _collect_pip(fs: Fs, result: EcosystemResult) -> None:
    for root in PY_SITE_GLOBS:
        for dirpath, dirs, _files in fs.walk(root, 4):
            if os.path.basename(dirpath) == "site-packages":
                for entry in fs.listdir(dirpath):
                    parsed = parse_dist_info(entry)
                    if parsed:
                        _add(result, "pip", _row(parsed[0], parsed[1], parsed[0], "pip", dirpath))
                        _add_library(result, "PyPI", parsed[0], parsed[1], dirpath)
                dirs[:] = []


_SERVER_NUMBER_RE = re.compile(r"^server\.number=(\d+\.\d+\.\d+)", re.MULTILINE)


def _handle_jar(fs: Fs, result: EcosystemResult, dirpath: str, fn: str, opened: list[int]) -> None:
    path = _join(dirpath, fn)
    coords: list[tuple[str, str, str]] = []
    if opened[0] < MAX_JARS_OPENED:
        opened[0] += 1
        coords = fs.jar_coords(path)
    for g, a, v in coords:
        _add_library(result, "Maven", f"{g}:{a}", v, path)
    if not coords and fn.endswith(".jar"):  # no pom.properties: the repository layout may name it
        layout = catalog.maven_layout_coords(path)
        if layout:
            _add_library(result, "Maven", f"{layout[0]}:{layout[1]}", layout[2], path)
    if not fn.endswith(".jar"):
        return
    parsed = parse_jar_name(fn)
    if parsed and parsed[0] not in JAR_PRODUCTS:
        entry = catalog.jar_entry(parsed[0])
        if entry:
            _add(result, "jar", _row(parsed[0], parsed[1], entry.product, "jar", path, cpe=entry.cpe))
    if fn == "catalina.jar":  # Tomcat's jars carry no version in their names
        m = _SERVER_NUMBER_RE.search(fs.jar_read(path, "org/apache/catalina/util/ServerInfo.properties"))
        if m:
            _add(result, "jar", _row("tomcat", m.group(1), "Tomcat", "jar", path, cpe="apache:tomcat"))


def _collect_everywhere(fs: Fs, result: EcosystemResult) -> None:
    """One pass over the whole filesystem for what the fixed-root collectors above can miss:
    applications installed at /ofbiz or /node_modules, repositories deeper than their walk
    depth, version files of well-known applications. Recognises files by what they are, not
    by which directory they sit in."""
    opened = [0]
    for n, (dirpath, dirs, files) in enumerate(fs.walk("/", EVERYWHERE_DEPTH)):
        if n >= MAX_WALK_DIRS:
            result.notes.append(f"filesystem walk stopped after {MAX_WALK_DIRS} directories")
            break
        if dirpath in ("", "/"):
            dirs[:] = [d for d in dirs if d not in _PRUNE_AT_ROOT]
        dirs[:] = [d for d in dirs if d not in _PRUNE_NAMES and not d.startswith(_JDK_PREFIXES)]
        base = os.path.basename(dirpath)

        if base == "node_modules" and dirpath.count("/node_modules") == 1:
            for entry in fs.listdir(dirpath):
                names = ([f"{entry}/{sub}" for sub in fs.listdir(_join(dirpath, entry))]
                         if entry.startswith("@") else [entry])
                for name in names:
                    pj = _join(dirpath, name, "package.json")
                    parsed = parse_package_json(fs.read(pj)) if fs.isfile(pj) else None
                    if parsed:
                        _add(result, "npm", _row(parsed[0], parsed[1], parsed[0], "npm", dirpath))
                        _add_library(result, "npm", parsed[0], parsed[1], dirpath)
            dirs[:] = []
            continue
        if base == "site-packages":
            for entry in fs.listdir(dirpath):
                parsed = parse_dist_info(entry)
                if parsed:
                    _add(result, "pip", _row(parsed[0], parsed[1], parsed[0], "pip", dirpath))
                    _add_library(result, "PyPI", parsed[0], parsed[1], dirpath)
            dirs[:] = []
            continue
        for d in dirs:  # editable / source installs keep <pkg>.egg-info outside site-packages
            if d.endswith(".egg-info") and not parse_dist_info(d):
                parsed = parse_pkg_info(fs.read(_join(dirpath, d, "PKG-INFO")))
                if parsed:
                    _add(result, "pip", _row(parsed[0], parsed[1], parsed[0], "pip", dirpath))
                    _add_library(result, "PyPI", parsed[0], parsed[1], dirpath)
        if base in ("specifications", "default") and "/specifications" in dirpath:  # RubyGems
            for fn in files:
                parsed = parse_gemspec_filename(fn)
                if parsed:
                    _add(result, "gem", _row(parsed[0], parsed[1], parsed[0], "gem", dirpath))
                    _add_library(result, "RubyGems", parsed[0], parsed[1], dirpath)
        if dirpath.endswith("vendor/composer") and "installed.json" in files:
            src = os.path.dirname(os.path.dirname(dirpath))
            for name, ver in parse_composer_installed(fs.read(_join(dirpath, "installed.json"))):
                _add(result, "composer", _row(name, ver, name.split("/")[-1], "composer", src))
                _add_library(result, "Packagist", name, ver, src)

        for fn in files:
            if fn.endswith((".jar", ".war")):
                _handle_jar(fs, result, dirpath, fn, opened)
                continue
            full = _join(dirpath, fn)
            probes = catalog.probes_for(full)
            text = fs.read(full) if probes else ""
            for probe in probes:
                ver = catalog.probe_version(probe, text)
                if ver:
                    _add(result, "app-probe", _row(probe.product.lower(), ver, probe.product, "app-probe",
                                                   full, cpe=probe.cpe))
                    if probe.osv:
                        _add_library(result, probe.osv[0], probe.osv[1], ver, full)
                    break


def collect(fs: Fs) -> EcosystemResult:
    result = EcosystemResult()
    for fn in (_collect_wordpress, _collect_composer, _collect_jars, _collect_npm, _collect_pip,
               _collect_everywhere):
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


def _jar_coords_linux(path: str) -> list[tuple[str, str, str]]:
    """Maven coordinates in a jar/war, including the jars it bundles under WEB-INF/lib or BOOT-INF/lib."""
    try:
        with zipfile.ZipFile(path) as zf:
            out = maven_coords(zf)
            for info in zf.infolist():
                if (info.filename.startswith(NESTED_LIB_DIRS) and info.filename.endswith(".jar")
                        and info.file_size <= MAX_NESTED_JAR_BYTES):
                    try:
                        with zipfile.ZipFile(io.BytesIO(zf.read(info))) as inner:
                            out.extend(maven_coords(inner))
                    except (zipfile.BadZipFile, OSError):
                        continue
            return out
    except (zipfile.BadZipFile, OSError):
        return []


def _jar_read_linux(path: str, member: str) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.read(member)[:100_000].decode("utf-8", "replace")
    except (KeyError, zipfile.BadZipFile, OSError):
        return ""


def linux_fs() -> Fs:
    return Fs(walk=_walk_linux, read=_read_linux, listdir=_listdir_linux,
              isdir=os.path.isdir, isfile=os.path.isfile, jar_coords=_jar_coords_linux,
              jar_read=_jar_read_linux)
