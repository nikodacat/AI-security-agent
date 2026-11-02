"""Catalog of common software the generic readers cannot name on their own.

Three readers already work without a list: Maven coordinates out of a jar's pom.properties,
Composer/npm/PyPI package names, and the OS package manager. They leave three gaps, and this
module is the (data-only) answer to each:

* FILE_PROBES   applications whose version lives only in their own source (Drupal, phpMyAdmin,
                MediaWiki, ...): a file path suffix and a regex that captures the version.
* JAR_CATALOG   Java services whose jars carry no pom.properties because they are built with
                Ant/Ivy (Elasticsearch, Solr, ...), recognised by jar file name.
* the binary --version table in unmanaged.py (daemons the package manager does not own).

Every entry gives the CPE (`vendor:product`, NVD's naming) so cve-matcher can ask NVD without
a translation table of its own; entries with a package-registry name also give the OSV
coordinates. Adding a product is adding a row; nothing here executes anything.

The version regexes are written from how each project lays out its release files. Those
marked UNVERIFIED have not been run against a real install here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FileProbe:
    product: str                 # display name, also the KEV product spelling
    suffix: str                  # file path ends with this (matched on whole path components)
    regex: str                   # group 1 = version
    cpe: str                     # "vendor:product"
    osv: tuple[str, str] | None = None   # (ecosystem, package name) when OSV knows it
    verified: bool = False       # run against a real install in this project


FILE_PROBES: tuple[FileProbe, ...] = (
    FileProbe("Drupal", "core/lib/Drupal.php", r"const\s+VERSION\s*=\s*'([^']+)'",
              "drupal:drupal", ("Packagist", "drupal/core")),
    FileProbe("phpMyAdmin", "libraries/classes/Config.php", r"'PMA_VERSION',\s*'([^']+)'",
              "phpmyadmin:phpmyadmin", ("Packagist", "phpmyadmin/phpmyadmin")),
    FileProbe("phpMyAdmin", "libraries/classes/Version.php", r"const\s+VERSION\s*=\s*'([^']+)'",
              "phpmyadmin:phpmyadmin", ("Packagist", "phpmyadmin/phpmyadmin")),
    FileProbe("phpMyAdmin", "libraries/Config.class.php", r"'PMA_VERSION',\s*'([^']+)'",
              "phpmyadmin:phpmyadmin", ("Packagist", "phpmyadmin/phpmyadmin")),
    FileProbe("MediaWiki", "includes/Defines.php", r"define\(\s*'MW_VERSION',\s*'([^']+)'",
              "mediawiki:mediawiki", ("Packagist", "mediawiki/core")),
    FileProbe("Moodle", "version.php", r"\$release\s*=\s*'(\d+\.\d+(?:\.\d+)?)",
              "moodle:moodle"),
    FileProbe("Roundcube", "program/include/iniset.php", r"define\('RCMAIL_VERSION',\s*'([^']+)'",
              "roundcube:webmail", ("Packagist", "roundcube/roundcubemail")),
    FileProbe("GitLab", "gitlab-rails/VERSION", r"^(\d+\.\d+\.\d+)", "gitlab:gitlab"),
    FileProbe("Zabbix", "include/defines.inc.php", r"define\('ZABBIX_VERSION',\s*'([^']+)'",
              "zabbix:zabbix"),
    FileProbe("Nextcloud", "version.php", r"\$OC_VersionString\s*=\s*'([^']+)'",
              "nextcloud:nextcloud"),
    # Several capture groups are joined with "." (Joomla keeps release, patch level apart).
    FileProbe("Joomla", "libraries/cms/version/version.php",
              r"\$RELEASE\s*=\s*'(\d+\.\d+)';[\s\S]*?\$DEV_LEVEL\s*=\s*'(\d+)'",
              r"joomla:joomla\!", verified=True),
    FileProbe("Joomla", "libraries/src/Version.php",
              r"MAJOR_VERSION\s*=\s*(\d+);[\s\S]*?MINOR_VERSION\s*=\s*(\d+);[\s\S]*?PATCH_VERSION\s*=\s*(\d+)",
              r"joomla:joomla\!"),
    FileProbe("Kibana", "kibana/package.json", r'"name"\s*:\s*"kibana"[\s\S]*?"version"\s*:\s*"(\d[^"]*)"',
              "elastic:kibana"),
    FileProbe("Grafana", "grafana/VERSION", r"^(\d+\.\d+\.\d+)", "grafana:grafana", verified=True),
)


@dataclass(frozen=True)
class JarEntry:
    product: str                 # display name
    pattern: str                 # regex on the jar's artifact name (the part before the version)
    cpe: str                     # "vendor:product"


JAR_CATALOG: tuple[JarEntry, ...] = (
    JarEntry("Elasticsearch", r"elasticsearch", "elastic:elasticsearch"),
    JarEntry("Solr", r"solr-core", "apache:solr"),
    JarEntry("ActiveMQ", r"activemq-(?:all|broker)", "apache:activemq"),
    JarEntry("RocketMQ", r"rocketmq-(?:broker|common)", "apache:rocketmq"),
    JarEntry("Kafka", r"kafka(?:_[\d.]+|-clients)", "apache:kafka"),
    JarEntry("ZooKeeper", r"zookeeper", "apache:zookeeper"),
    JarEntry("Hadoop", r"hadoop-common", "apache:hadoop"),
    JarEntry("Spark", r"spark-core(?:_[\d.]+)?", "apache:spark"),
    JarEntry("Cassandra", r"apache-cassandra|cassandra-all", "apache:cassandra"),
    JarEntry("Flink", r"flink-dist(?:_[\d.]+)?", "apache:flink"),
    JarEntry("NiFi", r"nifi-api", "apache:nifi"),
    JarEntry("Ignite", r"ignite-core", "apache:ignite"),
    JarEntry("HBase", r"hbase-server", "apache:hbase"),
    JarEntry("Hive", r"hive-exec", "apache:hive"),
    JarEntry("Druid", r"druid-(?:core|server)", "apache:druid"),
    JarEntry("Dubbo", r"dubbo", "apache:dubbo"),
    JarEntry("Groovy", r"groovy(?:-all)?", "apache:groovy"),
    JarEntry("Shiro", r"shiro-core", "apache:shiro"),
    JarEntry("Jetty", r"jetty-server", "eclipse:jetty"),
    JarEntry("Undertow", r"undertow-core", "redhat:undertow"),
    JarEntry("Keycloak", r"keycloak-(?:core|services)", "redhat:keycloak"),
    JarEntry("Hazelcast", r"hazelcast", "hazelcast:hazelcast"),
    JarEntry("Jenkins", r"jenkins-core", "jenkins:jenkins"),
)

_JAR_CATALOG_RE = tuple((e, re.compile(rf"^(?:{e.pattern})$")) for e in JAR_CATALOG)


def jar_entry(artifact: str) -> JarEntry | None:
    """Catalog entry for a jar artifact name (e.g. 'elasticsearch', 'kafka_2.12'), or None."""
    for entry, rx in _JAR_CATALOG_RE:
        if rx.match(artifact):
            return entry
    return None


def probes_for(path: str) -> list[FileProbe]:
    """Every FILE_PROBE whose suffix matches `path` on whole path components, most specific
    (longest suffix) first. A generic name such as version.php belongs to several products,
    so the caller tries each until one finds a version in the file."""
    hits = [p for p in FILE_PROBES if path == p.suffix or path.endswith("/" + p.suffix)]
    return sorted(hits, key=lambda p: -len(p.suffix))


def probe_for(path: str) -> FileProbe | None:
    """The most specific FILE_PROBE for `path`, or None."""
    hits = probes_for(path)
    return hits[0] if hits else None


def probe_version(probe: FileProbe, text: str) -> str:
    m = re.search(probe.regex, text or "", re.MULTILINE)
    return ".".join(g for g in m.groups() if g) if m else ""


# --- Maven repository layout --------------------------------------------------------------


def maven_layout_coords(path: str) -> tuple[str, str, str] | None:
    """(group, artifact, version) from a jar's place in a Maven/Karaf/Gradle repository tree.

    <repo>/org/jboss/spec/foo/1.0/foo-1.0.jar : the directories name the coordinates. The
    repository root is found by its conventional name ("repository" for ~/.m2, "system" for
    Karaf/Nexus); Gradle's cache keeps the group as a single directory under files-2.1.
    """
    parts = [p for p in path.split("/") if p]
    if len(parts) < 4 or not parts[-1].endswith(".jar"):
        return None
    if "files-2.1" in parts:
        i = parts.index("files-2.1")
        if len(parts) >= i + 5:
            return parts[i + 1], parts[i + 2], parts[i + 3]
        return None
    artifact, version = parts[-3], parts[-2]
    if not parts[-1].startswith(f"{artifact}-{version}"):
        return None
    for marker in ("repository", "system"):
        if marker in parts[:-3]:
            i = len(parts) - 4 - parts[:-3][::-1].index(marker)
            group = ".".join(parts[i + 1:-3])
            if group:
                return group, artifact, version
    return None
