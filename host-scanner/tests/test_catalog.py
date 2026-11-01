"""Catalog entries, the Maven-layout reader, and the whole-filesystem pass (fake filesystem)."""

from __future__ import annotations

import json
import re
import unittest

from scanners import catalog, unmanaged
from scanners import ecosystems as eco

from test_ecosystems import _fake_fs


class CatalogReaders(unittest.TestCase):
    def test_every_probe_regex_compiles_and_has_one_group(self):
        for p in catalog.FILE_PROBES:
            self.assertEqual(re.compile(p.regex).groups, 1, p.product)
            self.assertEqual(p.cpe.count(":"), 1, p.product)

    def test_drupal_and_phpmyadmin_version_files(self):
        drupal = catalog.probe_for("/var/www/html/core/lib/Drupal.php")
        self.assertEqual(catalog.probe_version(drupal, "  const VERSION = '8.5.0';\n"), "8.5.0")
        pma = catalog.probe_for("/var/www/html/libraries/classes/Config.php")
        self.assertEqual(catalog.probe_version(pma, "$this->set('PMA_VERSION', '4.8.1');"), "4.8.1")

    def test_suffix_matches_whole_path_components_only(self):
        self.assertIsNone(catalog.probe_for("/x/notcore/lib/Drupal.php"))
        self.assertIsNotNone(catalog.probe_for("core/lib/Drupal.php"))

    def test_jar_catalog_names_jars_that_have_no_pom_properties(self):
        self.assertEqual(catalog.jar_entry("elasticsearch").cpe, "elastic:elasticsearch")
        self.assertEqual(catalog.jar_entry("kafka_2.12").cpe, "apache:kafka")
        self.assertIsNone(catalog.jar_entry("guava"))
        self.assertIsNone(catalog.jar_entry("elasticsearch-extra"))  # whole-name match, not prefix

    def test_maven_layout_in_a_karaf_system_directory(self):
        p = "/opt/sonatype/nexus/system/org/jboss/spec/jboss-annotations-api_1.2_spec/1.0.0.Final/jboss-annotations-api_1.2_spec-1.0.0.Final.jar"
        self.assertEqual(catalog.maven_layout_coords(p),
                         ("org.jboss.spec", "jboss-annotations-api_1.2_spec", "1.0.0.Final"))

    def test_maven_layout_in_a_local_repository_and_gradle_cache(self):
        self.assertEqual(
            catalog.maven_layout_coords("/root/.m2/repository/org/apache/struts/struts2-core/2.3.30/struts2-core-2.3.30.jar"),
            ("org.apache.struts", "struts2-core", "2.3.30"))
        self.assertEqual(
            catalog.maven_layout_coords("/root/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/30.0/abc123/guava-30.0.jar"),
            ("com.google.guava", "guava", "30.0"))

    def test_layout_is_not_guessed_without_a_repository_root_or_matching_file_name(self):
        self.assertIsNone(catalog.maven_layout_coords("/opt/app/lib/foo/1.0/foo-1.0.jar"))
        self.assertIsNone(catalog.maven_layout_coords("/r/repository/org/x/foo/1.0/other-1.0.jar"))


class WholeFilesystemPass(unittest.TestCase):
    def test_app_installed_at_the_filesystem_root_is_found(self):
        fs = _fake_fs({"/ofbiz/framework/lib/foo-1.0.jar": ""})
        fs.jar_coords = lambda p: [("org.example", "foo", "1.0")] if p.endswith("foo-1.0.jar") else []
        libs = eco.collect(fs).libraries
        self.assertIn({"ecosystem": "Maven", "name": "org.example:foo", "version": "1.0",
                       "path": "/ofbiz/framework/lib/foo-1.0.jar"}, libs)

    def test_top_level_node_modules_at_root_including_scoped_packages(self):
        fs = _fake_fs({
            "/node_modules/mongo-express/package.json": '{"name":"mongo-express","version":"0.53.0"}',
            "/node_modules/@types/node/package.json": '{"name":"@types/node","version":"12.0.0"}',
            "/node_modules/mongo-express/node_modules/inner/package.json": '{"name":"inner","version":"1.0.0"}',
        })
        got = {(l["name"], l["version"]) for l in eco.collect(fs).libraries if l["ecosystem"] == "npm"}
        self.assertEqual(got, {("mongo-express", "0.53.0"), ("@types/node", "12.0.0")})

    def test_version_file_of_a_known_application_becomes_an_app_row_and_a_library(self):
        fs = _fake_fs({"/srv/site/core/lib/Drupal.php": "const VERSION = '8.5.0';"})
        r = eco.collect(fs)
        row = next(a for a in r.apps if a["Source"] == "app-probe")
        self.assertEqual((row["Product"], row["DisplayVersion"], row["Cpe"]), ("Drupal", "8.5.0", "drupal:drupal"))
        self.assertIn(("Packagist", "drupal/core", "8.5.0"),
                      {(l["ecosystem"], l["name"], l["version"]) for l in r.libraries})

    def test_a_file_that_does_not_contain_a_version_adds_nothing(self):
        r = eco.collect(_fake_fs({"/srv/site/version.php": "<?php // not moodle"}))
        self.assertEqual([a for a in r.apps if a["Source"] == "app-probe"], [])

    def test_catalogued_jar_gets_a_cpe_from_its_file_name(self):
        r = eco.collect(_fake_fs({"/usr/share/elasticsearch/lib/elasticsearch-1.4.2.jar": ""}))
        row = next(a for a in r.apps if a["DisplayName"] == "elasticsearch")
        self.assertEqual((row["DisplayVersion"], row["Product"], row["Cpe"]),
                         ("1.4.2", "Elasticsearch", "elastic:elasticsearch"))

    def test_jar_already_in_the_kev_table_is_not_added_twice(self):
        r = eco.collect(_fake_fs({"/opt/a/lib/log4j-core-2.14.1.jar": ""}))
        self.assertEqual(len([a for a in r.apps if a["DisplayName"] == "log4j-core"]), 1)

    def test_tomcat_version_is_read_from_catalina_jar_not_its_name(self):
        fs = _fake_fs({"/usr/local/tomcat/lib/catalina.jar": ""})
        fs.jar_read = lambda p, m: "server.info=Apache Tomcat/9.0.30\nserver.number=9.0.30.0\n"
        row = next(a for a in eco.collect(fs).apps if a["DisplayName"] == "tomcat")
        self.assertEqual((row["DisplayVersion"], row["Cpe"]), ("9.0.30", "apache:tomcat"))

    def test_jar_without_pom_properties_is_named_by_its_repository_layout(self):
        p = "/opt/nexus/system/org/foo/bar/1.2/bar-1.2.jar"
        libs = eco.collect(_fake_fs({p: ""})).libraries
        self.assertIn(("Maven", "org.foo:bar", "1.2"), {(l["ecosystem"], l["name"], l["version"]) for l in libs})

    def test_jdk_and_virtual_filesystems_are_not_walked(self):
        fs = _fake_fs({"/usr/lib/jvm/java-8/lib/tools.jar": "", "/opt/app/lib/x-1.0.jar": ""})
        fs.jar_coords = lambda p: [("g", "a", "1")]
        # the fake walk ignores pruning, so check the pruning rules themselves
        self.assertTrue("jvm" in eco._PRUNE_NAMES and "openjdk-8".startswith(eco._JDK_PREFIXES))
        self.assertEqual(eco._PRUNE_AT_ROOT, {"proc", "sys", "dev", "run"})

    def test_walk_is_bounded(self):
        fs = _fake_fs({"/opt/a/x.txt": ""})
        calls = []

        def endless(root, depth):
            for i in range(eco.MAX_WALK_DIRS + 10):
                calls.append(i)
                yield (f"/d{i}", [], [])

        fs.walk = endless
        r = eco.EcosystemResult()
        eco._collect_everywhere(fs, r)
        self.assertLessEqual(len(calls), eco.MAX_WALK_DIRS + 2)
        self.assertTrue(any("stopped after" in n for n in r.notes))


class BinaryCatalog(unittest.TestCase):
    # Samples are real output captured from the binaries named, except where marked.
    SAMPLES = {
        "samba": "Version 4.6.3\n",
        "postgresql": "postgres (PostgreSQL) 13.23\n",
        "mongodb": "db version v3.4.24\ngit version: abc\n",
        "redis": "Redis server v=5.0.14 sha=00000000:0 malloc=jemalloc-5.1.0 bits=64 build=x\n",
        "nodejs": "v12.14.0\n",
        "nginx": "nginx version: nginx/1.13.2\n",
    }

    def test_each_spec_has_a_cpe_and_a_compiling_regex(self):
        for s in unmanaged.SPECS:
            self.assertEqual(s.cpe.count(":"), 1, s.key)
            self.assertEqual(re.compile(s.version_regex).groups, 1, s.key)

    def test_versions_parse_from_real_output(self):
        by_key = {s.key: s for s in unmanaged.SPECS}
        want = {"samba": "4.6.3", "postgresql": "13.23", "mongodb": "3.4.24", "redis": "5.0.14",
                "nodejs": "12.14.0", "nginx": "1.13.2"}
        for key, version in want.items():
            self.assertEqual(unmanaged.parse_version(by_key[key], self.SAMPLES[key]), version, key)

    def test_binary_names_do_not_collide_between_specs(self):
        names = [b for s in unmanaged.SPECS for b in s.binaries]
        self.assertEqual(len(names), len(set(names)))

    def test_installed_app_row_carries_the_cpe(self):
        res = unmanaged.UnmanagedResult(binaries=[{
            "name": "samba", "product": "Samba", "cpe": "samba:samba", "version": "4.6.3",
            "path": "/usr/local/samba/sbin/smbd", "running": True, "pids": [1], "managed_by_package": False}])
        self.assertEqual(unmanaged.to_installed_apps(res)[0]["Cpe"], "samba:samba")


if __name__ == "__main__":
    unittest.main()
