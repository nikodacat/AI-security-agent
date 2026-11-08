"""Tests for application-layer inventory (fake filesystem; runs on any OS)."""

from __future__ import annotations

import json
import unittest

from scanners import ecosystems as eco
from scanners.ecosystems import Fs

WP_VERSION_PHP = "<?php\n$wp_version = '5.7';\n$wp_db_version = 49752;\n"
PLUGIN = """<?php
/**
 * Plugin Name: Contact Form 7
 * Version: 5.3.1
 * Author: Takayuki Miyoshi
 */
"""
THEME = "/*\nTheme Name: Twenty Twenty-One\nVersion: 1.2\nAuthor: the WordPress team\n*/"


def _fake_fs(files: dict[str, str]) -> Fs:
    dirs: dict[str, set[str]] = {}
    for path in files:
        parts = path.strip("/").split("/")
        for i in range(len(parts)):
            parent = "/" + "/".join(parts[:i])
            dirs.setdefault(parent if parent != "/" else "/", set()).add(parts[i])
    all_dirs = {d for d in dirs}

    def walk(root, max_depth):
        out = []
        for d in sorted(all_dirs):
            if d == root or d.startswith(root.rstrip("/") + "/"):
                names = dirs[d]
                subdirs = sorted(n for n in names if (d.rstrip("/") + "/" + n) in all_dirs)
                filenames = sorted(n for n in names if (d.rstrip("/") + "/" + n) in files)
                out.append((d, subdirs, filenames))
        return out

    return Fs(
        walk=walk,
        read=lambda p: files.get(p, ""),
        listdir=lambda p: sorted(dirs.get(p, [])),
        isdir=lambda p: p in all_dirs,
        isfile=lambda p: p in files,
    )


class TestParsers(unittest.TestCase):
    def test_wp_core_version(self):
        self.assertEqual(eco.parse_wp_core_version(WP_VERSION_PHP), "5.7")
        self.assertEqual(eco.parse_wp_core_version("nothing"), "")

    def test_wp_header(self):
        h = eco.parse_wp_header(PLUGIN)
        self.assertEqual((h["name"], h["version"], h["author"]), ("Contact Form 7", "5.3.1", "Takayuki Miyoshi"))
        self.assertEqual(eco.parse_wp_header(THEME)["name"], "Twenty Twenty-One")

    def test_composer_v2_and_v1_layouts(self):
        v2 = json.dumps({"packages": [{"name": "phpunit/phpunit", "version": "v5.6.2"}]})
        v1 = json.dumps([{"name": "phpmailer/phpmailer", "version": "5.2.16"}])
        self.assertEqual(eco.parse_composer_installed(v2), [("phpunit/phpunit", "5.6.2")])
        self.assertEqual(eco.parse_composer_installed(v1), [("phpmailer/phpmailer", "5.2.16")])
        self.assertEqual(eco.parse_composer_installed("not json"), [])

    def test_jar_names(self):
        self.assertEqual(eco.parse_jar_name("log4j-core-2.14.1.jar"), ("log4j-core", "2.14.1"))
        self.assertEqual(eco.parse_jar_name("spring-core-5.3.17.RELEASE.jar"), ("spring-core", "5.3.17.RELEASE"))
        self.assertIsNone(eco.parse_jar_name("app.jar"))

    def test_dist_info_and_package_json(self):
        self.assertEqual(eco.parse_dist_info("Django-3.2.4.dist-info"), ("Django", "3.2.4"))
        self.assertEqual(eco.parse_dist_info("typing_extensions-4.0.0.dist-info"), ("typing-extensions", "4.0.0"))
        self.assertEqual(eco.parse_package_json('{"name":"lodash","version":"4.17.20"}'), ("lodash", "4.17.20"))
        self.assertIsNone(eco.parse_package_json('{"name":"x"}'))


class TestCollect(unittest.TestCase):
    def test_wordpress_core_plugin_theme(self):
        wp = "/var/www/html"
        fs = _fake_fs({
            f"{wp}/wp-includes/version.php": WP_VERSION_PHP,
            f"{wp}/wp-content/plugins/contact-form-7/contact-form-7.php": PLUGIN,
            f"{wp}/wp-content/themes/twentytwentyone/style.css": THEME,
        })
        r = eco.collect(fs)
        by_src = {a["Source"]: a for a in r.apps}
        core = by_src["wordpress-core"]
        self.assertEqual((core["DisplayVersion"], core["Publisher"], core["Product"]), ("5.7", "WordPress", "Core"))
        self.assertEqual(by_src["wordpress-plugin"]["DisplayVersion"], "5.3.1")
        self.assertEqual(by_src["wordpress-plugin"]["Product"], "Contact Form 7")
        self.assertEqual(by_src["wordpress-theme"]["DisplayVersion"], "1.2")

    def test_composer_products_use_last_segment_for_product_only_matching(self):
        fs = _fake_fs({"/var/www/app/vendor/composer/installed.json": json.dumps(
            {"packages": [{"name": "phpmailer/phpmailer", "version": "5.2.16"}]})})
        r = eco.collect(fs)
        self.assertEqual((r.apps[0]["Product"], r.apps[0]["Publisher"]), ("phpmailer", ""))

    def test_only_mappable_jars_are_reported(self):
        fs = _fake_fs({"/opt/app/lib/log4j-core-2.14.1.jar": "", "/opt/app/lib/guava-30.0.jar": ""})
        r = eco.collect(fs)
        self.assertEqual([(a["DisplayName"], a["Product"]) for a in r.apps], [("log4j-core", "Log4j2")])

    def test_jar_in_root_maven_repository_is_found(self):
        # Vulhub's Struts2 image runs from here; the path is too deep to reach from /root.
        path = "/root/.m2/repository/org/apache/struts/struts2-core/2.3.30/struts2-core-2.3.30.jar"
        r = eco.collect(_fake_fs({path: ""}))
        self.assertEqual([(a["DisplayName"], a["DisplayVersion"], a["Product"]) for a in r.apps],
                         [("struts2-core", "2.3.30", "Struts")])

    def test_duplicate_jar_reported_once(self):
        fs = _fake_fs({"/opt/a/lib/log4j-core-2.14.1.jar": "", "/opt/b/lib/log4j-core-2.14.1.jar": ""})
        self.assertEqual(len(eco.collect(fs).apps), 1)

    def test_npm_top_level_only(self):
        fs = _fake_fs({
            "/var/www/app/node_modules/lodash/package.json": '{"name":"lodash","version":"4.17.20"}',
            "/var/www/app/node_modules/lodash/node_modules/inner/package.json": '{"name":"inner","version":"1.0.0"}',
        })
        names = [a["DisplayName"] for a in eco.collect(fs).apps if a["Source"] == "npm"]
        self.assertEqual(names, ["lodash"])

    def test_pip_only_site_packages_under_usr_local(self):
        fs = _fake_fs({"/usr/local/lib/python3.9/site-packages/Django-3.2.4.dist-info/METADATA": "x"})
        apps = [a for a in eco.collect(fs).apps if a["Source"] == "pip"]
        self.assertEqual([(a["DisplayName"], a["DisplayVersion"]) for a in apps], [("Django", "3.2.4")])

    def test_same_package_at_two_paths_is_reported_once_with_other_paths(self):
        fs = _fake_fs({
            "/usr/src/wordpress/wp-includes/version.php": WP_VERSION_PHP,
            "/var/www/html/wp-includes/version.php": WP_VERSION_PHP,
        })
        apps = [a for a in eco.collect(fs).apps if a["Source"] == "wordpress-core"]
        self.assertEqual(len(apps), 1)
        self.assertEqual(len(apps[0]["OtherPaths"]), 1)

    def test_cap_per_ecosystem(self):
        files = {f"/opt/app/lib/log4j-core-2.{i}.0.jar": "" for i in range(eco.MAX_PER_ECOSYSTEM + 20)}
        r = eco.collect(_fake_fs(files))
        self.assertEqual(sum(1 for a in r.apps if a["Source"] == "jar"), eco.MAX_PER_ECOSYSTEM)
        self.assertTrue(any("truncated" in n for n in r.notes))

    def test_pom_properties_parser(self):
        body = "#Generated\ngroupId=org.apache.shiro\nartifactId=shiro-core\nversion=1.2.4\n"
        self.assertEqual(eco.parse_pom_properties(body), ("org.apache.shiro", "shiro-core", "1.2.4"))
        self.assertIsNone(eco.parse_pom_properties("groupId=x\nartifactId=y\n"))

    def test_maven_coords_from_a_jar_and_from_jars_it_bundles(self):
        import io
        import os
        import tempfile
        import zipfile

        def jar(coords, extra=None):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for g, a, v in coords:
                    z.writestr(f"META-INF/maven/{g}/{a}/pom.properties", f"groupId={g}\nartifactId={a}\nversion={v}\n")
                for name, data in (extra or {}).items():
                    z.writestr(name, data)
            return buf.getvalue()

        inner = jar([("org.apache.shiro", "shiro-core", "1.2.4")])
        fat = jar([("com.example", "demo", "1.0")], {"BOOT-INF/lib/shiro-core-1.2.4.jar": inner,
                                                      "BOOT-INF/lib/not-a-jar.jar": b"garbage"})
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "demo.jar")
            with open(path, "wb") as fh:
                fh.write(fat)
            self.assertEqual(sorted(eco._jar_coords_linux(path)),
                             [("com.example", "demo", "1.0"), ("org.apache.shiro", "shiro-core", "1.2.4")])
            self.assertEqual(eco._jar_coords_linux(os.path.join(d, "missing.jar")), [])

    def test_every_jar_with_coordinates_becomes_a_library_even_when_not_a_kev_product(self):
        fs = _fake_fs({"/opt/app/lib/guava-30.0.jar": ""})
        fs.jar_coords = lambda p: [("com.google.guava", "guava", "30.0")]
        r = eco.collect(fs)
        self.assertEqual(r.apps, [])  # not mappable to a KEV product, so not an installed app
        self.assertEqual(r.libraries, [{"ecosystem": "Maven", "name": "com.google.guava:guava",
                                        "version": "30.0", "path": "/opt/app/lib/guava-30.0.jar"}])

    def test_composer_npm_pip_are_libraries_in_their_own_ecosystem_names(self):
        fs = _fake_fs({
            "/var/www/app/vendor/composer/installed.json": json.dumps(
                {"packages": [{"name": "drupal/core", "version": "8.5.0"}]}),
            "/var/www/app/node_modules/lodash/package.json": '{"name":"lodash","version":"4.17.20"}',
            "/usr/local/lib/python3.9/site-packages/Django-3.2.4.dist-info/METADATA": "x",
        })
        got = {(l["ecosystem"], l["name"], l["version"]) for l in eco.collect(fs).libraries}
        self.assertEqual(got, {("Packagist", "drupal/core", "8.5.0"), ("npm", "lodash", "4.17.20"),
                               ("PyPI", "Django", "3.2.4")})

    def test_library_list_is_capped(self):
        fs = _fake_fs({"/opt/app/lib/a.jar": ""})
        fs.jar_coords = lambda p: [("g", f"a{i}", "1.0") for i in range(eco.MAX_LIBRARIES + 5)]
        r = eco.collect(fs)
        self.assertEqual(len(r.libraries), eco.MAX_LIBRARIES)
        self.assertIn("libraries truncated", r.notes)

    def test_one_failing_collector_does_not_hide_others(self):
        fs = _fake_fs({"/opt/app/lib/log4j-core-2.14.1.jar": ""})
        real_walk = fs.walk

        def boom_for_var_www(root, depth):
            if root == "/var/www":
                raise OSError("denied")
            return real_walk(root, depth)

        fs.walk = boom_for_var_www
        r = eco.collect(fs)
        self.assertTrue(any("failed" in n for n in r.notes))
        self.assertTrue(any(a["Source"] == "jar" for a in r.apps))


if __name__ == "__main__":
    unittest.main()
