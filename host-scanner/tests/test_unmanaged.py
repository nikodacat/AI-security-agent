"""Tests for unmanaged-software discovery (probes are faked; runs on any OS)."""

from __future__ import annotations

import stat
import unittest

from scanners import unmanaged as um
from scanners.unmanaged import Probes, parse_version


def _probes(*, binaries=(), owners=None, running=None, outputs=None, modes=None):
    owners = owners or {}
    outputs = outputs or {}
    modes = modes or {}
    ran: list[str] = []

    def run_version(path, args):
        ran.append(path)
        return outputs.get(path, "")

    p = Probes(
        find_binaries=lambda: list(binaries),
        mode_of=lambda path: modes.get(path, 0o755),
        run_version=run_version,
        owner_of=lambda path: owners.get(path),
        running_exes=lambda: dict(running or {}),
        realpath=lambda path: path,
    )
    p.ran = ran  # type: ignore[attr-defined]
    return p


PHP_OUT = "PHP 7.4.21 (cli) (built: Jul  1 2021 19:26:44) ( NTS )\nCopyright (c) The PHP Group"


class TestParseVersion(unittest.TestCase):
    def test_php(self):
        self.assertEqual(parse_version(um.SPECS[0], PHP_OUT), "7.4.21")

    def test_apache_from_stderr_style_output(self):
        spec = next(s for s in um.SPECS if s.key == "apache-httpd")
        self.assertEqual(parse_version(spec, "Server version: Apache/2.4.49 (Unix)\nServer built: x"), "2.4.49")

    def test_nginx(self):
        spec = next(s for s in um.SPECS if s.key == "nginx")
        self.assertEqual(parse_version(spec, "nginx version: nginx/1.18.0"), "1.18.0")

    def test_redis(self):
        spec = next(s for s in um.SPECS if s.key == "redis")
        self.assertEqual(parse_version(spec, "Redis server v=6.2.6 sha=00000000:0 malloc=jemalloc-5.1.0"), "6.2.6")

    def test_openssl_letter_suffix(self):
        spec = next(s for s in um.SPECS if s.key == "openssl")
        self.assertEqual(parse_version(spec, "OpenSSL 1.1.1k  25 Mar 2021"), "1.1.1k")

    def test_garbage_gives_empty(self):
        self.assertEqual(parse_version(um.SPECS[0], "bash: php: command not found"), "")
        self.assertEqual(parse_version(um.SPECS[0], ""), "")


class TestUnsafe(unittest.TestCase):
    def test_tmp_paths(self):
        for p in ("/tmp/php", "/dev/shm/x/php", "/var/tmp/nginx"):
            self.assertTrue(um.is_unsafe_to_execute(p))
        self.assertFalse(um.is_unsafe_to_execute("/usr/local/bin/php", 0o755))

    def test_world_writable(self):
        self.assertTrue(um.is_unsafe_to_execute("/usr/local/bin/php", 0o777))
        self.assertTrue(um.is_unsafe_to_execute("/opt/x/php", 0o755 | stat.S_IWOTH))


class TestCollect(unittest.TestCase):
    def test_unmanaged_php_identified_with_version_and_running(self):
        path = "/usr/local/bin/php"
        p = _probes(binaries=[path], outputs={path: PHP_OUT}, running={path: [12]})
        r = um.collect(p)
        self.assertEqual(len(r.binaries), 1)
        b = r.binaries[0]
        self.assertEqual((b["name"], b["version"], b["product"]), ("php", "7.4.21", "PHP"))
        self.assertTrue(b["running"])
        self.assertEqual(b["pids"], [12])

    def test_package_owned_binary_is_skipped_and_never_executed(self):
        path = "/usr/local/bin/php"
        p = _probes(binaries=[path], owners={path: "php7.4-cli"}, outputs={path: PHP_OUT})
        r = um.collect(p)
        self.assertEqual(r.binaries, [])
        self.assertEqual(p.ran, [])

    def test_name_not_on_allowlist_is_never_executed(self):
        p = _probes(binaries=["/usr/local/bin/evil", "/opt/x/payload"], outputs={})
        r = um.collect(p)
        self.assertEqual(r.binaries, [])
        self.assertEqual(p.ran, [])

    def test_unsafe_location_not_executed_but_noted(self):
        path = "/tmp/php"
        p = _probes(binaries=[path], outputs={path: PHP_OUT})
        r = um.collect(p)
        self.assertEqual(p.ran, [])
        self.assertEqual(r.binaries[0]["version"], "")
        self.assertTrue(any("not executed" in n for n in r.notes))

    def test_world_writable_mode_not_executed(self):
        path = "/opt/php/bin/php"
        p = _probes(binaries=[path], outputs={path: PHP_OUT}, modes={path: 0o777})
        r = um.collect(p)
        self.assertEqual(p.ran, [])
        self.assertEqual(r.binaries[0]["version"], "")

    def test_same_real_binary_via_two_links_reported_once(self):
        p = Probes(
            find_binaries=lambda: ["/usr/local/bin/php", "/usr/local/bin/php-cgi"],
            mode_of=lambda _p: 0o755, run_version=lambda _p, _a: PHP_OUT,
            owner_of=lambda _p: None, running_exes=lambda: {},
            realpath=lambda _p: "/usr/local/bin/php",
        )
        self.assertEqual(len(um.collect(p).binaries), 1)

    def test_unreadable_version_noted(self):
        path = "/usr/local/bin/nginx"
        p = _probes(binaries=[path], outputs={path: "permission denied"})
        r = um.collect(p)
        self.assertEqual(r.binaries[0]["version"], "")
        self.assertTrue(any("version not readable" in n for n in r.notes))

    def test_running_unowned_unidentified_binary_reported(self):
        p = _probes(running={"/usr/local/bin/mystery": [7], "/usr/sbin/sshd": [3]},
                    owners={"/usr/sbin/sshd": "openssh-server"})
        r = um.collect(p)
        self.assertEqual([x["path"] for x in r.running_unmanaged], ["/usr/local/bin/mystery"])

    def test_running_unmanaged_is_capped(self):
        running = {f"/opt/app/bin{i}": [i] for i in range(um.MAX_UNMANAGED_RUNNING + 10)}
        r = um.collect(_probes(running=running))
        self.assertEqual(len(r.running_unmanaged), um.MAX_UNMANAGED_RUNNING)
        self.assertTrue(any("truncated" in n for n in r.notes))


class TestToInstalledApps(unittest.TestCase):
    def test_versioned_binary_becomes_app_row_for_kev_matching(self):
        path = "/usr/local/bin/php"
        r = um.collect(_probes(binaries=[path], outputs={path: PHP_OUT}))
        apps = um.to_installed_apps(r)
        self.assertEqual(apps[0]["DisplayName"], "php")
        self.assertEqual(apps[0]["DisplayVersion"], "7.4.21")
        self.assertEqual(apps[0]["Product"], "PHP")
        self.assertEqual(apps[0]["Source"], "unmanaged-binary")
        self.assertEqual(apps[0]["Publisher"], "")

    def test_versionless_binary_is_dropped(self):
        path = "/tmp/php"
        r = um.collect(_probes(binaries=[path]))
        self.assertEqual(um.to_installed_apps(r), [])


if __name__ == "__main__":
    unittest.main()
