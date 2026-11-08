"""Tests for filesystem exposure findings (fake filesystem; runs on any OS)."""

from __future__ import annotations

import stat
import unittest

from scanners import leaks as lk
from scanners.leaks import LeakHost

from test_ecosystems import _fake_fs

REG = stat.S_IFREG
DIR = stat.S_IFDIR


def _host(files: dict, stats: dict | None = None, xattrs: dict | None = None) -> LeakHost:
    """files: path->content; stats: path->mode (default regular 0644, dirs default 0755)."""
    stats = stats or {}
    xattrs = xattrs or {}
    fs = _fake_fs(files)

    def st(path):
        if path in stats:
            return stats[path], len(files.get(path, "")), False
        if path in files:
            return REG | 0o644, len(files[path]), False
        if fs.isdir(path):
            return DIR | 0o755, 0, False
        return None

    return LeakHost(fs=fs, stat=st, getxattr=lambda p, n: xattrs.get(p))


def _ids(result) -> list[str]:
    return [f["id"] for f in result["findings"]]


class TestSuid(unittest.TestCase):
    def test_standard_suid_is_counted_not_flagged(self):
        r = lk.collect(_host({"/usr/bin/passwd": "x"}, {"/usr/bin/passwd": REG | stat.S_ISUID | 0o755}))
        self.assertEqual(_ids(r), [])
        self.assertEqual(r["suid_baseline_binaries"], 1)

    def test_suid_outside_system_dirs_is_high(self):
        r = lk.collect(_host({"/opt/tool/helper": "x"}, {"/opt/tool/helper": REG | stat.S_ISUID | 0o755}))
        self.assertEqual(r["findings"][0]["id"], "suid-unusual-location")
        self.assertEqual(r["findings"][0]["severity"], "high")

    def test_unknown_suid_in_system_dir_is_medium(self):
        r = lk.collect(_host({"/usr/bin/weird": "x"}, {"/usr/bin/weird": REG | stat.S_ISGID | 0o755}))
        self.assertEqual((r["findings"][0]["id"], r["findings"][0]["severity"]),
                         ("suid-unknown-binary", "medium"))

    def test_symlinks_ignored(self):
        host = _host({"/usr/local/bin/x": "x"})
        host.stat = lambda p: (REG | stat.S_ISUID | 0o755, 1, True) if p.endswith("/x") else None
        self.assertEqual(lk.collect(host)["findings"], [])


class TestCaps(unittest.TestCase):
    def test_decode(self):
        blob = bytes([1, 0, 0, 0]) + (1 << 7).to_bytes(4, "little") + bytes(4)  # cap_setuid
        self.assertEqual(lk.decode_caps(blob), ["cap_setuid"])
        self.assertEqual(lk.decode_caps(None), [])
        self.assertEqual(lk.decode_caps(b"short"), [])

    def test_capability_finding(self):
        blob = bytes([1, 0, 0, 0]) + (1 << 21).to_bytes(4, "little") + bytes(4)  # cap_sys_admin
        r = lk.collect(_host({"/usr/local/bin/tool": "x"}, xattrs={"/usr/local/bin/tool": blob}))
        self.assertEqual(_ids(r), ["file-capabilities"])
        self.assertIn("cap_sys_admin", r["findings"][0]["evidence"])


class TestWorldWritable(unittest.TestCase):
    def test_world_writable_file_in_etc(self):
        r = lk.collect(_host({"/etc/cron.d/job": "x"}, {"/etc/cron.d/job": REG | 0o666}))
        self.assertEqual(_ids(r), ["world-writable-sensitive"])

    def test_sticky_world_writable_dir_is_fine(self):
        r = lk.collect(_host({"/etc/tmpdir/f": "x"}, {"/etc/tmpdir": DIR | 0o777 | stat.S_ISVTX}))
        self.assertEqual(_ids(r), [])

    def test_normal_files_are_fine(self):
        self.assertEqual(lk.collect(_host({"/etc/hosts": "x"}))["findings"], [])


class TestLeaks(unittest.TestCase):
    def _ids_for(self, files, stats=None):
        return set(_ids(lk.collect(_host(files, stats))))

    def test_dotenv_but_not_example(self):
        ids = self._ids_for({"/var/www/html/.env": "SECRET=1", "/var/www/html/.env.example": "x"})
        self.assertEqual(ids, {"leak-dotenv"})

    def test_vcs_dir_detected(self):
        self.assertIn("leak-vcs-dir", self._ids_for({"/var/www/html/.git/HEAD": "ref"}))

    def test_sql_dump_and_backup_and_phpinfo(self):
        ids = self._ids_for({"/var/www/html/db.sql": "x", "/var/www/html/wp-config.php.bak": "x",
                             "/var/www/html/phpinfo.php": "x"})
        self.assertEqual(ids, {"leak-sql-dump", "leak-backup", "leak-phpinfo"})

    def test_private_key_by_content_not_by_extension(self):
        ids = self._ids_for({"/var/www/html/a.pem": "-----BEGIN RSA PRIVATE KEY-----\nabc",
                             "/var/www/html/b.pem": "-----BEGIN CERTIFICATE-----\nabc"})
        self.assertEqual(ids, {"leak-private-key"})

    def test_evidence_never_contains_file_content(self):
        r = lk.collect(_host({"/var/www/html/.env": "DB_PASSWORD=hunter2"}))
        self.assertNotIn("hunter2", str(r))

    def test_wp_config_world_readable(self):
        ids = self._ids_for({"/var/www/html/wp-config.php": "x"}, {"/var/www/html/wp-config.php": REG | 0o644})
        self.assertIn("wp-config-world-readable", ids)
        ids = self._ids_for({"/var/www/html/wp-config.php": "x"}, {"/var/www/html/wp-config.php": REG | 0o640})
        self.assertNotIn("wp-config-world-readable", ids)

    def test_cap_on_number_of_findings(self):
        files = {f"/var/www/html/b{i}.sql": "x" for i in range(lk.MAX_FINDINGS_PER_KIND + 25)}
        r = lk.collect(_host(files))
        self.assertEqual(sum(1 for i in _ids(r) if i == "leak-sql-dump"), lk.MAX_FINDINGS_PER_KIND)
        self.assertIn("leak-sql-dump-truncated", _ids(r))

    def test_findings_sorted_high_first(self):
        r = lk.collect(_host({"/var/www/html/x.bak": "x", "/var/www/html/.env": "x"}))
        self.assertEqual(r["findings"][0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
