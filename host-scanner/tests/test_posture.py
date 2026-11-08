"""Tests for security-posture findings (fake filesystem; runs on any OS)."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from scanners import posture as po
from scanners.posture import Host

from test_ecosystems import _fake_fs

NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


def _host(files: dict, mtimes=None, certs=None) -> Host:
    mtimes = mtimes or {}
    certs = certs or {}
    return Host(fs=_fake_fs(files), mtime=lambda p: mtimes.get(p),
                now=lambda: NOW, decode_cert=lambda p: certs.get(p))


def _ids(result) -> set[str]:
    return {f["id"] for f in result["findings"]}


class TestSshd(unittest.TestCase):
    def test_first_occurrence_wins_and_match_block_ignored(self):
        cfg = po.parse_sshd_config(
            "PermitRootLogin no\nPermitRootLogin yes\nMatch User x\nPasswordAuthentication yes\n")
        self.assertEqual(cfg["permitrootlogin"], "no")
        self.assertNotIn("passwordauthentication", cfg)

    def test_findings(self):
        f = {x.id for x in po.sshd_findings(po.parse_sshd_config(
            "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\nX11Forwarding yes\n"))}
        self.assertEqual(f, {"ssh-root-login", "ssh-password-auth", "ssh-empty-passwords", "ssh-x11-forwarding"})

    def test_safe_config_has_no_findings(self):
        self.assertEqual(po.sshd_findings(po.parse_sshd_config(
            "PermitRootLogin prohibit-password\nPasswordAuthentication no\n")), [])

    def test_collected_from_files_including_dropin(self):
        r = po.collect(_host({"/etc/ssh/sshd_config": "PasswordAuthentication no\n",
                              "/etc/ssh/sshd_config.d/10.conf": "PermitRootLogin yes\n"}))
        self.assertIn("ssh-root-login", _ids(r))
        self.assertEqual(r["ssh"]["passwordauthentication"], "no")

    def test_no_sshd_means_no_section(self):
        self.assertNotIn("ssh", po.collect(_host({"/etc/hosts": "x"})))


class TestSudo(unittest.TestCase):
    def test_nopasswd_flagged_comments_and_defaults_ignored(self):
        f = po.sudoers_findings({
            "/etc/sudoers": "Defaults env_reset\n# a NOPASSWD comment\nroot ALL=(ALL) ALL\n",
            "/etc/sudoers.d/x": "deploy ALL=(ALL) NOPASSWD: ALL\n"})
        self.assertEqual([x.id for x in f], ["sudo-nopasswd"])
        self.assertIn("/etc/sudoers.d/x:1", f[0].evidence)


class TestSysctl(unittest.TestCase):
    def test_weak_values_flagged_good_values_not(self):
        r = po.collect(_host({"/proc/sys/kernel/randomize_va_space": "0\n",
                              "/proc/sys/kernel/kptr_restrict": "1\n",
                              "/proc/sys/fs/protected_symlinks": "0\n"}))
        self.assertIn("sysctl-kernel-randomize_va_space", _ids(r))
        self.assertIn("sysctl-fs-protected_symlinks", _ids(r))
        self.assertNotIn("sysctl-kernel-kptr_restrict", _ids(r))
        self.assertEqual(r["sysctl"]["kernel.randomize_va_space"], 0)


class TestContainer(unittest.TestCase):
    def _files(self, **over):
        base = {
            "/proc/1/cgroup": "0::/docker/abc\n",
            "/proc/self/status": "CapEff:\t00000000a80425fb\nSeccomp:\t2\nNoNewPrivs:\t0\n",
            "/proc/1/status": "Uid:\t0\t0\t0\t0\n",
            "/proc/1/environ": "PATH=/usr/bin\0DB_PASSWORD=hunter2\0APP_API_KEY=abc\0HOME=/root\0",
            "/proc/self/mountinfo": ("36 1 8:1 / / rw - overlay overlay rw\n"
                                     "40 36 8:1 /data /srv/data ro - ext4 /dev/sda1 rw\n"),
        }
        base.update(over)
        return base

    def test_default_container_flags(self):
        r = po.collect(_host(self._files()))
        self.assertTrue(r["container"]["in_container"])
        ids = _ids(r)
        self.assertIn("container-runs-as-root", ids)
        self.assertIn("container-secret-env", ids)
        self.assertNotIn("container-privileged", ids)
        self.assertEqual(r["container"]["host_bind_mounts"][0]["mount_point"], "/srv/data")

    def test_docker_managed_mounts_are_not_reported(self):
        info = ("40 36 8:1 /x /etc/hosts rw - ext4 /dev/sda1 rw\n"
                "41 36 8:1 /y /var/www/html rw - ext4 /dev/sda1 rw\n")
        self.assertEqual([m["mount_point"] for m in po.parse_mountinfo_binds(info)], ["/var/www/html"])

    def test_secret_env_reports_names_never_values(self):
        blob = str(po.collect(_host(self._files())))
        self.assertIn("DB_PASSWORD", blob)
        self.assertNotIn("hunter2", blob)

    def test_privileged_and_docker_sock(self):
        r = po.collect(_host(self._files(**{
            "/proc/self/status": "CapEff:\t000001ffffffffff\nSeccomp:\t0\n",
            "/var/run/docker.sock": "",
        })))
        self.assertTrue({"container-privileged", "container-docker-sock", "container-no-seccomp"} <= _ids(r))

    def test_not_in_container(self):
        r = po.collect(_host({"/proc/1/cgroup": "0::/init.scope\n"}))
        self.assertEqual(r["container"], {"in_container": False})


class TestTls(unittest.TestCase):
    def _run(self, not_after, subject="CN=a", issuer="CN=ca"):
        files = {"/etc/nginx/nginx.conf": "ssl_certificate /etc/nginx/ssl/a.crt;\n",
                 "/etc/nginx/ssl/a.crt": "PEM"}
        certs = {"/etc/nginx/ssl/a.crt": {"subject": subject, "issuer": issuer, "not_after": not_after}}
        return po.collect(_host(files, certs=certs))

    def test_expired(self):
        self.assertIn("tls-expired", _ids(self._run(NOW - timedelta(days=3))))

    def test_expiring_soon(self):
        self.assertIn("tls-expiring", _ids(self._run(NOW + timedelta(days=10))))

    def test_valid_far_future_no_finding(self):
        ids = _ids(self._run(NOW + timedelta(days=200)))
        self.assertFalse({"tls-expired", "tls-expiring", "tls-self-signed"} & ids)

    def test_self_signed(self):
        self.assertIn("tls-self-signed", _ids(self._run(NOW + timedelta(days=200), "CN=x", "CN=x")))


class TestHygiene(unittest.TestCase):
    def test_eol_os(self):
        r = po.collect(_host({"/etc/os-release":
                              'ID=debian\nVERSION_ID="10"\nPRETTY_NAME="Debian GNU/Linux 10 (buster)"\n'}))
        self.assertIn("os-eol", _ids(r))
        self.assertEqual(r["hygiene"]["os"]["eol_date"], "2024-06-30")

    def test_supported_os_no_finding(self):
        r = po.collect(_host({"/etc/os-release": 'ID=debian\nVERSION_ID="12"\n'}))
        self.assertNotIn("os-eol", _ids(r))

    def test_unknown_os_has_no_eol_claim(self):
        r = po.collect(_host({"/etc/os-release": "ID=plan9\nVERSION_ID=4\n"}))
        self.assertNotIn("os-eol", _ids(r))

    def test_stale_apt(self):
        old = (NOW - timedelta(days=90)).timestamp()
        r = po.collect(_host({"/etc/os-release": "ID=x\n"},
                             mtimes={"/var/lib/apt/periodic/update-success-stamp": old}))
        self.assertIn("apt-stale", _ids(r))

    def test_fresh_apt_no_finding(self):
        fresh = (NOW - timedelta(days=2)).timestamp()
        r = po.collect(_host({"/etc/os-release": "ID=x\n"},
                             mtimes={"/var/lib/apt/periodic/update-success-stamp": fresh}))
        self.assertNotIn("apt-stale", _ids(r))

    def test_unattended_upgrades_detection(self):
        with_pkg = po.collect(_host({"/var/lib/dpkg/status": "Package: unattended-upgrades\nStatus: ok\n"}))
        without = po.collect(_host({"/var/lib/dpkg/status": "Package: bash\nStatus: ok\n"}))
        self.assertNotIn("no-auto-updates", _ids(with_pkg))
        self.assertIn("no-auto-updates", _ids(without))

    def test_reboot_required(self):
        self.assertIn("reboot-required", _ids(po.collect(_host({"/var/run/reboot-required": ""}))))


class TestCollect(unittest.TestCase):
    def test_findings_sorted_by_severity(self):
        r = po.collect(_host({"/etc/ssh/sshd_config": "PermitRootLogin yes\nX11Forwarding yes\n",
                              "/proc/sys/kernel/kptr_restrict": "0\n"}))
        sev = [f["severity"] for f in r["findings"]]
        self.assertEqual(sev, sorted(sev, key={"high": 0, "medium": 1, "low": 2}.get))

    def test_failing_collector_noted_others_survive(self):
        h = _host({"/etc/ssh/sshd_config": "PermitRootLogin yes\n"})
        real_read = h.fs.read

        def read(path):
            if path == "/etc/os-release":
                raise OSError("x")
            return real_read(path)

        h.fs.read = read
        r = po.collect(h)
        self.assertTrue(any("hygiene failed" in n for n in r["notes"]))
        self.assertIn("ssh-root-login", _ids(r))


if __name__ == "__main__":
    unittest.main()
