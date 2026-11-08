"""Tests for service-config facts (fake /proc and fake filesystem)."""

from __future__ import annotations

import unittest

from scanners import services as sv
from scanners.services import Proc

from test_ecosystems import _fake_fs

NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 x
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 x
   2: 0100007F:C350 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 x
"""
NET_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 x
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 x
"""


class TestProcNet(unittest.TestCase):
    def test_only_listen_state_and_decoding(self):
        socks = sv.parse_proc_net_tcp(NET_TCP, "ipv4")
        self.assertEqual([(s["bind"], s["port"], s["inode"]) for s in socks],
                         [("0.0.0.0", 80, 11111), ("127.0.0.1", 8080, 22222)])

    def test_ipv6(self):
        socks = sv.parse_proc_net_tcp(NET_TCP6, "ipv6")
        self.assertEqual([(s["bind"], s["port"]) for s in socks], [("::1", 8080), ("::", 443)])

    def test_garbage_is_ignored(self):
        self.assertEqual(sv.parse_proc_net_tcp("", "ipv4"), [])
        self.assertEqual(sv.parse_proc_net_tcp("hdr\nnot a row", "ipv4"), [])

    def test_loopback(self):
        self.assertTrue(sv.is_loopback("127.0.0.1"))
        self.assertTrue(sv.is_loopback("::1"))
        self.assertTrue(sv.is_loopback("::ffff:127.0.0.1"))  # IPv4 loopback seen through an IPv6 socket
        self.assertFalse(sv.is_loopback("::ffff:10.0.0.5"))
        self.assertFalse(sv.is_loopback("0.0.0.0"))


class TestListening(unittest.TestCase):
    def test_ports_are_joined_to_owning_process(self):
        proc = Proc(
            net_tcp=NET_TCP, net_tcp6="",
            socket_owners=lambda: {11111: [1, 9], 22222: [40]},
            exe_of=lambda pid: {1: "/usr/sbin/apache2", 40: "/usr/local/bin/php"}.get(pid, ""),
            cmdline_of=lambda pid: {1: "apache2 -DFOREGROUND", 40: "php -S 127.0.0.1:8080"}.get(pid, ""),
        )
        out = sv.collect_listening(proc)
        self.assertEqual([(o["port"], o["exe"], o["loopback_only"]) for o in out],
                         [(80, "/usr/sbin/apache2", False), (8080, "/usr/local/bin/php", True)])
        self.assertEqual(out[0]["pids"], [1, 9])

    def test_unowned_socket_has_empty_process_fields(self):
        proc = Proc(NET_TCP, "", lambda: {}, lambda p: "x", lambda p: "x")
        out = sv.collect_listening(proc)
        self.assertEqual((out[0]["exe"], out[0]["cmdline"], out[0]["pids"]), ("", "", []))


class TestApache(unittest.TestCase):
    def test_modules_from_loadmodule_and_mods_enabled(self):
        texts = {
            "/usr/local/apache2/conf/httpd.conf": "LoadModule rewrite_module modules/mod_rewrite.so\n#LoadModule proxy_module x.so\n",
            "/etc/apache2/mods-enabled/php7.load": "LoadModule php7_module /usr/lib/php7.so",
            "/etc/apache2/mods-enabled/cgi.load": "",
        }
        mods = sv.parse_loaded_modules(texts)
        self.assertIn("rewrite_module", mods)
        self.assertIn("php7_module", mods)
        self.assertIn("cgi_module", mods)
        self.assertNotIn("proxy_module", mods)  # commented out

    def test_flags_and_interesting_directives(self):
        fs = _fake_fs({
            "/etc/apache2/apache2.conf": "ServerTokens Prod\nDocumentRoot /var/www/html\n# comment\nUnrelated x\n",
            "/etc/apache2/mods-enabled/proxy.load": "LoadModule proxy_module m.so",
            "/etc/apache2/mods-enabled/php7.load": "LoadModule php7_module m.so",
        })
        a = sv.collect_apache(fs)
        self.assertTrue(a["has_mod_proxy"])
        self.assertTrue(a["has_mod_php"])
        self.assertFalse(a["has_mod_cgi"])
        self.assertTrue(any("DocumentRoot /var/www/html" in d for d in a["directives"]))
        self.assertFalse(any("Unrelated" in d for d in a["directives"]))
        self.assertFalse(any("comment" in d for d in a["directives"]))

    def test_available_but_not_enabled_modules_are_not_reported_as_loaded(self):
        fs = _fake_fs({
            "/etc/apache2/mods-available/proxy.load": "LoadModule proxy_module m.so",
            "/etc/apache2/mods-available/cgi.load": "LoadModule cgi_module m.so",
            "/etc/apache2/mods-enabled/rewrite.load": "LoadModule rewrite_module m.so",
            "/etc/apache2/sites-available/x.conf": "DocumentRoot /srv/unused",
        })
        a = sv.collect_apache(fs)
        self.assertEqual(a["modules"], ["rewrite_module"])
        self.assertFalse(a["has_mod_proxy"])
        self.assertFalse(a["has_mod_cgi"])
        self.assertFalse(any("/srv/unused" in d for d in a["directives"]))

    def test_no_apache_gives_empty(self):
        self.assertEqual(sv.collect_apache(_fake_fs({"/etc/hosts": "x"})), {})


class TestPhpAndNginx(unittest.TestCase):
    def test_php_ini_last_assignment_wins_and_comments_ignored(self):
        text = "; expose_php = On\nexpose_php = Off\nallow_url_include = 0 ; trailing\ndisable_functions = \"exec,system\"\nunrelated=1\n"
        self.assertEqual(sv.parse_php_ini(text),
                         {"expose_php": "Off", "allow_url_include": "0", "disable_functions": "exec,system"})

    def test_conf_d_overrides_php_ini(self):
        fs = _fake_fs({
            "/usr/local/etc/php/php.ini": "expose_php = On\n",
            "/usr/local/etc/php/conf.d/zz-hardening.ini": "expose_php = Off\n",
        })
        self.assertEqual(sv.collect_php(fs)["settings"]["expose_php"], "Off")

    def test_nginx_directives(self):
        fs = _fake_fs({"/etc/nginx/nginx.conf": "worker_processes 1;\nlisten 80;\nproxy_pass http://127.0.0.1:9000;\n"})
        d = sv.collect_nginx(fs)["directives"]
        self.assertEqual(len(d), 2)


class TestCollect(unittest.TestCase):
    def test_failing_part_is_noted_and_others_survive(self):
        def boom():
            raise OSError("denied")

        proc = Proc(NET_TCP, "", boom, lambda p: "", lambda p: "")
        r = sv.collect(_fake_fs({"/etc/nginx/nginx.conf": "listen 80;\n"}), proc)
        self.assertTrue(any(n.startswith("listening failed") for n in r.notes))
        self.assertTrue(r.nginx["directives"])

    def test_proc_none_skips_listening(self):
        r = sv.collect(_fake_fs({"/etc/hosts": "x"}), None)
        self.assertEqual(r.listening, [])


if __name__ == "__main__":
    unittest.main()
