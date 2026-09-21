#!/usr/bin/env python3
"""
Regression cases taken from real vendor firmware, not invented.

Every check here corresponds to a bug that shipped and was caught only by
running against an actual image. Standalone so it does not depend on which
revision of smoke_test.py is on disk.

    python3 test_regressions.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.core import verifiers  # noqa: F401
from sentinel.core.contracts import (Confidence, RunContext, Scope, Severity)
from sentinel.firmware.analyzers.secrets import (
    CONFIG_CRED_RE, HardcodedCredentialDetector, _hash_algorithm)
from sentinel.firmware.analyzers.services import ServiceAnalyzer, _is_text_config
from sentinel.firmware.models import RootFS
from sentinel.firmware.unpack import identify

HERE = Path(__file__).resolve().parent
RUNDIR = HERE / "runs" / "regressions"
RUNDIR.mkdir(parents=True, exist_ok=True)
ok = True


def check(label, cond):
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


print("\n== Unit: the regexes and helpers ==")
# Tenda AC6: `samba_passwd=` is empty, and \s in the value pattern matches
# newlines, so it captured `ses_cl_enable=1` from the line below. Nineteen
# confirmed findings in one run came from that single character.
check("empty-valued key does not capture the following line",
      CONFIG_CRED_RE.search(b"samba_passwd=\nses_cl_enable=1") is None)
check("a real value on the same line still matches",
      CONFIG_CRED_RE.search(b"wl0_wpa_psk=Secret42").group("val") == b"Secret42")
check("a quoted value excludes the closing quote",
      CONFIG_CRED_RE.search(b'admin_password = "Sup3rS3cret"').group("val")
      == b"Sup3rS3cret")

# Tenda ships admin/support/user all at uid 0 with 13-char DES hashes. The
# first version of this detector reported "hardcoded crypt hash" and said
# nothing about either fact.
check("DES hash is named as broken", "DES" in _hash_algorithm(b"6HgsSsJIEOc2U"))
check("MD5 crypt is named as weak",
      "weak" in _hash_algorithm(b"$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1"))
check("SHA-512 crypt is not called weak",
      "weak" not in _hash_algorithm(b"$6$abcd$efgh"))

# /init is a symlink to busybox on most MIPS images, and busybox embeds a
# table naming every applet it was built with -- telnetd, ftpd, httpd. Read
# as init config, it invents services on every busybox image in existence.
check("an ELF is rejected as init config",
      not _is_text_config(open("/bin/sh", "rb").read()))
check("a shell script is accepted", _is_text_config(b"#!/bin/sh\nexec /sbin/init\n"))
check("an nvram-style config is accepted",
      _is_text_config(b"wl_wpa_psk=\nwl_mode=ap\n"))


print("\n== Integration: the fixture ==")
fixture = HERE / "fixture" / "rootfs"
if not fixture.is_dir():
    print("  fixture missing; run ./extend_fixture.sh first")
    sys.exit(1)

rfs = identify(RootFS(root=fixture))
ctx = RunContext("regressions", RUNDIR, Scope("LOCAL"), lambda e, d: None)
findings = list(HardcodedCredentialDetector().run(rfs, ctx))

nv = [f for f in findings if f.target.endswith("nvram_default.cfg")]
check("the .cfg produces exactly one finding", len(nv) == 1)
check("that finding has exactly one occurrence",
      bool(nv) and nv[0].context.get("occurrences") == 1)
check("no finding at all against JavaScript in the web root",
      not any("main.html" in f.target for f in findings))

pw = [f for f in findings if f.target == "etc_ro/passwd"]
check("all accounts in one passwd collapse to one finding", len(pw) == 1)
check("a uid-0 non-root account is named root-equivalent",
      bool(pw) and any("root-equivalent" in d
                       for d in pw[0].context.get("details", [])))
check("uid 0 plus DES escalates to CRITICAL",
      bool(pw) and pw[0].severity == Severity.CRITICAL)

# OpenBMC Romulus ships root/0penBmc, published upstream. A documented
# default and a vendor-baked secret are different findings, and calling the
# first HIGH costs credibility with a maintainer who knows their own image.
kd = [f for f in findings if f.context.get("known_default")]
check("a published default hash is demoted to INFO and named",
      bool(kd) and kd[0].severity == Severity.INFO
      and "OpenBMC" in kd[0].title)

an = ServiceAnalyzer()
services = an.discover(rfs)
check("services under etc_ro/init.d are found",
      any(s.name == "httpd" for s in services))
check("busybox is not read as init config",
      not any("busybox" in p for s in services for p in s.config_paths))

# OpenBMC Romulus: stock openssl.cnf ships `# input_password = secret` as
# documentation, and six confirmed findings came from commented-out lines.
ssl = [f for f in findings if "openssl.cnf" in f.target]
check("commented-out example credentials produce no finding", not ssl)

# Also Romulus: TemporaryFileSystem=/tmp/bmcweb is a systemd sandboxing
# directive, and reading it as the service binary reported the hardening
# measure as the executable.
bmc = next((s for s in services if s.name == "bmcweb"), None)
check("systemd binary comes from ExecStart, not a sandbox directive",
      bmc is not None and bmc.binary == "/usr/bin/bmcweb")

orphans = an.orphan_binaries(services, rfs)
gap = an.coverage_finding(orphans, services, rfs, ctx)
check("a daemon nothing starts is reported as a coverage gap",
      gap is not None and gap.confidence == Confidence.PROBABLE)

print("\n" + ("ALL REGRESSION CHECKS PASSED" if ok else "FAILURES ABOVE"))
sys.exit(0 if ok else 1)
