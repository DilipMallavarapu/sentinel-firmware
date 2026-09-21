#!/usr/bin/env python3
"""
Coverage for the analyzers `test_regressions.py` barely touches.

That file grew around the false positives real firmware produced, so it is
dense on `secrets` and `services` and nearly silent on extraction, binary
analysis, backdoor detection and hardening. Those are not less important —
they are just younger, which means their bugs have not been found yet.

The cases here are written differently from the regression suite on purpose.
Regression cases pin behaviour that was once wrong. These pin behaviour that
must stay right: the filters that keep the noise out, the thresholds that
decide what gets reported, and the refusals that keep the tool inside its
authorization. Each one is built from a synthetic artefact constructed in
memory, so the suite runs anywhere and does not depend on a fixture tree.

    python3 test_analyzers.py
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.core import verifiers  # noqa: F401,E402
from sentinel.core.contracts import (  # noqa: E402
    Confidence, RunContext, Scope, Severity,
)

ok = True
_section = ""


def section(name: str) -> None:
    global _section
    _section = name
    print(f"\n== {name} ==")


def check(label: str, cond) -> None:
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


TMP = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))


def make_elf(machine: int = 0x08, rodata: bytes = b"", little: bool = True,
             etype: int = 2) -> bytes:
    """
    A minimal but structurally valid 32-bit ELF with a real .rodata section.

    Built by hand rather than shelled out to a compiler so the tests run on
    any host and the section contents are exactly what the case needs.
    """
    o = "<" if little else ">"
    eh, sh_size, n_sec = 52, 40, 4
    ro_off = eh
    shstr = b"\x00.shstrtab\x00.rodata\x00.text\x00"
    shstr_off = ro_off + len(rodata)
    shoff = shstr_off + len(shstr) + 16

    h = bytearray(eh)
    h[0:4] = b"\x7fELF"
    h[4], h[5], h[6] = 1, (1 if little else 2), 1
    struct.pack_into(o + "H", h, 16, etype)
    struct.pack_into(o + "H", h, 18, machine)
    struct.pack_into(o + "I", h, 20, 1)
    struct.pack_into(o + "I", h, 32, shoff)
    struct.pack_into(o + "H", h, 46, sh_size)
    struct.pack_into(o + "H", h, 48, n_sec)
    struct.pack_into(o + "H", h, 50, 3)

    def sh(name_off, addr, off, size):
        b = bytearray(sh_size)
        struct.pack_into(o + "I", b, 0, name_off)
        struct.pack_into(o + "I", b, 12, addr)
        struct.pack_into(o + "I", b, 16, off)
        struct.pack_into(o + "I", b, 20, size)
        return bytes(b)

    secs = (sh(0, 0, 0, 0) + sh(11, 0x400000, ro_off, len(rodata))
            + sh(19, 0x410000, ro_off, 0) + sh(1, 0, shstr_off, len(shstr)))
    return bytes(h) + rodata + shstr + b"\x00" * 16 + secs


def rootfs_with(files: dict[str, bytes], name: str):
    """Build a throwaway rootfs and return it identified."""
    from sentinel.firmware.models import RootFS
    from sentinel.firmware.unpack import identify
    root = TMP / name
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if rel.endswith((".cgi", ".so")) or "/bin/" in rel or "/sbin/" in rel:
            p.chmod(0o755)
    return identify(RootFS(root=root))


def ctx_for(name: str) -> RunContext:
    d = TMP / f"run-{name}"
    d.mkdir(parents=True, exist_ok=True)
    return RunContext(name, d, Scope("LOCAL-TESTS"), lambda e, x: None)


# ==========================================================================
section("unpack: identification and rootfs scoring")
# ==========================================================================

from sentinel.firmware.unpack import (  # noqa: E402
    _entropy, identify, locate_rootfs, MAGICS,
)
from sentinel.firmware.models import RootFS  # noqa: E402

check("random bytes read as high entropy", _entropy(bytes(range(256)) * 8) > 7.9)
check("repetitive bytes read as low entropy", _entropy(b"A" * 2048) < 1.0)
check("empty input does not divide by zero", _entropy(b"") == 0.0)

# Encrypted vendor images are the case that must never look like a clean
# scan: high entropy with no recognised filesystem magic.
check("squashfs magic is recognised", any(m == b"hsqs" for m, _ in MAGICS))

real = rootfs_with({
    "bin/busybox": make_elf(machine=0x28),
    "etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
    "etc/shadow": b"root:*:1::::::\n",
    "etc/init.d/rcS": b"#!/bin/sh\n",
    "sbin/init": b"#!/bin/sh\n",
    "lib/ld-uClibc.so.0": b"",
    "usr/bin/env": b"",
}, "real-root")
fragment = rootfs_with({"foo/bar.txt": b"hello", "foo/baz.txt": b"world"},
                       "fragment")

found, board = locate_rootfs(real.root.parent)
check("a real rootfs scores high enough to be located", found is not None)
found_f, board_f = locate_rootfs(fragment.root)
check("a fragment is rejected rather than scanned", found_f is None)
check("the scoreboard is returned for the report", isinstance(board, dict))

check("architecture read from the ELF header", real.arch == "arm")
check("uclibc detected from the loader", real.libc == "uclibc")
check("sysvinit detected from etc/init.d", real.init_system == "sysvinit")

# walk() must not follow a symlink out of the extraction root -- firmware
# archives ship links to /etc/passwd on the analysis host as a matter of
# routine.
outside = TMP / "outside-secret.txt"
outside.write_text("host secret")
(real.root / "etc" / "escape").symlink_to(outside)
walked = [e.rel for e in real.walk()]
check("a symlink is recorded, not followed",
      any(e.is_symlink for e in real.walk() if e.rel.endswith("escape")))
check("no file outside the root is walked",
      not any("outside-secret" in w for w in walked))


# ==========================================================================
section("binanalysis: what counts as a shell command")
# ==========================================================================

from sentinel.firmware.analyzers.binanalysis import (  # noqa: E402
    CommandTemplateDetector, extract_templates, parse_elf, Template,
)
try:
    from sentinel.firmware.analyzers.binanalysis import _shell_metachars
    HAVE_FILTER = True
except ImportError:
    HAVE_FILTER = False

check("the lookalike filter is present", HAVE_FILTER)

if HAVE_FILTER:
    real_cmds = [
        "echo root:%s | chpasswd -m",                       # CVE-2024-48456
        "/bin/lzma d %s %s && /bin/unmkpkg -u %s / > /dev/null",
        "3322ip -S qdns -u %s:%s -h %s -i %s &",
        "echo %s >> %s",
    ]
    lookalikes = [
        "[1;31m[TIMER_CHECK >>%s(%d)]:",                    # ANSI debug log
        "GET /nic/update?hostname=%s&mx=NOCHG  HTTP/1.0",   # URL query
        "NAT-PMP port mapping request : %hu->%s:%hu",       # arrow
        '{"err_code":%d,"sn":"%s"}',                        # JSON
        "Try `%s -h' or '%s --help' for more information.", # help text
        "can't initialize iptables table `%s': %s",         # GNU quoting
    ]
    check("every real command template keeps its metacharacters",
          all(_shell_metachars(t) for t in real_cmds))
    check("every lookalike is stripped to nothing",
          not any(_shell_metachars(t) for t in lookalikes))

# The scoring bonus must consult the filtered list. Reading the raw tuple let
# a URL query string collect the full adjacency bonus after the filter had
# already rejected its `&`.
url = Template(text="GET /nic/update?hostname=%s&mx=NOCHG HTTP/1.0", offset=0,
               specs=["%s"], commands=[], metachars=[])
real_t = Template(text="echo %s >> %s", offset=0, specs=["%s", "%s"],
                  commands=["echo"], metachars=[">>"])
check("a filtered-out template scores near zero", url.score < 5)
check("a real template clears the reporting threshold", real_t.score >= 17)

rodata = b"\x00".join([
    b"echo root:%s | chpasswd -m",
    b"log: interface %s state changed to %d",
    b"failed to open %s: %s",
]) + b"\x00"
view = parse_elf(make_elf(rodata=rodata))
check("sections parse out of a hand-built ELF", view is not None)
tmpl = extract_templates(view)
check("the injection template is extracted", any("chpasswd" in t.text for t in tmpl))
check("benign log format strings are not extracted",
      not any("state changed" in t.text for t in tmpl))
check("a non-ELF is rejected rather than parsed", parse_elf(b"MZ\x90\x00" * 40) is None)
check("a truncated ELF does not raise", parse_elf(b"\x7fELF" + b"\x00" * 20) is None)

# min_score is what stops 60 of 103 binaries being reported. A single bland
# template scores 12; the threshold must sit above that.
det = CommandTemplateDetector()
check("min_score is above the single-bland-template floor", det.min_score > 12)

rfs_bin = rootfs_with({
    "www/cgi-bin/apply.cgi": make_elf(rodata=rodata),
    "bin/quiet": make_elf(rodata=b"just a plain string with no specifier\x00"),
}, "binroot")
found_bin = list(det.run(rfs_bin, ctx_for("bin")))
check("the CGI binary is reported", any("apply.cgi" in f.target for f in found_bin))
check("a binary with no templates is not reported",
      not any("quiet" in f.target for f in found_bin))
check("command-template findings never reach confirmed",
      all(f.confidence != Confidence.CONFIRMED for f in found_bin))


# ==========================================================================
section("sharedkeys: the front end / back end bridge")
# ==========================================================================

from sentinel.firmware.analyzers.sharedkeys import (  # noqa: E402
    SharedKeywordDetector, STOPWORDS, correlate, extract_frontend_keywords,
)

_page = b"""<html><form action="/goform/setWan">
<input type="text" name="wanIpAddr" id="wanIpAddr">
<input type="text" name="wanNetmask">
<input type="text" name="wanGateway">
<input type="text" name="dnsServer1">
<input type="text" name="pppoeUser">
<input type="password" name="pppoePasswd">
<input type="text" name="ddnsUser">
<select name="wanIface"><option value="eth0">eth0</option></select>
</form><script>var x = document.getElementById("hostName").value;</script></html>"""

_ro = b"\x00".join([
    b"wanIpAddr", b"echo nameserver %s >> /etc/resolv.conf",
    b"pppoeUser", b"pppoePasswd", b"3322ip -S qdns -u %s:%s -h %s &",
]) + b"\x00"

rfs_sk = rootfs_with({"www/wan.html": _page,
                      "bin/netctrl": make_elf(rodata=_ro),
                      "bin/unrelated": make_elf(rodata=b"nothing here\x00")},
                     "sharedroot")

kws = extract_frontend_keywords(rfs_sk)
check("parameter names are pulled out of the form", "wanIpAddr" in kws)
check("a password field is captured too", "pppoePasswd" in kws)
check("getElementById names are captured", "hostName" in kws)
check("boilerplate is filtered out",
      not any(k.lower() in STOPWORDS for k in kws))
check("markup attributes are not mistaken for parameters",
      "value" not in kws and "action" not in kws)

_corr = correlate(kws, "bin/netctrl", (rfs_sk.root / "bin/netctrl").read_bytes())
check("shared names are found in the binary", _corr and len(_corr.shared) >= 3)
check("adjacency to a command template is detected",
      _corr and len(_corr.adjacencies) >= 1)
check("the nearest adjacency is the one reported first",
      _corr and _corr.adjacencies == sorted(_corr.adjacencies, key=lambda a: a[2]))
check("a binary sharing nothing correlates to nothing",
      correlate(kws, "bin/unrelated",
                (rfs_sk.root / "bin/unrelated").read_bytes()) is None
      or not correlate(kws, "bin/unrelated",
                       (rfs_sk.root / "bin/unrelated").read_bytes()).shared)

_sk = list(SharedKeywordDetector().run(rfs_sk, ctx_for("sk")))
check("the correlated binary is reported", any("netctrl" in f.target for f in _sk))
check("adjacency raises it to HIGH",
      any(f.severity == Severity.HIGH for f in _sk))
# Two strings close together in .rodata usually share a function, but that is
# evidence about source layout, not dataflow. Claiming confirmed would put a
# proof on a linker coincidence.
check("shared keywords never reach confirmed",
      all(f.confidence != Confidence.CONFIRMED for f in _sk))
# Busybox ships one binary under many applet names; vendors rebuild the same
# daemon as dhcpcd_wan1..wan4. On a real image that turned one finding into
# ten and buried the distinct ones.
_dupe = make_elf(rodata=_ro)
rfs_dup = rootfs_with({"www/wan.html": _page,
                       "bin/netctrl": _dupe,
                       "bin/netctrl_wan1": _dupe,
                       "bin/netctrl_wan2": _dupe}, "duproot")
_dups = list(SharedKeywordDetector().run(rfs_dup, ctx_for("sk3")))
check("identical binaries collapse to one finding", len(_dups) == 1)
check("the duplicate names are still recorded",
      _dups and len(_dups[0].context.get("identical_copies", [])) == 2)

check("a rootfs with no front end produces nothing",
      not list(SharedKeywordDetector().run(
          rootfs_with({"bin/x": make_elf(rodata=_ro)}, "nofrontend"),
          ctx_for("sk2"))))


# ==========================================================================
section("backdoor: literature-derived detectors")
# ==========================================================================

from sentinel.firmware.analyzers.backdoor import (  # noqa: E402
    AuthorizedKeysDetector, BuildBannerDetector, ShippedTlsKeypairDetector,
)
import base64 as _b64  # noqa: E402
import os as _os  # noqa: E402

_key_body = _b64.b64encode(_os.urandom(600)).decode()
_pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(_key_body[i:i + 64] for i in range(0, len(_key_body), 64))
        + "\n-----END RSA PRIVATE KEY-----\n").encode()
_crt = _pem.replace(b"RSA PRIVATE KEY", b"CERTIFICATE")

rfs_bd = rootfs_with({
    "root/.ssh/authorized_keys":
        b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD" + b"A" * 80
        + b" builduser@vendor-buildhost\n",
    "etc/ssl/private/device.key": _pem,
    "etc/ssl/certs/device.crt": _crt,
    "lib/banner.bin":
        b"Linux version 2.6.31 (root@vendor-build01) (gcc version 4.2.0)\x00",
}, "backdoorroot")
c = ctx_for("backdoor")

ak = list(AuthorizedKeysDetector().run(rfs_bd, c))
check("a shipped authorized_keys is found", len(ak) == 1)
check("it is CRITICAL", ak and ak[0].severity == Severity.CRITICAL)
check("it is confirmed by a byte proof",
      ak and ak[0].confidence == Confidence.CONFIRMED)
check("the key comment is captured for vendor follow-up",
      ak and any("vendor-buildhost" in cm
                 for cm in ak[0].context.get("key_comments", [])))

tls = list(ShippedTlsKeypairDetector().run(rfs_bd, c))
check("a shipped key/cert pair is found", len(tls) == 1)
check("fleet-wide impact is not asserted from the filesystem",
      tls and "regenerat" in tls[0].summary.lower())

bn = list(BuildBannerDetector().run(rfs_bd, c))
check("the build banner is extracted", len(bn) == 1)
check("building as root is called out",
      bn and bn[0].context.get("built_as_root"))

clean = rootfs_with({"etc/hosts": b"127.0.0.1 localhost\n"}, "cleanroot")
check("no authorized_keys means no finding",
      not list(AuthorizedKeysDetector().run(clean, c)))
check("a cert with no private key means no keypair finding",
      not list(ShippedTlsKeypairDetector().run(
          rootfs_with({"etc/ssl/certs/ca.crt": _crt}, "certonly"), c)))


# ==========================================================================
section("hardening: unknown is not absent")
# ==========================================================================

from sentinel.firmware.analyzers.hardening import HardeningAnalyzer  # noqa: E402

an = HardeningAnalyzer()
mit = {"nx": True, "pie": True, "canary": True, "relro": "full",
       "fortify": True, "stripped": False, "text_relocs": False}

# A file the worker could not parse carries no mitigation block. Counting it
# as unhardened manufactures findings out of extraction failures.
records_unparsed = [{"path": "bin/packed", "type": "ET_EXEC",
                     "error": "elf parse: bad magic"}] * 5
out = list(an.analyze(records_unparsed, clean, [], ctx_for("hard1")))
check("unparseable records produce no hardening findings", out == [])

good = [{"path": f"bin/p{i}", "type": "ET_EXEC", "mitigations": dict(mit)}
        for i in range(20)]
check("a fully hardened image reports nothing",
      list(an.analyze(good, clean, [], ctx_for("hard2"))) == [])

bad_mit = dict(mit, nx=False, canary=False, pie=False, relro="none")
bad = [{"path": f"bin/p{i}", "type": "ET_EXEC", "mitigations": dict(bad_mit)}
       for i in range(20)]
agg = list(an.analyze(bad, clean, [], ctx_for("hard3")))
check("an unhardened image reports image-wide findings", len(agg) >= 2)
check("aggregates are reported once, not per binary", len(agg) <= 6)
check("aggregates stay below confirmed",
      all(f.confidence != Confidence.CONFIRMED for f in agg))

# The interesting middle: a minority hardened. Firing only at exactly zero
# coverage loses the case real vendor images actually present.
mixed = ([{"path": f"bin/g{i}", "type": "ET_EXEC", "mitigations": dict(mit)}
          for i in range(2)]
         + [{"path": f"bin/b{i}", "type": "ET_EXEC", "mitigations": dict(bad_mit)}
            for i in range(38)])
check("partial coverage is still reported",
      len(list(an.analyze(mixed, clean, [], ctx_for("hard4")))) >= 1)


# ==========================================================================
section("http_auth: scope is enforced in code")
# ==========================================================================

from sentinel.firmware.analyzers.http_auth import (  # noqa: E402
    REDFISH_PUBLIC, UnauthenticatedSurfaceDetector,
)

d_remote = UnauthenticatedSurfaceDetector("https://10.0.0.5", ("root", "x"))
refused = False
try:
    list(d_remote.run(None, ctx_for("auth1")))
except PermissionError:
    refused = True
check("an out-of-scope host is refused before any request", refused)

d_local = UnauthenticatedSurfaceDetector("https://127.0.0.1:1", None)
check("an emulated target is allowed", d_local.applicable(None))
check("the Redfish service root is allowlisted", "/redfish/v1" in REDFISH_PUBLIC)
check("children do not inherit the root's exemption",
      "/redfish/v1/Systems" not in REDFISH_PUBLIC)
check("the account service is probed, not exempted",
      "/redfish/v1/AccountService/Accounts" not in REDFISH_PUBLIC)


print("\n" + ("ALL ANALYZER CHECKS PASSED" if ok else "FAILURES ABOVE"))
sys.exit(0 if ok else 1)
