#!/usr/bin/env python3
"""Apply the newline / uid-0 / binary-init fixes in place. Idempotent."""
import pathlib, sys
ok = True

def edit(path, pairs, marker, want):
    global ok
    p = pathlib.Path(path)
    if not p.is_file():
        print(f"  MISSING {path}"); ok = False; return
    s = p.read_text()
    for old, new in pairs:
        if new in s:           # already applied
            continue
        if old not in s:
            print(f"  NO MATCH in {path}: {old.splitlines()[0][:55]}")
            ok = False; continue
        s = s.replace(old, new)
    p.write_text(s)
    got = s.count(marker)
    print(f"  {path}: {marker} x{got} {'ok' if got >= want else 'FAILED'}")
    if got < want: ok = False

# ---------------------------------------------------------------- secrets
edit("sentinel/firmware/analyzers/secrets.py", [
 (r'''    rb"\s*[=:]\s*[\"']?(?P<val>[^\s\"']{6,64})[\"']?",''',
  r'''    # [ \t]* NOT \s*: \s matches newline, so `samba_passwd=` with an empty
    # value captures the whole of the following line. Every empty-valued key
    # in an nvram dump became a confirmed finding through that one character.
    rb"[ \t]*[=:][ \t]*[\"']?(?P<val>[^\s\"']{6,64})[\"']?",'''),
 # older variant, in case the quote fix never landed either
 (r'''    rb"\s*[=:]\s*[\"']?(?P<val>[!-~]{6,64})[\"']?",''',
  r'''    rb"[ \t]*[=:][ \t]*[\"']?(?P<val>[^\s\"']{6,64})[\"']?",'''),
 ('''@dataclass
class _Hit:''',
  '''def _hash_algorithm(h: bytes) -> str:
    """Name the algorithm, and say plainly when it is a broken one."""
    if h.startswith(b"$6$"):
        return "SHA-512 crypt"
    if h.startswith(b"$5$"):
        return "SHA-256 crypt"
    if h.startswith((b"$2a$", b"$2b$", b"$2y$")):
        return "bcrypt"
    if h.startswith(b"$1$"):
        return "MD5 crypt (weak; GPU-crackable)"
    if len(h) == 13:
        return ("traditional DES crypt (broken; 8-character maximum, "
                "falls to a wordlist in minutes)")
    return "unrecognised hash format"


@dataclass
class _Hit:'''),
 ('''            yield _Hit(rel, m.start("hash"), h, "crypt_hash",
                       f"account {m.group('user').decode()} has a set password hash")''',
  '''            user = m.group("user").decode()

            # The hash existing is the least interesting part. Severity is
            # decided by the account's uid and the algorithm: a non-root
            # account at uid 0 is root under another name, and a 13-character
            # DES hash falls to a wordlist whatever it protects.
            line_end = data.find(b"\\n", m.start())
            line = data[m.start():line_end if line_end > 0 else len(data)]
            fields = line.split(b":")
            uid = int(fields[2]) if len(fields) >= 3 and fields[2].isdigit() else None
            algo = _hash_algorithm(h)
            if uid == 0 and user != "root":
                detail = (f"account {user} is uid 0 -- root-equivalent under "
                          f"a different name")
            elif uid == 0:
                detail = "root has a set password hash"
            else:
                detail = f"account {user} has a set password hash"
            yield _Hit(rel, m.start("hash"), h, "crypt_hash",
                       detail + f"; {algo}")'''),
 ('''        count = 1 + len(siblings)
        plural = f" ({count} occurrences)" if count > 1 else ""''',
  '''        count = 1 + len(siblings)
        plural = f" ({count} occurrences)" if count > 1 else ""
        details_all = [hit.detail, *(s.detail for s in siblings)]
        hidden_root = sum(1 for d in details_all
                          if "uid 0 -- root-equivalent" in d)
        if hidden_root:
            plural = (f" ({count} accounts, {hidden_root} of them "
                      f"root-equivalent)")'''),
 ('''        }[hit.kind]''',
  '''        }[hit.kind]
        joined = " ".join([hit.detail, *(s.detail for s in siblings)])
        if "uid 0 -- root-equivalent" in joined and "DES" in joined:
            severity = Severity.CRITICAL'''),
], "root-equivalent", 3)

# --------------------------------------------------------------- services
edit("sentinel/firmware/analyzers/services.py", [
 ('''PORT_RE = re.compile(''',
  '''def _is_text_config(raw: bytes) -> bool:
    """
    Reject anything that is not a plain-text script or config.

    /init and /sbin/init are symlinks to busybox on most embedded images, and
    busybox embeds a table of every applet it was compiled with. Treating
    that as init configuration "discovers" telnetd, ftpd and httpd on every
    busybox image ever built, whether or not any of them start.
    """
    if raw[:4] == b"\\x7fELF":
        return False
    head = raw[:4096]
    if b"\\x00" in head:
        return False
    nonprint = sum(1 for b in head if b < 9 or (13 < b < 32) or b > 126)
    return nonprint <= len(head) * 0.05


PORT_RE = re.compile('''),
 ('''            for f in files:
                try:
                    text = f.read_text("utf-8", "replace")
                except OSError:
                    continue
                self._scan_text(text, f, rootfs, services)''',
  '''            for f in files:
                try:
                    raw = f.read_bytes()
                except OSError:
                    continue
                if not _is_text_config(raw):
                    continue
                self._scan_text(raw.decode("utf-8", "replace"), f, rootfs,
                                services)'''),
], "_is_text_config", 2)

# ------------------------------------------------------------- smoke test
# The old assertion searched context["details"], which records the KEY name
# and never the captured value -- so it passed whether or not the bug was
# present. Assert on the occurrence count instead, which does move.
edit("smoke_test.py", [
 ('''check("an empty-valued key does NOT capture the next line",
      not any("ses_cl_enable" in str(x.context.get("details", ""))
              or "pppoe_service" in str(x.context.get("details", ""))
              for x in findings))''',
  '''nv = [x for x in findings if x.target.endswith("nvram_default.cfg")]
check("the .cfg yields exactly one finding (the real secret)", len(nv) == 1)
check("empty-valued keys did NOT capture the following line",
      bool(nv) and nv[0].context.get("occurrences") == 1)'''),
], "occurrences\") == 1", 1)

sys.exit(0 if ok else 1)
