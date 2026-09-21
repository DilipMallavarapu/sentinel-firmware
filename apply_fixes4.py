#!/usr/bin/env python3
"""
Reject commented-out config lines, and resolve systemd binary paths from
ExecStart rather than from whichever directive happens to mention a path.
Both found against a stock OpenBMC Romulus image. Idempotent.
"""
import pathlib, sys
ok = True

def edit(path, pairs, marker, want):
    global ok
    p = pathlib.Path(path)
    if not p.is_file():
        print(f"  MISSING {path}"); ok = False; return
    s = p.read_text()
    for old, new in pairs:
        if new in s:
            continue
        if old not in s:
            print(f"  NO MATCH in {path}: {old.splitlines()[0][:55]}")
            ok = False; continue
        s = s.replace(old, new, 1)
    p.write_text(s)
    got = s.count(marker)
    print(f"  {path}: {marker} x{got} {'ok' if got >= want else 'FAILED'}")
    if got < want: ok = False

edit("sentinel/firmware/analyzers/secrets.py", [
 ('''def _is_literal_secret(val: bytes) -> bool:''',
  '''def _line_is_commented(data: bytes, pos: int) -> bool:
    """
    True when the match sits on a commented-out line.

    Stock openssl.cnf ships `# input_password = secret` as documentation, and
    reporting that as a hardcoded credential is the same error class as
    matching JavaScript: the bytes are real, the claim is not. Checks only
    the text between the line start and the match, so a `#` appearing later
    as part of a value does not disqualify it.
    """
    start = data.rfind(b"\\n", 0, pos) + 1
    prefix = data[start:pos].lstrip()
    return prefix[:1] in (b"#", b";") or prefix[:2] == b"//"


def _is_literal_secret(val: bytes) -> bool:'''),
 ('''            if not _is_literal_secret(val):
                continue''',
  '''            if not _is_literal_secret(val):
                continue
            if _line_is_commented(data, m.start()):
                continue'''),
], "_line_is_commented", 2)

edit("sentinel/firmware/analyzers/services.py", [
 # systemd names the daemon on ExecStart. Other directives carry paths for
 # entirely different reasons -- TemporaryFileSystem=/tmp/bmcweb is a
 # sandboxing option, and reading it as the service binary reports the
 # hardening measure as if it were the executable.
 ('''                bm = re.search(rf"(/\\S*{re.escape(name)})\\b", stripped)
                if bm:
                    svc.binary = bm.group(1)''',
  '''                lower = stripped.lower()
                if lower.startswith(("execstart", "execstartpre")):
                    em = re.search(r"=\\s*[-@+!]*(/\\S+)", stripped)
                    if em:
                        svc.binary = em.group(1)
                elif not any(lower.startswith(d) for d in _PATH_DIRECTIVES):
                    bm = re.search(rf"(/\\S*{re.escape(name)})\\b", stripped)
                    if bm and not svc.binary:
                        svc.binary = bm.group(1)'''),
 ('''PORT_RE = re.compile(''',
  '''# systemd directives whose paths are never the service executable. Several
# are sandboxing options, so mistaking them for the binary reports a
# hardening measure as the thing being hardened.
_PATH_DIRECTIVES = (
    "temporaryfilesystem", "bindpaths", "bindreadonlypaths", "readwritepaths",
    "readonlypaths", "inaccessiblepaths", "runtimedirectory", "statedirectory",
    "cachedirectory", "logsdirectory", "configurationdirectory",
    "workingdirectory", "rootdirectory", "rootimage", "environmentfile",
    "pidfile", "conditionpathexists", "requiresmountsfor", "what", "where",
)


PORT_RE = re.compile('''),
], "_PATH_DIRECTIVES", 2)

sys.exit(0 if ok else 1)
