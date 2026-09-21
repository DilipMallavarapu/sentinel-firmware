#!/usr/bin/env python3
"""
Report service-discovery coverage: name the daemons present that no init
config starts, instead of a silent zero. Idempotent.
"""
import pathlib, re, sys
ok = True

ORPHAN_BLOCK = '    def orphan_binaries(self, services, rootfs):\n        """\n        Service binaries present in the image that no init config mentions.\n\n        The honest answer to a hard limit. Tenda and many other vendors start\n        their daemons from compiled code -- /init is busybox, rcS hands off to\n        a proprietary supervisor, and nothing in any text file names httpd.\n        Static config parsing cannot follow that, and reporting "0 services"\n        silently implies the device has no network surface, which is the most\n        dangerous output this analyzer can produce.\n\n        So: name the binaries we can see, say we could not find what starts\n        them, and point at the stage that can answer it.\n        """\n        named = {s.name for s in services}\n        found = []\n        for entry in rootfs.walk(max_size=32 << 20):\n            base = entry.rel.rsplit("/", 1)[-1]\n            if base not in SERVICE_BINARIES or base in named:\n                continue\n            if entry.is_symlink or not entry.executable:\n                continue\n            found.append(entry.rel)\n        return sorted(set(found))\n\n    def coverage_finding(self, orphans, services, rootfs, ctx):\n        if not orphans:\n            return None\n        return Finding(\n            detector_id="fw.services.unexplained",\n            title=(f"{len(orphans)} service binaries present that no init "\n                   f"configuration starts"),\n            severity=Severity.INFO,\n            axis=Axis.PRESENCE,\n            target=str(rootfs.root.name),\n            summary=(\n                "These daemons are in the image but nothing in any readable "\n                "init script, inittab or config references them, so this "\n                "analyzer cannot say whether they run, on which ports, or as "\n                "which user. Where /init is busybox and startup is driven "\n                "from compiled code, that is expected rather than a parsing "\n                "failure. Treat the attack surface as unknown, not absent, "\n                "and resolve it by emulating the image or by reversing "\n                "whatever rcS hands control to."\n            ),\n            confidence=Confidence.PROBABLE,\n            context={\n                "locus": {"scope": "image", "check": "service_coverage"},\n                "unexplained_binaries": orphans[:40],\n                "explained_services": [s.name for s in services],\n            },\n            triage_notes=["coverage gap, not a vulnerability; it marks where "\n                          "static analysis stops"],\n        )\n\n'

def load(path):
    p = pathlib.Path(path)
    if not p.is_file():
        print(f"  MISSING {path}")
        return None, None
    return p, p.read_text()

# ---- services.py -------------------------------------------------------
p, s = load("sentinel/firmware/analyzers/services.py")
if s is None:
    ok = False
elif "def orphan_binaries" in s:
    print("  services.py: already has orphan_binaries")
else:
    anchor = "    def findings(self, services"
    if anchor not in s:
        print("  services.py: NO MATCH on findings() anchor"); ok = False
    else:
        s = s.replace(anchor, ORPHAN_BLOCK + anchor, 1)
        p.write_text(s)
        print("  services.py: orphan_binaries added")

# ---- pipeline.py -------------------------------------------------------
p, t = load("sentinel/firmware/pipeline.py")
if t is None:
    ok = False
elif "orphan_binaries" in t:
    print("  pipeline.py: already wired")
else:
    old_call = "    findings = list(an.findings(services, rfs, _ctx(run)))"
    new_call = (
        "    ctx = _ctx(run)\n"
        "    findings = list(an.findings(services, rfs, ctx))\n"
        "    orphans = an.orphan_binaries(services, rfs)\n"
        "    gap = an.coverage_finding(orphans, services, rfs, ctx)\n"
        "    if gap:\n"
        "        findings.append(gap)")
    if old_call not in t:
        print("  pipeline.py: NO MATCH on findings() call"); ok = False
    else:
        t = t.replace(old_call, new_call, 1)
        # The note line is regex-matched because its exact text has drifted.
        t2, n = re.subn(
            r'note=f"\{len\(services\)\} services; web: [^\n]*\)',
            ('note=(f"{len(services)} started by config; web: "\n'
             '             f"{\', \'.join(web) or \'none\'}"\n'
             '             + (f"; {len(orphans)} service binaries unexplained"\n'
             '                if orphans else "")))'),
            t, count=1)
        if n == 0:
            print("  pipeline.py: note line not updated (cosmetic only)")
        t = t2
        p.write_text(t)
        print("  pipeline.py: wired")

sys.exit(0 if ok else 1)
