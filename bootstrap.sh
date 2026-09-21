#!/usr/bin/env bash
# Run once, from the directory holding the flat downloaded files.
# Moves everything into the package layout the relative imports expect,
# creates the __init__ files, and builds a fixture so the smoke test runs.
set -euo pipefail

# WSL materialises the NTFS alternate data stream as a literal file whose
# name contains a colon. The separator is ':' not '.', which is why
# `rm *.Zone.Identifier` found nothing.
rm -f -- *:Zone.Identifier 2>/dev/null || true

mkdir -p sentinel/core sentinel/firmware/analyzers sentinel/templates go/elfscan ui images runs bin

mv -f contracts.py verifiers.py checkpoint.py goworker.py  sentinel/core/          2>/dev/null || true
mv -f models.py unpack.py pipeline.py                      sentinel/firmware/      2>/dev/null || true
mv -f secrets.py hardening.py services.py                  sentinel/firmware/analyzers/ 2>/dev/null || true
mv -f cli.py                                               sentinel/              2>/dev/null || true
mv -f SCHEMA.md                                            sentinel/templates/     2>/dev/null || true
mv -f main.go                                              go/elfscan/             2>/dev/null || true
mv -f firmware_run.html                                    ui/                     2>/dev/null || true

echo '"""Sentinel."""' > sentinel/__init__.py
echo '"""Sentinel."""' > sentinel/firmware/__init__.py
echo '"""Sentinel."""' > sentinel/firmware/analyzers/__init__.py
cat > sentinel/core/__init__.py <<'PY'
"""Sentinel core contracts, shared by the web and firmware lanes."""
from . import verifiers as _verifiers  # noqa: F401  (registers proof verifiers)
PY

[ -f go/go.mod ] || (cd go && go mod init sentinel/go >/dev/null 2>&1) || true

# --- fixture -----------------------------------------------------------
# A synthetic rootfs carrying one of each thing the detectors must catch,
# and one of each thing they must NOT call a finding. The false-positive
# cases matter more than the true ones: they are what the test is for.
FX=fixture/rootfs
rm -rf fixture
for d in bin sbin etc/init.d usr/sbin lib docs; do mkdir -p "$FX/$d"; done

printf 'root:$1$Vr3Kq2xZ$8Qk1mZ0pW9sLdN2cXbYvA1:0:0:99999:7:::\n' >  "$FX/etc/shadow"
printf 'daemon:*:1:1:99999:7:::\nnobody:!:2:2:99999:7:::\n'       >> "$FX/etc/shadow"
printf 'root:x:0:0:root:/root:/bin/sh\n'                           >  "$FX/etc/passwd"
printf '#!/bin/sh\n/sbin/telnetd -p 23 &\n/usr/sbin/lighttpd -f /etc/lighttpd.conf -u root &\n# dropbear disabled\n' > "$FX/etc/init.d/rcS"
printf 'server.port = 8080\nadmin_password = "Sup3rS3cretDeviceKey"\n'  > "$FX/etc/lighttpd.conf"
printf 'Example config:\n  admin_password = "changeme"\nSample: root:$1$abcdefgh$0123456789abcdefghijkl:0:0:::\n' > "$FX/docs/README.md"
touch "$FX/lib/ld-uClibc.so.0" "$FX/sbin/telnetd" "$FX/usr/sbin/lighttpd"

python3 - "$FX" <<'PY'
import base64, os, struct, sys, pathlib
fx = pathlib.Path(sys.argv[1])
b = base64.b64encode(os.urandom(700)).decode()
(fx/"etc/device_key.pem").write_text(
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(b[i:i+64] for i in range(0, len(b), 64))
    + "\n-----END RSA PRIVATE KEY-----\n")
h = bytearray(64); h[0:4] = b"\x7fELF"; h[4]=1; h[5]=1; h[6]=1
struct.pack_into("<H", h, 16, 2)      # ET_EXEC
struct.pack_into("<H", h, 18, 0x28)   # EM_ARM
(fx/"bin/busybox").write_bytes(bytes(h) + b"\x00"*200)
PY

echo
echo "layout:"
find sentinel go ui -type f | sort | sed 's/^/  /'
echo
echo "next:"
echo "  python3 smoke_test.py            # 22 checks, no dependencies"
echo "  go build -o bin/elfscan ./go/elfscan"
