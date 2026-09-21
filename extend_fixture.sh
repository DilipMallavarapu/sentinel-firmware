#!/usr/bin/env bash
# Adds the Tenda-derived regression cases to the fixture rootfs.
# Run from the repo root, once, before the updated smoke_test.py.
set -euo pipefail
FX=fixture/rootfs
mkdir -p "$FX/bin" "$FX/sbin" "$FX/lib" "$FX/docs" "$FX/usr/sbin" \
         "$FX/etc/init.d" "$FX/webroot_ro" "$FX/etc_ro/init.d"

# The exact false-positive shape from webroot_ro/main.html: JavaScript that
# satisfies a key=value credential pattern while containing no secret.
cat > "$FX/webroot_ro/main.html" <<'HTML'
<html><script>
function doLogin(){
  var password = document.getElementById("pwd").value;
  $.post("/login.cgi", {password: $("#pwd").val(), user: form.user.value});
  if (password.length < 6) { alert("too short"); }
}
var admin_password = form.admin.value;
</script></html>
HTML

# A real secret sitting in the same directory, to prove the fix did not just
# blanket-exclude the web root.
cat > "$FX/webroot_ro/nvram_default.cfg" <<'CFG'
wl0_wpa_psk=RealDeviceSecret42
http_passwd=admin
sys_password=$(nvram get pw)
CFG

printf 'root:$1$Tt7Kk2xZ$9Zk1mZ0pW9sLdN2cXbYvB2:0:0:root:/root:/bin/sh\nsupport:$1$Ab3Cd4ef$1Zk1mZ0pW9sLdN2cXbYvC3:0:0:support:/:/bin/sh\nnobody:*:99:99:nobody:/:/bin/false\n' > "$FX/etc_ro/passwd"
printf '#!/bin/sh\n/bin/telnetd &\n/usr/sbin/httpd -p 8080 &\n' > "$FX/etc_ro/init.d/rcS"
printf '#!/bin/sh\nexec /sbin/init\n' > "$FX/init"; chmod +x "$FX/init"

# "changeme" is a placeholder and is correctly skipped, so the doc-path
# demotion needs a real-shaped value to exercise it.
printf 'Example config:\n  admin_password = "ExampleOnlyN0tReal"\nSample: root:$1$abcdefgh$0123456789abcdefghijkl:0:0:::\n' > "$FX/docs/README.md"

python3 -c "
import struct,pathlib
h=bytearray(64); h[0:4]=b'\x7fELF'; h[4]=h[5]=h[6]=1
struct.pack_into('<H',h,16,2); struct.pack_into('<H',h,18,0x28)
struct.pack_into('<I',h,20,1)
pathlib.Path('$FX/bin/busybox').write_bytes(bytes(h)+b'\x00'*200)"
echo "fixture extended"

# Tenda AC6: admin/support/user all at uid 0, most on 13-char DES hashes.
# Added by hand during development and never written here, so a clean clone
# failed the uid-0 and CRITICAL-escalation checks.
printf 'admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh\n' >> "$FX/etc_ro/passwd"

# A daemon that exists but nothing starts, so orphan_binaries has a subject.
# rcS mentions dropbear only in a comment, which the scanner skips.
printf '#!/bin/sh\nexit 0\n' > "$FX/usr/sbin/dropbear"
chmod +x "$FX/usr/sbin/dropbear"
