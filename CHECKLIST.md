## Firmware assessment checklist

What a complete pass over an image covers, and how much of it Sentinel does
for you.

Coverage marks:

- **auto** — a stage produces findings for this with no input from you
- **partial** — the stage finds some of it; the rest needs your eyes
- **manual** — the tool gives you material to work from, nothing more

The manual items are not a backlog. Several of them cannot be automated in
principle, and a scanner that claimed to cover them would be lying. Knowing
which is which is the point of this document.

---

## 1. Acquisition and integrity

| | check | why |
|---|---|---|
| auto | SHA-256 of the image, recorded in the report | Makes the run citable. Every finding is bound to a specific file. |
| auto | Image hash matches the authorization scope | The run refuses an image you are not cleared to analyse. |
| auto | High-entropy regions with no recognised filesystem | Encrypted image. A scanner that returns nothing here has failed silently, so it is flagged loudly. |
| manual | Where did the image come from? | Vendor download, flash dump, update capture, and OTA interception all imply different scopes and different legal footing. |
| manual | Is the image signed? Is the signature checked on-device? | An unsigned image on a device that accepts it is the whole ballgame. Needs the bootloader, not the rootfs. |
| manual | Does the update channel use TLS, and is the cert pinned? | Requires traffic capture. |

## 2. Extraction

| | check | why |
|---|---|---|
| auto | Filesystem identification and extraction (unblob → binwalk → carve) | |
| auto | Root filesystem scored, not guessed | Vendor images produce a dozen candidate directories; picking wrong means every later stage reports nothing and the run looks clean. |
| auto | Architecture, endianness, libc, init system | Decides which emulation path is viable. |
| auto | Fragment warning when the "rootfs" has under two top-level dirs | A clean report from an extraction fragment is the worst output this tool can produce. |
| partial | What did **not** extract | Partition list records offsets and kinds, but unextracted regions are yours to chase. Second filesystems, recovery images and kernel blobs hide here. |
| manual | Multiple firmware versions diffed | Comparing two releases is the fastest route to "what did they just patch, and why". |

## 3. Credentials and key material

| | check | why |
|---|---|---|
| auto | crypt hashes in `passwd` / `shadow`, with uid and algorithm named | A non-root account at uid 0 is root under another name. A 13-char DES hash falls to a wordlist regardless of what it protects. |
| auto | Locked accounts (`*`, `!`) and `x` placeholders rejected | Not credentials. |
| auto | Embedded private keys, PEM body validated as decodable base64 | |
| auto | Literal credential assignments in config files | Markup, script, comments and shell substitutions are rejected structurally. |
| auto | Published upstream defaults demoted to INFO and named | `root:0penBmc` is documented; calling it HIGH costs credibility with a maintainer who knows their own image. |
| partial | Default WPA PSKs, API tokens, cloud credentials | Caught when they use a recognised key name. A vendor-specific name will be missed — extend `CONFIG_CRED_RE`. |
| manual | Are the keys unique per device or shared across the fleet? | Needs two devices. A shared key is a fleet-wide compromise; a unique one is one device. |
| manual | Certificate validity, CA reuse, self-signed leaf accepted by clients | |

## 4. Backdoor and implant hunting

The category with the least automation, because a backdoor is defined by
intent and intent is not a byte pattern. What the tool gives you is the
inventory; the judgement is yours.

| | check | why |
|---|---|---|
| auto | Undocumented uid-0 accounts | The most common real backdoor in consumer firmware, and it looks exactly like sloppiness. |
| auto | Service binaries present that no init config starts | On a compiled-startup image this is expected. On a systemd image with real units, a daemon nothing references is worth explaining. |
| auto | setuid binaries, flagged in the ELF inventory | |
| manual | `~root/.ssh/authorized_keys` and any `authorized_keys` in the image | A key shipped in firmware is remote root for whoever holds the private half. Check this by hand on every image. |
| manual | Hardcoded IPs and hostnames in network-facing binaries | `strings` the daemons. A device that phones a fixed address is telling you something. |
| manual | Magic values in authentication paths | A comparison against a constant that bypasses the normal check. Only visible in disassembly. |
| manual | Undocumented CGI endpoints not linked from the web UI | Diff the handler table in the binary against what the UI references. |
| manual | Debug and factory modes gated on an nvram variable | `telnetd` started when `factory_mode=1` is a backdoor with a switch. Grep init scripts for conditional service starts. |
| manual | Init scripts or cron jobs fetching and executing remote content | |
| manual | Kernel modules not present in the upstream tree | A vendor `.ko` doing packet inspection deserves a read. |
| manual | Accounts whose shell is not `nologin` but have no documented purpose | |

Practical order: run the tool, read the uid-0 and orphan-service findings,
then spend your manual time on `authorized_keys`, conditional service starts
in init scripts, and `strings` on the network daemons. That covers most of
what is actually found in the field.

## 5. Attack surface

| | check | why |
|---|---|---|
| auto | Services started by init config, with port and running user | |
| auto | Web services running as root flagged separately | |
| auto | Coverage gap reported when binaries exist that no config starts | Silence would imply no attack surface. |
| partial | Web root inventory: CGI binaries, upload handlers, auth pages | `discover_cgi()` ranks them; reading them is yours. |
| manual | D-Bus policy files — who may call what | On OpenBMC this is where privilege boundaries actually live. |
| manual | IPC: unix sockets, shared memory, netlink consumers | |
| manual | Physical: UART pinout, JTAG, SPI flash readback | Different discipline, same target. |

## 6. Memory safety and hardening

| | check | why |
|---|---|---|
| auto | NX, PIE, stack canary, RELRO, FORTIFY across every ELF | ~800 binaries/second. |
| auto | Image-wide aggregate below 80% coverage | A toolchain default is one flag change, not N code changes. Reported once, not per binary. |
| auto | Individually flagged when network-facing or setuid **and** unhardened | |
| auto | Unparseable files excluded, with a coverage count | A parse failure is not a mitigation gap. |
| partial | Risky libc imports attached as review context | `strcpy` in a binary is not a bug. Listed to steer manual review, never a finding on its own. |
| manual | Actual memory-safety bugs in request handlers | Needs disassembly or fuzzing. The hardening data tells you which binary to start with. |
| manual | Fuzzing the network daemons | Once emulation boots, the daemons are reachable and AFL++ in qemu mode becomes viable. |

## 7. Known vulnerabilities

| | check | why |
|---|---|---|
| partial | Component and version strings → CVE candidates | Stays at `candidate` tier permanently. "This binary reports BusyBox 1.29" is a fact; "this device is vulnerable to CVE-X" is not. |
| manual | Is the vulnerable code path actually built in? | Distros disable features. Version matching without a build check produces the noise that makes SBOM output unreadable. |
| manual | Backported patches with no version bump | Vendors patch without changing the string, so a version match is a hypothesis. |

## 8. Runtime, once it boots

| | check | why |
|---|---|---|
| auto | Boot under QEMU for modelled boards, network restricted to one port | |
| auto | Auth boundary: which endpoints answer unauthenticated | The first detector that can claim reachability. |
| auto | Spec-public endpoints allowlisted by exact path | Flagging the Redfish service root is reporting the standard as a bug. |
| partial | CGI reachability via user-mode emulation | Establishes that a handler runs and reflects input. The foothold, not the finding. |
| manual | Authenticated surface: what a low-privilege account can reach | |
| manual | Session handling, token entropy, fixation | |
| manual | Injection classes against live handlers | The harness measures; you supply the probe. |

## 9. Before you report

| | check |
|---|---|
| auto | Every confirmed proof re-verified offline at inspect time |
| auto | Values redacted from `report.json`, kept in the blob store |
| manual | Each confirmed finding eyeballed once — open the file, look at the offset, agree |
| manual | Published defaults separated from vendor-baked secrets |
| manual | Presence findings not written up as though they were exploitable |
| manual | Disclosure scope confirmed against the authorization reference |

The eyeball pass is not optional. Every false-positive class this tool
handles was found by looking at real output and disagreeing with it — none
came from the fixture. On a new vendor, assume there is a class nobody has
hit yet, and read the confirmed tier before you trust it.

---

## The short version

A run gives you, with no input beyond a path:

- image identity and scope binding
- extraction, architecture, init system
- credentials with uid and algorithm context
- services, ports, running users, and an explicit coverage gap
- exploit-mitigation posture image-wide and per binary
- where the board is modelled: a booted device and its auth boundary

What it will not give you, and where the real bugs usually are:

- `authorized_keys` shipped in the image
- services started conditionally on a factory or debug flag
- hardcoded endpoints in the network daemons
- magic-value auth bypasses in disassembly
- memory-safety bugs in the handlers the hardening data points at

Run the tool first. It takes minutes and it tells you where to spend the
days.
