# Detector template schema

Two ways to write a detector. Pick by how the finding gets proved, not by
how hard the vulnerability class sounds.

**Declarative YAML** — when the proof is a byte match, a validated pattern,
or a control/probe differential the engine can run for you. This covers most
of the OWASP catalogue and nearly all firmware presence checks. No code.

**Python or Go plugin** — when the detector needs real logic: multi-step
auth flows, taint reasoning across CGI parameters, anything stateful. The
plugin implements the same `Detector` protocol and is held to the same rule:
declare `can_confirm: true` and you must also supply a proof kind that has a
registered verifier, or the registry refuses to load you.

---

## The `oracle` block is the whole point

Everything above `oracle` is targeting. `oracle` is what separates a finding
from a guess, and a template without one is capped at `candidate` forever.
Writing it is the hard part of authoring a detector, and if you cannot write
one, say so in `confidence_ceiling` rather than inventing a signature that
will fire on production traffic.

```yaml
id: web.sqli.boolean
name: Boolean-differential SQL injection
lane: web
severity: high
axis: reachability
owasp: "A03:2021"
cwe: CWE-89

match:
  targets: [query_param, form_field, json_field, header]
  skip_if:
    - param_name_matches: "^(csrf|nonce|_token|signature)$"   # breaking these
                                                              # changes the
                                                              # response for
                                                              # boring reasons

oracle:
  kind: differential
  # Two controls, not one. If the two controls already differ, the endpoint
  # is noisy and the finding is void. This single rule removes most of the
  # blind-injection false positives people accept as unavoidable.
  requests:
    - id: control_a
      mutate: {append: "' AND '1'='1"}
    - id: control_b
      mutate: {append: "' AND '1'='1"}
    - id: probe
      mutate: {append: "' AND '1'='2"}
  dimension: length
  min_delta: 48
  # Both controls and the probe body are stored as blobs. The proof is
  # re-checkable offline forever.

confidence_ceiling: confirmed
references:
  - https://owasp.org/Top10/A03_2021-Injection/
```

```yaml
id: fw.tls.embedded_cert
name: Embedded TLS private key
lane: firmware
severity: critical
axis: presence          # presence only: we do not claim the key is in use

match:
  paths: ["etc/**", "usr/**", "www/**"]
  max_size: 2097152

oracle:
  kind: pattern_match
  pattern: "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----([A-Za-z0-9+/=\\s]{100,})-----END"
  validator: pem_block   # the base64 body must actually decode to >=64 bytes
  refute_if_sha256_in: known_benign_keys.txt

confidence_ceiling: confirmed
```

## Field reference

| field | meaning |
|---|---|
| `axis` | `presence` or `reachability`. A template that only reads files may not declare `reachability`; the loader rejects it. |
| `match.skip_if` | Negative targeting. Cheaper and more honest than filtering results afterwards. |
| `oracle.kind` | One of the registered proof kinds: `byte_match`, `pattern_match`, `differential`, `oob_callback`, `runtime_diff`, `sbom_pin`. |
| `oracle.validator` | Structural check on the match. Required for `pattern_match` to reach `confirmed` — a regex alone never confirms anything. |
| `refute_if_sha256_in` | Known-benign list. A refutation list beats a confidence penalty: it is explicit, auditable, and it does not quietly suppress a real hit. |
| `confidence_ceiling` | The highest tier this template can reach. Set it to `candidate` for version-match templates and mean it. |

## Authoring order for the OWASP catalogue

Work by oracle type, not by OWASP number. Every template that shares an
oracle shares its test harness, so building in this order means each batch is
cheap after the first:

1. **`byte_match` / `pattern_match`** — secrets, exposed files, misconfigured
   headers, cookie flags, directory listing. Static, deterministic, and the
   fastest route to a large confirmed catalogue.
2. **`differential`** — SQLi, command injection reflection, auth bypass,
   IDOR/BOLA. Reuses one control/probe harness across all of them.
3. **`oob_callback`** — SSRF, blind XXE, blind command injection, log4shell
   class issues. Needs the canary service; one integration, many templates.
4. **`runtime_diff`** — everything that only means something against a live
   or emulated target. Last, because it depends on the emulation lane.

A template with no oracle is not a detector. It is a hunch with a filename.
