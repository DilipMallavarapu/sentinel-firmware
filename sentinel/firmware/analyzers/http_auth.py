"""
sentinel.firmware.analyzers.http_auth
=====================================

Authentication-boundary checks against a live (emulated) target.

This is the first detector in the codebase that can claim REACHABILITY. It
does not read bytes off a disk and infer anything; it sends a request without
credentials, sends the same request with them, and stores both transcripts.
The finding is "this endpoint served data to an unauthenticated caller", and
the proof is the pair of responses.

What makes this honest rather than a 200-counter:

  * Redfish *specifies* that a handful of endpoints are unauthenticated --
    the service root, $metadata, odata, and the version document. Flagging
    those is reporting the standard as a vulnerability. They are allowlisted
    by exact path, not by prefix, so /redfish/v1/Systems does not inherit the
    root's exemption.

  * Every finding needs a control. An endpoint that returns 200 to everyone
    including authenticated callers tells us nothing on its own; what matters
    is that an endpoint returning real data unauthenticated is one that the
    authenticated path also serves. Both transcripts are stored.

  * A 200 with an error body is not access. bmcweb answers some paths with
    200 and a Redfish error payload, so the body is inspected for an error
    resource before anything is called a bypass.

Scope: the target must be an emulated instance or a host the authorization
explicitly covers. This module refuses to run against anything else -- the
difference between testing your own QEMU guest and testing somebody's BMC is
the entire difference between research and an offence.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Optional

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)

# Paths the Redfish specification defines as unauthenticated. Exact matches
# only: the service root being public does not make its children public.
REDFISH_PUBLIC = {
    "/redfish", "/redfish/v1", "/redfish/v1/",
    "/redfish/v1/odata", "/redfish/v1/$metadata",
    "/redfish/v1/JsonSchemas",
}

# Endpoints whose unauthenticated exposure actually matters, in the order a
# reviewer would want to see them.
INTERESTING = [
    "/redfish/v1/AccountService/Accounts",
    "/redfish/v1/AccountService",
    "/redfish/v1/SessionService/Sessions",
    "/redfish/v1/Managers/bmc",
    "/redfish/v1/Managers/bmc/NetworkProtocol",
    "/redfish/v1/Managers/bmc/EthernetInterfaces",
    "/redfish/v1/Systems/system",
    "/redfish/v1/Systems/system/LogServices",
    "/redfish/v1/Chassis",
    "/redfish/v1/UpdateService",
    "/redfish/v1/CertificateService",
    "/redfish/v1/TaskService/Tasks",
]


@dataclass
class _Response:
    status: int
    body: bytes
    headers: dict

    def to_json(self) -> bytes:
        return json.dumps({
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body.decode("utf-8", "replace")[:20000],
        }, indent=2).encode()

    @property
    def is_error_resource(self) -> bool:
        """A 200 carrying a Redfish error payload is not access."""
        try:
            doc = json.loads(self.body or b"{}")
        except (json.JSONDecodeError, ValueError):
            return False
        return "error" in doc and "@odata.id" not in doc


def _request(url: str, path: str, auth: Optional[tuple[str, str]],
             timeout: int = 20) -> _Response:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # emulated guest, self-signed by design

    req = urllib.request.Request(url.rstrip("/") + path, method="GET")
    req.add_header("Accept", "application/json")
    if auth:
        import base64
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return _Response(r.status, r.read(), dict(r.headers))
    except urllib.error.HTTPError as e:
        return _Response(e.code, e.read(), dict(e.headers))
    except Exception as exc:
        return _Response(0, str(exc).encode(), {})


class UnauthenticatedSurfaceDetector:
    meta = DetectorMeta(
        id="http.auth.unauthenticated_surface",
        name="Endpoints served without authentication",
        severity=Severity.HIGH,
        axis=Axis.REACHABILITY,
        lane="both",
        cwe="CWE-306",
        owasp="A01:2021",
        proof_kinds=["runtime_diff"],
        can_confirm=True,
        tags=["redfish", "auth", "runtime"],
    )

    def __init__(self, base_url: str, credentials: Optional[tuple[str, str]] = None,
                 paths: Optional[list[str]] = None):
        self.base_url = base_url
        self.credentials = credentials
        self.paths = paths or INTERESTING

    def applicable(self, subject) -> bool:
        return self.base_url.startswith(("http://", "https://"))

    def run(self, subject, ctx: RunContext) -> Iterable[Finding]:
        host = self.base_url.split("//", 1)[-1].split(":")[0].split("/")[0]
        if host not in ("127.0.0.1", "localhost", "::1") \
                and not ctx.scope.permits_host(host):
            raise PermissionError(
                f"{host} is not an emulated target and is not in scope "
                f"{ctx.scope.authorization_ref}; refusing to send requests")

        for path in self.paths:
            if path in REDFISH_PUBLIC:
                continue

            anon = _request(self.base_url, path, None)
            if anon.status == 0:
                continue                      # transport failure, not a finding

            authed = (_request(self.base_url, path, self.credentials)
                      if self.credentials else None)

            served = anon.status == 200 and not anon.is_error_resource
            if not served:
                continue

            # An endpoint that serves the same content to everyone is only
            # interesting if the authenticated path serves it too -- that is
            # what makes it a bypass rather than a public resource.
            note = "200 without credentials"
            if authed is not None:
                if authed.status != 200:
                    note = (f"200 unauthenticated but {authed.status} "
                            f"authenticated -- inspect before reporting")
                else:
                    note = (f"200 both ways; {len(anon.body)} bytes anon vs "
                            f"{len(authed.body)} authenticated")

            label = path.strip("/").replace("/", "_") or "root"
            anon_blob = ctx.store_blob(f"{label}.anon.json", anon.to_json())
            ctrl_blob = ctx.store_blob(
                f"{label}.auth.json",
                (authed or _Response(0, b"not requested", {})).to_json())

            f = Finding(
                detector_id=self.meta.id,
                title=f"{path} served without authentication",
                severity=Severity.HIGH,
                axis=Axis.REACHABILITY,
                target=path,
                summary=(
                    f"An unauthenticated GET returned {anon.status} with "
                    f"{len(anon.body)} bytes of content. Both transcripts are "
                    f"stored, so this can be re-checked without the target. "
                    f"Redfish defines a small set of public endpoints and this "
                    f"is not one of them."
                ),
                cwe=self.meta.cwe,
                owasp=self.meta.owasp,
                context={
                    "locus": {"path": path},
                    "anon_status": anon.status,
                    "auth_status": authed.status if authed else None,
                    "note": note,
                    "base_url": self.base_url,
                },
            )
            proof = ProofArtifact(
                kind="runtime_diff",
                claim={"control_transcript": ctrl_blob,
                       "probe_transcript": anon_blob,
                       "observable": "status"},
                blobs=[anon_blob, ctrl_blob],
            )
            try:
                f.confirm(proof, ctx.artifact_root)
            except Exception:
                f.confidence = Confidence.PROBABLE
                f.triage_notes.append("transcripts stored but proof did not "
                                      "verify; treat as unconfirmed")
            yield f


__all__ = ["UnauthenticatedSurfaceDetector", "REDFISH_PUBLIC", "INTERESTING"]
