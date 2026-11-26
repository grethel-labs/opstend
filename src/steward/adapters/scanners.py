"""ScannerAdapter v1: OSV exact-version queries and Trivy digest-pinned images."""

from __future__ import annotations

import http.client
import json
import math
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from ..core.images import image_id
from ..core.process import CommandError, run_bounded
from ..core.tools import TRIVY_BINARY
from ..core.vulnerabilities import Advisory, Component, ScanError, ScanResult
from .notifications import _PinnedHTTPS, public_addresses, target

MAX_RESPONSE = 8 * 1024 * 1024


def retry_delay(value: str | None, *, now: float) -> float:
    try:
        delay = float(value)
    except (ValueError, TypeError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            delay = date.timestamp() - now
        except (ValueError, TypeError, OverflowError, AttributeError):
            return 60
    return min(3153600000, max(1, delay)) if math.isfinite(delay) else 60


def api(method: str, url: str, body: dict | None = None) -> dict:
    """Pinned public HTTPS, bounded JSON, no redirects/proxies or raw exceptions."""
    connection = None
    try:
        host, path = target(url)
        addresses = public_addresses(host)
        connection = _PinnedHTTPS(host, addresses[0])
        connection.request(
            method,
            path,
            json.dumps(body).encode() if body is not None else None,
            {"Content-Type": "application/json", "User-Agent": "steward-scanner/1"},
        )
        response = connection.getresponse()
        if response.status == 429:
            raise ScanError(
                "quota_exhausted",
                retry_after_s=retry_delay(response.getheader("Retry-After"), now=time.time()),
            )
        if response.status >= 500:
            raise ScanError("unavailable")
        if response.status != 200:
            raise ScanError("invalid_response")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ScanError("invalid_response")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ScanError("invalid_response")
        return value
    except TimeoutError:
        raise ScanError("timeout") from None
    except (OSError, http.client.HTTPException):
        raise ScanError("unavailable") from None
    except (ValueError, RecursionError):
        raise ScanError("invalid_response") from None
    finally:
        if connection:
            connection.close()


class ScannerAdapter(Protocol):
    version: int
    capabilities: tuple[str, ...]
    input_schema: dict
    timeout_s: int

    def health(self) -> dict: ...

    def scan(
        self, subjects: list[Component], *, inventory_revision: str, now: float
    ) -> list[ScanResult]: ...


def failed(source, subject, revision, now, error, findings=None):
    bounded, size = [], 0
    for finding in findings or []:
        size += len(finding.model_dump_json().encode())
        if size > 60000:
            break
        bounded.append(finding)
    return ScanResult(
        source=source,
        subject=subject,
        inventory_revision=revision,
        checked_at=now,
        state="unknown" if error == "unsupported" else "scan_failed",
        error_class=error,
        findings=bounded,
        complete=False,
    )


def severity(value: str) -> str:
    value = str(value).lower()
    return value if value in ("low", "medium", "high", "critical") else "unknown"


def osv_advisory(data: dict, subject: Component) -> Advisory | None:
    if data.get("withdrawn"):
        return None
    affected = [
        a
        for a in data.get("affected", [])
        if a.get("package", {}).get("ecosystem") == subject.ecosystem
        and a.get("package", {}).get("name", "").lower().replace("_", "-")
        == subject.name.lower().replace("_", "-")
    ]
    if not affected:
        raise ScanError("evidence_mismatch")
    rating = severity(data.get("database_specific", {}).get("severity", "unknown"))
    for item in data.get("severity", []):
        if item.get("type") == "Ubuntu":
            rating = severity(item.get("score"))
    fixes = sorted(
        {
            str(event["fixed"])
            for a in affected
            for r in a.get("ranges", [])
            for event in r.get("events", [])
            if "fixed" in event
        }
    )[:100]
    id = data["id"]
    return Advisory(
        id=id,
        aliases=data.get("aliases", [])[:100],
        severity=rating,
        summary=data.get("summary") or id,
        modified=data.get("modified"),
        affected_package=subject.name,
        installed_version=subject.version,
        fixed_versions=fixes,
        source_url=f"https://osv.dev/vulnerability/{id}",
    )


class OSV:
    version = 1
    capabilities = ("packages.exact_version", "vendor.backports", "dependencies")
    input_schema = Component.model_json_schema()
    timeout_s = 180

    def __init__(
        self,
        request: Callable = api,
        *,
        max_requests: int = 1000,
        monotonic: Callable | None = None,
    ):
        self.request, self.max_requests = request, max_requests
        self.monotonic = monotonic or time.monotonic

    def health(self) -> dict:
        return {"ready": True, "scope": "local_configuration", "network_checked": False}

    def scan(self, subjects, *, inventory_revision, now):
        started = self.monotonic()
        out, cache, used, deadline = [], {}, 0, started + self.timeout_s
        retry_after_s = None

        def request(method, path, body=None):
            nonlocal used, retry_after_s
            if retry_after_s is not None:
                raise ScanError("quota_exhausted", retry_after_s=retry_after_s)
            if used >= self.max_requests:
                raise ScanError("quota_exhausted")
            if self.monotonic() >= deadline:
                raise ScanError("timeout")
            used += 1
            try:
                return self.request(method, "https://api.osv.dev" + path, body)
            except ScanError as exc:
                if exc.error_class == "quota_exhausted":
                    retry_after_s = min(
                        3153600000, (exc.retry_after_s or 60) + max(0, self.monotonic() - started)
                    )
                raise

        for start in range(0, len(subjects), 100):
            batch = subjects[start : start + 100]
            supported = [s for s in batch if s.ecosystem and s.kind != "image"]
            out.extend(
                failed("osv", s, inventory_revision, now, "unsupported")
                for s in batch
                if s not in supported
            )
            if not supported:
                continue
            pending = {s.key: (s, None) for s in supported}
            found = {s.key: {} for s in supported}
            errors = {}
            for _ in range(10):
                if not pending:
                    break
                pairs = list(pending.values())
                queries = [
                    {
                        "package": {"name": s.name, "ecosystem": s.ecosystem},
                        "version": s.version,
                        **({"page_token": token} if token else {}),
                    }
                    for s, token in pairs
                ]
                try:
                    response = request("POST", "/v1/querybatch", {"queries": queries})
                    results = response.get("results")
                    if not isinstance(results, list) or len(results) != len(pairs):
                        raise ScanError("invalid_response")
                    next_page = {}
                    for (subject, old_token), result in zip(pairs, results, strict=True):
                        if not isinstance(result, dict) or not isinstance(
                            result.get("vulns", []), list
                        ):
                            raise ScanError("invalid_response")
                        for match in result.get("vulns", []):
                            id = match["id"]
                            if not isinstance(id, str) or not re.fullmatch(
                                r"[A-Za-z0-9._:-]{1,120}", id
                            ):
                                raise ScanError("invalid_response")
                            found[subject.key][id] = match
                            if len(found[subject.key]) > 1000:
                                raise ScanError("incomplete")
                        token = result.get("next_page_token")
                        if token:
                            if (
                                not isinstance(token, str)
                                or len(token) > 4096
                                or token == old_token
                            ):
                                raise ScanError("incomplete")
                            next_page[subject.key] = (subject, token)
                    pending = next_page
                except (ScanError, KeyError, TypeError, AttributeError) as exc:
                    error = exc.error_class if isinstance(exc, ScanError) else "invalid_response"
                    errors.update({s.key: error for s, _ in pairs})
                    pending = {}
                    break
            errors.update({key: "incomplete" for key in pending})
            for subject in supported:
                findings, findings_bytes = [], 0
                try:
                    if subject.key in errors:
                        raise ScanError(errors[subject.key])
                    for id in found[subject.key]:
                        data = cache.get(id)
                        if data is None:
                            data = request("GET", f"/v1/vulns/{id}")
                            if len(json.dumps(data).encode()) <= 65536:
                                if len(cache) >= 16:
                                    cache.pop(next(iter(cache)))
                                cache[id] = data
                        if data.get("id") != id:
                            raise ScanError("evidence_mismatch")
                        finding = osv_advisory(data, subject)
                        if finding:
                            findings.append(finding)
                            findings_bytes += len(finding.model_dump_json().encode())
                            if findings_bytes > 120000:
                                raise ScanError("incomplete")
                    out.append(
                        ScanResult(
                            source="osv",
                            subject=subject,
                            inventory_revision=inventory_revision,
                            checked_at=now,
                            state="confirmed" if findings else "not_affected",
                            findings=findings,
                            complete=True,
                        )
                    )
                except (ScanError, ValidationError, KeyError, TypeError, AttributeError) as exc:
                    error = exc.error_class if isinstance(exc, ScanError) else "invalid_response"
                    out.append(failed("osv", subject, inventory_revision, now, error, findings))
        for result in out:
            if result.error_class == "quota_exhausted":
                result.retry_after_s = retry_after_s or 60
        return out


class Trivy:
    version = 1
    capabilities = ("images.by_digest", "vendor.backports", "dependencies")
    input_schema = Component.model_json_schema()
    timeout_s = 180

    def __init__(
        self,
        binary: Path | None = None,
        cache: Path = Path("/var/cache/steward-scanner"),
    ):
        self.binary = binary or (TRIVY_BINARY if TRIVY_BINARY.is_file() else Path("/usr/bin/trivy"))
        self.cache = cache

    def health(self) -> dict:
        return {"ready": self.binary.is_file(), "scope": "local_binary", "network_checked": False}

    def _run(self, argv: list[str]) -> dict:
        try:
            raw = run_bounded(
                [str(self.binary), *argv],
                cwd=self.cache,
                env={"PATH": "/usr/bin:/bin", "HOME": str(self.cache)},
                timeout=self.timeout_s,
                max_bytes=MAX_RESPONSE,
            )
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ScanError("invalid_response")
            return value
        except CommandError as exc:
            raise ScanError(
                "invalid_response" if exc.error_class == "output_limit" else exc.error_class
            ) from None
        except (ValueError, RecursionError):
            raise ScanError("invalid_response") from None

    def scan(self, subjects, *, inventory_revision, now):
        out = []
        for subject in subjects:
            if subject.kind != "image" or subject.image is None:
                out.append(failed("trivy", subject, inventory_revision, now, "unsupported"))
                continue
            findings = {}
            try:
                self.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
                data = self._run(
                    [
                        "image",
                        "--scanners",
                        "vuln",
                        "--format",
                        "json",
                        "--list-all-pkgs",
                        "--config",
                        "/dev/null",
                        "--ignorefile",
                        "/dev/null",
                        "--max-image-size",
                        "1GB",
                        "--parallel",
                        "1",
                        "--timeout",
                        f"{self.timeout_s}s",
                        "--cache-dir",
                        str(self.cache),
                        "--image-src",
                        "remote",
                        subject.image,
                    ]
                )
                expected = subject.image.rsplit("@", 1)[1]
                digests = data.get("Metadata", {}).get("RepoDigests", [])
                if not any(isinstance(d, str) and d.endswith("@" + expected) for d in digests):
                    raise ScanError("evidence_mismatch")
                if (
                    subject.expected_image_id is not None
                    and image_id(data.get("Metadata", {}).get("ImageID"))
                    != subject.expected_image_id
                ):
                    raise ScanError("evidence_mismatch")
                if not isinstance(data.get("Results"), list) or not data["Results"]:
                    raise ScanError("incomplete")
                for result in data["Results"]:
                    if not result.get("Packages"):
                        raise ScanError("incomplete")
                    for item in result.get("Vulnerabilities") or []:
                        id = item["VulnerabilityID"]
                        advisory = Advisory(
                            id=id,
                            severity=severity(item.get("Severity")),
                            summary=item.get("Title") or id,
                            affected_package=item.get("PkgName"),
                            installed_version=item.get("InstalledVersion"),
                            fixed_versions=str(item.get("FixedVersion", "")).split(", ")
                            if item.get("FixedVersion")
                            else [],
                            source_url=f"https://avd.aquasec.com/nvd/{id.lower()}",
                        )
                        findings[(id, item.get("PkgName"), item.get("InstalledVersion"))] = advisory
                metadata = self._run(
                    ["version", "--format", "json", "--cache-dir", str(self.cache)]
                )
                stamp = metadata.get("VulnerabilityDB", {}).get("UpdatedAt")
                if not stamp:
                    raise ScanError("incomplete")
                parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ScanError("invalid_response")
                updated = parsed.timestamp()
                state = "confirmed" if findings else "not_affected"
                if not 0 <= now - updated <= 86400:
                    state = "stale"
                out.append(
                    ScanResult(
                        source="trivy",
                        subject=subject,
                        inventory_revision=inventory_revision,
                        checked_at=now,
                        database_updated_at=updated,
                        state=state,
                        findings=list(findings.values()),
                        complete=state != "stale",
                    )
                )
            except (
                ScanError,
                ValidationError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            ) as exc:
                error = exc.error_class if isinstance(exc, ScanError) else "invalid_response"
                out.append(
                    failed(
                        "trivy", subject, inventory_revision, now, error, list(findings.values())
                    )
                )
        return out
