"""Policy-gated remote threat-intelligence enrichment.

No threat feed or response cache is persisted. A provider is contacted only for
domain/IP values selected by an explicit policy regex gate.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from semantic_targets import normalize_host


MAX_RESPONSE_BYTES = 1_048_576
MAX_LABELS = 32
SUPPORTED_TYPES = {"domain", "ip"}
API_KEY_ENV = "VIRUSTOTAL_API_KEY"
Transport = Callable[[str, str, float], tuple[int, bytes]]


class ThreatIntelError(RuntimeError):
    """Raised when remote enrichment cannot produce a trustworthy result."""


def normalize_indicator(indicator_type: str, value: str) -> str:
    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ThreatIntelError(f"invalid IP target {value!r}") from exc
    if indicator_type == "domain":
        if any(character in value for character in "@/:[]") or any(
            character.isspace() for character in value
        ):
            raise ThreatIntelError(f"invalid domain target {value!r}")
        normalized = normalize_host(value)
        if normalized is None:
            raise ThreatIntelError(f"invalid domain target {value!r}")
        return normalized
    raise ThreatIntelError(f"unsupported remote threat-intelligence target {indicator_type!r}")


@dataclass(frozen=True)
class ThreatMatches:
    indicator_ids: tuple[str, ...] = ()
    verdicts: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    matched_targets: tuple[str, ...] = ()
    confidences: tuple[int, ...] = ()
    uncertain: bool = False

    def as_dict(self) -> dict[str, list[Any]]:
        return {
            "threat.indicator_ids": list(self.indicator_ids),
            "threat.verdicts": list(self.verdicts),
            "threat.labels": list(self.labels),
            "threat.sources": list(self.sources),
            "threat.matched_targets": list(self.matched_targets),
            "threat.confidences": list(self.confidences),
        }


def merge_matches(items: Iterable[ThreatMatches], *, uncertain: bool = False) -> ThreatMatches:
    matches = list(items)

    def unique(attribute: str) -> tuple[Any, ...]:
        return tuple(dict.fromkeys(value for item in matches for value in getattr(item, attribute)))

    return ThreatMatches(
        indicator_ids=unique("indicator_ids"),
        verdicts=unique("verdicts"),
        labels=unique("labels"),
        sources=unique("sources"),
        matched_targets=unique("matched_targets"),
        confidences=unique("confidences"),
        uncertain=uncertain or any(item.uncertain for item in matches),
    )


def _default_transport(url: str, api_key: str, timeout: float) -> tuple[int, bytes]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "AiDR/0.1",
            "x-apikey": api_key,
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS origin
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            return int(response.status), payload
    except HTTPError as exc:
        if exc.code == 404:
            return 404, b""
        raise ThreatIntelError(f"VirusTotal returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ThreatIntelError(f"VirusTotal request failed: {type(exc).__name__}") from exc


@dataclass
class VirusTotalEnricher:
    api_key_env: str = API_KEY_ENV
    timeout_ms: int = 1500
    failure_mode: str = "open"
    malicious_threshold: int = 1
    suspicious_threshold: int = 1
    max_lookups: int = 4
    transport: Transport = _default_transport
    _memo: dict[tuple[str, str], ThreatMatches] = field(default_factory=dict, init=False)
    _warnings: list[str] = field(default_factory=list, init=False)
    _lookup_count: int = field(default=0, init=False)
    _latency_ms: float = field(default=0.0, init=False)
    _available: bool = field(default=False, init=False)

    def _failure(self, message: str) -> ThreatMatches:
        if self.failure_mode == "closed":
            raise ThreatIntelError(message)
        self._warnings.append(message)
        return ThreatMatches()

    def _lookup(self, indicator_type: str, raw_value: str) -> ThreatMatches:
        try:
            value = normalize_indicator(indicator_type, raw_value)
        except ThreatIntelError as exc:
            return self._failure(str(exc))
        key = (indicator_type, value)
        if key in self._memo:
            return self._memo[key]
        if self._lookup_count >= self.max_lookups:
            result = self._failure(
                f"remote threat-intelligence lookup limit {self.max_lookups} exceeded"
            )
            self._memo[key] = result
            return result
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            result = self._failure(
                f"VirusTotal API key environment variable {self.api_key_env!r} is not set"
            )
            self._memo[key] = result
            return result

        collection = "domains" if indicator_type == "domain" else "ip_addresses"
        url = f"https://www.virustotal.com/api/v3/{collection}/{quote(value, safe='')}"
        started = time.perf_counter()
        self._lookup_count += 1
        try:
            status, payload = self.transport(url, api_key, self.timeout_ms / 1000)
            self._latency_ms += (time.perf_counter() - started) * 1000
            if status == 404:
                result = self._result(indicator_type, value, {}, "unknown")
                self._available = True
            elif status != 200:
                result = self._failure(f"VirusTotal returned HTTP {status}")
            else:
                result = self._parse_response(indicator_type, value, payload)
                self._available = True
        except ThreatIntelError as exc:
            self._latency_ms += (time.perf_counter() - started) * 1000
            result = self._failure(str(exc))
        self._memo[key] = result
        return result

    def _result(
        self, indicator_type: str, value: str, attributes: dict[str, Any], verdict: str
    ) -> ThreatMatches:
        stats = attributes.get("last_analysis_stats", {})
        total = sum(
            count for count in stats.values()
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0
        )
        flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        confidence = round(flagged * 100 / total) if total else 0
        labels = attributes.get("tags", [])
        safe_labels = tuple(
            item for item in labels[:MAX_LABELS]
            if isinstance(item, str) and 0 < len(item) <= 128
        ) if isinstance(labels, list) else ()
        digest = hashlib.sha256(f"{indicator_type}\0{value}".encode()).hexdigest()[:24]
        return ThreatMatches(
            indicator_ids=(f"virustotal:{indicator_type}:{digest}",),
            verdicts=(verdict,),
            labels=safe_labels,
            sources=("virustotal",),
            matched_targets=(value,),
            confidences=(confidence,),
        )

    def _parse_response(self, indicator_type: str, value: str, payload: bytes) -> ThreatMatches:
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ThreatIntelError("VirusTotal response exceeds the size limit")
        try:
            document = json.loads(payload)
            attributes = document["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ThreatIntelError("VirusTotal returned an invalid response") from exc
        if not isinstance(attributes, dict) or not isinstance(stats, dict):
            raise ThreatIntelError("VirusTotal returned an invalid response")
        for field_name in ("malicious", "suspicious", "harmless", "undetected"):
            count = stats.get(field_name, 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ThreatIntelError("VirusTotal returned invalid analysis statistics")
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        verdict = (
            "malicious"
            if malicious >= self.malicious_threshold
            else "suspicious"
            if suspicious >= self.suspicious_threshold
            else "benign"
            if harmless > 0
            else "unknown"
        )
        return self._result(indicator_type, value, attributes, verdict)

    def lookup(self, typed_values: Iterable[tuple[str, str]], *, uncertain: bool = False) -> ThreatMatches:
        selected = [
            self._lookup(indicator_type, value)
            for indicator_type, value in dict.fromkeys(typed_values)
            if indicator_type in SUPPORTED_TYPES
        ]
        return merge_matches(selected, uncertain=uncertain)

    def metadata(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "available": self._available,
            "provider": "virustotal",
            "source": "virustotal",
            "lookup_count": self._lookup_count,
            "latency_ms": round(self._latency_ms, 3),
            "failure_mode": self.failure_mode,
            "warning": "; ".join(dict.fromkeys(self._warnings)) or None,
        }


def disabled_metadata() -> dict[str, Any]:
    return {
        "enabled": False,
        "available": False,
        "provider": None,
        "source": None,
        "lookup_count": 0,
        "latency_ms": 0.0,
        "failure_mode": None,
        "warning": None,
    }


def build_enricher(config: Any, *, transport: Transport = _default_transport) -> VirusTotalEnricher | None:
    if not isinstance(config, dict) or not bool(config.get("enabled", False)):
        return None
    if config.get("provider") != "virustotal":
        raise ThreatIntelError("unsupported threat-intelligence provider")
    return VirusTotalEnricher(
        api_key_env=str(config.get("api_key_env", API_KEY_ENV)),
        timeout_ms=int(config.get("timeout_ms", 1500)),
        failure_mode=str(config.get("failure_mode", "open")),
        malicious_threshold=int(config.get("malicious_threshold", 1)),
        suspicious_threshold=int(config.get("suspicious_threshold", 1)),
        max_lookups=int(config.get("max_lookups", 4)),
        transport=transport,
    )
