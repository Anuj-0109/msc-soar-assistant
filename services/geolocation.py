from __future__ import annotations

import ipaddress
import json
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

import settings


CACHE_TTL_HOURS = 24
SOURCE_NAME = "IPWhois.io free geolocation endpoint"
ACCURACY_NOTICE = (
    "IP geolocation is approximate network-location intelligence. It must not "
    "be interpreted as a person's identity, household, street address, or "
    "proof that an end user is physically present in the reported location."
)


def _base_dir() -> Path:
    return Path(getattr(settings, "BASE_DIR", Path.cwd()))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime | None = None) -> str:
    return (value or _utc_now()).strftime("%Y-%m-%d %H:%M:%S UTC")


def _cache_path() -> Path:
    return _base_dir() / "geolocation_cache.db"


def _connect_cache() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_cache_path()))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS geolocation_cache (
            ip_address TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            retrieved_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _is_public_ip(ip_text: str) -> tuple[bool, str]:
    try:
        parsed = ipaddress.ip_address(ip_text)
    except ValueError:
        return False, "The value is not a valid IP address."

    if parsed.version != 4:
        return False, "This prototype currently presents IPv4 geolocation only."
    if parsed.is_private:
        return False, "Private addresses do not have meaningful public geolocation."
    if parsed.is_loopback:
        return False, "Loopback addresses do not have public geolocation."
    if parsed.is_link_local:
        return False, "Link-local addresses do not have public geolocation."
    if parsed.is_multicast:
        return False, "Multicast addresses do not identify a public endpoint."
    if parsed.is_reserved or not parsed.is_global:
        return False, (
            "Reserved, documentation, special-purpose, or otherwise non-global "
            "addresses are not submitted to an external geolocation service."
        )
    return True, ""


def _read_cache(ip_text: str) -> dict[str, Any] | None:
    conn = _connect_cache()
    try:
        row = conn.execute(
            "SELECT payload_json, expires_at FROM geolocation_cache WHERE ip_address = ?",
            (ip_text,),
        ).fetchone()
        if not row:
            return None

        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError):
            return None

        if expires_at <= _utc_now():
            conn.execute(
                "DELETE FROM geolocation_cache WHERE ip_address = ?",
                (ip_text,),
            )
            conn.commit()
            return None

        payload = json.loads(row["payload_json"])
        payload["status"] = "CACHED"
        payload["cache_status"] = "HIT"
        return payload
    except (json.JSONDecodeError, sqlite3.Error):
        return None
    finally:
        conn.close()


def _write_cache(ip_text: str, payload: dict[str, Any]) -> None:
    now = _utc_now()
    expires = now + timedelta(hours=CACHE_TTL_HOURS)
    stored = dict(payload)
    stored["status"] = "LIVE"
    stored["cache_status"] = "MISS"

    conn = _connect_cache()
    try:
        conn.execute(
            """
            INSERT INTO geolocation_cache (
                ip_address,
                payload_json,
                retrieved_at,
                expires_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                payload_json = excluded.payload_json,
                retrieved_at = excluded.retrieved_at,
                expires_at = excluded.expires_at
            """,
            (
                ip_text,
                json.dumps(stored, sort_keys=True),
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _normalise_live_response(ip_text: str, raw: dict[str, Any]) -> dict[str, Any]:
    connection = raw.get("connection") or {}
    timezone_data = raw.get("timezone") or {}

    return {
        "status": "LIVE",
        "cache_status": "MISS",
        "source": SOURCE_NAME,
        "ip_address": ip_text,
        "country": raw.get("country"),
        "country_code": raw.get("country_code"),
        "continent": raw.get("continent"),
        "continent_code": raw.get("continent_code"),
        "region": raw.get("region"),
        "region_code": raw.get("region_code"),
        "city": raw.get("city"),
        "postal": raw.get("postal"),
        "latitude": raw.get("latitude"),
        "longitude": raw.get("longitude"),
        "timezone_id": timezone_data.get("id"),
        "timezone_abbreviation": timezone_data.get("abbr"),
        "utc_offset": timezone_data.get("utc"),
        "asn": connection.get("asn"),
        "organisation": connection.get("org"),
        "isp": connection.get("isp"),
        "network_domain": connection.get("domain"),
        "retrieved_at": _utc_text(),
        "accuracy_notice": ACCURACY_NOTICE,
    }


def lookup_public_ip(
    ip_text: str,
    *,
    force_refresh: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    candidate = str(ip_text or "").strip()
    public, reason = _is_public_ip(candidate)
    if not public:
        return {
            "status": "NOT_APPLICABLE",
            "source": None,
            "ip_address": candidate,
            "message": reason,
            "retrieved_at": _utc_text(),
            "accuracy_notice": ACCURACY_NOTICE,
        }

    if not force_refresh:
        cached = _read_cache(candidate)
        if cached:
            return cached

    fields = ",".join(
        [
            "success",
            "message",
            "ip",
            "type",
            "continent",
            "continent_code",
            "country",
            "country_code",
            "region",
            "region_code",
            "city",
            "latitude",
            "longitude",
            "is_eu",
            "postal",
            "connection",
            "timezone",
        ]
    )

    try:
        response = requests.get(
            f"https://ipwho.is/{candidate}",
            params={"fields": fields},
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "MSc-SOAR-Geolocation/1.0",
            },
        )
        response.raise_for_status()
        raw = response.json()
    except requests.RequestException as exc:
        return {
            "status": "ERROR",
            "source": SOURCE_NAME,
            "ip_address": candidate,
            "message": f"Geolocation request failed: {exc}",
            "retrieved_at": _utc_text(),
            "accuracy_notice": ACCURACY_NOTICE,
        }
    except ValueError as exc:
        return {
            "status": "ERROR",
            "source": SOURCE_NAME,
            "ip_address": candidate,
            "message": f"Geolocation service returned invalid JSON: {exc}",
            "retrieved_at": _utc_text(),
            "accuracy_notice": ACCURACY_NOTICE,
        }

    if not raw.get("success", False):
        return {
            "status": "UNAVAILABLE",
            "source": SOURCE_NAME,
            "ip_address": candidate,
            "message": str(raw.get("message") or "No geolocation result was returned."),
            "retrieved_at": _utc_text(),
            "accuracy_notice": ACCURACY_NOTICE,
        }

    payload = _normalise_live_response(candidate, raw)
    _write_cache(candidate, payload)
    return payload


def resolve_public_ipv4(domain: str, limit: int = 3) -> dict[str, Any]:
    candidate = str(domain or "").strip().lower().rstrip(".")
    if not candidate:
        return {
            "status": "ERROR",
            "domain": candidate,
            "addresses": [],
            "message": "A domain is required.",
        }

    try:
        results = socket.getaddrinfo(
            candidate,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return {
            "status": "UNAVAILABLE",
            "domain": candidate,
            "addresses": [],
            "message": f"DNS resolution failed: {exc}",
        }

    addresses: list[str] = []
    excluded: list[dict[str, str]] = []
    for result in results:
        ip_text = result[4][0]
        if ip_text in addresses:
            continue
        public, reason = _is_public_ip(ip_text)
        if public:
            addresses.append(ip_text)
        else:
            excluded.append({"ip_address": ip_text, "reason": reason})
        if len(addresses) >= max(1, limit):
            break

    return {
        "status": "SUCCESS" if addresses else "NOT_APPLICABLE",
        "domain": candidate,
        "addresses": addresses,
        "excluded_addresses": excluded,
        "message": (
            "Current public IPv4 addresses resolved successfully."
            if addresses
            else "The domain did not resolve to a supported public IPv4 address."
        ),
    }


def lookup_ioc_geolocation(
    value: str,
    ioc_type: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    candidate = str(value or "").strip()
    kind = str(ioc_type or "").upper().strip()

    if kind == "HASH":
        return {
            "status": "NOT_APPLICABLE",
            "ioc_type": "HASH",
            "ioc_value": candidate,
            "locations": [],
            "message": (
                "File hashes do not represent network locations. Geolocation "
                "is not applicable."
            ),
            "accuracy_notice": ACCURACY_NOTICE,
            "retrieved_at": _utc_text(),
        }

    if kind == "IP":
        location = lookup_public_ip(
            candidate,
            force_refresh=force_refresh,
        )
        return {
            "status": location.get("status"),
            "ioc_type": "IP",
            "ioc_value": candidate,
            "resolved_ips": [candidate],
            "locations": [location],
            "message": location.get("message") or (
                "Approximate public-IP location and network ownership retrieved."
            ),
            "accuracy_notice": ACCURACY_NOTICE,
            "retrieved_at": location.get("retrieved_at") or _utc_text(),
        }

    if kind == "DOMAIN":
        resolution = resolve_public_ipv4(candidate)
        locations = [
            lookup_public_ip(ip_text, force_refresh=force_refresh)
            for ip_text in resolution.get("addresses", [])
        ]

        successful = [
            item
            for item in locations
            if item.get("status") in {"LIVE", "CACHED"}
        ]
        if successful:
            status = "LIVE" if any(
                item.get("status") == "LIVE" for item in successful
            ) else "CACHED"
        else:
            status = resolution.get("status", "UNAVAILABLE")

        return {
            "status": status,
            "ioc_type": "DOMAIN",
            "ioc_value": candidate,
            "resolved_ips": resolution.get("addresses", []),
            "excluded_addresses": resolution.get("excluded_addresses", []),
            "locations": locations,
            "message": (
                "These records describe the domain's currently resolved public "
                "infrastructure, not the registrant's or visitor's physical location."
                if locations
                else resolution.get("message")
            ),
            "dns_resolution": resolution,
            "accuracy_notice": ACCURACY_NOTICE,
            "retrieved_at": _utc_text(),
        }

    return {
        "status": "NOT_APPLICABLE",
        "ioc_type": kind or "UNKNOWN",
        "ioc_value": candidate,
        "locations": [],
        "message": "Geolocation supports IP and domain indicators only.",
        "accuracy_notice": ACCURACY_NOTICE,
        "retrieved_at": _utc_text(),
    }
