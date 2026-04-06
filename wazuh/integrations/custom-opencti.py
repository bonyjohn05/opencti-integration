#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from typing import Any, Iterable
from urllib.parse import urlparse

import requests

# =========================================================
# Config
# =========================================================
OPENCTI_URL_DEFAULT = "http://YOUR_OPENCTI_IP:8080/graphql"
OUTPUT_FILE = "/var/ossec/logs/opencti.log"
REQUEST_TIMEOUT = 10
VERIFY_TLS = False   # Set True if using proper HTTPS certs

# Set to True if you want to log "no match" events too
LOG_NO_MATCH = False

# =========================================================
# Extraction keys
# =========================================================
IP_SRC_KEYS = [
    "srcip", "src_ip", "source_ip", "data.srcip", "data.src_ip", "data.source_ip",
    "source.ip", "client.ip", "network.client.ip", "observer.ip"
]
IP_DST_KEYS = [
    "dstip", "dst_ip", "destination_ip", "data.dstip", "data.dst_ip", "data.destination_ip",
    "destination.ip", "server.ip", "network.destination.ip", "target.ip"
]

MD5_KEYS = ["syscheck.md5_after", "syscheck.md5", "data.md5", "md5"]
SHA1_KEYS = ["syscheck.sha1_after", "syscheck.sha1", "data.sha1", "sha1"]
SHA256_KEYS = ["syscheck.sha256_after", "syscheck.sha256", "data.sha256", "sha256"]

DOMAIN_KEYS = ["domain", "data.domain", "dns.question.name", "dns.question", "host.name"]
URL_KEYS = ["data.url", "url", "urls", "http.url", "request.url"]

HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")


# =========================================================
# Helpers
# =========================================================
def load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_nested(data: Any, dotted_key: str) -> Any:
    current = data
    for part in dotted_key.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def flatten_to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            if isinstance(item, (dict, list)):
                continue
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    if isinstance(value, (dict, list)):
        return []
    s = str(value).strip()
    return [s] if s else []


def unique_preserve(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def normalize_hash(value: str, expected_len: int) -> str | None:
    v = value.strip().lower()
    if len(v) != expected_len or not HASH_RE.fullmatch(v):
        return None
    return v


def normalize_domain(value: str) -> str | None:
    v = value.strip().lower().rstrip(".")
    if not v or " " in v or "/" in v:
        return None
    if normalize_ip(v):
        return None
    return v


def normalize_url(value: str) -> str | None:
    v = value.strip()
    try:
        parsed = urlparse(v)
        if parsed.scheme and parsed.netloc:
            return v
    except Exception:
        return None
    return None


def extract_values(alert: dict[str, Any], keys: list[str]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for key in keys:
        raw = get_nested(alert, key)
        for item in flatten_to_list(raw):
            values.append((key, item))
    return values


def labels_from_node(node: dict[str, Any]) -> list[str]:
    labels = node.get("objectLabel")
    if not labels:
        return []
    
    out: list[str] = []
    # Handle list of dicts directly
    if isinstance(labels, list):
        for label in labels:
            if isinstance(label, dict):
                value = label.get("value")
                if value:
                    out.append(str(value))
            elif isinstance(label, str):
                out.append(label)
    # Fallback for old format just in case
    elif isinstance(labels, dict) and "edges" in labels:
        for edge in labels.get("edges", []):
            value = edge.get("node", {}).get("value")
            if value:
                out.append(str(value))
    return out


# =========================================================
# Candidate building
# =========================================================
def build_candidates(alert: dict[str, Any]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []

    for source_field, raw in extract_values(alert, IP_SRC_KEYS):
        ip = normalize_ip(raw)
        if ip and is_public_ip(ip):
            candidates.append({"type": "ip", "value": ip, "source_field": source_field, "direction": "src"})

    for source_field, raw in extract_values(alert, IP_DST_KEYS):
        ip = normalize_ip(raw)
        if ip and is_public_ip(ip):
            candidates.append({"type": "ip", "value": ip, "source_field": source_field, "direction": "dst"})

    for source_field, raw in extract_values(alert, URL_KEYS):
        url = normalize_url(raw)
        if url:
            candidates.append({"type": "url", "value": url, "source_field": source_field, "direction": "n/a"})

    for source_field, raw in extract_values(alert, DOMAIN_KEYS):
        domain = normalize_domain(raw)
        if domain:
            candidates.append({"type": "domain", "value": domain, "source_field": source_field, "direction": "n/a"})

    for source_field, raw in extract_values(alert, MD5_KEYS):
        h = normalize_hash(raw, 32)
        if h:
            candidates.append({"type": "md5", "value": h, "source_field": source_field, "direction": "n/a"})

    for source_field, raw in extract_values(alert, SHA1_KEYS):
        h = normalize_hash(raw, 40)
        if h:
            candidates.append({"type": "sha1", "value": h, "source_field": source_field, "direction": "n/a"})

    for source_field, raw in extract_values(alert, SHA256_KEYS):
        h = normalize_hash(raw, 64)
        if h:
            candidates.append({"type": "sha256", "value": h, "source_field": source_field, "direction": "n/a"})

    dedup: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item["type"], item["value"])
        if key not in seen:
            seen.add(key)
            dedup.append(item)

    return dedup


# =========================================================
# OpenCTI query
# =========================================================
def graphql_query(opencti_url: str, token: str, search_value: str) -> dict[str, Any]:
    query = """
    query SearchObservable($search: String!) {
      stixCyberObservables(search: $search, first: 10) {
        edges {
          node {
            id
            entity_type
            observable_value
            created_at
            x_opencti_score
            x_opencti_description
            objectLabel {
              id
              value
            }
          }
        }
      }
      indicators(search: $search, first: 10) {
        edges {
          node {
            id
            name
            pattern
            created_at
            x_opencti_score
            description
            objectLabel {
              id
              value
            }
          }
        }
      }
    }
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        opencti_url,
        headers=headers,
        json={"query": query, "variables": {"search": search_value}},
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    response.raise_for_status()
    data = response.json()
    if "errors" in data:
        raise ValueError(f"GraphQL returned errors: {data['errors']}")
    return data


def normalize_match(candidate: dict[str, str], result: dict[str, Any]) -> dict[str, Any]:
    data = result.get("data", {})
    observable_edges = data.get("stixCyberObservables", {}).get("edges", [])
    indicator_edges = data.get("indicators", {}).get("edges", [])

    return {
        "ioc": {
            "type": candidate["type"],
            "value": candidate["value"],
            "source_field": candidate["source_field"],
            "direction": candidate["direction"],
        },
        "opencti": {
            "matched": bool(observable_edges or indicator_edges),
            "match_count": len(observable_edges) + len(indicator_edges),
            "observable_matches": [
                {
                    "id": edge["node"].get("id"),
                    "entity_type": edge["node"].get("entity_type"),
                    "value": edge["node"].get("observable_value"),
                    "score": edge["node"].get("x_opencti_score"),
                    "description": edge["node"].get("x_opencti_description"),
                    "labels": labels_from_node(edge["node"]),
                }
                for edge in observable_edges
            ],
            "indicator_matches": [
                {
                    "id": edge["node"].get("id"),
                    "name": edge["node"].get("name"),
                    "pattern": edge["node"].get("pattern"),
                    "score": edge["node"].get("x_opencti_score"),
                    "description": edge["node"].get("description"),
                    "labels": labels_from_node(edge["node"]),
                }
                for edge in indicator_edges
            ],
        },
    }


# =========================================================
# Output
# =========================================================
def append_json_line(payload: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":")) + "\n")


def build_base_event(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "opencti",
        "event_type": "threat_intel",
        "timestamp": alert.get("timestamp"),
        "agent": {
            "id": alert.get("agent", {}).get("id"),
            "name": alert.get("agent", {}).get("name"),
            "ip": alert.get("agent", {}).get("ip"),
        },
        "rule": {
            "id": alert.get("rule", {}).get("id"),
            "level": alert.get("rule", {}).get("level"),
            "description": alert.get("rule", {}).get("description"),
        },
    }


# =========================================================
# Main
# =========================================================
def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: custom-opencti.py <alert_file> <api_key> [hook_url]", file=sys.stderr)
        return 1

    alert_path = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else OPENCTI_URL_DEFAULT

    try:
        alert = load_json(alert_path)
        base = build_base_event(alert)
        candidates = build_candidates(alert)

        if not candidates:
            return 0

        any_match = False

        for candidate in candidates:
            result = graphql_query(hook_url, api_key, candidate["value"])
            normalized = normalize_match(candidate, result)

            if normalized["opencti"]["matched"]:
                any_match = True
                event = {
                    **base,
                    "ioc": normalized["ioc"],
                    "opencti": normalized["opencti"],
                }
                append_json_line(event)
            elif LOG_NO_MATCH:
                event = {
                    **base,
                    "ioc": normalized["ioc"],
                    "opencti": normalized["opencti"],
                }
                append_json_line(event)

        return 0

    except Exception as exc:
        try:
            alert = load_json(alert_path)
            base = build_base_event(alert)
        except Exception:
            base = {
                "integration": "opencti",
                "event_type": "threat_intel",
            }

        error_event = {
            **base,
            "opencti": {
                "matched": False,
                "error": str(exc),
            },
        }
        append_json_line(error_event)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
