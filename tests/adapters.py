"""How each product would turn samarkand's neutral output into its own shapes, written as the products'
code is today. The tests check these against what the products produce from the same fixtures, so a
product adopting a module can start from the adapter here."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from samarkand import stix

# ---- Rowanholt: STIX to its ten-column rows, with validity beside them ------------------------------

RH_COLUMNS = (
    "Evidential Element",
    "Threat Group",
    "Procedure Example",
    "Technique ID",
    "Technique Name",
    "Tactic",
    "Contextual Evidence",
    "Reference URL",
    "Navigation Layer URL",
    "Source Type",
)
RH_OBSERVABLES = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "process", "windows-registry-key")


def rowanholt_kind(item: stix.Indicator) -> str:
    t, path = item.stix_type, item.stix_path.lower()
    if t in ("ipv4-addr", "ipv6-addr"):
        return "ip"
    if t == "domain-name":
        return "domain"
    if t == "url":
        return "url"
    if t == "file":
        return "hash" if "hashes" in path else "file"
    if t == "process":
        return "cmd" if "command_line" in path else "software"
    if t == "windows-registry-key":
        return "reg"
    if t == "software" and item.object_type == "indicator":
        return "software"
    return ""


def _naive(at: datetime | None) -> str | None:
    return at.astimezone(timezone.utc).replace(tzinfo=None).isoformat() if at else None


def rowanholt_rows(bundle: dict) -> dict:
    parsed = stix.parse(bundle)
    # Rowanholt reads only objects with ids
    groups = [g for g in parsed.groups if g.stix_id]
    only_group = groups[0].name if len(groups) == 1 else ""
    report = next((r for r in parsed.reports if r.stix_id), None)
    source = "STIX: " + ((report.name if report else "") or only_group or parsed.bundle_id or "bundle")
    rows, seen, validity = [], set(), {}
    for item in parsed.indicators:
        if not item.object_id:
            continue
        if item.object_type != "indicator" and item.object_type not in RH_OBSERVABLES:
            continue
        kind = rowanholt_kind(item)
        if not kind:
            continue
        group = item.groups[0] if item.groups else only_group
        timed = item.valid_until is not None or item.confidence is not None
        first_seen = item.valid_from or item.created
        for technique in item.techniques or (None,):
            tid = technique.id if technique else (item.named_techniques[0] if item.named_techniques else "")
            tactics = technique.tactics if technique else item.tactics
            row = {
                "Evidential Element": item.value,
                "Threat Group": group,
                "Procedure Example": (item.description or item.name or "")[:1000],
                "Technique ID": tid,
                "Technique Name": technique.name if technique else "",
                "Tactic": ", ".join(p.replace("-", " ").title() for p in tactics),
                "Contextual Evidence": f"{kind}: {item.name or item.object_type}"[:500],
                "Reference URL": (item.references or (report.references if report else ()) or ("",))[0],
                "Navigation Layer URL": "",
                "Source Type": source,
            }
            key = (item.value.lower(), group.lower(), tid.upper(), source.lower())
            if timed:
                own = (item.valid_until, item.confidence, first_seen)
                if key in validity:
                    held = validity[key]
                    until = None if held[0] is None or own[0] is None else max(held[0], own[0])
                    conf = [c for c in (held[1], own[1]) if c is not None]
                    firsts = [s for s in (held[2], own[2]) if s is not None]
                    validity[key] = (until, max(conf) if conf else None, min(firsts) if firsts else None)
                else:
                    validity[key] = own
            if item.value and key not in seen:
                seen.add(key)
                rows.append(row)
    return {
        "rows": rows,
        "validity": [
            {"key": list(k), "valid_until": _naive(v[0]), "confidence": v[1], "first_seen": _naive(v[2])}
            for k, v in validity.items()
        ],
    }


# ---- Shikari: STIX and MISP to its extraction shape -------------------------------------------------


def _host(value: str) -> str:
    if "://" in value:
        return (urlparse(value).netloc or value).split("@")[-1].split(":")[0]
    return value


def _add(iocs: dict, kind: str, value: str) -> None:
    value = (value or "").strip()
    if value and value not in iocs[kind]:
        iocs[kind].append(value)


def shikari_kind(item: stix.Indicator) -> tuple[str, str] | None:
    t, path = item.stix_type, item.stix_path
    if item.object_type == "indicator":
        if t in ("ipv4-addr", "ipv6-addr"):
            return "ip", item.value
        if t == "domain-name":
            return "domain", item.value
        if t == "url":
            return "domain", _host(item.value)
        if t == "file":
            return ("hash" if "hashes" in path.lower() else "file"), item.value
        if t == "process":
            return ("cmd" if "command_line" in path else "sw"), item.value
        if t == "windows-registry-key":
            return "reg", item.value
        if t == "software":
            return "sw", item.value
        return None
    if t in ("ipv4-addr", "ipv6-addr"):
        return "ip", item.value
    if t == "domain-name":
        return "domain", item.value
    if t == "url":
        return "domain", _host(item.value)
    if t == "file":
        return ("hash" if path.startswith("hashes") else "file"), item.value
    if t == "process":
        return "cmd", item.value
    if t == "windows-registry-key":
        return "reg", item.value
    return None


def shikari_stix(bundle: dict) -> dict:
    parsed = stix.parse(bundle)
    iocs: dict = defaultdict(list)
    for item in parsed.indicators:
        mapped = shikari_kind(item)
        if mapped:
            _add(iocs, *mapped)
    techniques = [tid for t in parsed.techniques for tid in t.ids]
    techniques += [
        tid for item in parsed.indicators if item.object_type == "indicator" for tid in item.named_techniques
    ]
    described = sorted([*parsed.groups, *parsed.reports], key=lambda o: o.position)
    group_name = parsed.groups[0].name if parsed.groups else ""
    title = parsed.reports[0].name if parsed.reports else ""
    description = next((o.description for o in described if o.description), "")
    return {
        "success": True,
        "group_name": group_name,
        "group_desc": description[:500],
        "title": title or group_name,
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "stix",
    }


SHIKARI_ATTR_KIND = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "domain",
    "uri": "domain",
    "link": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "imphash": "hash",
    "authentihash": "hash",
    "ssdeep": "hash",
    "filename": "file",
    "filepath": "file",
    "regkey": "reg",
    "regkey|value": "reg",
    "windows-service-name": "sw",
    "windows-service-displayname": "sw",
    "mutex": "sw",
    "command": "cmd",
    "windows-scheduled-task": "cmd",
}
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def shikari_misp(event: dict) -> dict:
    from samarkand import misp

    parsed = misp.parse(event)
    iocs: dict = defaultdict(list)
    for attr in parsed.attributes:
        if attr.composite:
            left, right = attr.parts
            if attr.type == "domain|ip":
                _add(iocs, "domain", left.value)
                _add(iocs, "ip", right.value)
            elif attr.type.startswith("filename|"):
                _add(iocs, "file", left.value)
                _add(iocs, "hash", right.value)
            elif attr.type == "regkey|value":
                _add(iocs, "reg", left.value)
            continue
        kind = SHIKARI_ATTR_KIND.get(attr.type)
        if kind:
            _add(iocs, kind, _host(attr.value) if kind == "domain" and "://" in attr.value else attr.value)
    # Shikari reads techniques from any tag naming mitre or attack-pattern, and from galaxies
    techniques = [
        t
        for tag in parsed.tags
        if "mitre" in tag.lower() or "attack-pattern" in tag.lower()
        for t in _TID.findall(tag)
    ]
    techniques += [
        t
        for cluster in parsed.attack_patterns
        for t in _TID.findall(cluster.value + " " + json.dumps(cluster.meta))
    ]
    group_name = parsed.threat_actors[0].split(" - ")[0] if parsed.threat_actors else ""
    return {
        "success": True,
        "group_name": group_name,
        "group_desc": parsed.info[:500],
        "title": parsed.info or group_name,
        "techniques": sorted(set(techniques)),
        "tactics": [],
        "procedures": [],
        "iocs": {k: v for k, v in iocs.items() if v},
        "ioc_mentions": {},
        "source": "misp",
    }
