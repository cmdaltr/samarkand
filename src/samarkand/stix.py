"""STIX 2.1 as plain JSON: reading a bundle into neutral indicators, and building objects and bundles.

Hand-written rather than through the `stix2` library: the objects are few, vendor and MISP exports
carry custom properties the strict loaders reject, and building dictionaries doesn't need a large
dependency.

Reading (`parse`) is per indicator: each value in a bundle comes back as its
own `Indicator` with the groups and techniques its own STIX relationships (`indicates`, `related-to`,
`uses`) link it to, never every technique in the bundle. Each value keeps the STIX type and property
it came from, so a product maps it to its own vocabulary; `Kind` is a neutral one to start from.

Building gives deterministic ids (UUIDv5 under a namespace the product owns,
and the spec's own SCO namespace over the ID contributing properties), UTC millisecond timestamps,
and the OASIS TLP 2.0 marking definitions, carried by every object in `object_marking_refs`.
`bundle` puts a simple bundle together from neutral parts; a product with more to say (incidents,
notes, sightings) uses the object builders directly.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import ntpath
import posixpath
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)

SPEC = "2.1"
MEDIA_TYPE = "application/stix+json;version=2.1"
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # STIX 2.1, section 2.9
ATTACK_URL = "https://attack.mitre.org/techniques/"
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
GROUP_TYPES = ("intrusion-set", "threat-actor")
LINK_TYPES = ("indicates", "related-to", "uses")

# OASIS TLP 2.0 (cti-stix-common-objects, extension-definition-specifications/tlp-2.0)
TLP_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP_MARKINGS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}
TLP_CREATED = "2022-10-01T00:00:00.000Z"


class Kind(str, Enum):
    """A neutral vocabulary for indicator values. The values match the observable types the products
    already use, so a product with its own maps by value."""

    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    EMAIL_SUBJECT = "email_subject"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    FILE_HASH_SHA512 = "file_hash_sha512"
    FILE_HASH = "file_hash"  # any other algorithm (SSDEEP, TLSH, SHA3-256…)
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    DIRECTORY = "directory"
    PROCESS_NAME = "process_name"
    PROCESS_COMMAND = "process_command"
    REGISTRY_KEY = "registry_key"
    SERVICE_NAME = "service_name"
    USER_ACCOUNT = "user_account"
    MUTEX = "mutex"
    CERTIFICATE = "certificate"
    ASN = "asn"
    MAC_ADDRESS = "mac_address"
    USER_AGENT = "user_agent"
    SOFTWARE = "software"
    CVE = "cve"


HASH_KINDS = {
    "md5": Kind.FILE_HASH_MD5,
    "sha-1": Kind.FILE_HASH_SHA1,
    "sha1": Kind.FILE_HASH_SHA1,
    "sha-256": Kind.FILE_HASH_SHA256,
    "sha256": Kind.FILE_HASH_SHA256,
    "sha-512": Kind.FILE_HASH_SHA512,
    "sha512": Kind.FILE_HASH_SHA512,
}
HASH_NAMES = {
    Kind.FILE_HASH_MD5: "MD5",
    Kind.FILE_HASH_SHA1: "SHA-1",
    Kind.FILE_HASH_SHA256: "SHA-256",
    Kind.FILE_HASH_SHA512: "SHA-512",
}


class NotABundle(ValueError):
    """The document isn't a STIX bundle or a list of STIX objects."""


# ---- time -------------------------------------------------------------------------------------------

_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?\s*(Z|z|[+-]\d{2}:?\d{2})?$"
)


def timestamp(at: datetime) -> str:
    """A STIX timestamp: UTC, millisecond precision, Z. A naive time is taken as UTC."""
    at = at.astimezone(timezone.utc) if at.tzinfo else at.replace(tzinfo=timezone.utc)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


def parse_time(value: object) -> datetime | None:
    """A STIX timestamp (any number of fractional digits) or an ISO date, as an aware UTC time; None
    when it isn't one. The same on every Python from 3.10."""
    if not isinstance(value, str):
        return None
    found = _TIMESTAMP.match(value.strip())
    if not found:
        return None
    year, month, day, hour, minute, second, fraction, zone = found.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    offset = timezone.utc
    if zone and zone not in ("Z", "z"):
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        offset = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        at = datetime(
            int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0), micro, offset
        )
    except ValueError:
        return None
    return at.astimezone(timezone.utc)


# ---- reading ----------------------------------------------------------------------------------------

# objtype(:path)? (= | LIKE | MATCHES) 'value': the comparisons inside a STIX pattern
PATTERN_COMPARISON = re.compile(
    r"([a-z0-9][a-z0-9-]*)(?::([^\s=<>!]+))?\s*(?:=|LIKE|MATCHES)\s*'((?:[^'\\]|\\.)*)'", re.IGNORECASE
)


@dataclass(frozen=True)
class Technique:
    """An ATT&CK technique as a bundle names it (an attack-pattern)."""

    ids: tuple[str, ...]  # ATT&CK ids: its mitre-attack references, else any named in its text
    name: str = ""
    tactics: tuple[str, ...] = ()  # kill-chain phase names, as given ("command-and-control")
    stix_id: str = ""
    references: tuple[str, ...] = ()  # URLs from its external references

    @property
    def id(self) -> str:
        """The first ATT&CK id, or ""."""
        return self.ids[0] if self.ids else ""


@dataclass(frozen=True)
class Group:
    """An intrusion set or threat actor."""

    name: str
    description: str = ""
    stix_type: str = "intrusion-set"
    stix_id: str = ""
    position: int = 0  # where it is among the bundle's objects


@dataclass(frozen=True)
class Indicator:
    """One value from a bundle, with what its own STIX object says about it."""

    value: str
    kind: Kind | None  # None: a STIX type this vocabulary has no word for
    stix_type: str  # the cyber observable type the value is of ("file")
    stix_path: str  # the property ("hashes.'SHA-256'", "name", "value")
    object_type: str  # "indicator", or the cyber observable's own type
    object_id: str = ""
    name: str = ""
    description: str = ""
    pattern: str = ""
    groups: tuple[str, ...] = ()  # names linked by relationships, in order
    techniques: tuple[Technique, ...] = ()  # linked by relationships, in order
    named_techniques: tuple[str, ...] = ()  # ATT&CK ids in the object's own name
    tactics: tuple[str, ...] = ()  # the object's own kill-chain phase names
    references: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    indicator_types: tuple[str, ...] = ()
    created: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    confidence: int | None = None  # 0 to 100, or None when absent or out of range


@dataclass(frozen=True)
class Report:
    """A report object."""

    name: str
    description: str = ""
    references: tuple[str, ...] = ()
    stix_id: str = ""
    position: int = 0  # where it is among the bundle's objects


@dataclass(frozen=True)
class Parsed:
    """A bundle read into neutral parts."""

    bundle_id: str
    indicators: tuple[Indicator, ...] = ()
    techniques: tuple[Technique, ...] = ()  # every attack-pattern in the bundle, in order
    groups: tuple[Group, ...] = ()
    reports: tuple[Report, ...] = ()
    object_count: int = 0

    @property
    def only_group(self) -> str:
        """The group's name when the bundle has exactly one, else ""."""
        return self.groups[0].name if len(self.groups) == 1 else ""


def _load(data: str | bytes | Mapping[str, Any] | Sequence[Any]) -> Any:
    if isinstance(data, (str, bytes)):
        try:
            return json.loads(data)
        except ValueError as exc:
            raise NotABundle(f"Not JSON: {exc}") from exc
    return data


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _references(obj: Mapping[str, Any]) -> tuple[str, ...]:
    refs = obj.get("external_references") or []
    return tuple(r["url"] for r in refs if isinstance(r, dict) and isinstance(r.get("url"), str) and r["url"])


def _phases(obj: Mapping[str, Any]) -> tuple[str, ...]:
    phases = obj.get("kill_chain_phases") or []
    return tuple(p["phase_name"] for p in phases if isinstance(p, dict) and p.get("phase_name"))


def attack_ids(obj: Mapping[str, Any]) -> tuple[str, ...]:
    """The ATT&CK ids an object carries: its mitre-attack external ids, else any T-number in its name
    and description."""
    found = []
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() in (
            "mitre-attack",
            "mitre attack",
        ):
            external = str(ref.get("external_id") or "")
            if TECHNIQUE.fullmatch(external):
                found.append(external)
    if not found:
        found = TECHNIQUE.findall(f"{_text(obj.get('name'))} {_text(obj.get('description'))}")
    return tuple(found)


def technique_of(obj: Mapping[str, Any]) -> Technique:
    """An attack-pattern object as a Technique."""
    return Technique(
        ids=attack_ids(obj),
        name=_text(obj.get("name")),
        tactics=_phases(obj),
        stix_id=_text(obj.get("id")),
        references=_references(obj),
    )


def _kind(stix_type: str, path: str, value: str) -> Kind | None:
    path = path.lower()
    if stix_type in ("ipv4-addr", "ipv6-addr"):
        return Kind.CIDR if "/" in value else Kind.IP_ADDRESS
    if stix_type == "file" or stix_type == "x509-certificate":
        if "hashes" in path:
            if stix_type == "x509-certificate":
                return Kind.CERTIFICATE
            algorithm = path.split("hashes.", 1)[-1].strip("'\"")
            return HASH_KINDS.get(algorithm, Kind.FILE_HASH)
        if stix_type == "x509-certificate":
            return Kind.CERTIFICATE
        return Kind.DIRECTORY if "parent_directory_ref" in path else Kind.FILE_NAME
    if stix_type == "process":
        if "command_line" in path:
            return Kind.PROCESS_COMMAND
        if "service_name" in path:
            return Kind.SERVICE_NAME
        return Kind.PROCESS_NAME
    if stix_type == "network-traffic" and "user-agent" in path:
        return Kind.USER_AGENT
    if stix_type == "email-message":
        return Kind.EMAIL_SUBJECT if "subject" in path else None
    return {
        "domain-name": Kind.DOMAIN,
        "url": Kind.URL,
        "email-addr": Kind.EMAIL,
        "windows-registry-key": Kind.REGISTRY_KEY,
        "software": Kind.SOFTWARE,
        "mutex": Kind.MUTEX,
        "mac-addr": Kind.MAC_ADDRESS,
        "user-account": Kind.USER_ACCOUNT,
        "autonomous-system": Kind.ASN,
        "directory": Kind.DIRECTORY,
        "vulnerability": Kind.CVE,
    }.get(stix_type)


def unquote(value: str) -> str:
    """A pattern string's value without its escapes (\\' and \\\\)."""
    return value.replace("\\'", "'").replace("\\\\", "\\")


def pattern_values(pattern: str) -> list[tuple[str, str, str]]:
    """(STIX type, property, value) for each quoted comparison in a STIX pattern, in order. The type is
    lower-cased; the property is as written."""
    out = []
    for stix_type, path, value in PATTERN_COMPARISON.findall(pattern or ""):
        value = unquote(value).strip()
        if value:
            out.append((stix_type.lower(), path or "", value))
    return out


def observable_values(obj: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """(STIX type, property, value) for a cyber observable object."""
    kind = _text(obj.get("type"))
    simple = {
        "ipv4-addr": "value",
        "ipv6-addr": "value",
        "domain-name": "value",
        "url": "value",
        "email-addr": "value",
        "mac-addr": "value",
        "mutex": "name",
        "software": "name",
        "directory": "path",
        "user-account": "account_login",
        "windows-registry-key": "key",
    }
    if kind in simple:
        value = obj.get(simple[kind])
        return [(kind, simple[kind], value)] if isinstance(value, str) and value else []
    if kind == "file":
        hashes = obj.get("hashes") or {}
        out = [(kind, f"hashes.'{name}'", h) for name, h in hashes.items() if isinstance(h, str) and h]
        return out + (
            [(kind, "name", obj["name"])] if isinstance(obj.get("name"), str) and obj["name"] else []
        )
    if kind == "process":
        line = obj.get("command_line")
        return [(kind, "command_line", line)] if isinstance(line, str) and line else []
    if kind == "autonomous-system" and isinstance(obj.get("number"), int):
        return [(kind, "number", str(obj["number"]))]
    return []


OBSERVABLE_TYPES = (
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "email-addr",
    "mac-addr",
    "mutex",
    "software",
    "directory",
    "user-account",
    "windows-registry-key",
    "file",
    "process",
    "autonomous-system",
)


def _confidence(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else None


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def parse(data: str | bytes | Mapping[str, Any] | Sequence[Any]) -> Parsed:
    """A STIX 2.1 bundle (or a bare list of objects, or their JSON) read into neutral parts.

    Objects sharing an id are one object, the last one read (a newer version), in the place the first
    was. Objects without an id are kept, though nothing can refer to them. Raises NotABundle."""
    data = _load(data)
    objects = data.get("objects") if isinstance(data, dict) else data
    if not isinstance(objects, list):
        raise NotABundle("Not a STIX bundle: no 'objects' list.")
    ordered: list[dict[str, Any]] = []
    place: dict[str, int] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        oid = obj.get("id")
        if isinstance(oid, str) and oid:
            if oid in place:
                ordered[place[oid]] = obj
                continue
            place[oid] = len(ordered)
        ordered.append(obj)
    by_id = {o["id"]: o for o in ordered if isinstance(o.get("id"), str) and o["id"]}

    links: dict[str, list[dict[str, Any]]] = {}
    for rel in ordered:
        if rel.get("type") == "relationship" and rel.get("relationship_type") in LINK_TYPES:
            target = by_id.get(rel.get("target_ref"))  # type: ignore[arg-type]
            if target is not None:
                links.setdefault(_text(rel.get("source_ref")), []).append(target)

    indicators: list[Indicator] = []
    for obj in ordered:
        kind = obj.get("type")
        if kind == "indicator":
            values = pattern_values(_text(obj.get("pattern")))
        elif kind in OBSERVABLE_TYPES:
            values = observable_values(obj)
        else:
            continue
        linked = links.get(_text(obj.get("id")), []) if obj.get("id") else []
        name = _text(obj.get("name"))
        context = {
            "object_type": _text(kind),
            "object_id": _text(obj.get("id")),
            "name": name,
            "description": _text(obj.get("description")),
            "pattern": _text(obj.get("pattern")),
            "groups": tuple(_text(t.get("name")) for t in linked if t.get("type") in GROUP_TYPES),
            "techniques": tuple(technique_of(t) for t in linked if t.get("type") == "attack-pattern"),
            "named_techniques": tuple(TECHNIQUE.findall(name)),
            "tactics": _phases(obj),
            "references": _references(obj),
            "labels": _strings(obj.get("labels")),
            "indicator_types": _strings(obj.get("indicator_types")),
            "created": parse_time(obj.get("created")),
            "valid_from": parse_time(obj.get("valid_from")),
            "valid_until": parse_time(obj.get("valid_until")),
            "confidence": _confidence(obj.get("confidence")),
        }
        for stix_type, path, value in values:
            indicators.append(Indicator(value, _kind(stix_type, path, value), stix_type, path, **context))

    bundle_id = _text(data.get("id")) if isinstance(data, dict) else ""
    return Parsed(
        bundle_id=bundle_id,
        indicators=tuple(indicators),
        techniques=tuple(technique_of(o) for o in ordered if o.get("type") == "attack-pattern"),
        groups=tuple(
            Group(
                _text(o.get("name")), _text(o.get("description")), _text(o.get("type")), _text(o.get("id")), i
            )
            for i, o in enumerate(ordered)
            if o.get("type") in GROUP_TYPES
        ),
        reports=tuple(
            Report(_text(o.get("name")), _text(o.get("description")), _references(o), _text(o.get("id")), i)
            for i, o in enumerate(ordered)
            if o.get("type") == "report"
        ),
        object_count=len(ordered),
    )


# ---- building ---------------------------------------------------------------------------------------


def object_id(namespace: uuid.UUID, kind: str, *parts: object) -> str:
    """A stable id: `kind--` and UUIDv5 under the product's namespace over the parts joined by |.
    The kind isn't hashed, so give parts that are unique among objects of that kind."""
    return f"{kind}--{uuid.uuid5(namespace, '|'.join(str(p) for p in parts))}"


def sco_id(kind: str, contributing: Mapping[str, Any]) -> str:
    """The spec's deterministic id for a cyber observable: UUIDv5 under SCO_NAMESPACE over the canonical
    JSON of its ID contributing properties."""
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"


def quote(value: str) -> str:
    """A value as a pattern string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def tlp_name(tlp: str) -> str:
    """A TLP level as TLP_MARKINGS keys it: "TLP:AMBER+STRICT" or "amber_strict" give "amber+strict"."""
    name = str(getattr(tlp, "value", tlp)).strip().lower().removeprefix("tlp:").replace("_", "+")
    name = "clear" if name == "white" else name
    if name not in TLP_MARKINGS:
        raise ValueError(f"Not a TLP 2.0 level: {tlp!r}")
    return name


def tlp_marking(tlp: str) -> dict[str, Any]:
    """The OASIS TLP 2.0 marking definition for a level."""
    name = tlp_name(tlp)
    return {
        "type": "marking-definition",
        "spec_version": SPEC,
        "id": TLP_MARKINGS[name],
        "created": TLP_CREATED,
        "name": f"TLP:{name.upper()}",
        "extensions": {TLP_EXTENSION: {"extension_type": "property-extension", "tlp_2_0": name}},
    }


def _split_path(path: str) -> tuple[str, str]:
    module = ntpath if ("\\" in path or ":" in path[:3]) else posixpath
    head, tail = module.split(path)
    return head, tail


_CERT_HASHES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _as_kind(kind: Kind | str | Enum) -> Kind | None:
    try:
        return Kind(getattr(kind, "value", kind))
    except ValueError:
        return None


def cyber_observables(
    kind: Kind | str | Enum, value: str, *, namespace: uuid.UUID | None = None
) -> tuple[list[dict[str, Any]], str | None]:
    """The STIX cyber observables for one value, and the pattern an indicator matches it with.
    ([], None) when STIX has no faithful way to say it. `namespace` gives a process its id (process
    has no ID contributing properties); without one, a command line has a pattern but no object."""
    v = value.strip()
    k = _as_kind(kind)

    def sco(stix_type: str, contributing: dict[str, Any], **extra: Any) -> dict[str, Any]:
        return {
            "type": stix_type,
            "spec_version": SPEC,
            "id": sco_id(stix_type, contributing),
            **contributing,
            **extra,
        }

    if k in (Kind.IP_ADDRESS, Kind.CIDR):
        try:
            version = ipaddress.ip_network(v, strict=False).version
        except ValueError:
            return [], None
        stix_type = "ipv6-addr" if version == 6 else "ipv4-addr"
        return [sco(stix_type, {"value": v})], f"[{stix_type}:value = {quote(v)}]"
    simple = {
        Kind.DOMAIN: ("domain-name", "value"),
        Kind.URL: ("url", "value"),
        Kind.EMAIL: ("email-addr", "value"),
        Kind.MUTEX: ("mutex", "name"),
        Kind.REGISTRY_KEY: ("windows-registry-key", "key"),
        Kind.MAC_ADDRESS: ("mac-addr", "value"),
        Kind.USER_ACCOUNT: ("user-account", "account_login"),
        Kind.SOFTWARE: ("software", "name"),
        Kind.DIRECTORY: ("directory", "path"),
    }
    if k in simple:
        stix_type, prop = simple[k]
        if k is Kind.MAC_ADDRESS:
            v = v.lower().replace("-", ":")
        if k is Kind.SOFTWARE:
            return [sco(stix_type, {prop: v})], f"[software:name = {quote(v)}]"
        return [sco(stix_type, {prop: v})], f"[{stix_type}:{prop} = {quote(v)}]"
    if k in HASH_NAMES:
        name = HASH_NAMES[k]
        return [sco("file", {"hashes": {name: v.lower()}})], f"[file:hashes.'{name}' = {quote(v.lower())}]"
    if k is Kind.FILE_NAME:
        return [sco("file", {"name": v})], f"[file:name = {quote(v)}]"
    if k is Kind.FILE_PATH:
        directory, name = _split_path(v)
        if not name:
            return [sco("directory", {"path": v})], f"[directory:path = {quote(v)}]"
        if not directory:
            return [sco("file", {"name": name})], f"[file:name = {quote(name)}]"
        folder = sco("directory", {"path": directory})
        file = sco("file", {"name": name, "parent_directory_ref": folder["id"]})
        pattern = f"[file:name = {quote(name)} AND file:parent_directory_ref.path = {quote(directory)}]"
        return [file, folder], pattern
    if k is Kind.PROCESS_NAME:
        return [sco("file", {"name": v})], f"[process:image_ref.name = {quote(v)}]"
    if k is Kind.PROCESS_COMMAND:
        objects = []
        if namespace is not None:
            objects = [
                {
                    "type": "process",
                    "spec_version": SPEC,
                    "id": object_id(namespace, "process", v),
                    "command_line": v,
                }
            ]
        return objects, f"[process:command_line = {quote(v)}]"
    if k is Kind.EMAIL_SUBJECT:
        return [
            sco("email-message", {"subject": v}, is_multipart=False)
        ], f"[email-message:subject = {quote(v)}]"
    if k is Kind.ASN:
        digits = v.upper().removeprefix("AS")
        if not digits.isdigit():
            return [], None
        return [
            sco("autonomous-system", {"number": int(digits)})
        ], f"[autonomous-system:number = {int(digits)}]"
    if k is Kind.CERTIFICATE:
        name = _CERT_HASHES.get(len(v)) if all(c in "0123456789abcdefABCDEF:" for c in v) else None
        if name:
            h = v.replace(":", "").lower()
            return [
                sco("x509-certificate", {"hashes": {name: h}})
            ], f"[x509-certificate:hashes.'{name}' = {quote(h)}]"
        return [
            sco("x509-certificate", {"serial_number": v})
        ], f"[x509-certificate:serial_number = {quote(v)}]"
    if k is Kind.SERVICE_NAME:
        return [], f"[process:extensions.'windows-service-ext'.service_name = {quote(v)}]"
    if k is Kind.USER_AGENT:
        return [], f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = {quote(v)}]"
    return [], None


def common(identity: str, created: datetime, now: datetime, tlp: str) -> dict[str, Any]:
    """The properties every object made here carries, in this order: spec_version, created_by_ref,
    created (never after now), modified (now) and the TLP marking."""
    return {
        "spec_version": SPEC,
        "created_by_ref": identity,
        "created": timestamp(min(_aware(created), _aware(now))),
        "modified": timestamp(now),
        "object_marking_refs": [TLP_MARKINGS[tlp_name(tlp)]],
    }


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def identity_object(
    identity: str, name: str, created: datetime, now: datetime, identity_class: str = "organization"
) -> dict[str, Any]:
    """Who the bundle is from."""
    return {
        "type": "identity",
        "spec_version": SPEC,
        "id": identity,
        "created": timestamp(min(_aware(created), _aware(now))),
        "modified": timestamp(now),
        "name": name,
        "identity_class": identity_class,
    }


def attack_pattern_object(
    stix_id: str, technique_id: str, props: Mapping[str, Any], name: str = "", tactics: Iterable[str] = ()
) -> dict[str, Any]:
    """An ATT&CK technique, referenced by its ATT&CK id and URL. `props` is `common(...)`."""
    phases = [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics]
    return {
        "type": "attack-pattern",
        "id": stix_id,
        **props,
        "name": name or technique_id,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"{ATTACK_URL}{technique_id.replace('.', '/')}/",
            }
        ],
        **({"kill_chain_phases": phases} if phases else {}),
    }


def indicator_object(
    stix_id: str,
    props: Mapping[str, Any],
    *,
    name: str,
    pattern: str,
    valid_from: datetime,
    description: str | None = None,
    indicator_types: Sequence[str] = (),
    labels: Sequence[str] = (),
    confidence: int | None = None,
    external_references: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """An indicator with a STIX pattern. Optional properties are left out when empty."""
    return {
        "type": "indicator",
        "id": stix_id,
        **props,
        "name": name,
        **({"description": description} if description else {}),
        **({"indicator_types": list(indicator_types)} if indicator_types else {}),
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": SPEC,
        "valid_from": timestamp(valid_from),
        **({"labels": list(labels)} if labels else {}),
        **({"confidence": confidence} if confidence is not None else {}),
        **({"external_references": [dict(r) for r in external_references]} if external_references else {}),
    }


def relationship_object(
    stix_id: str,
    props: Mapping[str, Any],
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    *,
    description: str | None = None,
    labels: Sequence[str] = (),
    confidence: int | None = None,
) -> dict[str, Any]:
    """A relationship between two objects."""
    return {
        "type": "relationship",
        "id": stix_id,
        **props,
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        **({"description": description} if description else {}),
        **({"labels": list(labels)} if labels else {}),
        **({"confidence": confidence} if confidence is not None else {}),
    }


@dataclass(frozen=True)
class ExportTechnique:
    """A technique to put in a bundle."""

    id: str  # T1059.001
    name: str = ""
    tactics: tuple[str, ...] = ()  # kill-chain phase names ("execution")


@dataclass(frozen=True)
class ExportIndicator:
    """A value to put in a bundle as an indicator, with its observables."""

    key: str  # stable and unique within the export: what the indicator's id is derived from
    kind: Kind | str
    value: str
    name: str = ""
    description: str = ""
    created: datetime | None = None
    valid_from: datetime | None = None
    indicator_types: tuple[str, ...] = ("malicious-activity",)
    labels: tuple[str, ...] = ()
    confidence: int | None = None
    techniques: tuple[str, ...] = ()  # ATT&CK ids it indicates
    external_references: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class Export:
    """What `bundle` needs: who it's from, its TLP, and its parts."""

    namespace: uuid.UUID  # the product's own, so its ids never collide with another's
    key: str  # what makes this export the same one next time (a case or incident id)
    producer: str  # the identity's name
    tlp: str
    created: datetime
    name: str
    description: str = ""
    indicators: tuple[ExportIndicator, ...] = ()
    techniques: tuple[ExportTechnique, ...] = ()
    producer_key: str = ""  # what the identity's id is derived from; the producer's name if empty
    report_types: tuple[str, ...] = ("threat-report",)
    external_references: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


def bundle(export: Export, now: datetime) -> dict[str, Any]:
    """A bundle: the producer's identity, the TLP marking, an attack-pattern per technique, each
    indicator with its cyber observables and `indicates` relationships, and a report referencing them
    all. Ids are stable, so exporting again gives the same ids and a newer `modified`. Values STIX
    can't express are left out, logged."""
    ns, tlp = export.namespace, tlp_name(export.tlp)
    identity = object_id(ns, "identity", export.producer_key or export.producer)
    objects: list[dict[str, Any]] = [
        identity_object(identity, export.producer, export.created, now),
        tlp_marking(tlp),
    ]
    marking = [TLP_MARKINGS[tlp]]

    patterns: dict[str, str] = {}

    def technique(tid: str, name: str = "", tactics: Iterable[str] = ()) -> str:
        if tid not in patterns:
            ap = attack_pattern_object(
                object_id(ns, "attack-pattern", "mitre-attack", tid),
                tid,
                common(identity, export.created, now, tlp),
                name,
                tactics,
            )
            patterns[tid] = ap["id"]
            objects.append(ap)
        return patterns[tid]

    for t in export.techniques:
        technique(t.id, t.name, t.tactics)
    seen: set[str] = {o["id"] for o in objects}
    for item in export.indicators:
        scos, pattern = cyber_observables(item.kind, item.value, namespace=ns)
        if pattern is None:
            log.info("Left out of the bundle: STIX has no pattern for a %s", item.kind)
            continue
        for obj in scos:
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append({**obj, "object_marking_refs": marking})
        created = item.created or export.created
        indicator = indicator_object(
            object_id(ns, "indicator", export.key, item.key),
            common(identity, created, now, tlp),
            name=item.name or item.value,
            pattern=pattern,
            valid_from=item.valid_from or created,
            description=item.description or None,
            indicator_types=item.indicator_types,
            labels=item.labels,
            confidence=item.confidence,
            external_references=item.external_references,
        )
        objects.append(indicator)
        for tid in item.techniques:
            objects.append(
                relationship_object(
                    object_id(ns, "relationship", export.key, item.key, tid),
                    common(identity, created, now, tlp),
                    "indicates",
                    indicator["id"],
                    technique(tid),
                )
            )
    refs = [o["id"] for o in objects if o["type"] not in ("identity", "marking-definition")]
    objects.append(
        {
            "type": "report",
            "id": object_id(ns, "report", export.key),
            **common(identity, export.created, now, tlp),
            "name": export.name,
            **({"description": export.description} if export.description else {}),
            "report_types": list(export.report_types),
            "published": timestamp(now),
            "object_refs": refs,
            **(
                {"external_references": [dict(r) for r in export.external_references]}
                if export.external_references
                else {}
            ),
        }
    )
    return {"type": "bundle", "id": object_id(ns, "bundle", export.key, timestamp(now)), "objects": objects}
