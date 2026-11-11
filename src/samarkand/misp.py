"""MISP events as plain JSON, without PyMISP: reading one, building one, and pushing it to an instance.

The shapes are the ones the products' exporters and importers already agree on:
ATT&CK techniques as `mitre-attack-pattern` galaxy clusters with `meta.external_id`, plus a
`misp-galaxy:mitre-attack-pattern="Name - T1234"` tag so simple parsers find them too; a group as a
`threat-actor` cluster and tag; the TLP as a `tlp:` tag from MISP's TLP 2.0 taxonomy.

What goes in an event (which values, which are for IDS, what the comments say) is the product's.
`event` only assembles one, with keys in a fixed order and empty optional fields left out.

`push` adds the event, or edits it when the instance already has its uuid, so pushing again
updates the same event. It never publishes: an admin publishes in MISP.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from samarkand import _http
from samarkand.stix import Kind

log = logging.getLogger(__name__)

TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CONFIDENCE_TAG = 'estimative-language:confidence-in-analytic-judgment="{}"'
ATTACK_TAG = 'misp-galaxy:mitre-attack-pattern="{}"'
ACTOR_TAG = 'misp-galaxy:threat-actor="{}"'
DISTRIBUTIONS = {0: "Your organisation only", 1: "This community only", 2: "Connected communities", 3: "All"}
COMMENT_LIMIT = 1000

# Kind -> (MISP attribute type, category). A kind not here has no faithful MISP type.
ATTRIBUTE_TYPES: dict[Kind, tuple[str, str]] = {
    Kind.IP_ADDRESS: ("ip-dst", "Network activity"),
    Kind.CIDR: ("ip-dst", "Network activity"),
    Kind.DOMAIN: ("domain", "Network activity"),
    Kind.URL: ("url", "Network activity"),
    Kind.EMAIL: ("email-src", "Payload delivery"),
    Kind.EMAIL_SUBJECT: ("email-subject", "Payload delivery"),
    Kind.FILE_HASH_MD5: ("md5", "Payload delivery"),
    Kind.FILE_HASH_SHA1: ("sha1", "Payload delivery"),
    Kind.FILE_HASH_SHA256: ("sha256", "Payload delivery"),
    Kind.FILE_HASH_SHA512: ("sha512", "Payload delivery"),
    Kind.FILE_NAME: ("filename", "Artifacts dropped"),
    Kind.FILE_PATH: ("filename", "Artifacts dropped"),
    Kind.PROCESS_NAME: ("filename", "Artifacts dropped"),
    Kind.PROCESS_COMMAND: ("text", "Artifacts dropped"),
    Kind.REGISTRY_KEY: ("regkey", "Persistence mechanism"),
    Kind.SERVICE_NAME: ("windows-service-name", "Artifacts dropped"),
    Kind.USER_ACCOUNT: ("target-user", "Targeting data"),
    Kind.CVE: ("vulnerability", "External analysis"),
    Kind.MUTEX: ("mutex", "Artifacts dropped"),
    Kind.ASN: ("AS", "Network activity"),
    Kind.MAC_ADDRESS: ("mac-address", "Network activity"),
    Kind.USER_AGENT: ("user-agent", "Network activity"),
    Kind.CERTIFICATE: ("x509-fingerprint-sha1", "Network activity"),
}
# Types an IDS can't match on, so never to_ids
NOT_FOR_IDS = frozenset({"text", "target-user", "phone-number", "vulnerability", "comment", "link"})
_CERT_TYPES = {32: "x509-fingerprint-md5", 40: "x509-fingerprint-sha1", 64: "x509-fingerprint-sha256"}
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# MISP attribute type -> Kind, for reading
KINDS: dict[str, Kind] = {
    "ip-src": Kind.IP_ADDRESS,
    "ip-dst": Kind.IP_ADDRESS,
    "ip": Kind.IP_ADDRESS,
    "domain": Kind.DOMAIN,
    "hostname": Kind.DOMAIN,
    "url": Kind.URL,
    "uri": Kind.URL,
    "link": Kind.URL,
    "md5": Kind.FILE_HASH_MD5,
    "sha1": Kind.FILE_HASH_SHA1,
    "sha256": Kind.FILE_HASH_SHA256,
    "sha512": Kind.FILE_HASH_SHA512,
    "imphash": Kind.FILE_HASH,
    "authentihash": Kind.FILE_HASH,
    "ssdeep": Kind.FILE_HASH,
    "tlsh": Kind.FILE_HASH,
    "filename": Kind.FILE_NAME,
    "filepath": Kind.FILE_PATH,
    "regkey": Kind.REGISTRY_KEY,
    "windows-service-name": Kind.SERVICE_NAME,
    "windows-service-displayname": Kind.SERVICE_NAME,
    "mutex": Kind.MUTEX,
    "command": Kind.PROCESS_COMMAND,
    "email": Kind.EMAIL,
    "email-src": Kind.EMAIL,
    "email-dst": Kind.EMAIL,
    "email-subject": Kind.EMAIL_SUBJECT,
    "target-user": Kind.USER_ACCOUNT,
    "vulnerability": Kind.CVE,
    "AS": Kind.ASN,
    "mac-address": Kind.MAC_ADDRESS,
    "user-agent": Kind.USER_AGENT,
    "x509-fingerprint-md5": Kind.CERTIFICATE,
    "x509-fingerprint-sha1": Kind.CERTIFICATE,
    "x509-fingerprint-sha256": Kind.CERTIFICATE,
}


class NotAnEvent(ValueError):
    """The document isn't a MISP event."""


# ---- building ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Attribute:
    """One MISP attribute. Optional fields left as None are left out of the event."""

    type: str
    category: str
    value: str
    to_ids: bool | None = None
    comment: str | None = None
    uuid: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    tags: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """The attribute as MISP JSON, keys in a fixed order."""
        out: dict[str, Any] = {}
        if self.uuid is not None:
            out["uuid"] = self.uuid
        out.update(type=self.type, category=self.category, value=self.value)
        for key in ("to_ids", "comment", "first_seen", "last_seen"):
            if getattr(self, key) is not None:
                out[key] = getattr(self, key)
        if self.tags:
            out["Tag"] = [{"name": t} for t in self.tags]
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Attribute:
        """An attribute from MISP JSON."""
        return cls(
            type=str(data.get("type", "")),
            category=str(data.get("category", "")),
            value=str(data.get("value", "")),
            to_ids=data.get("to_ids"),
            comment=data.get("comment"),
            uuid=data.get("uuid"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            tags=tuple(_tag_name(t) for t in data.get("Tag") or [] if _tag_name(t)),
        )


def hash_type(value: str) -> str:
    """md5, sha1, sha256 or sha512 by a hex digest's length; sha256 for anything else."""
    v = value.strip()
    if v and all(c in "0123456789abcdefABCDEF" for c in v):
        return _HASH_TYPES.get(len(v), "sha256")
    return "sha256"


def attribute_type(kind: Kind | str, value: str) -> tuple[str, str, str] | None:
    """(MISP type, category, value as MISP should hold it) for a value of a kind, or None when MISP has
    no faithful type. A certificate's type follows its digest's length; a CVE is upper-cased."""
    try:
        k = Kind(getattr(kind, "value", kind))
    except ValueError:
        return None
    mapped = ATTRIBUTE_TYPES.get(k)
    if mapped is None:
        return None
    misp_type, category = mapped
    value = value.strip()
    if k is Kind.CERTIFICATE:
        bare = value.replace(":", "").lower()
        if all(c in "0123456789abcdef" for c in bare):
            misp_type = _CERT_TYPES.get(len(bare), "text")
        else:
            misp_type = "text"
        value = bare if misp_type != "text" else value
    if k is Kind.CVE:
        value = value.upper()
    return misp_type, category, value


def attribute(kind: Kind | str, value: str, **fields: Any) -> Attribute | None:
    """An attribute for a value of a kind, or None when MISP has no faithful type. `to_ids` is
    forced off for types an IDS can't match on."""
    found = attribute_type(kind, value)
    if found is None:
        return None
    misp_type, category, held = found
    if fields.get("to_ids") and misp_type in NOT_FOR_IDS:
        fields["to_ids"] = False
    if isinstance(fields.get("comment"), str):
        fields["comment"] = fields["comment"][:COMMENT_LIMIT]
    return Attribute(misp_type, category, held, **fields)


def technique_label(tid: str, name: str = "") -> str:
    """MISP's cluster value for a technique: "PowerShell - T1059.001", or the id alone without a name."""
    return f"{name} - {tid}" if name and name != tid else tid


def event(
    *,
    info: str,
    date: str,
    attributes: Iterable[Attribute | Mapping[str, Any]] = (),
    techniques: Iterable[tuple[str, str]] = (),
    threat_actor: str = "",
    tlp: str | None = None,
    uuid: str | None = None,
    threat_level_id: str = "2",
    analysis: str = "1",
    distribution: int | str = 0,
    published: bool | None = None,
    timestamp: int | None = None,
    tags: Sequence[str] = (),
) -> dict[str, Any]:
    """An event: {"Event": {...}}. `techniques` are (ATT&CK id, name) pairs, each a galaxy cluster
    and a tag; `threat_actor` a cluster and a tag; `tlp` a `tlp:` tag first among the tags; `tags`
    any others, last. `analysis` is MISP's 0 initial, 1 ongoing, 2 complete; `threat_level_id` 1 high
    to 4 undefined."""
    techniques = list(techniques)
    labels = [technique_label(tid, name) for tid, name in techniques]
    event_tags = [f"tlp:{_tlp(tlp)}"] if tlp else []
    event_tags += [ATTACK_TAG.format(label) for label in labels]
    if threat_actor:
        event_tags.append(ACTOR_TAG.format(threat_actor))
    event_tags += list(tags)
    galaxies: list[dict[str, Any]] = []
    if techniques:
        galaxies.append(
            {
                "type": "mitre-attack-pattern",
                "name": "Attack Pattern",
                "GalaxyCluster": [
                    {"type": "mitre-attack-pattern", "value": label, "meta": {"external_id": [tid]}}
                    for (tid, _), label in zip(techniques, labels, strict=True)
                ],
            }
        )
    if threat_actor:
        galaxies.append(
            {
                "type": "threat-actor",
                "name": "Threat Actor",
                "GalaxyCluster": [{"type": "threat-actor", "value": threat_actor}],
            }
        )
    body: dict[str, Any] = {}
    if uuid is not None:
        body["uuid"] = uuid
    body.update(info=info, date=date, threat_level_id=str(threat_level_id), analysis=str(analysis))
    body["distribution"] = str(distribution)
    if published is not None:
        body["published"] = published
    if timestamp is not None:
        body["timestamp"] = str(int(timestamp))
    body["Attribute"] = [a.as_dict() if isinstance(a, Attribute) else dict(a) for a in attributes]
    body["Tag"] = [{"name": t} for t in event_tags]
    body["Galaxy"] = galaxies
    return {"Event": body}


def _tlp(tlp: str) -> str:
    name = str(getattr(tlp, "value", tlp)).strip().lower().removeprefix("tlp:").replace("_", "+")
    return "clear" if name == "white" else name


# ---- reading ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Part:
    """One half of a composite attribute (filename|md5): its type and value."""

    type: str
    value: str
    kind: Kind | None = None


@dataclass(frozen=True)
class ParsedAttribute:
    """An attribute as read, with its neutral kind, and both halves of a composite one."""

    type: str
    value: str
    category: str = ""
    to_ids: bool = False
    comment: str = ""
    uuid: str = ""
    object_name: str = ""  # the MISP object it was in, if any
    tags: tuple[str, ...] = ()
    kind: Kind | None = None
    parts: tuple[Part, ...] = ()

    @property
    def composite(self) -> bool:
        """filename|md5, domain|ip, regkey|value and the like."""
        return bool(self.parts)


@dataclass(frozen=True)
class Cluster:
    """A galaxy cluster."""

    galaxy: str  # the galaxy's type
    value: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedEvent:
    """An event read into neutral parts."""

    uuid: str
    info: str
    date: str
    attributes: tuple[ParsedAttribute, ...] = ()
    tags: tuple[str, ...] = ()
    attack_patterns: tuple[Cluster, ...] = ()
    threat_actors: tuple[str, ...] = ()  # cluster values, as given ("Carbanak - FIN7")
    techniques: tuple[str, ...] = ()  # ATT&CK ids from galaxies and tags, in order, once each
    tlp: str = ""


def _tag_name(tag: Any) -> str:
    return str(tag.get("name", "")) if isinstance(tag, dict) else str(tag)


def _attribute(data: Mapping[str, Any], object_name: str = "") -> ParsedAttribute | None:
    misp_type = str(data.get("type", ""))
    value = str(data.get("value", "")).strip()
    if not value:
        return None
    parts: tuple[Part, ...] = ()
    if "|" in misp_type and "|" in value:
        types = misp_type.split("|", 1)
        values = value.split("|", 1)
        parts = tuple(Part(t, v.strip(), KINDS.get(t)) for t, v in zip(types, values, strict=True))
    return ParsedAttribute(
        type=misp_type,
        value=value,
        category=str(data.get("category", "")),
        to_ids=bool(data.get("to_ids", False)),
        comment=str(data.get("comment") or ""),
        uuid=str(data.get("uuid") or ""),
        object_name=object_name,
        tags=tuple(n for n in (_tag_name(t) for t in data.get("Tag") or []) if n),
        kind=None if parts else KINDS.get(misp_type),
        parts=parts,
    )


def parse(data: str | bytes | Mapping[str, Any]) -> ParsedEvent:
    """A MISP event ({"Event": {...}} or a bare event, or its JSON) read into neutral parts.
    Attributes inside objects are read after the event's own. Raises NotAnEvent."""
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise NotAnEvent(f"Not JSON: {exc}") from exc
    found = data.get("Event", data) if isinstance(data, Mapping) else None
    if not isinstance(found, Mapping):
        raise NotAnEvent("Not a MISP event.")
    attributes = [_attribute(a) for a in found.get("Attribute") or [] if isinstance(a, Mapping)]
    for obj in found.get("Object") or []:
        if isinstance(obj, Mapping):
            name = str(obj.get("name", ""))
            attributes += [_attribute(a, name) for a in obj.get("Attribute") or [] if isinstance(a, Mapping)]
    tags = tuple(n for n in (_tag_name(t) for t in found.get("Tag") or []) if n)
    techniques: list[str] = []

    def note(text: str) -> None:
        for tid in TECHNIQUE.findall(text):
            if tid not in techniques:
                techniques.append(tid)

    for tag in tags:
        if "mitre" in tag.lower() or "attack-pattern" in tag.lower():
            note(tag)
    patterns, actors = [], []
    for galaxy in found.get("Galaxy") or []:
        if not isinstance(galaxy, Mapping):
            continue
        kind = str(galaxy.get("type", ""))
        for cluster in galaxy.get("GalaxyCluster") or []:
            if not isinstance(cluster, Mapping):
                continue
            value = str(cluster.get("value", ""))
            meta = cluster.get("meta") if isinstance(cluster.get("meta"), dict) else {}
            if "attack-pattern" in kind:
                patterns.append(Cluster(kind, value, meta))
                note(value + " " + json.dumps(meta))
            elif "threat-actor" in kind or "intrusion-set" in kind:
                actors.append(value)
    tlp = next((t.split(":", 1)[1].strip() for t in tags if t.lower().startswith("tlp:")), "")
    return ParsedEvent(
        uuid=str(found.get("uuid") or ""),
        info=str(found.get("info", "")),
        date=str(found.get("date") or ""),
        attributes=tuple(a for a in attributes if a is not None),
        tags=tags,
        attack_patterns=tuple(patterns),
        threat_actors=tuple(actors),
        techniques=tuple(techniques),
        tlp=tlp.lower(),
    )


def events_of(payload: Any) -> list[dict[str, Any]]:
    """The events in a `/events/restSearch` answer: {"response": [{"Event": …}, …]} on current MISP,
    a bare list on older versions."""
    body = payload.get("response", payload) if isinstance(payload, dict) else payload
    return [e for e in body if isinstance(e, dict)] if isinstance(body, list) else []


# ---- pushing ----------------------------------------------------------------------------------------


class MispProblem(Exception):
    """The MISP instance refused or couldn't be reached, with a reason an admin can act on."""


@dataclass(frozen=True)
class Pushed:
    """What MISP made of a push."""

    action: str  # "added" or "updated"
    event_id: str
    uuid: str
    url: str


Request = Callable[..., _http.Response]


def _headers(key: str, user_agent: str) -> dict[str, str]:
    return {
        "Authorization": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }


def _problem(status: int, body: bytes) -> MispProblem:
    try:
        found = json.loads(body)
        message = str(found.get("message") or found.get("name") or "")
    except (ValueError, AttributeError):
        message = ""
    if status in (401, 403):
        return MispProblem(f"MISP refused the API key (HTTP {status}). {message}".strip())
    return MispProblem(f"MISP answered HTTP {status}. {message}".strip())


def _unreachable(exc: BaseException) -> MispProblem:
    return MispProblem(f"Couldn't reach MISP: {str(exc)[:200] or type(exc).__name__}")


def _pushed(root: str, exists: bool, event_uuid: str, answer: bytes) -> Pushed:
    try:
        made = json.loads(answer).get("Event", {})
    except (ValueError, AttributeError):
        made = {}
    event_id = str(made.get("id", "")) if isinstance(made, dict) else ""
    made_uuid = str(made.get("uuid", event_uuid)) if isinstance(made, dict) else event_uuid
    return Pushed(
        "updated" if exists else "added", event_id, made_uuid, f"{root}/events/view/{event_id or event_uuid}"
    )


def _plan(base_url: str, payload: Mapping[str, Any]) -> tuple[str, str | None, bytes]:
    root = base_url.strip().rstrip("/")
    if not root:
        raise MispProblem("No MISP URL is set.")
    event_uuid = payload.get("Event", {}).get("uuid") if isinstance(payload.get("Event"), dict) else None
    return root, event_uuid, json.dumps(payload).encode()


def push(
    base_url: str,
    key: str,
    payload: Mapping[str, Any],
    *,
    verify: bool = True,
    timeout: float = 30.0,
    user_agent: str = "samarkand-misp/1",
    request: Request = _http.request,
) -> Pushed:
    """Add the event (`/events/add`), or edit it when MISP already has one with its uuid. An event
    without a uuid is always added. Raises MispProblem."""
    root, event_uuid, body = _plan(base_url, payload)
    headers = _headers(key, user_agent)
    exists = False
    try:
        if event_uuid:
            seen = request(
                "GET", f"{root}/events/view/{event_uuid}", headers=headers, timeout=timeout, verify=verify
            )
            # MISP answers a missing event with 404, or 403 on some versions; a bad key fails the add too
            if seen.status not in (200, 403, 404):
                raise _problem(seen.status, b"")
            exists = seen.status == 200
        path = f"/events/edit/{event_uuid}" if exists else "/events/add"
        answer = request("POST", root + path, body=body, headers=headers, timeout=timeout, verify=verify)
    except OSError as exc:
        raise _unreachable(exc) from exc
    if answer.status >= 300:
        raise _problem(answer.status, answer.body)
    return _pushed(root, exists, event_uuid or "", answer.body)


async def push_async(
    base_url: str,
    key: str,
    payload: Mapping[str, Any],
    *,
    verify: bool = True,
    timeout: float = 30.0,
    user_agent: str = "samarkand-misp/1",
    request: Callable[..., Any] = _http.request_async,
) -> Pushed:
    """`push` with httpx (`samarkand[async]`)."""
    root, event_uuid, body = _plan(base_url, payload)
    headers = _headers(key, user_agent)
    exists = False
    try:
        if event_uuid:
            seen = await request(
                "GET", f"{root}/events/view/{event_uuid}", headers=headers, timeout=timeout, verify=verify
            )
            if seen.status not in (200, 403, 404):
                raise _problem(seen.status, b"")
            exists = seen.status == 200
        path = f"/events/edit/{event_uuid}" if exists else "/events/add"
        answer = await request(
            "POST", root + path, body=body, headers=headers, timeout=timeout, verify=verify
        )
    except MispProblem:
        raise
    except Exception as exc:  # noqa: BLE001 (httpx's errors, without importing httpx here)
        raise _unreachable(exc) from exc
    if answer.status >= 300:
        raise _problem(answer.status, answer.body)
    return _pushed(root, exists, event_uuid or "", answer.body)


def version(
    base_url: str,
    key: str,
    *,
    verify: bool = True,
    timeout: float = 30.0,
    user_agent: str = "samarkand-misp/1",
    request: Request = _http.request,
) -> str:
    """The instance's MISP version, which proves the URL and key work. Raises MispProblem."""
    root = base_url.strip().rstrip("/")
    try:
        answer = request(
            "GET",
            f"{root}/servers/getVersion",
            headers=_headers(key, user_agent),
            timeout=timeout,
            verify=verify,
        )
    except OSError as exc:
        raise _unreachable(exc) from exc
    if answer.status >= 300:
        raise _problem(answer.status, answer.body)
    try:
        return str(json.loads(answer.body).get("version", ""))
    except (ValueError, AttributeError):
        return ""
