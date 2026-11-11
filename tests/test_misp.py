"""MISP: reading every fixture as Shikari's importer does, rebuilding Ostraka's and Shikari's exported
events, and pushing through a fake instance."""

from __future__ import annotations

import asyncio
import json

import pytest
from adapters import shikari_misp
from conftest import vector

from samarkand import _http, misp
from samarkand.stix import Kind

FIXTURES = {"shikari-event": "event", "edges": "event", "ostraka-event": "event", "shikari-run": "event"}


@pytest.mark.parametrize("name", FIXTURES)
def test_shikaris_extraction_comes_out_exactly_as_shikari_makes_it(name):
    expected = vector("misp/expected-shikari.json")["fixtures"][name]
    assert shikari_misp(vector(f"misp/{name}.json")["event"]) == expected


def test_ostrakas_event_rebuilds_byte_for_byte():
    original = vector("misp/ostraka-event.json")["event"]
    body = original["Event"]
    for raw in body["Attribute"]:
        assert json.dumps(misp.Attribute.from_dict(raw).as_dict()) == json.dumps(raw)
    clusters = body["Galaxy"][0]["GalaxyCluster"]
    techniques = [(c["meta"]["external_id"][0], c["value"].rsplit(" - ", 1)[0]) for c in clusters]
    rebuilt = misp.event(
        uuid=body["uuid"],
        info=body["info"],
        date=body["date"],
        threat_level_id=body["threat_level_id"],
        analysis=body["analysis"],
        distribution=0,
        published=False,
        timestamp=int(body["timestamp"]),
        tlp="amber",
        techniques=techniques,
        attributes=[misp.Attribute.from_dict(a) for a in body["Attribute"]],
    )
    assert json.dumps(rebuilt) == json.dumps(original)


# Ostraka's observables in test_exports_units.record(), by reference: (kind, value as recorded)
OSTRAKA_OBSERVABLES = {
    "OBS-1": (Kind.IP_ADDRESS, "203.0.113.45"),
    "OBS-2": (Kind.FILE_HASH_SHA256, "9D3C7A1E5B2F48C06E1A7D4B9F3C2E8A1D6B5F4C3A2E1D0F9B8C7A6E5D4C3B2A"),
    "OBS-3": (Kind.URL, "https://evil.example/it's/gate.php"),
    "OBS-4": (Kind.FILE_PATH, "C:\\Users\\Public\\beacon.exe"),
    "OBS-5": (Kind.PROCESS_COMMAND, "powershell -nop -w hidden -enc SQBFAFgA"),
    "OBS-6": (Kind.CVE, "cve-2024-3400"),
}


def test_attribute_types_are_ostrakas():
    attributes = vector("misp/ostraka-event.json")["event"]["Event"]["Attribute"]
    by_ref = {a["comment"].split(".")[0]: a for a in attributes if a["comment"].startswith("OBS-")}
    assert set(by_ref) == set(OSTRAKA_OBSERVABLES)  # OBS-7, an alias, has no MISP type
    for ref, (kind, value) in OSTRAKA_OBSERVABLES.items():
        assert misp.attribute_type(kind, value) == (
            by_ref[ref]["type"],
            by_ref[ref]["category"],
            by_ref[ref]["value"],
        )
    assert misp.attribute_type("alias", "Big Bad") is None and misp.attribute_type(Kind.SOFTWARE, "x") is None


def test_certificates_and_ids():
    assert misp.attribute_type(Kind.CERTIFICATE, "AB:" * 19 + "CD")[0] == "x509-fingerprint-sha1"
    assert misp.attribute_type(Kind.CERTIFICATE, "0x1234serial") == (
        "text",
        "Network activity",
        "0x1234serial",
    )
    assert misp.attribute(Kind.PROCESS_COMMAND, "whoami", to_ids=True).to_ids is False
    assert misp.attribute(Kind.IP_ADDRESS, " 203.0.113.9 ", to_ids=True, comment="x" * 2000).as_dict() == {
        "type": "ip-dst",
        "category": "Network activity",
        "value": "203.0.113.9",
        "to_ids": True,
        "comment": "x" * 1000,
    }
    assert [misp.hash_type(v) for v in ("a" * 32, "a" * 40, "a" * 64, "a" * 128, "a" * 12, "zz")] == [
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha256",
        "sha256",
    ]


# Shikari's run_to_misp, through samarkand: its kinds and categories are Shikari's own
SHIKARI_KIND_ATTR = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "file": ("filename", "Payload delivery"),
    "reg": ("regkey", "Persistence mechanism"),
    "sw": ("windows-service-name", "Artifacts dropped"),
}


def shikari_run(group: str, detections: list, description: str, date: str) -> dict:
    attributes, seen, techniques = [], set(), []
    for det in detections:
        tid = det["technique_id"]
        if tid not in [t for t, _ in techniques]:
            techniques.append((tid, det.get("technique_name") or tid))
        for kind, values in det["indicators"].items():
            for value in values:
                if (kind, value) in seen:
                    continue
                seen.add((kind, value))
                if kind == "hash":
                    atype, category = misp.hash_type(value), "Payload delivery"
                elif kind in SHIKARI_KIND_ATTR:
                    atype, category = SHIKARI_KIND_ATTR[kind]
                else:
                    continue
                to_ids = kind in ("ip", "domain", "hash", "file")
                attributes.append(misp.Attribute(atype, category, value, to_ids=to_ids, comment="Shikari"))
    if description:
        attributes.insert(
            0, misp.Attribute("comment", "External analysis", description[:2000], comment="Shikari")
        )
    n, t = len(detections), len(techniques)
    info = (f"Shikari run: {group}" if group else "Shikari run") + (
        f" — {t} technique{'' if t == 1 else 's'}, {n} detection{'' if n == 1 else 's'}"
    )
    return misp.event(
        info=info,
        date=date,
        analysis="2",
        threat_level_id="2",
        attributes=attributes,
        techniques=techniques,
        threat_actor=group,
    )


def test_shikaris_run_event_rebuilds_with_the_same_content():
    data = vector("misp/shikari-run.json")
    rebuilt = shikari_run(
        data["group"], data["detections"], data["description"], data["event"]["Event"]["date"]
    )
    assert json.dumps(rebuilt, sort_keys=True) == json.dumps(data["event"], sort_keys=True)
    # Only the order of two keys differs: samarkand writes threat_level_id before analysis, as Ostraka does
    assert list(rebuilt["Event"]) == [
        "info",
        "date",
        "threat_level_id",
        "analysis",
        "distribution",
        "Attribute",
        "Tag",
        "Galaxy",
    ]
    assert list(data["event"]["Event"]) == [
        "info",
        "date",
        "analysis",
        "threat_level_id",
        "distribution",
        "Attribute",
        "Tag",
        "Galaxy",
    ]


def test_reading_takes_composites_objects_string_tags_and_actors():
    parsed = misp.parse(vector("misp/edges.json")["event"])
    assert (parsed.uuid, parsed.tlp, parsed.threat_actors) == (
        "5f0c1b9e-0000-4000-8000-000000000001",
        "amber+strict",
        ("Carbanak - FIN7",),
    )
    assert parsed.techniques == ("T1110", "T1566")
    pair = next(a for a in parsed.attributes if a.type == "domain|ip")
    assert [(p.type, p.value, p.kind) for p in pair.parts] == [
        ("domain", "evil.example", Kind.DOMAIN),
        ("ip", "203.0.113.7", Kind.IP_ADDRESS),
    ]
    dropped = [a for a in parsed.attributes if a.object_name == "file"]
    assert [(a.value, a.kind) for a in dropped] == [
        ("drop.dll", Kind.FILE_NAME),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", Kind.FILE_HASH_SHA1),
    ]
    assert not any(a.type == "ip-src" for a in parsed.attributes)  # empty values are left out
    url = next(a for a in parsed.attributes if a.type == "url")
    assert url.to_ids and url.category == "Network activity" and url.kind is Kind.URL


def test_reading_ostrakas_event_back():
    parsed = misp.parse(json.dumps(vector("misp/ostraka-event.json")["event"]))
    assert parsed.tlp == "amber" and parsed.techniques == ("T1071.001",)
    tags = {a.value: a.tags for a in parsed.attributes}
    assert tags["203.0.113.45"] == ('estimative-language:confidence-in-analytic-judgment="high"',)


@pytest.mark.parametrize("data", ["not json", [], {"Event": "x"}])
def test_anything_else_isnt_an_event(data):
    with pytest.raises(misp.NotAnEvent):
        misp.parse(data)


def test_a_bare_event_reads_too():
    assert (
        misp.parse({"info": "bare", "Attribute": [{"type": "md5", "value": "a" * 32}]}).attributes[0].kind
        is Kind.FILE_HASH_MD5
    )


def test_rest_search_answers_old_and_new():
    assert misp.events_of({"response": [{"Event": {"info": "a"}}, "junk"]}) == [{"Event": {"info": "a"}}]
    assert misp.events_of([{"Event": {"info": "b"}}]) == [{"Event": {"info": "b"}}]
    assert misp.events_of({"message": "nothing"}) == []


def test_tags_go_tlp_first_then_techniques_then_the_actor_then_the_rest():
    made = misp.event(
        info="x",
        date="2026-11-11",
        tlp="TLP:AMBER_STRICT",
        techniques=[("T1059.001", "PowerShell"), ("T9999", "")],
        threat_actor="FIN7",
        tags=["custom:a"],
    )
    assert [t["name"] for t in made["Event"]["Tag"]] == [
        "tlp:amber+strict",
        'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"',
        'misp-galaxy:mitre-attack-pattern="T9999"',
        'misp-galaxy:threat-actor="FIN7"',
        "custom:a",
    ]
    assert "uuid" not in made["Event"] and "published" not in made["Event"]


# ---- pushing ------------------------------------------------------------------------------------


class Instance:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, method, url, *, headers, timeout, verify, body=None):
        self.calls.append((method, url, headers, verify, body))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        status, payload = answer
        return _http.Response(status, json.dumps(payload).encode() if payload is not None else b"")


EVENT = {"Event": {"uuid": "0b6f8f4e-0000-4000-8000-000000000001", "info": "x"}}


def test_a_first_push_adds_and_a_second_updates():
    instance = Instance((404, None), (200, {"Event": {"id": "17", "uuid": EVENT["Event"]["uuid"]}}))
    pushed = misp.push("https://misp.example/", "key", EVENT, verify=False, request=instance)
    assert pushed == misp.Pushed("added", "17", EVENT["Event"]["uuid"], "https://misp.example/events/view/17")
    assert [c[:2] for c in instance.calls] == [
        ("GET", f"https://misp.example/events/view/{EVENT['Event']['uuid']}"),
        ("POST", "https://misp.example/events/add"),
    ]
    assert instance.calls[0][2]["Authorization"] == "key" and instance.calls[0][3] is False
    assert json.loads(instance.calls[1][4]) == EVENT
    again = Instance((200, {}), (200, {"Event": {"id": "17"}}))
    assert misp.push("https://misp.example", "key", EVENT, request=again).action == "updated"
    assert again.calls[1][1].endswith(f"/events/edit/{EVENT['Event']['uuid']}")


def test_an_event_without_a_uuid_is_added():
    instance = Instance((200, {"Event": {"id": "3", "uuid": "new"}}))
    assert misp.push("https://misp.example", "k", {"Event": {"info": "x"}}, request=instance).uuid == "new"
    assert len(instance.calls) == 1


@pytest.mark.parametrize(
    ("answers", "says"),
    [
        (
            ((404, None), (403, {"message": "Authentication failed."})),
            "refused the API key (HTTP 403). Authentication failed.",
        ),
        (((500, None),), "MISP answered HTTP 500."),
        (((404, None), (400, {"name": "Event could not be saved."})), "HTTP 400. Event could not be saved."),
        ((ConnectionRefusedError("refused"),), "Couldn't reach MISP: refused"),
    ],
)
def test_a_refused_push_says_why(answers, says):
    with pytest.raises(
        misp.MispProblem, match=says.replace(".", r"\.").replace("(", r"\(").replace(")", r"\)")
    ):
        misp.push("https://misp.example", "key", EVENT, request=Instance(*answers))


def test_no_url_is_a_problem_not_a_crash():
    with pytest.raises(misp.MispProblem, match="No MISP URL"):
        misp.push("  ", "key", EVENT, request=Instance())


def test_the_async_push_does_the_same():
    instance = Instance((404, None), (200, {"Event": {"id": "9"}}))

    async def request(*args, **kwargs):
        return instance(*args, **kwargs)

    assert asyncio.run(misp.push_async("https://misp.example", "k", EVENT, request=request)).event_id == "9"

    async def down(*args, **kwargs):
        raise OSError("gone")

    with pytest.raises(misp.MispProblem, match="Couldn't reach MISP: gone"):
        asyncio.run(misp.push_async("https://misp.example", "k", EVENT, request=down))


def test_version_proves_the_url_and_key():
    assert (
        misp.version("https://misp.example", "k", request=Instance((200, {"version": "2.5.12"}))) == "2.5.12"
    )
    with pytest.raises(misp.MispProblem, match="HTTP 401"):
        misp.version("https://misp.example", "k", request=Instance((401, None)))
