"""STIX: reading every product's fixtures into what each product produces today, and building objects
byte for byte as Ostraka's exporter does, checked against the spec's rules."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import pytest
from adapters import rowanholt_rows, shikari_stix
from conftest import vector

from samarkand import stix

OSTRAKA_NAMESPACE = uuid.UUID("5c6f5e0e-58f4-4f39-9b0e-0f3e2a5c0b7d")  # ostraka/exports/stix.py
FIXTURES = ("rowanholt-groups", "rowanholt-validity", "shikari-bundle", "edges", "ostraka-bundle")


def bundle_of(name: str) -> dict:
    return vector(f"stix/{name}.json")["bundle"]


# ---- reading ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", FIXTURES)
def test_rowanholts_rows_and_validity_come_out_exactly_as_rowanholt_makes_them(name):
    expected = vector("stix/expected-rowanholt.json")["fixtures"][name]
    assert rowanholt_rows(bundle_of(name)) == expected


# Shikari's pattern reader doesn't undo escapes (\' and \\), so where a fixture has one its values
# differ, and samarkand's are the right ones (docs/DIFFERENCES.md, STIX). Each pair is (Shikari's,
# samarkand's).
SHIKARI_ESCAPES = {
    "edges": {("file", "it\\", "it's.exe"), ("reg", "HKLM\\\\Run%", "HKLM\\Run%")},
    "ostraka-bundle": {("file", "C:\\\\Users\\\\Public", "C:\\Users\\Public")},
}


def flat(iocs: dict) -> set:
    return {(kind, value) for kind, values in iocs.items() for value in values}


@pytest.mark.parametrize("name", FIXTURES)
def test_shikaris_extraction_comes_out_as_shikari_makes_it_but_for_escapes(name):
    expected = vector("stix/expected-shikari.json")["fixtures"][name]
    got = shikari_stix(bundle_of(name))
    assert {k: v for k, v in got.items() if k != "iocs"} == {k: v for k, v in expected.items() if k != "iocs"}
    pairs = SHIKARI_ESCAPES.get(name, set())
    assert flat(expected["iocs"]) - flat(got["iocs"]) == {(kind, theirs) for kind, theirs, _ in pairs}
    assert flat(got["iocs"]) - flat(expected["iocs"]) == {(kind, ours) for kind, _, ours in pairs}
    if not pairs:
        assert got == expected


def test_each_value_keeps_its_own_links():
    parsed = stix.parse(bundle_of("rowanholt-groups"))
    c2 = next(i for i in parsed.indicators if i.value == "c2.example.test")
    assert (c2.kind, c2.groups, [t.id for t in c2.techniques]) == (
        stix.Kind.DOMAIN,
        ("APT34",),
        ["T1071.001"],
    )
    assert c2.techniques[0].tactics == ("command-and-control",)
    hashed = next(i for i in parsed.indicators if i.stix_type == "file")
    assert (hashed.kind, hashed.stix_path, hashed.groups) == (
        stix.Kind.FILE_HASH_SHA256,
        "hashes.'SHA-256'",
        (),
    )
    assert parsed.only_group == "" and [g.name for g in parsed.groups] == ["APT34", "APT35"]


def test_patterns_unescape_and_every_comparison_is_read():
    parsed = stix.parse(bundle_of("edges"))
    by_value = {i.value: i for i in parsed.indicators}
    assert by_value["it's.exe"].kind is stix.Kind.FILE_NAME
    assert by_value["HKLM\\Run%"].kind is stix.Kind.REGISTRY_KEY
    assert by_value["Cobalt Strike"].kind is stix.Kind.SOFTWARE
    assert by_value["rundll32.exe"].kind is stix.Kind.PROCESS_NAME
    assert by_value["https://evil.example/a?b=1"].kind is stix.Kind.URL
    quoted = by_value["it's.exe"]
    assert quoted.named_techniques == ("T1105",) and quoted.groups == ("FIN7",)
    assert quoted.valid_from == datetime(2026, 2, 1, 9, tzinfo=timezone.utc) and quoted.confidence is None
    assert by_value["192.0.2.10"].techniques[0].name == "PowerShell"
    assert parsed.reports[0].references == ("https://vendor.example/r/1",)


def test_kinds_from_stix_types():
    cases = {
        "[ipv6-addr:value = '2001:db8::/32']": stix.Kind.CIDR,
        "[file:hashes.MD5 = 'x']": stix.Kind.FILE_HASH_MD5,
        "[file:hashes.'SHA-512' = 'x']": stix.Kind.FILE_HASH_SHA512,
        "[file:hashes.SSDEEP = 'x']": stix.Kind.FILE_HASH,
        "[file:parent_directory_ref.path = 'C:\\\\x']": stix.Kind.DIRECTORY,
        "[email-addr:value = 'x']": stix.Kind.EMAIL,
        "[email-message:subject = 'x']": stix.Kind.EMAIL_SUBJECT,
        "[x509-certificate:serial_number = 'x']": stix.Kind.CERTIFICATE,
        "[process:extensions.'windows-service-ext'.service_name = 'x']": stix.Kind.SERVICE_NAME,
        "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'x']": (
            stix.Kind.USER_AGENT
        ),
        "[mutex:name = 'x']": stix.Kind.MUTEX,
        "[artifact:mime_type = 'x']": None,
    }
    for pattern, kind in cases.items():
        (item,) = stix.parse([{"type": "indicator", "id": "indicator--1", "pattern": pattern}]).indicators
        assert item.kind is kind, pattern


def test_a_newer_version_of_an_object_replaces_the_old_in_its_place():
    parsed = stix.parse(
        [
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'old.example']"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value = 'b.example']"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'new.example']"},
        ]
    )
    assert [i.value for i in parsed.indicators] == ["new.example", "b.example"]


@pytest.mark.parametrize("data", [{"foo": "bar"}, "not json", b"{}", 3])
def test_anything_else_isnt_a_bundle(data):
    with pytest.raises(stix.NotABundle):
        stix.parse(data)


def test_json_text_and_a_bare_list_both_read():
    text = json.dumps(bundle_of("shikari-bundle"))
    assert stix.parse(text).techniques[0].ids == ("T1003.001",)
    assert stix.parse(bundle_of("shikari-bundle")["objects"]).groups[0].name == "APT29"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-01-01T00:00:00Z", datetime(2026, 1, 1, tzinfo=timezone.utc)),
        ("2026-04-01T00:00:00.000Z", datetime(2026, 4, 1, tzinfo=timezone.utc)),
        ("2026-04-01T00:00:00.12Z", datetime(2026, 4, 1, 0, 0, 0, 120000, tzinfo=timezone.utc)),
        ("2026-04-01T00:00:00.123456789Z", datetime(2026, 4, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)),
        ("2026-04-01T02:00:00+02:00", datetime(2026, 4, 1, tzinfo=timezone.utc)),
        ("2026-04-01", datetime(2026, 4, 1, tzinfo=timezone.utc)),
        ("2026-02-30T00:00:00Z", None),
        ("yesterday", None),
        (12, None),
    ],
)
def test_timestamps_read_the_same_on_every_python(text, expected):
    assert stix.parse_time(text) == expected


# ---- building -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case", vector("stix/ostraka-observables.json")["cases"], ids=lambda c: f"{c['kind']}:{c['value']}"
)
def test_cyber_observables_and_patterns_are_ostrakas_byte_for_byte(case):
    objects, pattern = stix.cyber_observables(case["kind"], case["value"], namespace=OSTRAKA_NAMESPACE)
    assert json.dumps(objects) == json.dumps(case["objects"]) and pattern == case["pattern"]


@pytest.mark.parametrize(("tlp", "marking"), vector("stix/tlp-markings.json")["markings"].items())
def test_tlp_markings_are_the_oasis_definitions_byte_for_byte(tlp, marking):
    assert json.dumps(stix.tlp_marking(tlp)) == json.dumps(marking)


def test_tlp_names_are_forgiving():
    assert stix.tlp_name("TLP:AMBER+STRICT") == stix.tlp_name("amber_strict") == "amber+strict"
    assert stix.tlp_name("white") == "clear"
    with pytest.raises(ValueError):
        stix.tlp_name("purple")


def test_ostrakas_identity_attack_patterns_and_relationships_rebuild_byte_for_byte():
    data = vector("stix/ostraka-bundle.json")
    now = datetime.fromisoformat(data["now"])
    objects = data["bundle"]["objects"]
    identity, marking = objects[0], objects[1]
    declared = stix.parse_time(identity["created"])
    assert json.dumps(stix.identity_object(identity["id"], identity["name"], declared, now)) == json.dumps(
        identity
    )
    assert identity["id"] == stix.object_id(
        OSTRAKA_NAMESPACE, "identity", "http://ostraka.test/|Northwind Ltd"
    )
    assert json.dumps(stix.tlp_marking("amber")) == json.dumps(marking)
    patterns = [o for o in objects if o["type"] == "attack-pattern"]
    relationships = [o for o in objects if o["type"] == "relationship"]
    assert patterns and relationships
    for ap in patterns:
        tid = ap["external_references"][0]["external_id"]
        assert ap["id"] == stix.object_id(OSTRAKA_NAMESPACE, "attack-pattern", "mitre-attack", tid)
        rebuilt = stix.attack_pattern_object(
            ap["id"],
            tid,
            stix.common(identity["id"], declared, now, "amber"),
            ap["name"],
            [p["phase_name"] for p in ap.get("kill_chain_phases", [])],
        )
        assert json.dumps(rebuilt) == json.dumps(ap)
    for rel in relationships:
        rebuilt = stix.relationship_object(
            rel["id"],
            stix.common(identity["id"], stix.parse_time(rel["created"]), now, "amber"),
            rel["relationship_type"],
            rel["source_ref"],
            rel["target_ref"],
            description=rel["description"],
            labels=rel["labels"],
            confidence=rel["confidence"],
        )
        assert json.dumps(rebuilt) == json.dumps(rel)
    for ind in (o for o in objects if o["type"] == "indicator"):
        rebuilt = stix.indicator_object(
            ind["id"],
            stix.common(identity["id"], stix.parse_time(ind["created"]), now, "amber"),
            name=ind["name"],
            pattern=ind["pattern"],
            valid_from=stix.parse_time(ind["valid_from"]),
            description=ind["description"],
            indicator_types=ind["indicator_types"],
            labels=ind["labels"],
            confidence=ind["confidence"],
            external_references=ind["external_references"],
        )
        assert json.dumps(rebuilt) == json.dumps(ind)


def test_timestamps_are_utc_milliseconds():
    assert (
        stix.timestamp(datetime(2026, 11, 11, 12, 0, 0, 123456, tzinfo=timezone.utc))
        == "2026-11-11T12:00:00.123Z"
    )
    assert stix.timestamp(datetime(2026, 11, 11, 12)) == "2026-11-11T12:00:00.000Z"


# The rules of STIX 2.1 a consumer relies on (Ostraka's tests/test_exports_units.py check_bundle)
ID = re.compile(
    r"^([a-z][a-z0-9-]+)--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
SCO = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file", "directory", "process", "mutex",
       "windows-registry-key", "mac-addr", "user-account", "email-message", "autonomous-system",
       "x509-certificate", "software"}  # fmt: skip
REQUIRED = {
    "identity": {"name"},
    "report": {"name", "published", "object_refs"},
    "attack-pattern": {"name"},
    "indicator": {"pattern", "pattern_type", "valid_from"},
    "relationship": {"relationship_type", "source_ref", "target_ref"},
    "marking-definition": {"created"},
}


def refs_in(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k != "id":
                yield from refs_in(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from refs_in(v, key)
    elif isinstance(obj, str) and (key.endswith("_ref") or key.endswith("_refs")):
        yield obj


def check_bundle(bundle: dict) -> dict:
    assert bundle["type"] == "bundle" and ID.match(bundle["id"]).group(1) == "bundle"
    assert "spec_version" not in bundle
    objects = {o["id"]: o for o in bundle["objects"]}
    assert len(objects) == len(bundle["objects"]), "duplicate ids"
    for obj in bundle["objects"]:
        match = ID.match(obj["id"])
        assert match and match.group(1) == obj["type"], obj["id"]
        assert obj["spec_version"] == "2.1"
        assert REQUIRED.get(obj["type"], set()) <= obj.keys(), obj["type"]
        if obj["type"] not in SCO:
            assert TS.match(obj["created"]), obj
            if obj["type"] != "marking-definition":
                assert TS.match(obj["modified"]) and obj["modified"] >= obj["created"], obj
        for ref in refs_in(obj):
            assert ref in objects, f"{obj['id']} refers to missing {ref}"
        if obj["type"] not in ("marking-definition", "identity"):
            assert obj["object_marking_refs"] == [stix.TLP_MARKINGS["green"]], obj
    return objects


NS = uuid.UUID("3b6e0d55-6a33-4c55-8f0e-2b6d3e5d9c11")  # this test's own
T0 = datetime(2026, 11, 9, 8, tzinfo=timezone.utc)
NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)


def export() -> stix.Export:
    return stix.Export(
        namespace=NS,
        key="CASE-7",
        producer="Northwind Ltd",
        tlp="green",
        created=T0,
        name="CASE-7: beaconing",
        description="Two indicators.",
        techniques=(stix.ExportTechnique("T1071.001", "Web Protocols", ("command-and-control",)),),
        indicators=(
            stix.ExportIndicator(
                "ip-1", stix.Kind.IP_ADDRESS, "203.0.113.45", confidence=85, techniques=("T1071.001",)
            ),
            stix.ExportIndicator(
                "cmd-1", "process_command", "powershell -enc 'x'", techniques=("T1059.001",)
            ),
            stix.ExportIndicator("path-1", stix.Kind.FILE_PATH, "C:\\Users\\Public\\beacon.exe"),
            stix.ExportIndicator("dup-ip", stix.Kind.IP_ADDRESS, "203.0.113.45"),
            stix.ExportIndicator("alias", "alias", "Big Bad"),
        ),
    )


def test_a_built_bundle_follows_the_spec_and_every_reference_resolves():
    built = stix.bundle(export(), NOW)
    objects = check_bundle(built)
    kinds = [o["type"] for o in built["objects"]]
    assert kinds.count("indicator") == 4 and kinds.count("ipv4-addr") == 1  # one SCO for the repeated IP
    assert kinds.count("attack-pattern") == 2  # T1059.001 added when an indicator names it
    report = built["objects"][-1]
    assert report["type"] == "report" and set(report["object_refs"]) == set(objects) - {
        built["objects"][0]["id"],
        stix.TLP_MARKINGS["green"],
        report["id"],
    }
    rels = [o for o in built["objects"] if o["type"] == "relationship"]
    assert {(objects[r["source_ref"]]["pattern"], objects[r["target_ref"]]["name"]) for r in rels} == {
        ("[ipv4-addr:value = '203.0.113.45']", "Web Protocols"),
        ("[process:command_line = 'powershell -enc \\'x\\'']", "T1059.001"),
    }


def test_the_same_export_twice_has_the_same_ids():
    first, second = stix.bundle(export(), NOW), stix.bundle(export(), NOW.replace(hour=13))
    assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]
    assert first["id"] != second["id"]


def test_a_built_bundle_reads_back():
    parsed = stix.parse(stix.bundle(export(), NOW))
    ip = next(i for i in parsed.indicators if i.object_type == "indicator" and i.value == "203.0.113.45")
    assert [t.id for t in ip.techniques] == ["T1071.001"] and ip.confidence == 85
    assert parsed.reports[0].name == "CASE-7: beaconing"
