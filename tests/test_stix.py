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


# ---- 0.1.1: a product's own objects in a bundle ---------------------------------------------------

SHIKARI_NAMESPACE = uuid.UUID("ad90fcf4-f2c8-4490-bf60-9d46f7697c62")  # shikari/parsers/stix_export.py
SHIKARI_HASHES = {32: stix.Kind.FILE_HASH_MD5, 40: stix.Kind.FILE_HASH_SHA1, 64: stix.Kind.FILE_HASH_SHA256,
                  128: stix.Kind.FILE_HASH_SHA512}  # fmt: skip
SHIKARI_KINDS = {
    "ip": stix.Kind.IP_ADDRESS,
    "domain": stix.Kind.DOMAIN,
    "file": stix.Kind.FILE_NAME,
    "cmd": stix.Kind.PROCESS_COMMAND,
    "reg": stix.Kind.REGISTRY_KEY,
    "sw": stix.Kind.PROCESS_NAME,
}


def shikari_export(run: dict, now: datetime) -> tuple[stix.Export, dict]:
    """Shikari's run_to_stix up to bundle(): the Export, and its techniques' names by id."""
    techniques, iocs = {}, {}
    for det in run["detections"]:
        tid = det.get("technique_id") or ""
        if tid and tid not in techniques:
            techniques[tid] = det.get("technique_name") or ""
        for ioc_kind, values in det["indicators"].items():
            for value in values:
                if ioc_kind == "hash":
                    found = stix.digest_of(value)
                    kind = found.kind if found else stix.Kind.FILE_HASH_SHA256
                else:
                    kind = SHIKARI_KINDS.get(ioc_kind)
                if kind is not None:
                    linked = iocs.setdefault((kind, value), [])
                    if tid and tid not in linked:
                        linked.append(tid)
    export = stix.Export(
        namespace=SHIKARI_NAMESPACE,
        key=run["group"],
        producer="Shikari",
        tlp="amber",
        created=now,
        name=f"Shikari run: {run['group']}",
        description=run["description"],
        techniques=tuple(stix.ExportTechnique(tid, name) for tid, name in techniques.items()),
        indicators=tuple(
            stix.ExportIndicator(
                key=f"{kind.value}|{value}", kind=kind, value=value, techniques=tuple(linked)
            )
            for (kind, value), linked in iocs.items()
        ),
    )
    return export, techniques


def shikari_own(run: dict, export: stix.Export, techniques: dict, now: datetime) -> list[dict]:
    """Shikari's intrusion-set, `uses` relationships and detections, from the Export's refs alone."""
    key, ns = export.key, export.namespace
    props = stix.common(export.identity_ref, now, now, export.tlp)
    patterns = {tid: export.attack_pattern_ref(tid) for tid in techniques}
    intrusion = {"type": "intrusion-set", "id": stix.object_id(ns, "intrusion-set", key), **props,
                 "name": run["group"], "description": run["description"]}  # fmt: skip
    own = [intrusion]
    for tid, pattern in patterns.items():
        rel = stix.object_id(ns, "relationship", key, "uses", tid)
        own.append(stix.relationship_object(rel, props, "uses", intrusion["id"], pattern))
    seen: dict = {}
    for det in run["detections"]:
        tid, name, siem = det["technique_id"], det["name"], det["siem"]
        n = seen[(name, siem, tid)] = seen.get((name, siem, tid), 0) + 1
        detection = {
            "type": "x-shikari-detection",
            "id": stix.object_id(ns, "x-shikari-detection", key, name, siem, tid, n),
            **props,
            "name": name,
            "siem": siem,
            "query": det.get("query") or "",
            "technique_id": tid,
        }
        own.append(detection)
        if tid in patterns:
            rel = stix.object_id(ns, "relationship", key, "detects", detection["id"])
            own.append(stix.relationship_object(rel, props, "detects", detection["id"], patterns[tid]))
    return own


def test_shikaris_export_through_extra_objects_is_byte_for_byte_what_it_makes_today():
    data = vector("stix/shikari-export.json")
    run = vector("misp/shikari-run.json")
    now = datetime.fromisoformat(data["now"])
    export, techniques = shikari_export(run, now)
    built = stix.bundle(export, now, extra_objects=shikari_own(run, export, techniques, now))
    assert json.dumps(built, indent=2) == json.dumps(data["bundle"], indent=2)


def test_the_export_names_the_ids_bundle_gives():
    data = vector("stix/shikari-export.json")
    export, techniques = shikari_export(vector("misp/shikari-run.json"), datetime.fromisoformat(data["now"]))
    plain = stix.bundle(export, NOW)
    assert plain["objects"][0]["id"] == export.identity_ref
    patterns = {o["external_references"][0]["external_id"]: o["id"] for o in plain["objects"]
                if o["type"] == "attack-pattern"}  # fmt: skip
    assert patterns == {tid: export.attack_pattern_ref(tid) for tid in techniques}
    assert export.attack_pattern_ref("T1059.001") == stix.object_id(
        SHIKARI_NAMESPACE, "attack-pattern", "mitre-attack", "T1059.001"
    )


def test_no_extra_objects_is_the_bundle_it_always_was():
    assert stix.bundle(export(), NOW) == stix.bundle(export(), NOW, extra_objects=())


def test_extra_objects_go_before_the_report_which_names_them_and_stays_last():
    ex = export()
    props = stix.common(ex.identity_ref, T0, NOW, ex.tlp)
    actor = {
        "type": "intrusion-set",
        "id": stix.object_id(NS, "intrusion-set", "Big Bad"),
        **props,
        "name": "Big Bad",
    }
    note = {"type": "note", "id": stix.object_id(NS, "note", "1"), **props, "content": "x",
            "object_refs": [actor["id"]]}  # fmt: skip
    plain = stix.bundle(ex, NOW)
    built = stix.bundle(ex, NOW, extra_objects=iter([actor, note]))  # any iterable
    assert built["objects"][:-1] == plain["objects"][:-1] + [actor, note]
    report = built["objects"][-1]
    assert report["type"] == "report"
    assert report["object_refs"] == plain["objects"][-1]["object_refs"] + [actor["id"], note["id"]]
    check_bundle(built)
    parsed = stix.parse(built)
    assert [g.name for g in parsed.groups] == ["Big Bad"] and parsed.reports[0].position == len(
        built["objects"]
    ) - 1


def test_an_extra_marking_or_identity_isnt_a_report_ref_as_the_standard_ones_arent():
    ex = export()
    second = stix.identity_object(stix.object_id(NS, "identity", "Other"), "Other", T0, NOW)
    built = stix.bundle(ex, NOW, extra_objects=[second, stix.tlp_marking("red")])
    assert second["id"] not in built["objects"][-1]["object_refs"]
    assert stix.TLP_MARKINGS["red"] not in built["objects"][-1]["object_refs"]


@pytest.mark.parametrize(
    "bad",
    [
        {"type": "indicator", "id": stix.object_id(NS, "indicator", "CASE-7", "ip-1")},  # already there
        {"type": "identity", "id": stix.object_id(NS, "identity", "Northwind Ltd")},
        {"type": "note"},
        {"id": "note--1"},
        {"type": "note", "id": ""},
    ],
)
def test_an_extra_object_without_an_id_or_with_one_taken_is_refused(bad):
    with pytest.raises(ValueError):
        stix.bundle(export(), NOW, extra_objects=[bad])


def test_two_extra_objects_with_one_id_are_refused():
    obj = {"type": "note", "id": "note--4a3a0d2b-5b8e-4d55-9a5c-8f7b0e4c2a11"}
    with pytest.raises(ValueError):
        stix.bundle(export(), NOW, extra_objects=[obj, dict(obj)])


# ---- 0.1.1: objects without an id ----------------------------------------------------------------


def with_ids(objects: list) -> list:
    """What Rowanholt passes stix.parse today (threat_intel/stix.py)."""
    return [o for o in objects if isinstance(o, dict) and isinstance(o.get("id"), str) and o["id"]]


@pytest.mark.parametrize("name", FIXTURES)
def test_skipping_objects_without_an_id_is_rowanholts_filter(name):
    bundle = bundle_of(name)
    skipped = stix.parse(bundle, skip_without_id=True)
    filtered = stix.parse({**bundle, "objects": with_ids(bundle["objects"])})
    assert skipped == filtered
    assert stix.parse(bundle) == stix.parse(bundle, skip_without_id=False)


def test_shikaris_bundle_has_objects_without_ids_and_they_are_skipped():
    bundle = bundle_of("shikari-bundle")
    kept, skipped = stix.parse(bundle), stix.parse(bundle, skip_without_id=True)
    assert skipped.object_count == len(with_ids(bundle["objects"])) < kept.object_count
    assert all(i.object_id for i in skipped.indicators) and all(g.stix_id for g in skipped.groups)


def test_a_relationship_without_an_id_links_nothing_when_skipped():
    objects = [
        {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'c2.example']"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT34"},
        {
            "type": "relationship",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "intrusion-set--1",
        },  # fmt: skip
        {"type": "indicator", "pattern": "[domain-name:value = 'no-id.example']"},
        {"type": "indicator", "id": "", "pattern": "[domain-name:value = 'empty-id.example']"},
        {"type": "indicator", "id": 7, "pattern": "[domain-name:value = 'number-id.example']"},
    ]
    kept = stix.parse(objects)
    assert kept.indicators[0].groups == ("APT34",) and len(kept.indicators) == 4
    skipped = stix.parse(objects, skip_without_id=True)
    assert [(i.value, i.groups) for i in skipped.indicators] == [("c2.example", ())]
    assert skipped.object_count == 2


def test_the_rowanholt_rows_read_the_same_from_a_skipping_parse():
    # Rowanholt's adapter still filters after parsing; with the bundle pre-skipped nothing changes
    for name in FIXTURES:
        bundle = bundle_of(name)
        assert rowanholt_rows({**bundle, "objects": with_ids(bundle["objects"])}) == rowanholt_rows(bundle)


# ---- 0.1.1: one table of digests -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kind", "stix_name", "misp_type"),
    [
        ("d41d8cd98f00b204e9800998ecf8427e", stix.Kind.FILE_HASH_MD5, "MD5", "md5"),
        ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", stix.Kind.FILE_HASH_SHA1, "SHA-1", "sha1"),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            stix.Kind.FILE_HASH_SHA256,
            "SHA-256",
            "sha256",
        ),
        (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            stix.Kind.FILE_HASH_SHA512,
            "SHA-512",
            "sha512",
        ),
    ],
)
def test_a_digest_is_named_by_its_length_for_stix_and_misp(value, kind, stix_name, misp_type):
    found = stix.digest_of(f" {value}\n")
    assert (found.kind, found.stix, found.misp, found.length) == (kind, stix_name, misp_type, len(value))
    assert stix.HASH_NAMES[kind] == stix_name and stix.HASH_KINDS[stix_name.lower()] is kind
    objects, pattern = stix.cyber_observables(kind, value)
    assert objects[0]["hashes"] == {stix_name: value.lower()}


@pytest.mark.parametrize("value", ["", "   ", "a" * 12, "a" * 56, "g" * 32, "a" * 31 + "-", "0x" + "a" * 30])
def test_anything_else_is_no_digest(value):
    assert stix.digest_of(value) is None


def test_the_digest_table_is_shikaris_by_length():
    assert {d.length: d.kind for d in stix.DIGESTS} == SHIKARI_HASHES
