"""Navigator layers: Rowanholt's and Ostraka's rebuilt byte for byte, and the release read from ATT&CK's
own data."""

from __future__ import annotations

import json

import pytest
from conftest import vector

from samarkand import navigator as N

RH = vector("navigator/rowanholt-layers.json")
OST = vector("navigator/ostraka-layer.json")


def test_rowanholts_layers_are_rowanholts_byte_for_byte():
    techniques = {tid: tuple(v) for tid, v in RH["techniques"].items()}
    plain = N.build_layer(
        "CASE-1",
        "enterprise-attack",
        techniques,
        attack_version=RH["attack_version"],
        platforms=RH["platforms"],
    )
    assert json.dumps(plain) == json.dumps(RH["layers"]["plain"])
    confirmed = N.build_layer(
        "CASE-1 (confirmed)",
        "enterprise-attack",
        techniques,
        attack_version=RH["attack_version"],
        platforms=RH["platforms"],
        description="Techniques behind the analysts' confirmed findings only",
        legend=RH["legend"],
        show_ids=True,
    )
    assert json.dumps(confirmed) == json.dumps(RH["layers"]["confirmed"])
    mobile = N.build_layer(
        "CASE-1",
        "mobile-attack",
        {"T1406": ("#ed5565", "x")},
        attack_version="20.1",
        platforms=RH["mobile_platforms"],
    )
    assert json.dumps(mobile) == json.dumps(RH["layers"]["mobile"])


@pytest.mark.parametrize("which", ["confirmed", "with_leads"])
def test_ostrakas_layers_are_ostrakas_byte_for_byte(which):
    layer = OST[which]
    marks = {t["techniqueID"]: N.Mark(t["color"], t["comment"], t["links"]) for t in layer["techniques"]}
    rebuilt = N.build_layer(
        layer["name"],
        layer["domain"],
        marks,
        attack_version=OST["attack_version"],
        platforms=OST["platforms"],
        description=layer["description"],
        legend=layer["legendItems"],
        show_ids=True,
        metadata=layer["metadata"],
        links=[],
    )
    assert json.dumps(rebuilt) == json.dumps(layer)


def test_a_parent_opens_when_its_sub_techniques_are_marked_and_comments_are_cut():
    layer = N.build_layer(
        "x",
        N.ENTERPRISE,
        {"T1059.001": N.Mark("#fff", "y" * 1500), "T1059": ("#fff", "")},
        attack_version="18",
        platforms=[],
    )
    shown = {t["techniqueID"]: t for t in layer["techniques"]}
    assert shown["T1059"]["showSubtechniques"] and not shown["T1059.001"]["showSubtechniques"]
    assert len(shown["T1059.001"]["comment"]) == N.COMMENT_LIMIT
    assert "links" not in shown["T1059"] and "links" not in layer
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1059", "T1059.001"]


@pytest.mark.parametrize(("version", "major"), [("20.1", "20"), ("v18.0", "18"), ("17", "17")])
def test_the_layer_names_the_datas_major_version(version, major):
    assert N.attack_major(version) == major
    assert (
        N.build_layer("x", N.ENTERPRISE, {}, attack_version=version, platforms=[])["versions"]["attack"]
        == major
    )


def test_a_version_that_isnt_one_is_refused():
    with pytest.raises(ValueError):
        N.attack_major("")


def test_the_release_comes_from_attacks_own_data():
    release = N.release_of(vector("navigator/attack-sample.json")["bundle"])
    assert (release.version, release.major) == ("20.1", "20")
    assert release.platforms[N.ENTERPRISE] == RH["platforms"]  # the same list Rowanholt's lookup gives
    assert release.platforms[N.MOBILE] == ["Android", "iOS"]


def test_data_without_a_version_is_refused():
    with pytest.raises(ValueError, match="No ATT&CK version"):
        N.release_of({"objects": [{"type": "attack-pattern", "x_mitre_platforms": ["Windows"]}]})


def test_scores_and_a_gradient_for_an_assessment_layer():
    gradient = {"colors": ["#e57373", "#fff176", "#2e7d32"], "minValue": 1, "maxValue": 4}
    layer = N.build_layer(
        "Assessment", N.ENTERPRISE, {"T1003.001": N.Mark("#2e7d32", "Blue: prevented", score=4)},
        attack_version="20.1", platforms=["Windows"], gradient=gradient,
    )  # fmt: skip
    (entry,) = layer["techniques"]
    assert list(entry)[:3] == ["techniqueID", "score", "color"] and entry["score"] == 4
    assert layer["gradient"] == gradient and layer["gradient"] is not gradient
