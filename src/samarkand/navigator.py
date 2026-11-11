"""ATT&CK Navigator layers (layer format 4.5).

A layer marks techniques of one domain, each with a colour and a comment and, optionally, links.
It names the ATT&CK major version of the data the product has (never a hard-coded one) and lists
every platform the domain has, cloud ones included, or cloud-only techniques would be filtered out
of sight. With no tactic given, Navigator marks a technique under every tactic it has, and a parent
whose sub-techniques are marked opens to show them.

`release_of` reads the version and platforms from ATT&CK's own STIX data, for a product that has
the bundle but no lookup of its own.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

NAVIGATOR_VERSION = "5.3.2"
LAYER_VERSION = "4.5"
ENTERPRISE = "enterprise-attack"
MOBILE = "mobile-attack"
ICS = "ics-attack"
CONFIRMED_COLOUR = "#ed5565"
LEAD_COLOUR = "#ffce54"
COMMENT_LIMIT = 1000
GRADIENT = {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": 100}


@dataclass(frozen=True)
class Mark:
    """How one technique shows: its colour, its comment and, when given, its links ({label, url}) and
    a score for the layer's gradient."""

    colour: str
    comment: str = ""
    links: Sequence[Mapping[str, str]] | None = None
    score: int | float | None = None


def attack_major(version: str) -> str:
    """The major version a layer names: "20.1" gives "20"."""
    major = str(version or "").strip().lstrip("vV").split(".")[0]
    if not major.isdigit():
        raise ValueError(f"Not an ATT&CK version: {version!r}")
    return major


def _mark(value: Mark | tuple[str, str] | Sequence[Any]) -> Mark:
    if isinstance(value, Mark):
        return value
    colour, comment, *rest = value
    return Mark(colour, comment, rest[0] if rest else None)


def build_layer(
    name: str,
    domain: str,
    techniques: Mapping[str, Mark | tuple[str, str]],
    *,
    attack_version: str,
    platforms: Iterable[str],
    description: str = "",
    legend: Sequence[Mapping[str, str]] | None = None,
    show_ids: bool = False,
    metadata: Sequence[Mapping[str, str]] = (),
    links: Sequence[Mapping[str, str]] | None = None,
    navigator_version: str = NAVIGATOR_VERSION,
    gradient: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A layer of `techniques` ({ATT&CK id: Mark, or a (colour, comment) pair}, all of
    `domain`). `attack_version` and `platforms` come from the product's ATT&CK data. Layer-level
    `links` and each technique's `links` and `score` are written only when given; `gradient` is the
    scores' colour scale (red to green over 0 to 100 by default)."""
    marks = {tid: _mark(value) for tid, value in techniques.items()}
    parents = {tid.split(".")[0] for tid in marks if "." in tid}
    entries = []
    for tid, mark in sorted(marks.items()):
        entry: dict[str, Any] = {"techniqueID": tid}
        if mark.score is not None:
            entry["score"] = mark.score
        entry.update(
            {
                "color": mark.colour,
                "comment": mark.comment[:COMMENT_LIMIT],
                "enabled": True,
                "metadata": [],
            }
        )
        if mark.links is not None:
            entry["links"] = [dict(link) for link in mark.links]
        entry["showSubtechniques"] = tid in parents
        entries.append(entry)
    layer: dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": attack_major(attack_version),
            "navigator": navigator_version,
            "layer": LAYER_VERSION,
        },
        "domain": domain,
        "description": description,
        "filters": {"platforms": list(platforms)},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": show_ids,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": entries,
        "gradient": json.loads(json.dumps(gradient or GRADIENT)),
        "legendItems": [dict(item) for item in legend or []],
        "metadata": [dict(item) for item in metadata],
    }
    if links is not None:
        layer["links"] = [dict(link) for link in links]
    layer.update(
        {
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }
    )
    return layer


@dataclass(frozen=True)
class Release:
    """What a layer needs from ATT&CK's data: its version, and each domain's platforms."""

    version: str  # "20.1"
    platforms: dict[str, list[str]] = field(default_factory=dict)  # domain: sorted platforms

    @property
    def major(self) -> str:
        """The version a layer names."""
        return attack_major(self.version)


def release_of(*bundles: Mapping[str, Any]) -> Release:
    """The ATT&CK release in one or more of ATT&CK's STIX bundles (enterprise-attack.json and the
    like): the version from its x-mitre-collection, and the platforms its current techniques name,
    per domain. Revoked and deprecated techniques don't count. Raises ValueError without a version."""
    version = ""
    platforms: dict[str, set[str]] = {}
    for bundle in bundles:
        for obj in bundle.get("objects") or []:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version") and not version:
                version = str(obj["x_mitre_version"])
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            for domain in obj.get("x_mitre_domains") or [ENTERPRISE]:
                platforms.setdefault(domain, set()).update(obj.get("x_mitre_platforms") or [])
    if not version:
        raise ValueError("No ATT&CK version in the data: no x-mitre-collection with an x_mitre_version.")
    return Release(version, {d: sorted(p) for d, p in sorted(platforms.items())})
