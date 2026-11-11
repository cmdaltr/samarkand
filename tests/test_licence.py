"""The licence line against the vectors, and the behaviour the shared spec asks every product's tests to
cover: valid, tampered, another key, another product, not yet valid, grace then lapse, perpetual,
wildcard and edition features."""

from __future__ import annotations

import base64
import json
import re
from datetime import date, datetime, timedelta, timezone

import pytest
from conftest import vector
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from samarkand import licence as L

V = vector("licence/vectors.json")
KEY = V["test_public_key"]
FREE_SEATS = 4


def at(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@pytest.mark.parametrize("case", V["valid"], ids=lambda c: c["name"])
def test_each_valid_vector_reads_back_to_its_payload(case):
    product = case["payload"]["product"]
    lic = L.parse(case["line"], product=product, public_keys=(KEY,))
    assert L.payload_of(lic) == case["payload"]
    for expected in case["standing"]:
        s = L.standing(lic, at(expected["at"]), free_seats=FREE_SEATS)
        seats = FREE_SEATS if expected["seats"] == "free" else expected["seats"]
        assert (s.state, s.edition.value, s.seats) == (expected["state"], expected["edition"], seats), (
            expected
        )


@pytest.mark.parametrize("case", V["valid"], ids=lambda c: c["name"])
def test_the_issuers_encoding_gives_the_vector_line_byte_for_byte(case, test_keys):
    lic = L.parse(case["line"], product=case["payload"]["product"], public_keys=(KEY,))
    head = L.head_of(lic)
    assert L.line_of(head, test_keys["test"].sign(head.encode())) == case["line"]


@pytest.mark.parametrize("case", V["refused"], ids=lambda c: c["name"])
def test_each_refused_vector_is_refused_for_its_reason(case):
    with pytest.raises(L.LicenceProblem) as problem:
        L.parse(case["line"], product=case["product"], public_keys=(KEY,), name="Ostraka")
    assert problem.value.code == case["code"]


# What Ostraka says today for each refusal (ostraka/licence.py), checked against its own code
OSTRAKA_SAYS = {
    "tampered": "That licence wasn't issued for Ostraka, or has been altered.",
    "another-key": "That licence wasn't issued for Ostraka, or has been altered.",
    "another-product": "That's a licence for shikari, not Ostraka.",
    "another-product-in-the-payload": "That's a licence for shikari, not Ostraka.",
    "another-format-version": "That isn't an Ostraka licence. Paste the whole line you were sent.",
    "free-edition": "That licence grants nothing beyond the free edition.",
    "no-seats": "That licence grants nothing beyond the free edition.",
    "missing-field": "That licence is from a newer version of Ostraka. Update, then try again.",
    "unknown-edition": "That licence is from a newer version of Ostraka. Update, then try again.",
    "payload-not-json": "That licence is damaged. Paste the whole line you were sent.",
    "not-a-licence-0": "That isn't an Ostraka licence. Paste the whole line you were sent.",
    "not-a-licence-1": "That isn't an Ostraka licence. Paste the whole line you were sent.",
    "not-a-licence-2": "That licence is damaged. Paste the whole line you were sent.",
    "not-a-licence-3": "That isn't an Ostraka licence. Paste the whole line you were sent.",
}


@pytest.mark.parametrize("case", V["refused"], ids=lambda c: c["name"])
def test_the_messages_are_the_ones_the_products_show_today(case):
    with pytest.raises(L.LicenceProblem, match="^" + re.escape(OSTRAKA_SAYS[case["name"]]) + "$"):
        L.parse(case["line"], product="ostraka", public_keys=(KEY,), name="Ostraka")


def test_the_article_follows_the_name():
    for product, name, said in (("shikari", "Shikari", "a Shikari"), ("rowanholt", None, "a Rowanholt")):
        with pytest.raises(L.LicenceProblem, match=f"isn't {said} licence"):
            L.parse("hello", product=product, public_keys=(KEY,), name=name)


def test_a_licence_for_another_product_names_it():
    line = next(c["line"] for c in V["valid"] if c["name"] == "shikari-pro")
    with pytest.raises(L.LicenceProblem, match="licence for shikari, not Rowanholt"):
        L.parse(line, product="rowanholt", public_keys=(KEY,))


def test_a_rotated_key_still_reads_licences_signed_by_the_old_one():
    line = V["valid"][0]["line"]
    assert L.parse(line, product="ostraka", public_keys=(V["other_public_key"], KEY)).licence_id
    with pytest.raises(L.LicenceProblem) as problem:
        L.parse(line, product="ostraka", public_keys=(V["other_public_key"],))
    assert problem.value.code == L.BAD_SIGNATURE


def test_no_keys_refuses_everything():
    with pytest.raises(L.LicenceProblem):
        L.parse(V["valid"][0]["line"], product="ostraka", public_keys=())


def test_a_key_that_isnt_one_is_the_products_mistake_not_the_customers():
    with pytest.raises(ValueError, match="Not a raw Ed25519 public key") as raised:
        L.parse(V["valid"][0]["line"], product="ostraka", public_keys=("abcd",))
    assert not isinstance(raised.value, L.LicenceProblem)


def test_a_payload_that_isnt_an_object_is_unreadable(test_keys):
    head = f"ostraka-licence-1.{base64.urlsafe_b64encode(b'[1,2]').rstrip(b'=').decode()}"
    line = L.line_of(head, test_keys["test"].sign(head.encode()))
    with pytest.raises(L.LicenceProblem) as problem:
        L.parse(line, product="ostraka", public_keys=(KEY,))
    assert problem.value.code == L.UNREADABLE


def test_the_payload_is_canonical_json():
    _, payload, _ = V["valid"][1]["line"].split(".")
    text = base64.urlsafe_b64decode(payload + "==").decode()
    assert text == L.canonical(json.loads(text))
    assert "=" not in payload


def lic(edition: str = "pro", seats: int | None = 10, expires: date | None = date(2027, 11, 30), **extra):
    return L.Licence(
        "lic_test",
        "Northwind Ltd",
        L.Edition(edition),
        seats,
        date(2026, 11, 11),
        expires,
        product="ostraka",
        **extra,
    )


def noon(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, 12, tzinfo=timezone.utc)


def test_no_licence_is_the_free_edition_with_the_products_seats():
    s = L.standing(None, free_seats=2)
    assert (s.edition, s.seats, s.state, s.features) == (L.Edition.FREE, 2, "free", frozenset())
    assert not s.has(L.AUTOMATION) and not s.custom_branding and s.organisation == ""


def test_grace_then_lapse():
    licence = lic("services", seats=25, expires=date(2027, 1, 31))
    assert L.standing(licence, noon(date(2027, 1, 31)), free_seats=4).state == "active"
    grace = L.standing(licence, noon(date(2027, 2, 1)), free_seats=4)
    assert (grace.state, grace.edition, grace.seats, grace.organisation) == (
        "grace",
        L.Edition.SERVICES,
        25,
        "Northwind Ltd",
    )
    assert L.standing(licence, noon(date(2027, 3, 2)), free_seats=4).state == "grace"
    lapsed = L.standing(licence, noon(date(2027, 3, 3)), free_seats=4)
    assert (lapsed.state, lapsed.edition, lapsed.seats, lapsed.organisation) == (
        "lapsed",
        L.Edition.FREE,
        4,
        "",
    )
    assert L.grace_ends(licence) == date(2027, 1, 31) + timedelta(days=30)


def test_pending_then_active_and_perpetual():
    later = lic(not_before=date(2026, 12, 1))
    pending = L.standing(later, noon(date(2026, 11, 30)), free_seats=4)
    assert (pending.state, pending.seats, pending.features) == ("pending", 4, frozenset())
    assert L.standing(later, noon(date(2026, 12, 1)), free_seats=4).state == "active"
    forever = lic(expires=None)
    assert L.standing(forever, noon(date(2099, 1, 1)), free_seats=4).state == "active"
    assert L.grace_ends(forever) is None


def test_a_naive_time_is_utc():
    licence = lic(expires=date(2027, 1, 31))
    assert L.standing(licence, datetime(2027, 2, 1, 0, 0), free_seats=4).state == "grace"
    assert L.standing(licence, datetime(2027, 1, 31, 23, 59), free_seats=4).state == "active"


def test_editions_grant_the_shared_features_and_a_licence_adds_more():
    pro = L.standing(lic("pro"), noon(date(2026, 11, 11)), free_seats=4)
    assert pro.has(L.REPORT_BRANDING) and pro.has(L.AUTOMATION)
    assert not pro.has(L.BRAND_LIBRARY) and not pro.has(L.MANAGED_SERVICE)
    plus = L.standing(lic("pro", features=(L.BRAND_LIBRARY,)), noon(date(2026, 11, 11)), free_seats=4)
    assert plus.brand_library
    everything = L.standing(lic("pro", features=("*",)), noon(date(2026, 11, 11)), free_seats=4)
    assert everything.has(L.MANAGED_SERVICE) and everything.has("anything-later")
    services = L.standing(lic("services"), noon(date(2026, 11, 11)), free_seats=4)
    assert services.features == set(L.FEATURES)


def test_the_edition_table_is_the_specs():
    assert L.EDITION_FEATURES == {
        L.Edition.FREE: frozenset(),
        L.Edition.PRO: {"report-branding", "automation"},
        L.Edition.SERVICES: {"report-branding", "automation", "brand-library", "managed-service"},
    }


def test_a_lapsed_licence_cant_be_installed_but_a_pending_one_can():
    old = lic(expires=date(2025, 1, 31))
    with pytest.raises(L.LicenceProblem, match="ran out on 2025-01-31") as problem:
        L.check_installable(old, noon(date(2026, 11, 11)))
    assert problem.value.code == L.LAPSED
    assert L.check_installable(lic(not_before=date(2027, 1, 1)), noon(date(2026, 11, 11)))
    assert L.check_installable(lic(expires=date(2026, 11, 1)), noon(date(2026, 11, 11)))  # in grace


def test_a_signed_licence_round_trips_through_the_issuers_encoding(test_keys):
    original = lic(
        "services",
        seats=None,
        expires=None,
        email="ops@northwind.example",
        features=("*",),
        not_before=date(2026, 12, 1),
    )
    head = L.head_of(original)
    line = L.line_of(head, test_keys["test"].sign(head.encode()))
    assert L.parse(line, product="ostraka", public_keys=(KEY,)) == original


def test_a_licence_must_name_its_product_to_be_encoded():
    with pytest.raises(ValueError):
        L.head_of(L.Licence("x", "y", L.Edition.PRO, 1, date(2026, 1, 1), None))


def test_rules_bind_a_product_once(caplog):
    rules = L.Rules("ostraka", (KEY,), free_seats=4, name="Ostraka")
    line = V["valid"][0]["line"]
    assert rules.standing(rules.parse(line), at("2026-11-11T12:00:00Z")).state == "active"
    assert rules.current(None).state == "free"
    assert rules.current(line, at("2026-11-11T12:00:00Z")).edition is L.Edition.PRO
    withdrawn = L.Rules("ostraka", (V["other_public_key"],), free_seats=4)
    assert withdrawn.current(line).state == "free"
    assert "doesn't verify" in caplog.text


def test_a_fresh_key_signs_nothing_the_test_key_trusts():
    stranger = Ed25519PrivateKey.generate()
    head = L.head_of(lic())
    with pytest.raises(L.LicenceProblem):
        L.parse(L.line_of(head, stranger.sign(head.encode())), product="ostraka", public_keys=(KEY,))
