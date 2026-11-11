"""Write the licence and webhook test vectors (tests/vectors/licence/, tests/vectors/webhooks/).

Run from the repository root: `python tests/vectors/make_vectors.py`. The vectors are committed;
this script is how they were made, and it doesn't import samarkand, so the package is tested
against lines it didn't produce. Licences are signed with the throwaway seeds in
THROWAWAY-TEST-SEED.key, which no product trusts. Ed25519 signatures are deterministic, so running
it again gives the same files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
SEED = HERE / "licence" / "THROWAWAY-TEST-SEED.key"


def seeds() -> dict[str, Ed25519PrivateKey]:
    keys = {}
    for line in SEED.read_text().splitlines():
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            keys[name] = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))
    return keys


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def line(key: Ed25519PrivateKey, payload: dict, prefix: str | None = None) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    head = f"{prefix or payload['product'] + '-licence-1'}.{b64(canonical.encode())}"
    return f"{head}.{b64(key.sign(head.encode()))}"


def base(**changes: object) -> dict:
    payload: dict = {
        "licence_id": "lic_0123456789ab",
        "product": "ostraka",
        "licensee": "Northwind Ltd",
        "edition": "pro",
        "seats": 10,
        "issued": "2026-11-11",
        "expires": "2027-11-30",
    }
    payload.update(changes)
    return {k: v for k, v in payload.items() if v is not ...}


def licence_vectors() -> dict:
    keys = seeds()
    test, other = keys["test"], keys["other"]
    valid = []

    def ok(name: str, payload: dict, standing: list[dict], note: str = "") -> None:
        valid.append(
            {
                "name": name,
                "note": note,
                "line": line(test, payload),
                "payload": payload,
                "standing": standing,
            }
        )

    ok(
        "pro",
        base(),
        [
            {"at": "2026-11-11T12:00:00Z", "state": "active", "edition": "pro", "seats": 10},
            {"at": "2027-11-30T23:59:59Z", "state": "active", "edition": "pro", "seats": 10},
            {"at": "2027-12-01T00:00:00Z", "state": "grace", "edition": "pro", "seats": 10},
            {"at": "2027-12-30T23:59:59Z", "state": "grace", "edition": "pro", "seats": 10},
            {"at": "2027-12-31T00:00:00Z", "state": "lapsed", "edition": "free", "seats": "free"},
        ],
        "Runs to the end of its expiry day, then 30 days' grace, then Free.",
    )
    ok(
        "services-perpetual-wildcard-pending",
        base(
            edition="services",
            seats=None,
            expires=None,
            email="ops@northwind.example",
            features=["*"],
            not_before="2026-12-01",
        ),
        [
            {"at": "2026-11-30T23:59:59Z", "state": "pending", "edition": "free", "seats": "free"},
            {"at": "2026-12-01T00:00:00Z", "state": "active", "edition": "services", "seats": None},
            {"at": "2099-01-01T00:00:00Z", "state": "active", "edition": "services", "seats": None},
        ],
        "Unlimited seats, no expiry, every feature, and a first day in the future.",
    )
    ok(
        "pro-with-an-extra-feature",
        base(features=["brand-library", "custom-later"]),
        [{"at": "2026-11-11T12:00:00Z", "state": "active", "edition": "pro", "seats": 10}],
        "Pro plus brand-library and a feature id no product knows yet.",
    )
    ok("services", base(edition="services", seats=25, expires="2027-01-31"), [])
    for product in ("shikari", "rowanholt"):
        ok(f"{product}-pro", base(product=product), [], f"A good licence for {product}.")

    refused = []

    def no(name: str, text: str, code: str, note: str = "") -> None:
        refused.append({"name": name, "note": note, "line": text, "product": "ostraka", "code": code})

    good = line(test, base())
    head, payload, signature = good.split(".")
    more = base(seats=500)
    forged = b64(json.dumps(more, sort_keys=True, separators=(",", ":")).encode())
    no("tampered", f"{head}.{forged}.{signature}", "bad-signature", "The seats edited after signing.")
    no("another-key", line(other, base()), "bad-signature", "Signed by a key the product doesn't trust.")
    no("another-product", line(test, base(product="shikari")), "other-product", "shikari-licence-1.")
    no(
        "another-product-in-the-payload",
        line(test, base(product="shikari"), prefix="ostraka-licence-1"),
        "other-product",
        "An ostraka-licence-1 line whose payload names shikari.",
    )
    no(
        "another-format-version",
        line(test, base(), prefix="ostraka-licence-2"),
        "not-a-licence",
        "A format this version doesn't read.",
    )
    no("free-edition", line(test, base(edition="free")), "grants-nothing")
    no("no-seats", line(test, base(seats=0)), "grants-nothing")
    no("missing-field", line(test, base(issued=...)), "unreadable", "No issued date: from a newer format.")
    no("unknown-edition", line(test, base(edition="enterprise")), "unreadable")
    bad_json = f"ostraka-licence-1.{b64(b'not json')}"
    no("payload-not-json", f"{bad_json}.{b64(test.sign(bad_json.encode()))}", "damaged")
    for i, text in enumerate(["", "hello", "ostraka-licence-1.!!!.???", "ostraka-licence-1.a"]):
        no(f"not-a-licence-{i}", text, "damaged" if "!!!" in text else "not-a-licence")

    return {
        "about": (
            "Licence lines signed with the throwaway 'test' seed in THROWAWAY-TEST-SEED.key, which no "
            "product trusts. A product checks its own parser against them by trusting test_public_key "
            "in place of its PUBLIC_KEYS."
        ),
        "test_public_key": public_hex(test),
        "other_public_key": public_hex(other),
        "free_seats_placeholder": "free",
        "valid": valid,
        "refused": refused,
    }


def body(event: str, data: dict, sent_at: object) -> bytes:
    return json.dumps({"event": event, "sent_at": sent_at, "data": data}, default=str).encode()


def webhook_vectors() -> dict:
    secret = "s3cret-s3cret-s3cret"
    cases = [
        (
            "incident.created",
            {"ref": "OST-2026-001", "title": "Beaconing to [ip address]"},
            "2026-11-11T12:00:00+00:00",
        ),
        (
            "run.completed",
            {"run": "FIN7", "phase": "done", "created_yaml": 12},
            "2026-11-11T12:00:00.123456+00:00",
        ),
        (
            "job.failed",
            {"job_id": "j1", "error": "Read <path>: no such file", "images": 2},
            "2026-11-11T12:00:00+00:00",
        ),
        (
            "finding.confirmed",
            {"host": "FIN-WS-07", "note": "café, naïve, 東京"},
            "2026-11-11T12:00:00+00:00",
        ),
    ]
    out = []
    for event, data, sent_at in cases:
        raw = body(event, data, sent_at)
        out.append(
            {
                "event": event,
                "data": data,
                "sent_at": sent_at,
                "secret": secret,
                "body": raw.decode(),
                "signature": "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest(),
            }
        )
    legacy = body("run.completed", {"run": "FIN7"}, 1762862400.5)
    return {
        "about": "Webhook bodies as the bytes sent, each with its signature under `secret`.",
        "deliveries": out,
        "epoch_sent_at": {
            "note": "Shikari's and Rowanholt's bodies before samarkand: sent_at as epoch seconds.",
            "body": legacy.decode(),
            "signature": "sha256=" + hmac.new(secret.encode(), legacy, hashlib.sha256).hexdigest(),
            "secret": secret,
        },
        "headers": {
            "X-Ostraka": ["X-Ostraka-Event", "X-Ostraka-Signature"],
            "X-Shikari": ["X-Shikari-Event", "X-Shikari-Signature"],
            "X-Rowanholt": ["X-Rowanholt-Event", "X-Rowanholt-Signature"],
        },
        "urls": {
            "allowed": [
                "https://hooks.example.org/ostraka",
                "https://soar.example.org/rowanholt",
                "https://10.0.0.5/hook",
                "https://203.0.113.9/hook",
                "http://localhost:8080/hook",
                "http://soar.localhost/hook",
                "http://127.0.0.1:9000/hook",
                "http://[::1]/h",
                "http://10.1.2.3/hook",
                "http://172.20.0.5/h",
                "http://192.168.1.10:5000/h",
                "HTTPS://Hooks.Example.org/x",
            ],
            "refused": [
                "http://hooks.example.org/ostraka",
                "http://203.0.113.9/hook",
                "http://8.8.8.8/h",
                "http://172.32.0.1/h",
                "http://[fd00::1]/h",
                "http://localhost.localdomain/h",
                "https://169.254.169.254/latest/meta-data",
                "http://169.254.169.254/latest/meta-data",
                "https://[fe80::1]/h",
                "https://[::ffff:169.254.169.254]/h",
                "https://user:pw@soar.example.org/h",
                "https://user@soar.example.org/h",
                "ftp://hooks.example.org",
                "hooks.example.org/ostraka",
                "soar",
                "https://",
                "",
            ],
        },
    }


def main() -> None:
    for path, data in (
        (HERE / "licence" / "vectors.json", licence_vectors()),
        (HERE / "webhooks" / "vectors.json", webhook_vectors()),
    ):
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
