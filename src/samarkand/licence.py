"""The licence line shared by every product, checked offline against public keys the product supplies.

A licence is one line, `<product>-licence-1.<payload>.<signature>`:

- `payload` is base64url, without padding, of canonical JSON (sorted keys, compact separators);
- `signature` is Ed25519, base64url without padding, over the ASCII of `<product>-licence-1.<payload>`,
  so the product and the format version are signed too and a line for one product can't be passed
  off as another's.

Payload fields: `licence_id`, `product`, `licensee`, `edition` (`pro` or `services`), `seats` (a
number, or null for unlimited), `issued`, `expires` (a date, or null for perpetual), and optionally
`email`, `features` (extra feature ids, or `*` for all) and `not_before`. Dates are `YYYY-MM-DD`.

A licence runs from the start of its `not_before` day (UTC) to the end of its `expires` day, then
carries on for GRACE with a warning, then the installation is Free again. Before `not_before` it is
Free, shown as pending. A lapsed licence never deactivates anyone: that rule, the seat count and where
the licence is kept are each product's own.

There is no signing here. Licences are issued by each product's own admin script with the product's
private key, which never leaves the licensor. `head_of` gives the exact text an issuer signs and
`line_of` puts the line together, so an issuer can use the same encoding without this package ever
holding a private key.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger(__name__)

FORMAT_VERSION = 1
SUFFIX = f"-licence-{FORMAT_VERSION}"
GRACE = timedelta(days=30)


class Edition(str, Enum):
    """The three editions. Code asks `Standing.has(feature)`, never the edition's name."""

    FREE = "free"
    PRO = "pro"
    SERVICES = "services"


# Feature ids: short, kebab-case, stable, and the same in every product.
REPORT_BRANDING = "report-branding"  # one brand for the installation's reports
BRAND_LIBRARY = "brand-library"  # a brand per client, chosen for each piece of work
AUTOMATION = "automation"  # signed webhooks, checked when one is sent
MANAGED_SERVICE = "managed-service"  # a right in the commercial terms, not a switch in the code
FEATURES = (REPORT_BRANDING, BRAND_LIBRARY, AUTOMATION, MANAGED_SERVICE)
WILDCARD = "*"
EDITION_FEATURES: dict[Edition, frozenset[str]] = {
    Edition.FREE: frozenset(),
    Edition.PRO: frozenset({REPORT_BRANDING, AUTOMATION}),
    Edition.SERVICES: frozenset({REPORT_BRANDING, BRAND_LIBRARY, AUTOMATION, MANAGED_SERVICE}),
}

# Why a licence was refused, for code to act on; the message is for the admin.
NOT_A_LICENCE = "not-a-licence"
OTHER_PRODUCT = "other-product"
DAMAGED = "damaged"
BAD_SIGNATURE = "bad-signature"
UNREADABLE = "unreadable"  # signed, but fields this version doesn't understand: a newer format
GRANTS_NOTHING = "grants-nothing"
LAPSED = "lapsed"

# A Standing's state
FREE = "free"
PENDING = "pending"
ACTIVE = "active"
IN_GRACE = "grace"
LAPSED_STATE = "lapsed"


class LicenceProblem(ValueError):
    """A licence that can't be used, with a reason an admin can act on (the message) and one code can
    (`code`, one of the module's reason constants)."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Licence:
    """What a licence says, once its signature has checked out."""

    licence_id: str
    licensee: str
    edition: Edition
    seats: int | None  # None: unlimited
    issued: date
    expires: date | None  # None: perpetual
    email: str = ""
    features: tuple[str, ...] = ()  # beyond the edition's own
    not_before: date | None = None
    product: str = ""


@dataclass(frozen=True)
class Standing:
    """What the installation may do now."""

    edition: Edition
    seats: int | None  # None: unlimited
    state: str  # "free" (no licence), "pending", "active", "grace" or "lapsed"
    licence: Licence | None = None
    features: frozenset[str] = field(default_factory=frozenset)

    def has(self, feature: str) -> bool:
        """Whether the installation may use `feature` now."""
        return feature in self.features or WILDCARD in self.features

    @property
    def custom_branding(self) -> bool:
        """Reports may carry the installation's own brand."""
        return self.has(REPORT_BRANDING)

    @property
    def brand_library(self) -> bool:
        """A brand may be kept per client."""
        return self.has(BRAND_LIBRARY)

    @property
    def organisation(self) -> str:
        """The licensee, while the licence is in force (active or in grace), else ""."""
        return self.licence.licensee if self.licence and self.state in (ACTIVE, IN_GRACE) else ""


def format_of(product: str) -> str:
    """The line's prefix for a product: "acme" gives "acme-licence-1"."""
    return f"{product}{SUFFIX}"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(payload: dict[str, Any]) -> str:
    """The JSON that is encoded and signed: sorted keys, compact separators."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def payload_of(licence: Licence) -> dict[str, Any]:
    """The signed fields. Optional ones are left out rather than sent empty."""
    out: dict[str, Any] = {
        "licence_id": licence.licence_id,
        "product": licence.product,
        "licensee": licence.licensee,
        "edition": licence.edition.value,
        "seats": licence.seats,
        "issued": licence.issued.isoformat(),
        "expires": licence.expires.isoformat() if licence.expires else None,
    }
    if licence.email:
        out["email"] = licence.email
    if licence.features:
        out["features"] = sorted(licence.features)
    if licence.not_before:
        out["not_before"] = licence.not_before.isoformat()
    return out


def head_of(licence: Licence) -> str:
    """`<product>-licence-1.<payload>`: the text an issuer signs (its ASCII bytes) with the product's
    private key. For the licensor's admin script only; no product needs it."""
    if not licence.product:
        raise ValueError("A licence names its product.")
    return f"{format_of(licence.product)}.{_b64(canonical(payload_of(licence)).encode())}"


def line_of(head: str, signature: bytes) -> str:
    """The licence line from its head and the Ed25519 signature over it."""
    return f"{head}.{_b64(signature)}"


def _article(name: str) -> str:
    return "an" if name[:1].lower() in "aeiou" else "a"


def load_keys(public_keys: Iterable[str]) -> tuple[Ed25519PublicKey, ...]:
    """Raw Ed25519 public keys given as hex. A key that isn't one is a mistake in the product, so it
    raises ValueError rather than refusing a customer's licence."""
    keys = []
    for key in public_keys:
        try:
            keys.append(Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)))
        except ValueError as exc:
            raise ValueError(f"Not a raw Ed25519 public key in hex: {key!r}") from exc
    return tuple(keys)


def _day(value: Any) -> date | None:
    return date.fromisoformat(value) if value else None


def parse(
    text: str,
    *,
    product: str,
    public_keys: Iterable[str] | Iterable[Ed25519PublicKey],
    name: str | None = None,
) -> Licence:
    """A licence for `product`, once its signature checks out against one of `public_keys` (a tuple,
    so a key can be rotated by adding the new one). `name` is the product's name as people read it,
    for the messages; it defaults to the id with a capital. Raises LicenceProblem."""
    shown = name or product.capitalize()
    expected = format_of(product)
    keys = tuple(k if isinstance(k, Ed25519PublicKey) else load_keys((k,))[0] for k in public_keys)
    parts = (text or "").strip().split(".")
    if len(parts) != 3 or not parts[0].endswith(SUFFIX):
        raise LicenceProblem(
            f"That isn't {_article(shown)} {shown} licence. Paste the whole line you were sent.",
            NOT_A_LICENCE,
        )
    if parts[0] != expected:
        other = parts[0][: -len(SUFFIX)]
        raise LicenceProblem(f"That's a licence for {other}, not {shown}.", OTHER_PRODUCT)
    head = f"{parts[0]}.{parts[1]}"
    try:
        signature = _unb64(parts[2])
        payload = json.loads(_unb64(parts[1]))
    except (binascii.Error, ValueError) as exc:
        raise LicenceProblem("That licence is damaged. Paste the whole line you were sent.", DAMAGED) from exc
    for key in keys:
        try:
            key.verify(signature, head.encode())
            break
        except InvalidSignature:
            continue
    else:
        raise LicenceProblem(f"That licence wasn't issued for {shown}, or has been altered.", BAD_SIGNATURE)
    try:
        licence = Licence(
            licence_id=str(payload["licence_id"]),
            product=str(payload["product"]),
            licensee=str(payload["licensee"]),
            email=str(payload.get("email", "")),
            edition=Edition(payload["edition"]),
            seats=None if payload["seats"] is None else int(payload["seats"]),
            features=tuple(str(f) for f in payload.get("features", [])),
            issued=date.fromisoformat(payload["issued"]),
            not_before=_day(payload.get("not_before")),
            expires=_day(payload["expires"]),
        )
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise LicenceProblem(
            f"That licence is from a newer version of {shown}. Update, then try again.", UNREADABLE
        ) from exc
    if licence.product != product:
        raise LicenceProblem(f"That's a licence for {licence.product}, not {shown}.", OTHER_PRODUCT)
    if licence.edition is Edition.FREE or (licence.seats is not None and licence.seats < 1):
        raise LicenceProblem("That licence grants nothing beyond the free edition.", GRANTS_NOTHING)
    return licence


def _midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, timezone.utc)


def standing(licence: Licence | None, now: datetime | None = None, *, free_seats: int | None) -> Standing:
    """The edition a licence (or none) gives at `now` (UTC; a naive time is taken as UTC).
    `free_seats` is the product's own free number."""
    free = Standing(Edition.FREE, free_seats, FREE)
    if licence is None:
        return free
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if licence.not_before and now < _midnight(licence.not_before):
        return Standing(Edition.FREE, free_seats, PENDING, licence)
    granted = EDITION_FEATURES[licence.edition] | frozenset(licence.features)
    paid = Standing(licence.edition, licence.seats, ACTIVE, licence, granted)
    if licence.expires is None:
        return paid
    ends = _midnight(licence.expires + timedelta(days=1))
    if now < ends:
        return paid
    if now < ends + GRACE:
        return Standing(licence.edition, licence.seats, IN_GRACE, licence, granted)
    return Standing(Edition.FREE, free_seats, LAPSED_STATE, licence)


def grace_ends(licence: Licence) -> date | None:
    """The last day of grace, or None for a perpetual licence."""
    return licence.expires + GRACE if licence.expires else None


def check_installable(licence: Licence, now: datetime | None = None) -> Licence:
    """`licence`, if it may be installed now: one already past its grace is refused (LicenceProblem,
    LAPSED). A pending licence may be installed; it takes effect on its first day."""
    if standing(licence, now, free_seats=None).state == LAPSED_STATE:
        raise LicenceProblem(f"That licence ran out on {licence.expires}.", LAPSED)
    return licence


@dataclass(frozen=True)
class Rules:
    """One product's licence rules, bound once: its id, its trusted public keys (hex), its free seat
    number and its name as people read it.

        RULES = Rules("acme", ("cf9e…",), free_seats=4, name="Acme")
        RULES.parse(line); RULES.standing(licence)
    """

    product: str
    public_keys: tuple[str, ...]
    free_seats: int | None
    name: str = ""
    _keys: tuple[Ed25519PublicKey, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.public_keys:
            log.warning("No public keys for %s: every licence will be refused.", self.product)
        object.__setattr__(self, "_keys", load_keys(self.public_keys))

    def licence(
        self,
        licence_id: str,
        licensee: str,
        edition: Edition | str,
        seats: int | None,
        issued: date,
        expires: date | None,
        **optional: Any,
    ) -> Licence:
        """A Licence for this product: `Licence`'s own fields in its order, with `product` filled in
        unless it's given (a test of another product's licence passes one). For an issuer's script
        and tests, so a product needs no subclass of Licence to default its id."""
        optional.setdefault("product", self.product)
        return Licence(licence_id, licensee, Edition(edition), seats, issued, expires, **optional)

    def parse(self, text: str) -> Licence:
        """See `parse`. The licence carries the product's id in `product`: every payload names its
        product, and a line whose payload doesn't is refused (UNREADABLE), as is one naming another."""
        return parse(text, product=self.product, public_keys=self._keys, name=self.name or None)

    def standing(self, licence: Licence | None, now: datetime | None = None) -> Standing:
        """See `standing`."""
        return standing(licence, now, free_seats=self.free_seats)

    def current(self, text: str | None, now: datetime | None = None) -> Standing:
        """The standing from a stored line, or none. A stored line that no longer verifies (say, after
        a key was withdrawn) counts as no licence, logged, so the installation carries on as Free."""
        if not text:
            return self.standing(None, now)
        try:
            return self.standing(self.parse(text), now)
        except LicenceProblem as problem:
            log.warning(
                "The installed %s licence doesn't verify (%s): treating it as none.", self.product, problem
            )
            return self.standing(None, now)
