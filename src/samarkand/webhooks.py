"""Signed webhooks, sending and receiving, as every product does them.

A delivery is a POST of `{"event", "sent_at", "data"}` as JSON, with `<prefix>-Event` naming the event
and, when the webhook has a secret, `<prefix>-Signature: sha256=<hex HMAC-SHA256 of the raw body>`.
The product passes its prefix (`X-Acme`), its event names and its data, already masked by its own
rules for anything leaving it. Nothing else is signed: there's no timestamp or delivery id in the
signature, so a receiver must make acting on a delivery harmless to repeat.

`sent_at` is ISO 8601 in UTC (`2026-11-11T12:00:00+00:00`). A receiver also accepts the epoch
seconds some products sent before samarkand (`Delivery.sent_at_time`).

The URL rules are the strictest the products agree on: https anywhere; plain http only to this
machine (localhost, *.localhost, loopback) or an RFC 1918 address, where a receiver often has no
certificate; never a link-local address (cloud metadata), whatever the scheme; never credentials in
the URL. The host isn't resolved, so a name that resolves to a link-local address isn't caught here.

Sending makes TRIES attempts, waiting BACKOFF times the attempt number between them, and stops early
on an answer that trying again won't change (any 4xx but 429). Redirects aren't followed. Whether to
send at all (the `automation` feature) and where results are kept (the last KEEP_DELIVERIES per
webhook) are the product's.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from samarkand import _http

log = logging.getLogger(__name__)

TRIES = 3
BACKOFF = 2.0  # seconds, times the attempt number
TIMEOUT = 10.0
KEEP_DELIVERIES = 20  # the spec's number for the admin page; the product keeps them
ERROR_LIMIT = 200
# RFC 1918. ipaddress's is_private also counts documentation and other reserved ranges.
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

Post = Callable[[str, bytes, Mapping[str, str], float], int]
AsyncPost = Callable[[str, bytes, Mapping[str, str], float], Awaitable[int]]


class Headers(NamedTuple):
    """The two header names a product sends."""

    event: str
    signature: str


def headers_for(prefix: str) -> Headers:
    """The header names for a prefix: "X-Acme" gives ("X-Acme-Event", "X-Acme-Signature")."""
    prefix = prefix.strip().rstrip("-")
    if not prefix:
        raise ValueError("A header prefix such as X-Acme is needed.")
    return Headers(f"{prefix}-Event", f"{prefix}-Signature")


def user_agent_for(prefix: str) -> str:
    """The default User-Agent for a prefix: "X-Acme" gives "Acme-Webhook/1"."""
    name = prefix.strip().rstrip("-")
    name = name[2:] if name.lower().startswith("x-") else name
    return f"{name}-Webhook/1"


def _sent_at(sent_at: datetime | None) -> str:
    at = sent_at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return at.astimezone(timezone.utc).isoformat()


def envelope(event: str, data: Mapping[str, Any], sent_at: datetime | None = None) -> dict[str, Any]:
    """The delivery as a dict: {"event", "sent_at", "data"}. `sent_at` defaults to now; a naive time
    is taken as UTC."""
    return {"event": event, "sent_at": _sent_at(sent_at), "data": dict(data)}


def body(event: str, data: Mapping[str, Any], sent_at: datetime | None = None) -> bytes:
    """The bytes sent and signed. Values JSON can't hold are sent as their str()."""
    return json.dumps(envelope(event, data, sent_at), default=str).encode()


def sign(secret: str, raw: bytes) -> str:
    """The signature header's value for `raw`: sha256=<hex HMAC-SHA256>."""
    return "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def verify(secret: str, raw: bytes, header: str | None) -> bool:
    """Whether `header` is `raw` signed with `secret`, compared in constant time. An empty secret or
    header never is."""
    if not secret or not header:
        return False
    return hmac.compare_digest(sign(secret, raw).encode(), header.strip().encode())


class NotADelivery(ValueError):
    """A body that isn't `{"event", "sent_at", "data"}`."""


@dataclass(frozen=True)
class Delivery:
    """A received delivery."""

    event: str
    sent_at: Any
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def sent_at_time(self) -> datetime | None:
        """`sent_at` as an aware UTC time, from ISO 8601 or epoch seconds; None if it's neither."""
        value = self.sent_at
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        if isinstance(value, str):
            try:
                at = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError:
                return None
            return at.replace(tzinfo=timezone.utc) if at.tzinfo is None else at.astimezone(timezone.utc)
        return None


def parse(raw: bytes) -> Delivery:
    """The delivery in a webhook body. Check the signature first (`verify`). Raises NotADelivery."""
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise NotADelivery("Not JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("event"), str):
        raise NotADelivery("No event.")
    data = payload.get("data")
    return Delivery(payload["event"], payload.get("sent_at"), data if isinstance(data, dict) else {})


def _address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def url_problem(url: str) -> str | None:
    """Why a webhook can't use this URL, or None."""
    try:
        parts = urlsplit((url or "").strip())
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 (a port that isn't a number raises here)
    except ValueError:
        return "The URL must start with https://."
    if parts.scheme.lower() not in ("http", "https") or not host:
        return "The URL must start with https://."
    if parts.username is not None or parts.password is not None:
        return "Put credentials in the webhook's secret, not the URL."
    address = _address(host)
    if address is not None and address.is_link_local:
        return "Webhooks are never sent to link-local addresses."
    if parts.scheme.lower() == "http":
        local = host == "localhost" or host.endswith(".localhost")
        nearby = address is not None and (
            address.is_loopback or (address.version == 4 and any(address in n for n in _PRIVATE))
        )
        if not (local or nearby):
            return "Use https://. Plain http:// is only allowed to localhost and private network addresses."
    return None


def events_problem(events: Iterable[str], allowed: Iterable[str]) -> str | None:
    """Why a webhook can't subscribe to `events`, or None: at least one, all from `allowed`."""
    chosen, known = set(events or ()), list(allowed)
    if not chosen or chosen - set(known):
        return f"Choose events from {', '.join(known)}."
    return None


def retryable(status: int | None) -> bool:
    """Whether trying again might help: no answer, a 5xx or a 429."""
    return status is None or status >= 500 or status == 429


def delays(tries: int = TRIES, backoff: float = BACKOFF) -> list[float]:
    """The waits between tries: [2.0, 4.0] for three."""
    return [backoff * (attempt + 1) for attempt in range(max(tries - 1, 0))]


@dataclass(frozen=True)
class Outgoing:
    """One delivery, ready to send."""

    url: str
    event: str
    body: bytes
    headers: dict[str, str]


def prepare(
    url: str,
    event: str,
    data: Mapping[str, Any],
    *,
    prefix: str,
    secret: str | None = None,
    user_agent: str | None = None,
    sent_at: datetime | None = None,
) -> Outgoing:
    """The body and headers for one delivery: signed when there's a secret."""
    raw = body(event, data, sent_at)
    names = headers_for(prefix)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": user_agent or user_agent_for(prefix),
        names.event: event,
    }
    if secret:
        headers[names.signature] = sign(secret, raw)
    return Outgoing(url.strip(), event, raw, headers)


@dataclass
class Result:
    """How a delivery went, for the product to keep."""

    event: str
    at: datetime
    ok: bool = False
    status: int | None = None
    error: str = ""
    tries: int = 0

    def as_dict(self) -> dict[str, Any]:
        """The result with `at` as ISO 8601, for a JSON store."""
        out = asdict(self)
        out["at"] = self.at.isoformat()
        return out


def _failure(exc: BaseException) -> str:
    return str(exc)[:ERROR_LIMIT] or type(exc).__name__


def _record(result: Result, status: int) -> bool:
    """Note an answer; True when it's final."""
    result.status = status
    if status < 300:
        result.ok, result.error = True, ""
        return True
    result.error = f"HTTP {status}"
    return not retryable(status)  # the receiver refused it; trying again won't change that


def _refused(outgoing: Outgoing) -> Result | None:
    problem = url_problem(outgoing.url)
    if problem:
        return Result(outgoing.event, datetime.now(timezone.utc), error=f"not sent: {problem}")
    return None


def post_sync(url: str, raw: bytes, headers: Mapping[str, str], timeout: float) -> int:
    """POST with the standard library, redirects not followed; the status."""
    return _http.request("POST", url, body=raw, headers=headers, timeout=timeout).status


async def post_async(url: str, raw: bytes, headers: Mapping[str, str], timeout: float) -> int:
    """POST with httpx, redirects not followed; the status."""
    return (await _http.request_async("POST", url, body=raw, headers=headers, timeout=timeout)).status


def send(
    outgoing: Outgoing,
    *,
    tries: int = TRIES,
    backoff: float = BACKOFF,
    timeout: float = TIMEOUT,
    post: Post = post_sync,
    sleep: Callable[[float], None] = time.sleep,
) -> Result:
    """Deliver, trying again with backoff. Never raises for the receiver's sake: a failure to reach it
    is recorded in the result. A URL `url_problem` refuses isn't sent at all (tries 0)."""
    refused = _refused(outgoing)
    if refused:
        return refused
    result = Result(outgoing.event, datetime.now(timezone.utc))
    waits = delays(tries, backoff)
    for attempt in range(tries):
        result.tries = attempt + 1
        try:
            if _record(result, post(outgoing.url, outgoing.body, outgoing.headers, timeout)):
                break
        except Exception as exc:  # noqa: BLE001 (any failure to reach the receiver is recorded, not raised)
            result.status, result.error = None, _failure(exc)
        if attempt < len(waits):
            sleep(waits[attempt])
    if not result.ok:
        log.info("Webhook %s to %s not delivered: %s", outgoing.event, outgoing.url, result.error)
    return result


async def send_async(
    outgoing: Outgoing,
    *,
    tries: int = TRIES,
    backoff: float = BACKOFF,
    timeout: float = TIMEOUT,
    post: AsyncPost = post_async,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Result:
    """`send`, with httpx (`samarkand[async]`) and asyncio's sleep."""
    refused = _refused(outgoing)
    if refused:
        return refused
    result = Result(outgoing.event, datetime.now(timezone.utc))
    waits = delays(tries, backoff)
    for attempt in range(tries):
        result.tries = attempt + 1
        try:
            if _record(result, await post(outgoing.url, outgoing.body, outgoing.headers, timeout)):
                break
        except Exception as exc:  # noqa: BLE001 (any failure to reach the receiver is recorded, not raised)
            result.status, result.error = None, _failure(exc)
        if attempt < len(waits):
            await sleep(waits[attempt])
    if not result.ok:
        log.info("Webhook %s to %s not delivered: %s", outgoing.event, outgoing.url, result.error)
    return result


def deliver(
    url: str,
    event: str,
    data: Mapping[str, Any],
    *,
    prefix: str,
    secret: str | None = None,
    user_agent: str | None = None,
    sent_at: datetime | None = None,
    **sending: Any,
) -> Result:
    """`prepare` then `send`: one event to one webhook, synchronously."""
    return send(
        prepare(url, event, data, prefix=prefix, secret=secret, user_agent=user_agent, sent_at=sent_at),
        **sending,
    )


async def deliver_async(
    url: str,
    event: str,
    data: Mapping[str, Any],
    *,
    prefix: str,
    secret: str | None = None,
    user_agent: str | None = None,
    sent_at: datetime | None = None,
    **sending: Any,
) -> Result:
    """`prepare` then `send_async`."""
    return await send_async(
        prepare(url, event, data, prefix=prefix, secret=secret, user_agent=user_agent, sent_at=sent_at),
        **sending,
    )
