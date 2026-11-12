"""A TAXII 2.1 client: a collection's objects, following its pagination, with optional Basic auth.
Standard library only.

`collection_url` is the collection's own URL (…/collections/<id>/); `objects/` is added to it. Pages
are asked for with `limit` (at most PAGE_SIZE), `added_after` for only what's new, and `next` as the
server gives it, until the server says there is no `more`, stops giving a `next`, repeats one, or the
caller's limit is reached. Redirects aren't followed, so credentials only ever go to the URL given.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from samarkand import _http

log = logging.getLogger(__name__)

ACCEPT = "application/taxii+json;version=2.1"
PAGE_SIZE = 1000
LIMIT = 5000
TIMEOUT = 60.0
USER_AGENT = "TAXII 2.1 client"

Request = Callable[..., _http.Response]


class TaxiiProblem(OSError):
    """The TAXII server refused or couldn't be reached, with a reason an admin can act on (its message).

    An OSError, as the failure to reach a server it often stands for is, so a product's `except
    OSError` (Rowanholt's routes answer 502 to one) catches it without re-raising. Raised with the
    message alone, so `str()` is the message and `errno` is None."""


def _headers(username: str, password: str, user_agent: str) -> dict[str, str]:
    headers = {"Accept": ACCEPT, "User-Agent": user_agent}
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def _get(request: Request, url: str, headers: dict[str, str], timeout: float, verify: bool) -> Any:
    try:
        answer = request("GET", url, headers=headers, timeout=timeout, verify=verify)
    except OSError as exc:
        raise TaxiiProblem(
            f"Couldn't reach the TAXII server: {str(exc)[:200] or type(exc).__name__}"
        ) from exc
    if answer.status in (401, 403):
        raise TaxiiProblem(f"The TAXII server refused the credentials (HTTP {answer.status}).")
    if answer.status >= 300:
        raise TaxiiProblem(f"The TAXII server answered HTTP {answer.status}.")
    try:
        return json.loads(answer.body or b"{}")
    except ValueError as exc:
        raise TaxiiProblem("The TAXII server's answer isn't JSON.") from exc


def base_of(collection_url: str) -> str:
    """The collection's URL ending in a slash."""
    url = collection_url.strip()
    return url if url.endswith("/") else url + "/"


def fetch_objects(
    collection_url: str,
    *,
    username: str = "",
    password: str = "",
    added_after: str = "",
    limit: int = LIMIT,
    timeout: float = TIMEOUT,
    verify: bool = True,
    user_agent: str = USER_AGENT,
    request: Request = _http.request,
) -> list[dict[str, Any]]:
    """Every STIX object in the collection, up to `limit`, following the `more`/`next` pagination.
    `added_after` (ISO 8601) fetches only what was added since. Raises TaxiiProblem."""
    base = base_of(collection_url)
    headers = _headers(username, password, user_agent)
    params: dict[str, object] = {"limit": min(limit, PAGE_SIZE)}
    if added_after:
        params["added_after"] = added_after
    objects: list[dict[str, Any]] = []
    seen: set[str] = set()
    while len(objects) < limit:
        envelope = _get(request, f"{base}objects/?{urlencode(params)}", headers, timeout, verify)
        if not isinstance(envelope, dict):
            raise TaxiiProblem("The TAXII server's answer isn't an envelope.")
        objects.extend(o for o in envelope.get("objects") or [] if isinstance(o, dict))
        following = envelope.get("next")
        if not envelope.get("more") or not following or following in seen:
            break
        seen.add(following)
        params["next"] = following
    log.info("TAXII: %d objects from %s", min(len(objects), limit), base)
    return objects[:limit]


def fetch_bundle(collection_url: str, **options: Any) -> dict[str, Any]:
    """The collection's objects as a bundle, ready for `samarkand.stix.parse`."""
    return {"type": "bundle", "objects": fetch_objects(collection_url, **options)}


def collection_info(
    collection_url: str,
    *,
    username: str = "",
    password: str = "",
    timeout: float = 30.0,
    verify: bool = True,
    user_agent: str = USER_AGENT,
    request: Request = _http.request,
) -> dict[str, Any]:
    """The collection's own description (id, title, description, can_read…). Raises TaxiiProblem."""
    found = _get(
        request,
        collection_url.strip().rstrip("/") + "/",
        _headers(username, password, user_agent),
        timeout,
        verify,
    )
    if not isinstance(found, dict):
        raise TaxiiProblem("The TAXII server's answer isn't a collection.")
    return found
