"""One HTTP request, two ways: the standard library (sync) and httpx (async, the optional extra).

Redirects are never followed unless asked: a webhook, a TAXII server or a MISP instance is the
address an admin registered, not wherever it points next. TLS is verified unless the caller turns it
off for that one request.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Response:
    """What came back: the status, the body and the headers (names lower-cased)."""

    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None  # the 3xx comes back to the caller as the answer


def request(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool = True,
    follow_redirects: bool = False,
) -> Response:
    """Send one request with the standard library. Any status is a Response; a failure to reach the
    server raises OSError (urllib.error.URLError is one)."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=context)]
    if not follow_redirects:
        handlers.append(_NoRedirects())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method)  # noqa: S310
    try:
        with opener.open(req, timeout=timeout) as answer:
            return Response(answer.status, answer.read(), {k.lower(): v for k, v in answer.headers.items()})
    except urllib.error.HTTPError as answer:
        found = answer.headers.items() if answer.headers else []
        return Response(answer.code, answer.read() or b"", {k.lower(): v for k, v in found})


async def request_async(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool = True,
    follow_redirects: bool = False,
) -> Response:
    """The same request with httpx (`pip install samarkand[async]`). A failure to reach the server
    raises httpx.HTTPError."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - only without the extra
        raise RuntimeError("The async sender needs httpx: install samarkand[async].") from exc
    async with httpx.AsyncClient(timeout=timeout, verify=verify, follow_redirects=follow_redirects) as client:
        answer = await client.request(method, url, content=body, headers=dict(headers or {}))
        return Response(answer.status_code, answer.content, {k.lower(): v for k, v in answer.headers.items()})
