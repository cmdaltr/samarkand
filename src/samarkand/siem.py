"""Running a query, read-only, against a SIEM: Splunk (SPL), Elasticsearch (ES|QL), Microsoft Defender XDR
(KQL through Advanced Hunting) and Google SecOps (UDM search). Standard library and `cryptography`; the
async runner needs httpx (`samarkand[async]`).

Each SIEM is a class holding its address and credentials, with `query()` and `check()` and their
`_async` twins. The work is written once, as a generator of the requests a query needs (`Call`) and the
pauses between them (`Wait`), and `run` or `run_async` sends them, so the sync and async paths can't
drift apart and the tests drive the generators with scripted answers.

A query returns a `Result`: the rows as dicts, whether more were there than were read, and what the SIEM
said about the run. Nothing is kept here but a client's sign-in token (Defender XDR, SecOps), reused
until shortly before it expires: what to store, show or log is the product's. Anything that
goes wrong (bad syntax, expired credentials, a busy or unreachable SIEM) raises `SiemProblem` with
the SIEM's own words where it gave some.

The search window:

- Splunk takes `start` and `end` (datetimes, or Splunk's own `-24h` and `now`); a time term in the SPL
  (`earliest=-1d`) overrides them.
- Elasticsearch filters on `@timestamp` between `start` and `end` when given, besides the ES|QL's own
  `WHERE`.
- Defender XDR's window is the query's own (`| where Timestamp > ago(1d)`), else Advanced Hunting's
  default of 30 days; `start` and `end` aren't used.
- Google SecOps needs one: `start` and `end`, else the last 24 hours.

The Splunk, Elasticsearch and Defender XDR clients are Shikari's (`shikari/query/`), moved here in
0.2.0. Google SecOps is built from Google's Chronicle API documentation (`udmSearch`, a service
account's key signed into an OAuth token here) and hasn't yet been run against a live tenant.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlencode

from samarkand import _http

TIMEOUT = 300.0  # seconds a whole query may take
REQUEST_TIMEOUT = 60.0
RETRIES = 3  # for 429 and 503: a SIEM's search concurrency and rate limits
MAX_ROWS = 1000
TOKEN_MARGIN = 300.0  # seconds before an OAuth token expires that a new one is signed in for


class SiemProblem(OSError):
    """The SIEM refused the query or couldn't be reached, with a reason an analyst can act on (its
    message). An OSError, as taxii.TaxiiProblem is; raised with the message alone."""


@dataclass(frozen=True)
class Call:
    """One HTTP request a query needs."""

    method: str
    url: str
    body: bytes | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout: float = REQUEST_TIMEOUT


@dataclass(frozen=True)
class Wait:
    """A pause before the next request: a job still running, or a SIEM asking for a moment."""

    seconds: float


@dataclass
class Result:
    """What a query returned. `truncated` says more rows were there than were read; `stats` is what the
    SIEM said about the run (its job id, counts, time taken), as plain values."""

    rows: list[dict[str, Any]]
    truncated: bool = False
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def columns(self) -> list[str]:
        """Every column any row has, in the order they first appear."""
        return list(dict.fromkeys(k for row in self.rows for k in row))


Steps = Generator["Call | Wait", "_http.Response | None", Any]


def _json(answer: _http.Response) -> Any:
    try:
        return json.loads(answer.body or b"null")
    except ValueError as exc:
        raise SiemProblem(f"Unexpected answer (HTTP {answer.status}): not JSON") from exc


def _send(call: Call, reason: Any = None) -> Steps:
    """A request that waits out 429 and 503, honouring Retry-After. Returns the final answer."""
    for attempt in range(RETRIES + 1):
        answer = yield call
        assert answer is not None
        if answer.status in (429, 503) and attempt < RETRIES:
            try:
                pause = float(answer.headers.get("retry-after") or 2**attempt)
            except ValueError:
                pause = float(2**attempt)
            yield Wait(min(pause, 30.0))
            continue
        return answer
    return answer  # pragma: no cover


def run(steps: Steps, *, verify: bool = True) -> Any:
    """Send a query's requests with the standard library and return what it returns."""
    answer: _http.Response | None = None
    try:
        while True:
            step = steps.send(answer)
            if isinstance(step, Wait):
                time.sleep(step.seconds)
                answer = None
                continue
            try:
                answer = _http.request(
                    step.method,
                    step.url,
                    body=step.body,
                    headers=step.headers,
                    timeout=step.timeout,
                    verify=verify,
                )
            except OSError as exc:
                raise _unreachable(step.url, exc) from exc
    except StopIteration as done:
        return done.value


async def run_async(steps: Steps, *, verify: bool = True) -> Any:
    """`run` with httpx (`samarkand[async]`)."""
    answer: _http.Response | None = None
    try:
        while True:
            step = steps.send(answer)
            if isinstance(step, Wait):
                await asyncio.sleep(step.seconds)
                answer = None
                continue
            try:
                answer = await _http.request_async(
                    step.method,
                    step.url,
                    body=step.body,
                    headers=step.headers,
                    timeout=step.timeout,
                    verify=verify,
                )
            except Exception as exc:  # noqa: BLE001 (httpx's errors, without importing httpx here)
                raise _unreachable(step.url, exc) from exc
    except StopIteration as done:
        return done.value


def _unreachable(url: str, exc: BaseException) -> SiemProblem:
    return SiemProblem(f"Couldn't reach {_host(url)}: {str(exc)[:200] or type(exc).__name__}")


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0]


def _when(value: datetime | str | None, default: str) -> str:
    """A time for Splunk: epoch seconds for a datetime, else Splunk's own words."""
    if value is None:
        return default
    if isinstance(value, datetime):
        return str(int(value.timestamp()))
    return value


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _form(data: Mapping[str, Any]) -> bytes:
    return urlencode(data).encode()


class _Client:
    """What every SIEM client shares: the sync and async front of its generators."""

    verify: bool

    def _query(self, query: str, start: Any, end: Any, max_rows: int, timeout: float) -> Steps:
        raise NotImplementedError

    def _check(self) -> Steps:
        raise NotImplementedError

    def query(
        self,
        query: str,
        *,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
        max_rows: int = MAX_ROWS,
        timeout: float = TIMEOUT,
    ) -> Result:
        """Run a query and read back at most `max_rows` rows (0: all of them)."""
        if not query or not query.strip():
            raise SiemProblem("The query is empty.")
        return run(self._query(query, start, end, max_rows, timeout), verify=self.verify)

    async def query_async(
        self,
        query: str,
        *,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
        max_rows: int = MAX_ROWS,
        timeout: float = TIMEOUT,
    ) -> Result:
        """`query` with httpx."""
        if not query or not query.strip():
            raise SiemProblem("The query is empty.")
        return await run_async(self._query(query, start, end, max_rows, timeout), verify=self.verify)

    def check(self) -> Result:
        """Whether the credentials work and a trivial query runs; raises SiemProblem if not."""
        return run(self._check(), verify=self.verify)

    async def check_async(self) -> Result:
        """`check` with httpx."""
        return await run_async(self._check(), verify=self.verify)


class _Bearer(_Client):
    """A client signing in for an OAuth token, kept and reused until shortly before it expires."""

    _bearer: tuple[str, float] | None = None

    def _sign_in(self) -> Steps:
        """The token endpoint's answer, as JSON (access_token, expires_in)."""
        raise NotImplementedError

    def _token(self) -> Steps:
        if self._bearer and time.monotonic() < self._bearer[1]:
            return self._bearer[0]
        data = yield from self._sign_in()
        try:
            lifetime = float(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600.0
        self._bearer = (data["access_token"], time.monotonic() + max(lifetime - TOKEN_MARGIN, 0.0))
        return self._bearer[0]

    def _authorised(self, call: Callable[[str], Call]) -> Steps:
        """`call` sent with the token. A kept token refused (revoked, or the clock off) is dropped and the
        call sent once more with a new one."""
        kept = self._bearer is not None and time.monotonic() < self._bearer[1]
        answer = yield from _send(call((yield from self._token())))
        if answer.status == 401 and kept:
            self._bearer = None
            answer = yield from _send(call((yield from self._token())))
        return answer


# ---- Splunk -------------------------------------------------------------------------------------------


def _splunk_messages(answer: _http.Response) -> str:
    """Splunk's own words: {"messages": [{"type": "ERROR", "text": ...}]}, each once (it repeats them)."""
    try:
        body = json.loads(answer.body or b"{}")
    except ValueError:
        return answer.body[:300].decode(errors="replace") or f"HTTP {answer.status}"
    texts = [m.get("text", "") for m in (body.get("messages") or []) if isinstance(m, dict) and m.get("text")]
    return "; ".join(dict.fromkeys(texts)) or f"HTTP {answer.status}"


class Splunk(_Client):
    """SPL through Splunk's search jobs API on the management port (https://host:8089). A token
    (Settings > Tokens) is sent as a Bearer token; a username and password log in for a session key."""

    def __init__(
        self, url: str, *, token: str = "", username: str = "", password: str = "", verify: bool = True
    ) -> None:
        if not url or not (token or (username and password)):
            raise ValueError("Splunk needs its management URL and a token, or a username and password.")
        self.base = url.rstrip("/").removesuffix("/services") + "/services"
        self.token, self.username, self.password, self.verify = token, username, password, verify
        self._session = ""

    @staticmethod
    def search_string(query: str) -> str:
        """A search job needs a leading command: `search` for a bare search, nothing for `| tstats …`."""
        q = query.strip()
        return q if q.startswith("|") or q.lower().startswith("search ") else f"search {q}"

    def _login(self) -> Steps:
        answer = yield from _send(
            Call(
                "POST",
                f"{self.base}/auth/login",
                _form({"username": self.username, "password": self.password, "output_mode": "json"}),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        if answer.status >= 400:
            raise SiemProblem(f"Splunk refused the login: {_splunk_messages(answer)}")
        self._session = _json(answer)["sessionKey"]

    def _call(self, method: str, path: str, form: Mapping[str, Any] | None = None) -> Steps:
        """A call with the credentials, logging in again once if a session key expired."""
        for again in (False, True):
            if not self.token and not self._session:
                yield from self._login()
            auth = f"Bearer {self.token}" if self.token else f"Splunk {self._session}"
            headers = {"Authorization": auth}
            url = f"{self.base}/{path}"
            body = None
            if method == "GET" and form:
                url += "?" + urlencode(form)
            elif form:
                body = _form(form)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            answer = yield from _send(Call(method, url, body, headers))
            if answer.status == 401 and not self.token and not again:
                self._session = ""
                continue
            if answer.status == 401:
                reason = _splunk_messages(answer)
                raise SiemProblem(f"Splunk refused the credentials (token expired or wrong?): {reason}")
            return answer
        return answer  # pragma: no cover

    def _query(self, query: str, start: Any, end: Any, max_rows: int, timeout: float) -> Steps:
        began = time.monotonic()
        answer = yield from self._call(
            "POST",
            "search/jobs",
            {
                "search": self.search_string(query),
                "earliest_time": _when(start, "-24h"),
                "latest_time": _when(end, "now"),
                "output_mode": "json",
            },
        )
        if answer.status >= 400:  # bad SPL is refused here, at dispatch, with the parser's message
            raise SiemProblem(_splunk_messages(answer))
        sid = _json(answer)["sid"]
        while True:
            answer = yield from self._call("GET", f"search/jobs/{quote(sid)}", {"output_mode": "json"})
            if answer.status >= 400:
                raise SiemProblem(_splunk_messages(answer))
            job = _json(answer)["entry"][0]["content"]
            if job.get("dispatchState") == "FAILED" or job.get("isFailed"):
                messages = job.get("messages") if isinstance(job.get("messages"), list) else []
                texts = [m.get("text", "") for m in messages if isinstance(m, dict)]
                raise SiemProblem("; ".join(t for t in texts if t) or "The search failed.")
            if job.get("isDone"):
                break
            if time.monotonic() - began > timeout:
                yield from self._call("POST", f"search/jobs/{quote(sid)}/control", {"action": "cancel"})
                raise SiemProblem(f"The search took longer than {int(timeout)} seconds and was cancelled.")
            yield Wait(1.0)

        total = int(job.get("resultCount", 0))
        wanted = total if not max_rows else min(max_rows, total)
        rows: list[dict[str, Any]] = []
        while len(rows) < wanted:
            answer = yield from self._call(
                "GET",
                f"search/jobs/{quote(sid)}/results",
                {"output_mode": "json", "count": min(1000, wanted - len(rows)), "offset": len(rows)},
            )
            if answer.status >= 400:
                raise SiemProblem(_splunk_messages(answer))
            page = _json(answer).get("results") or []
            if not page:
                break
            rows.extend(page)
        return Result(
            rows,
            truncated=len(rows) < total,
            stats={
                "sid": sid,
                "result_count": total,
                "scan_count": job.get("scanCount", 0),
                "event_count": job.get("eventCount", 0),
                "run_duration": job.get("runDuration", 0),
            },
        )

    def _check(self) -> Steps:
        return (yield from self._query("| makeresults", None, None, 1, 60.0))


# ---- Elasticsearch ------------------------------------------------------------------------------------

DEFAULT_LIMIT = 1000  # what ES|QL returns when a query sets no LIMIT
_STATS = re.compile(r"\|\s*STATS\b", re.I)
_RESHAPES = re.compile(r"\|\s*(KEEP|DROP|RENAME)\b", re.I)  # can drop the _id and @timestamp paging needs
_TRAILING_LIMIT = re.compile(r"\|\s*LIMIT\s+(\d+)\s*$", re.I)
_FROM = re.compile(r"^\s*FROM\s+([^|]+?)(\s+METADATA\s+([^|]+?))?(?=\s*(?:\||$))", re.I)


def _literal(value: Any) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _elastic_reason(answer: _http.Response) -> str:
    """Elasticsearch's own words: {"error": {"root_cause": [{"reason": ...}], "reason": ...}}."""
    try:
        error = json.loads(answer.body or b"{}").get("error")
    except (ValueError, AttributeError):
        return answer.body[:300].decode(errors="replace") or f"HTTP {answer.status}"
    if isinstance(error, str):
        return error
    if not isinstance(error, dict):
        return f"HTTP {answer.status}"
    causes = [c.get("reason", "") for c in error.get("root_cause") or [] if isinstance(c, dict)]
    causes = [c for c in causes if c]
    return "; ".join(dict.fromkeys(causes)) or error.get("reason") or f"HTTP {answer.status}"


class Elastic(_Client):
    """ES|QL through Elasticsearch's query API (POST /_query). An API key (the encoded one Kibana or
    POST /_security/api_key gives) is sent as `ApiKey`; else a username and password.

    ES|QL has no cursor: a query returns at most its LIMIT (1,000 when it sets none). A query returning
    events (no STATS, no LIMIT of its own, no KEEP, DROP or RENAME) is paged by @timestamp and _id, so
    `max_rows` can go past that; any other is run as written and `truncated` says it came back full."""

    def __init__(
        self, url: str, *, api_key: str = "", username: str = "", password: str = "", verify: bool = True
    ) -> None:
        if not url or not (api_key or (username and password)):
            raise ValueError("Elasticsearch needs its URL and an API key, or a username and password.")
        self.url, self.verify = url.rstrip("/"), verify
        if api_key:
            self.auth = f"ApiKey {api_key}"
        else:
            self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    @staticmethod
    def pageable(query: str) -> bool:
        """Whether the query returns events (paged) rather than a summary or its own LIMIT (run once)."""
        q = query.strip()
        return (
            bool(_FROM.match(q))
            and not _STATS.search(q)
            and not _TRAILING_LIMIT.search(q)
            and not _RESHAPES.search(q)
        )

    @staticmethod
    def page_query(query: str, size: int, after: tuple[str, str] | None = None) -> str:
        """The query with _id in its METADATA, a keyset WHERE past the last row, sorted, limited."""
        q = query.strip()
        m = _FROM.match(q)
        assert m is not None
        sources = m.group(1).strip()
        metadata = [s.strip() for s in (m.group(3) or "").split(",") if s.strip()]
        if "_id" not in metadata:
            metadata.append("_id")
        rest = q[m.end() :]
        if after:
            ts, doc = after
            rest += (
                f"\n| WHERE @timestamp > TO_DATETIME({_literal(ts)})"
                f" OR (@timestamp == TO_DATETIME({_literal(ts)}) AND _id > {_literal(doc)})"
            )
        head = f"FROM {sources} METADATA {', '.join(metadata)}"
        return f"{head}{rest}\n| SORT @timestamp ASC, _id ASC\n| LIMIT {size}"

    def _run(self, query: str, window: dict[str, Any] | None, timeout: float) -> Steps:
        body: dict[str, Any] = {"query": query}
        if window:
            body["filter"] = {"range": {"@timestamp": window}}
        answer = yield from _send(
            Call(
                "POST",
                f"{self.url}/_query?format=json",
                json.dumps(body).encode(),
                {"Authorization": self.auth, "Content-Type": "application/json"},
                timeout,
            )
        )
        if answer.status == 401:
            reason = _elastic_reason(answer)
            raise SiemProblem(f"Elasticsearch refused the credentials (API key expired or wrong?): {reason}")
        if answer.status == 403:
            raise SiemProblem(f"Not allowed to read these indices: {_elastic_reason(answer)}")
        if answer.status >= 400:  # bad ES|QL is refused with the parser's or verifier's message
            raise SiemProblem(_elastic_reason(answer))
        data = _json(answer)
        names = [c["name"] for c in data.get("columns", [])]
        rows = [dict(zip(names, values, strict=False)) for values in data.get("values", [])]
        return rows, int(data.get("took", 0)), bool(data.get("is_partial"))

    def _query(self, query: str, start: Any, end: Any, max_rows: int, timeout: float) -> Steps:
        window = {
            k: (_iso(v) if isinstance(v, datetime) else v)
            for k, v in (("gte", start), ("lte", end))
            if v is not None
        }
        began = time.monotonic()
        if not self.pageable(query):
            rows, took, partial = yield from self._run(query, window, timeout)
            m = _TRAILING_LIMIT.search(query.strip())
            limit = int(m.group(1)) if m else DEFAULT_LIMIT
            return Result(rows, len(rows) >= limit, {"took_ms": took, "partial": partial, "pages": 1})
        rows: list[dict[str, Any]] = []
        after, pages, partial, took = None, 0, False, 0
        while True:
            size = 1000 if not max_rows else min(1000, max_rows - len(rows))
            paged = self.page_query(query, size, after)
            page, took_now, partial_now = yield from self._run(paged, window, timeout)
            pages, took, partial = pages + 1, took + took_now, partial or partial_now
            rows.extend(page)
            spent = round(time.monotonic() - began, 3)
            stats = {"took_ms": took, "partial": partial, "pages": pages, "run_duration": spent}
            if len(page) < size:
                return Result(rows, False, stats)
            if max_rows and len(rows) >= max_rows:
                return Result(rows, True, stats)  # more may be there
            last = page[-1]
            if last.get("@timestamp") is None or last.get("_id") is None:
                raise SiemProblem("Can't page: the rows have no @timestamp or _id.")
            after = (last["@timestamp"], last["_id"])

    def _check(self) -> Steps:
        return (yield from self._query("ROW ok = 1", None, None, 1, 60.0))


# ---- Microsoft Defender XDR ---------------------------------------------------------------------------

GRAPH_HUNTING = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"


class Defender(_Bearer):
    """KQL through Advanced Hunting (Microsoft Graph runHuntingQuery), as an app registration in the
    tenant with the ThreatHunting.Read.All application permission (admin consented)."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, *, verify: bool = True) -> None:
        if not (tenant_id and client_id and client_secret):
            raise ValueError("Defender XDR needs the app registration's tenant ID, client ID and secret.")
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self.verify = verify

    def _sign_in(self) -> Steps:
        answer = yield from _send(
            Call(
                "POST",
                f"https://login.microsoftonline.com/{quote(self.tenant_id)}/oauth2/v2.0/token",
                _form(
                    {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "grant_type": "client_credentials",
                        "scope": "https://graph.microsoft.com/.default",
                    }
                ),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        if answer.status >= 400:
            data = _json(answer) if answer.body else {}
            reason = data.get("error_description", "").split("\r\n")[0] if isinstance(data, dict) else ""
            reason = reason or f"HTTP {answer.status}"
            raise SiemProblem(f"Microsoft Entra refused the app registration: {reason}")
        return _json(answer)

    def _query(self, query: str, start: Any, end: Any, max_rows: int, timeout: float) -> Steps:
        answer = yield from self._authorised(
            lambda bearer: Call(
                "POST",
                GRAPH_HUNTING,
                json.dumps({"Query": query}).encode(),
                {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
                timeout,
            )
        )
        if answer.status in (401, 403):
            raise SiemProblem(
                f"Advanced Hunting refused the app registration (does it have ThreatHunting.Read.All, admin "
                f"consented?): HTTP {answer.status}"
            )
        if answer.status >= 400:
            try:
                error = json.loads(answer.body or b"{}").get("error") or {}
                reason = error.get("message", "") if isinstance(error, dict) else str(error)
            except ValueError:
                reason = ""
            raise SiemProblem(reason or f"Advanced Hunting answered HTTP {answer.status}.")
        data = _json(answer)
        rows = data.get("results") or []
        total = len(rows)
        if max_rows:
            rows = rows[:max_rows]
        return Result(rows, len(rows) < total, {"result_count": total, "schema": data.get("schema") or []})

    def _check(self) -> Steps:
        return (yield from self._query("DeviceInfo | take 1", None, None, 1, 60.0))


# ---- Google SecOps ------------------------------------------------------------------------------------

GOOGLE_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def service_account_assertion(account: Mapping[str, Any], scope: str, now: datetime) -> str:
    """A service account's signed JWT (RS256) asking Google's token endpoint for an access token."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = serialization.load_pem_private_key(str(account["private_key"]).encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The service account's key isn't an RSA key.")
    issued = int(now.timestamp())
    header = {"alg": "RS256", "typ": "JWT"}
    if account.get("private_key_id"):
        header["kid"] = str(account["private_key_id"])
    claims = {
        "iss": account["client_email"],
        "scope": scope,
        "aud": account.get("token_uri") or "https://oauth2.googleapis.com/token",
        "iat": issued,
        "exp": issued + 3600,
    }
    signing = ".".join(_b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims))
    signature = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing}.{_b64url(signature)}"


def flatten(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """A nested UDM event as one row: {"principal": {"hostname": "h"}} becomes {"principal.hostname": "h"}."""
    out: dict[str, Any] = {}
    for key, inner in value.items():
        name = f"{prefix}{key}"
        if isinstance(inner, Mapping):
            out.update(flatten(inner, f"{name}."))
        else:
            out[name] = inner
    return out


class SecOps(_Bearer):
    """UDM search through the Chronicle API (…/instances/<customer id>:udmSearch), as a service account
    with the Chronicle API Viewer role. `region` is the instance's (us, europe, europe-west2…); `project`
    is the Google Cloud project bound to it; `instance` is the SecOps customer ID."""

    def __init__(
        self,
        service_account: str | Mapping[str, Any],
        project: str,
        instance: str,
        *,
        region: str = "us",
        verify: bool = True,
    ) -> None:
        account = json.loads(service_account) if isinstance(service_account, str) else dict(service_account)
        if not (account.get("client_email") and account.get("private_key") and project and instance):
            raise ValueError("Google SecOps needs a service account key (JSON), the project and customer ID.")
        self.account, self.project, self.instance = account, project, instance
        self.region, self.verify = region, verify

    @property
    def endpoint(self) -> str:
        return (
            f"https://{self.region}-chronicle.googleapis.com/v1alpha/projects/{quote(self.project)}"
            f"/locations/{quote(self.region)}/instances/{quote(self.instance)}:udmSearch"
        )

    def _sign_in(self) -> Steps:
        assertion = service_account_assertion(self.account, GOOGLE_SCOPE, datetime.now(timezone.utc))
        answer = yield from _send(
            Call(
                "POST",
                self.account.get("token_uri") or "https://oauth2.googleapis.com/token",
                _form({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        if answer.status >= 400:
            data = _json(answer) if answer.body else {}
            reason = data.get("error_description", "") if isinstance(data, dict) else ""
            raise SiemProblem(f"Google refused the service account: {reason or f'HTTP {answer.status}'}")
        return _json(answer)

    def _query(self, query: str, start: Any, end: Any, max_rows: int, timeout: float) -> Steps:
        finish = end if isinstance(end, datetime) else datetime.now(timezone.utc)
        begin = start if isinstance(start, datetime) else finish - timedelta(hours=24)
        params = {
            "query": query.strip(),
            "timeRange.startTime": _iso(begin),
            "timeRange.endTime": _iso(finish),
            "limit": max_rows or 10000,
        }
        answer = yield from self._authorised(
            lambda bearer: Call(
                "GET",
                f"{self.endpoint}?{urlencode(params)}",
                headers={"Authorization": f"Bearer {bearer}"},
                timeout=timeout,
            )
        )
        if answer.status in (401, 403):
            raise SiemProblem(
                f"Google SecOps refused the service account (does it have the Chronicle API Viewer role?): "
                f"HTTP {answer.status}"
            )
        if answer.status >= 400:
            try:
                error = json.loads(answer.body or b"{}").get("error") or {}
                reason = error.get("message", "") if isinstance(error, dict) else str(error)
            except ValueError:
                reason = ""
            raise SiemProblem(reason or f"Google SecOps answered HTTP {answer.status}.")
        data = _json(answer) or {}
        rows = [flatten(e.get("udm") or {}) for e in data.get("events") or [] if isinstance(e, dict)]
        return Result(
            rows,
            bool(data.get("moreDataAvailable")),
            {"start": _iso(begin), "end": _iso(finish)},
        )

    def _check(self) -> Steps:
        return (yield from self._query('metadata.event_type = "USER_LOGIN"', None, None, 1, 60.0))
