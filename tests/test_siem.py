"""SIEM queries, driven by scripted answers: the requests each client makes, how it reads what comes back,
and the problems it reports. No network."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from samarkand import siem
from samarkand._http import Response

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def ok(body: Any, status: int = 200, **headers: str) -> Response:
    return Response(status, json.dumps(body).encode(), headers)


def drive(steps: siem.Steps, answers: list[Response]) -> tuple[Any, list[siem.Call], list[float]]:
    """Run a query's generator against scripted answers: (what it returned, its calls, its waits)."""
    calls: list[siem.Call] = []
    waits: list[float] = []
    answer: Response | None = None
    queue = list(answers)
    try:
        while True:
            step = steps.send(answer)
            if isinstance(step, siem.Wait):
                waits.append(step.seconds)
                answer = None
            else:
                calls.append(step)
                answer = queue.pop(0)
    except StopIteration as done:
        assert not queue, f"{len(queue)} answers left over"
        return done.value, calls, waits


def form(call: siem.Call) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs((call.body or b"").decode()).items()}


def query_of(call: siem.Call) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(call.url).query).items()}


# ---- Splunk -------------------------------------------------------------------------------------------


def splunk_job(done: bool = True, **content: Any) -> Response:
    return ok({"entry": [{"content": {"isDone": done, "resultCount": 2, "scanCount": 9, **content}}]})


def test_splunk_runs_a_job_waits_for_it_and_pages_its_results():
    client = siem.Splunk("https://splunk.example:8089", token="t0k")
    result, calls, waits = drive(
        client._query("index=main user=bob", NOW, "now", 0, 300),
        [
            ok({"sid": "1.23"}, 201),
            splunk_job(done=False),
            splunk_job(),
            ok({"results": [{"user": "bob"}, {"user": "bob", "host": "h1"}]}),
        ],
    )
    assert [c.method for c in calls] == ["POST", "GET", "GET", "GET"]
    assert calls[0].url == "https://splunk.example:8089/services/search/jobs"
    assert calls[0].headers["Authorization"] == "Bearer t0k"
    assert form(calls[0]) == {
        "search": "search index=main user=bob",
        "earliest_time": str(int(NOW.timestamp())),
        "latest_time": "now",
        "output_mode": "json",
    }
    assert waits == [1.0]
    assert query_of(calls[3]) == {"output_mode": "json", "count": "2", "offset": "0"}
    assert result.rows == [{"user": "bob"}, {"user": "bob", "host": "h1"}]
    assert result.columns == ["user", "host"]
    assert result.truncated is False and result.stats["sid"] == "1.23"


def test_splunk_leaves_a_generating_command_as_it_is():
    assert siem.Splunk.search_string("| tstats count") == "| tstats count"
    assert siem.Splunk.search_string("search x") == "search x"


def test_splunk_logs_in_with_a_password_and_again_when_the_session_expires():
    client = siem.Splunk("https://splunk.example:8089/services", username="u", password="p")
    result, calls, _ = drive(
        client._query("| makeresults", None, None, 1, 60),
        [
            ok({"sessionKey": "s1"}),
            ok({"messages": []}, 401),
            ok({"sessionKey": "s2"}),
            ok({"sid": "9"}, 201),
            splunk_job(resultCount=1),
            ok({"results": [{"_time": "x"}]}),
        ],
    )
    assert calls[0].url.endswith("/services/auth/login") and form(calls[0])["username"] == "u"
    assert calls[1].headers["Authorization"] == "Splunk s1"
    assert calls[3].headers["Authorization"] == "Splunk s2"
    assert result.rows == [{"_time": "x"}]


def test_splunk_reads_at_most_max_rows():
    client = siem.Splunk("https://s:8089", token="t")
    result, calls, _ = drive(
        client._query("x", None, None, 1, 60),
        [ok({"sid": "1"}, 201), splunk_job(), ok({"results": [{"a": 1}]})],
    )
    assert query_of(calls[-1])["count"] == "1"
    assert result.truncated is True


def test_splunk_says_what_was_wrong_with_the_spl():
    client = siem.Splunk("https://s:8089", token="t")
    with pytest.raises(siem.SiemProblem, match="Unknown search command 'frob'"):
        drive(
            client._query("| frob", None, None, 1, 60),
            [ok({"messages": [{"type": "FATAL", "text": "Unknown search command 'frob'."}] * 2}, 400)],
        )


def test_splunk_waits_out_a_busy_server():
    client = siem.Splunk("https://s:8089", token="t")
    _, _, waits = drive(
        client._query("x", None, None, 1, 60),
        [
            Response(503, b"", {"retry-after": "3"}),
            ok({"sid": "1"}, 201),
            splunk_job(resultCount=0),
        ],
    )
    assert waits == [3.0]


def test_splunk_refuses_an_expired_token():
    client = siem.Splunk("https://s:8089", token="t")
    with pytest.raises(siem.SiemProblem, match="refused the credentials"):
        drive(client._query("x", None, None, 1, 60), [ok({"messages": [{"text": "bad token"}]}, 401)])


def test_splunk_needs_credentials():
    with pytest.raises(ValueError):
        siem.Splunk("https://s:8089")


# ---- Elasticsearch ------------------------------------------------------------------------------------


def esql(rows: list[list[Any]], columns: list[str], **extra: Any) -> Response:
    columns_out = [{"name": c, "type": "keyword"} for c in columns]
    return ok({"columns": columns_out, "values": rows, "took": 3, **extra})


def test_elastic_runs_a_summary_once_with_the_window_as_a_filter():
    client = siem.Elastic("https://es.example:9200/", api_key="k==")
    result, calls, _ = drive(
        client._query("FROM logs-* | STATS n = COUNT(*) BY host.name", NOW, None, 1000, 60),
        [esql([[3, "h1"]], ["n", "host.name"])],
    )
    assert calls[0].url == "https://es.example:9200/_query?format=json"
    assert calls[0].headers["Authorization"] == "ApiKey k=="
    body = json.loads(calls[0].body or b"")
    assert body["query"].startswith("FROM logs-*")
    assert body["filter"] == {"range": {"@timestamp": {"gte": "2026-11-18T12:00:00Z"}}}
    assert result.rows == [{"n": 3, "host.name": "h1"}] and result.truncated is False


def test_elastic_pages_an_event_query_by_timestamp_and_id():
    client = siem.Elastic("https://es:9200", username="u", password="p")
    cols = ["@timestamp", "_id", "user.name"]
    page = [["2026-11-18T10:00:00Z", f"d{i}", "bob"] for i in range(1000)]
    result, calls, _ = drive(
        client._query('FROM logs-* | WHERE user.name == "bob"', None, None, 0, 60),
        [esql(page, cols), esql([["2026-11-18T11:00:00Z", "z", "bob"]], cols)],
    )
    assert calls[0].headers["Authorization"] == "Basic " + base64.b64encode(b"u:p").decode()
    second = json.loads(calls[1].body or b"")["query"]
    assert "METADATA _id" in second and '_id > "d999"' in second and second.endswith("| LIMIT 1000")
    assert len(result.rows) == 1001 and result.stats["pages"] == 2


def test_elastic_says_what_was_wrong_with_the_esql():
    client = siem.Elastic("https://es:9200", api_key="k")
    with pytest.raises(siem.SiemProblem, match="Unknown column"):
        drive(
            client._query("FROM x | KEEP nope", None, None, 10, 60),
            [ok({"error": {"root_cause": [{"reason": "Unknown column [nope]"}]}}, 400)],
        )


def test_elastic_knows_which_queries_page():
    assert siem.Elastic.pageable("FROM logs-* | WHERE a == 1")
    assert not siem.Elastic.pageable("FROM logs-* | STATS COUNT(*)")
    assert not siem.Elastic.pageable("FROM logs-* | LIMIT 5")
    assert not siem.Elastic.pageable("ROW ok = 1")


# ---- Defender XDR -------------------------------------------------------------------------------------


def test_defender_gets_a_token_then_hunts():
    client = siem.Defender("tenant-1", "client-1", "secret-1")
    result, calls, _ = drive(
        client._query("DeviceProcessEvents | take 2", None, None, 1, 60),
        [
            ok({"access_token": "bearer-1"}),
            ok(
                {
                    "schema": [{"name": "DeviceName", "type": "String"}],
                    "results": [{"DeviceName": "a"}, {"DeviceName": "b"}],
                }
            ),
        ],
    )
    assert calls[0].url == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    assert form(calls[0])["scope"] == "https://graph.microsoft.com/.default"
    assert calls[1].url == siem.GRAPH_HUNTING
    assert calls[1].headers["Authorization"] == "Bearer bearer-1"
    assert json.loads(calls[1].body or b"") == {"Query": "DeviceProcessEvents | take 2"}
    assert result.rows == [{"DeviceName": "a"}] and result.truncated is True
    assert result.stats["result_count"] == 2


def test_defender_says_what_was_wrong_with_the_kql():
    client = siem.Defender("t", "c", "s")
    with pytest.raises(siem.SiemProblem, match="Failed to resolve table"):
        drive(
            client._query("Nope", None, None, 1, 60),
            [
                ok({"access_token": "b"}),
                ok({"error": {"code": "BadRequest", "message": "Failed to resolve table 'Nope'"}}, 400),
            ],
        )


def test_defender_names_the_permission_it_needs():
    client = siem.Defender("t", "c", "s")
    with pytest.raises(siem.SiemProblem, match="ThreatHunting.Read.All"):
        drive(client._query("x", None, None, 1, 60), [ok({"access_token": "b"}), ok({}, 403)])


def hunted(rows: int = 1) -> Response:
    return ok({"schema": [], "results": [{"n": i} for i in range(rows)]})


def test_defender_keeps_its_token_between_queries():
    client = siem.Defender("t", "c", "s")
    _, first, _ = drive(client._query("a", None, None, 1, 60), [ok({"access_token": "b1"}), hunted()])
    _, second, _ = drive(client._query("b", None, None, 1, 60), [hunted()])
    assert len(first) == 2 and [c.url for c in second] == [siem.GRAPH_HUNTING]
    assert second[0].headers["Authorization"] == "Bearer b1"


def test_defender_signs_in_again_once_the_token_is_near_expiry(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(siem.time, "monotonic", lambda: clock[0])
    client = siem.Defender("t", "c", "s")
    drive(client._query("a", None, None, 1, 60), [ok({"access_token": "b1", "expires_in": 3599}), hunted()])
    clock[0] += 3599 - siem.TOKEN_MARGIN - 1
    _, calls, _ = drive(client._query("b", None, None, 1, 60), [hunted()])
    assert len(calls) == 1
    clock[0] += 2
    _, calls, _ = drive(client._query("c", None, None, 1, 60), [ok({"access_token": "b2"}), hunted()])
    assert calls[1].headers["Authorization"] == "Bearer b2"


def test_defender_drops_a_kept_token_that_is_refused_and_tries_once_more():
    client = siem.Defender("t", "c", "s")
    drive(client._query("a", None, None, 1, 60), [ok({"access_token": "b1"}), hunted()])
    result, calls, _ = drive(
        client._query("b", None, None, 1, 60), [ok({}, 401), ok({"access_token": "b2"}), hunted()]
    )
    assert [c.headers.get("Authorization") for c in calls] == ["Bearer b1", None, "Bearer b2"]
    assert result.rows == [{"n": 0}]


def test_defender_reports_a_new_token_refused_without_retrying():
    client = siem.Defender("t", "c", "s")
    with pytest.raises(siem.SiemProblem, match="ThreatHunting.Read.All"):
        drive(client._query("a", None, None, 1, 60), [ok({"access_token": "b1"}), ok({}, 401)])
    assert client._bearer is not None  # kept: Entra issued it; the permission is what's missing


# ---- Google SecOps ------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def account() -> tuple[dict[str, str], rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return (
        {
            "type": "service_account",
            "client_email": "secops@project-1.iam.gserviceaccount.com",
            "private_key": pem,
            "private_key_id": "kid-1",
            "token_uri": "https://oauth2.googleapis.com/token",
        },
        key,
    )


def _unpad(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def test_a_service_account_signs_its_own_assertion(account):
    info, key = account
    jwt = siem.service_account_assertion(info, siem.GOOGLE_SCOPE, NOW)
    header, claims, signature = jwt.split(".")
    assert json.loads(_unpad(header)) == {"alg": "RS256", "typ": "JWT", "kid": "kid-1"}
    assert json.loads(_unpad(claims)) == {
        "iss": "secops@project-1.iam.gserviceaccount.com",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": int(NOW.timestamp()),
        "exp": int(NOW.timestamp()) + 3600,
    }
    signed = f"{header}.{claims}".encode()
    key.public_key().verify(_unpad(signature), signed, padding.PKCS1v15(), hashes.SHA256())


def test_secops_searches_udm_over_the_window_and_flattens_events(account):
    info, _ = account
    client = siem.SecOps(json.dumps(info), "project-1", "cust-1", region="europe")
    start = datetime(2026, 11, 17, 0, 0, tzinfo=timezone.utc)
    result, calls, _ = drive(
        client._query('principal.hostname = "ws-114"', start, NOW, 100, 60),
        [
            ok({"access_token": "g-1"}),
            ok(
                {
                    "events": [
                        {
                            "name": "e1",
                            "udm": {
                                "metadata": {"event_type": "PROCESS_LAUNCH"},
                                "principal": {"hostname": "ws-114"},
                            },
                        }
                    ],
                    "moreDataAvailable": True,
                }
            ),
        ],
    )
    assert form(calls[0])["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assert urlsplit(calls[1].url).netloc == "europe-chronicle.googleapis.com"
    path = "/v1alpha/projects/project-1/locations/europe/instances/cust-1:udmSearch"
    assert urlsplit(calls[1].url).path == path
    assert query_of(calls[1]) == {
        "query": 'principal.hostname = "ws-114"',
        "timeRange.startTime": "2026-11-17T00:00:00Z",
        "timeRange.endTime": "2026-11-18T12:00:00Z",
        "limit": "100",
    }
    assert calls[1].headers["Authorization"] == "Bearer g-1"
    assert result.rows == [{"metadata.event_type": "PROCESS_LAUNCH", "principal.hostname": "ws-114"}]
    assert result.truncated is True


def test_secops_needs_a_service_account():
    with pytest.raises(ValueError):
        siem.SecOps("{}", "p", "i")


# ---- running ------------------------------------------------------------------------------------------


def test_an_empty_query_is_refused_before_anything_is_sent():
    with pytest.raises(siem.SiemProblem, match="empty"):
        siem.Splunk("https://s:8089", token="t").query("  ")


def test_an_unreachable_siem_is_a_problem(monkeypatch):
    def refuse(*args: Any, **kwargs: Any) -> Response:
        raise OSError("Connection refused")

    monkeypatch.setattr(siem._http, "request", refuse)
    with pytest.raises(siem.SiemProblem, match="Couldn't reach es:9200: Connection refused"):
        siem.Elastic("https://es:9200", api_key="k").query("ROW ok = 1")


def test_the_async_runner_sends_the_same_requests(monkeypatch):
    seen: list[str] = []

    async def answer(method: str, url: str, **kwargs: Any) -> Response:
        seen.append(f"{method} {url}")
        return Response(200, json.dumps({"columns": [{"name": "ok"}], "values": [[1]]}).encode(), {})

    monkeypatch.setattr(siem._http, "request_async", answer)
    result = asyncio.run(siem.Elastic("https://es:9200", api_key="k").check_async())
    assert seen == ["POST https://es:9200/_query?format=json"] and result.rows == [{"ok": 1}]


def test_secops_keeps_its_token_between_queries(account):
    info, _ = account
    client = siem.SecOps(json.dumps(info), "p", "i")
    drive(client._query("q", None, NOW, 1, 60), [ok({"access_token": "g-1"}), ok({"events": []})])
    _, calls, _ = drive(client._query("q", None, NOW, 1, 60), [ok({"events": []})])
    assert len(calls) == 1 and calls[0].headers["Authorization"] == "Bearer g-1"
