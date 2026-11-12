"""The TAXII 2.1 client: the requests it makes (the same URLs Rowanholt's makes), pagination, limits,
Basic auth and errors, through a fake server and a real one on this machine."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from samarkand import _http, stix, taxii

COLLECTION = "https://taxii.example/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116"


def obj(n: int) -> dict:
    return {
        "type": "indicator",
        "id": f"indicator--{n:08d}-0000-4000-8000-000000000000",
        "pattern": f"[domain-name:value = 'd{n}.example']",
    }


class Server:
    """Pages of objects; each page names the next until the last."""

    def __init__(self, pages, status=200, body=None):
        self.pages, self.status, self.body, self.calls = pages, status, body, []

    def __call__(self, method, url, *, headers, timeout, verify):
        self.calls.append((method, url, headers, timeout, verify))
        if self.body is not None or self.status != 200:
            return _http.Response(self.status, self.body or b"")
        query = parse_qs(urlsplit(url).query)
        index = int(query.get("next", ["0"])[0])
        more = index + 1 < len(self.pages)
        envelope = {"objects": self.pages[index], "more": more, **({"next": str(index + 1)} if more else {})}
        return _http.Response(200, json.dumps(envelope).encode())


def test_every_page_is_followed_and_the_urls_are_rowanholts():
    server = Server([[obj(1), obj(2)], [obj(3)], [obj(4)]])
    found = taxii.fetch_objects(COLLECTION, added_after="2026-11-01T00:00:00Z", request=server)
    assert [o["id"][11:19] for o in found] == ["00000001", "00000002", "00000003", "00000004"]
    urls = [call[1] for call in server.calls]
    assert urls == [
        f"{COLLECTION}/objects/?limit=1000&added_after=2026-11-01T00%3A00%3A00Z",
        f"{COLLECTION}/objects/?limit=1000&added_after=2026-11-01T00%3A00%3A00Z&next=1",
        f"{COLLECTION}/objects/?limit=1000&added_after=2026-11-01T00%3A00%3A00Z&next=2",
    ]
    assert server.calls[0][2] == {
        "Accept": "application/taxii+json;version=2.1",
        "User-Agent": "TAXII 2.1 client",
    }


def test_the_limit_stops_paging_and_cuts_the_last_page():
    server = Server([[obj(1), obj(2)], [obj(3), obj(4)], [obj(5)]])
    assert len(taxii.fetch_objects(COLLECTION + "/", limit=3, request=server)) == 3
    assert len(server.calls) == 2 and "limit=3" in server.calls[0][1]


def test_a_repeated_next_ends_the_loop():
    class Loop(Server):
        def __call__(self, method, url, **kw):
            self.calls.append(url)
            return _http.Response(
                200, json.dumps({"objects": [obj(1)], "more": True, "next": "same"}).encode()
            )

    loop = Loop([])
    assert len(taxii.fetch_objects(COLLECTION, request=loop)) == 2 and len(loop.calls) == 2


def test_basic_auth_when_given():
    server = Server([[obj(1)]])
    taxii.fetch_objects(
        COLLECTION,
        username="analyst",
        password="pa:ss",
        user_agent="Rowanholt (TAXII 2.1 client)",
        request=server,
    )
    headers = server.calls[0][2]
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"analyst:pa:ss").decode()
    assert headers["User-Agent"] == "Rowanholt (TAXII 2.1 client)"


@pytest.mark.parametrize(
    ("server", "says"),
    [
        (Server([], status=401), "refused the credentials"),
        (Server([], status=404), "answered HTTP 404"),
        (Server([], body=b"<html>"), "isn't JSON"),
        (Server([], body=b"[1]"), "isn't an envelope"),
    ],
)
def test_a_server_that_refuses_says_why(server, says):
    with pytest.raises(taxii.TaxiiProblem, match=says):
        taxii.fetch_objects(COLLECTION, request=server)


def test_an_unreachable_server_says_so():
    def down(*args, **kwargs):
        raise ConnectionRefusedError("refused")

    with pytest.raises(taxii.TaxiiProblem, match="Couldn't reach the TAXII server: refused"):
        taxii.fetch_objects(COLLECTION, request=down)


def test_the_bundle_reads_straight_into_stix():
    server = Server([[obj(1)], [obj(2)]])
    parsed = stix.parse(taxii.fetch_bundle(COLLECTION, request=server))
    assert [i.value for i in parsed.indicators] == ["d1.example", "d2.example"]


class Taxii(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):  # noqa: N802
        Taxii.seen.append((self.path, self.headers.get("Authorization"), self.headers.get("Accept")))
        if self.path.endswith("/collections/c1/"):
            body = {"id": "c1", "title": "Lab feed", "can_read": True}
        elif "next=p2" in self.path:
            body = {"objects": [obj(2)], "more": False}
        else:
            body = {"objects": [obj(1)], "more": True, "next": "p2"}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", taxii.ACCEPT)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def test_against_a_real_server():
    Taxii.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Taxii)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api1/collections/c1"
        assert taxii.collection_info(url, username="u", password="p")["title"] == "Lab feed"
        assert len(taxii.fetch_objects(url, username="u", password="p")) == 2
    finally:
        server.shutdown()
    assert [s[0] for s in Taxii.seen] == [
        "/api1/collections/c1/",
        "/api1/collections/c1/objects/?limit=1000",
        "/api1/collections/c1/objects/?limit=1000&next=p2",
    ]
    assert all(s[1] == "Basic dTpw" and s[2] == taxii.ACCEPT for s in Taxii.seen)


@pytest.mark.parametrize(
    "server", [Server([], status=401), Server([], status=500), Server([], body=b"<html>")], ids=str
)
def test_a_taxii_problem_is_an_oserror_with_its_message(server):
    # Products answer an OSError with 502 (Rowanholt's threat_intel_routes), so they need no wrapper
    with pytest.raises(OSError) as raised:
        taxii.fetch_objects(COLLECTION, request=server)
    problem = raised.value
    assert isinstance(problem, taxii.TaxiiProblem) and isinstance(problem, Exception)
    assert problem.errno is None and problem.args == (str(problem),) and str(problem).startswith("The TAXII")


def test_an_unreachable_server_is_still_one_taxii_problem_not_the_raw_oserror():
    def down(*args, **kwargs):
        raise TimeoutError("timed out")

    with pytest.raises(taxii.TaxiiProblem, match="Couldn't reach the TAXII server: timed out") as raised:
        taxii.collection_info(COLLECTION, request=down)
    assert isinstance(raised.value.__cause__, TimeoutError)
