"""netguard: no request reaches a link-local address, however the host is written or whatever its name
resolves to, and a request goes to the address that was checked, the name kept in Host."""

import asyncio
import http.server
import socket
import threading

import pytest

from samarkand import _http, netguard

real_getaddrinfo = socket.getaddrinfo


@pytest.fixture
def names(monkeypatch):
    """A resolver for made-up names (the rest resolve as usual), counting the lookups."""
    table: dict[str, list[str]] = {}
    lookups: list[str] = []

    def getaddrinfo(host, port, *args, **kwargs):
        if host in table:
            lookups.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in table[host]]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return table, lookups


@pytest.fixture
def server():
    """A local HTTP server that answers with the Host header it was sent."""

    class Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = (self.headers.get("Host") or "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "2852039166",
        "0xa9fea9fe",
        "0251.0376.0251.0376",
        "169.254.43518",
        "::ffff:169.254.169.254",
        "fe80::1",
        "[fe80::1]",
    ],
)
def test_a_link_local_address_is_refused_however_its_written(host):
    with pytest.raises(netguard.Refused):
        netguard.resolve(host, 443)


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "100.101.102.103", "203.0.113.9", "::1"])
def test_other_addresses_are_used_as_written(host):
    assert netguard.resolve(host, 443) == host


def test_a_name_resolving_to_link_local_is_refused_even_beside_a_good_address(names):
    table, _ = names
    table["metadata.attacker.example"] = ["169.254.169.254"]
    table["mixed.attacker.example"] = ["203.0.113.9", "169.254.169.254"]
    for name in table:
        with pytest.raises(netguard.Refused):
            netguard.resolve(name, 443)


def test_a_name_is_resolved_to_the_address_connected_to(names):
    table, _ = names
    table["siem.example.test"] = ["10.0.0.5", "10.0.0.6"]
    assert netguard.resolve("siem.example.test", 8089) == "10.0.0.5"


def test_the_sync_sender_connects_to_the_checked_address_keeping_the_name(names, server):
    table, lookups = names
    table["hooks.example.test"] = ["127.0.0.1"]
    answer = _http.request("GET", f"http://hooks.example.test:{server}/")
    assert answer.status == 200 and answer.body == f"hooks.example.test:{server}".encode()
    assert lookups == ["hooks.example.test"]  # resolved once, by the guard


def test_the_sync_sender_refuses_a_name_resolving_to_link_local(names):
    table, _ = names
    table["rebind.attacker.example"] = ["169.254.169.254"]
    with pytest.raises(OSError):
        _http.request("GET", "http://rebind.attacker.example/latest/meta-data", timeout=2)


def test_the_async_sender_connects_to_the_checked_address_keeping_the_name(names, server):
    table, lookups = names
    table["hooks.example.test"] = ["127.0.0.1"]
    answer = asyncio.run(_http.request_async("GET", f"http://hooks.example.test:{server}/"))
    assert answer.status == 200 and answer.body == f"hooks.example.test:{server}".encode()
    assert lookups == ["hooks.example.test"]


def test_the_async_sender_refuses_a_name_resolving_to_link_local(names):
    import httpx

    table, _ = names
    table["rebind.attacker.example"] = ["169.254.169.254"]
    with pytest.raises(httpx.ConnectError, match="link-local"):
        asyncio.run(_http.request_async("GET", "http://rebind.attacker.example/latest/meta-data", timeout=2))
