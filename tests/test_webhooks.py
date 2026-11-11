"""Webhooks against the vectors, the URL rules from all three products' tests, and delivery through a
fake sender and a real local server, sync and async."""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import vector

from samarkand import webhooks as W

V = vector("webhooks/vectors.json")


@pytest.mark.parametrize("case", V["deliveries"], ids=lambda c: c["event"])
def test_the_body_and_signature_are_the_vectors_byte_for_byte(case):
    raw = W.body(case["event"], case["data"], datetime.fromisoformat(case["sent_at"]))
    assert raw == case["body"].encode()
    assert W.sign(case["secret"], raw) == case["signature"]
    assert W.verify(case["secret"], raw, case["signature"])
    assert W.verify(case["secret"], raw, f"  {case['signature']}\n")


@pytest.mark.parametrize("case", V["deliveries"], ids=lambda c: c["event"])
def test_a_receiver_refuses_anything_altered(case):
    raw = case["body"].encode()
    assert not W.verify(case["secret"], raw + b" ", case["signature"])
    assert not W.verify("another secret", raw, case["signature"])
    assert not W.verify(case["secret"], raw, None)
    assert not W.verify("", raw, case["signature"])
    assert not W.verify(case["secret"], raw, case["signature"].replace("sha256=", "sha1="))


def test_a_receiver_reads_the_envelope_and_both_kinds_of_sent_at():
    case = V["deliveries"][1]
    got = W.parse(case["body"].encode())
    assert (got.event, got.data) == (case["event"], case["data"])
    assert got.sent_at_time == datetime(2026, 11, 11, 12, 0, 0, 123456, tzinfo=timezone.utc)
    legacy = V["epoch_sent_at"]
    assert W.verify(legacy["secret"], legacy["body"].encode(), legacy["signature"])
    old = W.parse(legacy["body"].encode())
    assert old.sent_at == 1762862400.5 and old.sent_at_time == datetime.fromtimestamp(
        1762862400.5, timezone.utc
    )
    assert W.Delivery("x", "yesterday").sent_at_time is None and W.Delivery("x", True).sent_at_time is None


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"data": {}}', b'{"event": 3}'])
def test_a_body_that_isnt_a_delivery_is_refused(raw):
    with pytest.raises(W.NotADelivery):
        W.parse(raw)


def test_data_that_isnt_an_object_reads_as_empty():
    assert W.parse(b'{"event": "x", "data": [1]}').data == {}


@pytest.mark.parametrize(("prefix", "names"), V["headers"].items())
def test_header_names_come_from_the_prefix(prefix, names):
    assert tuple(W.headers_for(prefix)) == tuple(names)
    assert W.headers_for(prefix + "-") == tuple(names)


def test_the_user_agent_comes_from_the_prefix_too():
    assert W.user_agent_for("X-Ostraka") == "Ostraka-Webhook/1"
    with pytest.raises(ValueError):
        W.headers_for("  ")


@pytest.mark.parametrize("url", V["urls"]["allowed"])
def test_https_anywhere_and_http_only_to_this_machine_or_a_private_network(url):
    assert W.url_problem(url) is None


@pytest.mark.parametrize("url", V["urls"]["refused"])
def test_every_url_any_product_refuses_is_refused(url):
    assert W.url_problem(url)


def test_the_refusals_say_why():
    assert "link-local" in W.url_problem("https://169.254.169.254/")
    assert "credentials" in W.url_problem("https://a:b@hooks.example.org/")
    assert "Plain http://" in W.url_problem("http://hooks.example.org/")
    assert W.url_problem("https://hooks.example.org:notaport/") == "The URL must start with https://."


def test_events_must_be_the_products_own():
    allowed = ("incident.created", "task.assigned")
    assert W.events_problem(["task.assigned"], allowed) is None
    assert W.events_problem([], allowed) == "Choose events from incident.created, task.assigned."
    assert W.events_problem(["run.completed"], allowed)


def test_the_envelope_is_utc_whatever_time_it_is_given():
    naive = W.envelope("x", {}, datetime(2026, 11, 11, 12))
    assert naive["sent_at"] == "2026-11-11T12:00:00+00:00"
    from datetime import timedelta

    elsewhere = datetime(2026, 11, 11, 13, tzinfo=timezone(timedelta(hours=1)))
    assert W.envelope("x", {}, elsewhere)["sent_at"] == "2026-11-11T12:00:00+00:00"
    assert json.loads(W.body("x", {"when": datetime(2026, 1, 1)}))["data"]["when"] == "2026-01-01 00:00:00"


def test_prepare_signs_only_with_a_secret():
    at = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
    signed = W.prepare(
        " https://h.example/x ", "run.completed", {"run": "FIN7"}, prefix="X-Shikari", secret="s", sent_at=at
    )
    assert signed.url == "https://h.example/x"
    assert signed.headers == {
        "Content-Type": "application/json",
        "User-Agent": "Shikari-Webhook/1",
        "X-Shikari-Event": "run.completed",
        "X-Shikari-Signature": W.sign("s", signed.body),
    }
    plain = W.prepare("https://h.example/x", "run.completed", {}, prefix="X-Shikari", user_agent="ua/2")
    assert "X-Shikari-Signature" not in plain.headers and plain.headers["User-Agent"] == "ua/2"


class Fake:
    """A receiver that answers from a script: a status, or an exception to raise."""

    def __init__(self, *answers):
        self.answers, self.calls, self.slept = list(answers), [], []

    def post(self, url, raw, headers, timeout):
        self.calls.append((url, raw, dict(headers), timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def sleep(self, seconds):
        self.slept.append(seconds)


def outgoing():
    return W.prepare("https://h.example/x", "job.failed", {"job_id": "j1"}, prefix="X-Rowanholt", secret="s")


def test_three_tries_with_backoff_on_a_server_error():
    fake = Fake(500, 503, 200)
    result = W.send(outgoing(), post=fake.post, sleep=fake.sleep)
    assert (result.ok, result.status, result.tries, result.error) == (True, 200, 3, "")
    assert fake.slept == [2.0, 4.0] == W.delays()
    assert all(call[3] == W.TIMEOUT for call in fake.calls)


def test_a_refusal_is_tried_once_but_429_is_tried_again():
    fake = Fake(404)
    result = W.send(outgoing(), post=fake.post, sleep=fake.sleep)
    assert (result.ok, result.status, result.tries, result.error) == (False, 404, 1, "HTTP 404")
    fake = Fake(429, 429, 429)
    result = W.send(outgoing(), post=fake.post, sleep=fake.sleep)
    assert (result.tries, result.error, fake.slept) == (3, "HTTP 429", [2.0, 4.0])


def test_a_redirect_is_an_answer_not_followed():
    fake = Fake(302)
    assert W.send(outgoing(), post=fake.post, sleep=fake.sleep).error == "HTTP 302"


def test_an_unreachable_receiver_is_recorded_not_raised():
    fake = Fake(ConnectionRefusedError("refused"), OSError(), TimeoutError("x" * 500))
    result = W.send(outgoing(), post=fake.post, sleep=fake.sleep)
    assert (result.ok, result.status, result.tries) == (False, None, 3)
    assert result.error == "x" * 200
    assert W.send(outgoing(), tries=1, post=Fake(OSError()).post).error == "OSError"


def test_a_url_the_rules_refuse_is_never_sent():
    fake = Fake(200)
    bad = W.prepare("http://169.254.169.254/x", "e", {}, prefix="X-Ostraka")
    result = W.send(bad, post=fake.post, sleep=fake.sleep)
    assert (result.ok, result.tries, fake.calls) == (False, 0, [])
    assert result.error.startswith("not sent: ")


def test_a_result_keeps_as_json():
    result = W.send(outgoing(), post=Fake(200).post)
    kept = json.loads(json.dumps(result.as_dict()))
    assert kept["ok"] and kept["status"] == 200 and datetime.fromisoformat(kept["at"]).tzinfo


def test_the_async_sender_follows_the_same_schedule():
    fake = Fake(500, 200)
    slept = []

    async def post(url, raw, headers, timeout):
        return fake.post(url, raw, headers, timeout)

    async def sleep(seconds):
        slept.append(seconds)

    result = asyncio.run(W.send_async(outgoing(), post=post, sleep=sleep))
    assert (result.ok, result.tries, slept) == (True, 2, [2.0])
    refused = asyncio.run(W.send_async(W.prepare("ftp://x", "e", {}, prefix="X-A"), post=post, sleep=sleep))
    assert refused.tries == 0


# ---- a real receiver on this machine ------------------------------------------------------------


class Receiver(BaseHTTPRequestHandler):
    seen: list = []
    status = 200

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        Receiver.seen.append((self.path, dict(self.headers), raw))
        self.send_response(Receiver.status)
        if Receiver.status == 302:
            self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    Receiver.seen, Receiver.status = [], 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def check_received(secret="s3cret"):
    path, headers, raw = Receiver.seen[-1]
    assert path == "/hook"
    assert headers["X-Ostraka-Event"] == "incident.created"
    assert W.verify(secret, raw, headers["X-Ostraka-Signature"])
    assert W.parse(raw).data == {"ref": "OST-2026-001"}


def test_the_standard_library_sender_delivers_signed(receiver):
    result = W.deliver(
        f"{receiver}/hook", "incident.created", {"ref": "OST-2026-001"}, prefix="X-Ostraka", secret="s3cret"
    )
    assert result.ok and result.tries == 1
    check_received()


def test_the_standard_library_sender_doesnt_follow_a_redirect(receiver):
    Receiver.status = 302
    result = W.deliver(f"{receiver}/hook", "incident.created", {}, prefix="X-Ostraka", tries=1)
    assert result.error == "HTTP 302" and len(Receiver.seen) == 1


def test_the_httpx_sender_delivers_signed(receiver):
    pytest.importorskip("httpx")
    result = asyncio.run(
        W.deliver_async(
            f"{receiver}/hook",
            "incident.created",
            {"ref": "OST-2026-001"},
            prefix="X-Ostraka",
            secret="s3cret",
        )
    )
    assert result.ok
    check_received()
    Receiver.status = 302
    assert (
        asyncio.run(W.deliver_async(f"{receiver}/hook", "e", {}, prefix="X-Ostraka", tries=1)).error
        == "HTTP 302"
    )
