# Where the products disagree

Where Ostraka, Shikari and Rowanholt disagree on a wire detail, samarkand picks one. Each entry says
where each product stands today (file and line, at the commits read on 11 November 2026: Ostraka
`integration` 65536db, Shikari 64135d73, Rowanholt 69f1c10), what samarkand does, and what switching
changes for each product.

## Licence

The three products sign and read the line identically: every vector in
`tests/vectors/licence/vectors.json` was checked against each product's own `parse` and `sign` (with
the test key trusted in place of `PUBLIC_KEYS`), and all three give the same licence, the same line
byte for byte and the same messages with their own name. All three also refuse a lapsed licence at
install (Ostraka `backend/ostraka/api/installation.py:96`, Shikari `shikari/licensing.py:266`
`check`, Rowanholt `src/web/backend/licence_routes.py:110` and `manage_licence.py:54`), which is
`check_installable` here. What differs is behaviour at the edges, not the format:

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| A signed payload that is valid JSON but not an object (a list, say) | `licence.py:198` catches `KeyError, ValueError, TypeError`; `payload.get` on a list raises `AttributeError`, which escapes as a 500 | `licensing.py:216`, the same | `licence.py:194`, the same | `UNREADABLE` ("from a newer version"), like any other unreadable payload | Only a licensor-signed oddity reaches this, so nothing a customer could see today |
| `parse(None)` | `licence.py:165` `text.strip()` raises `AttributeError` | `licensing.py:183` `(text or "")`: "isn't a Shikari licence" | `licence.py:161`, as Ostraka | As Shikari | Ostraka and Rowanholt refuse a missing line cleanly instead of raising |
| Why a licence was refused | The message only | The message only | The message only | The same message, plus `LicenceProblem.code` (`not-a-licence`, `other-product`, `damaged`, `bad-signature`, `unreadable`, `grants-nothing`, `lapsed`) | Nothing; the code is there for an API that wants to say more than the text |
| Free seats and the product's name | Module constants (`FREE_SEATS = 4`, "Ostraka") | `FREE_SEATS = 2`, "Shikari" | `FREE_SEATS = 4`, "Rowanholt" | Passed in (`standing(..., free_seats=)`, `Rules(product, keys, free_seats, name)`) | Each product binds a `Rules` once with its own |
| Signing | `licence.sign` (`licence.py:152`), used by `scripts/admin/sign_licence.py` | `licensing.py:171` | `licence.py:148` | No signing code. `head_of` gives the text to sign and `line_of` assembles the line; the licensing repo's `scripts/licences.py` delegates issuing to each product's `scripts/admin/issue-licence.sh`, so it needs no signer from here | Each product's `sign` becomes `line_of(head_of(lic), key.sign(head_of(lic).encode()))` in its admin script |

## Webhooks

The envelope, the signature and the retry schedule are the same in all three (three tries, waits of
2 s and 4 s, stop on a 4xx other than 429, the last 20 kept). `tests/vectors/webhooks/vectors.json`
was checked against Ostraka's `body_of`, `sign` and `integrations/signing.signature_ok`: the bodies
and signatures are Ostraka's byte for byte.

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| `sent_at` | ISO 8601 in UTC, `utcnow().isoformat()` (`webhooks.py:207` `body_of`) | Epoch seconds as a float, `time.time()` (`webhooks.py:142`) | Epoch seconds (`webhooks.py:192`) | ISO 8601 in UTC (`2026-11-11T12:00:00+00:00`); `Delivery.sent_at_time` reads either | Shikari and Rowanholt: a receiver that reads `sent_at` as a number must read a string. The signature is over the raw body, so verification is unaffected. Ostraka: nothing |
| User-Agent | `ostraka-webhook/1` (`webhooks.py:220`) | `Shikari-Webhook/1` (`webhooks.py:143`) | `Rowanholt-Webhook/1` (`webhooks.py:193`) | `<Name>-Webhook/1` from the prefix (`Ostraka-Webhook/1`); `user_agent=` overrides | Ostraka's changes case, unless it passes its own |
| Header names | Hard-coded `X-Ostraka-…`; `integrations/signing.headers_for(product)` capitalises a product id | Hard-coded `X-Shikari-…` | Hard-coded `X-Rowanholt-…` | `headers_for(prefix)` from the prefix the product passes (`X-Ostraka`) | None on the wire |
| http:// | Allowed to localhost, `*.localhost`, loopback and RFC 1918 (`webhooks.py:69` `url_problem`) | Any host (`webhooks.py:80` `validate`: http or https, anything) | As Ostraka, plus `localhost.localdomain` (`webhooks.py:96` `_private_host`) | As Ostraka; `localhost.localdomain` refused (the strictest set: only Rowanholt allowed it) | Shikari: a plain-http webhook to a public host or a LAN name now fails `url_problem` and is not sent. Rowanholt: `http://localhost.localdomain` likewise |
| Link-local addresses (169.254/16, fe80::/10) | Refused whatever the scheme (`webhooks.py:80`) | Allowed | Refused for http only (not private), allowed over https | Refused whatever the scheme, IPv4-mapped IPv6 (`::ffff:169.254.169.254`) included, which `ipaddress` before the 2024 security releases doesn't count as link-local by itself | Rowanholt and Shikari: an https webhook to a link-local address (cloud metadata) is refused |
| Credentials in the URL | Allowed | Allowed | Refused (`webhooks.py:115`) | Refused: "Put credentials in the webhook's secret, not the URL." | Ostraka and Shikari: a URL with `user:pass@` is refused |
| Checking the URL when sending | No (checked when saved) | No | No | `send` refuses a URL `url_problem` refuses (tries 0, `not sent: …`) | A webhook saved under the old rules, or edited by hand in Shikari's or Rowanholt's JSON store, stops sending until it's fixed |
| Redirects | Not followed (`notify/channels.py` `fetch`, `follow_redirects=False`) | Followed (`requests.post` default, `webhooks.py:150`) | Not followed (`webhooks.py:187`) | Not followed, sync and async; a 3xx is a final answer (`HTTP 302`) | Shikari: a receiver that redirects now records a failure |
| Timeout | 15 s (`notify/channels.py` `fetch`) | 10 s (`webhooks.py:150`) | 10 s (`TIMEOUT`) | 10 s (`TIMEOUT`), `timeout=` overrides | Ostraka waits 10 s, not 15, unless it passes 15 |
| Transport | httpx, async | requests, sync, on a thread | httpx, sync, on a thread | Standard library (sync) or httpx (async, `samarkand[async]`) | Shikari no longer needs requests for webhooks |
| Error text | `str(exc)[:200]` or the exception's name | `str(e)[:200]` (empty for some errors) | `str(exc)[:200]` | As Ostraka | Shikari: an error with no message records its type rather than "" |
| `events_problem` message | "Choose events from a, b." | "Choose events from a, b" | "Choose events from a, b" | As Ostraka, with the product's events passed in | Punctuation only |
