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

## STIX

Reading follows Rowanholt (each value with its own linked groups and techniques); building follows
Ostraka (hand-written JSON, stable ids, TLP 2.0 markings). `tests/test_stix.py` turns samarkand's
output into Rowanholt's ten-column rows and Shikari's extraction shape (`tests/adapters.py`) and
compares them with what each product's own parser gives for every fixture: Rowanholt's rows and
validity are identical for all five fixtures, and Shikari's extraction is identical but for the
escaped values below. Ostraka's cyber observables, patterns, TLP markings, identity,
attack-patterns, indicators and relationships rebuild byte for byte.

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| Escapes in pattern strings (`'it\'s.exe'`, `'HKLM\\Run'`) | Writes them (`exports/stix.py` `_quote`) | Not understood: `'([^']*)'` (`parsers/stix_import.py:20`) stops at an escaped quote and leaves `\\` doubled | Undone (`threat_intel/stix.py:29`, then `\'` and `\\` replaced) | As Rowanholt | Shikari: `it\'s.exe` reads as `it's.exe` rather than `it\`, and `C:\\Users` as `C:\Users` (Ostraka's own bundles carry such paths) |
| Objects without an `id` | Never writes one | Read (its tests' bundles have none) | Skipped: `by_id` keeps only objects with ids (`threat_intel/stix.py:127`) | Read, with `object_id` "" so a product can skip them, as `tests/adapters.py` does for Rowanholt | None, if Rowanholt's adapter skips them as now. Without that, Rowanholt would gain rows from id-less objects |
| Two objects with one id (a newer version) | Never writes one | Both read | The last read, in the first's place (dict order) | As Rowanholt | Shikari: an IOC that only the older version had is no longer read |
| Which techniques | Each indicator names its own through `indicates` | Every attack-pattern in the bundle, plus T-numbers in indicator names (`stix_import.py:120`) | Each value's own, through `indicates`, `related-to` or `uses`; else a T-number in its name | Both: `Parsed.techniques` (every attack-pattern) and `Indicator.techniques` (linked) and `named_techniques` | None; each product picks the one it uses today |
| `confidence` | Writes 15 or 85 | Not read | 0 to 100, but `True` counts as 1 (`threat_intel/stix.py:116`) | 0 to 100, booleans refused | Rowanholt: `"confidence": true` is no confidence, not 1 |
| Timestamps | Writes `YYYY-MM-DDTHH:MM:SS.mmmZ` | Not read | `datetime.fromisoformat` after replacing Z (`threat_intel/validity.py:46`), which on Python 3.10 refuses fractions that aren't 3 or 6 digits | `parse_time`, any number of fractional digits, the same on 3.10 to 3.12; aware UTC (Rowanholt's adapter drops the zone, as it stores naive UTC) | Rowanholt: `.12Z` or nanosecond times read on 3.10 too |
| Export | Hand-written; deterministic ids; TLP 2.0 marking on every object; `identity_class` organization | `stix2` library (`parsers/stix_export.py:107`); random ids; no markings; `identity_class` system (`:57`); one indicator ORing up to five IOCs per kind, IPs always `ipv4-addr`, hashes always `SHA-256` (`:20`, `:43`); a custom `x-shikari-detection` per detection | No export | Ostraka's object builders (`identity_object`, `attack_pattern_object`, `indicator_object`, `relationship_object`, `cyber_observables`, `tlp_marking`) and a neutral `bundle()` (one indicator per value, its real observable type, `indicates` relationships, a report) | Shikari: drops the `stix2` dependency; its bundles gain markings, stable ids, one indicator per IOC and correct IPv6 and hash types. `x-shikari-detection` objects stay Shikari's own, added to the objects list |
| A process's command line | An SCO with an id under Ostraka's namespace | `process:command_line` pattern | Read | The pattern always; the SCO only when the caller passes its namespace (process has no ID contributing properties, so the spec gives no id) | None for Ostraka, which passes its namespace |

## TAXII

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| Transport | No TAXII client | requests (`parsers/taxii_client.py:35`) | urllib (`threat_intel/stix.py:186`) | urllib, the request URLs Rowanholt's makes (`objects/?limit=…&added_after=…&next=…`) | Shikari no longer needs requests here |
| Redirects | | Followed, with the Basic auth header | Followed (urllib's default) | Not followed: credentials go only to the URL given | A server that redirects (http to https, say) needs its final URL configured |
| Errors | | `requests.HTTPError` from `raise_for_status` (`:36`) | `urllib.error.HTTPError` | `TaxiiProblem`, with a message for the admin (credentials refused, HTTP status, not JSON, unreachable) | Each product catches `TaxiiProblem` |
| Collection URL for `collection_info` | | Without its trailing slash (`:49`) | No `collection_info` | With it, as TAXII 2.1 writes collection URLs | Servers that are strict about the slash answer |
| User-Agent | | `Shikari (TAXII 2.1 client)` | `Rowanholt (TAXII 2.1 client)` (`threat_intel/stix.py:176`) | `TAXII 2.1 client`; `user_agent=` sets the product's | Pass the old string to keep it |
| TLS verification | | requests' default (on) | On | On; `verify=False` for one request | None |

## MISP

Reading follows Shikari's importer; building follows the event shape Shikari's exporter and
Ostraka's share. `tests/test_misp.py` turns samarkand's reading into Shikari's extraction shape for
all four fixtures (Shikari's own, Shikari's exported run, Ostraka's exported event and an edge-case
event) and gets exactly what `parse_misp_event` gives; Ostraka's exported event rebuilds byte for
byte; Shikari's exported run rebuilds with the same content and two keys in another order.

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| Key order in an event | `uuid, info, date, threat_level_id, analysis, distribution, published, timestamp` (`exports/misp.py:178`) | `info, date, analysis, threat_level_id, distribution` (`parsers/misp_export.py:91`) | No MISP | As Ostraka; optional keys left out when not given | Shikari: `threat_level_id` and `analysis` swap places. JSON key order means nothing to MISP |
| Event uuid | From the incident (UUIDv5), so a second push updates | None: MISP makes one, and every export is a new event | | Given by the caller, or left out | None; Shikari can start passing one to make pushes update |
| Category of a file name | Artifacts dropped (`exports/misp.py:53`) | Payload delivery (`parsers/misp_export.py:23`) | | `ATTRIBUTE_TYPES` is Ostraka's table (Artifacts dropped); `Attribute` takes any category | None if Shikari keeps building its attributes with its own categories, as the test's `shikari_run` does |
| SHA-512 | No such kind | `hash_type` by length, 128 gives sha512 | | Both: `Kind.FILE_HASH_SHA512` and `hash_type` | None |
| TLP | A `tlp:` tag first (`exports/misp.py:155`) | No TLP tag | | `tlp=` adds `tlp:<level>` first; `ParsedEvent.tlp` reads it | Shikari gains a TLP tag only if it passes one |
| Threat actor | None | A `threat-actor` galaxy and tag | | `threat_actor=`, Shikari's shape | None |
| Composite attributes | Never writes one | Split only when both type and value contain `|` (`parsers/misp_import.py:51`) | | The same; both halves in `ParsedAttribute.parts` with their kinds | None |
| Empty values | | Skipped | | Skipped | None |
| Push | Async httpx: GET `/events/view/<uuid>`, then `/events/edit/<uuid>` or `/events/add` (`exports/misp.py:230`) | Pulls only (`/events/restSearch`) | | Ostraka's add-or-update, sync (stdlib) and async (httpx); an event without a uuid is always added; `events_of` reads a restSearch answer as Shikari does | Ostraka catches `samarkand.misp.MispProblem` instead of its own; its User-Agent becomes `samarkand-misp/1` unless it passes `ostraka-misp/1` |

## Navigator

`build_layer` is Rowanholt's (`post/mitre/layers.py:45`). Rowanholt's three captured layers and
Ostraka's two (confirmed only, and with leads) rebuild byte for byte.

| What | Ostraka | Shikari | Rowanholt | samarkand | Switching changes |
|---|---|---|---|---|---|
| ATT&CK version | The bundled data's major (`exports/navigator.py` `attack_major`) | Hard-coded `"17"` by default (`assessments/export.py:36`) | The pinned release's major (`attack_lookup.version()`) | `attack_version=` is required and the layer names its major; `release_of` reads it from ATT&CK's STIX data | Shikari: its assessment layer names the ATT&CK version of the bundle it loads, not 17 |
| Navigator version | 5.3.2 | 4.9.0 (`assessments/export.py:53`) | 5.3.2 | 5.3.2; `navigator_version=` overrides | Shikari's layers say 5.3.2 |
| Platforms | A hard-coded copy of Rowanholt's list (`exports/navigator.py:36`): Ostraka's bundled ATT&CK data has none | No `filters` | Every platform the domain's techniques name | Passed in; `release_of` gives each domain's from the data, revoked and deprecated techniques left out | Ostraka can read them from data instead of keeping a copy; Shikari's layers gain `filters`, so cloud-only techniques aren't hidden |
| Links | On every technique and at layer level, `[]` when none (`:115`, `:127`) | None | None | Written only when given (`Mark.links`, `links=`) | None for either: Ostraka passes them, Rowanholt doesn't |
| Scores | None | `score` per technique with its own gradient (1 to 4) | None | `Mark.score` and `gradient=`, written only when given | Shikari's layers also gain `layout`, `sorting`, `filters`, `metadata` and the other keys Rowanholt's carry |
| Layer-level `metadata` | TLP, incident, source | None | `[]` | `metadata=`, `[]` by default | None |
