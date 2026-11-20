# Changelog

Products pin an exact version. Every version keeps the wire formats and the test vectors of the one
before unless its entry says otherwise.

## 0.2.3 (20 November 2026)

Two fixes from running Shikari's query clients. Wire formats are as they were.

- `samarkand.netguard` tries each address a name resolves to, in the resolver's order, until one
  answers; 0.2.2 tried only the first. `localhost` on macOS resolves to ::1 first, so a SIEM listening
  only on 127.0.0.1 was unreachable. Every address is still checked before any is tried: one link-local
  address refuses the name. `netguard.addresses` gives the list; `netguard.resolve` is its first.
- `siem.Defender` and `siem.SecOps` keep their OAuth token and reuse it until five minutes before it
  expires (`expires_in`, else an hour), instead of signing in for every query. A kept token that's
  refused with 401 is dropped and the request sent once more with a new one.

## 0.2.2 (19 November 2026)

The second fix from Ostraka's November security assessment. Wire formats are as they were; a request
that would reach a link-local address now fails instead.

- `samarkand.netguard`: a host is resolved once, refused (`netguard.Refused`, an `OSError`) if it is or
  resolves to a link-local address, and connected to at the address that was checked, with the name
  kept for the Host header, SNI and the certificate check. A name that resolves to 169.254.169.254, or
  to a public address when checked and a link-local one a moment later, no longer gets through.
- Every request samarkand sends (webhooks, MISP, TAXII, the SIEM clients) connects through it, sync
  and async. A refused async request raises `httpx.ConnectError`, as an unreachable one does.
- `netguard.AsyncTransport` does the same for a product's own httpx clients: pass it as `transport=`
  (with `verify` on the transport, since a client given one ignores its own).

## 0.2.1 (19 November 2026)

A fix from Ostraka's November security assessment. Everything 0.2.0 callers do behaves as it did,
except that the URLs below are now refused.

- `webhooks.url_problem` reads an IPv4 address as the resolver does, so a link-local address
  written as one number, in hex or octal, or in the short form (`https://2852039166/`,
  `https://0xa9fea9fe/`, `https://0251.0376.0251.0376/`, `https://169.254.43518/`, all
  169.254.169.254) is refused like the dotted form. The send-time check uses the same rule, so a URL
  saved before is refused when it's next sent. The cases are in the webhook vectors.

## 0.2.0 (18 November 2026)

Adds `samarkand.siem`. Everything 0.1.1 callers do behaves as it did.

- `siem.Splunk`, `siem.Elastic` and `siem.Defender`: Shikari's query clients (`shikari/query/`),
  moved here so Ostraka can run the same queries. Splunk runs SPL as a search job (token, or a
  username and password with a session key renewed once when it expires), waits for it and pages its
  results; Elasticsearch runs ES|QL through `/_query`, paging a query that returns events by
  `@timestamp` and `_id`, and now filters on `@timestamp` between `start` and `end` when given;
  Defender XDR runs KQL through Microsoft Graph's `runHuntingQuery` as an app registration with
  ThreatHunting.Read.All. What each does is as it was in Shikari, except that a failure raises
  `siem.SiemProblem` (an `OSError`) where Shikari returned `{"status": "error"}`.
- `siem.SecOps`: Google SecOps UDM search through the Chronicle API (`…/instances/<customer
  id>:udmSearch`), as a service account whose key signs its own token request (RS256, with
  `cryptography`; no google-auth). New, built from Google's documentation, and not yet run against a
  live tenant. Events come back flattened to dotted columns (`principal.hostname`).
- Each client's work is a generator of requests (`siem.Call`) and pauses (`siem.Wait`), sent by
  `siem.run` (standard library) or `siem.run_async` (httpx, `samarkand[async]`), so sync and async
  can't drift apart. 429 and 503 are retried three times, honouring Retry-After.

## 0.1.1 (12 November 2026)

Additions the products' switch-overs asked for. Everything 0.1.0 callers do behaves as it did.

- `stix.bundle(export, now, *, extra_objects=())`: a product's own objects (Shikari's intrusion-set
  and `x-shikari-detection` objects) go in after the standard ones and in the report's `object_refs`
  (identities and marking definitions excepted, as for the standard ones), with the report still
  last. An extra object without a type and an id, or with an id already in the bundle, raises
  ValueError. The order of a bundle's objects is now documented.
- `stix.Export.identity_ref` and `stix.Export.attack_pattern_ref(technique_id)`: the ids `bundle()`
  gives the producer's identity and a technique's attack-pattern, so a product's own objects can
  refer to them before the bundle is built.
- `stix.parse(data, *, skip_without_id=False)`: with `True`, objects without a (non-empty string) id
  are left out before anything is read, as Rowanholt filters them: an id-less relationship links
  nothing, and id-less groups, reports and indicators aren't counted.
- `stix.Digest`, `stix.DIGESTS` and `stix.digest_of(value)`: one table naming a hex digest by its
  length (MD5, SHA-1, SHA-256, SHA-512) as its Kind, STIX hash key and MISP type. `misp.hash_type`
  reads it; its answers are unchanged.
- `taxii.TaxiiProblem` is an `OSError` (it was an `Exception`), so `except OSError` catches it. It is
  raised with its message alone, so `str()` and `args` are as before and `errno` is None. Nothing in
  samarkand catches `OSError` around code that raises it.
- `licence.Rules.licence(licence_id, licensee, edition, seats, issued, expires, **optional)`: a
  Licence with the product's id in `product` unless given. `Rules.parse` already returns a licence
  carrying its product (every payload names it, and one that doesn't is still refused as
  `unreadable`); this is for issuers and tests, so a product needs no Licence subclass.
- `navigator.PLATFORMS` and `navigator.PLATFORMS_RELEASE`: every platform each domain's techniques
  name in ATT&CK 20.1 (Enterprise and Mobile), for a product whose ATT&CK data names none. There is
  no fallback ATT&CK version.
- Test vector `stix/shikari-export.json`: Shikari's STIX export of a run, made on 0.1.0 by popping
  the report; `extra_objects` rebuilds it byte for byte.

## 0.1.0 (11 November 2026)

The licence line, signed webhooks, STIX 2.1, TAXII 2.1, MISP events and ATT&CK Navigator layers, as
Ostraka, Shikari and Rowanholt made them, with the test vectors.
