# Changelog

Products pin an exact version. Every version keeps the wire formats and the test vectors of the one
before unless its entry says otherwise.

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
