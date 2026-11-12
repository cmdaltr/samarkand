# Changelog

Products pin an exact version. Every version keeps the wire formats and the test vectors of the one
before unless its entry says otherwise.

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
