# samarkand

The wire formats and pure logic that Ostraka, Shikari and Rowanholt each used to carry their own copy
of, in one package: the licence line, signed webhooks, STIX 2.1, TAXII 2.1, MISP events and ATT&CK
Navigator layers.

The package knows no product. A product passes in what is its own: its id (`ostraka`), its public
keys, its free seat number, its header prefix (`X-Ostraka`), its event names, its STIX namespace and
its data, already masked by its own rules.

## What's in, and what isn't

| Module | Contains |
|---|---|
| `samarkand.licence` | The line `<product>-licence-1.<payload>.<signature>`, checked offline against the product's Ed25519 public keys (a tuple, for rotation); validity, 30 days' grace then Free; editions and features (`report-branding`, `brand-library`, `automation`, `managed-service`, extras and `*`); refusals with a message and a code |
| `samarkand.webhooks` | The `{"event", "sent_at", "data"}` envelope, `sign` and a constant-time `verify`, header names from a prefix, the URL rules, the retry schedule, and delivery through the standard library or httpx |
| `samarkand.stix` | Reading a bundle into neutral indicators, techniques, groups and reports; building objects and bundles with stable ids and TLP 2.0 markings. Hand-written JSON, no `stix2` |
| `samarkand.taxii` | A TAXII 2.1 client: a collection's objects, following pagination, with optional Basic auth |
| `samarkand.misp` | Reading and building MISP events, and pushing one (add, or update by uuid) |
| `samarkand.navigator` | Navigator layers (format 4.5), with the ATT&CK version taken from the product's data |

Out, and staying in each product: where a licence, a webhook or a delivery record is stored; routes
and UI; seat counting; accepting the commercial terms; which events exist and what their data says;
masking what leaves the product; which indicators count as confirmed; checking a feature at the point
of use. There is no signing code for licences: issuing stays with each product's admin script and
the licensor's private key.

## Installing

```bash
pip install samarkand            # cryptography is the only dependency
pip install "samarkand[async]"   # adds httpx, for the async webhook sender and MISP push
```

Python 3.10 or later.

## Using each module

### Licence

```python
from samarkand import licence

RULES = licence.Rules("ostraka", PUBLIC_KEYS, free_seats=4, name="Ostraka")

lic = RULES.parse(line)  # raises licence.LicenceProblem(message, code)
licence.check_installable(lic)  # refuses one already past its grace
standing = RULES.current(stored_line)  # a line that no longer verifies counts as none
if standing.has(licence.AUTOMATION):
    ...
```

An issuer (the product's `scripts/admin/` signer, never a server) signs `licence.head_of(lic)` with
the product's private key and joins the line with `licence.line_of(head, signature)`.

### Webhooks

```python
from samarkand import webhooks

problem = webhooks.url_problem(url) or webhooks.events_problem(events, EVENTS)

result = webhooks.deliver(url, "incident.created", masked_data, prefix="X-Ostraka", secret=secret)
result = await webhooks.deliver_async(url, "incident.created", masked_data, prefix="X-Ostraka", secret=secret)
keep(result.as_dict())  # the product keeps the last webhooks.KEEP_DELIVERIES

# receiving
names = webhooks.headers_for("X-Shikari")
if webhooks.verify(secret, raw_body, request.headers.get(names.signature)):
    delivery = webhooks.parse(raw_body)
```

### STIX and TAXII

```python
from samarkand import stix, taxii

parsed = stix.parse(bundle)              # or taxii.fetch_bundle(collection_url, username=…, password=…)
for item in parsed.indicators:
    item.value, item.kind, item.stix_type, item.stix_path, item.groups, item.techniques

bundle = stix.bundle(stix.Export(namespace=MY_NAMESPACE, key=case_id, producer="Northwind Ltd",
                                 tlp="amber", created=declared, name=title, indicators=…, techniques=…), now)
```

A product with more to say than `bundle()` covers (Ostraka's incidents, notes and sightings) builds
its own objects with `identity_object`, `attack_pattern_object`, `indicator_object`,
`relationship_object`, `cyber_observables`, `tlp_marking`, `common` and `object_id`.

### MISP

```python
from samarkand import misp

parsed = misp.parse(event_json)
event = misp.event(info=…, date=…, attributes=[misp.attribute(kind, value, to_ids=True, comment=…)],
                   techniques=[("T1059.001", "PowerShell")], tlp="amber", uuid=stable_uuid)
pushed = misp.push(base_url, api_key, event)        # or await misp.push_async(...)
```

### Navigator

```python
from samarkand import navigator

release = navigator.release_of(enterprise_attack_bundle)
layer = navigator.build_layer(
    f"{case} (confirmed)",
    navigator.ENTERPRISE,
    {"T1059.001": navigator.Mark(navigator.CONFIRMED_COLOUR, "#3 PowerShell cradle")},
    attack_version=release.version,
    platforms=release.platforms[navigator.ENTERPRISE],
    show_ids=True,
)
```

## Adopting it in a product

`tests/adapters.py` turns samarkand's neutral output into Rowanholt's ten-column rows and Shikari's
extraction shapes, and the tests prove those come out as each product's own code makes them today.
A product switching over starts from its adapter. `docs/DIFFERENCES.md` lists every place the three
products disagreed, which way samarkand went, and what switching changes for each.

## Test vectors

`tests/vectors/` is the point of the package, and it doesn't change to suit the code. If the package
disagrees with a vector, the package is wrong, or the change is a wire-format change: then it goes in
`docs/DIFFERENCES.md` first, with what it changes for each product, and the vector changes with it.

- `licence/`: licence lines made by `tests/vectors/make_vectors.py`, signed with the throwaway seeds
  in `THROWAWAY-TEST-SEED.key`. No product trusts them and none ever may: `tests/test_vectors.py`
  checks they aren't any product's key. The script doesn't import samarkand, so the package is tested
  against lines it didn't make. A product checks its own parser by trusting `test_public_key` in
  place of its `PUBLIC_KEYS` and running the same vectors.
- `webhooks/`: bodies as the bytes sent, each with its signature, and every URL any product's tests
  allow or refuse.
- `stix/`, `misp/` and `navigator/`: fixtures from the products' own tests, and what each product's
  code produces from them today (`expected-*.json`, `ostraka-*.json`, `rowanholt-layers.json`),
  captured on 11 November 2026.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/pytest
```

CI (`.github/workflows/test.yml`) runs the same on Python 3.10, 3.11 and 3.12.

## Licence

Elastic License 2.0 (`LICENSE`); the licensor is Ben Smith (cmdaltr).
