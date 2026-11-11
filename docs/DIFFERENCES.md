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
