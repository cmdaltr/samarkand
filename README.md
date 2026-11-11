# samarkand

The wire formats and pure logic that Ostraka, Shikari and Rowanholt each carry their own copy of,
in one package: the licence line, signed webhooks, STIX 2.1, TAXII 2.1, MISP events and ATT&CK
Navigator layers. Storage, routes, UI and product rules stay in each product.

Being built; the modules land one commit at a time.

## Test vectors

`tests/vectors/` is the point of the package. Every vector is either made by
`tests/vectors/make_vectors.py` (licences signed with the throwaway seeds in
`tests/vectors/licence/THROWAWAY-TEST-SEED.key`, which no product trusts) or captured from a
product's own code over its own test fixtures. A vector never changes to suit the code: if the
package disagrees with a vector, the package is wrong, or the change is a wire-format change and
goes in `docs/DIFFERENCES.md` first.
