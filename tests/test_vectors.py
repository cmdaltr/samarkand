"""The vectors themselves: reproducible, and signed with a key no product trusts."""

import json
import runpy
from pathlib import Path

VECTORS = Path(__file__).parent / "vectors"
# The public halves the products ship today (not secret). The test key must never be one of them.
PRODUCT_KEYS = {
    "cf9e0496426f783c79180af19dd77d40d2b4ea7d7104191784c48b8d1a40cb1f",  # ostraka
    "e499f52ec803749de5d97429a632e140d98f81b8b528f61540dac3c8b3ecb282",  # shikari
    "4a048df1b8382979b9fad6c665efd29c21df4528c65df35ccd62fa0ae2f47f6d",  # rowanholt
}


def test_the_generated_vectors_are_what_the_script_makes(tmp_path, monkeypatch):
    made = runpy.run_path(str(VECTORS / "make_vectors.py"))
    assert json.loads((VECTORS / "licence" / "vectors.json").read_text()) == json.loads(
        json.dumps(made["licence_vectors"]())
    )
    assert json.loads((VECTORS / "webhooks" / "vectors.json").read_text()) == json.loads(
        json.dumps(made["webhook_vectors"]())
    )


def test_the_test_keys_are_no_products_keys():
    data = json.loads((VECTORS / "licence" / "vectors.json").read_text())
    assert {data["test_public_key"], data["other_public_key"]}.isdisjoint(PRODUCT_KEYS)


def test_the_seed_file_says_what_it_is():
    text = (VECTORS / "licence" / "THROWAWAY-TEST-SEED.key").read_text()
    assert text.startswith("# THROWAWAY TEST KEYS.")
    assert "No product trusts them" in text
