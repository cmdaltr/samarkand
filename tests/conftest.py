"""Shared helpers: the vectors, and the throwaway test keys."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VECTORS = Path(__file__).parent / "vectors"


def vector(path: str) -> Any:
    """A vector file, parsed."""
    return json.loads((VECTORS / path).read_text())


@pytest.fixture(scope="session")
def test_keys() -> dict[str, Ed25519PrivateKey]:
    """The throwaway seeds no product trusts: {"test": …, "other": …}."""
    keys = {}
    for line in (VECTORS / "licence" / "THROWAWAY-TEST-SEED.key").read_text().splitlines():
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            keys[name] = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))
    return keys
