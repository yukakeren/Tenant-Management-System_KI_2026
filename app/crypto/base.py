"""Cipher suite interface. 

A suite only knows how to seal/open ONE chunk. Framing, chunk indexes, the final flag,
associated data and keys are handled by container.py/keys.py.
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Protocol


class IntegrityError(Exception):
    """Ciphertext failed authentication. The message must never say why."""

    def __init__(self) -> None:
        super().__init__("integrity check failed")


class ChunkSealer(Protocol):
    def seal(self, index: int, plaintext: bytes, ad: bytes) -> bytes: ...


class ChunkOpener(Protocol):
    def open(self, index: int, record: bytes, ad: bytes) -> bytes:
        """Return the plaintext, or raise IntegrityError on ANY problem
        (bad tag, record too short, bad padding, wrong order)."""
        ...


class CipherSuite(ABC):
    id: ClassVar[int]  # written into the container header: 1=aes, 2=des, 3=rc4
    name: ClassVar[str]  # "aes" | "des" | "rc4", same as secret_blobs.cipher

    @abstractmethod
    def new_params(self) -> bytes:
        """Fresh random per-file values (nonce prefix / salt), stored in the header."""

    @abstractmethod
    def sealer(self, dek: bytes, params: bytes) -> ChunkSealer:
        """Single use, one per file. Called with index 0, 1, 2, ... in order."""

    @abstractmethod
    def opener(self, dek: bytes, params: bytes) -> ChunkOpener:
        """Single use, one per file. Called with index 0, 1, 2, ... in order."""


REGISTRY: dict[str, CipherSuite] = {}
_BY_ID: dict[int, CipherSuite] = {}


def register(cls: type[CipherSuite]) -> type[CipherSuite]:
    """Class decorator: @register on a CipherSuite subclass adds one instance to the registry."""
    suite = cls()
    if suite.name in REGISTRY or suite.id in _BY_ID:
        raise ValueError(f"cipher suite {suite.name!r} / id {suite.id} registered twice")
    REGISTRY[suite.name] = suite
    _BY_ID[suite.id] = suite
    return cls


def get_suite(name_or_id: str | int) -> CipherSuite:
    suite = _BY_ID.get(name_or_id) if isinstance(name_or_id, int) else REGISTRY.get(name_or_id)
    if suite is None:
        raise KeyError(f"unknown cipher suite {name_or_id!r}")
    return suite
