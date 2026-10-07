"""Checksummed snapshot envelope used to persist the committed journal."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .journal import JOURNAL_GENESIS, JournalEntry, link_digest

ENVELOPE_VERSION = 1


def canonical(entries: list[JournalEntry]) -> str:
    """Stable JSON rendering used for the integrity digest."""

    payload = [entry.as_dict() for entry in entries]
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_for(entries: list[JournalEntry]) -> str:
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def chain_digest_after(
    entries: list[JournalEntry], watermark: int, previous: str = JOURNAL_GENESIS
) -> str:
    """Fold a journal prefix's entries into an incremental chain digest."""

    digest = previous
    for entry in entries:
        if entry.sequence <= watermark:
            continue
        digest = link_digest(digest, entry)
    return digest


def chain_digest(entries: list[JournalEntry]) -> str:
    return chain_digest_after(entries, 0)


@dataclass(frozen=True)
class Envelope:
    """A snapshot of the committed journal plus enough metadata to verify it."""

    watermark: int
    digest: str
    entries: tuple[JournalEntry, ...]
    version: int = ENVELOPE_VERSION
    chain_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "watermark": self.watermark,
            "digest": self.digest,
            "chain_digest": self.chain_digest or chain_digest(list(self.entries)),
            "entry_count": len(self.entries),
            "entries": [entry.as_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Envelope":
        entries = tuple(JournalEntry.from_dict(item) for item in raw.get("entries", []))
        return cls(
            watermark=int(raw.get("watermark", 0)),
            digest=str(raw.get("digest", "")),
            entries=entries,
            version=int(raw.get("version", ENVELOPE_VERSION)),
            chain_digest=str(raw.get("chain_digest", "")),
        )

    def verify(self) -> bool:
        """True when the digest still matches the entries and the watermark agrees."""

        if digest_for(list(self.entries)) != self.digest:
            return False
        if self.watermark != (self.entries[-1].sequence if self.entries else 0):
            return False
        expected = chain_digest(list(self.entries))
        if self.chain_digest and self.chain_digest != expected:
            return False
        return True


def build(entries: list[JournalEntry]) -> Envelope:
    watermark = entries[-1].sequence if entries else 0
    return Envelope(
        watermark=watermark,
        digest=digest_for(entries),
        entries=tuple(entries),
        chain_digest=chain_digest(entries),
    )
