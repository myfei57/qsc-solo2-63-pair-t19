"""Append-only command journal with an explicit commit watermark.

Every mutation the plant performs is expressed as a command. Commands are first
buffered as *pending*; readers never see them. A commit moves the whole buffer
into the committed log and advances the watermark, a rollback drops it. This is
what gives the service "uncommitted records are invisible" and "restart replays
from the watermark" as real properties instead of conventions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

JOURNAL_GENESIS = "0" * 64


def link_digest(previous: str, entry: "JournalEntry") -> str:
    """Hash one journal entry onto the prefix digest before it."""

    material = json.dumps(
        [previous, entry.as_dict()],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class JournalEntry:
    """One committed command."""

    sequence: int
    kind: str
    payload: dict[str, Any]
    at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "payload": self.payload,
            "at": self.at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "JournalEntry":
        payload = raw.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("journal payload must be an object")
        return cls(
            sequence=int(raw.get("sequence", 0)),
            kind=str(raw.get("kind", "")),
            payload=dict(payload),
            at=str(raw.get("at", "")),
        )

    @property
    def tombstone(self) -> bool:
        """A tombstone retires an entity instead of updating it."""

        return self.kind.endswith(".remove")


class Journal:
    """Committed entries plus the buffer of commands not yet committed."""

    def __init__(self) -> None:
        self._committed: list[JournalEntry] = []
        self._pending: list[tuple[str, dict[str, Any], str]] = []
        self._digest = JOURNAL_GENESIS

    @property
    def watermark(self) -> int:
        if not self._committed:
            return 0
        return self._committed[-1].sequence

    @property
    def digest(self) -> str:
        return self._digest

    def committed(self) -> list[JournalEntry]:
        return list(self._committed)

    def since(self, watermark: int) -> list[JournalEntry]:
        """Entries with ``sequence`` strictly greater than ``watermark``."""

        if not self._committed or watermark >= self._committed[-1].sequence:
            return []
        if watermark < self._committed[0].sequence:
            return list(self._committed)
        return [entry for entry in self._committed if entry.sequence > watermark]

    def pending(self) -> list[tuple[str, dict[str, Any], str]]:
        return list(self._pending)

    def has_pending(self) -> bool:
        return bool(self._pending)

    def append(self, kind: str, payload: dict[str, Any], at: str = "") -> None:
        self._pending.append((kind, payload, at))

    def commit(self) -> int:
        """Promote every buffered command; returns the new watermark."""

        sequence = self.watermark
        for kind, payload, at in self._pending:
            sequence += 1
            entry = JournalEntry(sequence=sequence, kind=kind, payload=payload, at=at)
            self._committed.append(entry)
            self._digest = link_digest(self._digest, entry)
        self._pending = []
        return sequence

    def rollback(self) -> int:
        """Discard the buffer; returns how many commands were dropped."""

        dropped = len(self._pending)
        self._pending = []
        return dropped

    def tombstones(self) -> list[JournalEntry]:
        return [entry for entry in self._committed if entry.tombstone]

    def kinds(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self._committed:
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        return dict(sorted(counts.items()))
