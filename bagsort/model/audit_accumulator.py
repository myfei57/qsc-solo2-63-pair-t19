"""Append-only Merkle mountain range over audit entry digests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

Peak = tuple[int, str]


def _leaf(index: int, digest: str) -> str:
    material = json.dumps(
        ["audit-leaf", index, digest],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _node(height: int, left: str, right: str) -> str:
    material = json.dumps(
        ["audit-node", height, left, right],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _root(count: int, peaks: list[Peak]) -> str:
    folded = ""
    for height, digest in reversed(peaks):
        folded = digest if not folded else _node(height, digest, folded)
    material = json.dumps(
        ["audit-root", count, folded],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditAccumulator:
    count: int
    peaks: tuple[Peak, ...]

    @property
    def root(self) -> str:
        return _root(self.count, list(self.peaks))

    def as_list(self) -> list[list[Any]]:
        return [[height, digest] for height, digest in self.peaks]

    @classmethod
    def from_list(cls, raw: list[list[Any]] | tuple[tuple[int, str], ...] = ()) -> "AuditAccumulator":
        peaks = tuple((int(height), str(digest)) for height, digest in raw)
        return cls(count=sum(2**height for height, _digest in peaks), peaks=peaks)

    def append(self, digest: str) -> "AuditAccumulator":
        peak_height = 0
        peak_digest = _leaf(self.count, digest)
        peaks = {height: value for height, value in self.peaks}
        while peak_height in peaks:
            left = peaks.pop(peak_height)
            peak_digest = _node(peak_height, left, peak_digest)
            peak_height += 1
        peaks[peak_height] = peak_digest
        ordered = tuple((height, peaks[height]) for height in sorted(peaks, reverse=True))
        return AuditAccumulator(count=self.count + 1, peaks=ordered)
