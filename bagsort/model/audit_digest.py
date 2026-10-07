"""Deterministic digest material for audit entries."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol


class AuditDigestEntry(Protocol):
    sequence: int
    kind: str
    subject: str
    detail: dict[str, Any]
    prev_digest: str


def digest_of(entry: AuditDigestEntry) -> str:
    material = json.dumps(
        [
            entry.sequence,
            entry.kind,
            entry.subject,
            entry.detail,
            entry.prev_digest,
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
