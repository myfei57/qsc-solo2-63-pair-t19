"""Checkpoint ledger used by incremental audit verification.

A checkpoint says "the audit chain was verified up to ``sequence`` and the
digest there was ``digest``". The ledger lives in its own file next to the
state snapshot, never inside the journal: verification progress must be
resumable without the verifier ever writing to the chain it checks. The
ledger is itself hash linked (each marker commits to the previous one), so a
rewritten checkpoint file is detected on load and truncated to the longest
prefix that still checks out.

Checkpoint spacing: fixed count versus time window
--------------------------------------------------

The two policies trade localisation cost against storage overhead in
opposite directions, so the choice has to be made with the localisation cost
stated plainly:

* ``CountPolicy(every=N)`` (the default) drops a checkpoint every ``N``
  entries. Every segment is at most ``N`` entries, so re-playing the
  previous checkpoint result costs at most ``2N`` digests per run (the
  certified segment plus the open tail) and pinning down a broken link
  costs at most one more segment scan of ``N`` entries — a *bounded*
  localisation price that does not grow with the chain. The cost is
  storage: the ledger holds ``chain_length / N`` markers and grows linearly
  with the chain (each marker is ~150 bytes, small next to the entries
  themselves).
* ``WindowPolicy(seconds=T)`` drops a checkpoint per time window. Storage is
  bounded by elapsed time rather than traffic — quiet periods write almost
  nothing and bursts write nothing extra. The price is localisation: a
  window may swallow an unbounded number of entries, so when a link breaks
  inside a busy window the segment that has to be re-scanned to find the
  exact entry is arbitrarily large. Localisation time becomes unpredictable
  exactly when the plant is busiest.

The default is fixed count because "which segment broke" must be answerable
in bounded time; the ledger growth is the acceptable price. Choose the
window policy only when write volume is flat and ledger size matters more
than worst-case localisation time.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .chain import GENESIS

LEDGER_VERSION = 1


def default_ledger_path(store_path: str) -> str:
    """The checkpoint file that belongs to a given state snapshot."""

    base, _ext = os.path.splitext(store_path)
    return f"{base}.checkpoints.json"


def link_of(prev_link: str, sequence: int, digest: str, entries: int, at: str) -> str:
    """Hash chain link over one marker, committing to every marker before it."""

    material = json.dumps(
        [prev_link, sequence, digest, entries, at],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Checkpoint:
    """One persisted verification marker on the audit chain."""

    sequence: int
    digest: str
    entries: int
    at: str
    link: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "digest": self.digest,
            "entries": self.entries,
            "at": self.at,
            "link": self.link,
        }

    @classmethod
    def build(cls, sequence: int, digest: str, entries: int, at: str, prev_link: str) -> "Checkpoint":
        return cls(
            sequence=sequence,
            digest=digest,
            entries=entries,
            at=at,
            link=link_of(prev_link, sequence, digest, entries, at),
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Checkpoint":
        return cls(
            sequence=int(raw.get("sequence", 0)),
            digest=str(raw.get("digest", "")),
            entries=int(raw.get("entries", 0)),
            at=str(raw.get("at", "")),
            link=str(raw.get("link", "")),
        )


class CheckpointPolicy(Protocol):
    """Decides when a verified position is worth a persisted checkpoint."""

    def should_checkpoint(
        self, entries_since: int, moment: datetime, last_at: datetime | None
    ) -> bool: ...

    def describe(self) -> dict[str, Any]: ...

    def segment_bound(self) -> int | None:
        """Worst-case entries inside one segment, or ``None`` when unbounded."""
        ...


@dataclass(frozen=True)
class CountPolicy:
    """Drop a checkpoint every ``every`` verified entries."""

    every: int = 64

    def __post_init__(self) -> None:
        if self.every < 1:
            raise ValueError("checkpoint interval must be at least one")

    def should_checkpoint(
        self, entries_since: int, moment: datetime, last_at: datetime | None
    ) -> bool:
        return entries_since >= self.every

    def describe(self) -> dict[str, Any]:
        return {"kind": "count", "every": self.every}

    def segment_bound(self) -> int | None:
        return self.every


@dataclass(frozen=True)
class WindowPolicy:
    """Drop a checkpoint once the chain's own timestamps cross ``seconds``.

    The window is measured on entry timestamps, not on the verifier's clock,
    so a catch-up run over a long history still splits it into window-sized
    segments. What it cannot bound is how many entries a busy window holds.
    """

    seconds: float

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError("checkpoint window must be positive")

    def should_checkpoint(
        self, entries_since: int, moment: datetime, last_at: datetime | None
    ) -> bool:
        if entries_since < 1:
            return False
        if last_at is None:
            return True
        return (moment - last_at).total_seconds() >= self.seconds

    def describe(self) -> dict[str, Any]:
        return {"kind": "window", "seconds": self.seconds}

    def segment_bound(self) -> int | None:
        return None


def parse_at(raw: str) -> datetime | None:
    """Parse the service's ISO timestamp, or ``None`` when it is malformed."""

    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


class CheckpointLedger:
    """The persisted verification progress: policy checkpoints plus a head.

    ``checkpoints`` are the policy-spaced markers used to localise a break to
    a segment. ``verified`` is the exact position the last run reached, so a
    chain that grows by less than one segment between runs still resumes
    where it stopped instead of re-scanning the whole open segment.
    """

    def __init__(
        self,
        path: str,
        policy: CheckpointPolicy,
        checkpoints: list[Checkpoint] | None = None,
        verified: Checkpoint | None = None,
        status: str = "fresh",
    ) -> None:
        self.path = path
        self.policy = policy
        self.checkpoints = checkpoints or []
        self.verified = verified
        self.status = status

    # -- persistence -------------------------------------------------------

    @classmethod
    def load(cls, path: str, policy: CheckpointPolicy) -> "CheckpointLedger":
        """Read the ledger file, truncating anything that fails its own chain.

        A missing file is a fresh ledger. An unparsable file is rebuilt from
        scratch. A file whose markers no longer link up keeps only the
        longest valid prefix, so verification resumes from the newest marker
        that is still trustworthy.
        """

        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except FileNotFoundError:
            return cls(path, policy)
        except (ValueError, OSError):
            return cls(path, policy, status="rebuilt")
        try:
            checkpoints = [Checkpoint.from_dict(item) for item in raw.get("checkpoints", [])]
            verified_raw = raw.get("verified")
            verified = Checkpoint.from_dict(verified_raw) if verified_raw else None
        except (TypeError, ValueError, AttributeError):
            return cls(path, policy, status="rebuilt")

        kept: list[Checkpoint] = []
        prev_link = GENESIS
        for marker in checkpoints:
            if marker.link != link_of(prev_link, marker.sequence, marker.digest, marker.entries, marker.at):
                break
            kept.append(marker)
            prev_link = marker.link
        status = "ok" if len(kept) == len(checkpoints) else "truncated"
        if verified is not None:
            if kept and verified.sequence == kept[-1].sequence and verified.link == kept[-1].link:
                pass  # the cursor simply is the newest checkpoint
            else:
                expected = link_of(prev_link, verified.sequence, verified.digest, verified.entries, verified.at)
                if verified.link != expected:
                    verified = None
                    status = "truncated"
        return cls(path, policy, checkpoints=kept, verified=verified, status=status)

    def save(self) -> None:
        """Write the ledger atomically; the chain itself is never touched."""

        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        raw = json.dumps(self.as_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(raw)
        os.replace(temporary, self.path)

    # -- mutation ----------------------------------------------------------

    def _checkpoint_link(self) -> str:
        """Link the next marker anchors to.

        Policy checkpoints chain to policy checkpoints only, and the verified
        cursor anchors to the newest checkpoint, so the file always validates
        as ``checkpoints… + verified`` no matter how many runs rewrote the
        cursor between two checkpoints.
        """

        return self.checkpoints[-1].link if self.checkpoints else GENESIS

    def append(self, sequence: int, digest: str, at: str) -> Checkpoint:
        """Persist a policy checkpoint at a freshly verified position."""

        marker = Checkpoint.build(sequence, digest, sequence, at, self._checkpoint_link())
        self.checkpoints.append(marker)
        self.verified = marker
        return marker

    def mark_verified(self, sequence: int, digest: str, at: str) -> Checkpoint:
        """Remember how far the last run verified, checkpoint or not."""

        if self.checkpoints and self.checkpoints[-1].sequence == sequence:
            self.verified = self.checkpoints[-1]
            return self.verified
        self.verified = Checkpoint.build(sequence, digest, sequence, at, self._checkpoint_link())
        return self.verified

    def truncate_after(self, sequence: int) -> None:
        """Roll the ledger back to ``sequence`` after a replay disagreement."""

        self.checkpoints = [m for m in self.checkpoints if m.sequence <= sequence]
        if self.verified is not None and self.verified.sequence > sequence:
            self.verified = self.checkpoints[-1] if self.checkpoints else None

    def reset(self) -> None:
        """Forget all progress; the next run verifies from the genesis."""

        self.checkpoints = []
        self.verified = None

    # -- queries -----------------------------------------------------------

    def newest_before(self, sequence: int, strict: bool = True) -> Checkpoint | None:
        """The newest checkpoint below (or at) ``sequence``."""

        best: Checkpoint | None = None
        for marker in self.checkpoints:
            if marker.sequence < sequence or (not strict and marker.sequence <= sequence):
                best = marker
            else:
                break
        return best

    def last_checkpoint_at(self) -> datetime | None:
        if not self.checkpoints:
            return None
        return parse_at(self.checkpoints[-1].at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": LEDGER_VERSION,
            "policy": self.policy.describe(),
            "checkpoints": [marker.as_dict() for marker in self.checkpoints],
            "verified": self.verified.as_dict() if self.verified else None,
        }
