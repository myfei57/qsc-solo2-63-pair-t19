"""Incremental, checkpointed verification of the audit chain.

Full verification (``AuditChain.verify``) re-hashes every entry from the
genesis on each call, so it slows down as the chain grows and can only
answer "the chain does not add up" without saying where. The incremental
verifier instead persists its progress as checkpoints (see
:mod:`bagsort.audit.checkpoints`) and each run then:

1. resumes from the persisted cursor — the last position the chain agreed
   with, falling back to the newest checkpoint that still matches, and to
   the genesis when nothing matches (for example after a store reset);
2. *replays the previous checkpoint result*: the segment the newest
   checkpoint certifies, plus the open tail up to the cursor, is
   re-verified, so a stored checkpoint is never trusted without re-checking
   the entries it certifies;
3. scans only the entries appended since the cursor, dropping new
   checkpoints as the policy dictates, and persists the ledger.

The work a run performs is bounded by two segments plus the new entries
(one certified segment, one open segment), so verification time does not
degrade as the chain grows. When a link breaks, the report names the exact
entry and the checkpoint-bounded segment around it, and the ledger is
rolled back to the newest trustworthy marker so the next run resumes the
investigation from there.

The verifier never writes to the store: the chain, the journal and any
persisted snapshot are read-only inputs. Only the checkpoint file changes.

Shallow versus deep
-------------------

A shallow run certifies everything from the last checkpoint forward and
relies on the ledger for older segments; a tamper that rewrote an old entry
*and* kept its digest fields consistent is only visible to the rolling
replay one segment back, to the snapshot/console cross-checks, or to a deep
run. ``verify(deep=True)`` re-verifies from the genesis (matching a full
``AuditChain.verify`` one for one) while still refreshing the checkpoints,
which is the scheduled-audit companion to the cheap per-run shallow mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bagsort.clock import Clock
from bagsort.store.store import Store
from .chain import GENESIS, AuditChain, digest_of
from .checkpoints import (
    Checkpoint,
    CheckpointLedger,
    CheckpointPolicy,
    CountPolicy,
    default_ledger_path,
    parse_at,
)

# Why a link no longer checks out.
PREV_DIGEST_MISMATCH = "prev_digest_mismatch"
DIGEST_MISMATCH = "digest_mismatch"
CHECKPOINT_REPLAY_MISMATCH = "checkpoint_replay_mismatch"


@dataclass(frozen=True)
class VerificationReport:
    """The outcome of one incremental verification run."""

    intact: bool
    deep: bool
    from_sequence: int
    to_sequence: int
    entries_checked: int
    replayed: dict[str, int] | None
    checkpoints_written: int
    checkpoints_total: int
    head_sequence: int
    head_digest: str
    watermark: int
    ledger: str
    policy: dict[str, Any]
    localization: dict[str, Any]
    at: str
    failure: dict[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "deep": self.deep,
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "entries_checked": self.entries_checked,
            "replayed": self.replayed,
            "checkpoints_written": self.checkpoints_written,
            "checkpoints_total": self.checkpoints_total,
            "head": {"sequence": self.head_sequence, "digest": self.head_digest},
            "watermark": self.watermark,
            "ledger": self.ledger,
            "policy": self.policy,
            "localization": self.localization,
            "at": self.at,
            "failure": self.failure,
        }


class IncrementalVerifier:
    """Checkpointed verification over one audit chain."""

    def __init__(
        self,
        chain: AuditChain,
        store: Store,
        clock: Clock,
        path: str | None = None,
        policy: CheckpointPolicy | None = None,
    ) -> None:
        self._chain = chain
        self._store = store
        self._clock = clock
        self._path = path or default_ledger_path(store.path)
        self._policy = policy or CountPolicy()
        self._checked = 0

    @property
    def path(self) -> str:
        return self._path

    # -- verification ------------------------------------------------------

    def verify(self, deep: bool = False) -> VerificationReport:
        """Verify from the persisted cursor forward and persist the new one."""

        entries = self._chain.entries()
        ledger = CheckpointLedger.load(self._path, self._policy)
        self._checked = 0
        written = 0
        now_iso = self._clock.now_iso()

        if deep:
            ledger.reset()
            resume = None
        else:
            resume = self._resume_point(ledger, entries)

        # Replay the previous checkpoint result before trusting the cursor:
        # the segment the newest checkpoint certifies, plus the open tail up
        # to the cursor. With the count policy that is at most two segments.
        replayed: dict[str, int] | None = None
        if resume is not None and resume.sequence > 0:
            newest = ledger.newest_before(resume.sequence, strict=False)
            anchor = ledger.newest_before(newest.sequence) if newest else None
            anchor_sequence = anchor.sequence if anchor else 0
            anchor_digest = anchor.digest if anchor else GENESIS
            replayed = {"from": anchor_sequence, "to": resume.sequence}
            bad = self._scan(entries, anchor_sequence, resume.sequence, anchor_digest)
            if bad is None and entries[resume.sequence - 1].digest != resume.digest:
                bad = (resume.sequence, CHECKPOINT_REPLAY_MISMATCH)
            if bad is not None:
                ledger.truncate_after(anchor_sequence)
                ledger.save()
                return self._report(
                    ledger,
                    intact=False,
                    deep=deep,
                    from_sequence=anchor_sequence,
                    to_sequence=len(entries),
                    replayed=replayed,
                    written=0,
                    failure={
                        "sequence": bad[0],
                        "reason": bad[1],
                        "segment": {"start": anchor_sequence + 1, "end": resume.sequence},
                        "recheck_from": anchor_sequence,
                    },
                )

        start = resume.sequence if resume else 0
        previous = resume.digest if resume else GENESIS
        last_checkpoint = ledger.checkpoints[-1].sequence if ledger.checkpoints else 0
        since_checkpoint = start - last_checkpoint
        last_at = ledger.last_checkpoint_at()
        now = self._clock.now()

        index = start
        failure: dict[str, Any] | None = None
        while index < len(entries):
            entry = entries[index]
            bad = self._check_entry(entry, previous)
            if bad is not None:
                segment_start = (
                    ledger.checkpoints[-1].sequence + 1 if ledger.checkpoints else 1
                )
                failure = {
                    "sequence": bad[0],
                    "reason": bad[1],
                    "segment": {"start": segment_start, "end": len(entries)},
                    "recheck_from": index,
                }
                break
            previous = entry.digest
            index += 1
            since_checkpoint += 1
            moment = parse_at(entry.at) or now
            if self._policy.should_checkpoint(since_checkpoint, moment, last_at):
                ledger.append(entry.sequence, entry.digest, now_iso)
                written += 1
                since_checkpoint = 0
                last_at = moment

        if index > start:
            ledger.mark_verified(index, previous, now_iso)
        ledger.save()
        return self._report(
            ledger,
            intact=failure is None,
            deep=deep,
            from_sequence=start,
            to_sequence=len(entries),
            replayed=replayed,
            written=written,
            failure=failure,
        )

    # -- read-only views ---------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Cross-check the chain head against the persisted cursor."""

        ledger = CheckpointLedger.load(self._path, self._policy)
        head = self._chain.last()
        verified = ledger.verified
        return {
            "chain": {
                "entries": self._chain.count(),
                "head_sequence": head.sequence if head else 0,
                "head_digest": head.digest if head else GENESIS,
            },
            "verified": verified.as_dict() if verified else None,
            "checkpoints": len(ledger.checkpoints),
            "pending_entries": self._chain.count() - (verified.sequence if verified else 0),
            "chain_matches_checkpoint": (
                self._boundary_matches(verified) if verified is not None else None
            ),
            "ledger": ledger.status,
            "ledger_path": self._path,
            "policy": self._policy.describe(),
            "localization": self._localization(),
            "watermark": self._store.watermark,
        }

    def progress(self) -> dict[str, Any]:
        """The cheap liveness signal: how far verification has persisted."""

        ledger = CheckpointLedger.load(self._path, self._policy)
        verified = ledger.verified
        return {
            "verified_through": verified.sequence if verified else 0,
            "pending_entries": self._chain.count() - (verified.sequence if verified else 0),
            "checkpoints": len(ledger.checkpoints),
            "ledger": ledger.status,
        }

    def checkpoints(self) -> dict[str, Any]:
        """The persisted ledger plus the localisation cost it implies."""

        ledger = CheckpointLedger.load(self._path, self._policy)
        payload = ledger.as_dict()
        payload["status"] = ledger.status
        payload["path"] = ledger.path
        payload["localization"] = self._localization()
        return payload

    # -- internals ---------------------------------------------------------

    def _resume_point(
        self, ledger: CheckpointLedger, entries: list
    ) -> Checkpoint | None:
        """The newest persisted marker the chain still agrees with."""

        verified = ledger.verified
        if verified is not None and self._boundary_matches(verified, entries):
            return verified
        for marker in reversed(ledger.checkpoints):
            if self._boundary_matches(marker, entries):
                ledger.truncate_after(marker.sequence)
                ledger.verified = marker
                if ledger.status == "ok":
                    ledger.status = "truncated"
                return marker
        if ledger.checkpoints or ledger.verified:
            ledger.reset()
            ledger.status = "reset"
        return None

    def _boundary_matches(self, marker: Checkpoint | None, entries: list | None = None) -> bool:
        if marker is None:
            return False
        if marker.sequence == 0:
            return True
        if entries is not None:
            if marker.sequence > len(entries):
                return False
            return entries[marker.sequence - 1].digest == marker.digest
        entry = self._chain.entry_at(marker.sequence)
        return entry is not None and entry.digest == marker.digest

    def _check_entry(self, entry, previous: str) -> tuple[int, str] | None:
        """Recompute one entry; return the failure or ``None``."""

        self._checked += 1
        if entry.prev_digest != previous:
            return (entry.sequence, PREV_DIGEST_MISMATCH)
        if digest_of(entry) != entry.digest:
            return (entry.sequence, DIGEST_MISMATCH)
        return None

    def _scan(self, entries: list, start: int, stop: int, previous: str) -> tuple[int, str] | None:
        """Re-verify ``entries[start:stop]``; used to replay a checkpoint."""

        for index in range(start, stop):
            bad = self._check_entry(entries[index], previous)
            if bad is not None:
                return bad
            previous = entries[index].digest
        return None

    def _localization(self) -> dict[str, Any]:
        bound = self._policy.segment_bound()
        return {
            "segment_entries_max": bound,
            "bounded": bound is not None,
        }

    def _report(
        self,
        ledger: CheckpointLedger,
        *,
        intact: bool,
        deep: bool,
        from_sequence: int,
        to_sequence: int,
        replayed: dict[str, int] | None,
        written: int,
        failure: dict[str, Any] | None,
    ) -> VerificationReport:
        head = self._chain.last()
        return VerificationReport(
            intact=intact,
            deep=deep,
            from_sequence=from_sequence,
            to_sequence=to_sequence,
            entries_checked=self._checked,
            replayed=replayed,
            checkpoints_written=written,
            checkpoints_total=len(ledger.checkpoints),
            head_sequence=head.sequence if head else 0,
            head_digest=head.digest if head else GENESIS,
            watermark=self._store.watermark,
            ledger=ledger.status,
            policy=self._policy.describe(),
            localization=self._localization(),
            at=self._clock.now_iso(),
            failure=failure,
        )
