"""Incremental audit verification with durable resumption checkpoints."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from bagsort.clock import Clock
from bagsort.errors import ValidationError
from bagsort.store.journal import JOURNAL_GENESIS, link_digest
from bagsort.store.store import Store
from bagsort.model.audit_accumulator import AuditAccumulator
from .chain import GENESIS, AuditChain, digest_of
from .checkpoint import (
    CHECKPOINT_GENESIS,
    Checkpoint,
    CheckpointState,
    CheckpointStore,
    VerificationPolicy,
    digest_of as checkpoint_digest_of,
    genesis_checkpoint,
)


@dataclass(frozen=True)
class BrokenInterval:
    """The smallest checkpointer-bounded interval containing a failure."""

    start_sequence: int
    end_sequence: int
    resume_sequence: int
    reason: str
    entry_sequence: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "resume_sequence": self.resume_sequence,
            "entry_sequence": self.entry_sequence,
            "reason": self.reason,
        }


@dataclass
class VerificationResult:
    """Outcome and enough counters to prove the scan was incremental."""

    ok: bool
    mode: str
    status: str
    policy: dict[str, Any]
    total_entries: int
    start_sequence: int
    verified_sequence: int
    entries_checked: int
    digests_checked: int
    appends_checked: int
    checkpoint_count: int
    checkpoints_written: int
    previous_checkpoint_digest: str
    final_checkpoint_digest: str
    audit_digest: str
    audit_root: str
    journal_watermark: int
    journal_digest: str
    fallback_reason: str = ""
    broken_interval: BrokenInterval | None = None
    cross_checks: dict[str, bool] = field(default_factory=dict)
    localization_cost: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": self.mode,
            "status": self.status,
            "policy": self.policy,
            "total_entries": self.total_entries,
            "start_sequence": self.start_sequence,
            "verified_sequence": self.verified_sequence,
            "entries_checked": self.entries_checked,
            "digests_checked": self.digests_checked,
            "appends_checked": self.appends_checked,
            "checkpoint_count": self.checkpoint_count,
            "checkpoints_written": self.checkpoints_written,
            "previous_checkpoint_digest": self.previous_checkpoint_digest,
            "final_checkpoint_digest": self.final_checkpoint_digest,
            "audit_digest": self.audit_digest,
            "audit_root": self.audit_root,
            "journal_watermark": self.journal_watermark,
            "journal_digest": self.journal_digest,
            "fallback_reason": self.fallback_reason,
            "broken_interval": self.broken_interval.as_dict() if self.broken_interval else None,
            "cross_checks": dict(self.cross_checks),
            "localization_cost": dict(self.localization_cost),
        }


class AuditVerifier:
    """Verify audit prefixes, persist progress, and resume from the last anchor."""

    def __init__(
        self,
        audit: AuditChain,
        store: Store,
        checkpoint_store: CheckpointStore,
        clock: Clock,
        policy: VerificationPolicy | None = None,
    ) -> None:
        self._audit = audit
        self._store = store
        self._checkpoints = checkpoint_store
        self._clock = clock
        self._policy = policy or VerificationPolicy()

    @property
    def policy(self) -> VerificationPolicy:
        return self._policy

    def policy_summary(self) -> dict[str, Any]:
        return dict(self._policy.as_dict())

    def checkpoint_state(self) -> CheckpointState | None:
        state = self._checkpoints.load()
        if state is not None:
            return state
        head = self._checkpoints.load_head()
        return CheckpointState(checkpoints=(head,)) if head else None

    def head(self) -> Checkpoint | None:
        try:
            return self._checkpoints.load_head()
        except ValidationError:
            return None

    def clear(self) -> None:
        self._checkpoints.clear()

    def known_intact(self) -> bool:
        """True when the durable head already proves the current audit tail."""

        head = self.head()
        return (
            head is not None
            and head.sequence == self._audit.count()
            and self._audit.last_digest() == head.audit_digest
            and self._store.watermark == head.journal_watermark
            and self._store.journal_digest == head.journal_digest
            and self._state_anchor_matches(head)
        )

    def integrity(self) -> dict[str, Any]:
        """Read-only O(audit-peak count) view for health and the console."""

        head = self.head()
        state = self._store.state()
        accumulator = AuditAccumulator.from_list(state.audit_peaks)
        snapshot = self._store.snapshot_summary()
        head_ok = head is not None and head.sequence == len(state.audit)
        integrity = {
            "known_intact": self.known_intact(),
            "audit_count": len(state.audit),
            "audit_digest": state.audit[-1].digest if state.audit else GENESIS,
            "audit_root": accumulator.root,
            "checkpoint_sequence": head.sequence if head else 0,
            "checkpoint_digest": head.digest if head else CHECKPOINT_GENESIS,
            "checkpoint_matches_tail": head_ok
            and (state.audit[-1].digest if state.audit else GENESIS) == head.audit_digest,
            "audit_accumulator_root": accumulator.root,
            "snapshot": snapshot,
        }
        integrity["localization_cost"] = self._policy.localization_cost(len(state.audit))
        return integrity

    def verify_full(
        self, policy: VerificationPolicy | None = None, persist: bool = True
    ) -> VerificationResult:
        policy = policy or self._policy
        entries = self._audit.entries()
        anchors = self._journal_anchors(0, JOURNAL_GENESIS)
        return self._scan(
            entries=entries,
            anchors=anchors,
            start=None,
            existing=(),
            mode="full",
            policy=policy,
            persist=persist,
        )

    def verify_incremental(self, policy: VerificationPolicy | None = None) -> VerificationResult:
        policy = policy or self._policy
        try:
            state = self._checkpoints.load()
        except ValidationError as exc:
            result = self.verify_full(policy=policy)
            result.mode = "incremental"
            result.status = "fallback_full"
            result.fallback_reason = str(exc)
            return result

        if state is None or not state.checkpoints:
            result = self.verify_full(policy=policy)
            result.mode = "incremental"
            result.status = "full_seed"
            return result
        if state.last == state.checkpoints[0] and state.last.previous_checkpoint_digest != CHECKPOINT_GENESIS:
            try:
                recovered_head = self._checkpoints.load_head()
            except ValidationError:
                recovered_head = None
            if recovered_head is not None:
                state = CheckpointState(checkpoints=(recovered_head,))

        head = state.last
        entries = self._audit.entries()
        if head.sequence > len(entries):
            return self._fallback_full(policy, "audit chain is shorter than its checkpoint")
        if head.journal_watermark > self._store.watermark:
            return self._fallback_full(policy, "journal is shorter than its checkpoint")
        if head.sequence:
            tail_entry = entries[head.sequence - 1]
            if tail_entry.digest != head.audit_digest:
                return self._fallback_full(policy, "checkpoint audit prefix was rewritten")

        try:
            failure_marker = self._checkpoints.load_failure()
        except ValidationError:
            failure_marker = None
        if failure_marker:
            failure_interval = failure_marker.get("broken_interval", {})
            resume_sequence = int(failure_interval.get("resume_sequence", 0))
            candidates = [
                checkpoint
                for checkpoint in state.checkpoints
                if checkpoint.sequence <= resume_sequence and checkpoint.sequence > 0
            ]
            resume = candidates[-1] if candidates else state.checkpoints[0]
            anchors = self._journal_anchors(resume.journal_watermark, resume.journal_digest)
            suffix = entries[resume.sequence :]
            return self._scan(
                entries=suffix,
                anchors=anchors,
                start=resume,
                existing=tuple(state.checkpoints[: state.checkpoints.index(resume) + 1]),
                mode="retry",
                policy=head.policy if policy == self._policy else policy,
                persist=True,
            )

        resume = head
        anchors = self._journal_anchors(head.journal_watermark, head.journal_digest)
        if anchors[0][1] != head.journal_digest:
            return self._fallback_full(policy, "checkpoint journal anchor no longer matches")
        if head.snapshot_digest and self._store.persisted_digest:
            snapshot_ok = (
                self._store.persisted_digest == head.snapshot_digest
                and self._store.persisted_watermark == head.snapshot_watermark
            )
        else:
            snapshot_ok = True
        if not snapshot_ok:
            return self._fallback_full(policy, "checkpoint snapshot anchor no longer matches")

        suffix = entries[resume.sequence :]
        return self._scan(
            entries=suffix,
            anchors=anchors,
            start=resume,
            existing=state.checkpoints,
            mode="incremental",
            policy=head.policy if policy == self._policy else policy,
            persist=True,
        )

    def replay_checkpoint(self) -> VerificationResult:
        """Replay the stored head's claimed result without changing audit records."""

        state = self._checkpoints.load()
        if state is None or not state.checkpoints:
            return self.verify_full(persist=False)
        head = state.last
        entries = self._audit.entries_since(head.sequence)
        return self._scan(
            entries=entries,
            anchors=self._journal_anchors(head.journal_watermark, head.journal_digest),
            start=head,
            existing=state.checkpoints,
            mode="replay",
            policy=head.policy,
            persist=False,
        )

    def replay_and_compare(self) -> dict[str, Any]:
        replayed = self.replay_checkpoint().as_dict()
        full = self.verify_full(persist=False).as_dict()
        matches = (
            replayed["ok"] == full["ok"]
            and replayed["verified_sequence"] == full["verified_sequence"]
            and replayed["audit_digest"] == full["audit_digest"]
            and replayed["audit_root"] == full["audit_root"]
            and replayed["journal_digest"] == full["journal_digest"]
            and replayed["broken_interval"] == full["broken_interval"]
        )
        return {"matches": matches, "replayed": replayed, "full": full}

    def _fallback_full(self, policy: VerificationPolicy, reason: str) -> VerificationResult:
        result = self.verify_full(policy=policy)
        result.mode = "incremental"
        result.status = "fallback_full"
        result.fallback_reason = reason
        result.policy = policy.as_dict()
        return result

    def _journal_anchors(
        self, start_watermark: int, prefix_digest: str
    ) -> dict[int, tuple[int, str]]:
        """Map audit sequences to their journal command and folded digest."""

        previous_digest = prefix_digest if start_watermark else JOURNAL_GENESIS
        mapped: dict[int, tuple[int, str]] = {0: (start_watermark, previous_digest)}
        for entry in self._store.entries_since(start_watermark):
            previous_digest = link_digest(previous_digest, entry)
            if entry.kind == "audit.append":
                audit_sequence = int(entry.payload["entry"]["sequence"])
                mapped[audit_sequence] = (entry.sequence, previous_digest)
        mapped[-1] = (self._store.watermark, self._store.journal_digest)
        return mapped

    def _state_anchor_matches(self, checkpoint: Checkpoint) -> bool:
        accumulator = AuditAccumulator(
            count=checkpoint.sequence, peaks=checkpoint.audit_peaks
        )
        return (
            accumulator.root == checkpoint.audit_root
            and self._store.state().audit_root == checkpoint.audit_root
        )

    def _scan(
        self,
        entries: list,
        anchors: dict[int, tuple[int, str]],
        start: Checkpoint | None,
        existing: tuple[Checkpoint, ...],
        mode: str,
        policy: VerificationPolicy,
        persist: bool,
    ) -> VerificationResult:
        total = self._audit.count()
        current_watermark = self._store.watermark
        if start is None:
            sequence = 0
            audit_digest = GENESIS
            accumulator = AuditAccumulator(count=0, peaks=())
            checkpoints: list[Checkpoint] = []
            segment_started_at = self._clock.now_iso()
        else:
            sequence = start.sequence
            audit_digest = start.audit_digest
            accumulator = AuditAccumulator(count=start.sequence, peaks=start.audit_peaks)
            checkpoints: list[Checkpoint] = [start]
            segment_started_at = start.created_at

        if start is None:
            genesis = genesis_checkpoint(
                policy=policy,
                created_at=segment_started_at,
                snapshot_digest=self._store.persisted_digest,
                snapshot_watermark=self._store.persisted_watermark,
            )
            checkpoints.append(genesis)

        entries_checked = digests_checked = appends_checked = 0
        written = 0
        segment_entries = 0
        first_audit = True
        failure: BrokenInterval | None = None
        expected_sequence = sequence + 1

        for entry in entries:
            broken_start = checkpoints[-1].sequence
            if entry.sequence != expected_sequence:
                failure = BrokenInterval(
                    start_sequence=broken_start + 1,
                    end_sequence=total,
                    resume_sequence=broken_start,
                    reason="audit sequence gap",
                    entry_sequence=entry.sequence,
                )
                break
            if entry.prev_digest != audit_digest:
                failure = BrokenInterval(
                    start_sequence=broken_start + 1,
                    end_sequence=entry.sequence,
                    resume_sequence=broken_start,
                    reason="previous digest mismatch",
                    entry_sequence=entry.sequence,
                )
                break
            recomputed = digest_of(entry)
            digests_checked += 1
            if recomputed != entry.digest:
                failure = BrokenInterval(
                    start_sequence=entry.sequence,
                    end_sequence=entry.sequence,
                    resume_sequence=broken_start,
                    reason="entry digest mismatch",
                    entry_sequence=entry.sequence,
                )
                break
            accumulator = accumulator.append(digest_of(entry))
            appends_checked += 1
            expected_anchor = anchors.get(entry.sequence)
            if not expected_anchor:
                failure = BrokenInterval(
                    start_sequence=broken_start + 1,
                    end_sequence=entry.sequence,
                    resume_sequence=broken_start,
                    reason="audit entry is missing from journal",
                    entry_sequence=entry.sequence,
                )
                break

            if first_audit:
                segment_started_at = entries[0].at
                first_audit = False

            audit_digest = entry.digest
            sequence = entry.sequence
            expected_sequence += 1
            entries_checked += 1
            segment_entries += 1

            emit, reason = self._boundary(
                policy=policy,
                entry=entry,
                segment_started_at=segment_started_at,
                segment_entries=segment_entries,
                is_last=entry.sequence == total,
            )
            if emit:
                journal_sequence, journal_digest = expected_anchor
                checkpoint = self._make_checkpoint(
                    policy=policy,
                    sequence=sequence,
                    audit_digest=audit_digest,
                    accumulator=accumulator,
                    journal_watermark=journal_sequence,
                    journal_digest=journal_digest,
                    segment_index=len(checkpoints),
                    segment_started_at=segment_started_at,
                    entries_checked=segment_entries,
                    created_at=entry.at,
                    reason=reason,
                    previous=checkpoints[-1],
                )
                checkpoints.append(checkpoint)
                if persist and mode != "replay":
                    self._save_progress(checkpoints, existing, start is None, False)
                    written += 1
                segment_started_at = entry.at
                segment_entries = 0

        if failure is None and sequence < total:
            failure = BrokenInterval(
                start_sequence=checkpoints[-1].sequence + 1,
                end_sequence=total,
                resume_sequence=checkpoints[-1].sequence,
                reason="unexpected end of audit chain",
            )

        scanned_audit = bool(entries)
        current_checkpoint_is_audit_boundary = checkpoints[-1].reason in {
            "entry_interval",
            "time_window",
        }
        if (
            failure is None
            and scanned_audit
            and not (start is None and current_checkpoint_is_audit_boundary)
            and checkpoints[-1].sequence < sequence
        ):
            journal_sequence, journal_digest = anchors[sequence]
            checkpoint = self._make_checkpoint(
                policy=policy,
                sequence=sequence,
                audit_digest=audit_digest,
                accumulator=accumulator,
                journal_watermark=journal_sequence,
                journal_digest=journal_digest,
                segment_index=len(checkpoints),
                segment_started_at=segment_started_at,
                entries_checked=sequence - checkpoints[-1].sequence,
                created_at=entries[-1].at,
                reason="tail",
                previous=checkpoints[-1],
            )
            checkpoints.append(checkpoint)
            if persist and mode != "replay":
                self._save_progress(checkpoints, existing, start is None, False)
                written += 1

        current_accumulator = AuditAccumulator.from_list(self._store.state().audit_peaks)
        if failure is None and accumulator.root != current_accumulator.root:
            if start is not None and existing and start.sequence > 0:
                resume_checkpoint = existing[-2] if len(existing) >= 2 else existing[0]
                bad_start = resume_checkpoint.sequence + 1
                resume_at = resume_checkpoint.sequence
            else:
                bad_start = 1
                resume_at = 0
            failure = BrokenInterval(
                start_sequence=bad_start,
                end_sequence=start.sequence if start else total,
                resume_sequence=resume_at,
                reason="audit accumulator mismatch",
            )
        tail_anchor = anchors.get(-1, (0, ""))
        cross_checks = {
            "journal_anchor_matches": tail_anchor == (self._store.watermark, self._store.journal_digest),
            "audit_accumulator_matches": accumulator.root == current_accumulator.root,
            "snapshot_digest_matches": not self._store.persisted_digest
            or not self._store.dirty(),
            "snapshot_watermark_matches": not self._store.persisted_digest
            or self._store.persisted_watermark <= self._store.watermark,
        }

        last = checkpoints[-1] if checkpoints else start
        if failure is None and persist and mode != "replay":
            self._save_progress(checkpoints, existing, start is None, True)
            written += 1
        if failure is not None and persist and mode != "replay":
            interval = failure.as_dict()
            if start is not None and existing:
                prior = tuple(
                    checkpoint
                    for checkpoint in existing
                    if checkpoint.sequence < start.sequence
                )
                if prior:
                    interval["resume_sequence"] = prior[-1].sequence
            self._checkpoints.save_failure(
                {
                    "broken_interval": interval,
                    "checkpoint_digest": last.digest if last else CHECKPOINT_GENESIS,
                    "saved_at": self._clock.now_iso(),
                }
            )
        return VerificationResult(
            ok=failure is None and sequence == total,
            mode=mode,
            status="verified" if failure is None else "broken",
            policy=policy.as_dict(),
            total_entries=total,
            start_sequence=start.sequence if start else 0,
            verified_sequence=sequence,
            entries_checked=entries_checked,
            digests_checked=digests_checked,
            appends_checked=appends_checked,
            checkpoint_count=len(existing) - (1 if start else 0) + len(checkpoints),
            checkpoints_written=written,
            previous_checkpoint_digest=start.digest if start else CHECKPOINT_GENESIS,
            final_checkpoint_digest=last.digest if last else CHECKPOINT_GENESIS,
            audit_digest=audit_digest,
            audit_root=accumulator.root,
            journal_watermark=current_watermark,
            journal_digest=self._store.journal_digest,
            broken_interval=failure,
            cross_checks=cross_checks,
            localization_cost=policy.localization_cost(total),
        )

    def _boundary(
        self,
        policy: VerificationPolicy,
        entry,
        segment_started_at: str,
        segment_entries: int,
        is_last: bool,
    ) -> tuple[bool, str]:
        if policy.mode == "entries":
            if segment_entries >= policy.interval:
                return True, "entry_interval"
            return False, ""
        start = _parse_iso(segment_started_at)
        current = _parse_iso(entry.at)
        if (current - start).total_seconds() > policy.window_seconds:
            return True, "time_window"
        return False, ""

    def _make_checkpoint(
        self,
        policy: VerificationPolicy,
        sequence: int,
        audit_digest: str,
        accumulator: AuditAccumulator,
        journal_watermark: int,
        journal_digest: str,
        segment_index: int,
        segment_started_at: str,
        entries_checked: int,
        created_at: str,
        reason: str,
        previous: Checkpoint,
    ) -> Checkpoint:
        checkpoint = Checkpoint(
            sequence=sequence,
            audit_digest=audit_digest,
            audit_peaks=accumulator.peaks,
            audit_root=accumulator.root,
            journal_watermark=journal_watermark,
            journal_digest=journal_digest,
            snapshot_digest=self._store.persisted_digest,
            snapshot_watermark=self._store.persisted_watermark,
            segment_index=segment_index,
            segment_started_at=segment_started_at,
            entries_checked=entries_checked,
            created_at=created_at,
            reason=reason,
            previous_checkpoint_digest=previous.digest,
            policy=policy,
        )
        return Checkpoint(**{**checkpoint.__dict__, "digest": checkpoint_digest_of(checkpoint)})

    def _save_progress(
        self,
        new_checkpoints: list[Checkpoint],
        existing: tuple[Checkpoint, ...],
        fresh: bool,
        complete: bool,
    ) -> None:
        if fresh:
            checkpoints = tuple(new_checkpoints)
        else:
            checkpoints = existing[:-1] + tuple(new_checkpoints)
        state = CheckpointState(checkpoints=checkpoints)
        if complete:
            self._checkpoints.save(state)
        else:
            self._checkpoints.save_head(state.last)

def _parse_iso(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
