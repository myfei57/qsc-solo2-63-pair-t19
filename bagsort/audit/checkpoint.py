"""Durable, hash linked audit verification checkpoints."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from bagsort.errors import ValidationError
from bagsort.model.audit_accumulator import AuditAccumulator
from bagsort.store.journal import JOURNAL_GENESIS
from .chain import GENESIS

CHECKPOINT_VERSION = 1
CHECKPOINT_GENESIS = "0" * 64


@dataclass(frozen=True)
class VerificationPolicy:
    """When a checkpoint should be emitted during a verification scan."""

    mode: str = "entries"
    interval: int = 100
    window_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.mode not in {"entries", "time"}:
            raise ValidationError("checkpoint mode must be 'entries' or 'time'")
        if self.mode == "entries" and self.interval <= 0:
            raise ValidationError("entry checkpoint interval must be positive")
        if self.mode == "time" and self.window_seconds <= 0:
            raise ValidationError("time checkpoint window must be positive")
        if self.mode == "time":
            object.__setattr__(self, "window_seconds", float(self.window_seconds))

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "interval": self.interval,
            "window_seconds": self.window_seconds,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VerificationPolicy":
        return cls(
            mode=str(raw.get("mode", "entries")),
            interval=int(raw.get("interval", 100)),
            window_seconds=float(raw.get("window_seconds", 0.0)),
        )

    def localization_cost(self, total_entries: int) -> dict[str, Any]:
        """Storage and worst-case resume work for this checkpoint placement."""

        if self.mode == "entries":
            checkpoint_count = total_entries // self.interval + 1
            return {
                "strategy": "fixed_entries",
                "interval": self.interval,
                "checkpoint_count": checkpoint_count,
                "max_entries_to_rescan": 2 * self.interval,
                "storage_cost": "one linked checkpoint per fixed interval",
            }
        return {
            "strategy": "time_window",
            "window_seconds": self.window_seconds,
            "checkpoint_count": "one checkpoint per non-empty window",
            "max_entries_to_rescan": None,
            "storage_cost": "lower for sparse traffic, higher for bursty windows",
        }


@dataclass(frozen=True)
class Checkpoint:
    """A verified prefix and the anchors needed to resume from it."""

    sequence: int
    audit_digest: str
    audit_peaks: tuple[tuple[int, str], ...]
    audit_root: str
    journal_watermark: int
    journal_digest: str
    segment_index: int
    segment_started_at: str
    entries_checked: int
    created_at: str
    reason: str
    previous_checkpoint_digest: str
    policy: VerificationPolicy
    snapshot_digest: str = ""
    snapshot_watermark: int = 0
    digest: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "audit_digest": self.audit_digest,
            "audit_peaks": AuditAccumulator.from_list(self.audit_peaks).as_list(),
            "audit_root": self.audit_root,
            "journal_watermark": self.journal_watermark,
            "journal_digest": self.journal_digest,
            "snapshot_digest": self.snapshot_digest,
            "snapshot_watermark": self.snapshot_watermark,
            "segment_index": self.segment_index,
            "segment_started_at": self.segment_started_at,
            "entries_checked": self.entries_checked,
            "created_at": self.created_at,
            "reason": self.reason,
            "previous_checkpoint_digest": self.previous_checkpoint_digest,
            "policy": self.policy.as_dict(),
        }

    def as_dict(self) -> dict[str, Any]:
        data = self.unsigned_dict()
        data["digest"] = self.digest
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Checkpoint":
        policy = VerificationPolicy.from_dict(dict(raw.get("policy", {})))
        accumulator = AuditAccumulator.from_list(raw.get("audit_peaks", []))
        checkpoint = cls(
            sequence=int(raw.get("sequence", -1)),
            audit_digest=str(raw.get("audit_digest", "")),
            audit_peaks=accumulator.peaks,
            audit_root=str(raw.get("audit_root", "")),
            journal_watermark=int(raw.get("journal_watermark", -1)),
            journal_digest=str(raw.get("journal_digest", "")),
            snapshot_digest=str(raw.get("snapshot_digest", "")),
            snapshot_watermark=int(raw.get("snapshot_watermark", 0)),
            segment_index=int(raw.get("segment_index", -1)),
            segment_started_at=str(raw.get("segment_started_at", "")),
            entries_checked=int(raw.get("entries_checked", 0)),
            created_at=str(raw.get("created_at", "")),
            reason=str(raw.get("reason", "")),
            previous_checkpoint_digest=str(raw.get("previous_checkpoint_digest", "")),
            policy=policy,
            digest=str(raw.get("digest", "")),
        )
        if digest_of(checkpoint) != checkpoint.digest:
            raise ValidationError("checkpoint digest does not match")
        if accumulator.count != checkpoint.sequence or accumulator.root != checkpoint.audit_root:
            raise ValidationError("checkpoint audit accumulator does not match")
        return checkpoint


@dataclass(frozen=True)
class CheckpointState:
    """All retained checkpoints for one audit chain."""

    checkpoints: tuple[Checkpoint, ...]
    version: int = CHECKPOINT_VERSION

    @property
    def last(self) -> Checkpoint | None:
        return self.checkpoints[-1] if self.checkpoints else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "checkpoints": [checkpoint.as_dict() for checkpoint in self.checkpoints],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CheckpointState":
        version = int(raw.get("version", 0))
        if version != CHECKPOINT_VERSION:
            raise ValidationError(f"unsupported checkpoint version {version}")
        checkpoints: list[Checkpoint] = []
        previous = CHECKPOINT_GENESIS
        previous_sequence = 0
        previous_journal_watermark = 0
        for item in raw.get("checkpoints", []):
            checkpoint = Checkpoint.from_dict(dict(item))
            if checkpoint.previous_checkpoint_digest != previous:
                raise ValidationError("checkpoint previous-digest chain is broken")
            if checkpoints and checkpoint.sequence < previous_sequence:
                raise ValidationError("checkpoint audit sequences must not move backwards")
            if (
                checkpoints
                and checkpoint.sequence == previous_sequence
                and checkpoint.journal_watermark <= previous_journal_watermark
            ):
                raise ValidationError("journal-only checkpoints must advance the watermark")
            if (
                checkpoints
                and checkpoint.sequence > previous_sequence
                and checkpoint.journal_watermark < previous_journal_watermark
            ):
                raise ValidationError("checkpoint journal watermarks must not move backwards")
            checkpoints.append(checkpoint)
            previous = checkpoint.digest
            previous_sequence = checkpoint.sequence
            previous_journal_watermark = checkpoint.journal_watermark
        return cls(version=version, checkpoints=tuple(checkpoints))


def digest_of(checkpoint: Checkpoint) -> str:
    material = json.dumps(
        checkpoint.unsigned_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def genesis_checkpoint(
    policy: VerificationPolicy,
    created_at: str,
    snapshot_digest: str = "",
    snapshot_watermark: int = 0,
) -> Checkpoint:
    checkpoint = Checkpoint(
        sequence=0,
        audit_digest=GENESIS,
        audit_peaks=(),
        audit_root=AuditAccumulator(count=0, peaks=()).root,
        journal_watermark=0,
        journal_digest=JOURNAL_GENESIS,
        snapshot_digest=snapshot_digest,
        snapshot_watermark=snapshot_watermark,
        segment_index=0,
        segment_started_at=created_at,
        entries_checked=0,
        created_at=created_at,
        reason="genesis",
        previous_checkpoint_digest=CHECKPOINT_GENESIS,
        policy=policy,
    )
    return Checkpoint(**{**checkpoint.__dict__, "digest": digest_of(checkpoint)})


class CheckpointStore:
    """Atomically persist and reload resumable verification progress."""

    def __init__(self, path: str) -> None:
        self._path = os.path.abspath(path)

    @property
    def path(self) -> str:
        return self._path

    @property
    def head_path(self) -> str:
        return f"{self._path}.head"

    @property
    def failure_path(self) -> str:
        return f"{self._path}.failure"

    def _state_from_text(self, raw: str) -> CheckpointState | None:
        if not raw.strip():
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ValidationError(f"checkpoint file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("checkpoint file must contain an object")
        return CheckpointState.from_dict(data)

    def load(self) -> CheckpointState | None:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return None
        return self._state_from_text(raw)

    def load_head(self) -> Checkpoint | None:
        try:
            with open(self.head_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            state = self.load()
            return state.last if state else None
        if not raw.strip():
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ValidationError(f"checkpoint head is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("checkpoint head must contain an object")
        return Checkpoint.from_dict(data)

    def load_failure(self) -> dict[str, Any] | None:
        try:
            with open(self.failure_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ValidationError(f"failure marker is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("failure marker must contain an object")
        return data

    def save_failure(self, failure: dict[str, Any]) -> None:
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self.failure_path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(failure, ensure_ascii=False, indent=2, sort_keys=True))
        os.replace(temporary, self.failure_path)

    def clear_failure(self) -> None:
        try:
            os.remove(self.failure_path)
        except FileNotFoundError:
            pass

    def save_head(self, head: Checkpoint) -> None:
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self.head_path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(head.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        os.replace(temporary, self.head_path)

    def save(self, state: CheckpointState) -> None:
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self._path}.tmp"
        raw = json.dumps(
            state.as_dict(), ensure_ascii=False, indent=2, sort_keys=True
        )
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(raw)
        os.replace(temporary, self._path)
        head = state.last
        if head is not None:
            head_temporary = f"{self.head_path}.tmp"
            with open(head_temporary, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(head.as_dict(), ensure_ascii=False, indent=2, sort_keys=True)
                )
            os.replace(head_temporary, self.head_path)
        self.clear_failure()

    def clear(self) -> None:
        for path in (self._path, self.head_path, self.failure_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
