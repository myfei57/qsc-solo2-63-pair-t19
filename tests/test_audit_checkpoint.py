"""Resumable, checkpoint based audit verification."""

from __future__ import annotations

import json

from bagsort.audit.checkpoint import VerificationPolicy
from bagsort.model.entities import AuditEntry
from tests.support import check_in, register_flight


def _tamper_digest(entry: AuditEntry) -> AuditEntry:
    return AuditEntry(
        sequence=entry.sequence,
        kind=entry.kind,
        subject=entry.subject,
        detail=entry.detail,
        prev_digest=entry.prev_digest,
        digest="f" * 64,
        at=entry.at,
    )


def test_incremental_verification_checks_only_new_entries(plant, flight):
    check_in(plant, flight.id, 5)
    policy = VerificationPolicy(interval=2)

    seeded = plant.audit_verifier.verify_full(policy=policy)
    assert seeded.ok is True
    assert seeded.entries_checked == 6
    assert [c.sequence for c in plant.audit_verifier.checkpoint_state().checkpoints] == [0, 2, 4, 6]

    check_in(plant, flight.id, 2)
    resumed = plant.audit_verifier.verify_incremental(policy)
    assert resumed.ok is True
    assert resumed.status == "verified"
    assert resumed.start_sequence == 6
    assert resumed.entries_checked == 2
    assert resumed.fallback_reason == ""
    assert resumed.localization_cost["max_entries_to_rescan"] == 4
    assert plant.audit_verifier.replay_and_compare()["matches"] is True


def test_resume_work_depends_on_new_entries_not_total_chain_length(plant, flight):
    check_in(plant, flight.id, 19)
    policy = VerificationPolicy(interval=10)
    plant.audit_verifier.verify_full(policy=policy)

    check_in(plant, flight.id, 1)
    result = plant.audit_verifier.verify_incremental(policy)
    assert result.ok is True
    assert result.total_entries == 21
    assert result.start_sequence == 20
    assert result.entries_checked == 1
    assert result.digests_checked == 1
    assert result.localization_cost["max_entries_to_rescan"] == 20


def test_failure_is_localized_and_retry_restarts_at_prior_checkpoint(plant, flight):
    check_in(plant, flight.id, 4)
    policy = VerificationPolicy(interval=2)
    plant.audit_verifier.verify_full(policy=policy)
    check_in(plant, flight.id, 3)

    state = plant.store.state()
    state.audit[5] = _tamper_digest(state.audit[5])

    result = plant.audit_verifier.verify_incremental(policy)
    assert result.ok is False
    assert result.status == "broken"
    assert result.entries_checked == 1
    assert result.broken_interval is not None
    assert result.broken_interval.start_sequence == 6
    assert result.broken_interval.end_sequence == 6
    assert result.broken_interval.resume_sequence == 4

    marker_path = f"{plant.store.path}.audit-checkpoints.failure"
    with open(marker_path, "r", encoding="utf-8") as handle:
        marker = json.load(handle)
    assert marker["broken_interval"]["resume_sequence"] == 2

    retry = plant.audit_verifier.verify_incremental(policy)
    assert retry.ok is False
    assert retry.mode == "retry"
    assert retry.start_sequence == 2
    assert retry.entries_checked == 3
    assert retry.broken_interval is not None
    assert retry.broken_interval.entry_sequence == 6
    assert retry.broken_interval.resume_sequence == 4


def test_verification_does_not_rewrite_retained_audit_records(plant, flight):
    check_in(plant, flight.id, 3)
    policy = VerificationPolicy(interval=2)
    before = [entry.as_dict() for entry in plant.audit.entries()]
    journal_before = [entry.as_dict() for entry in plant.store.entries()]

    plant.audit_verifier.verify_full(policy=policy)
    check_in(plant, flight.id, 1)
    plant.audit_verifier.verify_incremental(policy)

    assert [entry.as_dict() for entry in plant.audit.entries()[: len(before)]] == before
    assert [entry.as_dict() for entry in plant.store.entries()[: len(journal_before)]] == journal_before


def test_time_window_checkpoints_group_entries_by_age(plant, flight):
    check_in(plant, flight.id, 2)
    plant.clock.advance(3600)
    plant.audit.record("manual", "probe", "audit")
    plant.clock.advance(3600)
    plant.audit.record("manual", "probe", "audit")

    result = plant.audit_verifier.verify_full(
        policy=VerificationPolicy(mode="time", window_seconds=3600)
    )

    assert result.ok is True
    checkpoints = plant.audit_verifier.checkpoint_state().checkpoints
    assert [(c.sequence, c.reason, c.entries_checked) for c in checkpoints] == [
        (0, "genesis", 0),
        (5, "time_window", 5),
    ]
    assert result.localization_cost["strategy"] == "time_window"
    assert result.localization_cost["max_entries_to_rescan"] is None


def test_checkpoint_chain_must_remain_hash_linked(plant, flight):
    check_in(plant, flight.id, 3)
    plant.audit_verifier.verify_full(policy=VerificationPolicy(interval=2))
    path = f"{plant.store.path}.audit-checkpoints"
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    raw["checkpoints"][1]["journal_watermark"] += 1
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(raw, handle)

    result = plant.audit_verifier.verify_incremental()
    assert result.status == "fallback_full"
    assert "checkpoint" in result.fallback_reason
    assert result.ok == plant.audit.verify()


def test_snapshot_checkpoint_and_console_cross_check(plant, flight):
    check_in(plant, flight.id, 2)
    plant.store.persist()
    result = plant.audit_verifier.verify_full()
    assert result.ok is True

    head = plant.audit_verifier.head()
    assert head is not None
    assert head.snapshot_digest == plant.store.persisted_digest
    assert head.journal_digest == plant.store.journal_digest

    integrity = plant.audit_verifier.integrity()
    assert integrity["known_intact"] is True
    assert integrity["checkpoint_matches_tail"] is True
    assert integrity["snapshot"]["snapshot_digest_matches"] is True
    assert integrity["snapshot"]["journal_anchor_matches"] is True


def test_checkpoint_progress_is_durable_across_restart(tmp_path):
    from bagsort.store.store import Store
    from bagsort.app import Plant

    path = tmp_path / "state.json"
    store = Store(str(path))
    plant = Plant.build(store)
    flight = register_flight(plant, chute="T1-CHA")
    check_in(plant, flight.id, 3)
    policy = VerificationPolicy(interval=2)
    plant.audit_verifier.verify_full(policy=policy)
    store.persist()
    digest = plant.audit.last_digest()

    restarted = Plant.build(Store.open(str(path)))
    check_in(restarted, flight.id, 1)
    result = restarted.audit_verifier.verify_incremental(policy)
    assert result.ok is True
    assert result.start_sequence == 4
    assert result.entries_checked == 1
    assert restarted.audit.last_digest() != digest
