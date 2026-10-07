"""Incremental, checkpointed verification of the audit chain."""

from __future__ import annotations

import json

from bagsort.app import Plant
from bagsort.audit.checkpoints import CountPolicy, WindowPolicy
from bagsort.audit.verify import IncrementalVerifier
from bagsort.clock import Clock
from bagsort.cli import main
from bagsort.model.entities import AuditEntry
from bagsort.store.store import Store
from tests.support import make_plant, make_server


def grow(plant: Plant, count: int) -> None:
    for index in range(count):
        plant.audit.record("probe", "bulk", "sorter", {"index": index})


def tamper(plant: Plant, sequence: int, **changes) -> AuditEntry:
    """Rewrite one committed entry in place, keeping its digest fields."""

    state = plant.store.state()
    index = sequence - 1
    original = state.audit[index]
    state.audit[index] = AuditEntry(
        sequence=original.sequence,
        kind=changes.get("kind", original.kind),
        subject=changes.get("subject", original.subject),
        detail=changes.get("detail", original.detail),
        prev_digest=changes.get("prev_digest", original.prev_digest),
        digest=changes.get("digest", original.digest),
        at=original.at,
    )
    return original


def restore(plant: Plant, entry: AuditEntry) -> None:
    plant.store.state().audit[entry.sequence - 1] = entry


def call(server, method: str, path: str, payload=None, query=None):
    response = server.call(method, path, payload, query)
    return response.status, json.loads(response.body)


# ---------------------------------------------------------------------------
# resumable progress
# ---------------------------------------------------------------------------


def test_first_run_verifies_everything_and_persists_checkpoints(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    report = plant.verify_incremental()
    assert report["intact"] is True
    assert (report["from_sequence"], report["to_sequence"]) == (0, 10)
    assert report["entries_checked"] == 10
    assert report["replayed"] is None
    assert report["checkpoints_written"] == 5
    assert report["head"] == {"sequence": 10, "digest": plant.audit.last().digest}
    assert report["ledger"] == "fresh"

    persisted = json.loads((tmp_path / "state.checkpoints.json").read_text())
    assert [mark["sequence"] for mark in persisted["checkpoints"]] == [2, 4, 6, 8, 10]
    assert persisted["verified"]["sequence"] == 10
    assert persisted["verified"]["digest"] == plant.audit.last().digest


def test_second_run_replays_the_last_segment_and_scans_only_new_entries(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    plant.verify_incremental()

    grow(plant, 3)
    report = plant.verify_incremental()
    assert report["intact"] is True
    assert report["from_sequence"] == 10
    assert report["replayed"] == {"from": 8, "to": 10}
    # 2 replayed + 3 new: the work is bounded by the segment, not the chain.
    assert report["entries_checked"] == 5
    assert report["checkpoints_written"] == 1
    assert report["head"]["sequence"] == 13

    idle = plant.verify_incremental()
    # The replay covers the segment the newest checkpoint certifies plus the
    # open tail: entries 11..13, still bounded by two segments.
    assert idle["entries_checked"] == 3
    assert idle["replayed"] == {"from": 10, "to": 13}


def test_checkpoints_follow_the_configured_interval(tmp_path):
    plant = make_plant(tmp_path, verify_every=3)
    grow(plant, 10)
    report = plant.verify_incremental()
    checkpoints = plant.verifier.checkpoints()
    assert [mark["sequence"] for mark in checkpoints["checkpoints"]] == [3, 6, 9]
    assert checkpoints["verified"]["sequence"] == 10
    assert report["checkpoints_total"] == 3


def test_resume_survives_a_process_restart(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 6)
    first = plant.verify_incremental()
    plant.store.persist()

    reopened = Plant.build(Store.open(plant.store.path), clock=Clock(), verify_every=2)
    grow(reopened, 2)
    report = reopened.verify_incremental()
    assert report["intact"] is True
    assert report["from_sequence"] == first["to_sequence"] == 6
    assert report["entries_checked"] == 4  # 2 replayed + 2 new
    assert report["head"]["sequence"] == 8


def test_empty_chain_verifies_clean(tmp_path):
    plant = make_plant(tmp_path)
    report = plant.verify_incremental()
    assert report["intact"] is True
    assert (report["from_sequence"], report["to_sequence"], report["entries_checked"]) == (0, 0, 0)


# ---------------------------------------------------------------------------
# localisation and resume after a break
# ---------------------------------------------------------------------------


def test_a_broken_tail_is_located_to_the_entry_and_the_segment(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    plant.verify_incremental()
    grow(plant, 3)
    original = tamper(plant, 12, kind="rewritten")

    report = plant.verify_incremental()
    assert report["intact"] is False
    assert report["failure"]["sequence"] == 12
    assert report["failure"]["reason"] == "digest_mismatch"
    assert report["failure"]["segment"] == {"start": 11, "end": 13}
    assert report["failure"]["recheck_from"] == 11
    # Progress up to the break is kept: the next run resumes at 11.
    assert plant.verifier.checkpoints()["verified"]["sequence"] == 11

    again = plant.verify_incremental()
    assert again["from_sequence"] == 11
    assert again["failure"]["sequence"] == 12

    restore(plant, original)
    healed = plant.verify_incremental()
    assert healed["intact"] is True
    assert healed["from_sequence"] == 11
    assert healed["head"]["sequence"] == 13


def test_a_tampered_checkpointed_segment_fails_the_replay(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    plant.verify_incremental()
    original = tamper(plant, 9, kind="rewritten")

    report = plant.verify_incremental()
    assert report["intact"] is False
    assert report["replayed"] == {"from": 8, "to": 10}
    assert report["failure"]["sequence"] == 9
    assert report["failure"]["segment"] == {"start": 9, "end": 10}
    assert report["failure"]["recheck_from"] == 8
    # The ledger rolled back to the last trustworthy checkpoint.
    assert plant.verifier.checkpoints()["verified"]["sequence"] == 8

    restore(plant, original)
    healed = plant.verify_incremental()
    assert healed["intact"] is True
    assert healed["from_sequence"] == 8


def test_incremental_and_full_verification_draw_the_same_conclusion(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    assert (plant.verify_incremental()["intact"], plant.audit.verify()) == (True, True)

    grow(plant, 3)
    tampered = tamper(plant, 12, kind="rewritten")
    assert (plant.verify_incremental()["intact"], plant.audit.verify()) == (False, False)
    restore(plant, tampered)
    assert (plant.verify_incremental()["intact"], plant.audit.verify()) == (True, True)

    # Entry 11 sits inside the segment the next run replays (10, 13].
    tampered = tamper(plant, 11, kind="rewritten")
    assert (plant.verify_incremental()["intact"], plant.audit.verify()) == (False, False)


def test_deep_verification_matches_full_verification_on_old_tampering(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 10)
    plant.verify_incremental()
    tamper(plant, 3, kind="rewritten")

    # Shallow runs certify the tail and the replayed segment; an entry rewritten
    # behind the last checkpoint with its digest fields kept is the documented
    # shallow boundary. The deep run re-verifies from the genesis and agrees
    # with a full verification one for one.
    assert plant.verify_incremental()["intact"] is True
    assert plant.audit.verify() is False
    deep = plant.verify_incremental(deep=True)
    assert deep["intact"] is False
    assert deep["failure"]["sequence"] == 3
    assert deep["entries_checked"] == 3


def test_a_reset_store_restarts_verification_from_the_genesis(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 6)
    plant.verify_incremental()
    plant.store.reset()

    report = plant.verify_incremental()
    assert report["intact"] is True
    assert report["ledger"] == "reset"
    assert (report["from_sequence"], report["to_sequence"]) == (0, 0)
    assert report["checkpoints_total"] == 0

    grow(plant, 3)
    again = plant.verify_incremental()
    assert again["intact"] is True
    assert again["from_sequence"] == 0
    assert again["to_sequence"] == 3


def test_a_rewritten_ledger_is_truncated_to_its_valid_prefix(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 6)
    plant.verify_incremental()

    ledger_path = tmp_path / "state.checkpoints.json"
    data = json.loads(ledger_path.read_text())
    data["checkpoints"][1]["digest"] = "f" * 64
    ledger_path.write_text(json.dumps(data))

    report = plant.verify_incremental()
    assert report["intact"] is True  # the chain itself is untouched
    assert report["ledger"] == "truncated"
    assert report["from_sequence"] == 2  # only the first marker survived
    assert plant.audit.verify() is True


def test_an_unreadable_ledger_is_rebuilt_from_scratch(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 4)
    plant.verify_incremental()
    (tmp_path / "state.checkpoints.json").write_text("not json")

    report = plant.verify_incremental()
    assert report["intact"] is True
    assert report["ledger"] == "rebuilt"
    assert report["from_sequence"] == 0


# ---------------------------------------------------------------------------
# the chain and the snapshot are read-only for the verifier
# ---------------------------------------------------------------------------


def test_verification_never_rewrites_the_chain_the_journal_or_the_snapshot(tmp_path):
    plant = make_plant(tmp_path, verify_every=2)
    grow(plant, 6)
    digest = plant.store.persist()
    snapshot_bytes = (tmp_path / "state.json").read_bytes()
    journal_before = [entry.as_dict() for entry in plant.store.entries()]
    audit_before = [entry.as_dict() for entry in plant.audit.entries()]
    watermark_before = plant.store.watermark

    assert plant.verify_incremental()["intact"] is True
    tampered = tamper(plant, 5, kind="rewritten")
    assert plant.verify_incremental()["intact"] is False

    assert plant.store.watermark == watermark_before
    assert plant.store.dirty() is False
    assert plant.store.pending() == []
    assert [entry.as_dict() for entry in plant.store.entries()] == journal_before
    expected_audit = audit_before[:4] + [plant.audit.entries()[4].as_dict()] + audit_before[5:]
    assert [entry.as_dict() for entry in plant.audit.entries()] == expected_audit
    assert (tmp_path / "state.json").read_bytes() == snapshot_bytes
    assert plant.store.envelope().digest == digest
    restore(plant, tampered)


# ---------------------------------------------------------------------------
# performance does not degrade as the chain grows
# ---------------------------------------------------------------------------


def test_verification_cost_is_bounded_by_new_entries_not_chain_length(tmp_path):
    every = 10
    plant = make_plant(tmp_path, verify_every=every)
    grow(plant, 300)
    assert plant.verify_incremental()["entries_checked"] == 300

    grow(plant, 5)
    short_chain = plant.verify_incremental()
    assert short_chain["from_sequence"] == 300
    assert short_chain["entries_checked"] == 5 + every

    grow(plant, 695)
    # Catch-up run: the new entries plus one replayed segment and open tail.
    assert plant.verify_incremental()["entries_checked"] == 695 + 5 + every

    grow(plant, 5)
    long_chain = plant.verify_incremental()
    assert long_chain["from_sequence"] == 1000
    # Same new work at 10x the chain length costs exactly the same.
    assert long_chain["entries_checked"] == short_chain["entries_checked"] == 5 + every


# ---------------------------------------------------------------------------
# window policy
# ---------------------------------------------------------------------------


def test_window_policy_spaces_checkpoints_by_chain_time(tmp_path):
    plant = make_plant(tmp_path)
    verifier = IncrementalVerifier(
        plant.audit,
        plant.store,
        plant.clock,
        path=str(tmp_path / "window.checkpoints.json"),
        policy=WindowPolicy(60),
    )
    grow(plant, 3)
    plant.clock.advance(120)
    grow(plant, 3)

    report = verifier.verify().as_dict()
    assert report["intact"] is True
    assert report["policy"] == {"kind": "window", "seconds": 60}
    assert report["localization"] == {"segment_entries_max": None, "bounded": False}
    checkpoints = verifier.checkpoints()
    assert [mark["sequence"] for mark in checkpoints["checkpoints"]] == [1, 4]

    plant.clock.advance(120)
    grow(plant, 2)
    verifier.verify()
    assert [mark["sequence"] for mark in verifier.checkpoints()["checkpoints"]] == [1, 4, 7]


def test_count_policy_states_its_localisation_bound(tmp_path):
    plant = make_plant(tmp_path, verify_every=8)
    grow(plant, 3)
    report = plant.verify_incremental()
    assert report["policy"] == {"kind": "count", "every": 8}
    assert report["localization"] == {"segment_entries_max": 8, "bounded": True}


# ---------------------------------------------------------------------------
# console
# ---------------------------------------------------------------------------


def test_console_verify_status_and_checkpoints_endpoints(tmp_path):
    server = make_server(tmp_path, verify_every=2)
    status, _ = call(server, "POST", "/api/flights", {"code": "CA1234", "chute": "A"})
    assert status == 201
    flight_id = "T1-CA1234"
    for barcode in ("BAG0001", "BAG0002", "BAG0003"):
        assert call(server, "POST", "/api/bags/checkin", {"barcode": barcode, "flight_id": flight_id})[0] == 201
    _, count = call(server, "GET", "/api/audit/count")
    assert count["count"] == 4

    status, report = call(server, "POST", "/api/audit/verify/incremental")
    assert status == 200
    assert report["intact"] is True
    assert report["to_sequence"] == 4
    assert report["checkpoints_total"] == 2

    status, checkpoints = call(server, "GET", "/api/audit/checkpoints")
    assert status == 200
    assert [mark["sequence"] for mark in checkpoints["checkpoints"]] == [2, 4]
    assert checkpoints["verified"]["sequence"] == 4
    assert checkpoints["policy"] == {"kind": "count", "every": 2}
    assert checkpoints["localization"]["bounded"] is True

    status, view = call(server, "GET", "/api/audit/verify/status")
    assert status == 200
    assert view["chain"]["head_sequence"] == 4
    assert view["verified"]["digest"] == view["chain"]["head_digest"]
    assert view["chain_matches_checkpoint"] is True
    assert view["pending_entries"] == 0
    assert view["snapshot"]["watermark"] == view["watermark"]
    assert len(view["snapshot"]["digest"]) == 64

    call(server, "POST", "/api/bags/checkin", {"barcode": "BAG0004", "flight_id": flight_id})
    _, view = call(server, "GET", "/api/audit/verify/status")
    assert view["pending_entries"] == 1

    status, deep = call(server, "POST", "/api/audit/verify/incremental", query={"deep": ["true"]})
    assert status == 200
    assert deep["deep"] is True
    assert deep["from_sequence"] == 0
    assert deep["intact"] is True

    _, health = call(server, "GET", "/api/health")
    assert health["audit_verified_through"] == 5
    assert health["audit_pending"] == 0


def test_cli_verify_command(tmp_path, capsys):
    state = tmp_path / "state.json"
    assert main(["--state", str(state), "demo", "--cycles", "2", "--persist"]) == 0
    capsys.readouterr()

    assert main(["--state", str(state), "verify"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["intact"] is True
    assert report["to_sequence"] > 0

    assert main(["--state", str(state), "verify"]) == 0
    resumed = json.loads(capsys.readouterr().out)
    assert resumed["from_sequence"] == report["to_sequence"]
    assert resumed["entries_checked"] <= resumed["localization"]["segment_entries_max"]
