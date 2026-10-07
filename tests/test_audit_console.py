"""Console exposure for checkpointed audit verification."""

from __future__ import annotations

from tests.test_console_api import bootstrap, call


def test_audit_verification_and_snapshot_console(server):
    flight_id = bootstrap(server)
    call(server, "POST", "/api/bags/checkin", {"barcode": "7001", "flight_id": flight_id})

    status, verify = call(
        server, "GET", "/api/audit/verify", query={"interval": ["1"], "mode": ["entries"]}
    )
    assert status == 200
    assert verify["ok"] is True
    assert verify["intact"] is True
    assert verify["entries_checked"] >= 2
    assert verify["checkpoint_count"] >= 2

    status, checkpoints = call(server, "GET", "/api/audit/checkpoints")
    assert status == 200
    assert checkpoints["count"] == verify["checkpoint_count"]

    status, replay = call(server, "GET", "/api/audit/verify/replay")
    assert status == 200
    assert replay["ok"] is True

    status, comparison = call(server, "GET", "/api/audit/verify/compare")
    assert status == 200
    assert comparison["matches"] is True

    status, persist = call(server, "POST", "/api/store/persist")
    assert status == 200
    assert persist["digest"]

    status, snapshot = call(server, "GET", "/api/store/snapshot")
    assert status == 200
    assert snapshot["persisted"] is True
    assert snapshot["snapshot_digest_matches"] is True
    assert snapshot["journal_anchor_matches"] is True

    status, integrity = call(server, "GET", "/api/audit/integrity")
    assert status == 200
    assert integrity["known_intact"] is True
    assert integrity["snapshot"]["persisted_digest"] == persist["digest"]
    assert integrity["checkpoint_digest"] == checkpoints["checkpoints"][-1]["digest"]


def test_time_window_policy_is_accepted_by_console(server):
    flight_id = bootstrap(server)
    call(server, "POST", "/api/bags/checkin", {"barcode": "7002", "flight_id": flight_id})
    status, verify = call(
        server,
        "GET",
        "/api/audit/verify",
        query={"mode": ["time"], "window": ["300"]},
    )
    assert status == 200
    assert verify["ok"] is True
    assert verify["policy"]["mode"] == "time"
    assert verify["policy"]["window_seconds"] == 300.0
