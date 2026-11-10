import tempfile
import unittest
from pathlib import Path
from shauditer.database.db import Database
from shauditer.models.target import normalize_target


class DatabaseTests(unittest.TestCase):
    def test_audit_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "db.sqlite")
            aid = db.next_audit_id()
            db.create_audit(aid, normalize_target("example.com"), "CREATED", "safe", Path(tmp)/aid)
            next_id = db.next_audit_id()
            self.assertNotEqual(aid, next_id)


if __name__ == "__main__":
    unittest.main()


def test_delete_audit_removes_owned_rows(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    aid = db.next_audit_id()
    db.create_audit(aid, normalize_target("example.com"), "CREATED", "safe", tmp_path / aid)
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO events(audit_id,event_type,timestamp,payload_json) VALUES (?,?,?,?)",
            (aid, "TEST", "2026-01-01T00:00:00+00:00", "{}"),
        )
        conn.execute(
            "INSERT INTO findings(finding_id,audit_id,finding_json,created_at,updated_at) VALUES (?,?,?,?,?)",
            ("F-0001", aid, "{}", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
    deleted = db.delete_audit(aid)
    assert deleted["audits"] == 1
    assert deleted["events"] == 1
    assert deleted["findings"] == 1
    assert db.get_audit(aid) is None
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE audit_id=?", (aid,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE audit_id=?", (aid,)).fetchone()[0] == 0
    assert db.delete_audit(aid) == {}
