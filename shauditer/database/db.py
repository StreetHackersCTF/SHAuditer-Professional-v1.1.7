from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS audits (
    audit_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_json TEXT NOT NULL,
    state TEXT NOT NULL,
    profile TEXT NOT NULL,
    workspace TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_audit ON events(audit_id, id);
CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL,
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    command_json TEXT,
    exit_code INTEGER,
    started_at TEXT,
    finished_at TEXT,
    stdout_path TEXT,
    stderr_path TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    module TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (audit_id, finding_id)
);

-- v0.2: explicit human approval and validation records.
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    action TEXT NOT NULL,
    operator TEXT NOT NULL,
    approved INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_audit_finding ON approvals(audit_id, finding_id, created_at);

CREATE TABLE IF NOT EXISTS validations (
    validation_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    method TEXT NOT NULL,
    operator TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    evidence_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validations_audit_finding ON validations(audit_id, finding_id, created_at);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    finding_id TEXT,
    session_type TEXT NOT NULL,
    privilege TEXT NOT NULL,
    operator TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_id TEXT,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_audit ON sessions(audit_id, created_at);

-- v0.3: read-only exploit intelligence and operator research reviews.
CREATE TABLE IF NOT EXISTS exploit_intelligence (
    intelligence_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(audit_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_exploit_intel_audit ON exploit_intelligence(audit_id, finding_id);

CREATE TABLE IF NOT EXISTS exploit_reviews (
    review_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    decision TEXT NOT NULL,
    module TEXT,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exploit_reviews_audit ON exploit_reviews(audit_id, finding_id, created_at);

-- v1.0: one-time bound operator permissions for low-impact PoC probes.
CREATE TABLE IF NOT EXISTS poc_executions (
    execution_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE,
    audit_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    evidence_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_poc_audit ON poc_executions(audit_id, created_at);

"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
        self._migrate_legacy_findings_pk()
        if os.name == "posix":
            self.path.chmod(0o600)

    def _migrate_legacy_findings_pk(self) -> None:
        """Upgrade v0.1 databases where finding_id alone was the primary key."""
        with self.connect() as conn:
            info = conn.execute("PRAGMA table_info(findings)").fetchall()
            pk = {row["name"]: row["pk"] for row in info}
            if pk.get("finding_id") == 1 and pk.get("audit_id", 0) == 0:
                conn.execute("ALTER TABLE findings RENAME TO findings_v01")
                conn.execute(
                    """CREATE TABLE findings (
                        finding_id TEXT NOT NULL,
                        audit_id TEXT NOT NULL,
                        finding_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (audit_id, finding_id)
                    )"""
                )
                conn.execute(
                    """INSERT OR REPLACE INTO findings(finding_id,audit_id,finding_json,created_at,updated_at)
                       SELECT finding_id,audit_id,finding_json,created_at,updated_at FROM findings_v01"""
                )
                conn.execute("DROP TABLE findings_v01")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def next_audit_id(self) -> str:
        year = datetime.now().year
        prefix = f"SHA-{year}-"
        with self.connect() as conn:
            row = conn.execute(
                "SELECT audit_id FROM audits WHERE audit_id LIKE ? ORDER BY audit_id DESC LIMIT 1",
                (prefix + "%",),
            ).fetchone()
        n = int(row["audit_id"].split("-")[-1]) + 1 if row else 1
        return f"{prefix}{n:05d}"

    def _next_id(self, table: str, column: str, prefix: str) -> str:
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT {column} FROM {table} WHERE {column} LIKE ? ORDER BY {column} DESC LIMIT 1",
                (prefix + "-%",),
            ).fetchone()
        n = int(row[column].split("-")[-1]) + 1 if row else 1
        return f"{prefix}-{n:05d}"

    def next_approval_id(self) -> str:
        return self._next_id("approvals", "approval_id", "AP")

    def next_validation_id(self) -> str:
        return self._next_id("validations", "validation_id", "VAL")

    def next_session_id(self) -> str:
        return self._next_id("sessions", "session_id", "SES")

    def next_intelligence_id(self) -> str:
        return self._next_id("exploit_intelligence", "intelligence_id", "EI")

    def next_exploit_review_id(self) -> str:
        return self._next_id("exploit_reviews", "review_id", "ER")

    def reserve_poc_execution(self, execution_id: str, approval_id: str, audit_id: str,
                              finding_id: str, action: str, operator: str) -> None:
        """Reserve a single-use approval atomically with explicit scope and identity."""
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id=? AND audit_id=? AND finding_id=? AND action=? AND operator=?",
                (approval_id, audit_id, finding_id, action, operator),
            ).fetchone()
            if row is None or not row["approved"]:
                raise PermissionError("no matching operator approval for this specific finding and check")
            try:
                age = now - datetime.fromisoformat(row["created_at"])
            except (ValueError, TypeError) as exc:
                raise PermissionError("invalid approval date") from exc
            if age < timedelta(0) or age > timedelta(hours=1):
                raise PermissionError("proof approval has expired (maximum 1 hour)")
            try:
                conn.execute(
                    "INSERT INTO poc_executions (execution_id,approval_id,audit_id,finding_id,operator,status,created_at) VALUES (?,?,?,?,?,?,?)",
                    (execution_id, approval_id, audit_id, finding_id, operator, "RESERVED", now.isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("this proof approval was already consumed") from exc

    def finish_poc_execution(self, execution_id: str, status: str, *, evidence_id: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE poc_executions SET status=?, evidence_id=?, finished_at=? WHERE execution_id=?",
                         (status, evidence_id, datetime.now(timezone.utc).isoformat(), execution_id))

    def get_poc_executions(self, audit_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM poc_executions WHERE audit_id=? ORDER BY created_at", (audit_id,)).fetchall()
        return [dict(row) for row in rows]

    def create_audit(self, audit_id, target, state, profile, workspace):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audits VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (audit_id, target.original, json.dumps(target.to_dict()), state, profile, str(workspace), now, now),
            )

    def update_state(self, audit_id: str, state: str):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute("UPDATE audits SET state=?, updated_at=? WHERE audit_id=?", (state, now, audit_id))

    def get_audit(self, audit_id: str):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM audits WHERE audit_id=?", (audit_id,)).fetchone()
        return dict(row) if row else None

    def list_audits(self, limit: int = 50):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audits ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def delete_audit(self, audit_id: str) -> dict[str, int]:
        """Delete one audit and all database records that belong to it.

        Filesystem cleanup is intentionally handled by the application layer so the
        database never receives arbitrary paths to delete.
        """
        tables = (
            "events",
            "module_runs",
            "evidence",
            "findings",
            "approvals",
            "validations",
            "sessions",
            "exploit_intelligence",
            "exploit_reviews",
            "poc_executions",
        )
        deleted: dict[str, int] = {}
        with self.connect() as conn:
            exists = conn.execute("SELECT 1 FROM audits WHERE audit_id=?", (audit_id,)).fetchone()
            if not exists:
                return {}
            for table in tables:
                cur = conn.execute(f"DELETE FROM {table} WHERE audit_id=?", (audit_id,))
                deleted[table] = max(cur.rowcount, 0)
            cur = conn.execute("DELETE FROM audits WHERE audit_id=?", (audit_id,))
            deleted["audits"] = max(cur.rowcount, 0)
        return deleted

    def add_event(self, event):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events(audit_id,event_type,timestamp,payload_json,previous_state,new_state) VALUES (?,?,?,?,?,?)",
                (event.audit_id, event.event_type, event.timestamp, json.dumps(event.payload), event.previous_state, event.new_state),
            )

    def get_events(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM events WHERE audit_id=? ORDER BY id", (audit_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_module_run(self, audit_id: str, module: str, status: str, command=None, exit_code=None,
                       started_at=None, finished_at=None, stdout_path=None, stderr_path=None, metadata=None):
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO module_runs(audit_id,module,status,command_json,exit_code,started_at,finished_at,stdout_path,stderr_path,metadata_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (audit_id, module, status, json.dumps(command or []), exit_code, started_at, finished_at,
                 stdout_path, stderr_path, json.dumps(metadata or {})),
            )

    def get_module_runs(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM module_runs WHERE audit_id=? ORDER BY id", (audit_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_evidence(self, evidence_id: str, audit_id: str, module: str, kind: str, path: str, sha256: str, metadata=None):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                (evidence_id, audit_id, module, kind, path, sha256, now, json.dumps(metadata or {})),
            )

    def get_evidence(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE audit_id=? ORDER BY created_at", (audit_id,)).fetchall()
        return [dict(r) for r in rows]

    def upsert_finding(self, audit_id: str, finding_id: str, finding: dict):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO findings(finding_id,audit_id,finding_json,created_at,updated_at) VALUES (?,?,?,?,?)
                   ON CONFLICT(audit_id,finding_id) DO UPDATE SET finding_json=excluded.finding_json, updated_at=excluded.updated_at""",
                (finding_id, audit_id, json.dumps(finding), now, now),
            )

    def get_finding(self, audit_id: str, finding_id: str):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE audit_id=? AND finding_id=?",
                (audit_id, finding_id),
            ).fetchone()
        if not row:
            return None
        obj = json.loads(row["finding_json"])
        obj.setdefault("finding_id", row["finding_id"])
        return obj

    def get_findings(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE audit_id=? ORDER BY finding_id", (audit_id,)).fetchall()
        result = []
        for row in rows:
            obj = json.loads(row["finding_json"])
            obj.setdefault("finding_id", row["finding_id"])
            result.append(obj)
        return result

    def add_approval(self, audit_id: str, finding_id: str, action: str, operator: str,
                     *, approved: bool, note: str = "") -> str:
        approval_id = self.next_approval_id()
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?)",
                (approval_id, audit_id, finding_id, action, operator, 1 if approved else 0, note, now),
            )
        return approval_id

    def get_approvals(self, audit_id: str, finding_id: str | None = None):
        query = "SELECT * FROM approvals WHERE audit_id=?"
        params: list[object] = [audit_id]
        if finding_id:
            query += " AND finding_id=?"
            params.append(finding_id)
        query += " ORDER BY created_at"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result = [dict(r) for r in rows]
        for row in result:
            row["approved"] = bool(row["approved"])
        return result

    def has_approval(self, audit_id: str, finding_id: str, action: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT approved FROM approvals
                   WHERE audit_id=? AND finding_id=? AND action=?
                   ORDER BY created_at DESC LIMIT 1""",
                (audit_id, finding_id, action),
            ).fetchone()
        return bool(row and row["approved"])

    def add_validation(self, audit_id: str, finding_id: str, status: str, method: str,
                       operator: str, *, note: str = "", evidence_id: str | None = None) -> str:
        validation_id = self.next_validation_id()
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO validations VALUES (?,?,?,?,?,?,?,?,?)",
                (validation_id, audit_id, finding_id, status, method, operator, note, evidence_id, now),
            )
        return validation_id

    def get_validations(self, audit_id: str, finding_id: str | None = None):
        query = "SELECT * FROM validations WHERE audit_id=?"
        params: list[object] = [audit_id]
        if finding_id:
            query += " AND finding_id=?"
            params.append(finding_id)
        query += " ORDER BY created_at"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def add_session(self, audit_id: str, finding_id: str | None, session_type: str, privilege: str,
                    operator: str, *, status: str = "ACTIVE", evidence_id: str | None = None,
                    note: str = "") -> str:
        session_id = self.next_session_id()
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, audit_id, finding_id, session_type, privilege, operator, status,
                 evidence_id, note, now, None),
            )
        return session_id

    def get_sessions(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM sessions WHERE audit_id=? ORDER BY created_at", (audit_id,)).fetchall()
        return [dict(r) for r in rows]

    def close_session(self, audit_id: str, session_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE sessions SET status='CLOSED', closed_at=? WHERE audit_id=? AND session_id=?",
                (now, audit_id, session_id),
            )
        return cur.rowcount > 0

    def upsert_exploit_intelligence(self, audit_id: str, finding_id: str, data: dict) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT intelligence_id, created_at FROM exploit_intelligence WHERE audit_id=? AND finding_id=?",
                (audit_id, finding_id),
            ).fetchone()
            if existing:
                intelligence_id = existing["intelligence_id"]
                conn.execute(
                    "UPDATE exploit_intelligence SET data_json=?, updated_at=? WHERE intelligence_id=?",
                    (json.dumps(data), now, intelligence_id),
                )
            else:
                intelligence_id = self.next_intelligence_id()
                conn.execute(
                    "INSERT INTO exploit_intelligence VALUES (?,?,?,?,?,?)",
                    (intelligence_id, audit_id, finding_id, json.dumps(data), now, now),
                )
        return intelligence_id

    def get_exploit_intelligence(self, audit_id: str, finding_id: str):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM exploit_intelligence WHERE audit_id=? AND finding_id=?",
                (audit_id, finding_id),
            ).fetchone()
        if not row:
            return None
        obj = json.loads(row["data_json"])
        obj["intelligence_id"] = row["intelligence_id"]
        obj["created_at"] = row["created_at"]
        obj["updated_at"] = row["updated_at"]
        return obj

    def get_all_exploit_intelligence(self, audit_id: str):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM exploit_intelligence WHERE audit_id=? ORDER BY created_at",
                (audit_id,),
            ).fetchall()
        result = []
        for row in rows:
            obj = json.loads(row["data_json"])
            obj["intelligence_id"] = row["intelligence_id"]
            obj["created_at"] = row["created_at"]
            obj["updated_at"] = row["updated_at"]
            result.append(obj)
        return result

    def add_exploit_review(self, audit_id: str, finding_id: str, operator: str, decision: str,
                           *, module: str | None = None, note: str = "") -> str:
        review_id = self.next_exploit_review_id()
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO exploit_reviews VALUES (?,?,?,?,?,?,?,?)",
                (review_id, audit_id, finding_id, operator, decision, module, note, now),
            )
        return review_id

    def get_exploit_reviews(self, audit_id: str, finding_id: str | None = None):
        query = "SELECT * FROM exploit_reviews WHERE audit_id=?"
        params: list[object] = [audit_id]
        if finding_id:
            query += " AND finding_id=?"
            params.append(finding_id)
        query += " ORDER BY created_at"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

