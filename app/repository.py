import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .contracts import (
    ExecutionResult,
    Operation,
    RequestExecution,
    StepCommand,
    StepResult,
    StepState,
)


def now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class IdempotencyConflict(RuntimeError):
    pass


class StateRepository:
    """Durable single-instance state store with atomic claims and WAL recovery."""

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS executions (
              request_id TEXT PRIMARY KEY,
              employee_id TEXT NOT NULL,
              correlation_id TEXT NOT NULL UNIQUE,
              idempotency_hash TEXT NOT NULL UNIQUE,
              request_hash TEXT NOT NULL,
              state TEXT NOT NULL,
              result_json TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS steps (
              step_id TEXT PRIMARY KEY,
              request_id TEXT NOT NULL REFERENCES executions(request_id),
              sequence INTEGER NOT NULL,
              idempotency_hash TEXT NOT NULL UNIQUE,
              command_json TEXT NOT NULL,
              state TEXT NOT NULL,
              attempt_count INTEGER NOT NULL DEFAULT 0,
              max_attempts INTEGER NOT NULL,
              retry_class TEXT,
              result_json TEXT,
              error_code TEXT,
              next_retry_at TEXT,
              claimed_at TEXT,
              updated_at TEXT NOT NULL,
              UNIQUE(request_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS ix_steps_runnable
              ON steps(state,next_retry_at,sequence);
            CREATE TABLE IF NOT EXISTS dead_letters (
              step_id TEXT PRIMARY KEY REFERENCES steps(step_id),
              request_id TEXT NOT NULL,
              error_code TEXT NOT NULL,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS callback_events (
              event_id TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              delivered INTEGER NOT NULL DEFAULT 0,
              attempt_count INTEGER NOT NULL DEFAULT 0,
              next_retry_at TEXT,
              last_error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replay_jti (
              jti_hash TEXT PRIMARY KEY,
              expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_windows (
              subject_hash TEXT NOT NULL,
              window_start INTEGER NOT NULL,
              count INTEGER NOT NULL,
              PRIMARY KEY(subject_hash,window_start)
            );
            CREATE TABLE IF NOT EXISTS encrypted_credentials (
              reference TEXT PRIMARY KEY,
              ciphertext BLOB NOT NULL,
              fingerprint TEXT NOT NULL,
              created_at TEXT NOT NULL,
              revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS compensation_actions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_id TEXT NOT NULL,
              step_id TEXT NOT NULL,
              action TEXT NOT NULL,
              state TEXT NOT NULL,
              evidence_hash TEXT,
              error_code TEXT,
              created_at TEXT NOT NULL,
              UNIQUE(request_id,step_id,action)
            );
            CREATE TABLE IF NOT EXISTS mock_mailboxes (
              employee_id TEXT PRIMARY KEY,
              email_address TEXT NOT NULL UNIQUE,
              external_mailbox_id TEXT NOT NULL UNIQUE,
              aliases_json TEXT NOT NULL DEFAULT '[]',
              provisioning_state TEXT NOT NULL,
              created_at TEXT NOT NULL,
              activated_at TEXT,
              suspended_at TEXT,
              terminated_at TEXT,
              credential_reference TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sip_browser_sessions (
              session_id TEXT PRIMARY KEY,
              employee_id TEXT NOT NULL,
              keycloak_subject TEXT NOT NULL,
              odoo_employee_id TEXT NOT NULL,
              vicidial_username TEXT NOT NULL,
              endpoint INTEGER NOT NULL,
              campaign TEXT NOT NULL,
              role TEXT NOT NULL,
              browser_session_binding TEXT NOT NULL UNIQUE,
              credential_fingerprint TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              state TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_sip_browser_active_employee
              ON sip_browser_sessions(employee_id)
              WHERE state='active';
            """
        )

    def transition_mock_mailbox(
        self,
        employee_id: str,
        operation: str,
        email_address: str | None = None,
    ) -> dict[str, Any]:
        """Durable, delivery-free mailbox mock used only when provider access is absent."""
        allowed = {
            "create_disabled": "disabled",
            "verify": None,
            "activate": "active",
            "suspend": "suspended",
            "reactivate": "active",
            "terminate": "terminated",
            "reconcile": None,
        }
        if operation not in allowed:
            raise ValueError("mock_mailbox_operation_unsupported")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM mock_mailboxes WHERE employee_id=?",
                (employee_id,),
            ).fetchone()
            if operation == "create_disabled":
                if not email_address:
                    raise ValueError("mock_mailbox_email_required")
                external_id = "mock:" + digest(email_address)[:32]
                if row is None:
                    timestamp = iso()
                    try:
                        self._connection.execute(
                            """INSERT INTO mock_mailboxes
                               (employee_id,email_address,external_mailbox_id,
                                provisioning_state,created_at,credential_reference)
                               VALUES(?,?,?,'disabled',?,?)""",
                            (
                                employee_id,
                                email_address,
                                external_id,
                                timestamp,
                                "mock:no-provider-credential",
                            ),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise IdempotencyConflict(
                            "mock_mailbox_address_collision"
                        ) from exc
                    row = self._connection.execute(
                        "SELECT * FROM mock_mailboxes WHERE employee_id=?",
                        (employee_id,),
                    ).fetchone()
                elif row["email_address"] != email_address:
                    raise IdempotencyConflict("mock_mailbox_identity_conflict")
            elif row is None:
                raise LookupError("mock_mailbox_not_found")
            next_state = allowed[operation]
            if next_state is not None and operation != "create_disabled":
                timestamp_column = {
                    "activate": "activated_at",
                    "reactivate": "activated_at",
                    "suspend": "suspended_at",
                    "terminate": "terminated_at",
                }[operation]
                self._connection.execute(
                    f"""UPDATE mock_mailboxes
                        SET provisioning_state=?,{timestamp_column}=?
                        WHERE employee_id=?""",
                    (next_state, iso(), employee_id),
                )
                row = self._connection.execute(
                    "SELECT * FROM mock_mailboxes WHERE employee_id=?",
                    (employee_id,),
                ).fetchone()
            return dict(row)

    def active_sip_browser_session(self, employee_id: str) -> dict | None:
        with self._lock:
            # Expiration is authoritative even if the worker has not run a
            # cleanup pass yet. Marking it here also releases the unique
            # active-employee constraint for a subsequent login.
            self._connection.execute(
                """UPDATE sip_browser_sessions SET state='expired',updated_at=?
                   WHERE employee_id=? AND state='active' AND expires_at<=?""",
                (iso(), employee_id, iso()),
            )
            row = self._connection.execute(
                """SELECT * FROM sip_browser_sessions
                   WHERE employee_id=? AND state='active' AND expires_at>?""",
                (employee_id, iso()),
            ).fetchone()
            return dict(row) if row else None

    def sip_browser_session(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM sip_browser_sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
            return dict(row) if row else None

    def create_sip_browser_session(self, values: dict[str, Any]) -> dict:
        timestamp = iso()
        with self._lock:
            self._connection.execute(
                """INSERT INTO sip_browser_sessions
                   (session_id,employee_id,keycloak_subject,odoo_employee_id,
                    vicidial_username,endpoint,campaign,role,
                    browser_session_binding,credential_fingerprint,expires_at,
                    state,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',?,?)""",
                (
                    values["session_id"],
                    values["employee_id"],
                    values["keycloak_subject"],
                    values["odoo_employee_id"],
                    values["vicidial_username"],
                    values["endpoint"],
                    values["campaign"],
                    values["role"],
                    values["browser_session_binding"],
                    values["credential_fingerprint"],
                    values["expires_at"],
                    timestamp,
                    timestamp,
                ),
            )
        return self.sip_browser_session(values["session_id"]) or {}

    def renew_sip_browser_session(
        self, session_id: str, fingerprint: str, expires_at: str
    ) -> dict:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE sip_browser_sessions
                   SET credential_fingerprint=?,expires_at=?,updated_at=?
                   WHERE session_id=? AND state='active'""",
                (fingerprint, expires_at, iso(), session_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("sip_browser_session_not_active")
        return self.sip_browser_session(session_id) or {}

    def expire_sip_browser_session(self, session_id: str) -> dict:
        with self._lock:
            self._connection.execute(
                """UPDATE sip_browser_sessions SET state='expired',updated_at=?
                   WHERE session_id=? AND state='active'""",
                (iso(), session_id),
            )
        return self.sip_browser_session(session_id) or {}

    def revoke_sip_browser_session(self, session_id: str) -> dict:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE sip_browser_sessions SET state='revoked',updated_at=?
                   WHERE session_id=? AND state='active'""",
                (iso(), session_id),
            )
            if cursor.rowcount != 1:
                row = self.sip_browser_session(session_id)
                if row and row["state"] == "revoked":
                    return row
                raise LookupError("sip_browser_session_not_active")
        return self.sip_browser_session(session_id) or {}

    def _transaction(self):
        return self._connection

    def begin_execution(
        self, execution: RequestExecution, request_hash: str
    ) -> tuple[ExecutionResult | None, bool]:
        key_hash = digest(execution.idempotency_key)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT request_hash,result_json FROM executions "
                    "WHERE idempotency_hash=?",
                    (key_hash,),
                ).fetchone()
                if existing:
                    if existing["request_hash"] != request_hash:
                        raise IdempotencyConflict("idempotency_payload_conflict")
                    self._connection.execute("COMMIT")
                    result = (
                        ExecutionResult.model_validate_json(existing["result_json"])
                        if existing["result_json"]
                        else None
                    )
                    return result, True
                timestamp = iso()
                self._connection.execute(
                    """INSERT INTO executions
                       (request_id,employee_id,correlation_id,idempotency_hash,
                        request_hash,state,created_at,updated_at)
                       VALUES(?,?,?,?,?,'pending',?,?)""",
                    (
                        execution.request_id,
                        execution.employee_id,
                        execution.correlation_id,
                        key_hash,
                        request_hash,
                        timestamp,
                        timestamp,
                    ),
                )
                for step in sorted(execution.steps, key=lambda item: item.sequence):
                    self._connection.execute(
                        """INSERT INTO steps
                           (step_id,request_id,sequence,idempotency_hash,command_json,
                            state,max_attempts,updated_at)
                           VALUES(?,?,?,?,?,'pending',?,?)""",
                        (
                            step.step_id,
                            execution.request_id,
                            step.sequence,
                            digest(step.idempotency_key),
                            step.model_dump_json(),
                            step.max_attempts,
                            timestamp,
                        ),
                    )
                self._connection.execute("COMMIT")
                return None, False
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def claim_next(self, request_id: str) -> StepCommand | None:
        timestamp = iso()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                blocked = self._connection.execute(
                    """SELECT 1 FROM steps
                       WHERE request_id=? AND state NOT IN ('succeeded','verified',
                           'compensated') AND state NOT IN ('pending','retry_wait')
                       LIMIT 1""",
                    (request_id,),
                ).fetchone()
                if blocked:
                    self._connection.execute("COMMIT")
                    return None
                row = self._connection.execute(
                    """SELECT * FROM steps
                       WHERE request_id=?
                         AND state IN ('pending','retry_wait')
                         AND (next_retry_at IS NULL OR next_retry_at<=?)
                         AND NOT EXISTS (
                           SELECT 1 FROM steps prior
                           WHERE prior.request_id=steps.request_id
                             AND prior.sequence<steps.sequence
                             AND prior.state NOT IN ('succeeded','verified','compensated')
                         )
                       ORDER BY sequence LIMIT 1""",
                    (request_id, timestamp),
                ).fetchone()
                if not row:
                    self._connection.execute("COMMIT")
                    return None
                self._connection.execute(
                    """UPDATE steps SET state='running',attempt_count=attempt_count+1,
                       claimed_at=?,updated_at=? WHERE step_id=?""",
                    (timestamp, timestamp, row["step_id"]),
                )
                self._connection.execute(
                    "UPDATE executions SET state='running',updated_at=? WHERE request_id=?",
                    (timestamp, request_id),
                )
                self._connection.execute("COMMIT")
                return StepCommand.model_validate_json(row["command_json"])
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def complete_step(self, step_id: str, state: StepState, result: dict[str, Any]):
        if state not in {StepState.SUCCEEDED, StepState.VERIFIED, StepState.COMPENSATED}:
            raise ValueError("invalid terminal success state")
        with self._lock:
            self._connection.execute(
                """UPDATE steps SET state=?,result_json=?,error_code=NULL,
                   next_retry_at=NULL,claimed_at=NULL,updated_at=? WHERE step_id=?""",
                (state, json.dumps(result, sort_keys=True), iso(), step_id),
            )

    def fail_step(
        self,
        step_id: str,
        error_code: str,
        retry_class: str,
        retry_at: datetime | None,
    ) -> StepState:
        with self._lock:
            row = self._connection.execute(
                "SELECT request_id,attempt_count,max_attempts FROM steps WHERE step_id=?",
                (step_id,),
            ).fetchone()
            exhausted = row["attempt_count"] >= row["max_attempts"]
            state = (
                StepState.DEAD_LETTER
                if exhausted or retry_class == "permanent"
                else StepState.RETRY_WAIT
            )
            self._connection.execute(
                """UPDATE steps SET state=?,retry_class=?,error_code=?,next_retry_at=?,
                   claimed_at=NULL,updated_at=? WHERE step_id=?""",
                (
                    state,
                    retry_class,
                    error_code,
                    iso(retry_at) if retry_at and state == StepState.RETRY_WAIT else None,
                    iso(),
                    step_id,
                ),
            )
            if state == StepState.DEAD_LETTER:
                self._connection.execute(
                    """INSERT OR IGNORE INTO dead_letters
                       (step_id,request_id,error_code,created_at) VALUES(?,?,?,?)""",
                    (step_id, row["request_id"], error_code, iso()),
                )
            return state

    def schedule_step_retry(self, request_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                """SELECT step_id FROM steps WHERE request_id=?
                   AND state IN ('failed','dead_letter','retry_wait')
                   AND attempt_count < max_attempts
                   ORDER BY sequence LIMIT 1""",
                (request_id,),
            ).fetchone()
            if not row:
                return False
            self._connection.execute(
                """UPDATE steps SET state='retry_wait',next_retry_at=?,claimed_at=NULL,
                   updated_at=? WHERE step_id=?""",
                (iso(), iso(), row["step_id"]),
            )
            self._connection.execute(
                "UPDATE dead_letters SET resolved_at=? WHERE step_id=?",
                (iso(), row["step_id"]),
            )
            return True

    def successful_commands(self, request_id: str) -> list[StepCommand]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT command_json FROM steps WHERE request_id=?
                   AND state IN ('succeeded','verified') ORDER BY sequence DESC""",
                (request_id,),
            ).fetchall()
            return [StepCommand.model_validate_json(row["command_json"]) for row in rows]

    def record_compensation(
        self,
        request_id: str,
        step_id: str,
        action: str,
        state: str,
        evidence_hash: str | None = None,
        error_code: str | None = None,
    ):
        with self._lock:
            self._connection.execute(
                """INSERT INTO compensation_actions
                   (request_id,step_id,action,state,evidence_hash,error_code,created_at)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(request_id,step_id,action)
                   DO UPDATE SET state=excluded.state,evidence_hash=excluded.evidence_hash,
                     error_code=excluded.error_code""",
                (
                    request_id,
                    step_id,
                    action,
                    state,
                    evidence_hash,
                    error_code,
                    iso(),
                ),
            )

    def cancel_pending(self, request_id: str) -> int:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE steps SET state='compensated',error_code='request_cancelled',
                   next_retry_at=NULL,claimed_at=NULL,updated_at=?
                   WHERE request_id=? AND state IN ('pending','retry_wait')""",
                (iso(), request_id),
            )
            return cursor.rowcount

    def recover_stale(self, claim_timeout_seconds: int) -> int:
        cutoff = iso(now() - timedelta(seconds=claim_timeout_seconds))
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE steps SET state='retry_wait',next_retry_at=?,claimed_at=NULL,
                   error_code='worker_restart_recovery',updated_at=?
                   WHERE state='running' AND claimed_at<?""",
                (iso(), iso(), cutoff),
            )
            return cursor.rowcount

    def pending_request_ids(self) -> list[str]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT DISTINCT request_id FROM steps
                   WHERE state IN ('pending','retry_wait')
                     AND (next_retry_at IS NULL OR next_retry_at<=?)
                   ORDER BY request_id""",
                (iso(),),
            ).fetchall()
            return [row["request_id"] for row in rows]

    def request_result(self, request_id: str, replayed: bool = False) -> ExecutionResult | None:
        with self._lock:
            execution = self._connection.execute(
                "SELECT * FROM executions WHERE request_id=?", (request_id,)
            ).fetchone()
            if not execution:
                return None
            steps = self._connection.execute(
                "SELECT * FROM steps WHERE request_id=? ORDER BY sequence",
                (request_id,),
            ).fetchall()
            results = []
            for row in steps:
                result = json.loads(row["result_json"]) if row["result_json"] else {}
                results.append(
                    StepResult(
                        step_id=row["step_id"],
                        target_system=result.get(
                            "target_system",
                            json.loads(row["command_json"])["target_system"],
                        ),
                        operation=result.get(
                            "operation", json.loads(row["command_json"])["operation"]
                        ),
                        state=row["state"],
                        attempt_count=row["attempt_count"],
                        external_id=result.get("external_id"),
                        external_reference=result.get("external_reference"),
                        credential_reference=result.get("credential_reference"),
                        evidence_hash=result.get("evidence_hash"),
                        error_code=row["error_code"],
                        retry_at=row["next_retry_at"],
                        replayed=replayed,
                    )
                )
            states = {item.state for item in results}
            if states <= {StepState.SUCCEEDED, StepState.VERIFIED, StepState.COMPENSATED}:
                state = "completed"
            elif StepState.DEAD_LETTER in states:
                state = "dead_letter"
            elif StepState.RETRY_WAIT in states:
                state = "retry_wait"
            elif StepState.RUNNING in states:
                state = "running"
            else:
                state = "pending"
            output = ExecutionResult(
                request_id=request_id,
                employee_id=execution["employee_id"],
                correlation_id=execution["correlation_id"],
                state=state,
                step_results=results,
                replayed=replayed,
            )
            self._connection.execute(
                """UPDATE executions SET state=?,result_json=?,updated_at=?
                   WHERE request_id=?""",
                (state, output.model_dump_json(), iso(), request_id),
            )
            return output

    def employee_results(self, employee_id: str) -> list[StepResult]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT s.* FROM steps s JOIN executions e USING(request_id)
                   WHERE e.employee_id=? ORDER BY s.updated_at DESC""",
                (employee_id,),
            ).fetchall()
        latest: dict[str, StepResult] = {}
        for row in rows:
            command = json.loads(row["command_json"])
            system = command["target_system"]
            if system in latest:
                continue
            result = json.loads(row["result_json"]) if row["result_json"] else {}
            latest[system] = StepResult(
                step_id=row["step_id"],
                target_system=system,
                operation=command["operation"],
                state=row["state"],
                attempt_count=row["attempt_count"],
                external_id=result.get("external_id"),
                external_reference=result.get("external_reference"),
                credential_reference=result.get("credential_reference"),
                evidence_hash=result.get("evidence_hash"),
                error_code=row["error_code"],
                retry_at=row["next_retry_at"],
            )
        return list(latest.values())

    def employee_commands(self, employee_id: str) -> list[StepCommand]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT s.command_json FROM steps s
                   JOIN executions e USING(request_id)
                   WHERE e.employee_id=? AND s.state IN ('succeeded','verified')
                   ORDER BY s.updated_at DESC""",
                (employee_id,),
            ).fetchall()
        latest: dict[str, StepCommand] = {}
        canonical: dict[str, StepCommand] = {}
        for row in rows:
            command = StepCommand.model_validate_json(row["command_json"])
            system = command.target_system.value
            latest.setdefault(system, command)
            if command.operation == Operation.CREATE_DISABLED:
                canonical[system] = command
        # Lifecycle and browser-session authorization must use the original
        # successful binding payload. Later suspend/reactivate/terminate steps
        # commonly carry an intentionally minimal payload and must not erase
        # provider identifiers, campaigns, roles, or endpoint assignment.
        return [canonical.get(system, command) for system, command in latest.items()]

    def accept_jti(self, jti: str, expires_at: int) -> bool:
        with self._lock:
            current = int(now().timestamp())
            self._connection.execute("DELETE FROM replay_jti WHERE expires_at<?", (current,))
            try:
                self._connection.execute(
                    "INSERT INTO replay_jti(jti_hash,expires_at) VALUES(?,?)",
                    (digest(jti), expires_at),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def check_rate(self, subject: str, limit: int, window_seconds: int) -> bool:
        current = int(now().timestamp())
        window = current - current % window_seconds
        subject_hash = digest(subject)
        with self._lock:
            self._connection.execute(
                """INSERT INTO rate_windows(subject_hash,window_start,count)
                   VALUES(?,?,1) ON CONFLICT(subject_hash,window_start)
                   DO UPDATE SET count=count+1""",
                (subject_hash, window),
            )
            count = self._connection.execute(
                "SELECT count FROM rate_windows WHERE subject_hash=? AND window_start=?",
                (subject_hash, window),
            ).fetchone()["count"]
            self._connection.execute(
                "DELETE FROM rate_windows WHERE window_start<?",
                (window - window_seconds * 2,),
            )
            return count <= limit

    def enqueue_callback(self, event_id: str, payload: dict[str, Any]):
        timestamp = iso()
        with self._lock:
            self._connection.execute(
                """INSERT OR IGNORE INTO callback_events
                   (event_id,payload_json,created_at,updated_at)
                   VALUES(?,?,?,?)""",
                (event_id, json.dumps(payload, sort_keys=True, default=str), timestamp, timestamp),
            )

    def due_callbacks(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM callback_events WHERE delivered=0 AND attempt_count<8
                   AND (next_retry_at IS NULL OR next_retry_at<=?)
                   ORDER BY created_at LIMIT ?""",
                (iso(), limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_callback(
        self, event_id: str, delivered: bool, error: str | None, retry_at: datetime | None
    ):
        with self._lock:
            row = self._connection.execute(
                "SELECT attempt_count FROM callback_events WHERE event_id=?", (event_id,)
            ).fetchone()
            exhausted = bool(row and row["attempt_count"] + 1 >= 8 and not delivered)
            self._connection.execute(
                """UPDATE callback_events SET delivered=?,attempt_count=attempt_count+1,
                   last_error=?,next_retry_at=?,updated_at=? WHERE event_id=?""",
                (
                    1 if delivered else (-1 if exhausted else 0),
                    "callback_retry_exhausted" if exhausted else error,
                    iso(retry_at) if retry_at and not exhausted else None,
                    iso(),
                    event_id,
                ),
            )

    def store_encrypted_credential(
        self, reference: str, ciphertext: bytes, fingerprint: str
    ):
        with self._lock:
            self._connection.execute(
                """INSERT INTO encrypted_credentials
                   (reference,ciphertext,fingerprint,created_at)
                   VALUES(?,?,?,?) ON CONFLICT(reference) DO NOTHING""",
                (reference, ciphertext, fingerprint, iso()),
            )

    def revoke_credential(self, reference: str):
        with self._lock:
            self._connection.execute(
                "UPDATE encrypted_credentials SET revoked_at=? WHERE reference=?",
                (iso(), reference),
            )

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "pending_steps": self._connection.execute(
                    "SELECT count(*) FROM steps WHERE state IN ('pending','retry_wait','running')"
                ).fetchone()[0],
                "dead_letters": self._connection.execute(
                    "SELECT count(*) FROM dead_letters WHERE resolved_at IS NULL"
                ).fetchone()[0],
                "pending_callbacks": self._connection.execute(
                    "SELECT count(*) FROM callback_events WHERE delivered=0"
                ).fetchone()[0],
                "failed_callbacks": self._connection.execute(
                    "SELECT count(*) FROM callback_events WHERE delivered=-1"
                ).fetchone()[0],
                "failed_compensations": self._connection.execute(
                    "SELECT count(*) FROM compensation_actions WHERE state='failed'"
                ).fetchone()[0],
            }
