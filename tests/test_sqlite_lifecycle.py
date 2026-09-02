import argparse
import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

import scripts.sqlite_lifecycle as lifecycle
from scripts.sqlite_lifecycle import backup, restore_verify

RELEASE_SHA = "1" * 40
IMAGE_REFERENCE = "ghcr.io/appolon1908-hue/codestra-provisioning-service@sha256:" + "2" * 64
ROOT = Path(__file__).resolve().parents[1]


def test_encrypted_backup_and_isolated_restore(tmp_path, capsys):
    database = tmp_path / "source.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("create table evidence (id integer primary key, value text)")
    connection.execute("insert into evidence(value) values ('preserved')")
    connection.commit()
    connection.close()
    key = tmp_path / "backup.key"
    key.write_bytes(b"k" * 32)
    destination = tmp_path / "backups"

    backup(
        argparse.Namespace(
            database=str(database),
            destination=str(destination),
            key_file=str(key),
            temporary_directory=str(tmp_path),
            release_sha=RELEASE_SHA,
            image_reference=IMAGE_REFERENCE,
            retention_days=30,
        )
    )
    created = json.loads(capsys.readouterr().out)
    encrypted = destination / created["backup"]
    assert encrypted.read_bytes()[:16] != database.read_bytes()[:16]
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert encrypted.with_suffix(encrypted.suffix + ".json").exists()
    assert json.loads((destination / "latest.json").read_text())["backup"] == encrypted.name
    assert created["format"] == "codestra-sqlite-backup-v2"
    assert created["release_sha"] == RELEASE_SHA
    assert created["image_reference"] == IMAGE_REFERENCE

    restore_verify(
        argparse.Namespace(
            backup=str(encrypted),
            key_file=str(key),
            temporary_directory=str(tmp_path),
            expected_release_sha=RELEASE_SHA,
            expected_image_reference=IMAGE_REFERENCE,
            max_age_seconds=3600,
        )
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["integrity_check"] == "ok"
    assert restored["quick_check"] == "ok"
    assert restored["schema_tables"] == 1
    assert restored["release_sha"] == RELEASE_SHA
    assert restored["image_reference"] == IMAGE_REFERENCE
    assert json.loads((destination / "latest.json").read_text())[
        "restore_rehearsal_timestamp_seconds"
    ] > 0


def _create_backup(tmp_path):
    database = tmp_path / "source.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("create table evidence (id integer primary key, value text)")
    connection.commit()
    connection.close()
    key = tmp_path / "backup.key"
    key.write_bytes(b"k" * 32)
    destination = tmp_path / "backups"
    backup(
        argparse.Namespace(
            database=str(database),
            destination=str(destination),
            key_file=str(key),
            temporary_directory=str(tmp_path),
            release_sha=RELEASE_SHA,
            image_reference=IMAGE_REFERENCE,
            retention_days=30,
        )
    )
    metadata = json.loads((destination / "latest.json").read_text())
    return destination / metadata["backup"], key


def _restore_args(artifact, key, tmp_path, **overrides):
    values = {
        "backup": str(artifact),
        "key_file": str(key),
        "temporary_directory": str(tmp_path),
        "expected_release_sha": RELEASE_SHA,
        "expected_image_reference": IMAGE_REFERENCE,
        "max_age_seconds": 3600,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_restore_rejects_header_tampering(tmp_path, capsys):
    artifact, key = _create_backup(tmp_path)
    capsys.readouterr()
    payload = bytearray(artifact.read_bytes())
    marker = RELEASE_SHA.encode()
    offset = payload.index(marker)
    payload[offset] = ord("3")
    artifact.write_bytes(payload)
    with pytest.raises(InvalidTag):
        restore_verify(
            _restore_args(
                artifact, key, tmp_path, expected_release_sha="3" + "1" * 39
            )
        )


def test_restore_rejects_wrong_expected_tuple_before_plaintext_write(tmp_path, capsys):
    artifact, key = _create_backup(tmp_path)
    capsys.readouterr()
    wrong_release = "3" * 40
    try:
        restore_verify(
            _restore_args(artifact, key, tmp_path, expected_release_sha=wrong_release)
        )
    except RuntimeError as error:
        assert str(error) == "backup release SHA mismatch"
    else:
        raise AssertionError("wrong release tuple was accepted")


def test_restore_rejects_nonpositive_recovery_age_limit(tmp_path, capsys):
    artifact, key = _create_backup(tmp_path)
    capsys.readouterr()
    # A zero-second limit is rejected before any decryption or plaintext write.
    try:
        restore_verify(_restore_args(artifact, key, tmp_path, max_age_seconds=0))
    except RuntimeError as error:
        assert str(error) == "maximum recovery age must be positive"
    else:
        raise AssertionError("invalid recovery age limit was accepted")


def test_restore_rejects_authenticated_stale_backup(tmp_path, capsys, monkeypatch):
    real_datetime = lifecycle.datetime

    class OldDatetime(real_datetime):
        @classmethod
        def now(cls, timezone=None):
            return real_datetime.now(timezone) - timedelta(days=2)

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "datetime", OldDatetime)
        artifact, key = _create_backup(tmp_path)
    capsys.readouterr()
    with pytest.raises(
        RuntimeError, match="authenticated backup is outside the recovery age limit"
    ):
        restore_verify(_restore_args(artifact, key, tmp_path, max_age_seconds=3600))


def test_systemd_units_require_tmpfs_and_exact_release_tuple():
    backup_unit = (
        ROOT / "deploy/systemd/codestra-provisioning-sqlite-backup.service"
    ).read_text()
    restore_runner = (ROOT / "scripts/run_sqlite_restore_rehearsal.sh").read_text()
    assert "--tmpfs /tmp:rw,noexec,nosuid" in backup_unit
    assert "--temporary-directory /tmp" in backup_unit
    assert "--release-sha ${PROVISIONING_RELEASE_SHA}" in backup_unit
    assert "--image-reference ${PROVISIONING_IMAGE}" in backup_unit
    assert "--expected-release-sha" in restore_runner
    assert "--expected-image-reference" in restore_runner
    assert "--max-age-seconds" in restore_runner
    assert "memory_bytes=$((scratch_bytes + runtime_overhead))" in restore_runner
    assert '--memory "${memory_bytes}b"' in restore_runner


def test_repository_database_files_are_private(tmp_path):
    from app.repository import StateRepository

    repository = StateRepository(str(tmp_path / "state.sqlite3"))
    status = repository.durability_status()
    assert status == {
        "journal_mode": "wal",
        "synchronous": 2,
        "busy_timeout": 30000,
        "foreign_keys": 1,
        "exists": True,
        "writable": True,
        "size_bytes": status["size_bytes"],
        "mode": 0o600,
    }


def test_repository_migrates_legacy_schema(tmp_path):
    from app.repository import StateRepository

    database = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        "create table executions (request_id text primary key, employee_id text, "
        "correlation_id text, idempotency_hash text, request_hash text, state text, "
        "result_json text, created_at text, updated_at text)"
    )
    connection.execute(
        "create table compensation_actions (id integer primary key, request_id text, "
        "step_id text, action text, state text, evidence_hash text, error_code text, "
        "created_at text, unique(request_id,step_id,action))"
    )
    connection.commit()
    connection.close()
    StateRepository(str(database))
    connection = sqlite3.connect(database)
    compensation = {
        row[1] for row in connection.execute("pragma table_info(compensation_actions)")
    }
    executions = {row[1] for row in connection.execute("pragma table_info(executions)")}
    connection.close()
    assert {"attempt_count", "max_attempts", "next_retry_at", "updated_at"} <= compensation
    assert "cancelled_at" in executions
