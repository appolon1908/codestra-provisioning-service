import argparse
import json
import sqlite3

from scripts.sqlite_lifecycle import backup, restore_verify


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
            retention_days=30,
        )
    )
    created = json.loads(capsys.readouterr().out)
    encrypted = destination / created["backup"]
    assert encrypted.read_bytes()[:16] != database.read_bytes()[:16]
    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert encrypted.with_suffix(encrypted.suffix + ".json").exists()

    restore_verify(
        argparse.Namespace(
            backup=str(encrypted),
            key_file=str(key),
            temporary_directory=str(tmp_path),
        )
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["integrity_check"] == "ok"
    assert restored["quick_check"] == "ok"
    assert restored["schema_tables"] == 1


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
