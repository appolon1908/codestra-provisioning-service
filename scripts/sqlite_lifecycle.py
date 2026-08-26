#!/usr/bin/env python3
"""Consistent encrypted backup and isolated verification for provisioning SQLite."""

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CODESTRA-SQLITE-BACKUP-V1\n"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encryption_key(path: Path) -> bytes:
    value = path.read_bytes().strip()
    candidates = [value]
    try:
        candidates.append(bytes.fromhex(value.decode()))
    except (UnicodeDecodeError, ValueError):
        pass
    try:
        candidates.append(base64.b64decode(value, validate=True))
    except (ValueError, base64.binascii.Error):
        pass
    for candidate in candidates:
        if len(candidate) == 32:
            return candidate
    raise RuntimeError("backup encryption key must decode to exactly 32 bytes")


def verify_database(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        tables = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
    finally:
        connection.close()
    if integrity != "ok" or quick != "ok" or tables < 1:
        raise RuntimeError("restored database validation failed")
    return {"integrity_check": integrity, "quick_check": quick, "schema_tables": tables}


def backup(args: argparse.Namespace) -> None:
    source = Path(args.database)
    destination = Path(args.destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    final = destination / f"provisioning-{timestamp}.sqlite3.aes256gcm"
    metadata_path = final.with_suffix(final.suffix + ".json")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        snapshot = Path(temporary) / "snapshot.sqlite3"
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=30)
        target_db = sqlite3.connect(snapshot)
        try:
            source_db.backup(target_db)
        finally:
            target_db.close()
            source_db.close()
        validation = verify_database(snapshot)
        plaintext_checksum = sha256(snapshot)
        nonce = os.urandom(12)
        ciphertext = AESGCM(encryption_key(Path(args.key_file))).encrypt(
            nonce, snapshot.read_bytes(), MAGIC
        )
        pending = Path(temporary) / final.name
        pending.write_bytes(MAGIC + nonce + ciphertext)
        os.chmod(pending, 0o600)
        encrypted_checksum = sha256(pending)
        os.replace(pending, final)
    metadata = {
        "format": "codestra-sqlite-backup-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "source": str(source),
        "backup": final.name,
        "encrypted": True,
        "plaintext_sha256": plaintext_checksum,
        "encrypted_sha256": encrypted_checksum,
        "size_bytes": final.stat().st_size,
        "retention_days": args.retention_days,
        "duration_seconds": round(time.monotonic() - started, 3),
        **validation,
    }
    metadata_path.write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(metadata_path, 0o600)
    latest_metadata = destination / "latest.json"
    temporary_metadata = destination / ".latest.json.tmp"
    temporary_metadata.write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(temporary_metadata, 0o600)
    os.replace(temporary_metadata, latest_metadata)
    cutoff = time.time() - args.retention_days * 86400
    for candidate in destination.glob("provisioning-*.sqlite3.aes256gcm*"):
        if candidate.stat().st_mtime < cutoff:
            candidate.unlink()
    print(json.dumps(metadata, sort_keys=True))


def restore_verify(args: argparse.Namespace) -> None:
    backup_path = Path(args.backup)
    payload = backup_path.read_bytes()
    if not payload.startswith(MAGIC):
        raise RuntimeError("unsupported backup format")
    encrypted_checksum = sha256(backup_path)
    offset = len(MAGIC)
    nonce, ciphertext = payload[offset : offset + 12], payload[offset + 12 :]
    plaintext = AESGCM(encryption_key(Path(args.key_file))).decrypt(
        nonce, ciphertext, MAGIC
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(dir=args.temporary_directory) as temporary:
        restored = Path(temporary) / "provisioning-restored.sqlite3"
        restored.write_bytes(plaintext)
        os.chmod(restored, 0o600)
        validation = verify_database(restored)
    result = {
        "backup": backup_path.name,
        "encrypted_sha256": encrypted_checksum,
        "restore_rto_seconds": round(time.monotonic() - started, 3),
        **validation,
    }
    print(json.dumps(result, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("backup")
    create.add_argument("--database", required=True)
    create.add_argument("--destination", required=True)
    create.add_argument("--key-file", required=True)
    create.add_argument("--retention-days", type=int, default=30)
    create.set_defaults(handler=backup)
    verify = commands.add_parser("restore-verify")
    verify.add_argument("--backup", required=True)
    verify.add_argument("--key-file", required=True)
    verify.add_argument("--temporary-directory", default=None)
    verify.set_defaults(handler=restore_verify)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.handler(arguments)
