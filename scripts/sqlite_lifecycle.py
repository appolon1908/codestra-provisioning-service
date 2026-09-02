#!/usr/bin/env python3
"""Consistent encrypted backup and isolated verification for provisioning SQLite."""

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import struct
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CODESTRA-SQLITE-BACKUP-V2\n"
RELEASE_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
MAX_HEADER_BYTES = 64 * 1024


def canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def validate_release_identity(release_sha: str, image_reference: str) -> None:
    if not RELEASE_SHA.fullmatch(release_sha):
        raise RuntimeError("release SHA must be immutable")
    if not IMAGE_REFERENCE.fullmatch(image_reference):
        raise RuntimeError("image reference must use an immutable registry digest")


def decode_payload(payload: bytes) -> tuple[dict[str, object], bytes, bytes, bytes]:
    if not payload.startswith(MAGIC):
        raise RuntimeError("unsupported backup format")
    offset = len(MAGIC)
    if len(payload) < offset + 4:
        raise RuntimeError("backup header is truncated")
    header_size = struct.unpack(">I", payload[offset : offset + 4])[0]
    if not 1 <= header_size <= MAX_HEADER_BYTES:
        raise RuntimeError("backup header size is invalid")
    header_start = offset + 4
    header_end = header_start + header_size
    if len(payload) < header_end + 13:
        raise RuntimeError("backup payload is truncated")
    header_bytes = payload[header_start:header_end]
    try:
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("backup header is invalid") from error
    if not isinstance(header, dict) or canonical_json(header) != header_bytes:
        raise RuntimeError("backup header is not canonical")
    aad = MAGIC + payload[offset : offset + 4] + header_bytes
    return header, aad, payload[header_end : header_end + 12], payload[header_end + 12 :]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
    validate_release_identity(args.release_sha, args.image_reference)
    work_root = Path(args.temporary_directory)
    if not work_root.is_dir() or work_root.is_symlink():
        raise RuntimeError("backup temporary directory is invalid")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    final = destination / f"provisioning-{timestamp}.sqlite3.aes256gcm"
    pending = destination / f".{final.name}.partial"
    metadata_path = final.with_suffix(final.suffix + ".json")
    metadata_pending = destination / f".{metadata_path.name}.partial"
    if any(
        path.exists() for path in (final, metadata_path, pending, metadata_pending)
    ):
        raise RuntimeError("backup timestamp collision")
    started = time.monotonic()
    previous_metadata = destination / "latest.json"
    previous = {}
    if previous_metadata.is_file():
        try:
            previous = json.loads(previous_metadata.read_text())
        except (OSError, ValueError, json.JSONDecodeError):
            previous = {}
    with tempfile.TemporaryDirectory(dir=work_root) as temporary:
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
        created_at = datetime.now(UTC).isoformat()
        authenticated = {
            "format": "codestra-sqlite-backup-v2",
            "created_at": created_at,
            "source_database": source.name,
            "release_sha": args.release_sha,
            "image_reference": args.image_reference,
            "plaintext_sha256": plaintext_checksum,
            **validation,
        }
        header = canonical_json(authenticated)
        header_size = struct.pack(">I", len(header))
        aad = MAGIC + header_size + header
        nonce = os.urandom(12)
        ciphertext = AESGCM(encryption_key(Path(args.key_file))).encrypt(
            nonce, snapshot.read_bytes(), aad
        )
        with pending.open("xb") as stream:
            stream.write(aad + nonce + ciphertext)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(pending, 0o600)
        encrypted_checksum = sha256(pending)
        os.replace(pending, final)
        sync_directory(destination)
    metadata = {
        **authenticated,
        "backup": final.name,
        "encrypted": True,
        "plaintext_sha256": plaintext_checksum,
        "encrypted_sha256": encrypted_checksum,
        "size_bytes": final.stat().st_size,
        "retention_days": args.retention_days,
        "duration_seconds": round(time.monotonic() - started, 3),
        "backup_failures_total": int(previous.get("backup_failures_total", 0)),
        "restore_rehearsal_timestamp_seconds": previous.get(
            "restore_rehearsal_timestamp_seconds", 0
        ),
        **validation,
    }
    metadata_pending.write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(metadata_pending, 0o600)
    sync_file(metadata_pending)
    os.replace(metadata_pending, metadata_path)
    sync_directory(destination)
    latest_metadata = destination / "latest.json"
    temporary_metadata = destination / ".latest.json.tmp"
    temporary_metadata.write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(temporary_metadata, 0o600)
    sync_file(temporary_metadata)
    os.replace(temporary_metadata, latest_metadata)
    sync_directory(destination)
    cutoff = time.time() - args.retention_days * 86400
    for candidate in destination.glob("provisioning-*.sqlite3.aes256gcm*"):
        if candidate.stat().st_mtime < cutoff:
            candidate.unlink()
    print(json.dumps(metadata, sort_keys=True))


def restore_verify(args: argparse.Namespace) -> None:
    backup_path = Path(args.backup)
    validate_release_identity(args.expected_release_sha, args.expected_image_reference)
    if args.max_age_seconds <= 0:
        raise RuntimeError("maximum recovery age must be positive")
    work_root = Path(args.temporary_directory)
    if not work_root.is_dir() or work_root.is_symlink():
        raise RuntimeError("restore temporary directory is invalid")
    payload = backup_path.read_bytes()
    encrypted_checksum = sha256(backup_path)
    header, aad, nonce, ciphertext = decode_payload(payload)
    if header.get("format") != "codestra-sqlite-backup-v2":
        raise RuntimeError("unsupported authenticated backup schema")
    if header.get("release_sha") != args.expected_release_sha:
        raise RuntimeError("backup release SHA mismatch")
    if header.get("image_reference") != args.expected_image_reference:
        raise RuntimeError("backup image reference mismatch")
    try:
        created_at = datetime.fromisoformat(str(header["created_at"]))
    except (KeyError, ValueError) as error:
        raise RuntimeError("authenticated backup timestamp is invalid") from error
    if created_at.tzinfo is None:
        raise RuntimeError("authenticated backup timestamp lacks timezone")
    age_seconds = (datetime.now(UTC) - created_at).total_seconds()
    if age_seconds < -300 or age_seconds > args.max_age_seconds:
        raise RuntimeError("authenticated backup is outside the recovery age limit")
    plaintext = AESGCM(encryption_key(Path(args.key_file))).decrypt(
        nonce, ciphertext, aad
    )
    if hashlib.sha256(plaintext).hexdigest() != header.get("plaintext_sha256"):
        raise RuntimeError("authenticated plaintext checksum mismatch")
    metadata_path = backup_path.with_suffix(backup_path.suffix + ".json")
    try:
        sidecar = json.loads(metadata_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("backup metadata sidecar is unavailable") from error
    expected_sidecar = {
        "backup": backup_path.name,
        "encrypted_sha256": encrypted_checksum,
        **header,
    }
    for name, expected in expected_sidecar.items():
        if sidecar.get(name) != expected:
            raise RuntimeError(f"backup metadata mismatch: {name}")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(dir=work_root) as temporary:
        restored = Path(temporary) / "provisioning-restored.sqlite3"
        restored.write_bytes(plaintext)
        os.chmod(restored, 0o600)
        validation = verify_database(restored)
    result = {
        "backup": backup_path.name,
        "encrypted_sha256": encrypted_checksum,
        "release_sha": header["release_sha"],
        "image_reference": header["image_reference"],
        "backup_created_at": header["created_at"],
        "backup_age_seconds": round(age_seconds, 3),
        "restore_rto_seconds": round(time.monotonic() - started, 3),
        **validation,
    }
    latest_metadata = backup_path.parent / "latest.json"
    metadata = dict(sidecar)
    metadata["restore_rehearsal_timestamp_seconds"] = time.time()
    metadata["restore_result"] = result
    pending = backup_path.parent / ".latest.json.tmp"
    pending.write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(pending, 0o600)
    sync_file(pending)
    os.replace(pending, latest_metadata)
    sync_directory(backup_path.parent)
    print(json.dumps(result, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("backup")
    create.add_argument("--database", required=True)
    create.add_argument("--destination", required=True)
    create.add_argument("--key-file", required=True)
    create.add_argument("--temporary-directory", required=True)
    create.add_argument("--release-sha", required=True)
    create.add_argument("--image-reference", required=True)
    create.add_argument("--retention-days", type=int, default=30)
    create.set_defaults(handler=backup)
    verify = commands.add_parser("restore-verify")
    verify.add_argument("--backup", required=True)
    verify.add_argument("--key-file", required=True)
    verify.add_argument("--temporary-directory", required=True)
    verify.add_argument("--expected-release-sha", required=True)
    verify.add_argument("--expected-image-reference", required=True)
    verify.add_argument("--max-age-seconds", type=int, required=True)
    verify.set_defaults(handler=restore_verify)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except Exception:
        if arguments.command == "backup":
            destination = Path(arguments.destination)
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            latest = destination / "latest.json"
            metadata = {}
            if latest.is_file():
                try:
                    metadata = json.loads(latest.read_text())
                except (OSError, ValueError, json.JSONDecodeError):
                    metadata = {}
            metadata["backup_failures_total"] = int(
                metadata.get("backup_failures_total", 0)
            ) + 1
            metadata["last_failure_at"] = datetime.now(UTC).isoformat()
            pending = destination / ".latest.json.tmp"
            pending.write_text(json.dumps(metadata, sort_keys=True) + "\n")
            os.chmod(pending, 0o600)
            os.replace(pending, latest)
        raise
