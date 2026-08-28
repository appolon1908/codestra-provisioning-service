import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

SENSITIVE = re.compile(
    r"authorization|password|passwd|secret|token|credential|private.?key|api.?key|cookie",
    re.IGNORECASE,
)
URL_CREDENTIAL = re.compile(
    r"([?&][^=]*(?:token|password|secret|key)[^=]*=)[^&#\s]+", re.IGNORECASE
)


def sanitize(value: Any, key: str = "") -> Any:
    if SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, BaseException):
        return {"type": type(value).__name__, "message": "[REDACTED_EXCEPTION]"}
    if isinstance(value, str):
        return URL_CREDENTIAL.sub(r"\1[REDACTED]", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": record.levelname,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = sanitize(record.exc_info[1])
        return json.dumps(sanitize(payload), separators=(",", ":"), default=str)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
