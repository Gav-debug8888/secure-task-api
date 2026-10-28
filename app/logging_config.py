"""Structured (JSON) logging for security events.

Security events are emitted with an `event` field so they can be shipped to a
SIEM and alerted on (e.g. many `login_failed` events from one IP).
Never log passwords, tokens or full request bodies.
"""
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update(getattr(record, "extra_fields", {}))
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


security_logger = logging.getLogger("security")


def log_security_event(event: str, level: int = logging.INFO, **fields) -> None:
    """Log a security event, e.g. log_security_event("login_failed", username="bob", ip="1.2.3.4")."""
    security_logger.log(level, event, extra={"extra_fields": {"event": event, **fields}})
