"""Shared GlitchTip (Sentry SDK) initialization/capture helpers."""

from __future__ import annotations

import logging
import os
from typing import Any

try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
except Exception:  # optional dependency
    sentry_sdk = None
    FlaskIntegration = None


_STATE = {
    "initialized": False,
    "enabled": False,
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, str(default))).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _build_init_kwargs(with_flask: bool) -> dict[str, Any]:
    dsn = str(os.getenv("GLITCHTIP_DSN", "") or "").strip()
    env = str(os.getenv("GLITCHTIP_ENV", os.getenv("ENVIRONMENT", "dev")) or "dev").strip()
    release = str(os.getenv("GLITCHTIP_RELEASE", "") or "").strip()
    try:
        traces = float(os.getenv("GLITCHTIP_TRACES_SAMPLE_RATE", "0.0") or 0.0)
    except Exception:
        traces = 0.0
    traces = max(0.0, min(1.0, traces))

    kwargs: dict[str, Any] = {
        "dsn": dsn,
        "environment": env,
        "send_default_pii": False,
        "traces_sample_rate": traces,
    }
    if release:
        kwargs["release"] = release

    if with_flask:
        if FlaskIntegration is None:
            logging.warning("GlitchTip requested with Flask integration, but dependency is unavailable.")
        else:
            kwargs["integrations"] = [FlaskIntegration()]

    return kwargs


def init_glitchtip(service: str = "netbox-helper", with_flask: bool = False) -> bool:
    """Initialize GlitchTip once per process.

    Enabled only when:
      - DEV=true
      - GLITCHTIP_DSN is set
      - GLITCHTIP_ENABLED is unset or true
    """
    if _STATE["initialized"]:
        return bool(_STATE["enabled"])

    _STATE["initialized"] = True

    enabled = _env_bool("DEV", False) and _env_bool("GLITCHTIP_ENABLED", True) and bool(
        str(os.getenv("GLITCHTIP_DSN", "") or "").strip()
    )
    if not enabled:
        _STATE["enabled"] = False
        return False

    if sentry_sdk is None:
        logging.warning("GlitchTip enabled but sentry_sdk is not installed.")
        _STATE["enabled"] = False
        return False

    try:
        kwargs = _build_init_kwargs(with_flask=with_flask)
        sentry_sdk.init(**kwargs)
        sentry_sdk.set_tag("service", str(service or "netbox-helper"))
        _STATE["enabled"] = True
        logging.info(
            "GlitchTip initialized (env=%s, service=%s).",
            kwargs.get("environment", "dev"),
            service,
        )
    except Exception as exc:
        logging.warning("Failed to initialize GlitchTip: %s", exc)
        _STATE["enabled"] = False

    return bool(_STATE["enabled"])


def capture_exception(exc: Exception, **context: Any) -> None:
    """Capture exception with optional tags/extras."""
    if not _STATE["enabled"] or sentry_sdk is None:
        return
    try:
        with sentry_sdk.push_scope() as scope:
            for key, value in (context or {}).items():
                if value is None:
                    continue
                text = str(value)
                if key in {
                    "job_id",
                    "site_name",
                    "server_id",
                    "branch",
                    "section",
                    "route",
                    "filename",
                    "script",
                    "service",
                    "device",
                }:
                    scope.set_tag(key, text[:200])
                else:
                    scope.set_extra(key, text[:2000])
            sentry_sdk.capture_exception(exc)
    except Exception:
        return

