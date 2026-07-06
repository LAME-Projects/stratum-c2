"""
core — thin re-export layer so server/ and client/ don't import from providers/ directly.

All heavy logic lives in providers/base.py; this module just surfaces what
the server and client packages need without coupling them to the provider hierarchy.
"""

from providers.base import (
    # constants
    MZ_MARKER,
    HB_REFRESH_INTERVAL,
    DOWNLOADS_DIR,
    # transport
    BaseTransport,
    TRANSPORT_REGISTRY,
    # session objects
    SessionProfile,
    AgentState,
    SessionHistory,
    Session,
    SessionManager,
    # monitors
    HeartbeatMonitor,
    AsyncPoller,
    # crypto
    encrypt_command,
    decrypt_output,
    # send
    send_async,
    # helpers
    deploy_id_from_key,
    decrypt_stage2,
)

__all__ = [
    "MZ_MARKER", "HB_REFRESH_INTERVAL", "DOWNLOADS_DIR",
    "BaseTransport", "TRANSPORT_REGISTRY",
    "SessionProfile", "AgentState", "SessionHistory", "Session", "SessionManager",
    "HeartbeatMonitor", "AsyncPoller",
    "encrypt_command", "decrypt_output",
    "send_async", "deploy_id_from_key", "decrypt_stage2",
]
