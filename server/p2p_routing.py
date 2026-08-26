"""
server/p2p_routing.py — P2P message routing logic.

When the server needs to send a command to an internal (P2P) beacon, it:
  1. Finds the chain path from egress to target (via p2p_parent_guid links)
  2. Encrypts the task JSON for the target session's epoch state
  3. Embeds routing metadata (p2p_route) so the egress beacon can forward
  4. Sends the envelope via the egress beacon's cloud channel

The actual per-hop link-key encryption is performed by the agents themselves
(each agent wraps/unwraps with its negotiated link key). The server only needs
to tell the egress which path to follow.

Response flow: the response arrives on the egress beacon's output path. The
egress has already stripped the per-hop layers, so the server receives the
raw JSON response tagged with the originating session_id.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from server.session import ServerSessionManager


def find_chain_path(
    sm: "ServerSessionManager",
    target_session_id: str,
) -> Optional[list[str]]:
    """
    Walk from target up to the egress beacon via p2p_parent_guid links.

    Returns the path as [egress_id, hop1_id, ..., target_id] (root to leaf order),
    or None if the chain is broken or target is already an egress beacon.
    """
    visited = set()
    path = [target_session_id]
    current = target_session_id

    while True:
        session = sm.get(current)
        if session is None:
            return None

        parent = getattr(session.profile, 'p2p_parent_guid', '')
        if not parent:
            break

        if parent in visited:
            return None
        visited.add(parent)
        path.append(parent)
        current = parent

    path.reverse()
    return path


def get_egress_for_session(
    sm: "ServerSessionManager",
    session_id: str,
) -> Optional[str]:
    """Return the egress beacon session_id for a given (possibly internal) beacon."""
    path = find_chain_path(sm, session_id)
    if path is None:
        return None
    return path[0]


def is_internal_beacon(sm: "ServerSessionManager", session_id: str) -> bool:
    """Check if a session is a P2P internal beacon (has a parent)."""
    session = sm.get(session_id)
    if session is None:
        return False
    return bool(getattr(session.profile, 'p2p_parent_guid', ''))


def build_routed_task(
    sm: "ServerSessionManager",
    task_json: str,
    chain_path: list[str],
    target_session_id: str,
) -> str:
    """
    Embed P2P routing metadata into the task JSON envelope.

    The egress beacon will read p2p_route and construct layered RoutedMessages
    with per-hop link-key encryption for each hop in the chain.

    Args:
        sm: session manager (used to resolve p2p_guid for each hop)
        task_json: The serialized task JSON (already has cmd_id, type, args, etc.)
        chain_path: [egress_id, hop1_id, ..., target_id]
        target_session_id: The final destination session_id

    Returns:
        Modified task JSON with p2p_route field added.
    """
    import json
    guid_path = []
    for sid in chain_path:
        sess = sm.get(sid)
        if sess:
            guid = getattr(sess.profile, 'p2p_guid', '') or sid
        else:
            guid = sid
        guid_path.append(guid)
    envelope = json.loads(task_json)
    envelope["p2p_route"] = {
        "target": target_session_id,
        "path": chain_path,
        "guid_path": guid_path,
        "hops": len(chain_path) - 1,
    }
    return json.dumps(envelope, ensure_ascii=False, separators=(',', ':'))


def build_p2p_response_tag(
    target_session_id: str,
    cmd_id: str,
) -> dict:
    """
    Build a tag dict that the egress beacon includes in cloud output so the
    server can route the response back to the correct internal session.
    """
    return {
        "p2p_origin": target_session_id,
        "cmd_id": cmd_id,
    }
