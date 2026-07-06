"""
server/routers/credentials.py — /api/v1/credentials endpoints.

Credential profiles are stored in  credentials/{provider}.json  (project root).
The same directory is read/written by the deploy wizard (providers/*/wizard.py),
so profiles saved via the WebGUI are immediately available to the wizard and vice-versa.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from .. import cred_store
from server.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


@router.get("/{provider}")
def list_profiles(provider: str, _: str = Depends(get_current_user)):
    """Return saved credential profiles for *provider* — identifier only, no secrets."""
    return {"provider": provider, "profiles": cred_store.load_profiles_safe(provider)}


@router.delete("/{provider}/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    provider: str,
    profile_id: str,
    request: Request,
    _: str = Depends(get_current_user),
):
    """Remove a saved credential profile by id."""
    cred_store.remove_profile(provider, profile_id)
    await request.app.state.ws.broadcast({
        "type": "credentials.changed",
        "payload": {"provider": provider},
    })
