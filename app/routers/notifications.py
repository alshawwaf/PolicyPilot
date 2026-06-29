"""Header notification bell — list / mark-read / delete / clear the current user's notifications.
All endpoints are auth-gated (the user's own notifications only)."""
import datetime as dt

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none
from ..services import notifications as notif

router = APIRouter(include_in_schema=False)


def _ago(t: dt.datetime | None) -> str:
    if t is None:
        return ""
    if t.tzinfo is None:                       # SQLite returns naive datetimes -> assume UTC
        t = t.replace(tzinfo=dt.timezone.utc)
    secs = max(0, int((dt.datetime.now(dt.timezone.utc) - t).total_seconds()))
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


@router.get("/notifications")
def list_notifications(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"items": [], "unread": 0}, status_code=401)
    items = notif.recent(db, user.id)
    return JSONResponse({
        "unread": notif.unread_count(db, user.id),
        "items": [{"id": n.id, "text": n.text, "kind": n.kind, "read": n.read,
                   "ago": _ago(n.created_at)} for n in items],
    })


@router.post("/notifications/read")
def mark_read(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"ok": False}, status_code=401)
    notif.mark_all_read(db, user.id)
    return JSONResponse({"ok": True})


@router.post("/notifications/clear")
def clear_notifications(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"ok": False}, status_code=401)
    return JSONResponse({"ok": True, "cleared": notif.clear(db, user.id)})


@router.post("/notifications/{nid}/delete")
def delete_notification(nid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"ok": False}, status_code=401)
    return JSONResponse({"ok": notif.delete_one(db, user.id, nid)})
