"""CSV + print-to-PDF export for the portal's list tables. Generic over ``services.exporting``: the
CSV path streams a UTF-8 file; the print path renders a standalone, branded, print-optimised page whose
CSS repeats the header on every page and never splits a row, so the browser's "Save as PDF" produces a
clean multi-page document with no new server dependency."""
import datetime as dt
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none
from ..services import exporting
from .ui import templates

router = APIRouter(include_in_schema=False)


def _filename(table_id: str, ext: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (table_id or "").lower()).strip("-") or "table"
    return f"policypilot-{slug}-{dt.date.today().isoformat()}.{ext}"


@router.get("/export/{table_id}.csv")
def export_csv(table_id: str, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    et = exporting.build(table_id, db, user, request.query_params)
    if et is None:
        return PlainTextResponse("Unknown table.", status_code=404)
    return PlainTextResponse(
        exporting.to_csv(et), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_filename(table_id, "csv")}"'})


@router.get("/export/{table_id}/print", response_class=HTMLResponse)
def export_print(table_id: str, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    et = exporting.build(table_id, db, user, request.query_params)
    if et is None:
        return HTMLResponse("<p>Unknown table.</p>", status_code=404)
    # Only follow a same-origin referer back, never an attacker-supplied absolute URL (open-redirect safe).
    ref = request.headers.get("referer") or "/"
    back = ref if ref.startswith("/") or ref.startswith(str(request.base_url)) else "/"
    return templates.TemplateResponse(request, "export_print.html", {
        "et": et, "generated": dt.datetime.now(dt.timezone.utc), "back": back})
