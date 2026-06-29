"""Activity-log redaction, scoped clearing, and paginated rendering."""
import datetime as dt

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401  (register tables on the metadata)
from app.db import Base
from app.models import ActivityLog
from app.routers.activity import KIND_LABELS, PAGE_SIZES, PROVIDER_LABELS, _filter_conds
from app.routers.ui import templates
from app.services.activity import redact_body, redact_headers


def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def _row(rid=1, kind="feed_poll"):
    return type("R", (), {"id": rid, "at": dt.datetime(2026, 6, 16, 23, 24, 45), "kind": kind,
                          "method": "GET", "path": "/gdc/x.json", "source_ip": "1.2.3.4",
                          "status": 200, "duration_ms": 9, "detail": {}})()


def test_redact_headers_masks_secrets():
    out = redact_headers({"Authorization": "Basic abc", "X-chkp-sid": "sid123",
                          "Cookie": "session=x", "Content-Type": "application/json"})
    assert out["Authorization"] == "(masked)"
    assert out["X-chkp-sid"] == "(masked)"
    assert out["Cookie"] == "(masked)"
    assert out["Content-Type"] == "application/json"


def test_redact_body_redacts_sensitive_keys_recursively():
    out = redact_body({"user": "admin", "password": "secret",
                       "nested": {"token": "t", "ip-address": "1.1.1.1"}})
    assert out["password"] == "***"
    assert out["nested"]["token"] == "***"
    assert out["user"] == "admin"
    assert out["nested"]["ip-address"] == "1.1.1.1"


def test_redact_body_handles_lists():
    out = redact_body([{"password": "p"}, {"name": "ok"}])
    assert out[0]["password"] == "***"
    assert out[1]["name"] == "ok"


def test_shell_renders_checkbox_filters_page_size_and_modal():
    counts = {"all": 4445, "feed_poll": 4077, "layer_apply": 19}
    html = _render("activity.html", counts=counts, kind_labels=KIND_LABELS, selected=["feed_poll"],
                   page_size=10, page_sizes=PAGE_SIZES, provider_labels=PROVIDER_LABELS,
                   dc_counts={"vcenter": 3, "proxmox": 5}, q="", selected_dc=[],
                   selected_status=[], status_classes=["2xx", "3xx", "4xx", "5xx"], flash=None)
    # filters are checkboxes on the left; the selected one is checked
    assert 'name="kinds" value="feed_poll" class="kind-cb" checked' in html
    assert 'name="kinds" value="layer_apply" class="kind-cb" ' in html
    # rows-per-page picker, default 10 selected
    assert '<select id="page-size"' in html and 'value="10" selected' in html
    # delete + clear controls and the viewer modal
    assert 'id="del-btn"' in html and 'id="clear-btn"' in html and 'id="rec-modal"' in html
    # the page opts into the wide container, and checkboxes are never full-width (left-aligned)
    assert '<main class="wide">' in html
    assert 'input[type="checkbox"], input[type="radio"]' in html
    # new: search bar, auto-refresh control, and the Data Center sub-filter (vCenter, Proxmox…)
    assert 'id="q-input"' in html and 'id="refresh-rate"' in html
    # Status / Type / Data center are multiselect dropdown menus folded into the top toolbar
    assert 'id="msel-status"' in html and 'id="msel-type"' in html and 'id="msel-dc"' in html
    assert 'name="dc" value="vcenter"' in html and 'name="dc" value="proxmox"' in html
    assert 'name="status" value="4xx"' in html


def test_filter_conds_are_independent_and_filters():
    # kinds / dc / status / q are independent AND conditions (each OR within itself).
    assert len(_filter_conds([], [], "", [])) == 0                          # nothing → no filter
    assert len(_filter_conds(["feed_poll"], [], "", [])) == 1               # kinds only
    assert len(_filter_conds([], ["proxmox"], "", [])) == 1                 # dc only
    assert len(_filter_conds(["feed_poll"], ["proxmox"], "", [])) == 2      # kinds AND dc (independent)
    assert len(_filter_conds([], [], "", ["4xx"])) == 1                     # status only
    assert len(_filter_conds(["datacenter"], [], "403", ["4xx"])) == 3      # kinds + search + status
    assert len(_filter_conds([], ["vcenter", "nsxt"], "sdk", [])) == 2      # dc (multi) + search


def test_pager_and_rows_render_selectable_clickable():
    html = _render("_activity_rows.html", rows=[_row(rid=42)], page=6, pages=88,
                   total=4399, kind_labels=KIND_LABELS,
                   stats={"total": 4399, "ok": 4001, "err": 12, "avg_ms": 8, "sources": 3})
    assert "Page 6 of 88" in html
    assert "« First" in html and "Last »" in html
    assert 'data-page="1"' in html and 'data-page="88"' in html      # First + Last
    assert 'data-page="5"' in html and 'data-page="7"' in html       # window around page 6
    assert 'aria-current="page"' in html                             # current page marked
    # live stats strip
    assert 'class="statbar"' in html and "4001" in html
    # each row is a clickable record with a selection checkbox
    assert 'class="act-row" data-id="42"' in html
    assert 'name="ids" value="42" class="row-cb"' in html


def _seed_db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    a = ActivityLog(kind="feed_poll", path="/a")
    b = ActivityLog(kind="feed_poll", path="/b")
    c = ActivityLog(kind="layer_apply", path="/c")
    db.add_all([a, b, c])
    db.commit()
    return db, a, b, c


def test_delete_by_ids_removes_only_selected_rows():
    db, a, b, c = _seed_db()
    db.execute(delete(ActivityLog).where(ActivityLog.id.in_([a.id, c.id])))
    db.commit()
    assert {r.path for r in db.scalars(select(ActivityLog)).all()} == {"/b"}


def test_clear_by_kinds_deletes_only_those_categories():
    db, a, b, c = _seed_db()
    db.execute(delete(ActivityLog).where(ActivityLog.kind.in_(["feed_poll"])))
    db.commit()
    remaining = db.scalars(select(ActivityLog)).all()
    assert len(remaining) == 1 and remaining[0].kind == "layer_apply"
