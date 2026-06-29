"""Import a fetched gateway dynamic layer into a portal Dynamic Layer (the UI 'Import to portal' button)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.models import DynamicLayer, Gateway, GatewayLayerSnapshot, User
from app.routers import gateways


def _client(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    u = User(username="a", password_hash="x"); db.add(u); db.commit()
    gw = Gateway(token="g", name="GW", host="h", port=443, username="admin", owner_id=u.id)
    db.add(gw); db.commit()
    db.add(GatewayLayerSnapshot(gateway_id=gw.id, ok=True, layers=[
        {"name": "dynamic_layer", "objects": {"hosts": [{"name": "client", "ip-address": "10.0.0.5"}]},
         "rulebase": [{"name": "allow_web", "action": "Accept", "source": ["client"],
                       "destination": ["lab_net"], "service": ["https"]}], "referenced": ["https"]}]))
    db.commit()
    monkeypatch.setattr(gateways, "get_user_or_none", lambda req, d: db.get(User, u.id))
    monkeypatch.setattr(gateways, "_flash", lambda *a, **k: None)   # no SessionMiddleware in the test app
    app = FastAPI()
    app.include_router(gateways.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app), db, gw, u


def test_import_layer_creates_portal_dynamic_layer(monkeypatch):
    c, db, gw, u = _client(monkeypatch)
    r = c.post(f"/gateways/{gw.id}/import-layer", data={"layer": "dynamic_layer"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/layers"
    rows = db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == u.id)).all()
    L = next((x for x in rows if x.name == "dynamic_layer"), None)
    assert L is not None and L.layer_name == "dynamic_layer"
    assert L.content["rulebase"][0]["name"] == "allow_web"     # the live rule is now in the portal copy
    assert L.content["objects"]["hosts"][0]["name"] == "client"


def test_import_unknown_layer_is_a_noop(monkeypatch):
    c, db, gw, u = _client(monkeypatch)
    r = c.post(f"/gateways/{gw.id}/import-layer", data={"layer": "nope"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/gateways/{gw.id}"   # back to the gateway
    assert db.scalars(select(DynamicLayer)).all() == []                              # nothing created
