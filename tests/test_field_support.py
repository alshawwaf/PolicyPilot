"""The Field-support matrix must stay TRUE to the engine (no drift) and render cleanly."""
from app.services import field_support as fs


def test_matrix_matches_the_engine_constants():
    # verify_against_engine() checks the Action/Time/Content rows == the real engine constants, so the
    # documented support can never silently diverge from what the code actually accepts.
    assert fs.verify_against_engine() == []


def test_matrix_is_complete_and_well_formed():
    rows = fs.matrix()
    fields = {r["field"] for r in rows}
    # every rule column the engine handles is documented
    for expected in ("Source", "Destination", "Service / Port", "Application / Site", "Action",
                     "Content (data types)", "Time", "Action Settings · Limit",
                     "Action Settings · Captive Portal", "Action Settings · UserCheck", "Install On", "VPN"):
        assert expected in fields, f"missing field row: {expected}"
    for r in rows:
        assert r["level"] in fs.LEVELS
        for (_name, lvl, _note) in r["supported"]:
            assert lvl in fs.LEVELS
    # UserCheck is now supported (interaction message + frequency + confirm + custom-frequency); the only
    # honest gap left is that there's no discovery tool for the interaction object (pass it by name).
    uc = next(r for r in rows if r["field"] == "Action Settings · UserCheck")
    assert uc["level"] == fs.REUSE and uc["supported"]
    assert any("interaction" in n.lower() for (n, _l, _d) in uc["supported"])
    assert any("discovery" in g.lower() for g in uc["gaps"])
    # the Limit row records the rate-not-volume gap
    lim = next(r for r in rows if r["field"] == "Action Settings · Limit")
    assert any("volume" in g.lower() or "gb" in g.lower() for g in lim["gaps"])


def test_field_support_page_renders():
    from app.routers.ui import templates
    html = templates.env.get_template("field_support.html").render(
        request=None, matrix=fs.matrix(), levels=fs.LEVELS, review_triggers=fs.REVIEW_TRIGGERS,
        user=None, flash=None)
    assert "Field support" in html and "correlate_time" in html and "Captive Portal" in html
    assert "Gaps &amp; caveats" in html or "Gaps & caveats" in html
