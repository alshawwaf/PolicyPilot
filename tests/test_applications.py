"""Application-name correlation: normalise, rank, and only auto-use a confident unique match."""
import types

from app.services import access_automation as aa
from app.services import applications as ap


def _app(name, uid=None, cat="", typ="application-site"):
    return {"name": name, "uid": uid or name, "type": typ, "primary-category": cat}


class _Sess:
    def __init__(self, apps, cats=None):
        self._apps, self._cats = apps, cats or []
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None):
        t = (payload or {}).get("type")
        if t == "application-site":
            return {"objects": self._apps}
        if t == "application-site-category":
            return {"objects": self._cats}
        return {"objects": []}


def test_norm_folds_case_and_punctuation():
    assert ap._norm("ABC News!") == "abcnews" and ap._norm("YouTube-Kids") == "youtubekids"


def test_normalized_exact_match_is_confident():
    ap._cache.clear()
    s = _Sess([_app("ABC News", cat="Media Streams"), _app("ABC Family", cat="Media Streams")])
    r = ap.resolve(s, "abcnews")
    assert r["match"] == "ABC News" and r["confidence"] == "normalized"
    assert any(c["name"] == "ABC News" for c in r["candidates"])


def test_exact_ci_match_is_confident():
    ap._cache.clear()
    s = _Sess([_app("Facebook"), _app("Facebook Messenger")])
    r = ap.resolve(s, "facebook")
    assert r["match"] == "Facebook" and r["confidence"] == "exact"


def test_ambiguous_returns_candidates_without_auto_match():
    ap._cache.clear()
    s = _Sess([_app("ABC News"), _app("ABC-News")])     # both normalize to "abcnews" -> ambiguous
    r = ap.resolve(s, "abcnews")
    assert r["match"] is None and len(r["candidates"]) >= 2 and r["note"]


def test_no_match_when_nothing_close():
    ap._cache.clear()
    s = _Sess([])
    r = ap.resolve(s, "totally-unknown-app-zzz")
    assert r["match"] is None and r["candidates"] == [] and r["note"]


def test_resolve_app_canonicalizes_the_request():
    ap._cache.clear()
    s = _Sess([_app("ABC News", cat="Media Streams")])
    req = aa.AccessRequest(src_cidrs=["1.2.3.4/32"], dst_cidrs=["0.0.0.0/0"], application="abcnews")
    res = aa._resolve_app(s, req)
    assert res["match"] == "ABC News" and req.application == "ABC News"   # rewritten to CP's name


def test_resolve_app_none_for_port_request():
    req = aa.AccessRequest(src_cidrs=["1.2.3.4/32"], dst_cidrs=["5.6.7.8/32"], protocol="tcp", ports="443")
    assert aa._resolve_app(_Sess([]), req) is None


def test_truncated_result_never_auto_matches():
    # a FULL page (== limit) means a duplicate could be hidden past the cutoff -> never auto-match,
    # even though exactly one "Facebook" is visible (a wrong app = wrong access).
    ap._cache.clear()
    flood = [_app("Facebook")] + [_app("App %d" % i) for i in range(ap._RESOLVE_LIMIT)]
    r = ap.resolve(_Sess(flood), "Facebook")
    assert r["match"] is None and "Too many matches" in r["note"]


def test_uidless_twins_stay_ambiguous():
    # two distinct uid-less objects that normalize alike must NOT collapse in dedup (that faked a match)
    ap._cache.clear()
    s = _Sess([{"name": "ABC News", "type": "application-site"},
               {"name": "abc-news", "type": "application-site"}])      # no uid key
    r = ap.resolve(s, "abcnews")
    assert r["match"] is None and len(r["candidates"]) == 2


# --- typo tolerance: a session whose show-objects filter is SUBSTRING (like the real SMS) ---------------
_CATALOG = ["Facebook", "Facebook - Login", "Facebook Messenger", "Faces", "FaceTime", "Facet",
            "Instagram", "Kappo", "Kappe"]


class _FilterSess:
    """show-objects filter behaves like the SMS: a case-insensitive SUBSTRING over the name."""
    def __init__(self, names=_CATALOG):
        self._names = names
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None):
        p = payload or {}
        if cmd != "show-objects" or p.get("type") != "application-site":
            return {"objects": []}
        f = (p.get("filter") or "").lower()
        objs = [{"name": n, "type": "application-site", "uid": n, "primary-category": ""}
                for n in self._names if f in n.lower()]
        return {"objects": objs[: p.get("limit", 200)]}


def _names(res):
    return [c["name"] for c in res["candidates"]]


def test_typo_prefix_fallback_surfaces_candidate():
    # "faccebook" is a substring of no name -> the exact filter returns nothing; the prefix fallback must
    # still surface Facebook, but without autocorrect it must NOT auto-match.
    ap._cache.clear()
    r = ap.resolve(_FilterSess(), "faccebook")
    assert r["match"] is None and "Facebook" in _names(r) and "did you mean" in r["note"].lower()


def test_typo_autocorrect_when_enabled():
    ap._cache.clear()
    r = ap.resolve(_FilterSess(), "faccebook", autocorrect_min=0.9)
    assert r["match"] == "Facebook" and r["confidence"] == "corrected" and "interpreted" in r["note"].lower()


def test_typo_not_autocorrected_below_threshold():
    ap._cache.clear()
    r = ap.resolve(_FilterSess(), "faccebook", autocorrect_min=0.99)   # 0.94 < 0.99
    assert r["match"] is None and "Facebook" in _names(r)


def test_ambiguous_close_pair_not_autocorrected():
    # "kappa" is one edit from BOTH Kappo and Kappe (a tie) -> no clear winner, never auto-correct.
    ap._cache.clear()
    r = ap.resolve(_FilterSess(), "kappa", autocorrect_min=0.7)
    assert r["match"] is None


def test_typo_no_candidates_for_gibberish():
    ap._cache.clear()
    r = ap.resolve(_FilterSess(), "zzzzzz")
    assert r["match"] is None and r["candidates"] == [] and "no check point application" in r["note"].lower()


# --- engine gating: only Autonomous (autopilot on) + a configured threshold auto-corrects ---------------
def _patch_settings(monkeypatch, store):
    from app.services import app_settings
    monkeypatch.setattr(app_settings, "get", lambda k: store.get(k))


def test_resolve_app_autocorrects_only_in_autonomous(monkeypatch):
    ap._cache.clear()
    _patch_settings(monkeypatch, {"aa_autopilot": True, "aa_app_autocorrect_min": 90})
    req = aa.AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=[], application="faccebook")
    res = aa._resolve_app(_FilterSess(), req)
    assert res["match"] == "Facebook" and req.application == "Facebook"
    assert req.application_kind == "application-site"


def test_resolve_app_no_autocorrect_when_supervised(monkeypatch):
    ap._cache.clear()
    _patch_settings(monkeypatch, {"aa_autopilot": False, "aa_app_autocorrect_min": 90})
    req = aa.AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=[], application="faccebook")
    res = aa._resolve_app(_FilterSess(), req)
    assert res["match"] is None and req.application == "faccebook" and "Facebook" in _names(res)


def test_resolve_app_no_autocorrect_when_threshold_zero(monkeypatch):
    ap._cache.clear()
    _patch_settings(monkeypatch, {"aa_autopilot": True, "aa_app_autocorrect_min": 0})
    req = aa.AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=[], application="faccebook")
    res = aa._resolve_app(_FilterSess(), req)
    assert res["match"] is None and req.application == "faccebook"
