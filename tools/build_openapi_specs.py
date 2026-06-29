"""Pre-build the full OpenAPI specs the embedded API explorer renders, and save them gzipped on disk
(app/coverage_data/openapi/<api>-<version>.json.gz) so the explorer serves them INSTANTLY instead of
re-converting the Check Point docs on every cold load.

For each version the picker offers it reads the locally pre-converted spec (CP-Docs-To-Swagger
SPEC_ROOT) when present, else converts it live over the CDN; injects the explorer's example values; and
writes the gzip bundle. At runtime coverage_build.openapi_spec() loads these first and only falls back
to live conversion for a version that isn't bundled (e.g. one newer than today).

    python tools/build_openapi_specs.py            # all picker versions, both APIs
    python tools/build_openapi_specs.py management v2.1   # one api/version
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import coverage, coverage_build as cb  # noqa: E402

SPEC_ROOT = os.environ.get("DCSIM_SPEC_ROOT", "/Users/khalid/Desktop/CP-Docs-To-Swagger/data/processed")


def _raw_spec(api_type: str, version: str):
    """The raw converted OpenAPI doc — from SPEC_ROOT if present (no network), else converted live."""
    local = os.path.join(SPEC_ROOT, api_type, version, "openapi.json")
    if os.path.exists(local):
        with open(local) as f:
            return json.load(f), "spec_root"
    return cb.fetch_spec(api_type, version), "converted(live)"


def build(api_type: str, version: str):
    spec, src = _raw_spec(api_type, version)
    cb._inject_examples(spec)                       # explorer-only example values (same as runtime)
    path = cb.save_bundled_spec(api_type, version, spec)
    size = os.path.getsize(path)
    print(f"  {api_type:11s} {version:8s}  {len(spec.get('paths', {})):4d} paths  "
          f"{size/1024:6.0f} KB  [{src}]")


def main(argv):
    if len(argv) == 3:
        targets = [(argv[1], argv[2])]
    else:
        vers = coverage.versions()
        targets = [(api, v) for api in ("management", "gaia") for v in vers.get(api, [])]
    print(f"Bundling {len(targets)} OpenAPI spec(s) -> {cb.OPENAPI_DIR}")
    for api, ver in targets:
        try:
            build(api, ver)
        except Exception as exc:  # noqa: BLE001
            print(f"  {api:11s} {ver:8s}  SKIPPED — {type(exc).__name__}: {str(exc)[:80]}")


if __name__ == "__main__":
    main(sys.argv)
