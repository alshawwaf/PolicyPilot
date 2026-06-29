"""Derive Terraform-provider and Ansible-collection SUPPORT from the LIVE sources, so the /coverage
comparison reflects what each tool actually covers today instead of a hand-maintained snapshot.

Two cost tiers:

* HEAVY (offline, run by ``tools/build_coverage.py``) — ``from_live()`` reads the real schemas:
  - Terraform: ``terraform init`` + ``terraform providers schema -json`` on CheckPointSW/checkpoint →
    every resource and its full argument set (attributes + nested blocks).
  - Ansible: download the ``check_point.mgmt`` / ``check_point.gaia`` collection tarballs from Ansible
    Galaxy → parse each ``cp_mgmt_* / cp_gaia_*`` module's DOCUMENTATION ``options`` (a tolerant indent
    parser, so no PyYAML dependency).
  The result is baked into the coverage artifacts; ``coverage_build`` then VERIFIES each API field/object
  against these sets (the curated rename maps shrink to candidate-name *hints*).

* LIGHT (runtime, the "Check for updates" button) — ``latest_versions()`` just queries the Terraform
  Registry + Ansible Galaxy version APIs (fast JSON GETs) so the page can flag "a newer provider /
  collection is available — re-bake to refresh support."

Everything is best-effort and degrades cleanly: if terraform isn't installed or the network is down, the
heavy path raises ``ToolSchemaError`` (the build falls back to the curated maps) and the light path
returns ``None`` per tool. TLS verification is always on (org policy)."""
from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field

import httpx

TF_PROVIDER = "CheckPointSW/checkpoint"
_GALAXY = "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index"
_REGISTRY = "https://registry.terraform.io/v1/providers"
_UA = {"User-Agent": "PolicyPilot-coverage/1.0"}


class ToolSchemaError(RuntimeError):
    """The live schema could not be read (terraform missing, network down, malformed response)."""


@dataclass
class ToolSchemas:
    """Derived support sets + the exact versions they came from. Passed to coverage_build so support is
    decided by membership in these sets rather than by the curated assumption maps."""
    tf_resources: dict = field(default_factory=dict)     # resource name -> {arg names}
    ans_modules: dict = field(default_factory=dict)      # module name  -> {option names}
    versions: dict = field(default_factory=dict)         # {terraform, ansible_mgmt, ansible_gaia}


# --------------------------------------------------------------------------- #
# Terraform — the authoritative machine-readable schema via the CLI
# --------------------------------------------------------------------------- #
def terraform_resources(version: str = "") -> tuple[dict, str]:
    """({resource_name: {arg names}}, provider_version) for CheckPointSW/checkpoint, read from
    ``terraform providers schema -json``. Pins ``version`` if given, else takes the registry latest.
    Raises ToolSchemaError if terraform isn't available or init/schema fails."""
    constraint = f'\n      version = "{version}"' if version else ""
    main_tf = ('terraform {\n  required_providers {\n    checkpoint = {\n'
               f'      source = "{TF_PROVIDER}"{constraint}\n    }}\n  }}\n}}\n')
    try:
        with tempfile.TemporaryDirectory(prefix="policypilot-tfschema-") as tmp:
            with open(f"{tmp}/main.tf", "w") as f:
                f.write(main_tf)
            init = subprocess.run(["terraform", "init", "-no-color", "-input=false"],
                                  cwd=tmp, capture_output=True, text=True, timeout=300)
            if init.returncode != 0:
                raise ToolSchemaError(f"terraform init failed: {(init.stderr or init.stdout)[-300:]}")
            sch = subprocess.run(["terraform", "providers", "schema", "-json"],
                                 cwd=tmp, capture_output=True, text=True, timeout=120)
            if sch.returncode != 0:
                raise ToolSchemaError(f"terraform providers schema failed: {sch.stderr[-300:]}")
            data = json.loads(sch.stdout)
            pinned = _lockfile_version(f"{tmp}/.terraform.lock.hcl")
    except FileNotFoundError as exc:        # terraform binary not on PATH
        raise ToolSchemaError("terraform CLI not found") from exc
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise ToolSchemaError(f"terraform schema unreadable: {exc}") from exc

    resources = _resources_from_schema(data)
    if not resources:
        raise ToolSchemaError("terraform schema contained no resources")
    return resources, (version or pinned or "")


def _resources_from_schema(data: dict) -> dict:
    """{resource_name: {arg names}} from a ``terraform providers schema -json`` document. An argument is
    any top-level attribute OR nested block (both are settable resource args)."""
    resources: dict = {}
    for prov in (data.get("provider_schemas") or {}).values():
        for name, rs in (prov.get("resource_schemas") or {}).items():
            block = rs.get("block", {}) or {}
            resources[name] = set(block.get("attributes", {}) or {}) | set(block.get("block_types", {}) or {})
    return resources


def _lockfile_version(path: str) -> str:
    try:
        with open(path) as f:
            m = re.search(r'version\s*=\s*"([^"]+)"', f.read())
            return m.group(1) if m else ""
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Ansible — module option sets from the Galaxy collection tarball
# --------------------------------------------------------------------------- #
def _client(timeout: float) -> httpx.Client:
    return httpx.Client(timeout=timeout, verify=True, follow_redirects=True, headers=_UA)


def ansible_modules(namespace: str, name: str, version: str = "", timeout: float = 90) -> tuple[dict, str]:
    """({module_name: {option names}}, version) for a Galaxy collection (e.g. check_point/mgmt), parsed
    from each module's DOCUMENTATION options. ``version=''`` uses the highest published. Raises
    ToolSchemaError on a network/format failure."""
    try:
        with _client(timeout) as c:
            if not version:
                idx = c.get(f"{_GALAXY}/{namespace}/{name}/").json()
                version = (idx.get("highest_version") or {}).get("version") or ""
                if not version:
                    raise ToolSchemaError(f"no published version for {namespace}.{name}")
            detail = c.get(f"{_GALAXY}/{namespace}/{name}/versions/{version}/").json()
            dl = detail.get("download_url")
            if not dl:
                raise ToolSchemaError(f"no download_url for {namespace}.{name} {version}")
            blob = c.get(dl).content
    except (httpx.HTTPError, json.JSONDecodeError, KeyError) as exc:
        raise ToolSchemaError(f"Galaxy fetch failed for {namespace}.{name}: {exc}") from exc

    modules: dict = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for m in tar.getnames():
                if not re.search(r"plugins/modules/[A-Za-z0-9_]+\.py$", m):
                    continue
                mod = m.rsplit("/", 1)[-1][:-3]                    # cp_mgmt_host
                if not (mod.startswith("cp_mgmt_") or mod.startswith("cp_gaia_")):
                    continue
                f = tar.extractfile(m)
                if f is None:
                    continue
                modules[mod] = _doc_options(f.read().decode("utf-8", "replace"))
    except tarfile.TarError as exc:
        raise ToolSchemaError(f"collection tarball unreadable: {exc}") from exc
    if not modules:
        raise ToolSchemaError(f"{namespace}.{name} {version} contained no cp_* modules")
    return modules, version


def _doc_options(src: str) -> set:
    """Top-level option names from an Ansible module's DOCUMENTATION block — a tolerant indent parser
    (no PyYAML). Reads the keys directly under ``options:`` at their common indent, stopping at the next
    top-level DOCUMENTATION section."""
    m = re.search(r"DOCUMENTATION\s*=\s*r?(['\"]{3})(.*?)\1", src, re.S)
    if not m:
        return set()
    opts: set = set()
    in_opts, base = False, None
    for ln in m.group(2).splitlines():
        if re.match(r"^\s*options:\s*$", ln):
            in_opts = True
            continue
        if not in_opts or not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:                       # back to a top-level section (author/short_description/…)
            break
        if base is None:
            base = indent
        if indent == base:
            mm = re.match(r"^\s+([A-Za-z_][\w-]*)\s*:", ln)
            if mm:
                opts.add(mm.group(1))
    return opts


# --------------------------------------------------------------------------- #
# Light: latest published versions (runtime "newer available?" check)
# --------------------------------------------------------------------------- #
def latest_versions(timeout: float = 12) -> dict:
    """Best-effort latest published versions: {terraform, ansible_mgmt, ansible_gaia} (value None if a
    lookup fails). Lightweight JSON GETs — safe to call from the request path."""
    out = {"terraform": None, "ansible_mgmt": None, "ansible_gaia": None}
    try:
        with _client(timeout) as c:
            try:
                out["terraform"] = c.get(f"{_REGISTRY}/{TF_PROVIDER}").json().get("version")
            except (httpx.HTTPError, json.JSONDecodeError):
                pass
            for key, name in (("ansible_mgmt", "mgmt"), ("ansible_gaia", "gaia")):
                try:
                    j = c.get(f"{_GALAXY}/check_point/{name}/").json()
                    out[key] = (j.get("highest_version") or {}).get("version")
                except (httpx.HTTPError, json.JSONDecodeError):
                    pass
    except Exception:  # noqa: BLE001 — best-effort; never break the caller
        pass
    return out


# --------------------------------------------------------------------------- #
# Assemble the full derived set (offline build use)
# --------------------------------------------------------------------------- #
def from_live(tf_version: str = "", mgmt_version: str = "", gaia_version: str = "") -> ToolSchemas:
    """Read Terraform + both Ansible collections live and return a ToolSchemas. Raises ToolSchemaError
    if Terraform can't be read (the dominant signal); a failing Ansible collection degrades to an empty
    module set for that collection (its objects then show an Ansible gap) rather than aborting."""
    tf_res, tf_ver = terraform_resources(tf_version)
    versions = {"terraform": tf_ver}
    ans_modules: dict = {}
    for key, name, ver in (("ansible_mgmt", "mgmt", mgmt_version), ("ansible_gaia", "gaia", gaia_version)):
        try:
            mods, v = ansible_modules("check_point", name, ver)
            ans_modules.update(mods)
            versions[key] = v
        except ToolSchemaError:
            versions[key] = None
    return ToolSchemas(tf_resources=tf_res, ans_modules=ans_modules, versions=versions)
