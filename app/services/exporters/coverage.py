"""Export builder: the Automation coverage matrix (API ↔ Terraform ↔ Ansible), flattened.

Mirrors the /coverage page: pick the same api/version the user is viewing, walk every category group
and flatten its object rows into one table — object-level support plus the field counts the page shows.
"""
from ..exporting import ExportTable, register


@register("coverage")
def build(db, user, qp) -> ExportTable:
    from .. import coverage

    api = qp.get("api") or "management"
    if api not in ("management", "gaia"):
        api = "management"
    version = qp.get("version") or coverage.latest(api)

    columns = ["Category", "Object", "Command", "web_api", "Terraform", "Ansible",
               "Fields", "TF fields", "Ansible fields", "Fully supported"]
    rows = []
    for g in coverage.object_groups(api, version):
        for r in g["rows"]:
            rows.append([
                g["title"],
                r["name"],
                r["command"],
                "Yes",
                "Yes" if r["has_tf"] else "No",
                "Yes" if r["has_ansible"] else "No",
                r["fields"],
                r["tf_fields"],
                r["ansible_fields"],
                "Yes" if r["full"] else "No",
            ])

    return ExportTable(title="Automation coverage", columns=columns, rows=rows,
                       subtitle=f"{api} API · {version}",
                       meta=[("API", api), ("Version", version)],
                       numeric_cols={6, 7, 8})
