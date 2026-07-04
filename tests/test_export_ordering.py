"""Object emission is dependency-ordered — leaf objects before the groups that
reference them — so the linear mgmt_cli / web_api restore backups re-apply
top-to-bottom without "referenced object does not exist" errors. (Terraform
orders itself via depends_on; this guards the linear backends.)"""
from app.services import mgmt_export


def test_creation_rank_orders_dependencies_before_dependents():
    types = ["group", "host", "service-group", "service-tcp",
             "application-site-group", "application-site", "zzz-unknown"]
    ordered = sorted(types, key=mgmt_export._creation_rank)
    assert ordered.index("host") < ordered.index("group")
    assert ordered.index("service-tcp") < ordered.index("service-group")
    assert ordered.index("application-site") < ordered.index("application-site-group")
    assert ordered[-1] == "zzz-unknown"  # unknown types sort last (alphabetical)


def test_generate_emits_members_before_groups():
    # Objects arrive keyed by type; "group" sorts before "host" alphabetically,
    # so without creation-ordering the group would be emitted first.
    bundle = {"layer": "Network", "rules": [], "objects_by_type": {
        "group": [{"name": "grpBeta", "members": [{"name": "hostAlpha"}]}],
        "host": [{"name": "hostAlpha", "ipv4-address": "10.0.0.1"}],
    }}
    out = mgmt_export.generate(bundle)
    for backend in ("mgmt_cli", "web_api"):
        text = out[backend]
        assert text.index("hostAlpha") < text.index("grpBeta"), \
            f"{backend}: member host must be created before the group"
