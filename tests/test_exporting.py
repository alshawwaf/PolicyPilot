"""Export framework: CSV (BOM + formula-injection guard) and the builder registry."""
from app.services.exporting import ExportTable, build, known, to_csv


def test_csv_has_bom_for_excel():
    out = to_csv(ExportTable(title="t", columns=["A"], rows=[["x"]]))
    assert out[0] == "﻿"


def test_csv_neutralises_formula_injection():
    et = ExportTable(title="t", columns=["A", "B"],
                     rows=[["=SUM(1)", "ok"], ["+1", 2], ["@cmd", "x"], ["-bad", "y"], ["safe", 7]])
    out = to_csv(et)
    assert "'=SUM(1)" in out and "'+1" in out and "'@cmd" in out and "'-bad" in out
    assert "safe,7" in out            # a real int cell stays numeric (not quoted)


def test_unknown_table_returns_none():
    assert build("does-not-exist", None, None, None) is None


def test_all_builders_registered():
    expected = {"activity", "gateways", "management", "layers", "access-servers", "coverage"}
    assert expected <= known()
