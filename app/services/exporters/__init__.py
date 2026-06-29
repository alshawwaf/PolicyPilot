"""Per-table export builders. Each module registers one table via ``@exporting.register("<id>")``;
``exporting._load_builders()`` auto-imports every module here, so adding a table is one new file."""
