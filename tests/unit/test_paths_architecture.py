from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATHS_DIR = ROOT / "backend" / "paths"


def test_paths_module_does_not_import_graph_internals_or_neo4j():
    forbidden = ("backend.graph", "neo4j")
    violations = []

    for source in PATHS_DIR.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        for forbidden_import in forbidden:
            if forbidden_import in text.lower():
                violations.append(f"{source.name}: {forbidden_import}")

    assert not violations, "Forbidden imports found: " + ", ".join(violations)
