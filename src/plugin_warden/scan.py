"""The static scan pipeline: fetch, map, check, score."""

from __future__ import annotations

from pathlib import Path

from . import scanners
from .acquire import Fetched, fetch, parse_target
from .engine import Scanner, scan_inventory
from .inventory import Inventory, build
from .models import Finding
from .report import Report, build_report


def static_scan(target: str, *, cache_dir: Path | None = None, metadata: bool = True,
                external: set[str] | None = None, marketplace: str | None = None) -> Report:
    """Scan a target without the agent. `external` names the optional scanners to
    run (None runs every one that is installed, an empty set runs none)."""
    fetched = fetch(parse_target(target), cache_dir=cache_dir, with_metadata=metadata)
    return scan_fetched(fetched, external=external, marketplace=marketplace)


def scan_fetched(fetched: Fetched, *, external: set[str] | None = None, marketplace: str | None = None) -> Report:
    inv = build(fetched.root)
    out = scan_inventory(inv)
    extra, status = ([], {}) if external == set() else scanners.run_all(fetched.root, external)
    return build_report(fetched, inv, out, contextualize(inv, extra), status, marketplace)


def contextualize(inv: Inventory, findings: list[Finding]) -> list[Finding]:
    """Apply the same context levels to external scanner hits as to static ones,
    so a token in a test fixture doesn't outrank code that runs on its own."""
    sc = Scanner(inv)
    for f in findings:
        info = inv.files.get(f.path)
        if info is None:
            continue
        f.severity, f.context = sc._context(f.path, info, False, f.severity)
    return findings
