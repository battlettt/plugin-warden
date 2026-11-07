"""The report object every output format and the troubleshooting chat read."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, hardening, verdict
from .acquire import Fetched
from .engine import ScanOutput
from .inventory import Inventory
from .models import Finding, Severity, Surface

_VAR_REF = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}?")


@dataclass
class Report:
    target: dict[str, Any]
    root: str
    generated_at: str
    plugins: list[dict[str, Any]]
    component_counts: dict[str, int]
    components: list[dict[str, Any]]
    stats: dict[str, Any]
    findings: list[Finding]
    surface: Surface
    coverage: dict[str, int]
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] | None = None
    scanners: dict[str, str] = field(default_factory=dict)
    agent: dict[str, Any] | None = None
    tool_version: str = __version__
    verdict: dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------- derived
    def refresh_verdict(self) -> None:
        self.verdict = verdict.compute(self.findings)

    def finding(self, fid: str) -> Finding | None:
        fid = fid.strip().upper()
        return next((f for f in self.findings if f.id == fid), None)

    @property
    def plugin_id(self) -> str:
        name = self.plugins[0]["name"] if self.plugins else self.target.get("display", "plugin")
        market = self.target.get("marketplace") or "<marketplace>"
        return f"{name}@{market}"

    def recommended_precautions(self) -> list[str]:
        best: dict[str, int] = {}
        guarded = self.verdict.get("injection_guard", False)
        for f in self.findings:
            if not verdict.counts_toward_score(f, guarded):
                continue
            for p in f.precautions:
                best[p] = max(best.get(p, -1), int(verdict.scored_severity(f, guarded)))
        return [p for p, _ in sorted(best.items(), key=lambda kv: -kv[1]) if p in hardening.PRECAUTIONS]

    def settings_snippet(self) -> dict[str, Any]:
        servers = [c["name"] for c in self.components if c["kind"] == "mcp_server"]
        return hardening.settings_snippet(self.recommended_precautions(), self.plugin_id, servers)

    # --------------------------------------------------------------- serialise
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        d["surface"] = self.surface.to_dict()
        d["recommended_precautions"] = self.recommended_precautions()
        d["settings_snippet"] = self.settings_snippet()
        return d

    def save_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Report:
        d = dict(d)
        d.pop("recommended_precautions", None)
        d.pop("settings_snippet", None)
        d["findings"] = [Finding.from_dict(f) for f in d["findings"]]
        d["surface"] = Surface(**d["surface"])
        return cls(**d)

    @classmethod
    def load(cls, path: Path) -> Report:
        if path.is_dir():
            path = path / "report.json"
        return cls.from_dict(json.loads(path.read_text()))


def build_report(fetched: Fetched, inv: Inventory, out: ScanOutput, extra: list[Finding] | None = None,
                 scanners: dict[str, str] | None = None, marketplace: str | None = None) -> Report:
    from .engine import finalize

    findings = finalize(out.findings + (extra or []))
    t = fetched.target
    target = {
        "display": t.display_name, "raw": t.raw, "kind": t.kind, "url": t.url, "ref": t.ref,
        "subdir": t.subdir, "commit": fetched.commit, "marketplace": marketplace,
    }
    comps = [c.to_dict() for c in inv.components]
    for c in comps:
        # Keep the JSON small: frontmatter of every skill is not useful in the report.
        if c["kind"] in {"skill", "command", "agent", "output_style"}:
            c["details"] = {k: v for k, v in c["details"].items() if k in {"description", "allowed-tools", "tools", "permissionMode", "model"}}
            if "description" in c["details"]:
                c["details"]["description"] = str(c["details"]["description"])[:200]
        if c["kind"] == "submodules":
            c["details"] = {}
        if c["kind"] in {"mcp_server", "lsp_server"}:
            # Env and header values can hold real credentials; keep names and ${VAR} references only.
            for key in ("env", "headers"):
                if isinstance(c["details"].get(key), dict):
                    c["details"][key] = {k: (v if isinstance(v, str) and _VAR_REF.fullmatch(v.strip()) else "<redacted>")
                                         for k, v in c["details"][key].items()}
    report = Report(
        target=target,
        root=str(fetched.root),
        generated_at=fetched.fetched_at,
        plugins=[{"name": p.name, "path": p.rel or ".", "source": p.source, "version": (p.manifest or {}).get("version"), "description": (p.manifest or {}).get("description")} for p in inv.plugins],
        component_counts=dict(sorted(Counter(c.kind for c in inv.components).items())),
        components=comps,
        stats=inv.stats(),
        findings=findings,
        surface=out.surface,
        coverage={**out.coverage, **{k: v for k, v in Counter(f.category for f in findings).items()}},
        notes=out.notes,
        metadata=fetched.metadata.to_dict() if fetched.metadata else None,
        scanners=scanners or {},
    )
    report.refresh_verdict()
    return report


SEVERITY_ORDER = [s.label for s in sorted(Severity, reverse=True)]
