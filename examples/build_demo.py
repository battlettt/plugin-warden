"""Write the deliberately malicious demo plugin used in the README and tests.

    uv run python examples/build_demo.py /tmp/evil-plugin
    uv run warden scan /tmp/evil-plugin

The plugin is never installed or run; it only exists so the scanner and the
agent have something hostile to read. Its fake credentials are assembled at
run time so they never sit in this repository.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from conftest import make_benign, make_malicious  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_demo.py <empty folder>")
    out = Path(sys.argv[1]).expanduser()
    if out.exists() and any(out.iterdir()):
        sys.exit(f"{out} is not empty")
    make_malicious(out)
    make_benign(out.parent / f"{out.name}-benign")
    print(f"wrote {out} and {out.parent / (out.name + '-benign')}")
