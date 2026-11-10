"""Build reviewed frontend and a fresh synthetic-only SQLite deployment artifact."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deployment.public_snapshot import generate_snapshot


def main():
    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("Node.js 22 and npm are required for the public demo build")
    for arguments in (("ci",), ("run", "build")):
        subprocess.run([npm, *arguments], cwd=ROOT / "frontend", check=True)
    snapshot = ROOT / "deployment" / "generated" / "public-demo.sqlite"
    # An existing database is never accepted as build input. A fresh build must
    # start from source, not a copied private or earlier runtime database.
    manifest = generate_snapshot(snapshot)
    print(f"Prepared public_demo snapshot: {manifest['counts']['connections']} synthetic connections")


if __name__ == "__main__":
    main()
