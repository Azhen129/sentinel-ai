"""Vercel entrypoint: immutable synthetic source, isolated writable SQLite copy."""
from pathlib import Path
import tempfile

from deployment.public_snapshot import public_app_from_snapshot

ROOT = Path(__file__).resolve().parents[1]
app = public_app_from_snapshot(
    ROOT / "deployment" / "generated" / "public-demo.sqlite",
    Path(tempfile.gettempdir()),
)
# The existing React build and all five hash routes are preserved. Vercel promotes
# these files to its CDN; fallback=None keeps unknown API URLs as real 404s.
app.frontend("/", directory=str(ROOT / "frontend" / "dist"), fallback=None, check_dir=False)
