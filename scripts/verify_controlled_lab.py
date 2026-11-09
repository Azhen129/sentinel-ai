"""Run bounded genuine owned-loopback activity only after an explicit --execute."""
import argparse
import json
from pathlib import Path
import sys
from datetime import datetime, timezone
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.controlled_lab import plan, run_controlled_lab


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Authorize this bounded loopback-only run; never captures Ethernet")
    parser.add_argument("--output-dir", type=Path, help="New private evidence directory; an existing directory is refused")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps(plan(), indent=2))
        return 0
    destination = args.output_dir or ROOT/"data"/"lab-runs"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8])
    try:
        report = run_controlled_lab(destination)
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps(dict(status="failed", error_type=type(exc).__name__,
            reason="Lab setup failed; no existing directory/database was reused. Inspect local permissions and prerequisites.")))
        return 1
    print(json.dumps(dict(report=str(destination.resolve()/"report.json"), counts=report["counts"],
                         outcomes=report["outcome_counts"], source=report["source"], capture=False), indent=2))
    return 1 if any(r["status"] in {"error", "unexpected_result"} for r in report["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
