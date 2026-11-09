"""Check prerequisites by default. --interactive explicitly opens the local menu."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detection.launcher import LauncherError, LocalMonitor


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Read-only prerequisites/inventory; no capture, service or key prompt")
    group.add_argument("--interactive", action="store_true", help="Explicitly open the local action menu")
    args = parser.parse_args(argv)
    launcher = LocalMonitor(ROOT)
    if args.interactive:
        return launcher.interactive()
    try:
        print(json.dumps(launcher.check(), indent=2))
        return 0
    except (LauncherError, OSError) as exc:
        print("Prerequisite check stopped: "+str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
