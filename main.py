import argparse
import logging
import time
from collections.abc import Sequence

from github_monitor import run_monitoring_cycle

logger = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bug Bounty Intelligence Engine")
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one monitoring cycle and exit",
    )
    args = parser.parse_args(argv)

    print("🚀 تم تشغيل محرك BugBountyEngine بنجاح!")

    if args.once:
        try:
            run_monitoring_cycle()
        except Exception:
            logger.exception("Unexpected error in monitoring cycle")
            return 1
        return 0

    while True:
        cycle_started = time.monotonic()
        try:
            run_monitoring_cycle()
        except Exception:
            logger.exception("Unexpected error in monitoring cycle")

        delay = max(0, 600 - (time.monotonic() - cycle_started))
        print(f"\n⏳ الانتظار {delay / 60:.1f} دقيقة قبل الدورة القادمة...")
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())