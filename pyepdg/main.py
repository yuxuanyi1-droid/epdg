from __future__ import annotations

import argparse

from .config import load
from .server import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Python ePDG control plane")
    parser.add_argument("config", nargs="?", default="configs/epdg/epdg.yaml", help="path to ePDG yaml config")
    args = parser.parse_args()
    cfg = load(args.config)
    run(cfg)


if __name__ == "__main__":
    main()
