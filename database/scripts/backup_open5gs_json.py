#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from bson import json_util
from pymongo import MongoClient


def main() -> int:
    out_dir = Path(__file__).resolve().parents[1] / "open5gs" / "open5gs_json"
    out_dir.mkdir(parents=True, exist_ok=True)

    client = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=5000)
    try:
        db = client["open5gs"]
        names = sorted(db.list_collection_names())
    except Exception as exc:
        print(f"failed to connect mongodb: {exc}")
        return 2

    manifest = []
    for name in names:
        docs = list(db[name].find())
        dst = out_dir / f"{name}.json"
        with dst.open("w", encoding="utf-8") as f:
            for doc in docs:
                f.write(json_util.dumps(doc, ensure_ascii=False))
                f.write("\n")
        manifest.append((name, len(docs), dst.name))

    with (out_dir / "MANIFEST.txt").open("w", encoding="utf-8") as f:
        for name, count, filename in manifest:
            f.write(f"{name}\t{count}\t{filename}\n")

    print(f"exported collections: {len(manifest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
