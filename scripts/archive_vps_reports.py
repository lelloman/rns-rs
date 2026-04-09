#!/usr/bin/env python3
"""Create an in-repo archive bundle for VPS reports."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
ARCHIVE_DIR = DOCS / "archive"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Archive VPS report documents into a zip bundle.")
    parser.add_argument(
        "--archive-dir",
        default=str(ARCHIVE_DIR),
        help="Output directory for the archive bundle and index",
    )
    parser.add_argument(
        "--stamp",
        help="Override archive stamp (YYYYMMDD). Default: current UTC date.",
    )
    return parser.parse_args()


def classify(path: pathlib.Path) -> str:
    name = path.name
    if name.startswith("vps-production-findings-"):
        return "production_findings"
    if name.startswith("vps-investigation-brief-"):
        return "investigation_brief"
    return "other"


def collect_files() -> list[pathlib.Path]:
    patterns = [
        "vps-production-findings-*.md",
        "vps-investigation-brief-*.md",
    ]
    files: list[pathlib.Path] = []
    for pattern in patterns:
        files.extend(sorted(DOCS.glob(pattern)))
    return sorted(set(files))


def build_manifest(files: list[pathlib.Path], archive_name: str, stamp: str) -> dict:
    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%d %H:%M:%S UTC"),
        "archive_name": archive_name,
        "archive_stamp": stamp,
        "report_count": len(files),
        "files": [
            {
                "path": str(path.relative_to(ROOT)),
                "filename": path.name,
                "kind": classify(path),
                "report_date": extract_report_date(path.name),
            }
            for path in files
        ],
    }


def extract_report_date(filename: str) -> str | None:
    match = re.search(r"(20\d{2}-\d{2}-\d{2})", filename)
    if match:
        return match.group(1)
    return None


def main() -> int:
    args = parse_args()
    archive_dir = pathlib.Path(args.archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = args.stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    files = collect_files()
    archive_name = f"vps-reports-{stamp}.zip"
    archive_path = archive_dir / archive_name

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, arcname=str(path.relative_to(ROOT)))

    manifest = build_manifest(files, archive_name, stamp)
    (archive_dir / "index.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
