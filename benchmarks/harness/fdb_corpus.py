from __future__ import annotations

import csv
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path

from harness.paths import CORPUS

FDB_ROOT = CORPUS / "amazon_fdb"
FDB_VERSIONED = FDB_ROOT / "src" / "fdb" / "versioned_datasets"


@dataclass(frozen=True)
class FdbDatasetSpec:
    key: str
    version: str | None = None
    zip_relative: Path | None = None


FDB_VERSIONED_DATASETS: tuple[FdbDatasetSpec, ...] = (
    FdbDatasetSpec(
        key="ipblock",
        version="20220607",
        zip_relative=Path("ipblock/20220607.zip"),
    ),
)


def versioned_zip_path(spec: FdbDatasetSpec) -> Path | None:
    if spec.zip_relative is None:
        return None
    path = FDB_VERSIONED / spec.zip_relative
    return path if path.is_file() else None


def available_fdb_keys() -> list[str]:
    keys: list[str] = []
    for spec in FDB_VERSIONED_DATASETS:
        if versioned_zip_path(spec) is not None:
            keys.append(spec.key)
    return keys


def load_versioned_test_rows(
    spec: FdbDatasetSpec,
) -> list[tuple[int, dict[str, str], int]]:
    """Return (index, feature_row, event_label) from a bundled FDB versioned zip."""
    zip_path = versioned_zip_path(spec)
    if zip_path is None:
        return []

    with zipfile.ZipFile(zip_path) as archive:
        labels_by_event: dict[str, int] = {}
        with archive.open("test_labels.csv") as handle:
            reader = csv.DictReader(io.TextIOWrapper(handle, encoding="utf-8"))
            for row in reader:
                labels_by_event[row["EVENT_ID"]] = int(row["EVENT_LABEL"])

        rows: list[tuple[int, dict[str, str], int]] = []
        with archive.open("test.csv") as handle:
            reader = csv.DictReader(io.TextIOWrapper(handle, encoding="utf-8"))
            for index, row in enumerate(reader):
                event_id = row["EVENT_ID"]
                label = labels_by_event.get(event_id)
                if label is None:
                    continue
                rows.append((index, row, label))
    return rows
