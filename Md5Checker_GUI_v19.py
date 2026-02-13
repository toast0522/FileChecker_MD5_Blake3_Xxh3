# -*- coding: utf-8 -*-
"""
Md5Checker_GUI_v19.py
PySide6 hash checker (white theme) - scalable model/view design.

v9 requested fixes/features:
- Tab switching smoother for huge tables (avoid ResizeToContents; pause sorting during filter change).
- Start/Check hashes ALL rows (source model), not just the current filtered tab.
- Status logic:
  - New      = file exists, no saved hash loaded
  - Loaded   = file exists, saved hash loaded
  - Unknown  = file does not exist
  - N/A      = cannot read/parse sidecar OR hashing error
  - Passed/Failed based on saved vs current hash
- Save exports hashes to a text file, Open loads it, Check compares on-disk hashes vs loaded hashes.
- Optional algorithms: BLAKE3 and XXH3-128.

Optional installs:
- pip install blake3
- pip install xxhash
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6 import QtCore, QtGui, QtWidgets


APP_TITLE = "Md5Checker"
APP_ORG = "LocalTools"
SETTINGS_FILE = "ui_settings.json"
DB_FILE = "hash_databases.sqlite"
EXPORT_EXT = "Hashes (*.txt);;All Files (*.*)"

ABS_PREFIX = "ABS::"


def _try_import_blake3():
    try:
        from blake3 import blake3  # type: ignore
        return blake3
    except Exception:
        return None


def _try_import_xxhash():
    try:
        import xxhash  # type: ignore
        return xxhash
    except Exception:
        return None


_BLAKE3 = _try_import_blake3()
_XXHASH = _try_import_xxhash()


class HashAlgo:
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    BLAKE3 = "BLAKE3"
    XXH3_128 = "XXH3-128"

    @staticmethod
    def all() -> List[str]:
        return [HashAlgo.MD5, HashAlgo.SHA1, HashAlgo.SHA256, HashAlgo.BLAKE3, HashAlgo.XXH3_128]

    @staticmethod
    def is_available(algo: str) -> bool:
        if algo in (HashAlgo.MD5, HashAlgo.SHA1, HashAlgo.SHA256):
            return True
        if algo == HashAlgo.BLAKE3:
            return _BLAKE3 is not None
        if algo == HashAlgo.XXH3_128:
            return _XXHASH is not None
        return False

    @staticmethod
    def availability_hint(algo: str) -> str:
        if algo == HashAlgo.BLAKE3 and _BLAKE3 is None:
            return "Requires: pip install blake3"
        if algo == HashAlgo.XXH3_128 and _XXHASH is None:
            return "Requires: pip install xxhash"
        return ""

    @staticmethod
    def compute(path: Path, algo: str, chunk_size: int = 1024 * 1024,
                abort_cb=None, progress_cb=None) -> str:
        try:
            total = path.stat().st_size
        except Exception:
            total = 0

        done = 0
        last_emit = 0.0

        def _emit_progress():
            nonlocal last_emit
            if progress_cb is None:
                return
            now = time.time()
            if now - last_emit > 0.15:
                last_emit = now
                try:
                    progress_cb(done, total)
                except Exception:
                    pass

        if algo in (HashAlgo.MD5, HashAlgo.SHA1, HashAlgo.SHA256):
            h = hashlib.new(algo.lower())
            with path.open("rb") as f:
                while True:
                    if abort_cb is not None and abort_cb():
                        raise RuntimeError("Aborted")
                    data = f.read(chunk_size)
                    if not data:
                        break
                    h.update(data)
                    done += len(data)
                    _emit_progress()
            return h.hexdigest().lower()

        if algo == HashAlgo.BLAKE3:
            if _BLAKE3 is None:
                raise RuntimeError("BLAKE3 not available. Install: pip install blake3")
            h = _BLAKE3()
            with path.open("rb") as f:
                while True:
                    if abort_cb is not None and abort_cb():
                        raise RuntimeError("Aborted")
                    data = f.read(chunk_size)
                    if not data:
                        break
                    h.update(data)
                    done += len(data)
                    _emit_progress()
            return h.hexdigest().lower()

        if algo == HashAlgo.XXH3_128:
            if _XXHASH is None:
                raise RuntimeError("XXH3 not available. Install: pip install xxhash")
            h = _XXHASH.xxh3_128()
            with path.open("rb") as f:
                while True:
                    if abort_cb is not None and abort_cb():
                        raise RuntimeError("Aborted")
                    data = f.read(chunk_size)
                    if not data:
                        break
                    h.update(data)
                    done += len(data)
                    _emit_progress()
            return h.hexdigest().lower()

        raise RuntimeError(f"Unknown algorithm: {algo}")


def safe_read_text(path: Path, max_bytes: int = 128 * 1024) -> str:
    try:
        b = path.read_bytes()
        if len(b) > max_bytes:
            b = b[:max_bytes]
        try:
            return b.decode("utf-8", errors="replace")
        except Exception:
            return b.decode(errors="replace")
    except Exception:
        return ""


def parse_hash_from_text(text: str) -> Optional[str]:
    text = text.strip()
    if not text:
        return None
    m = re.search(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{16,128})\b", text)
    if m:
        return m.group(1).lower()
    return None


def sidecar_md5_path(file_path: Path) -> Path:
    return file_path.with_name(file_path.name + ".md5")


class PatternMatcher:
    def __init__(self, patterns: List[str]):
        self.suffixes: List[str] = []
        self.fn_patterns: List[str] = []
        for p in patterns:
            p = (p or "").strip()
            if not p:
                continue
            pl = p.lower()
            if pl.startswith("*.") and ("*" not in pl[1:]) and ("?" not in pl) and ("[" not in pl):
                self.suffixes.append(pl[1:])
            else:
                self.fn_patterns.append(pl)

    def match(self, filename_lower: str) -> bool:
        for sfx in self.suffixes:
            if filename_lower.endswith(sfx):
                return True
        for pat in self.fn_patterns:
            if fnmatch.fnmatch(filename_lower, pat):
                return True
        return False


class HashDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path))
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        return con

    def _init(self) -> None:
        con = self._conn()
        try:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    root_folder TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    include_patterns TEXT NOT NULL,
                    exclude_patterns TEXT NOT NULL,
                    recurse INTEGER NOT NULL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshot_files (
                    snapshot_id INTEGER NOT NULL,
                    rel_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    hash TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, rel_path),
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
                )
                """
            )
            con.commit()
        finally:
            con.close()

    def list_snapshots(self) -> List[Tuple[int, str, str, str]]:
        con = self._conn()
        try:
            cur = con.execute("SELECT id, name, created_at, algorithm FROM snapshots ORDER BY created_at DESC;")
            return [(int(r[0]), str(r[1]), str(r[2]), str(r[3])) for r in cur.fetchall()]
        finally:
            con.close()

    def get_snapshot_meta(self, snapshot_id: int) -> Optional[Dict]:
        con = self._conn()
        try:
            cur = con.execute(
                "SELECT id, name, created_at, root_folder, algorithm, include_patterns, exclude_patterns, recurse "
                "FROM snapshots WHERE id=?;",
                (snapshot_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": int(row[0]),
                "name": str(row[1]),
                "created_at": str(row[2]),
                "root_folder": str(row[3]),
                "algorithm": str(row[4]),
                "include_patterns": str(row[5]),
                "exclude_patterns": str(row[6]),
                "recurse": bool(int(row[7])),
            }
        finally:
            con.close()

    def delete_snapshot(self, snapshot_id: int) -> None:
        con = self._conn()
        try:
            con.execute("DELETE FROM snapshots WHERE id=?;", (snapshot_id,))
            con.commit()
        finally:
            con.close()

    def create_snapshot(self, name: str, root_folder: str, algorithm: str,
                        include_patterns: str, exclude_patterns: str, recurse: bool) -> int:
        con = self._conn()
        try:
            created_at = time.strftime("%Y-%m-%d %H:%M:%S")
            cur = con.execute(
                "INSERT INTO snapshots(name, created_at, root_folder, algorithm, include_patterns, exclude_patterns, recurse) "
                "VALUES(?,?,?,?,?,?,?);",
                (name, created_at, root_folder, algorithm, include_patterns, exclude_patterns, 1 if recurse else 0),
            )
            con.commit()
            return int(cur.lastrowid)
        finally:
            con.close()

    def upsert_snapshot_files(self, snapshot_id: int, rows: List[Tuple[str, int, float, str]]) -> None:
        con = self._conn()
        try:
            con.execute("BEGIN;")
            con.executemany(
                "INSERT OR REPLACE INTO snapshot_files(snapshot_id, rel_path, size, mtime, hash) VALUES(?,?,?,?,?);",
                [(snapshot_id, r[0], int(r[1]), float(r[2]), r[3]) for r in rows],
            )
            con.commit()
        finally:
            con.close()

    def load_snapshot_files(self, snapshot_id: int) -> List[Tuple[str, int, float, str]]:
        con = self._conn()
        try:
            cur = con.execute(
                "SELECT rel_path, size, mtime, hash FROM snapshot_files WHERE snapshot_id=? ORDER BY rel_path ASC;",
                (snapshot_id,),
            )
            return [(str(r[0]), int(r[1]), float(r[2]), str(r[3])) for r in cur.fetchall()]
        finally:
            con.close()


class RowStatus:
    NA = "N/A"
    UNKNOWN = "Unknown"
    LOADED = "Loaded"
    NEW = "New"
    FAILED = "Failed"
    PASSED = "Passed"


@dataclass
class FileItem:
    path: Path
    in_folder: str
    current_hash: str = ""
    saved_hash: str = ""
    status: str = RowStatus.NEW
    snapshot_id: Optional[int] = None
    rel_path: Optional[str] = None
    search_blob_lower: str = ""
    # v16: caching + per-row error tooltip
    last_error: str = ""
    last_size: int = -1
    last_mtime: float = -1.0
    last_algo: str = ""

    def key(self) -> str:
        return str(self.path).lower()

    def build_search_blob(self) -> None:
        p = str(self.path)
        self.search_blob_lower = (self.path.name + " " + p).lower()


class HashTableModel(QtCore.QAbstractTableModel):
    COL_NAME = 0
    COL_IN_FOLDER = 1
    COL_CUR = 2
    COL_SAVED = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[FileItem] = []
        self._key_to_row: Dict[str, int] = {}
        self._counts: Dict[str, int] = {
            "All": 0,
            RowStatus.NA: 0,
            RowStatus.UNKNOWN: 0,
            RowStatus.LOADED: 0,
            RowStatus.NEW: 0,
            RowStatus.FAILED: 0,
            RowStatus.PASSED: 0,
        }

    def rebuild_counts(self) -> None:
        for k in list(self._counts.keys()):
            self._counts[k] = 0
        for it in self._rows:
            self._counts["All"] += 1
            self._counts[it.status] = self._counts.get(it.status, 0) + 1

    def clear_all(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._key_to_row.clear()
        self.rebuild_counts()
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else 4

    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return ["Name", "In Folder", "Current Hash", "Saved Hash"][section]
        return str(section + 1)

    def flags(self, index: QtCore.QModelIndex):
        if not index.isValid():
            return QtCore.Qt.ItemIsEnabled
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        r = index.row()
        c = index.column()
        if r < 0 or r >= len(self._rows):
            return None
        it = self._rows[r]

        if role == QtCore.Qt.DisplayRole:
            if c == self.COL_NAME:
                return self._decorate_name_text(it.status, it.path.name)
            if c == self.COL_IN_FOLDER:
                return it.in_folder
            if c == self.COL_CUR:
                return it.current_hash or ""
            if c == self.COL_SAVED:
                return it.saved_hash or ""
            return None

        if role == QtCore.Qt.ToolTipRole:
            if c == self.COL_NAME:
                tip = str(it.path)
                if getattr(it, 'last_error', ''):
                    tip += "\n[ERR] " + str(it.last_error)
                return tip
            if c == self.COL_IN_FOLDER:
                return str(it.path.parent)
            if c in (self.COL_CUR, self.COL_SAVED):
                if getattr(it, 'last_error', ''):
                    return "[ERR] " + str(it.last_error)
            return None

        if role == QtCore.Qt.ForegroundRole:
            if it.status == RowStatus.NA:
                return QtGui.QBrush(QtGui.QColor(120, 120, 120))
            if it.status == RowStatus.UNKNOWN:
                return QtGui.QBrush(QtGui.QColor(110, 110, 110))
            if it.status == RowStatus.FAILED:
                return QtGui.QBrush(QtGui.QColor(160, 0, 0))
            if it.status == RowStatus.PASSED:
                return QtGui.QBrush(QtGui.QColor(0, 110, 0))
            return QtGui.QBrush(QtGui.QColor(0, 0, 0))

        if role == QtCore.Qt.FontRole:
            f = QtGui.QFont()
            f.setBold(it.status in (RowStatus.PASSED, RowStatus.FAILED))
            return f

        if role == QtCore.Qt.UserRole:
            return it.key()
        if role == QtCore.Qt.UserRole + 1:
            return it.status
        if role == QtCore.Qt.UserRole + 2:
            return it.search_blob_lower

        return None

    def get_item(self, row: int) -> Optional[FileItem]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def find_row_by_key(self, key: str) -> Optional[int]:
        return self._key_to_row.get(key)

    def counts(self) -> Dict[str, int]:
        return dict(self._counts)

    def _bump_counts_add(self, status: str) -> None:
        self._counts["All"] += 1
        self._counts[status] = self._counts.get(status, 0) + 1

    def _bump_counts_change(self, old: str, new: str) -> None:
        if old == new:
            return
        self._counts[old] = max(0, self._counts.get(old, 0) - 1)
        self._counts[new] = self._counts.get(new, 0) + 1

    def add_items(self, items: List[FileItem]) -> int:
        if not items:
            return 0
        filtered: List[FileItem] = []
        for it in items:
            k = it.key()
            if k in self._key_to_row:
                continue
            it.build_search_blob()
            filtered.append(it)
        if not filtered:
            return 0

        start = len(self._rows)
        end = start + len(filtered) - 1
        self.beginInsertRows(QtCore.QModelIndex(), start, end)
        for i, it in enumerate(filtered):
            row = start + i
            self._rows.append(it)
            self._key_to_row[it.key()] = row
            self._bump_counts_add(it.status)
        self.endInsertRows()
        return len(filtered)

    def update_fields_by_key(self, key: str, **fields) -> None:
        row = self._key_to_row.get(key)
        if row is None:
            return
        it = self._rows[row]
        old_status = it.status

        for k, v in fields.items():
            if hasattr(it, k):
                setattr(it, k, v)

        if "path" in fields or "in_folder" in fields:
            it.build_search_blob()

        if "status" in fields:
            self._bump_counts_change(old_status, it.status)

        tl = self.index(row, 0)
        br = self.index(row, self.columnCount() - 1)
        self.dataChanged.emit(tl, br)

    @staticmethod
    def _decorate_name_text(status: str, name: str) -> str:
        prefix = {
            RowStatus.PASSED: "[OK] ",
            RowStatus.FAILED: "[FAIL] ",
            RowStatus.NA: "[N/A] ",
            RowStatus.LOADED: "[LOAD] ",
            RowStatus.NEW: "[NEW] ",
            RowStatus.UNKNOWN: "[?] ",
        }.get(status, "")
        return prefix + name


class FilterProxy(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._status_filter: str = "All"
        self._search_lower: str = ""
        # v17: keep filtering fast by avoiding auto-re-sorts on huge datasets
        self.setDynamicSortFilter(False)
        self.setSortCaseSensitivity(QtCore.Qt.CaseInsensitive)

    def set_status_filter(self, status: str) -> None:
        self._status_filter = status or "All"
        self.invalidate()

    def set_search_text(self, text: str) -> None:
        self._search_lower = (text or "").strip().lower()
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QtCore.QModelIndex) -> bool:
        m = self.sourceModel()
        if m is None:
            return True

        it = None
        try:
            if hasattr(m, '_rows') and 0 <= source_row < len(m._rows):
                it = m._rows[source_row]
        except Exception:
            it = None

        if self._status_filter and self._status_filter != 'All':
            st = None
            try:
                st = it.status if it is not None else m.data(m.index(source_row, 0, source_parent), QtCore.Qt.UserRole + 1)
            except Exception:
                st = None
            if st != self._status_filter:
                return False

        if self._search_lower:
            blob = ''
            try:
                blob = it.search_blob_lower if it is not None else m.data(m.index(source_row, 0, source_parent), QtCore.Qt.UserRole + 2)
            except Exception:
                blob = ''
            if not blob or self._search_lower not in str(blob):
                return False

        return True

        if self._status_filter and self._status_filter != "All":
            st = m.data(m.index(source_row, 0, source_parent), QtCore.Qt.UserRole + 1)
            if st != self._status_filter:
                return False

        if self._search_lower:
            blob = m.data(m.index(source_row, 0, source_parent), QtCore.Qt.UserRole + 2)
            if not blob or self._search_lower not in str(blob):
                return False

        return True


class HashWorkerSignals(QtCore.QObject):
    result = QtCore.Signal(str, str, str)
    progress = QtCore.Signal(str, int, int)
    finished = QtCore.Signal(str)


class HashWorker(QtCore.QRunnable):
    def __init__(self, key: str, path: Path, algorithm: str, chunk_size: int):
        super().__init__()
        self.key = key
        self.path = path
        self.algorithm = algorithm
        self.chunk_size = int(chunk_size)
        self.signals = HashWorkerSignals()
        self.setAutoDelete(True)
        self._abort = False

    def abort(self) -> None:
        self._abort = True

    def run(self) -> None:
        def abort_cb():
            return self._abort

        def progress_cb(done, total):
            self.signals.progress.emit(self.key, int(done), int(total))

        try:
            hv = HashAlgo.compute(self.path, self.algorithm, self.chunk_size, abort_cb, progress_cb)
            self.signals.result.emit(self.key, hv, "")
        except Exception as e:
            self.signals.result.emit(self.key, "", str(e))
        finally:
            self.signals.finished.emit(self.key)


class FolderScanSignals(QtCore.QObject):
    batch = QtCore.Signal(list)
    progress_ex = QtCore.Signal(int, int, int, float)
    finished = QtCore.Signal()
    error = QtCore.Signal(str)


class FolderScanWorker(QtCore.QRunnable):
    def __init__(self, root_folder: str, include_patterns: List[str], exclude_patterns: List[str],
                 recurse: bool, threads: int, exclude_md5_files: bool = True):
        super().__init__()
        self.root_folder = root_folder
        self.recurse = bool(recurse)
        self.threads = max(1, int(threads))
        self.signals = FolderScanSignals()
        self.setAutoDelete(True)

        self._abort = False
        self._abort_lock = threading.Lock()

        self._scanned = 0
        self._matched = 0
        self._scanned_lock = threading.Lock()

        self._q: "queue.Queue[str]" = queue.Queue(maxsize=20000)
        self._inc = PatternMatcher([p.strip() for p in (include_patterns or ["*.*"]) if p.strip()])
        self._exc = PatternMatcher([p.strip() for p in (exclude_patterns or []) if p.strip()])
        self._exclude_md5_files = bool(exclude_md5_files)

        self._t0 = time.time()
        self._last_progress = self._t0

    def abort(self) -> None:
        with self._abort_lock:
            self._abort = True

    def _is_aborted(self) -> bool:
        with self._abort_lock:
            return self._abort

    def _bump(self, scanned_add: int = 0, matched_add: int = 0) -> Tuple[int, int]:
        with self._scanned_lock:
            self._scanned += scanned_add
            self._matched += matched_add
            return self._scanned, self._matched

    def _emit_progress_if_needed(self) -> None:
        now = time.time()
        if now - self._last_progress < 0.12:
            return
        self._last_progress = now
        with self._scanned_lock:
            scanned = self._scanned
            matched = self._matched
        pending = self._q.qsize()
        dt = max(0.001, now - self._t0)
        rate = scanned / dt
        self.signals.progress_ex.emit(int(scanned), int(matched), int(pending), float(rate))

    def run(self) -> None:
        try:
            self._q.put_nowait(self.root_folder)
        except Exception:
            pass

        batch_lock = threading.Lock()
        batch: List[str] = []
        last_emit = time.time()

        def emit_batch(force=False):
            nonlocal batch, last_emit
            out = None
            with batch_lock:
                if not batch:
                    return
                if force or len(batch) >= 1500 or (time.time() - last_emit) > 0.18:
                    out = batch
                    batch = []
                    last_emit = time.time()
            if out:
                self.signals.batch.emit(out)

        def worker_loop():
            while True:
                if self._is_aborted():
                    break
                try:
                    d = self._q.get(timeout=0.20)
                except queue.Empty:
                    if self._q.unfinished_tasks == 0:
                        break
                    continue
                try:
                    try:
                        with os.scandir(d) as it:
                            for entry in it:
                                if self._is_aborted():
                                    break
                                self._bump(scanned_add=1)
                                try:
                                    if entry.is_dir(follow_symlinks=False):
                                        if self.recurse:
                                            try:
                                                self._q.put(entry.path, timeout=0.20)
                                            except Exception:
                                                pass
                                        continue
                                    if not entry.is_file(follow_symlinks=False):
                                        continue
                                    nm = entry.name.lower()
                                    if self._exclude_md5_files and nm.endswith('.md5'):
                                        continue
                                    if not self._inc.match(nm):
                                        continue
                                    if self._exc.match(nm):
                                        continue
                                    self._bump(matched_add=1)
                                    with batch_lock:
                                        batch.append(entry.path)
                                    emit_batch()
                                    self._emit_progress_if_needed()
                                except Exception:
                                    continue
                    except Exception:
                        pass
                finally:
                    try:
                        self._q.task_done()
                    except Exception:
                        pass
                    self._emit_progress_if_needed()

        threads: List[threading.Thread] = []
        try:
            for _ in range(self.threads):
                t = threading.Thread(target=worker_loop, daemon=True)
                threads.append(t)
                t.start()

            while True:
                if self._is_aborted():
                    break
                self._emit_progress_if_needed()
                if self._q.unfinished_tasks == 0 and self._q.qsize() == 0:
                    break
                time.sleep(0.08)

            for t in threads:
                t.join(timeout=0.4)

            emit_batch(force=True)
            self._emit_progress_if_needed()
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(str(e))
            self.signals.finished.emit()


class OptionsDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget, settings: Dict):
        super().__init__(parent)
        self.setWindowTitle("Options")
        self.setModal(True)
        self.resize(590, 410)

        self._settings = settings
        self.tabs = QtWidgets.QTabWidget(self)

        add_tab = QtWidgets.QWidget()
        add_layout = QtWidgets.QVBoxLayout(add_tab)

        self.chk_autostart = QtWidgets.QCheckBox("Auto start checking.")
        self.chk_autostart.setChecked(bool(settings.get("auto_start_checking", True)))
        add_layout.addWidget(self.chk_autostart)

        group = QtWidgets.QGroupBox("Add folders")
        form = QtWidgets.QFormLayout(group)

        self.cmb_include = QtWidgets.QComboBox()
        self.cmb_include.setEditable(True)
        include_default = settings.get("include_patterns", "*.exe;*.dll")
        history = settings.get("include_history", [])
        items = [include_default] + [x for x in history if x and x != include_default]
        for it in items[:10]:
            self.cmb_include.addItem(it)
        self.cmb_include.setCurrentText(include_default)

        self.txt_exclude = QtWidgets.QLineEdit()
        self.txt_exclude.setText(settings.get("exclude_patterns", "*.md5"))

        self.chk_exclude_md5 = QtWidgets.QCheckBox("Ignore .md5 files")
        self.chk_exclude_md5.setToolTip("Skip *.md5 sidecar files during folder scanning (recommended).")
        self.chk_exclude_md5.setChecked(bool(settings.get("exclude_md5_files", True)))

        self.chk_recurse = QtWidgets.QCheckBox("Recurse subfolders.")
        self.chk_recurse.setChecked(bool(settings.get("recurse_subfolders", True)))

        form.addRow("Include:", self.cmb_include)
        form.addRow("Exclude:", self.txt_exclude)
        form.addRow("", self.chk_exclude_md5)
        form.addRow("", self.chk_recurse)

        add_layout.addWidget(group)
        add_layout.addStretch(1)

        save_tab = QtWidgets.QWidget()
        save_layout = QtWidgets.QVBoxLayout(save_tab)
        self.chk_save_sidecar = QtWidgets.QCheckBox("Save as sidecar file: <filename>.md5")
        self.chk_save_sidecar.setChecked(bool(settings.get("save_sidecar", True)))
        self.chk_save_uppercase = QtWidgets.QCheckBox("Use uppercase hashes when saving sidecar")
        self.chk_save_uppercase.setChecked(bool(settings.get("save_uppercase", False)))
        save_layout.addWidget(self.chk_save_sidecar)
        save_layout.addWidget(self.chk_save_uppercase)
        save_layout.addStretch(1)

        adv_tab = QtWidgets.QWidget()
        adv_layout = QtWidgets.QFormLayout(adv_tab)

        self.spn_workers = QtWidgets.QSpinBox()
        self.spn_workers.setRange(1, 64)
        self.spn_workers.setValue(int(settings.get("max_workers", max(2, os.cpu_count() or 4))))

        self.spn_chunk = QtWidgets.QSpinBox()
        self.spn_chunk.setRange(64, 4096)
        self.spn_chunk.setSuffix(" KB")
        self.spn_chunk.setValue(int(settings.get("chunk_kb", 1024)))

        self.spn_scan_threads = QtWidgets.QSpinBox()
        self.spn_scan_threads.setRange(1, 64)
        self.spn_scan_threads.setValue(int(settings.get("scan_threads", max(4, min(32, (os.cpu_count() or 8))))))

        self.spn_insert_ms = QtWidgets.QSpinBox()
        self.spn_insert_ms.setRange(2, 200)
        self.spn_insert_ms.setSuffix(" ms")
        self.spn_insert_ms.setValue(int(settings.get("ui_insert_budget_ms", 16)))

        adv_layout.addRow("Max hash workers:", self.spn_workers)
        adv_layout.addRow("Read chunk:", self.spn_chunk)
        adv_layout.addRow("Scan threads:", self.spn_scan_threads)
        adv_layout.addRow("UI insert budget:", self.spn_insert_ms)

        self.tabs.addTab(add_tab, "Add")
        self.tabs.addTab(save_tab, "Save")
        self.tabs.addTab(adv_tab, "Advanced")

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Apply
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        btns.button(QtWidgets.QDialogButtonBox.Apply).clicked.connect(self.apply_to_settings)

        root = QtWidgets.QVBoxLayout(self)
        root.addWidget(self.tabs)
        root.addWidget(btns)

    def apply_to_settings(self) -> None:
        self._settings["auto_start_checking"] = bool(self.chk_autostart.isChecked())
        self._settings["include_patterns"] = self.cmb_include.currentText().strip() or "*.*"
        self._settings["exclude_patterns"] = self.txt_exclude.text().strip()
        self._settings["exclude_md5_files"] = bool(self.chk_exclude_md5.isChecked())
        self._settings["recurse_subfolders"] = bool(self.chk_recurse.isChecked())
        self._settings["save_sidecar"] = bool(self.chk_save_sidecar.isChecked())
        self._settings["save_uppercase"] = bool(self.chk_save_uppercase.isChecked())
        self._settings["max_workers"] = int(self.spn_workers.value())
        self._settings["chunk_kb"] = int(self.spn_chunk.value())
        self._settings["scan_threads"] = int(self.spn_scan_threads.value())
        self._settings["ui_insert_budget_ms"] = int(self.spn_insert_ms.value())

        hist = list(self._settings.get("include_history", []))
        cur = self._settings["include_patterns"]
        if cur:
            hist = [cur] + [x for x in hist if x and x != cur]
        self._settings["include_history"] = hist[:12]

    def accept(self) -> None:
        self.apply_to_settings()
        super().accept()


class DatabaseDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget, db: "HashDB"):
        super().__init__(parent)
        self.setWindowTitle("Database")
        self.setModal(True)
        self.resize(760, 450)

        self.db = db
        self.cmb = QtWidgets.QComboBox()
        self.cmb.setMinimumWidth(470)
        self.lbl_meta = QtWidgets.QLabel("")
        self.lbl_meta.setWordWrap(True)

        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_save_table = QtWidgets.QPushButton("Save current table as snapshot...")
        self.btn_load = QtWidgets.QPushButton("Load snapshot to table")
        self.btn_delete = QtWidgets.QPushButton("Delete snapshot")

        self.btn_load.setEnabled(False)
        self.btn_delete.setEnabled(False)

        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("Snapshots:"))
        top.addWidget(self.cmb, 1)
        top.addWidget(self.btn_refresh)

        btns = QtWidgets.QHBoxLayout()
        btns.addWidget(self.btn_save_table)
        btns.addStretch(1)
        btns.addWidget(self.btn_delete)
        btns.addWidget(self.btn_load)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.lbl_meta)
        layout.addStretch(1)
        layout.addLayout(btns)

        self.btn_refresh.clicked.connect(self.reload)
        self.cmb.currentIndexChanged.connect(self._on_changed)
        self.btn_delete.clicked.connect(self._delete_selected)
        self.reload()

    def reload(self) -> None:
        self.cmb.blockSignals(True)
        self.cmb.clear()
        self._snapshots = self.db.list_snapshots()
        for sid, name, created_at, algo in self._snapshots:
            self.cmb.addItem(f"{name}  [{algo}]  ({created_at})", sid)
        self.cmb.blockSignals(False)
        self._on_changed()

    def selected_snapshot_id(self) -> Optional[int]:
        sid = self.cmb.currentData()
        try:
            return int(sid) if sid is not None else None
        except Exception:
            return None

    def _on_changed(self) -> None:
        sid = self.selected_snapshot_id()
        meta = self.db.get_snapshot_meta(sid) if sid else None
        if not meta:
            self.lbl_meta.setText("No snapshot selected.")
            self.btn_load.setEnabled(False)
            self.btn_delete.setEnabled(False)
            return
        self.btn_load.setEnabled(True)
        self.btn_delete.setEnabled(True)
        self.lbl_meta.setText(
            "Name: {name}\nCreated: {created_at}\nRoot: {root_folder}\nAlgorithm: {algorithm}\n"
            "Include: {include_patterns}\nExclude: {exclude_patterns}\nRecurse: {recurse}".format(**meta)
        )

    def _delete_selected(self) -> None:
        sid = self.selected_snapshot_id()
        if not sid:
            return
        if QtWidgets.QMessageBox.question(self, "Delete snapshot", "Delete selected snapshot?") != QtWidgets.QMessageBox.Yes:
            return
        try:
            self.db.delete_snapshot(sid)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Delete snapshot", f"Failed: {e}")
        self.reload()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 700)
        self.setMinimumSize(940, 560)

        self._settings = self.load_settings()
        self._db = HashDB(self.db_path())

        self._threadpool = QtCore.QThreadPool.globalInstance()
        self._apply_threadpool_settings()

        self.model = HashTableModel(self)
        self.proxy = FilterProxy(self)
        self.proxy.setSourceModel(self.model)

        # v16: debounce search input (helps with 50k-200k rows)
        self._pending_search_text = ""
        self._search_debounce = QtCore.QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.setInterval(200)
        self._search_debounce.timeout.connect(self._apply_search_text)

        self._workers: Dict[str, HashWorker] = {}

        self._scan_worker: Optional[FolderScanWorker] = None
        self._scan_dialog: Optional[QtWidgets.QProgressDialog] = None
        self._scan_queue: "queue.Queue[str]" = queue.Queue(maxsize=400000)
        self._scan_scanned = 0
        self._scan_matched = 0
        self._scan_pending_dirs = 0
        self._scan_rate = 0.0
        self._scan_added = 0
        self._scan_autostart_after = False
        self._scan_errors = 0

        self._insert_timer = QtCore.QTimer(self)
        self._insert_timer.setInterval(0)
        self._insert_timer.timeout.connect(self._flush_scan_queue_timesliced)

        self._start_timer = QtCore.QTimer(self)
        self._start_timer.setInterval(0)
        self._start_timer.timeout.connect(self._start_hash_jobs_timesliced)
        self._start_row_iter = 0
        self._start_force = False
        self._start_only_with_saved = False

        self._tab_buttons: Dict[str, QtWidgets.QToolButton] = {}
        self._current_filter = "All"

        self._build_ui()
        self._wire_actions()
        self._recompute_all_statuses()
        self._update_counts_ui()

    def base_dir(self) -> Path:
        try:
            return Path(__file__).resolve().parent
        except Exception:
            return Path.cwd()

    def settings_path(self) -> Path:
        return self.base_dir() / SETTINGS_FILE

    def db_path(self) -> Path:
        return self.base_dir() / DB_FILE

    def load_settings(self) -> Dict:
        defaults = {
            "auto_start_checking": True,
            "include_patterns": "*.exe;*.dll",
            "exclude_patterns": "*.md5",
            "recurse_subfolders": True,
            "save_sidecar": True,
            "save_uppercase": False,
            "max_workers": max(2, min(4, (os.cpu_count() or 4))),
            "chunk_kb": 1024,
            "include_history": [],
            "algorithm": HashAlgo.MD5,
            "scan_threads": max(4, min(32, (os.cpu_count() or 8))),
            "ui_insert_budget_ms": 16,
            "last_export_path": "",
        }
        p = self.settings_path()
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    defaults.update(data)
            except Exception:
                pass
        if defaults.get("algorithm") not in HashAlgo.all():
            defaults["algorithm"] = HashAlgo.MD5
        return defaults

    def save_settings(self) -> None:
        try:
            self.settings_path().write_text(json.dumps(self._settings, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _apply_threadpool_settings(self) -> None:
        try:
            self._threadpool.setMaxThreadCount(int(self._settings.get("max_workers", 4)))
        except Exception:
            pass

    def _make_tab_button(self, text: str, icon: QtGui.QIcon) -> QtWidgets.QToolButton:
        btn = QtWidgets.QToolButton()
        btn.setCheckable(True)
        btn.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        btn.setIcon(icon)
        btn.setText(text)
        btn.setCursor(QtCore.Qt.PointingHandCursor)
        btn.setStyleSheet(
            """
            QToolButton {
                border: 1px solid #c8c8c8;
                border-radius: 3px;
                padding: 4px 8px;
                background: #f7f7f7;
            }
            QToolButton:checked {
                background: #e6f0ff;
                border: 1px solid #7aa7ff;
            }
            QToolButton:hover { background: #ffffff; }
            """
        )
        return btn

    def _build_ui(self) -> None:
        tb = QtWidgets.QToolBar("Main")
        tb.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        tb.setIconSize(QtCore.QSize(24, 24))
        self.addToolBar(tb)

        style = self.style()
        self.act_save = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton), "Save", self)
        self.act_save_each = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton), "S Each", self)
        self.act_open = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogOpenButton), "Open", self)
        self.act_check = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogApplyButton), "Check", self)

        self.act_add = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_FileDialogNewFolder), "Add", self)
        self.act_remove = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_TrashIcon), "Remove", self)
        self.act_clear = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogResetButton), "Clear", self)
        self.act_start = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_MediaPlay), "Start", self)
        self.act_copy = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogOpenButton), "Copy", self)
        self.act_copy_hash = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogOpenButton), "C Hash", self)
        self.act_locate = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DirIcon), "Locate", self)
        self.act_db = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_DirHomeIcon), "Database", self)
        self.act_options = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView), "Options", self)
        self.act_help = QtGui.QAction(style.standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation), "Help", self)

        for a in [self.act_save, self.act_save_each, self.act_open, self.act_add, self.act_remove, self.act_clear,
                  self.act_start, self.act_check, self.act_copy, self.act_copy_hash, self.act_locate,
                  self.act_db, self.act_options, self.act_help]:
            tb.addAction(a)

        tabs_bar = QtWidgets.QWidget()
        tabs_l = QtWidgets.QHBoxLayout(tabs_bar)
        tabs_l.setContentsMargins(6, 4, 6, 0)
        tabs_l.setSpacing(6)

        ico_all = style.standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView)
        ico_na = style.standardIcon(QtWidgets.QStyle.SP_MessageBoxWarning)
        ico_unknown = style.standardIcon(QtWidgets.QStyle.SP_MessageBoxQuestion)
        ico_loaded = style.standardIcon(QtWidgets.QStyle.SP_BrowserReload)
        ico_new = style.standardIcon(QtWidgets.QStyle.SP_FileDialogNewFolder)
        ico_failed = style.standardIcon(QtWidgets.QStyle.SP_MessageBoxCritical)
        ico_passed = style.standardIcon(QtWidgets.QStyle.SP_DialogApplyButton)

        self._tab_group = QtWidgets.QButtonGroup(self)
        self._tab_group.setExclusive(True)

        def add_tab(name: str, icon: QtGui.QIcon):
            btn = self._make_tab_button(f"{name}(0)", icon)
            self._tab_buttons[name] = btn
            self._tab_group.addButton(btn)
            tabs_l.addWidget(btn)

        add_tab("All", ico_all)
        add_tab(RowStatus.NA, ico_na)
        add_tab(RowStatus.UNKNOWN, ico_unknown)
        add_tab(RowStatus.LOADED, ico_loaded)
        add_tab(RowStatus.NEW, ico_new)
        add_tab(RowStatus.FAILED, ico_failed)
        add_tab(RowStatus.PASSED, ico_passed)
        tabs_l.addStretch(1)

        top = QtWidgets.QWidget()
        top_l = QtWidgets.QHBoxLayout(top)
        top_l.setContentsMargins(6, 6, 6, 0)
        top_l.setSpacing(8)

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Filter by name/path (contains)...")
        self.search_box.setClearButtonEnabled(True)

        self.btn_reload_saved = QtWidgets.QPushButton("Reload Saved Hash")

        self.algo_combo = QtWidgets.QComboBox()
        self.chk_enable_sorting = QtWidgets.QCheckBox("Sorting")
        self.chk_enable_sorting.setToolTip("Enable column sorting (may slow tab switching on huge tables)")
        self.chk_enable_sorting.setChecked(False)
        self.algo_combo.setMinimumWidth(160)
        for algo in HashAlgo.all():
            self.algo_combo.addItem(algo, algo)
        self.algo_combo.setCurrentText(self._settings.get("algorithm", HashAlgo.MD5))

        m = self.algo_combo.model()
        for i in range(self.algo_combo.count()):
            algo = self.algo_combo.itemData(i)
            if not HashAlgo.is_available(algo):
                item = m.item(i)
                if item:
                    item.setEnabled(False)
                    hint = HashAlgo.availability_hint(algo)
                    if hint:
                        item.setToolTip(hint)

        top_l.addWidget(QtWidgets.QLabel("Search:"))
        top_l.addWidget(self.search_box, 1)
        top_l.addWidget(QtWidgets.QLabel("Algo:"))
        top_l.addWidget(self.algo_combo)
        top_l.addWidget(self.chk_enable_sorting)
        top_l.addWidget(self.btn_reload_saved)

        self.view = QtWidgets.QTableView()
        self.view.setModel(self.proxy)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.view.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        # v17: sorting off by default (sorting + filter change can hang with 50k+ rows)
        self.view.setSortingEnabled(False)
        self.view.setAlternatingRowColors(True)
        self.view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.verticalHeader().setVisible(False)
        self.view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

        hdr = self.view.horizontalHeader()
        hdr.setSectionResizeMode(HashTableModel.COL_NAME, QtWidgets.QHeaderView.Interactive)
        hdr.setSectionResizeMode(HashTableModel.COL_IN_FOLDER, QtWidgets.QHeaderView.Stretch)
        hdr.setSectionResizeMode(HashTableModel.COL_CUR, QtWidgets.QHeaderView.Interactive)
        hdr.setSectionResizeMode(HashTableModel.COL_SAVED, QtWidgets.QHeaderView.Interactive)
        self.view.setColumnWidth(HashTableModel.COL_NAME, 240)
        self.view.setColumnWidth(HashTableModel.COL_CUR, 340)
        self.view.setColumnWidth(HashTableModel.COL_SAVED, 340)

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)
        self.lbl_counts = QtWidgets.QLabel("")
        self.status.addPermanentWidget(self.lbl_counts)

        center = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(center)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(6)
        v.addWidget(tabs_bar)
        v.addWidget(top)
        v.addWidget(self.view, 1)
        self.setCentralWidget(center)

        self._tab_buttons["All"].setChecked(True)
    def _wire_actions(self) -> None:
        self.act_add.triggered.connect(self.add_dialog)
        self.act_remove.triggered.connect(self.remove_selected)
        self.act_clear.triggered.connect(self.clear_all)
        self.act_start.triggered.connect(self.start_checking)
        self.act_check.triggered.connect(self.check_loaded_hashes)
        self.act_open.triggered.connect(self.open_hash_text_file)
        self.act_options.triggered.connect(self.open_options)
        self.act_help.triggered.connect(self.open_help)
        self.act_save.triggered.connect(self.save_hash_text_file)
        self.act_save_each.triggered.connect(self.save_selected_sidecar)
        self.act_copy.triggered.connect(self.copy_selected_rows)
        self.act_copy_hash.triggered.connect(self.copy_selected_hashes)
        self.act_locate.triggered.connect(self.locate_selected)
        self.act_db.triggered.connect(self.open_database)
        self.search_box.textChanged.connect(self._on_search_text_changed)
        self.btn_reload_saved.clicked.connect(self.reload_saved_sidecar_for_all)
        self.algo_combo.currentTextChanged.connect(self._on_algo_changed)
        self.chk_enable_sorting.toggled.connect(self._on_sorting_toggled)
        self.view.customContextMenuRequested.connect(self._on_context_menu)
        for name, btn in self._tab_buttons.items():
            btn.clicked.connect(lambda checked=False, n=name: self._set_filter(n))

    def _apply_search_text(self) -> None:
        self.proxy.set_search_text(self._pending_search_text)

    def _on_search_text_changed(self, text: str) -> None:
        self._pending_search_text = text or ""
        self._search_debounce.start()

    def _on_sorting_toggled(self, enabled: bool) -> None:
        # v17: Sorting can make filter/tab switching noticeably slower on very large tables.
        # Keep it optional.
        try:
            self.view.setUpdatesEnabled(False)
            self.view.setSortingEnabled(bool(enabled))
            self.proxy.setDynamicSortFilter(bool(enabled))
            if enabled:
                self.view.sortByColumn(HashTableModel.COL_NAME, QtCore.Qt.AscendingOrder)
        finally:
            self.view.setUpdatesEnabled(True)
    def _set_filter(self, name: str) -> None:
        # v17: Tab switching triggers a full proxy remap; if sorting is enabled it can also trigger
        # a full resort (very expensive for 50k+ rows). We therefore avoid toggling sorting here.
        self.view.setUpdatesEnabled(False)
        try:
            self._current_filter = name
            self.proxy.set_status_filter(name)
        finally:
            self.view.setUpdatesEnabled(True)

    def _on_context_menu(self, pos: QtCore.QPoint) -> None:
        menu = QtWidgets.QMenu(self)
        menu.addAction(self.act_start)
        menu.addAction(self.act_check)
        menu.addSeparator()
        menu.addAction(self.act_save)
        menu.addAction(self.act_open)
        menu.addSeparator()
        menu.addAction(self.act_save_each)
        menu.addSeparator()
        menu.addAction(self.act_copy)
        menu.addAction(self.act_copy_hash)
        menu.addSeparator()
        menu.addAction(self.act_locate)
        menu.addSeparator()
        menu.addAction(self.act_remove)
        menu.exec(self.view.viewport().mapToGlobal(pos))

    def _on_algo_changed(self, algo: str) -> None:
        self._settings["algorithm"] = algo
        self.save_settings()
        for it in self.model._rows:
            it.current_hash = ""
            if not it.path.exists():
                it.status = RowStatus.UNKNOWN
            else:
                it.status = RowStatus.LOADED if it.saved_hash else RowStatus.NEW
        self.model.layoutChanged.emit()
        self._update_counts_ui()

    def _patterns_from_text(self, text: str) -> List[str]:
        parts = re.split(r"[;,]\s*|\s+", (text or "").strip())
        out = [p.strip() for p in parts if p.strip()]
        return out or ["*.*"]

    def _selected_source_rows(self) -> List[int]:
        rows: List[int] = []
        sel = self.view.selectionModel()
        if not sel:
            return rows
        for idx in sel.selectedRows():
            src = self.proxy.mapToSource(idx)
            if src.isValid():
                rows.append(src.row())
        return sorted(set(rows))

    def _selected_items(self) -> List[FileItem]:
        out: List[FileItem] = []
        for r in self._selected_source_rows():
            it = self.model.get_item(r)
            if it:
                out.append(it)
        return out

    def _update_counts_ui(self) -> None:
        counts = self.model.counts()
        for name, btn in self._tab_buttons.items():
            btn.setText(f"{name}({counts.get(name, 0)})")
        self.lbl_counts.setText(
            f"All({counts.get('All', 0)})   N/A({counts.get(RowStatus.NA, 0)})   "
            f"Unknown({counts.get(RowStatus.UNKNOWN, 0)})   Loaded({counts.get(RowStatus.LOADED, 0)})   "
            f"New({counts.get(RowStatus.NEW, 0)})   Failed({counts.get(RowStatus.FAILED, 0)})   "
            f"Passed({counts.get(RowStatus.PASSED, 0)})"
        )

    def add_dialog(self) -> None:
        menu = QtWidgets.QMenu(self)
        a_files = menu.addAction("Add files...")
        a_folder = menu.addAction("Add folder (fast, scalable)...")
        chosen = menu.exec(QtGui.QCursor.pos())
        if chosen == a_files:
            self.add_files()
        elif chosen == a_folder:
            self.add_folder_nonblocking()

    def add_files(self) -> None:
        paths, _ = QtWidgets.QFileDialog.getOpenFileNames(self, "Select files", str(Path.home()))
        if not paths:
            return
        items: List[FileItem] = []
        for p in paths:
            pp = Path(p)
            if not pp.exists():
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.UNKNOWN)
            elif not pp.is_file():
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.NA)
            else:
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.NEW)
                ok = self._load_saved_sidecar(it)
                if it.saved_hash:
                    it.status = RowStatus.LOADED
                elif not ok:
                    it.status = RowStatus.NA
            items.append(it)
        self.model.add_items(items)
        self._update_counts_ui()
        if bool(self._settings.get("auto_start_checking", True)):
            self.start_checking()

    def add_folder_nonblocking(self) -> None:
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder", str(Path.home()))
        if not folder:
            return
        self._start_folder_scan(folder)

    def _start_folder_scan(self, folder: str) -> None:
        include = self._patterns_from_text(str(self._settings.get("include_patterns", "*.*")))
        exclude = self._patterns_from_text(str(self._settings.get("exclude_patterns", "")))
        recurse = bool(self._settings.get("recurse_subfolders", True))
        scan_threads = int(self._settings.get("scan_threads", max(4, min(32, (os.cpu_count() or 8)))))

        self._scan_scanned = self._scan_matched = self._scan_pending_dirs = self._scan_added = 0
        self._scan_rate = 0.0
        self._scan_errors = 0
        self._scan_autostart_after = bool(self._settings.get("auto_start_checking", True))

        try:
            while True:
                self._scan_queue.get_nowait()
        except Exception:
            pass

        dlg = QtWidgets.QProgressDialog("Scanning folders...", "Cancel", 0, 0, self)
        dlg.setWindowTitle("Add folder")
        dlg.setWindowModality(QtCore.Qt.WindowModal)
        dlg.setAutoClose(False)
        dlg.setAutoReset(False)
        dlg.setMinimumDuration(0)
        dlg.canceled.connect(self._cancel_folder_scan)
        self._scan_dialog = dlg
        dlg.show()

        worker = FolderScanWorker(folder, include, exclude, recurse, threads=scan_threads,
                                exclude_md5_files=bool(self._settings.get('exclude_md5_files', True)))
        self._scan_worker = worker
        worker.signals.batch.connect(self._on_scan_batch)
        worker.signals.progress_ex.connect(self._on_scan_progress)
        worker.signals.error.connect(self._on_scan_error)
        worker.signals.finished.connect(self._on_scan_finished)
        self._threadpool.start(worker)

        self._insert_timer.start()

    def _cancel_folder_scan(self) -> None:
        if self._scan_worker is not None:
            self._scan_worker.abort()

    @QtCore.Slot(list)
    def _on_scan_batch(self, paths: List[str]) -> None:
        for p in paths:
            try:
                self._scan_queue.put_nowait(p)
            except Exception:
                self._scan_errors += 1
                break

    @QtCore.Slot(int, int, int, float)
    def _on_scan_progress(self, scanned: int, matched: int, pending_dirs: int, rate_eps: float) -> None:
        self._scan_scanned = int(scanned)
        self._scan_matched = int(matched)
        self._scan_pending_dirs = int(pending_dirs)
        self._scan_rate = float(rate_eps)
        self._update_scan_dialog_text()

    @QtCore.Slot(str)
    def _on_scan_error(self, msg: str) -> None:
        self._scan_errors += 1
        if self._scan_dialog is not None:
            self._scan_dialog.setLabelText(f"[WARN] Scan error (#{self._scan_errors}): {msg}")

    @QtCore.Slot()
    def _on_scan_finished(self) -> None:
        self._scan_worker = None
        self._update_scan_dialog_text(done=True)

    def _update_scan_dialog_text(self, done: bool = False) -> None:
        if self._scan_dialog is None:
            return
        try:
            qsize = self._scan_queue.qsize()
        except Exception:
            qsize = 0
        label = (
            f"Scanning... scanned={self._scan_scanned:,}  matched={self._scan_matched:,}  "
            f"queued={qsize:,}  added={self._scan_added:,}  pending_dirs={self._scan_pending_dirs:,}  "
            f"rate={self._scan_rate:,.0f}/sec"
        )
        if self._scan_errors:
            label += f"  errors={self._scan_errors}"
        if done:
            label = "Finishing... " + label
        self._scan_dialog.setLabelText(label)

    def _flush_scan_queue_timesliced(self) -> None:
        budget_ms = int(self._settings.get("ui_insert_budget_ms", 16))
        t_end = time.perf_counter() + (budget_ms / 1000.0)

        items: List[FileItem] = []
        took = 0
        while took < 3000 and time.perf_counter() < t_end:
            try:
                p = self._scan_queue.get_nowait()
            except Exception:
                break
            took += 1
            pp = Path(p)
            if not pp.exists():
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.UNKNOWN)
            elif not pp.is_file():
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.NA)
            else:
                it = FileItem(path=pp, in_folder=str(pp.parent), status=RowStatus.NEW)
                ok = self._load_saved_sidecar(it)
                if it.saved_hash:
                    it.status = RowStatus.LOADED
                elif not ok:
                    it.status = RowStatus.NA
            items.append(it)

        if items:
            self._scan_added += self.model.add_items(items)
            self._update_counts_ui()

        self._update_scan_dialog_text(done=(self._scan_worker is None))

        if self._scan_worker is None:
            try:
                empty = self._scan_queue.qsize() == 0
            except Exception:
                empty = True
            if empty:
                self._insert_timer.stop()
                if self._scan_dialog is not None:
                    self._scan_dialog.close()
                    self._scan_dialog = None
                if self._scan_autostart_after:
                    self.start_checking()

    def remove_selected(self) -> None:
        rows = self._selected_source_rows()
        if not rows:
            return
        keep: List[FileItem] = []
        to_remove = set(rows)
        for i, it in enumerate(self.model._rows):
            if i not in to_remove:
                keep.append(it)

        self.model.beginResetModel()
        self.model._rows = keep
        self.model._key_to_row = {it.key(): i for i, it in enumerate(self.model._rows)}
        self.model.rebuild_counts()
        self.model.endResetModel()
        self._update_counts_ui()

    def clear_all(self) -> None:
        self._cancel_folder_scan()
        self.model.clear_all()
        self._workers.clear()
        self._update_counts_ui()

    def open_options(self) -> None:
        dlg = OptionsDialog(self, self._settings)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            self._apply_threadpool_settings()
            self.save_settings()

    def open_help(self) -> None:
        QtWidgets.QMessageBox.information(
            self, "Help",
            "Save/Open/Check text hashes\n\n"
            "Optional algorithms:\n"
            "- BLAKE3: pip install blake3\n"
            "- XXH3-128: pip install xxhash\n"
        )

    def locate_selected(self) -> None:
        items = self._selected_items()
        if not items:
            return
        p = items[0].path
        if not p.exists():
            QtWidgets.QMessageBox.warning(self, "Locate", "File does not exist.")
            return
        try:
            import subprocess
            subprocess.Popen(["explorer", "/select,", str(p)])
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Locate", "Failed to open Explorer.")

    def copy_selected_rows(self) -> None:
        items = self._selected_items()
        if not items:
            return
        algo = self._settings.get("algorithm", HashAlgo.MD5)
        lines = [f"{it.path}\t{algo}\t{it.current_hash}\t{it.saved_hash}\t{it.status}" for it in items]
        QtWidgets.QApplication.clipboard().setText("\n".join(lines))

    def copy_selected_hashes(self) -> None:
        items = self._selected_items()
        if not items:
            return
        QtWidgets.QApplication.clipboard().setText("\n".join([it.current_hash for it in items if it.current_hash]))

    def _load_saved_sidecar(self, it: FileItem) -> bool:
        try:
            p = sidecar_md5_path(it.path)
            if not p.exists():
                it.saved_hash = ""
                return True
            hv = parse_hash_from_text(safe_read_text(p))
            if hv:
                it.saved_hash = hv
                return True
            it.saved_hash = ""
            return False
        except Exception:
            it.saved_hash = ""
            return False

    def reload_saved_sidecar_for_all(self) -> None:
        self.setCursor(QtCore.Qt.BusyCursor)
        try:
            for it in self.model._rows:
                if not it.path.exists():
                    self.model.update_fields_by_key(it.key(), saved_hash="", status=RowStatus.UNKNOWN)
                    continue
                ok = self._load_saved_sidecar(it)
                if it.saved_hash:
                    st = RowStatus.LOADED
                else:
                    st = RowStatus.NEW if ok else RowStatus.NA
                self.model.update_fields_by_key(it.key(), saved_hash=it.saved_hash, status=st)
        finally:
            self.unsetCursor()
        self._update_counts_ui()

    def _write_sidecar(self, it: FileItem) -> Tuple[bool, str]:
        if not it.current_hash:
            return False, "No current hash to save."
        if not bool(self._settings.get("save_sidecar", True)):
            return False, "Sidecar saving disabled in Options."
        hv = it.current_hash.upper() if bool(self._settings.get("save_uppercase", False)) else it.current_hash
        out = hv + "  " + it.path.name + "\n"
        try:
            p = sidecar_md5_path(it.path)
            p.write_text(out, encoding="utf-8")
            return True, str(p)
        except Exception as e:
            return False, str(e)

    def save_selected_sidecar(self) -> None:
        items = self._selected_items()
        if not items:
            return
        okc = 0
        fail = 0
        errors = []
        for it in items:
            if not it.path.exists():
                fail += 1
                errors.append(f"{it.path}: does not exist")
                self.model.update_fields_by_key(it.key(), status=RowStatus.UNKNOWN)
                continue
            s_ok, info = self._write_sidecar(it)
            if s_ok:
                okc += 1
                new_status = self._refresh_compare_status(it)
                self.model.update_fields_by_key(it.key(), saved_hash=it.current_hash.lower(), status=new_status)
            else:
                fail += 1
                errors.append(f"{it.path}: {info}")
        self._update_counts_ui()
        if errors:
            QtWidgets.QMessageBox.information(self, "Save sidecar", f"Saved: {okc}\nFailed: {fail}\n\n" + "\n".join(errors[:18]) + (""
                if len(errors) <= 18 else "\n..."))

    def save_hash_text_file(self) -> None:
        if self.model.rowCount() == 0:
            QtWidgets.QMessageBox.information(self, "Save", "Table is empty.")
            return
        last = self._settings.get("last_export_path", "")
        start_dir = str(Path(last).parent) if last else str(self.base_dir())
        default_name = f"hashes_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        out_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save hashes", os.path.join(start_dir, default_name), EXPORT_EXT)
        if not out_path:
            return
        algo = self._settings.get("algorithm", HashAlgo.MD5)
        lines = []
        lines.append(f"# Md5Checker export\talgo={algo}\tcreated={time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("# Format: <hash>\\t<absolute_path>")
        saved = 0
        for it in self.model._rows:
            hv = (it.current_hash or it.saved_hash or "").strip().lower()
            if not hv:
                continue
            lines.append(f"{hv}\t{it.path}")
            saved += 1
        try:
            outp = Path(out_path)
            tmp = outp.with_suffix(outp.suffix + ".tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                os.replace(str(tmp), str(outp))
            except Exception:
                outp.write_text(tmp.read_text(encoding='utf-8', errors='replace'), encoding='utf-8')
                try:
                    tmp.unlink()
                except Exception:
                    pass
            self._settings["last_export_path"] = out_path
            self.save_settings()
            QtWidgets.QMessageBox.information(self, "Save", f"Saved {saved} hashes.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Save", f"Failed: {e}")

    def _parse_export_file(self, path: Path) -> Tuple[Optional[str], List[Tuple[str, str]]]:
        algo = None
        rows: List[Tuple[str, str]] = []
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s:
                    continue
                if s.startswith("#"):
                    m = re.search(r"algo=([A-Z0-9\-]+)", s)
                    if m:
                        algo = m.group(1).strip()
                    continue
                parts = s.split("\t")
                if len(parts) >= 2:
                    a = parts[0].strip()
                    b = "\t".join(parts[1:]).strip()
                    ha = parse_hash_from_text(a) or ""
                    hb = parse_hash_from_text(b) or ""
                    if ha and not hb:
                        rows.append((ha, b))
                    elif hb and not ha:
                        rows.append((hb, a))
                    else:
                        m2 = re.match(r"^([a-fA-F0-9]{16,128})\s+(.+)$", s)
                        if m2:
                            rows.append((m2.group(1).lower(), m2.group(2).strip()))
                    continue
                m2 = re.match(r"^([a-fA-F0-9]{16,128})\s+(.+)$", s)
                if m2:
                    rows.append((m2.group(1).lower(), m2.group(2).strip()))
        except Exception:
            return None, []
        return algo, rows

    def open_hash_text_file(self) -> None:
        last = self._settings.get("last_export_path", "")
        start_dir = str(Path(last).parent) if last else str(self.base_dir())
        in_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open hashes", start_dir, EXPORT_EXT)
        if not in_path:
            return
        algo, rows = self._parse_export_file(Path(in_path))
        if algo and algo in HashAlgo.all() and HashAlgo.is_available(algo):
            self._settings["algorithm"] = algo
            self.save_settings()
            self.algo_combo.setCurrentText(algo)

        self.clear_all()
        items: List[FileItem] = []
        for hv, p in rows:
            pp = Path(p)
            if not pp.exists():
                st = RowStatus.UNKNOWN
            elif not pp.is_file():
                st = RowStatus.NA
            else:
                st = RowStatus.LOADED
            items.append(FileItem(pp, str(pp.parent), "", hv.lower(), st))

        dlg = QtWidgets.QProgressDialog("Loading hashes...", "Cancel", 0, len(items), self)
        dlg.setWindowTitle("Open hashes")
        dlg.setWindowModality(QtCore.Qt.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.show()

        step = 5000
        for i in range(0, len(items), step):
            if dlg.wasCanceled():
                break
            self.model.add_items(items[i:i+step])
            dlg.setValue(min(i + step, len(items)))
            QtWidgets.QApplication.processEvents()

        dlg.close()
        self._settings["last_export_path"] = in_path
        self.save_settings()
        self._recompute_all_statuses()
        self._update_counts_ui()

    def check_loaded_hashes(self) -> None:
        self.start_checking(force=True, only_with_saved=True)

    def open_database(self) -> None:
        dlg = DatabaseDialog(self, self._db)

        def on_save():
            self._db_save_current_table_flow(dlg)

        def on_load():
            sid = dlg.selected_snapshot_id()
            if sid:
                self._db_load_snapshot_to_table(sid)
                dlg.accept()

        dlg.btn_save_table.clicked.connect(on_save)
        dlg.btn_load.clicked.connect(on_load)
        dlg.exec()

    def _compute_common_root(self, paths: List[str]) -> str:
        if not paths:
            return ""
        try:
            root = os.path.commonpath(paths)
            if os.path.isfile(root):
                root = os.path.dirname(root)
            return root
        except Exception:
            try:
                return str(Path(paths[0]).parent)
            except Exception:
                return ""

    def _db_save_current_table_flow(self, dlg: DatabaseDialog) -> None:
        if self.model.rowCount() == 0:
            QtWidgets.QMessageBox.information(self, "Save snapshot", "Table is empty.")
            return

        default_name = f"snapshot_{time.strftime('%Y%m%d_%H%M%S')}"
        name, ok = QtWidgets.QInputDialog.getText(self, "Snapshot name", "Name:", text=default_name)
        if not ok:
            return
        name = (name or "").strip()
        if not name:
            QtWidgets.QMessageBox.warning(self, "Snapshot name", "Name cannot be empty.")
            return

        algo = self._settings.get("algorithm", HashAlgo.MD5)
        include = str(self._settings.get("include_patterns", "*.*"))
        exclude = str(self._settings.get("exclude_patterns", ""))
        recurse = bool(self._settings.get("recurse_subfolders", True))

        abs_paths = [str(it.path) for it in self.model._rows if it.status not in (RowStatus.NA, RowStatus.UNKNOWN)]
        root_folder = self._compute_common_root(abs_paths) if abs_paths else ""

        try:
            snapshot_id = self._db.create_snapshot(name, root_folder, algo, include, exclude, recurse)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Save snapshot", f"Failed: {e}")
            return

        rows = []
        saved = 0
        skipped = 0
        for it in self.model._rows:
            if it.status in (RowStatus.NA, RowStatus.UNKNOWN):
                skipped += 1
                continue
            hv = (it.current_hash or it.saved_hash or "").strip().lower()
            if not hv:
                skipped += 1
                continue
            try:
                st = it.path.stat()
                size = int(st.st_size)
                mtime = float(st.st_mtime)
            except Exception:
                size, mtime = 0, 0.0

            ap = str(it.path)
            try:
                if root_folder:
                    rel = os.path.relpath(ap, root_folder)
                    if rel.startswith(".."):
                        rel = ABS_PREFIX + ap
                    else:
                        rel = rel.replace("\\", "/")
                else:
                    rel = ABS_PREFIX + ap
            except Exception:
                rel = ABS_PREFIX + ap

            rows.append((rel, size, mtime, hv))
            saved += 1

        try:
            self._db.upsert_snapshot_files(snapshot_id, rows)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Save snapshot", f"Failed writing files: {e}")
            return

        dlg.reload()
        QtWidgets.QMessageBox.information(self, "Save snapshot", f"Snapshot saved.\nRows saved: {saved}\nSkipped: {skipped}")

    def _db_load_snapshot_to_table(self, snapshot_id: int) -> None:
        meta = self._db.get_snapshot_meta(snapshot_id)
        if not meta:
            return
        root = Path(meta["root_folder"]) if meta.get("root_folder") else Path("")
        algo = meta["algorithm"]
        if algo in HashAlgo.all() and HashAlgo.is_available(algo):
            self._settings["algorithm"] = algo
            self.save_settings()
            self.algo_combo.setCurrentText(algo)

        self.clear_all()

        files = self._db.load_snapshot_files(snapshot_id)
        items = []
        for rel_path, size, mtime, hv in files:
            if rel_path.startswith(ABS_PREFIX):
                abs_path = Path(rel_path[len(ABS_PREFIX):])
            else:
                abs_path = (root / rel_path) if str(root) else Path(rel_path)
            status = RowStatus.UNKNOWN if not abs_path.exists() else RowStatus.LOADED
            items.append(FileItem(abs_path, str(abs_path.parent), "", hv, status, snapshot_id, rel_path))

        dlg = QtWidgets.QProgressDialog("Loading snapshot...", "Cancel", 0, len(items), self)
        dlg.setWindowTitle("Load snapshot")
        dlg.setWindowModality(QtCore.Qt.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.show()

        step = 5000
        for i in range(0, len(items), step):
            if dlg.wasCanceled():
                break
            self.model.add_items(items[i:i+step])
            dlg.setValue(min(i + step, len(items)))
            QtWidgets.QApplication.processEvents()

        dlg.close()
        self._update_counts_ui()

    def _is_cache_valid(self, it: FileItem, algo: str) -> bool:
        if not it.current_hash:
            return False
        if getattr(it, 'last_algo', '') != algo:
            return False
        try:
            st = it.path.stat()
            return (getattr(it, 'last_size', -1) == int(st.st_size)) and (abs(getattr(it, 'last_mtime', -1.0) - float(st.st_mtime)) < 0.0001)
        except Exception:
            return False

    def start_checking(self, force: bool = False, only_with_saved: bool = False) -> None:
        algo = self._settings.get("algorithm", HashAlgo.MD5)
        if not HashAlgo.is_available(algo):
            QtWidgets.QMessageBox.warning(self, "Algorithm", "Selected algorithm is not available.")
            return
        if self._start_timer.isActive():
            return
        self._start_row_iter = 0
        self._start_force = bool(force)
        self._start_only_with_saved = bool(only_with_saved)
        self.status.showMessage("Queueing hash jobs...")
        self._start_timer.start()

    def _start_hash_jobs_timesliced(self) -> None:
        algo = self._settings.get("algorithm", HashAlgo.MD5)
        chunk_bytes = int(self._settings.get("chunk_kb", 1024)) * 1024

        t_end = time.perf_counter() + 0.014
        started = 0
        total = self.model.rowCount()

        while self._start_row_iter < total and time.perf_counter() < t_end and started < 600:
            it = self.model.get_item(self._start_row_iter)
            self._start_row_iter += 1
            if not it:
                continue

            if self._start_only_with_saved and not it.saved_hash:
                continue

            if not it.path.exists():
                if it.status != RowStatus.UNKNOWN:
                    self.model.update_fields_by_key(it.key(), status=RowStatus.UNKNOWN, current_hash="")
                continue

            if not it.path.is_file():
                self.model.update_fields_by_key(it.key(), status=RowStatus.NA, current_hash="")
                continue

            if it.key() in self._workers:
                continue

            # v16 cache: if unchanged (size/mtime) and same algorithm, reuse existing hash
            if (not self._start_force) and self._is_cache_valid(it, algo):
                continue

            w = HashWorker(it.key(), it.path, algo, chunk_bytes)
            self._workers[it.key()] = w
            w.signals.progress.connect(self._on_worker_progress)
            w.signals.result.connect(self._on_worker_result)
            w.signals.finished.connect(self._on_worker_finished)
            self._threadpool.start(w)
            started += 1

        if total > 0:
            pct = int((self._start_row_iter / max(1, total)) * 100)
            self.status.showMessage(f"Queueing hash jobs... {pct}%  active_jobs={len(self._workers)}")

        if self._start_row_iter >= total:
            self._start_timer.stop()
            self.status.showMessage("Hashing...")

        self._update_counts_ui()

    @QtCore.Slot(str, int, int)
    def _on_worker_progress(self, key: str, done: int, total: int) -> None:
        try:
            name = Path(key).name
        except Exception:
            name = "file"
        if total > 0:
            pct = int((done / total) * 100)
            self.status.showMessage(f"Hashing: {name}  {pct}%  active_jobs={len(self._workers)}")
        else:
            self.status.showMessage(f"Hashing... active_jobs={len(self._workers)}")
    def _refresh_compare_status(self, it: FileItem) -> str:
        """
        Return the correct status for this row WITHOUT mutating it.status.
        This is important so that update_fields_by_key() can correctly bump counters
        using the old status -> new status transition.
        """
        if not it.path.exists():
            return RowStatus.UNKNOWN
        if it.saved_hash:
            if it.current_hash and it.current_hash.lower() == it.saved_hash.lower():
                return RowStatus.PASSED
            if it.current_hash:
                return RowStatus.FAILED
            return RowStatus.LOADED
        return RowStatus.NEW


    @QtCore.Slot(str, str, str)
    def _on_worker_result(self, key: str, hv: str, err: str) -> None:
        algo = self._settings.get("algorithm", HashAlgo.MD5)
        row = self.model.find_row_by_key(key)
        if row is None:
            return
        it = self.model.get_item(row)
        if not it:
            return

        if err:
            self.model.update_fields_by_key(key, current_hash="", status=RowStatus.NA)
        else:
            new_status = self._refresh_compare_status(it)
            self.model.update_fields_by_key(key, current_hash=hv, status=new_status)

        self._update_counts_ui()


    def _recompute_all_statuses(self) -> None:
        """
        Safety pass:
        After hashing or after loading saved hashes, ensure status is consistent:
        - If saved_hash + current_hash => Passed/Failed
        - If saved_hash only         => Loaded
        - If no saved_hash           => New
        - Missing file               => Unknown
        This guarantees rows move into Passed/Failed tabs reliably.
        """
        changed = 0
        for it in self.model._rows:
            old = it.status
            new = self._refresh_compare_status(it)
            if new != old:
                self.model.update_fields_by_key(it.key(), status=new)
                changed += 1
        if changed:
            self._update_counts_ui()

    @QtCore.Slot(str)
    def _on_worker_finished(self, key: str) -> None:
        self._workers.pop(key, None)
        self._update_counts_ui()
        if not self._workers and not self._start_timer.isActive():
            self._recompute_all_statuses()
            self.status.showMessage("Ready")

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self._cancel_folder_scan()
        self.save_settings()
        super().closeEvent(event)


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setOrganizationName(APP_ORG)
    app.setApplicationName(APP_TITLE)
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())