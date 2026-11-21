"""SQLite persistence: topology snapshots, baseline, audit events, and snapshot diffs."""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Optional

from .drift import diff_states
from .models import CloudState

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, label TEXT,
    fingerprint TEXT, state_json TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, detail_json TEXT);
"""


class Store:
    def __init__(self, path: str = "aerodrift.db"):
        self.con = sqlite3.connect(path)
        self.con.executescript(SCHEMA)

    def save_snapshot(self, state: CloudState, label: str = "auto") -> int:
        cur = self.con.execute(
            "INSERT INTO snapshots(ts,label,fingerprint,state_json) VALUES(?,?,?,?)",
            (state.captured_at, label, state.fingerprint(), json.dumps(state.to_dict())))
        self.con.commit()
        return cur.lastrowid

    def set_baseline(self, state: CloudState) -> int:
        return self.save_snapshot(state, "baseline")

    def get(self, snapshot_id: int) -> Optional[CloudState]:
        row = self.con.execute("SELECT state_json FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        return CloudState.from_dict(json.loads(row[0])) if row else None

    def get_baseline(self) -> Optional[CloudState]:
        row = self.con.execute(
            "SELECT state_json FROM snapshots WHERE label='baseline' ORDER BY id DESC LIMIT 1").fetchone()
        return CloudState.from_dict(json.loads(row[0])) if row else None

    def list_snapshots(self) -> list:
        return self.con.execute("SELECT id, ts, label, fingerprint FROM snapshots ORDER BY id").fetchall()

    def diff(self, id_a: int, id_b: int) -> list:
        a, b = self.get(id_a), self.get(id_b)
        if a is None or b is None:
            raise KeyError("unknown snapshot id")
        return diff_states(a, b)

    def log_event(self, kind: str, detail: dict) -> None:
        self.con.execute("INSERT INTO events(ts,kind,detail_json) VALUES(?,?,?)",
                         (time.time(), kind, json.dumps(detail, default=str)))
        self.con.commit()

    def events(self) -> list:
        return [(r[0], r[1], json.loads(r[2])) for r in
                self.con.execute("SELECT ts, kind, detail_json FROM events ORDER BY id")]
