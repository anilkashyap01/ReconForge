"""SQLite schema and small helpers. All timestamps are UTC ISO-8601 strings."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import ensure_dirs, get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope_entries(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, value TEXT NOT NULL, excluded INTEGER NOT NULL DEFAULT 0,
  authorization_note TEXT NOT NULL DEFAULT '', authorized_at TEXT, created_at TEXT NOT NULL,
  UNIQUE(project_id, kind, value, excluded));
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile TEXT NOT NULL, status TEXT NOT NULL, config_json TEXT NOT NULL, scope_json TEXT NOT NULL,
  exclusions_json TEXT NOT NULL, authorization_confirmed INTEGER NOT NULL DEFAULT 0,
  active_testing_confirmed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, started_at TEXT,
  completed_at TEXT, error TEXT, summary_json TEXT NOT NULL DEFAULT '{}',
  cancel_requested INTEGER NOT NULL DEFAULT 0, pause_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS scan_stages(
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  position INTEGER NOT NULL, name TEXT NOT NULL, tool TEXT NOT NULL, label TEXT NOT NULL,
  touches_target INTEGER NOT NULL DEFAULT 1, traffic_note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', started_at TEXT, finished_at TEXT, items INTEGER NOT NULL DEFAULT 0,
  input_count INTEGER NOT NULL DEFAULT 0, input_hash TEXT, attempts INTEGER NOT NULL DEFAULT 0,
  message TEXT, error TEXT, output_json TEXT, cached_from_scan INTEGER, cached_at TEXT,
  UNIQUE(scan_id, name));
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, value TEXT NOT NULL, sources TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, first_scan_id INTEGER, last_scan_id INTEGER,
  UNIQUE(project_id, kind, value));
CREATE TABLE IF NOT EXISTS asset_scans(
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT '', PRIMARY KEY(scan_id, asset_id, source));
CREATE TABLE IF NOT EXISTS dns_records(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host TEXT NOT NULL, rtype TEXT NOT NULL, value TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  last_scan_id INTEGER, UNIQUE(project_id, host, rtype, value));
CREATE TABLE IF NOT EXISTS ports(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp', service TEXT, product TEXT,
  version TEXT, source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id INTEGER,
  UNIQUE(project_id, host, ip, port, protocol));
CREATE TABLE IF NOT EXISTS endpoints(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  url TEXT NOT NULL, host TEXT NOT NULL, status_code INTEGER, title TEXT, webserver TEXT,
  technologies TEXT NOT NULL DEFAULT '[]', content_length INTEGER, kind TEXT NOT NULL DEFAULT 'http',
  source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id INTEGER,
  UNIQUE(project_id, url));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', asset TEXT NOT NULL,
  url TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL, confidence TEXT NOT NULL, source TEXT NOT NULL,
  template_id TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '',
  refs TEXT NOT NULL DEFAULT '[]', tool_version TEXT, template_version TEXT,
  validation_status TEXT NOT NULL DEFAULT 'unvalidated', analyst_notes TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, first_scan_id INTEGER, last_scan_id INTEGER,
  UNIQUE(project_id, fingerprint));
CREATE TABLE IF NOT EXISTS finding_scans(
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  PRIMARY KEY(scan_id, finding_id));
CREATE TABLE IF NOT EXISTS tool_runs(
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, stage_name TEXT NOT NULL,
  tool TEXT NOT NULL, version TEXT, argv_json TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, exit_code INTEGER,
  status TEXT NOT NULL, timed_out INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0,
  stdout_bytes INTEGER NOT NULL DEFAULT 0, stderr_tail TEXT NOT NULL DEFAULT '', error TEXT, stdout_head TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS scan_logs(
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ts TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS integrations(
  name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, last_success TEXT, last_error TEXT,
  backoff_until TEXT, usage_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT);
CREATE TABLE IF NOT EXISTS integration_results(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, scan_id INTEGER,
  provider TEXT NOT NULL, subject TEXT NOT NULL, payload_json TEXT NOT NULL, fetched_at TEXT NOT NULL,
  UNIQUE(project_id, provider, subject));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id, kind);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_stages_scan ON scan_stages(scan_id, position);
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def init_db() -> None:
    ensure_dirs()
    path = get_settings().db_path
    with db() as conn:
        conn.executescript(SCHEMA)
        migrate(conn)
    os.chmod(path, 0o600)


def migrate(conn: sqlite3.Connection) -> None:
    """Upgrade databases created by earlier versions without losing data."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(tool_runs)")}
    if "stdout_head" not in cols:
        conn.execute("ALTER TABLE tool_runs ADD COLUMN stdout_head TEXT NOT NULL DEFAULT ''")
    sql = (conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='ports'").fetchone() or {"sql": ""})["sql"]
    if "UNIQUE(project_id, host, port, protocol)" in sql:      # old key kept only one IP per host:port
        conn.executescript("""
            ALTER TABLE ports RENAME TO ports_old;
            CREATE TABLE ports(
              id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
              host TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp', service TEXT, product TEXT,
              version TEXT, source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id INTEGER,
              UNIQUE(project_id, host, ip, port, protocol));
            INSERT INTO ports(id,project_id,host,ip,port,protocol,service,product,version,source,first_seen,last_seen,last_scan_id)
              SELECT id,project_id,host,COALESCE(ip,''),port,protocol,service,product,version,source,first_seen,last_seen,last_scan_id FROM ports_old;
            DROP TABLE ports_old;
        """)


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(str(get_settings().db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def q(conn: sqlite3.Connection, sql: str, args: tuple | list = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def q1(conn: sqlite3.Connection, sql: str, args: tuple | list = ()) -> dict[str, Any] | None:
    row = conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def get_setting(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row["value"])
    except json.JSONDecodeError:
        return default


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, json.dumps(value)))
