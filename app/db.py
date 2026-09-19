"""SQLite 数据访问层。

启动时调用 ``init_db()`` 建表并写入演示数据，保证开箱即可看到
断档 / 重叠 / 逆序三类审计效果。
"""
from __future__ import annotations

import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from typing import Iterator

DB_PATH = os.environ.get("AUDIT_DB_PATH", os.path.join(os.path.dirname(__file__), "audit.db"))


def get_connection() -> sqlite3.Connection:
    # check_same_thread=False：FastAPI 异步路由与其同步依赖可能由线程池中的
    # 不同工作线程执行；连接本身是请求级独占（请求结束即提交关闭），跨线程安全。
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # 批量导入确认以 BEGIN IMMEDIATE 抢写锁；并发请求等待而非立即报 database is locked，
    # 排队者持锁后会因事件链指纹不匹配而被业务层拒绝（要求重新预览）
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def get_conn() -> Iterator[sqlite3.Connection]:
    """FastAPI 请求级依赖：请求结束自动提交并关闭连接。"""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id  INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    custodian  TEXT    NOT NULL,
    start_time TEXT    NOT NULL,
    end_time   TEXT,
    note       TEXT    NOT NULL DEFAULT '',
    seq        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_sample ON events(sample_id);

CREATE TABLE IF NOT EXISTS signoffs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id     INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    signer        TEXT    NOT NULL,
    signed_at     TEXT    NOT NULL,
    remark        TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'active',
    revoke_reason TEXT,
    revoked_at    TEXT,
    snapshot      TEXT    NOT NULL,
    digest        TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signoffs_sample ON signoffs(sample_id);

-- 双向交接确认：审计排序中每对相邻事件一条确认记录（多轮确认产生多行）。
-- from_* 为交出方、to_* 为接收方；事件快照与 digest 在确认当时绑定，
-- 事件后续被编辑/删除或相邻关系变化时仅置 invalidated，原行保留。
-- 事件外键不加 ON DELETE CASCADE：删除事件后失效记录仍需可查。
CREATE TABLE IF NOT EXISTS handovers (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id            INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    from_event_id        INTEGER NOT NULL,
    to_event_id          INTEGER NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'active',
    from_name            TEXT,
    from_confirmed_at    TEXT,
    to_name              TEXT,
    to_confirmed_at      TEXT,
    from_event_snapshot  TEXT    NOT NULL,
    to_event_snapshot    TEXT    NOT NULL,
    digest               TEXT    NOT NULL,
    invalidated_reason   TEXT,
    invalidated_at       TEXT,
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handovers_sample ON handovers(sample_id);
CREATE INDEX IF NOT EXISTS idx_handovers_pair
    ON handovers(from_event_id, to_event_id);

-- 异常处置队列：跨样本的审计发现处置状态。发现身份为 SHA-256 稳定指纹
-- （样本 + 关联事件 + 异常类型 + 时间边界），与列表顺序无关；
-- 链路变更后重算：仍存在沿用状态、消失转已消除、新出现未处理。
-- version 为乐观锁：处置写入必须携带客户端看到的版本，过期返回 409。
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT    NOT NULL UNIQUE,
    sample_id     INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    code          TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    event_ids     TEXT    NOT NULL DEFAULT '[]',
    custodians    TEXT    NOT NULL DEFAULT '[]',
    time_from     TEXT,
    time_to       TEXT,
    status        TEXT    NOT NULL DEFAULT 'open',
    handler       TEXT,
    note          TEXT    NOT NULL DEFAULT '',
    version       INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL,
    resolved_at   TEXT,
    eliminated_at TEXT,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_sample ON findings(sample_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- 状态迁移记录：首次出现、人工处置与系统自动迁移（消除 / 复现）全部留痕
CREATE TABLE IF NOT EXISTS finding_transitions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status   TEXT    NOT NULL,
    handler     TEXT,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ftrans_finding ON finding_transitions(finding_id);
"""


def init_db() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        _seed_demo_data(conn)


def _seed_demo_data(conn: sqlite3.Connection) -> None:
    """数据库为空时写入两个演示样本（其中一个故意包含断档与重叠）。"""
    if conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0] > 0:
        return

    today = date.today()
    base = datetime.combine(today, datetime.min.time()).replace(hour=9)

    def t(h: float, m: float = 0) -> str:
        return (base + timedelta(hours=h, minutes=m)).strftime("%Y-%m-%d %H:%M:%S")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "INSERT INTO samples (code, name, description, created_at) VALUES (?, ?, ?, ?)",
        ("SAM-DEMO-001", "演示样本·异常链路", "用于演示断档、重叠与逆序录入的检测效果", now),
    )
    sid = cur.lastrowid
    rows = [
        ("张三（采集组）", t(0), t(1), "现场采集并密封"),
        ("李四（运输组）", t(1), t(2, 30), "冷链车运输，温度 2-8℃"),
        # 录入顺序逆序（第三条先登记，时间却最早）
        ("赵六（档案室）", t(0, 30), t(0, 45), "事后补录的档案登记——时间早于录入顺序"),
        # 与上一条之间存在 40 分钟无人保管断档
        ("王五（检测组）", t(3, 10), t(4, 30), "实验室接收并检测"),
        # 与王五区间重叠
        ("孙七（留样柜）", t(4), t(5, 15), "检测期间并行留样"),
        # 仍在保管中，未归还
        ("周八（留样柜）", t(5, 15), None, "留样观察中"),
    ]
    event_ids = []
    for seq, (custodian, start, end, note) in enumerate(rows, start=1):
        ins = conn.execute(
            "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sid, custodian, start, end, note, seq),
        )
        event_ids.append(ins.lastrowid)

    cur = conn.execute(
        "INSERT INTO samples (code, name, description, created_at) VALUES (?, ?, ?, ?)",
        ("SAM-DEMO-002", "演示样本·完整链路", "各段交接无缝衔接，当前仍在保管中", now),
    )
    sid2 = cur.lastrowid
    rows2 = [
        ("张三（采集组）", t(0), t(1), "现场采集"),
        ("李四（运输组）", t(1), t(2, 30), "冷链运输"),
        ("王五（检测组）", t(2, 30), None, "检测中，尚未归还"),
    ]
    event_ids2 = []
    for seq, (custodian, start, end, note) in enumerate(rows2, start=1):
        ins = conn.execute(
            "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sid2, custodian, start, end, note, seq),
        )
        event_ids2.append(ins.lastrowid)

    _seed_handovers(conn, sid, event_ids, rows, sid2, event_ids2, rows2, now)


def _seed_handovers(
    conn: sqlite3.Connection,
    sid: int,
    ids: list[int],
    rows: list[tuple[str, str, str | None, str]],
    sid2: int,
    ids2: list[int],
    rows2: list[tuple[str, str, str | None, str]],
    now: str,
) -> None:
    """预置双向交接确认演示记录（含一条已失效的历史记录）。"""
    from .handovers import (
        ACTIVE,
        INVALIDATED,
        REASON_ADJACENCY_CHANGED,
        event_snapshot,
        pair_digest,
    )

    def snapshot(sample_id: int, event_id: int) -> dict:
        r = conn.execute(
            "SELECT custodian, start_time, end_time, note FROM events WHERE id = ?",
            (event_id,),
        ).fetchone()
        return event_snapshot(dict(r))

    def insert(sample_id, a, b, from_name, from_at, to_name, to_at,
               status, invalidated_reason=None, invalidated_at=None):
        sa, sb = snapshot(sample_id, a), snapshot(sample_id, b)
        conn.execute(
            "INSERT INTO handovers (sample_id, from_event_id, to_event_id, status, "
            "from_name, from_confirmed_at, to_name, to_confirmed_at, "
            "from_event_snapshot, to_event_snapshot, digest, "
            "invalidated_reason, invalidated_at, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sample_id, a, b, status,
                from_name, from_at, to_name, to_at,
                json.dumps(sa, ensure_ascii=False), json.dumps(sb, ensure_ascii=False),
                pair_digest(sa, sb),
                invalidated_reason, invalidated_at, now, now,
            ),
        )

    # 异常链路：按起始时间排序后，孙七（ids[5-1]? 见下）14:15 归还、
    # 周八 14:15 接手，是唯一时间一致的相邻交接 —— 两侧均已确认
    e_sun, e_zhou = ids[4], ids[5]
    insert(
        sid, e_sun, e_zhou,
        "孙七", "2026-01-01 14:16:00",
        "周八", "2026-01-01 14:16:30",
        ACTIVE,
    )
    # 历史失效记录：张三→李四曾在 10:00 完成双向确认，
    # 赵六的补录事件（ids[2]）插入到两人之间后不再相邻，原确认保留为失效
    e_zhang, e_li = ids[0], ids[1]
    insert(
        sid, e_zhang, e_li,
        "张三", "2026-01-01 10:01:00",
        "李四", "2026-01-01 10:01:00",
        INVALIDATED,
        invalidated_reason=REASON_ADJACENCY_CHANGED,
        invalidated_at=now,
    )
    # 完整链路：第一段（张三→李四）两侧均已确认；第二段（李四→王五）待确认
    insert(
        sid2, ids2[0], ids2[1],
        "张三", "2026-01-01 10:02:00",
        "李四", "2026-01-01 10:02:00",
        ACTIVE,
    )
