"""双向交接确认。

系统按审计排序（起始时间升序；起止倒置的事件与审计链一致不参与）取每一对
相邻事件作为一个 **交接项**：上一段是交出方，下一段是接收方。两侧分别填写
确认人姓名与确认时间；只有两侧均确认 **且** 上一段结束时间等于下一段开始时间，
交接项才标记为 ``confirmed``（已确认），否则为 ``pending``（待确认）或
``time_mismatch``（时间不一致）。

每条确认记录生成时都绑定两条事件当时的关键字段摘要（经手人 / 起始时间 /
结束时间 / 备注）以及二者合并后的 SHA-256 摘要。此后：

* 任一事件被编辑（关键字段变化）；
* 任一事件被删除；
* 新增 / 调整事件导致这对事件不再相邻；

原 active 记录都会原样保留、仅标记为 ``invalidated``（附原因与失效时间），
不再计入任何有效状态，必须由两侧重新确认。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Optional
from sqlite3 import Connection

from .audit import parse_dt

# 交接项状态
CONFIRMED = "confirmed"
PENDING = "pending"
TIME_MISMATCH = "time_mismatch"

# 确认记录状态
ACTIVE = "active"
INVALIDATED = "invalidated"

# 失效原因
REASON_EVENT_EDITED = "event_edited"
REASON_EVENT_DELETED = "event_deleted"
REASON_ADJACENCY_CHANGED = "adjacency_changed"

STATUS_TEXT = {
    CONFIRMED: "已确认",
    PENDING: "待确认",
    TIME_MISMATCH: "时间不一致",
}

REASON_TEXT = {
    REASON_EVENT_EDITED: "关联事件被编辑，绑定字段已变化",
    REASON_EVENT_DELETED: "关联事件已被删除",
    REASON_ADJACENCY_CHANGED: "事件新增或调整后两条记录不再相邻",
}

# 绑定时纳入摘要的关键字段（任一变化都会使原确认失效）
KEY_FIELDS = ("custodian", "start_time", "end_time", "note")


class HandoverError(Exception):
    """业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 摘要 ----------

def event_snapshot(event: dict[str, Any]) -> dict[str, Any]:
    """一条事件在确认当时的关键字段摘要。"""
    return {key: event.get(key) for key in KEY_FIELDS}


def pair_digest(snapshot_a: dict[str, Any], snapshot_b: dict[str, Any]) -> str:
    raw = json.dumps(
        {"from": snapshot_a, "to": snapshot_b}, ensure_ascii=False, sort_keys=True
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------- 相邻关系 ----------

def ordered_events(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    """返回与审计链一致的、按起始时间排序的事件（排除时间不可解析 / 起止倒置）。"""
    rows = conn.execute(
        "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    parsed: list[tuple[datetime, dict[str, Any]]] = []
    for r in rows:
        try:
            start = parse_dt(r["start_time"])
        except ValueError:
            continue
        if start is None:
            continue
        try:
            end = parse_dt(r["end_time"])
        except ValueError:
            end = None
        if end is not None and end < start:
            continue  # 起止倒置事件不参与区间链 / 相邻关系
        parsed.append(
            (
                start,
                {
                    "id": r["id"],
                    "sample_id": r["sample_id"],
                    "custodian": r["custodian"],
                    "start_time": r["start_time"],
                    "end_time": r["end_time"],
                    "note": r["note"],
                    "seq": r["seq"],
                },
            )
        )
    parsed.sort(key=lambda item: (item[0], item[1]["id"]))
    return [event for _, event in parsed]


def _time_consistent(prev_event: dict[str, Any], next_event: dict[str, Any]) -> bool:
    """上一段结束时间必须存在且严格等于下一段开始时间。"""
    if not prev_event.get("end_time"):
        return False
    try:
        return parse_dt(prev_event["end_time"]) == parse_dt(next_event["start_time"])
    except ValueError:
        return False


# ---------- 失效维护 ----------

def refresh_handover_validity(
    conn: Connection, sample_id: int, now: Optional[str] = None
) -> None:
    """事件增删改后调用：按当前数据把不再有效的 active 确认标记为失效（原行保留）。"""
    events = ordered_events(conn, sample_id)
    by_id = {e["id"]: e for e in events}
    adjacent_pairs = {
        (a["id"], b["id"]) for a, b in zip(events, events[1:])
    }
    now = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = conn.execute(
        "SELECT * FROM handovers WHERE sample_id = ? AND status = ?",
        (sample_id, ACTIVE),
    ).fetchall()
    for r in rows:
        reason: Optional[str] = None
        a = by_id.get(r["from_event_id"])
        b = by_id.get(r["to_event_id"])
        if a is None or b is None:
            reason = REASON_EVENT_DELETED
        elif (r["from_event_id"], r["to_event_id"]) not in adjacent_pairs:
            reason = REASON_ADJACENCY_CHANGED
        elif (
            json.loads(r["from_event_snapshot"]) != event_snapshot(a)
            or json.loads(r["to_event_snapshot"]) != event_snapshot(b)
        ):
            reason = REASON_EVENT_EDITED
        if reason is not None:
            conn.execute(
                "UPDATE handovers SET status = ?, invalidated_reason = ?, "
                "invalidated_at = ? WHERE id = ?",
                (INVALIDATED, reason, now, r["id"]),
            )


# ---------- 视图 ----------

def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event["id"],
        "seq": event["seq"],
        "custodian": event["custodian"],
        "start_time": event["start_time"],
        "end_time": event["end_time"],
        "note": event["note"],
    }


def _confirmation_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "from_name": row["from_name"],
        "from_confirmed_at": row["from_confirmed_at"],
        "to_name": row["to_name"],
        "to_confirmed_at": row["to_confirmed_at"],
        "digest": row["digest"][:12],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _history_dict(row: Any) -> dict[str, Any]:
    """失效记录视图：交接双方信息取自绑定快照，事件删除后仍可展示。"""
    from_snap = json.loads(row["from_event_snapshot"])
    to_snap = json.loads(row["to_event_snapshot"])
    reason = row["invalidated_reason"]
    return {
        "id": row["id"],
        "from_event_id": row["from_event_id"],
        "to_event_id": row["to_event_id"],
        "from_custodian": from_snap.get("custodian"),
        "from_end_time": from_snap.get("end_time"),
        "to_custodian": to_snap.get("custodian"),
        "to_start_time": to_snap.get("start_time"),
        "from_name": row["from_name"],
        "from_confirmed_at": row["from_confirmed_at"],
        "to_name": row["to_name"],
        "to_confirmed_at": row["to_confirmed_at"],
        "digest": row["digest"][:12],
        "reason": reason,
        "reason_text": REASON_TEXT.get(reason, reason or "—"),
        "invalidated_at": row["invalidated_at"],
        "created_at": row["created_at"],
    }


def build_handover_view(conn: Connection, sample_id: int) -> dict[str, Any]:
    """组装交接项列表（含当前有效确认）、失效记录与统计。"""
    events = ordered_events(conn, sample_id)

    active: dict[tuple[int, int], Any] = {}
    history: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT * FROM handovers WHERE sample_id = ? ORDER BY id DESC", (sample_id,)
    ).fetchall()
    for r in rows:
        if r["status"] == ACTIVE:
            # 正常情况下每对相邻事件至多一条 active；倒序取最新一条
            active.setdefault((r["from_event_id"], r["to_event_id"]), r)
        else:
            history.append(_history_dict(r))

    items: list[dict[str, Any]] = []
    confirmed_count = pending_count = mismatch_count = 0
    for index, (a, b) in enumerate(zip(events, events[1:]), start=1):
        consistent = _time_consistent(a, b)
        row = active.get((a["id"], b["id"]))
        confirmation = None
        status = PENDING
        if row is not None:
            confirmation = _confirmation_dict(row)
            if row["from_name"] and row["to_name"]:
                status = CONFIRMED if consistent else TIME_MISMATCH
        if status == CONFIRMED:
            confirmed_count += 1
        elif status == TIME_MISMATCH:
            mismatch_count += 1
        else:
            pending_count += 1
        items.append(
            {
                "index": index,
                "from_event": _public_event(a),
                "to_event": _public_event(b),
                "handover_at": a["end_time"],
                "time_consistent": consistent,
                "status": status,
                "status_text": STATUS_TEXT[status],
                "confirmation": confirmation,
            }
        )

    return {
        "items": items,
        "history": history,
        "summary": {
            "total": len(items),
            "confirmed": confirmed_count,
            "pending": pending_count,
            "time_mismatch": mismatch_count,
            "invalidated": len(history),
        },
    }


def get_handover_record(conn: Connection, handover_id: int) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM handovers WHERE id = ?", (handover_id,)
    ).fetchone()
    if row is None:
        raise HandoverError("交接确认记录不存在", status_code=404)
    from_snap = json.loads(row["from_event_snapshot"])
    to_snap = json.loads(row["to_event_snapshot"])
    reason = row["invalidated_reason"]
    return {
        "id": row["id"],
        "sample_id": row["sample_id"],
        "from_event_id": row["from_event_id"],
        "to_event_id": row["to_event_id"],
        "status": row["status"],
        "from_name": row["from_name"],
        "from_confirmed_at": row["from_confirmed_at"],
        "to_name": row["to_name"],
        "to_confirmed_at": row["to_confirmed_at"],
        "from_event_snapshot": from_snap,
        "to_event_snapshot": to_snap,
        "digest": row["digest"],
        "invalidated_reason": reason,
        "invalidated_reason_text": REASON_TEXT.get(reason, reason) if reason else None,
        "invalidated_at": row["invalidated_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# ---------- 确认写入 ----------

def confirm_handover(
    conn: Connection,
    sample_id: int,
    from_event_id: int,
    to_event_id: int,
    side: str,
    confirmer_name: str,
    confirmed_at: str,
) -> dict[str, Any]:
    """交出方（side='from'）或接收方（side='to'）填写姓名与确认时间。"""
    rows = conn.execute(
        "SELECT * FROM events WHERE id IN (?, ?)", (from_event_id, to_event_id)
    ).fetchall()
    by_id = {r["id"]: r for r in rows}
    if from_event_id == to_event_id or from_event_id not in by_id or to_event_id not in by_id:
        raise HandoverError("交接事件不存在", status_code=404)
    if by_id[from_event_id]["sample_id"] != sample_id or by_id[to_event_id]["sample_id"] != sample_id:
        raise HandoverError("交接事件不存在或不属于该样本", status_code=404)

    # 先按当前数据维护失效状态，再判断相邻关系
    refresh_handover_validity(conn, sample_id)
    ordered = ordered_events(conn, sample_id)
    ordered_ids = [e["id"] for e in ordered]
    if from_event_id not in ordered_ids or to_event_id not in ordered_ids:
        raise HandoverError("交接事件当前无法参与确认（时间缺失或起止倒置）")
    pos = ordered_ids.index(from_event_id)
    if pos + 1 >= len(ordered_ids) or ordered_ids[pos + 1] != to_event_id:
        raise HandoverError("两条事件当前不是审计排序中的相邻事件，无法确认该交接项")

    a = next(e for e in ordered if e["id"] == from_event_id)
    b = next(e for e in ordered if e["id"] == to_event_id)
    snap_a = event_snapshot(a)
    snap_b = event_snapshot(b)
    digest = pair_digest(snap_a, snap_b)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    row = conn.execute(
        "SELECT * FROM handovers WHERE sample_id = ? AND from_event_id = ? "
        "AND to_event_id = ? AND status = ? ORDER BY id DESC",
        (sample_id, from_event_id, to_event_id, ACTIVE),
    ).fetchone()

    if row is None:
        # 该交接项的第一轮确认：记录两侧事件当时的关键字段摘要
        fields = {
            "from": ("from_name", "from_confirmed_at"),
            "to": ("to_name", "to_confirmed_at"),
        }[side]
        values = {
            "from_name": confirmer_name if side == "from" else None,
            "from_confirmed_at": confirmed_at if side == "from" else None,
            "to_name": confirmer_name if side == "to" else None,
            "to_confirmed_at": confirmed_at if side == "to" else None,
        }
        cur = conn.execute(
            "INSERT INTO handovers (sample_id, from_event_id, to_event_id, status, "
            "from_name, from_confirmed_at, to_name, to_confirmed_at, "
            "from_event_snapshot, to_event_snapshot, digest, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sample_id, from_event_id, to_event_id, ACTIVE,
                values["from_name"], values["from_confirmed_at"],
                values["to_name"], values["to_confirmed_at"],
                json.dumps(snap_a, ensure_ascii=False),
                json.dumps(snap_b, ensure_ascii=False),
                digest, now, now,
            ),
        )
        handover_id = cur.lastrowid
    else:
        # 防御性校验：active 记录绑定的摘要必须与当前事件一致，
        # 若 refresh 之外出现漂移，原记录同样作废并重新开始
        if (
            json.loads(row["from_event_snapshot"]) != snap_a
            or json.loads(row["to_event_snapshot"]) != snap_b
        ):
            conn.execute(
                "UPDATE handovers SET status = ?, invalidated_reason = ?, "
                "invalidated_at = ? WHERE id = ?",
                (INVALIDATED, REASON_EVENT_EDITED, now, row["id"]),
            )
            return confirm_handover(
                conn, sample_id, from_event_id, to_event_id,
                side, confirmer_name, confirmed_at,
            )

        name_col, time_col = {
            "from": ("from_name", "from_confirmed_at"),
            "to": ("to_name", "to_confirmed_at"),
        }[side]
        if row[name_col]:
            role = "交出方" if side == "from" else "接收方"
            raise HandoverError(f"该交接项的{role}侧已完成确认，无需重复提交")
        conn.execute(
            f"UPDATE handovers SET {name_col} = ?, {time_col} = ?, updated_at = ? WHERE id = ?",
            (confirmer_name, confirmed_at, now, row["id"]),
        )
        handover_id = row["id"]

    view = build_handover_view(conn, sample_id)
    item = next(
        (
            i
            for i in view["items"]
            if i["from_event"]["id"] == from_event_id
            and i["to_event"]["id"] == to_event_id
        ),
        None,
    )
    return {"handover_id": handover_id, "item": item, "view": view}
