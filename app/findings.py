"""异常处置队列。

跨样本汇总审计引擎发现的异常（断档 / 重叠 / 起止倒置 / 逆序录入 / 时间错误），
并为每条发现维护处置状态：未处理 ``open`` / 已处理 ``resolved`` /
已消除 ``eliminated``（历史）。

发现的身份不依赖列表顺序（禁止按数组序号绑定），而是由 **样本 + 关联事件 +
异常类型 + 时间边界** 生成 SHA-256 稳定指纹。每次链路（交接事件）增删改、
或查看队列 / 汇总时，系统按当前数据重算全部发现的指纹并与库存记录比对：

* 指纹仍在    —— 同一条发现，沿用原有处置状态（仅刷新消息快照与最近出现时间）；
* 指纹消失    —— 转为「已消除」历史，原记录与处置信息保留，不计入未处理数，
                 未到期的限时认领租约随之一并失效；
* 指纹新出现  —— 以「未处理」入库；若命中一条已消除记录（同一异常复现），
                 则恢复原记录为未处理（版本号递增，租约不恢复、保持未认领）。

限时认领
========
未处理发现可由处置人认领，租约 **15 分钟**（``CLAIM_TTL_SECONDS``，可用环境
变量 ``AUDIT_CLAIM_TTL_SECONDS`` 覆盖）。认领 / 接管在 **单一事务** 内完成：
先按当前链路重算发现指纹，再同时校验 ``expected_version`` 与租约状态——

* 版本号过期                              -> 409（请刷新队列后重试）；
* 租约仍被其他人持有（未到期）           -> 409；
* 未被认领、认领人自己重复认领、租约到期 -> 认领 / 接管成功并递增版本。

只有**当前认领人**可以标记已处理或主动释放租约；未认领的未处理发现不能直接
处置。认领人重复提交认领是幂等的（不续期、不重复记录）。
异常被系统消除时租约自动失效；同一异常复现后保持未认领。

每次状态迁移（含系统自动迁移）都写入 ``finding_transitions`` 留痕，认领、释放、
过期接管分别以 ``event = claim / release / takeover`` 记录，可回看。
处置写入（标记已处理 / 重新打开）必须携带客户端看到的指纹版本号
``expected_version``：版本不一致说明期间状态已被他人更新或链路已变化，
返回 409 冲突，客户端应刷新队列后重试。
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Optional
from sqlite3 import Connection

from .audit import build_audit, parse_dt

# 处置状态
OPEN = "open"
RESOLVED = "resolved"
ELIMINATED = "eliminated"

STATUS_TEXT = {
    OPEN: "未处理",
    RESOLVED: "已处理",
    ELIMINATED: "已消除",
}

# 处置动作
ACTION_RESOLVE = "resolve"
ACTION_REOPEN = "reopen"

# 迁移记录类型：处置状态迁移 / 限时认领 / 主动释放 / 到期接管
EVENT_STATUS_CHANGE = "status_change"
EVENT_CLAIM = "claim"
EVENT_RELEASE = "release"
EVENT_TAKEOVER = "takeover"

EVENT_TEXT = {
    EVENT_STATUS_CHANGE: "状态迁移",
    EVENT_CLAIM: "限时认领",
    EVENT_RELEASE: "主动释放",
    EVENT_TAKEOVER: "到期接管",
}

# 认领租约时长（秒）：默认 15 分钟，可用环境变量覆盖
CLAIM_TTL_SECONDS = max(1, int(os.environ.get("AUDIT_CLAIM_TTL_SECONDS", "900")))


class FindingError(Exception):
    """业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _claim_deadline(now: Optional[datetime] = None) -> str:
    """认领租约到期时间（当前时间 + CLAIM_TTL_SECONDS）。"""
    base = now or datetime.now()
    return (base + timedelta(seconds=CLAIM_TTL_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")


def _lease_active(row: Any, now: str) -> bool:
    """租约是否仍有效：存在认领人且到期时间晚于当前时间。"""
    return bool(row["claimed_by"]) and bool(row["claim_expires_at"]) and row["claim_expires_at"] > now


# ---------- 稳定指纹 ----------

def finding_fingerprint(
    sample_id: int,
    code: str,
    event_ids: list[int],
    time_from: Optional[str],
    time_to: Optional[str],
) -> str:
    """发现身份 = 样本 + 关联事件 + 异常类型 + 时间边界 的 SHA-256。

    与事件在列表中的位置、发现数组序号无关；任一边界变化都视为另一条发现。
    """
    raw = json.dumps(
        {
            "sample_id": sample_id,
            "code": code,
            "event_ids": sorted(int(e) for e in event_ids),
            "time_from": time_from,
            "time_to": time_to,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finding_bounds(
    finding: dict[str, Any], events_by_id: dict[int, dict[str, Any]]
) -> tuple[Optional[str], Optional[str]]:
    """发现的时间边界：断档 / 重叠自带 from/to；其余类型取关联事件的起止范围。

    返回的 ``time_to`` 为 None 表示开放（关联事件仍在保管中）。
    """
    if "from" in finding or "to" in finding:
        return finding.get("from"), finding.get("to")
    starts: list[str] = []
    ends: list[str] = []
    open_end = False
    for eid in finding.get("event_ids") or []:
        ev = events_by_id.get(eid)
        if ev is None:
            continue
        if ev.get("start_time"):
            starts.append(str(ev["start_time"]))
        if ev.get("end_time"):
            ends.append(str(ev["end_time"]))
        else:
            open_end = True
    time_from = min(starts) if starts else None
    time_to = None if open_end else (max(ends) if ends else None)
    return time_from, time_to


def _finding_custodians(
    finding: dict[str, Any], events_by_id: dict[int, dict[str, Any]]
) -> list[str]:
    """关联事件的经手人（去重，用于队列的经手人筛选）。"""
    custodians: list[str] = []
    for eid in finding.get("event_ids") or []:
        ev = events_by_id.get(eid)
        if ev and ev.get("custodian") and ev["custodian"] not in custodians:
            custodians.append(ev["custodian"])
    return custodians


def _record_transition(
    conn: Connection,
    finding_id: int,
    from_status: Optional[str],
    to_status: str,
    handler: Optional[str],
    note: str,
    now: str,
    event: str = EVENT_STATUS_CHANGE,
) -> None:
    conn.execute(
        "INSERT INTO finding_transitions (finding_id, from_status, to_status, event, "
        "handler, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (finding_id, from_status, to_status, event, handler, note, now),
    )


# ---------- 同步（重算指纹并比对） ----------

def sync_sample_findings(
    conn: Connection, sample_id: int, now: Optional[str] = None
) -> dict[str, int]:
    """按当前事件链重算发现指纹，比对库存记录并迁移状态（幂等）。

    链路编辑后：仍存在的发现沿用处置状态；消失的转为已消除历史；
    新出现的保持未处理。返回各项迁移计数。
    """
    now = now or _now()
    rows = conn.execute(
        "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    events = [dict(r) for r in rows]
    events_by_id = {e["id"]: e for e in events}
    audit = build_audit(events)

    current: dict[str, dict[str, Any]] = {}
    for f in audit["findings"]:
        event_ids = [int(e) for e in (f.get("event_ids") or [])]
        time_from, time_to = _finding_bounds(f, events_by_id)
        fp = finding_fingerprint(sample_id, f["code"], event_ids, time_from, time_to)
        if fp in current:
            continue  # 完全同指纹的重复发现只记一条
        current[fp] = {
            "code": f["code"],
            "kind": f["kind"],
            "message": f["message"],
            "event_ids": event_ids,
            "custodians": _finding_custodians(f, events_by_id),
            "time_from": time_from,
            "time_to": time_to,
        }

    existing = conn.execute(
        "SELECT * FROM findings WHERE sample_id = ?", (sample_id,)
    ).fetchall()
    by_fp = {r["fingerprint"]: r for r in existing}
    stats = {"new": 0, "kept": 0, "eliminated": 0, "reappeared": 0}

    for fp, info in current.items():
        event_ids_json = json.dumps(info["event_ids"], ensure_ascii=False)
        custodians_json = json.dumps(info["custodians"], ensure_ascii=False)
        row = by_fp.get(fp)
        if row is None:
            # ON CONFLICT：并发请求同时首次同步同一指纹时，后者转为走更新分支
            cur = conn.execute(
                "INSERT INTO findings (fingerprint, sample_id, code, kind, message, "
                "event_ids, custodians, time_from, time_to, status, version, "
                "first_seen_at, last_seen_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?) "
                "ON CONFLICT(fingerprint) DO NOTHING",
                (
                    fp, sample_id, info["code"], info["kind"], info["message"],
                    event_ids_json, custodians_json,
                    info["time_from"], info["time_to"], OPEN,
                    now, now, now, now,
                ),
            )
            if cur.rowcount:
                _record_transition(
                    conn, cur.lastrowid, None, OPEN, None, "异常首次出现", now
                )
                stats["new"] += 1
                continue
            row = conn.execute(
                "SELECT * FROM findings WHERE fingerprint = ?", (fp,)
            ).fetchone()

        if row["status"] == ELIMINATED:
            # 同一指纹的异常复现：恢复原记录为未处理，历史迁移留痕；
            # 旧租约不恢复，复现后保持未认领（租约随消除已失效）
            conn.execute(
                "UPDATE findings SET status = ?, message = ?, event_ids = ?, "
                "custodians = ?, time_from = ?, time_to = ?, eliminated_at = ?, "
                "claimed_by = NULL, claim_expires_at = NULL, claimed_at = NULL, "
                "last_seen_at = ?, version = version + 1, updated_at = ? WHERE id = ?",
                (
                    OPEN, info["message"], event_ids_json, custodians_json,
                    info["time_from"], info["time_to"], now, now, now, row["id"],
                ),
            )
            _record_transition(
                conn, row["id"], ELIMINATED, OPEN, None,
                "异常再次出现，恢复为未处理", now,
            )
            stats["reappeared"] += 1
        else:
            # 仍存在：沿用处置状态，仅刷新消息快照与最近出现时间
            conn.execute(
                "UPDATE findings SET message = ?, event_ids = ?, custodians = ?, "
                "time_from = ?, time_to = ?, last_seen_at = ? WHERE id = ?",
                (
                    info["message"], event_ids_json, custodians_json,
                    info["time_from"], info["time_to"], now, row["id"],
                ),
            )
            stats["kept"] += 1

    for fp, row in by_fp.items():
        if fp in current or row["status"] == ELIMINATED:
            continue
        # 链路变更后消失：转为已消除历史（原记录与处置信息保留）；
        # 未到期的限时认领租约随异常消除自动失效
        had_lease = _lease_active(row, now)
        conn.execute(
            "UPDATE findings SET status = ?, eliminated_at = ?, "
            "claimed_by = NULL, claim_expires_at = NULL, claimed_at = NULL, "
            "version = version + 1, updated_at = ? WHERE id = ?",
            (ELIMINATED, now, now, row["id"]),
        )
        _record_transition(
            conn, row["id"], row["status"], ELIMINATED, None,
            "链路变更后该异常不再出现，转为已消除", now,
        )
        if had_lease:
            _record_transition(
                conn, row["id"], row["status"], ELIMINATED, row["claimed_by"],
                "异常已被系统消除，限时认领租约自动失效", now, event=EVENT_RELEASE,
            )
        stats["eliminated"] += 1
    return stats


def sync_all_findings(conn: Connection) -> None:
    """对全部样本执行指纹重算（队列 / 汇总读取前调用）。"""
    ids = [r["id"] for r in conn.execute("SELECT id FROM samples").fetchall()]
    for sid in ids:
        sync_sample_findings(conn, sid)


# ---------- 视图 ----------

CLAIM_STATE_UNCLAIMED = "unclaimed"
CLAIM_STATE_MINE = "mine"
CLAIM_STATE_CLAIMED = "claimed"
CLAIM_STATE_EXPIRED = "expired"

CLAIM_STATE_TEXT = {
    CLAIM_STATE_UNCLAIMED: "未认领",
    CLAIM_STATE_MINE: "我已认领",
    CLAIM_STATE_CLAIMED: "认领中",
    CLAIM_STATE_EXPIRED: "已过期可接管",
}


def _lease_view(row: Any, now: datetime) -> dict[str, Any]:
    """计算认领租约视图：认领人、到期时间、剩余秒数与租约是否仍有效。

    租约到期后 ``claim_active`` 为 False，当前认领人字段置空（视为未认领、
    可被任何人接管），原认领人保留在 ``last_claimed_by`` 仅供展示。
    """
    claimed_by = row["claimed_by"]
    expires = row["claim_expires_at"]
    if not claimed_by or not expires:
        return {
            "claimed_by": None,
            "last_claimed_by": None,
            "claimed_at": None,
            "claim_expires_at": None,
            "claim_ttl_seconds": CLAIM_TTL_SECONDS,
            "remaining_seconds": 0,
            "claim_active": False,
        }
    try:
        deadline = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        deadline = None
    active = deadline is not None and deadline > now
    if active:
        remaining = int((deadline - now).total_seconds())
        return {
            "claimed_by": claimed_by,
            "last_claimed_by": claimed_by,
            "claimed_at": row["claimed_at"],
            "claim_expires_at": expires,
            "claim_ttl_seconds": CLAIM_TTL_SECONDS,
            "remaining_seconds": max(0, remaining),
            "claim_active": True,
        }
    return {
        "claimed_by": None,
        "last_claimed_by": claimed_by,
        "claimed_at": None,
        "claim_expires_at": None,
        "claim_ttl_seconds": CLAIM_TTL_SECONDS,
        "remaining_seconds": 0,
        "claim_active": False,
    }


def _finding_dict(row: Any, now: Optional[datetime] = None) -> dict[str, Any]:
    now = now or datetime.now()
    lease = _lease_view(row, now)
    return {
        "fingerprint": row["fingerprint"],
        "version": row["version"],
        "sample": {
            "id": row["sample_id"],
            "code": row["sample_code"],
            "name": row["sample_name"],
        },
        "code": row["code"],
        "kind": row["kind"],
        "message": row["message"],
        "event_ids": json.loads(row["event_ids"]),
        "custodians": json.loads(row["custodians"]),
        "time_from": row["time_from"],
        "time_to": row["time_to"],
        "status": row["status"],
        "status_text": STATUS_TEXT.get(row["status"], row["status"]),
        "handler": row["handler"],
        "note": row["note"],
        "first_seen_at": row["first_seen_at"],
        "last_seen_at": row["last_seen_at"],
        "resolved_at": row["resolved_at"],
        "eliminated_at": row["eliminated_at"],
        "claimed_by": lease["claimed_by"],
        "last_claimed_by": lease["last_claimed_by"],
        "claimed_at": lease["claimed_at"],
        "claim_expires_at": lease["claim_expires_at"],
        "claim_ttl_seconds": lease["claim_ttl_seconds"],
        "remaining_seconds": lease["remaining_seconds"],
        "claim_active": lease["claim_active"],
        "updated_at": row["updated_at"],
    }


def queue_summary(conn: Connection, now: Optional[str] = None) -> dict[str, int]:
    """未处理 / 已处理 / 已消除 / 累计数量（全局，不受筛选影响）。

    另含 ``claimed``：当前持有有效认领租约的未处理发现数。
    """
    now = now or _now()
    counts = {OPEN: 0, RESOLVED: 0, ELIMINATED: 0}
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM findings GROUP BY status"):
        if r["status"] in counts:
            counts[r["status"]] = r["n"]
    claimed = conn.execute(
        "SELECT COUNT(*) AS n FROM findings "
        "WHERE status = ? AND claimed_by IS NOT NULL AND claim_expires_at > ?",
        (OPEN, now),
    ).fetchone()["n"]
    return {
        "open": counts[OPEN],
        "resolved": counts[RESOLVED],
        "eliminated": counts[ELIMINATED],
        "claimed": claimed,
        "total": sum(counts.values()),
    }


def normalize_bound(value: Optional[str], label: str) -> Optional[str]:
    """规范化筛选时间边界为存储格式；非法输入抛 400。"""
    if value is None or not str(value).strip():
        return None
    try:
        dt = parse_dt(str(value).strip())
    except ValueError:
        raise FindingError(f"{label}格式应为 YYYY-MM-DD HH:MM:SS", status_code=400)
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build_queue(
    conn: Connection,
    status: str = OPEN,
    code: Optional[str] = None,
    custodian: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    claim: Optional[str] = None,
) -> dict[str, Any]:
    """跨样本异常处置队列：先重算指纹，再按状态 / 异常类型 / 经手人 / 发生时间 /
    认领状态筛选。

    ``claim`` 仅对未处理项有意义：``unclaimed`` 未认领、``claimed`` 已被认领
    （租约有效中）、``expired`` 租约到期可接管。
    """
    sync_all_findings(conn)
    now_dt = datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    summary = queue_summary(conn, now_str)

    sql = (
        "SELECT f.*, s.code AS sample_code, s.name AS sample_name "
        "FROM findings f JOIN samples s ON s.id = f.sample_id"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if status and status != "all":
        clauses.append("f.status = ?")
        params.append(status)
    if code:
        clauses.append("f.code = ?")
        params.append(code)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY f.last_seen_at DESC, f.id DESC"

    custodian_q = (custodian or "").strip()
    items: list[dict[str, Any]] = []
    for r in conn.execute(sql, params).fetchall():
        item = _finding_dict(r, now_dt)
        if custodian_q and not any(custodian_q in c for c in item["custodians"]):
            continue
        # 发生时间筛选：发现的时间边界与筛选区间相交才保留（开放结束视为无限远）
        if time_from and item["time_to"] is not None and item["time_to"] < time_from:
            continue
        if time_to and item["time_from"] is not None and item["time_from"] > time_to:
            continue
        if claim:
            if claim not in (
                CLAIM_STATE_UNCLAIMED,
                CLAIM_STATE_CLAIMED,
                CLAIM_STATE_EXPIRED,
            ):
                raise FindingError(
                    "认领状态筛选仅支持 unclaimed（未认领）/ claimed（认领中）"
                    "/ expired（已过期可接管）",
                    status_code=400,
                )
            if item["status"] != OPEN:
                continue
            if claim == CLAIM_STATE_UNCLAIMED and not item["claimed_by"]:
                pass
            elif claim == CLAIM_STATE_CLAIMED and item["claim_active"]:
                pass
            elif (
                claim == CLAIM_STATE_EXPIRED
                and item["last_claimed_by"]
                and not item["claim_active"]
            ):
                pass
            else:
                continue
        items.append(item)

    custodians = [
        r["custodian"]
        for r in conn.execute(
            "SELECT DISTINCT custodian FROM events ORDER BY custodian"
        ).fetchall()
    ]
    return {
        "items": items,
        "summary": summary,
        "filters": {
            "status": status,
            "code": code,
            "custodian": custodian_q,
            "time_from": time_from,
            "time_to": time_to,
            "claim": claim,
        },
        "custodians": custodians,
        "synced_at": now_str,
        "server_time": now_str,
        "claim_ttl_seconds": CLAIM_TTL_SECONDS,
    }


def get_finding_detail(conn: Connection, fingerprint: str) -> dict[str, Any]:
    """发现详情 + 完整状态迁移记录（先按当前链路重算，保证状态新鲜）。"""
    row = conn.execute(
        "SELECT sample_id FROM findings WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()
    if row is None:
        raise FindingError("该审计发现不存在（可能样本已删除），请刷新队列", status_code=404)
    sync_sample_findings(conn, row["sample_id"])

    row = conn.execute(
        "SELECT f.*, s.code AS sample_code, s.name AS sample_name "
        "FROM findings f JOIN samples s ON s.id = f.sample_id "
        "WHERE f.fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    now_dt = datetime.now()
    transitions = [
        {
            "id": t["id"],
            "from_status": t["from_status"],
            "from_status_text": STATUS_TEXT.get(t["from_status"]) if t["from_status"] else None,
            "to_status": t["to_status"],
            "to_status_text": STATUS_TEXT.get(t["to_status"], t["to_status"]),
            "event": t["event"],
            "event_text": EVENT_TEXT.get(t["event"], t["event"]),
            "handler": t["handler"],
            "note": t["note"],
            "created_at": t["created_at"],
        }
        for t in conn.execute(
            "SELECT * FROM finding_transitions WHERE finding_id = ? ORDER BY id",
            (row["id"],),
        ).fetchall()
    ]
    detail = _finding_dict(row, now_dt)
    detail["server_time"] = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    detail["transitions"] = transitions
    return detail


# ---------- 限时认领 / 接管 / 释放 / 处置（单事务 + 版本与租约双校验） ----------

def _begin_immediate(conn: Connection) -> None:
    """开启立即写锁事务（与批量导入确认同款，杜绝「重算 -> 写入」间的并发写入）。"""
    conn.execute("BEGIN IMMEDIATE")


def _finish_with_detail(
    conn: Connection, fingerprint: str, now_str: str, commit: bool
) -> dict[str, Any]:
    """事务收尾：组装返回详情 + 全量重算（仅状态刷新，不再改本行），随后提交。

    重算与读取仍处于同一事务 / 同一把写锁内，保证客户端拿到的版本与库内一致。
    """
    detail = get_finding_detail(conn, fingerprint)
    sync_all_findings(conn)
    detail["summary"] = queue_summary(conn, now_str)
    if commit:
        conn.commit()
    return detail


def claim_finding(
    conn: Connection,
    fingerprint: str,
    handler: str,
    expected_version: int,
) -> dict[str, Any]:
    """限时认领 / 到期接管（租约 15 分钟）。

    单一事务（``BEGIN IMMEDIATE``）内：先按当前链路重算发现指纹，再**同时**
    校验 ``expected_version`` 与租约状态：

    * 版本过期                                 -> 409；
    * 租约仍被其他人持有（未到期）            -> 409；
    * 当前认领人重复提交                       -> 幂等成功（不续期、不重复留痕）；
    * 未认领 / 租约到期                        -> 认领或接管成功，版本 +1。
    """
    _begin_immediate(conn)
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            raise FindingError(
                "该审计发现不存在（可能样本已删除），请刷新队列", status_code=404
            )

        # 先重算：异常若已被消除 / 复现，状态与版本随之变化
        sync_sample_findings(conn, row["sample_id"])
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        # 同时校验指纹版本与租约状态
        if row["version"] != expected_version:
            raise FindingError(
                "该发现已被其他人处置或链路已变化（指纹版本过期），请刷新队列后重试",
                status_code=409,
            )
        if row["status"] != OPEN:
            text = (
                "该发现已处理，无需认领"
                if row["status"] == RESOLVED
                else "该异常已随链路变更消除，无法认领"
            )
            raise FindingError(text, status_code=409)

        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        if _lease_active(row, now_str):
            if row["claimed_by"] == handler:
                # 当前认领人重复提交：幂等返回，不续期、不递增版本、不重复留痕
                detail = get_finding_detail(conn, fingerprint)
                sync_all_findings(conn)
                detail["summary"] = queue_summary(conn, now_str)
                conn.commit()
                return detail
            raise FindingError(
                f"该发现已被 {row['claimed_by']} 认领，租约未到期（到期 "
                f"{row['claim_expires_at']}），暂不能接管",
                status_code=409,
            )

        deadline = _claim_deadline(now_dt)
        previous_owner = row["claimed_by"]  # 租约到期后旧认领人仍留在列上
        cur = conn.execute(
            "UPDATE findings SET claimed_by = ?, claim_expires_at = ?, claimed_at = ?, "
            "version = version + 1, updated_at = ? "
            "WHERE id = ? AND version = ? AND status = ? "
            "AND (claimed_by IS NULL OR claim_expires_at <= ?)",
            (handler, deadline, now_str, now_str, row["id"], expected_version, OPEN, now_str),
        )
        if not cur.rowcount:
            raise FindingError("该发现的认领状态已变化，请刷新队列后重试", status_code=409)

        if previous_owner and previous_owner != handler:
            # 到期接管：记录旧认领人与租约到期时间，便于追溯
            _record_transition(
                conn, row["id"], OPEN, OPEN, handler,
                f"租约到期（{row['claim_expires_at']}）后由 {previous_owner} 接管，"
                f"新租约至 {deadline}",
                now_str, event=EVENT_TAKEOVER,
            )
        else:
            _record_transition(
                conn, row["id"], OPEN, OPEN, handler,
                f"限时认领 {CLAIM_TTL_SECONDS // 60} 分钟，租约至 {deadline}",
                now_str, event=EVENT_CLAIM,
            )

        return _finish_with_detail(conn, fingerprint, now_str, commit=True)
    except FindingError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise


def release_finding(
    conn: Connection,
    fingerprint: str,
    handler: str,
    expected_version: int,
) -> dict[str, Any]:
    """主动释放认领租约：只有当前认领人可释放，未认领不能释放。"""
    _begin_immediate(conn)
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            raise FindingError(
                "该审计发现不存在（可能样本已删除），请刷新队列", status_code=404
            )

        sync_sample_findings(conn, row["sample_id"])
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        if row["version"] != expected_version:
            raise FindingError(
                "该发现已被其他人处置或链路已变化（指纹版本过期），请刷新队列后重试",
                status_code=409,
            )
        if row["status"] != OPEN:
            raise FindingError("仅未处理的发现可以释放认领", status_code=409)

        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        if not _lease_active(row, now_str):
            raise FindingError("该发现当前没有有效认领，无需释放", status_code=409)
        if row["claimed_by"] != handler:
            raise FindingError(
                f"只有当前认领人（{row['claimed_by']}）可以释放该发现",
                status_code=409,
            )

        cur = conn.execute(
            "UPDATE findings SET claimed_by = NULL, claim_expires_at = NULL, "
            "claimed_at = NULL, version = version + 1, updated_at = ? "
            "WHERE id = ? AND version = ? AND status = ? AND claimed_by = ? "
            "AND claim_expires_at > ?",
            (now_str, row["id"], expected_version, OPEN, handler, now_str),
        )
        if not cur.rowcount:
            raise FindingError("该发现的认领状态已变化，请刷新队列后重试", status_code=409)
        _record_transition(
            conn, row["id"], OPEN, OPEN, handler, "处置人主动释放认领", now_str,
            event=EVENT_RELEASE,
        )

        return _finish_with_detail(conn, fingerprint, now_str, commit=True)
    except FindingError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise


def dispose_finding(
    conn: Connection,
    fingerprint: str,
    action: str,
    handler: str,
    note: str,
    expected_version: int,
) -> dict[str, Any]:
    """标记已处理 / 重新打开。

    单一事务内先按当前链路重算指纹（若异常已消失或复现，版本号会随之变化），
    再同时校验指纹版本与认领租约：

    * 标记已处理：仅**当前认领人**可操作；未认领、租约被他人持有均返回 409；
    * 重新打开：把已处理发现恢复为未处理，新状态不附带认领租约（需重新认领）。

    处置成功后租约随状态关闭清除。版本过期或状态不允许同样返回 409。
    """
    _begin_immediate(conn)
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            raise FindingError(
                "该审计发现不存在（可能样本已删除），请刷新队列", status_code=404
            )

        sync_sample_findings(conn, row["sample_id"])
        row = conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        # 同时校验指纹版本与租约状态
        if row["version"] != expected_version:
            raise FindingError(
                "该发现已被其他人处置或链路已变化（指纹版本过期），请刷新队列后重试",
                status_code=409,
            )

        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        if action == ACTION_RESOLVE:
            if row["status"] != OPEN:
                text = (
                    "该发现已处理，无需重复操作"
                    if row["status"] == RESOLVED
                    else "该异常已随链路变更消除，无需处置"
                )
                raise FindingError(text, status_code=409)
            if not _lease_active(row, now_str):
                raise FindingError(
                    "该发现尚未被认领，请先认领（限时 15 分钟）后再标记已处理",
                    status_code=409,
                )
            if row["claimed_by"] != handler:
                raise FindingError(
                    f"该发现已被 {row['claimed_by']} 认领，只有当前认领人可以标记已处理",
                    status_code=409,
                )
            cur = conn.execute(
                "UPDATE findings SET status = ?, handler = ?, note = ?, resolved_at = ?, "
                "claimed_by = NULL, claim_expires_at = NULL, claimed_at = NULL, "
                "version = version + 1, updated_at = ? "
                "WHERE id = ? AND version = ? AND status = ? AND claimed_by = ? "
                "AND claim_expires_at > ?",
                (
                    RESOLVED, handler, note, now_str, now_str,
                    row["id"], expected_version, OPEN, handler, now_str,
                ),
            )
            if not cur.rowcount:
                raise FindingError("该发现状态已变化，请刷新队列后重试", status_code=409)
            _record_transition(
                conn, row["id"], OPEN, RESOLVED, handler, note or "标记已处理", now_str
            )
        elif action == ACTION_REOPEN:
            if row["status"] != RESOLVED:
                text = (
                    "该发现当前为未处理状态，无需重新打开"
                    if row["status"] == OPEN
                    else "该异常已随链路变更消除，不能重新打开"
                )
                raise FindingError(text, status_code=409)
            cur = conn.execute(
                "UPDATE findings SET status = ?, handler = ?, note = ?, resolved_at = NULL, "
                "claimed_by = NULL, claim_expires_at = NULL, claimed_at = NULL, "
                "version = version + 1, updated_at = ? "
                "WHERE id = ? AND version = ? AND status = ?",
                (OPEN, handler, note, now_str, row["id"], expected_version, RESOLVED),
            )
            if not cur.rowcount:
                raise FindingError("该发现状态已变化，请刷新队列后重试", status_code=409)
            _record_transition(
                conn, row["id"], RESOLVED, OPEN, handler, note or "重新打开", now_str
            )
        else:
            raise FindingError("不支持的处置动作", status_code=400)

        return _finish_with_detail(conn, fingerprint, now_str, commit=True)
    except FindingError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
