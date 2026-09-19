"""批量导入交接事件（UTF-8 CSV）。

采用「先预览、后确认」两段式流程，**预览阶段绝不写库**：

1. :func:`preview_bulk_import` 解析上传的 CSV（表头固定为
   「经手人,开始时间,结束时间,备注」），逐行复用 :class:`~app.schemas.EventCreate`
   的校验规则（与单条录入完全一致），并在内存中把合法行并入当前事件链，给出
   导入后的审计结论、审计发现与交接确认失效预测；返回体中的 ``token`` 是绑定
   **当前事件链指纹**的 HMAC 签名令牌（无状态、有效期 :data:`TOKEN_TTL_SECONDS`
   秒），令牌内携带规范化后的全部行数据。
2. :func:`confirm_bulk_import` 在单一事务（``BEGIN IMMEDIATE``）内重新校验令牌
   签名、有效期、样本归属与事件链指纹：预览之后链路发生任何增删改都会因指纹
   不一致被拒绝并要求重新预览。全部行再次校验通过后，按文件顺序一次性分配
   seq、写入事件并刷新交接确认失效状态；任一步失败整体回滚，不允许部分落库。
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import secrets
import time
from typing import Any, Optional
from sqlite3 import Connection

from pydantic import ValidationError

from .audit import build_audit, parse_dt
from .handovers import (
    ACTIVE,
    INVALIDATED,
    REASON_ADJACENCY_CHANGED,
    REASON_TEXT,
    build_handover_view,
    refresh_handover_validity,
)
from .schemas import EventCreate

# CSV 表头（顺序固定，不多不少）
CSV_HEADERS = ["经手人", "开始时间", "结束时间", "备注"]
FIELD_LABELS = {
    "custodian": "经手人",
    "start_time": "开始时间",
    "end_time": "结束时间",
    "note": "备注",
}

MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_IMPORT_ROWS = 1000
TOKEN_TTL_SECONDS = 10 * 60

# 进程级签名密钥：服务重启后旧令牌自然失效（前端提示重新预览）。
_SECRET = secrets.token_bytes(32)


class BulkImportError(Exception):
    """批量导入业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 事件链指纹与摘要令牌 ----------

def chain_fingerprint(conn: Connection, sample_id: int) -> str:
    """当前样本全部事件的 SHA-256 指纹；事件任何增删改都会改变。"""
    rows = conn.execute(
        "SELECT id, custodian, start_time, end_time, note, seq "
        "FROM events WHERE sample_id = ? ORDER BY id",
        (sample_id,),
    ).fetchall()
    raw = json.dumps([tuple(r) for r in rows], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def make_preview_token(
    sample_id: int,
    rows: list[dict[str, Any]],
    chain: str,
    ttl: int = TOKEN_TTL_SECONDS,
) -> tuple[str, int]:
    """生成 (token, 过期 unix 时间)。令牌载荷含规范化行数据，签名防篡改。"""
    expires_at = int(time.time()) + ttl
    payload = {
        "sample_id": sample_id,
        "chain": chain,
        "rows": rows,
        "exp": expires_at,
        "nonce": secrets.token_hex(8),
    }
    body = _b64encode(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    )
    signature = hmac.new(_SECRET, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}", expires_at


def verify_preview_token(token: str, sample_id: int) -> dict[str, Any]:
    """校验并解码预览令牌；任何不符都抛出 409，要求重新预览。"""
    try:
        body, sig_text = token.split(".", 1)
        expected = hmac.new(
            _SECRET, body.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64decode(sig_text), expected):
            raise ValueError
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except Exception:
        raise BulkImportError("预览令牌无效，请重新上传文件并预览", status_code=409)

    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise BulkImportError("预览令牌无效，请重新上传文件并预览", status_code=409)
    if payload.get("sample_id") != sample_id:
        raise BulkImportError("预览令牌与当前样本不匹配，请重新预览", status_code=409)
    if int(payload.get("exp", 0)) < int(time.time()):
        raise BulkImportError(
            f"预览已超过 {TOKEN_TTL_SECONDS // 60} 分钟有效期，请重新预览",
            status_code=409,
        )
    return payload


# ---------- CSV 解析与逐行校验 ----------

def parse_csv(content: bytes) -> list[tuple[int, list[str]]]:
    """解码 UTF-8 CSV 并返回 ``[(物理行号, 单元格列表), ...]``（不含表头）。

    文件级错误（编码、大小、表头、空文件、行数上限）抛 :class:`BulkImportError`；
    行级错误留给逐行校验，不在此处理。
    """
    if not content:
        raise BulkImportError("文件为空，请先按模板填写交接事件后再上传")
    if len(content) > MAX_IMPORT_BYTES:
        raise BulkImportError(
            f"文件过大（>{MAX_IMPORT_BYTES // (1024 * 1024)}MB），单次最多导入 "
            f"{MAX_IMPORT_ROWS} 行，请拆分后上传"
        )
    try:
        # utf-8-sig 可同时兼容带 / 不带 BOM 的 UTF-8 文件（Excel 另存 CSV 常带 BOM）
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise BulkImportError(
            "文件不是合法的 UTF-8 编码，请用「UTF-8（逗号分隔）(*.csv)」格式另存后重试"
        )

    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise BulkImportError("文件为空，请先按模板填写交接事件后再上传")

    header = [cell.strip() for cell in header]
    if header != CSV_HEADERS:
        raise BulkImportError(
            "CSV 表头必须是且只能是："
            + ",".join(CSV_HEADERS)
            + f"；当前表头为：{','.join(header) or '（空）'}"
        )

    rows: list[tuple[int, list[str]]] = []
    for cells in reader:
        # 完全空白的物理行直接跳过（文件末尾空行属常见情况）
        if not cells or all(not str(c).strip() for c in cells):
            continue
        rows.append((reader.line_num, [str(c).strip() for c in cells]))

    if not rows:
        raise BulkImportError("文件没有可导入的数据行，请按模板填写后再上传")
    if len(rows) > MAX_IMPORT_ROWS:
        raise BulkImportError(
            f"单次最多导入 {MAX_IMPORT_ROWS} 行（当前 {len(rows)} 行），请拆分后上传"
        )
    return rows


def validate_row(cells: list[str]) -> tuple[Optional[dict[str, Any]], list[str]]:
    """逐行复用 EventCreate 校验，返回 (规范化字段或 None, 错误信息列表)。"""
    errors: list[str] = []
    if len(cells) != len(CSV_HEADERS):
        errors.append(
            f"列数应为 {len(CSV_HEADERS)} 列（{','.join(CSV_HEADERS)}），"
            f"实际为 {len(cells)} 列"
        )

    padded = (cells + [""] * len(CSV_HEADERS))[: len(CSV_HEADERS)]
    custodian, start_time, end_raw, note = padded
    end_time = end_raw or None
    try:
        parsed = EventCreate(
            custodian=custodian,
            start_time=start_time,
            end_time=end_time,
            note=note,
        )
    except ValidationError as exc:
        for err in exc.errors():
            loc = err.get("loc") or ()
            field = str(loc[-1]) if loc else ""
            label = FIELD_LABELS.get(field, field)
            message = err.get("msg", "").removeprefix("Value error, ")
            errors.append(f"【{label}】{message}" if label else message)
        return None, errors

    if errors:
        # 列数有误时即使字段恰好能对上也不允许导入
        return None, errors
    return parsed.model_dump(), errors


# ---------- 内存中的链路投影 ----------

def _fetch_events(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def _ordered_chain(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """与审计排序一致：起始时间升序，排除时间不可解析 / 起止倒置的事件。"""
    parsed: list[tuple[Any, dict[str, Any]]] = []
    for event in events:
        try:
            start = parse_dt(event["start_time"])
        except ValueError:
            continue
        if start is None:
            continue
        try:
            end = parse_dt(event.get("end_time"))
        except ValueError:
            end = None
        if end is not None and end < start:
            continue
        parsed.append((start, event))
    parsed.sort(key=lambda item: (item[0], item[1]["id"]))
    return [event for _, event in parsed]


def _projected_handovers(
    conn: Connection, sample_id: int, projected: list[dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """返回 (导入后交接统计, 失效变化)。纯内存计算，不写库。"""
    ordered = _ordered_chain(projected)
    adjacent_pairs = {(a["id"], b["id"]) for a, b in zip(ordered, ordered[1:])}

    active_rows = conn.execute(
        "SELECT * FROM handovers WHERE sample_id = ? AND status = ?",
        (sample_id, ACTIVE),
    ).fetchall()

    live_active: dict[tuple[int, int], Any] = {}
    newly_invalidated: list[int] = []
    for row in active_rows:
        pair = (row["from_event_id"], row["to_event_id"])
        if pair not in adjacent_pairs:
            newly_invalidated.append(row["id"])
        else:
            live_active[pair] = row

    confirmed = pending = mismatch = 0
    for a, b in zip(ordered, ordered[1:]):
        status = "pending"
        row = live_active.get((a["id"], b["id"]))
        if row is not None and row["from_name"] and row["to_name"]:
            try:
                consistent = (
                    bool(a.get("end_time"))
                    and parse_dt(a["end_time"]) == parse_dt(b["start_time"])
                )
            except ValueError:
                consistent = False
            status = "confirmed" if consistent else "time_mismatch"
        if status == "confirmed":
            confirmed += 1
        elif status == "time_mismatch":
            mismatch += 1
        else:
            pending += 1

    history_count = conn.execute(
        "SELECT COUNT(*) FROM handovers WHERE sample_id = ? AND status = ?",
        (sample_id, INVALIDATED),
    ).fetchone()[0]

    summary = {
        "total": len(ordered) - 1 if ordered else 0,
        "confirmed": confirmed,
        "pending": pending,
        "time_mismatch": mismatch,
        "invalidated": history_count + len(newly_invalidated),
    }
    change = {
        "newly_invalidated": len(newly_invalidated),
        "reasons": (
            {REASON_ADJACENCY_CHANGED: REASON_TEXT[REASON_ADJACENCY_CHANGED]}
            if newly_invalidated
            else {}
        ),
        "invalidated_handover_ids": newly_invalidated,
    }
    return summary, change


# ---------- 预览 ----------

def preview_bulk_import(
    conn: Connection, sample_id: int, content: bytes
) -> dict[str, Any]:
    """解析 + 逐行校验 + 投影导入结果。只读，不执行任何写操作。"""
    raw_rows = parse_csv(content)
    existing = _fetch_events(conn, sample_id)
    current_audit = build_audit(existing)
    current_handovers = build_handover_view(conn, sample_id)

    max_seq = max((e["seq"] for e in existing), default=0)
    projected = [dict(e) for e in existing]
    line_by_new_id: dict[int, int] = {}

    row_views: list[dict[str, Any]] = []
    valid_count = 0
    for line_num, cells in raw_rows:
        normalized, errors = validate_row(cells)
        view: dict[str, Any] = {
            "line": line_num,
            "custodian": cells[0] if cells else "",
            "start_time": cells[1] if len(cells) > 1 else "",
            "end_time": cells[2] if len(cells) > 2 else "",
            "note": cells[3] if len(cells) > 3 else "",
            "seq_preview": None,
            "errors": errors,
            "in_conflict": False,
        }
        if normalized is not None:
            valid_count += 1
            seq = max_seq + valid_count
            new_id = -valid_count
            view["seq_preview"] = seq
            view["normalized"] = normalized
            line_by_new_id[new_id] = line_num
            projected.append(
                {
                    "id": new_id,
                    "sample_id": sample_id,
                    "custodian": normalized["custodian"],
                    "start_time": normalized["start_time"],
                    "end_time": normalized["end_time"],
                    "note": normalized["note"],
                    "seq": seq,
                }
            )
        else:
            view["normalized"] = None
        row_views.append(view)

    projected_audit = build_audit(projected)
    new_ids = set(line_by_new_id)
    conflict_codes = {"gap", "overlap", "reversed_interval"}
    new_findings: list[dict[str, Any]] = []
    conflict_lines: set[int] = set()
    for finding in projected_audit["findings"]:
        ids = finding.get("event_ids") or []
        if new_ids.intersection(ids):
            new_findings.append(finding)
        if finding.get("code") in conflict_codes:
            for eid in ids:
                if eid in new_ids:
                    conflict_lines.add(line_by_new_id[eid])
    for view in row_views:
        if view["line"] in conflict_lines:
            view["in_conflict"] = True

    projected_ho_summary, ho_change = _projected_handovers(
        conn, sample_id, projected
    )

    all_valid = valid_count == len(raw_rows)
    if not all_valid:
        # 只有全部行有效才可能导入；存在错误行时不展示录入序，
        # 避免用户按一个不会发生的序号理解数据
        for view in row_views:
            view["seq_preview"] = None
    token = None
    expires_at = None
    if all_valid:
        token, expires_at = make_preview_token(
            sample_id,
            [view["normalized"] for view in row_views],
            chain_fingerprint(conn, sample_id),
        )

    return {
        "total_rows": len(raw_rows),
        "valid_rows": valid_count,
        "invalid_rows": len(raw_rows) - valid_count,
        "all_valid": all_valid,
        "token": token,
        "expires_at": expires_at,
        "ttl_seconds": TOKEN_TTL_SECONDS,
        "rows": row_views,
        "current": {
            "event_count": len(existing),
            "audit": _audit_brief(current_audit),
            "handover_summary": current_handovers["summary"],
        },
        "projected": {
            "event_count": len(projected),
            "audit": _audit_brief(projected_audit),
            "new_findings": new_findings,
            "handover_summary": projected_ho_summary,
            "handover_change": ho_change,
        },
    }


def _audit_brief(audit: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": audit["status"],
        "conclusion": audit["conclusion"],
        "summary": audit["summary"],
    }


# ---------- 确认导入（单一事务） ----------

def confirm_bulk_import(
    conn: Connection, sample_id: int, token: str
) -> dict[str, Any]:
    """在已开启的写事务内再次校验并一次性写入。失败抛 BulkImportError，由路由回滚。"""
    payload = verify_preview_token(token, sample_id)

    sample = conn.execute(
        "SELECT 1 FROM samples WHERE id = ?", (sample_id,)
    ).fetchone()
    if sample is None:
        raise BulkImportError("样本不存在", status_code=404)

    # 持写锁重算指纹：预览之后链路有任何增删改一律拒绝
    if chain_fingerprint(conn, sample_id) != payload["chain"]:
        raise BulkImportError(
            "预览之后该样本的交接链路已发生增删改，为避免覆盖最新数据，"
            "请重新上传文件预览后再导入",
            status_code=409,
        )

    token_rows = payload["rows"]
    normalized_rows: list[dict[str, Any]] = []
    for row in token_rows:
        try:
            parsed = EventCreate(**row)
        except (ValidationError, TypeError):
            raise BulkImportError(
                "令牌中的导入数据未通过再次校验，请重新上传文件并预览",
                status_code=409,
            )
        normalized_rows.append(parsed.model_dump())

    if not normalized_rows:
        raise BulkImportError("令牌中没有可导入的数据行，请重新预览", status_code=409)

    max_seq = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) FROM events WHERE sample_id = ?", (sample_id,)
    ).fetchone()[0]

    before_active_ids = {
        r["id"]
        for r in conn.execute(
            "SELECT id FROM handovers WHERE sample_id = ? AND status = ?",
            (sample_id, ACTIVE),
        ).fetchall()
    }

    imported_ids: list[int] = []
    for index, data in enumerate(normalized_rows, start=1):
        cur = conn.execute(
            "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                sample_id,
                data["custodian"],
                data["start_time"],
                data["end_time"],
                data["note"],
                max_seq + index,
            ),
        )
        imported_ids.append(cur.lastrowid)

    # 新增事件可能插入到相邻事件之间，原确认随之失效（记录保留）
    refresh_handover_validity(conn, sample_id)

    reason_counts: dict[str, int] = {}
    if before_active_ids:
        placeholders = ",".join("?" * len(before_active_ids))
        rows = conn.execute(
            f"SELECT invalidated_reason, COUNT(*) AS n FROM handovers "
            f"WHERE sample_id = ? AND id IN ({placeholders}) AND status = ? "
            f"GROUP BY invalidated_reason",
            (sample_id, *before_active_ids, INVALIDATED),
        ).fetchall()
        reason_counts = {r["invalidated_reason"]: r["n"] for r in rows}

    events_after = _fetch_events(conn, sample_id)
    audit_after = build_audit(events_after)
    handovers_after = build_handover_view(conn, sample_id)

    return {
        "imported_count": len(imported_ids),
        "event_ids": imported_ids,
        "first_seq": max_seq + 1,
        "last_seq": max_seq + len(imported_ids),
        "invalidated_confirmations": sum(reason_counts.values()),
        "invalidation_reasons": reason_counts,
        "audit": audit_after,
        "handovers": handovers_after,
    }
