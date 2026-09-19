"""FastAPI 入口：样本 / 交接事件 CRUD、审计、结论签署与报告导出。"""
from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlite3 import Connection

from .audit import build_audit
from .bulk_import import (
    CSV_HEADERS,
    BulkImportError,
    confirm_bulk_import,
    preview_bulk_import,
)
from .db import get_conn, init_db
from .findings import (
    FindingError,
    build_queue,
    claim_finding,
    dispose_finding,
    get_finding_detail,
    normalize_bound,
    queue_summary,
    release_finding,
    sync_all_findings,
    sync_sample_findings,
)
from .handovers import (
    HandoverError,
    build_handover_view,
    confirm_handover,
    get_handover_record,
    refresh_handover_validity,
)
from .report import build_html, build_json, build_markdown
from .schemas import (
    BulkImportConfirm,
    EventCreate,
    FindingClaim,
    FindingDispose,
    FindingRelease,
    HandoverConfirm,
    SampleCreate,
    SignoffCreate,
    SignoffRevoke,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 启动时建表并写入演示数据（已初始化则跳过）
    init_db()
    yield


app = FastAPI(title="样本交接链路审计", version="1.0.0", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------- 样本 ----------

def _sample_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "code": row["code"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
    }


def _fetch_sample(conn: Connection, sample_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="样本不存在")
    return _sample_dict(row)


def _fetch_events(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    return [
        {
            "id": r["id"],
            "custodian": r["custodian"],
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "note": r["note"],
            "seq": r["seq"],
        }
        for r in rows
    ]


@app.get("/api/samples")
def list_samples(conn: Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM samples ORDER BY created_at DESC, id DESC").fetchall()
    samples = []
    for r in rows:
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE sample_id = ?", (r["id"],)
        ).fetchone()[0]
        d = _sample_dict(r)
        d["event_count"] = count
        samples.append(d)
    return samples


@app.post("/api/samples", status_code=201)
def create_sample(payload: SampleCreate, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    exists = conn.execute("SELECT 1 FROM samples WHERE code = ?", (payload.code,)).fetchone()
    if exists:
        raise HTTPException(status_code=409, detail=f"样本编号 {payload.code} 已存在")
    cur = conn.execute(
        "INSERT INTO samples (code, name, description, created_at) VALUES (?, ?, ?, ?)",
        (payload.code, payload.name, payload.description,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    return _fetch_sample(conn, cur.lastrowid)


@app.get("/api/samples/{sample_id}")
def get_sample(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    sample = _fetch_sample(conn, sample_id)
    events = _fetch_events(conn, sample_id)
    audit = build_audit(events)
    return {
        "sample": sample,
        "events": events,
        "audit": audit,
        "signoffs": _list_signoffs(conn, sample_id),
        "handovers": build_handover_view(conn, sample_id),
    }


@app.delete("/api/samples/{sample_id}", status_code=204)
def delete_sample(sample_id: int, conn: Connection = Depends(get_conn)) -> Response:
    _fetch_sample(conn, sample_id)
    conn.execute("DELETE FROM samples WHERE id = ?", (sample_id,))
    conn.commit()
    return Response(status_code=204)


# ---------- 交接事件 ----------

@app.post("/api/samples/{sample_id}/events", status_code=201)
def add_event(
    sample_id: int, payload: EventCreate, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    _fetch_sample(conn, sample_id)
    seq = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE sample_id = ?", (sample_id,)
    ).fetchone()[0]
    cur = conn.execute(
        "INSERT INTO events (sample_id, custodian, start_time, end_time, note, seq) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (sample_id, payload.custodian, payload.start_time, payload.end_time, payload.note, seq),
    )
    # 新事件可能插入到某对相邻事件之间，原确认随之失效（记录保留）
    refresh_handover_validity(conn, sample_id)
    # 重算审计发现指纹：新异常以未处理入库，消失的转已消除历史
    sync_sample_findings(conn, sample_id)
    conn.commit()
    row = conn.execute("SELECT * FROM events WHERE id = ?", (cur.lastrowid,)).fetchone()
    return {"id": row["id"], "seq": row["seq"]}


@app.put("/api/events/{event_id}")
def update_event(event_id: int, payload: EventCreate, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接事件不存在")
    conn.execute(
        "UPDATE events SET custodian = ?, start_time = ?, end_time = ?, note = ? WHERE id = ?",
        (payload.custodian, payload.start_time, payload.end_time, payload.note, event_id),
    )
    # 绑定该事件关键字段的原确认保留为失效记录，需两侧重新确认
    refresh_handover_validity(conn, row["sample_id"])
    # 重算审计发现指纹：仍存在的沿用处置状态，新出现的保持未处理
    sync_sample_findings(conn, row["sample_id"])
    conn.commit()
    return {"id": event_id, "updated": True}


@app.delete("/api/events/{event_id}", status_code=204)
def delete_event(event_id: int, conn: Connection = Depends(get_conn)) -> Response:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="交接事件不存在")
    sample_id = row["sample_id"]
    # 删除事件后，绑定它的原确认保留为失效记录（行与快照不删）
    conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    refresh_handover_validity(conn, sample_id)
    # 重算审计发现指纹：消失的异常转为已消除历史
    sync_sample_findings(conn, sample_id)
    conn.commit()
    return Response(status_code=204)


# ---------- 批量导入交接事件（CSV 预览 + 确认） ----------

@app.get("/api/samples/{sample_id}/events/import-template")
def download_import_template(sample_id: int, conn: Connection = Depends(get_conn)) -> Response:
    """下载 UTF-8 CSV 导入模板（含表头与示例行；示例行不会被自动导入）。"""
    _fetch_sample(conn, sample_id)
    lines = [
        ",".join(CSV_HEADERS),
        "张三（采集组）,2026-09-18 09:00:00,2026-09-18 10:00:00,现场采集并密封",
        "李四（运输组）,2026-09-18 10:00:00,2026-09-18 11:30:00,冷链运输 2-8℃",
        "王五（检测组）,2026-09-18 11:30:00,,接手后仍在保管，结束时间留空",
    ]
    # 写入 UTF-8 BOM，保证 Excel 直接打开中文表头不乱码
    body = "\ufeff" + "\r\n".join(lines) + "\r\n"
    return Response(
        content=body.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=handover_events_template.csv; "
            "filename*=UTF-8''%E6%89%8B%E4%BA%A4%E4%BA%8B%E4%BB%B6%E5%AF%BC%E5%85%A5%E6%A8%A1%E6%9D%BF.csv"
        },
    )


@app.post("/api/samples/{sample_id}/events/import-preview")
async def preview_events_import(
    sample_id: int, request: Request, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """上传 CSV -> 逐行校验与导入后审计投影；只读不写库，返回绑定事件链的摘要令牌。"""
    _fetch_sample(conn, sample_id)
    content = await request.body()
    try:
        return preview_bulk_import(conn, sample_id, content)
    except BulkImportError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@app.post("/api/samples/{sample_id}/events/import-confirm", status_code=201)
def confirm_events_import(
    sample_id: int,
    payload: BulkImportConfirm,
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    """凭预览令牌在单一事务内再次校验并按文件顺序一次性写入。

    任何校验失败都回滚整个事务，绝不部分落库。
    """
    try:
        # BEGIN IMMEDIATE 立即获取写锁，杜绝「重算指纹 -> 写入」之间的并发写入
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = confirm_bulk_import(conn, sample_id, payload.token)
            # 导入后同事务重算审计发现指纹：新异常未处理、消失的转已消除
            sync_sample_findings(conn, sample_id)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    except BulkImportError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    result["sample"] = _fetch_sample(conn, sample_id)
    result["events"] = _fetch_events(conn, sample_id)
    result["signoffs"] = _list_signoffs(conn, sample_id)
    return result


# ---------- 审计 ----------

@app.get("/api/samples/{sample_id}/audit")
def get_audit(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    _fetch_sample(conn, sample_id)
    return build_audit(_fetch_events(conn, sample_id))


# ---------- 双向交接确认 ----------

@app.get("/api/samples/{sample_id}/handovers")
def list_handovers(sample_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """交接项（审计排序相邻事件）当前状态 + 失效历史记录。"""
    _fetch_sample(conn, sample_id)
    return build_handover_view(conn, sample_id)


@app.post("/api/samples/{sample_id}/handovers/confirm", status_code=200)
def confirm_pair(
    sample_id: int,
    from_event_id: int,
    to_event_id: int,
    payload: HandoverConfirm,
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    """交出方（side=from）或接收方（side=to）填写姓名与确认时间。"""
    _fetch_sample(conn, sample_id)
    try:
        result = confirm_handover(
            conn,
            sample_id,
            from_event_id,
            to_event_id,
            payload.side,
            payload.confirmer_name,
            payload.confirmed_at,
        )
    except HandoverError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    conn.commit()
    return result


@app.get("/api/handovers/{handover_id}")
def get_handover(handover_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """确认记录详情：双方确认信息、绑定的事件字段摘要、失效原因。"""
    try:
        return get_handover_record(conn, handover_id)
    except HandoverError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


# ---------- 异常处置队列（跨样本） ----------

@app.get("/api/findings/summary")
def findings_summary(conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """未处理 / 已处理 / 已消除数量（先按当前链路重算指纹）。"""
    sync_all_findings(conn)
    return queue_summary(conn)


@app.get("/api/findings/queue")
def findings_queue(
    status: str = Query("open", pattern="^(open|resolved|eliminated|all)$"),
    code: Optional[str] = Query(None),
    custodian: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    claim: Optional[str] = Query(None, pattern="^(unclaimed|claimed|expired)$"),
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    """跨样本异常处置队列：按状态 / 异常类型 / 经手人 / 发生时间 / 认领状态筛选。"""
    try:
        bound_from = normalize_bound(time_from, "发生时间从")
        bound_to = normalize_bound(time_to, "发生时间至")
        return build_queue(
            conn,
            status=status,
            code=(code or "").strip() or None,
            custodian=custodian,
            time_from=bound_from,
            time_to=bound_to,
            claim=claim,
        )
    except FindingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@app.get("/api/findings/{fingerprint}")
def finding_detail(fingerprint: str, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """发现详情：当前状态 + 完整状态迁移记录（含认领 / 释放 / 过期接管）。"""
    try:
        return get_finding_detail(conn, fingerprint)
    except FindingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@app.post("/api/findings/{fingerprint}/claim")
def finding_claim(
    fingerprint: str, payload: FindingClaim, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """限时认领未处理发现（15 分钟租约）；租约到期后同一接口即接管。

    服务端在单一事务内先按当前链路重算发现，再同时校验 expected_version
    与租约状态：租约未到期且属于他人返回 409；到期 / 未认领 / 已释放则
    认领或接管成功并递增版本。
    """
    try:
        return claim_finding(conn, fingerprint, payload.handler, payload.expected_version)
    except FindingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@app.post("/api/findings/{fingerprint}/release")
def finding_release(
    fingerprint: str, payload: FindingRelease, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """主动释放认领：只有当前未到期租约的认领人可以释放（版本递增）。"""
    try:
        return release_finding(
            conn,
            fingerprint,
            payload.handler,
            payload.expected_version,
            payload.note,
        )
    except FindingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@app.post("/api/findings/{fingerprint}/dispose")
def finding_dispose(
    fingerprint: str, payload: FindingDispose, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """处置写入：标记已处理 / 重新打开。

    服务端先在单一事务内按当前链路重算指纹，再同时校验客户端看到的指纹版本
    （expected_version）与认领租约：只有当前认领人可标记已处理；版本过期、
    租约冲突均返回 409，客户端应刷新队列后重试。
    """
    try:
        return dispose_finding(
            conn,
            fingerprint,
            payload.action,
            payload.handler,
            payload.note,
            payload.expected_version,
        )
    except FindingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


# ---------- 结论签署（不可变快照） ----------

def _signoff_summary(row: Any) -> dict[str, Any]:
    """签署记录的列表/摘要视图：状态 + 从快照中提取的审计摘要。"""
    snap = json.loads(row["snapshot"])
    audit = snap.get("audit", {})
    return {
        "id": row["id"],
        "sample_id": row["sample_id"],
        "signer": row["signer"],
        "signed_at": row["signed_at"],
        "remark": row["remark"],
        "status": row["status"],
        "revoke_reason": row["revoke_reason"],
        "revoked_at": row["revoked_at"],
        "created_at": row["created_at"],
        "digest": row["digest"][:12],
        "audit_status": audit.get("status"),
        "conclusion": audit.get("conclusion"),
        "summary": audit.get("summary"),
        "event_count": len(snap.get("events", [])),
    }


def _list_signoffs(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM signoffs WHERE sample_id = ? ORDER BY id DESC", (sample_id,)
    ).fetchall()
    return [_signoff_summary(r) for r in rows]


def _fetch_signoff(conn: Connection, signoff_id: int) -> Any:
    row = conn.execute("SELECT * FROM signoffs WHERE id = ?", (signoff_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="签署记录不存在")
    return row


@app.post("/api/samples/{sample_id}/signoffs", status_code=201)
def create_signoff(
    sample_id: int, payload: SignoffCreate, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """在当前审计结果上签署：保存样本 + 事件 + 审计发现的不可变快照。"""
    sample = _fetch_sample(conn, sample_id)
    events = _fetch_events(conn, sample_id)
    audit = build_audit(events)
    snapshot = {"sample": sample, "events": events, "audit": audit}
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "INSERT INTO signoffs (sample_id, signer, signed_at, remark, status, "
        "snapshot, digest, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
        (sample_id, payload.signer, payload.signed_at, payload.remark, raw, digest, now),
    )
    conn.commit()
    return _signoff_summary(_fetch_signoff(conn, cur.lastrowid))


@app.get("/api/samples/{sample_id}/signoffs")
def list_signoffs(sample_id: int, conn: Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    _fetch_sample(conn, sample_id)
    return _list_signoffs(conn, sample_id)


@app.get("/api/signoffs/{signoff_id}")
def get_signoff(signoff_id: int, conn: Connection = Depends(get_conn)) -> dict[str, Any]:
    """快照详情：返回完整快照内容并现场校验完整性。"""
    row = _fetch_signoff(conn, signoff_id)
    detail = _signoff_summary(row)
    detail["digest"] = row["digest"]
    detail["snapshot"] = json.loads(row["snapshot"])
    detail["integrity_ok"] = (
        hashlib.sha256(row["snapshot"].encode("utf-8")).hexdigest() == row["digest"]
    )
    return detail


@app.post("/api/signoffs/{signoff_id}/revoke")
def revoke_signoff(
    signoff_id: int, payload: SignoffRevoke, conn: Connection = Depends(get_conn)
) -> dict[str, Any]:
    """撤销签署：记录原因与时间，原快照保留不变。"""
    row = _fetch_signoff(conn, signoff_id)
    if row["status"] == "revoked":
        raise HTTPException(status_code=409, detail="该签署已撤销，请勿重复操作")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE signoffs SET status = 'revoked', revoke_reason = ?, revoked_at = ? WHERE id = ?",
        (payload.reason, now, signoff_id),
    )
    conn.commit()
    return _signoff_summary(_fetch_signoff(conn, signoff_id))


# ---------- 报告导出 ----------

def _safe_filename(code: str, ext: str) -> str:
    stem = re.sub(r"[^\w一-鿿-]+", "_", code).strip("_") or "sample"
    return f"audit_report_{stem}.{ext}"


@app.get("/api/samples/{sample_id}/report")
def export_report(
    sample_id: int,
    format: str = Query("markdown", pattern="^(markdown|html|json)$"),
    conn: Connection = Depends(get_conn),
):
    sample = _fetch_sample(conn, sample_id)
    audit = build_audit(_fetch_events(conn, sample_id))
    signoffs = _list_signoffs(conn, sample_id)
    handovers = build_handover_view(conn, sample_id)

    if format == "markdown":
        body = build_markdown(sample, audit, signoffs, handovers)
        headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "md")}"'}
        return PlainTextResponse(content=body, media_type="text/markdown; charset=utf-8", headers=headers)
    if format == "html":
        body = build_html(sample, audit, signoffs, handovers)
        headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "html")}"'}
        return HTMLResponse(content=body, media_type="text/html; charset=utf-8", headers=headers)

    body = build_json(sample, audit, signoffs, handovers)
    headers = {"Content-Disposition": f'attachment; filename="{_safe_filename(sample["code"], "json")}"'}
    return Response(content=body, media_type="application/json; charset=utf-8", headers=headers)


# ---------- 前端静态页（挂在最后，避免吞掉 API 路由） ----------

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
