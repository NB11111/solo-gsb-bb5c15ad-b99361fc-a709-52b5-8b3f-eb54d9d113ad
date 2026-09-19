"""双向交接确认测试。

覆盖：交接项按审计排序生成、两侧确认状态机、时间不一致、确认绑定字段摘要、
事件编辑/删除/插入导致的失效（原记录保留）、重新确认、校验与级联删除、
样本详情 / 报告集成。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-handover-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_handover.db")

import itertools

import pytest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_seq = itertools.count(1)


@pytest.fixture()
def sample(client):
    code = f"UT-HANDOVER-{next(_seq):03d}"
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "交接确认测试样本", "description": "链路"},
    )
    assert resp.status_code == 201
    return resp.json()


def _add_event(client, sid, custodian, start, end=None, note=""):
    resp = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": custodian, "start_time": start, "end_time": end, "note": note},
    )
    assert resp.status_code == 201
    return resp.json()


def _confirm(client, sid, a, b, side, name, at):
    return client.post(
        f"/api/samples/{sid}/handovers/confirm"
        f"?from_event_id={a}&to_event_id={b}",
        json={"side": side, "confirmer_name": name, "confirmed_at": at},
    )


def _items(client, sid):
    return client.get(f"/api/samples/{sid}/handovers").json()


def _pair(client, sid, a, b):
    view = _items(client, sid)
    return next(
        (
            i
            for i in view["items"]
            if i["from_event"]["id"] == a and i["to_event"]["id"] == b
        ),
        None,
    )


def _chain(client, sid):
    """新增一条无缝三事件链路，返回 (e1, e2, e3) 按起始时间排序的 id。"""
    e1 = _add_event(client, sid, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    e2 = _add_event(client, sid, "李四", "2026-09-18 10:00:00", "2026-09-18 11:00:00")
    e3 = _add_event(client, sid, "王五", "2026-09-18 11:00:00", None)
    return e1["id"], e2["id"], e3["id"]


def test_items_generated_in_audit_order_and_empty(client, sample):
    sid = sample["id"]
    view = _items(client, sid)
    assert view["items"] == []
    assert view["summary"] == {
        "total": 0, "confirmed": 0, "pending": 0,
        "time_mismatch": 0, "invalidated": 0,
    }

    # 逆序补录：先登记 10:00 的事件，再登记 09:00 的事件
    e_b = _add_event(client, sid, "李四", "2026-09-18 10:00:00", "2026-09-18 11:00:00")
    e_a = _add_event(client, sid, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00")

    view = _items(client, sid)
    assert view["summary"]["total"] == 1
    item = view["items"][0]
    # 审计排序（起始时间）而非录入顺序：张三 -> 李四
    assert item["from_event"]["id"] == e_a["id"]
    assert item["to_event"]["id"] == e_b["id"]
    assert item["time_consistent"] is True
    assert item["status"] == "pending"
    assert item["confirmation"] is None


def test_full_confirmation_flow_confirmed(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)

    r = _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00")
    assert r.status_code == 200
    assert r.json()["item"]["status"] == "pending"

    view = _items(client, sid)
    pair1 = view["items"][0]
    assert pair1["confirmation"]["from_name"] == "张三"
    assert pair1["confirmation"]["to_name"] is None

    # 同侧重复确认 -> 409
    dup = _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:02:00")
    assert dup.status_code == 409

    r = _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 10:01:30")
    assert r.status_code == 200
    item = r.json()["item"]
    assert item["status"] == "confirmed"
    assert item["confirmation"]["digest"]

    summary = _items(client, sid)["summary"]
    # 仅 张三->李四 完成双向；李四->王五 仍待确认
    assert summary["confirmed"] == 1
    assert summary["pending"] == 1


def test_time_mismatch_status(client, sample):
    sid = sample["id"]
    e_a = _add_event(client, sid, "李四", "2026-09-18 10:00:00", "2026-09-18 12:00:00")
    e_b = _add_event(client, sid, "王五", "2026-09-18 13:30:00", "2026-09-18 14:00:00")
    a, b = e_a["id"], e_b["id"]

    r = _confirm(client, sid, a, b, "from", "李四", "2026-09-18 12:05:00")
    assert r.status_code == 200
    r = _confirm(client, sid, a, b, "to", "王五", "2026-09-18 13:31:00")
    assert r.status_code == 200
    item = r.json()["item"]
    assert item["time_consistent"] is False
    assert item["status"] == "time_mismatch"
    assert _items(client, sid)["summary"]["time_mismatch"] == 1


def test_edit_event_invalidates_and_allows_reconfirm(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)

    assert _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00").status_code == 200
    r = _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 10:01:30")
    assert r.json()["item"]["status"] == "confirmed"
    handover_id = r.json()["item"]["confirmation"]["id"]

    # 编辑张三的备注（关键字段之一）-> 原确认失效
    r = client.put(
        f"/api/events/{e_a}",
        json={"custodian": "张三", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00", "note": "补充交接备注"},
    )
    assert r.status_code == 200

    pair = _pair(client, sid, e_a, e_b)
    assert pair["status"] == "pending"  # 不再计入有效状态
    assert pair["confirmation"] is None
    view = _items(client, sid)
    assert view["summary"]["invalidated"] >= 1
    hist = next(h for h in view["history"] if h["id"] == handover_id)
    assert hist["reason"] == "event_edited"
    assert hist["invalidated_at"]
    assert hist["from_name"] == "张三"  # 原确认内容保留

    # 记录详情：已失效，绑定的旧字段摘要仍可查
    detail = client.get(f"/api/handovers/{handover_id}").json()
    assert detail["status"] == "invalidated"
    assert detail["invalidated_reason"] == "event_edited"
    assert detail["from_event_snapshot"]["note"] == ""  # 编辑前的旧摘要
    assert len(detail["digest"]) == 64

    # 两侧重新确认 -> 再次有效
    assert _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 15:00:00").status_code == 200
    r = _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 15:00:00")
    assert r.status_code == 200
    assert r.json()["item"]["status"] == "confirmed"
    # 失效历史仍保留
    assert any(h["id"] == handover_id for h in _items(client, sid)["history"])


def test_insert_between_invalidates_adjacency(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)

    assert _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00").status_code == 200
    r = _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 10:01:30")
    assert r.json()["item"]["status"] == "confirmed"
    handover_id = r.json()["item"]["confirmation"]["id"]

    # 在张三(09-10) 与李四(10-11) 之间插入一条 09:30-10:00 的事件
    e_mid = _add_event(client, sid, "赵六", "2026-09-18 09:30:00", "2026-09-18 10:00:00")

    view = _items(client, sid)
    pairs = {(i["from_event"]["id"], i["to_event"]["id"]) for i in view["items"]}
    # 张三李四不再相邻 -> 无该交接项；出现新的 张三->赵六
    assert (e_a, e_b) not in pairs
    assert (e_a, e_mid["id"]) in pairs
    # 原确认以 adjacency_changed 失效保留（按 id 倒序，最新历史在最前）
    latest = view["history"][0]
    assert latest["id"] == handover_id
    assert latest["reason"] == "adjacency_changed"

    # 对不再相邻的事件发起确认 -> 409
    r = _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 16:00:00")
    assert r.status_code == 409


def test_delete_event_invalidates_then_record_remains(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)

    # 先对 张三->李四 完成双向确认
    assert _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00").status_code == 200
    r = _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 10:01:30")
    assert r.json()["item"]["status"] == "confirmed"
    handover_id = r.json()["item"]["confirmation"]["id"]

    # 删除李四事件
    assert client.delete(f"/api/events/{e_b}").status_code == 204

    view = _items(client, sid)
    hist = next(h for h in view["history"] if h["id"] == handover_id)
    assert hist["reason"] == "event_deleted"
    assert hist["to_custodian"] == "李四"  # 删除事件的字段快照仍保留
    detail = client.get(f"/api/handovers/{handover_id}").json()
    assert detail["status"] == "invalidated"
    assert detail["to_event_snapshot"]["custodian"] == "李四"


def test_confirm_validation(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)

    # side 非法 -> 422
    r = client.post(
        f"/api/samples/{sid}/handovers/confirm?from_event_id={e_a}&to_event_id={e_b}",
        json={"side": "both", "confirmer_name": "张三", "confirmed_at": "2026-09-18 10:00:00"},
    )
    assert r.status_code == 422
    # 姓名为空 -> 422
    assert _confirm(client, sid, e_a, e_b, "from", "  ", "2026-09-18 10:00:00").status_code == 422
    # 时间格式错误 -> 422
    assert _confirm(client, sid, e_a, e_b, "from", "张三", "昨天").status_code == 422
    # 同一事件作为两侧 / 不存在的事件 -> 404
    assert _confirm(client, sid, e_a, e_a, "from", "张三", "2026-09-18 10:00:00").status_code == 404
    assert _confirm(client, sid, 999999, e_b, "from", "张三", "2026-09-18 10:00:00").status_code == 404
    # 不存在的交接记录
    assert client.get("/api/handovers/999999").status_code == 404


def test_sample_detail_and_report_include_handovers(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)
    _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00")
    _confirm(client, sid, e_a, e_b, "to", "李四", "2026-09-18 10:01:30")

    detail = client.get(f"/api/samples/{sid}").json()
    assert "handovers" in detail
    assert "items" in detail["handovers"] and "summary" in detail["handovers"]

    md = client.get(f"/api/samples/{sid}/report?format=markdown").text
    assert "双向交接确认" in md
    assert "已确认" in md

    html_resp = client.get(f"/api/samples/{sid}/report?format=html").text
    assert "双向交接确认" in html_resp

    payload = client.get(f"/api/samples/{sid}/report?format=json").json()
    assert "handovers" in payload
    assert payload["handovers"]["summary"]["total"] == len(payload["handovers"]["items"])


def test_delete_sample_cascades_handovers(client, sample):
    sid = sample["id"]
    e_a, e_b, _ = _chain(client, sid)
    _confirm(client, sid, e_a, e_b, "from", "张三", "2026-09-18 10:01:00")
    assert client.get(f"/api/samples/{sid}/handovers").status_code == 200
    assert client.delete(f"/api/samples/{sid}").status_code == 204
    assert client.get(f"/api/samples/{sid}/handovers").status_code == 404
