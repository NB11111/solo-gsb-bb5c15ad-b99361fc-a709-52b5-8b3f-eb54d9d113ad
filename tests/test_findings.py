"""异常处置队列测试。

覆盖：跨样本汇总与筛选（异常类型 / 经手人 / 发生时间）、稳定指纹身份
（编辑经手人后指纹不变、处置状态沿用；禁止按数组序号绑定）、链路编辑后
重算（消失转已消除、复现恢复未处理、新异常保持未处理）、处置状态机
（已处理 / 重新打开）、指纹版本乐观锁（过期 409）、状态迁移记录、
样本删除级联。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-findings-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_findings.db")

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
    code = f"UT-FINDING-{next(_seq):03d}"
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "处置队列测试样本", "description": ""},
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


def _make_gap_sample(client, sample):
    """两段事件，中间 30 分钟断档（10:00 ~ 10:30 无人负责）。"""
    sid = sample["id"]
    e1 = _add_event(client, sid, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    e2 = _add_event(client, sid, "李四", "2026-09-18 10:30:00", "2026-09-18 11:00:00")
    return sid, e1, e2


def _queue(client, **params):
    resp = client.get("/api/findings/queue", params=params)
    assert resp.status_code == 200
    return resp.json()


def _items_of(data, sid, code=None):
    return [
        it
        for it in data["items"]
        if it["sample"]["id"] == sid and (code is None or it["code"] == code)
    ]


def _dispose(client, fp, action, version, handler="王敏", note=""):
    return client.post(
        f"/api/findings/{fp}/dispose",
        json={
            "action": action,
            "expected_version": version,
            "handler": handler,
            "note": note,
        },
    )


def test_queue_cross_sample_and_stable_fingerprint(client, sample):
    sid, e1, e2 = _make_gap_sample(client, sample)
    data = _queue(client)
    gaps = _items_of(data, sid, "gap")
    assert len(gaps) == 1
    item = gaps[0]
    assert item["status"] == "open"
    assert item["version"] == 1
    assert item["time_from"] == "2026-09-18 10:00:00"
    assert item["time_to"] == "2026-09-18 10:30:00"
    assert set(item["custodians"]) == {"张三", "李四"}
    assert len(item["fingerprint"]) == 64
    assert data["summary"]["open"] >= 1

    # 指纹由内容生成、与列表顺序无关：重复获取结果一致
    again = _items_of(_queue(client), sid, "gap")[0]
    assert again["fingerprint"] == item["fingerprint"]


def test_dispose_resolve_reopen_and_version_conflict(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    # 标记已处理
    resp = _dispose(client, fp, "resolve", ver, note="已补充交接说明")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["status"] == "resolved"
    assert detail["handler"] == "王敏"
    assert detail["note"] == "已补充交接说明"
    assert detail["version"] == ver + 1
    assert detail["resolved_at"]

    # 过期版本再次处置 -> 409 冲突
    assert _dispose(client, fp, "resolve", ver).status_code == 409
    # 当前版本但状态不允许（已处理不能重复标记）-> 409
    assert _dispose(client, fp, "resolve", ver + 1).status_code == 409
    # 重新打开携带旧版本 -> 409
    assert _dispose(client, fp, "reopen", ver).status_code == 409

    # 当前版本重新打开 -> 成功，回到未处理
    ok = _dispose(client, fp, "reopen", ver + 1, note="复核发现仍需补手续")
    assert ok.status_code == 200
    assert ok.json()["status"] == "open"
    assert ok.json()["resolved_at"] is None

    # 状态迁移记录完整留痕
    detail = client.get(f"/api/findings/{fp}").json()
    moves = [(t["from_status"], t["to_status"]) for t in detail["transitions"]]
    assert moves == [(None, "open"), ("open", "resolved"), ("resolved", "open")]
    assert detail["transitions"][1]["handler"] == "王敏"
    assert detail["transitions"][1]["note"] == "已补充交接说明"


def test_state_kept_when_fingerprint_unchanged(client, sample):
    sid, _, e2 = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]
    assert _dispose(client, fp, "resolve", item["version"], note="已核实").status_code == 200

    # 仅编辑经手人（异常类型 / 关联事件 / 时间边界均不变）-> 指纹不变，处置状态沿用
    resp = client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四（运输组）",
            "start_time": "2026-09-18 10:30:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    assert resp.status_code == 200
    resolved = _items_of(_queue(client, status="resolved"), sid, "gap")
    assert len(resolved) == 1
    assert resolved[0]["fingerprint"] == fp
    assert resolved[0]["handler"] == "王敏"
    assert "李四（运输组）" in resolved[0]["custodians"]
    # 未处理队列中不再出现该发现
    assert _items_of(_queue(client), sid, "gap") == []


def test_disappear_eliminated_and_reappear_reopens(client, sample):
    sid, _, e2 = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]

    # 修复断档（10:30 -> 10:00 无缝衔接）-> 发现转为已消除历史
    client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四",
            "start_time": "2026-09-18 10:00:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    assert _items_of(_queue(client), sid, "gap") == []
    eliminated = _items_of(_queue(client, status="eliminated"), sid, "gap")
    assert len(eliminated) == 1
    assert eliminated[0]["fingerprint"] == fp
    assert eliminated[0]["eliminated_at"]

    # 已消除的发现不能处置
    stale = _dispose(client, fp, "resolve", eliminated[0]["version"])
    assert stale.status_code == 409

    # 再次制造同样的断档 -> 同一指纹复现，恢复未处理（版本递增）
    client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四",
            "start_time": "2026-09-18 10:30:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    back = _items_of(_queue(client), sid, "gap")
    assert len(back) == 1
    assert back[0]["fingerprint"] == fp
    assert back[0]["status"] == "open"
    assert back[0]["version"] > eliminated[0]["version"]

    detail = client.get(f"/api/findings/{fp}").json()
    moves = [(t["from_status"], t["to_status"]) for t in detail["transitions"]]
    assert moves == [(None, "open"), ("open", "eliminated"), ("eliminated", "open")]


def test_new_findings_stay_open_after_chain_edit(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    assert _dispose(client, item["fingerprint"], "resolve", item["version"]).status_code == 200

    # 新增事件制造重叠 -> 新异常未处理；原断档已处理状态不受影响
    _add_event(client, sid, "王五", "2026-09-18 10:45:00", "2026-09-18 12:00:00")
    open_items = _items_of(_queue(client), sid)
    assert any(it["code"] == "overlap" and it["status"] == "open" for it in open_items)
    resolved = _items_of(_queue(client, status="resolved"), sid, "gap")
    assert len(resolved) == 1
    assert resolved[0]["fingerprint"] == item["fingerprint"]


def test_filters_by_code_custodian_and_time(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    _add_event(client, sid, "王五", "2026-09-18 10:45:00", "2026-09-18 12:00:00")

    # 按异常类型
    gaps = _items_of(_queue(client, code="gap"), sid)
    assert gaps and all(it["code"] == "gap" for it in gaps)
    overlaps = _items_of(_queue(client, code="overlap"), sid)
    assert overlaps and all(it["code"] == "overlap" for it in overlaps)

    # 按经手人（模糊匹配关联事件的经手人）
    by_cust = _items_of(_queue(client, custodian="王五"), sid)
    assert by_cust and all("王五" in it["custodians"] for it in by_cust)
    assert _items_of(_queue(client, custodian="不存在的人"), sid) == []

    # 按发生时间：与发现时间边界相交才保留
    hit = _items_of(
        _queue(client, time_from="2026-09-18 10:00:00", time_to="2026-09-18 11:00:00"),
        sid,
    )
    assert {it["code"] for it in hit} == {"gap", "overlap"}
    miss = _items_of(
        _queue(client, time_from="2026-01-01 00:00:00", time_to="2026-01-02 00:00:00"),
        sid,
    )
    assert miss == []

    # 汇总数量不受筛选影响
    data = _queue(client, code="gap")
    assert data["summary"]["open"] >= 2


def test_invalid_time_filter_rejected(client):
    resp = client.get("/api/findings/queue", params={"time_from": "not-a-time"})
    assert resp.status_code == 400


def test_dispose_unknown_fingerprint(client):
    resp = _dispose(client, "0" * 64, "resolve", 1)
    assert resp.status_code == 404


def test_dispose_validation(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]
    # 空处置人 -> 422；非法动作 -> 422；版本号缺失 -> 422
    assert _dispose(client, fp, "resolve", 1, handler="  ").status_code == 422
    assert _dispose(client, fp, "close", 1).status_code == 422
    resp = client.post(
        f"/api/findings/{fp}/dispose",
        json={"action": "resolve", "handler": "王敏"},
    )
    assert resp.status_code == 422


def test_summary_endpoint(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    _queue(client)  # 触发同步
    s = client.get("/api/findings/summary").json()
    assert s["open"] >= 1
    assert s["total"] == s["open"] + s["resolved"] + s["eliminated"]


def test_event_delete_eliminates_and_sample_delete_cascades(client, sample):
    sid, e1, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]

    # 删除事件使断档消失 -> 已消除
    assert client.delete(f"/api/events/{e1['id']}").status_code == 204
    eliminated = _items_of(_queue(client, status="eliminated"), sid, "gap")
    assert len(eliminated) == 1

    # 删除样本 -> 发现记录级联清除
    assert client.delete(f"/api/samples/{sid}").status_code == 204
    assert client.get(f"/api/findings/{fp}").status_code == 404
