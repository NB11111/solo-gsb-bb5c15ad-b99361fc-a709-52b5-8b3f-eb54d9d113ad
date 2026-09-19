"""异常处置队列测试。

覆盖：跨样本汇总与筛选（异常类型 / 经手人 / 发生时间 / 认领状态）、稳定指纹身份
（编辑经手人后指纹不变、处置状态沿用；禁止按数组序号绑定）、链路编辑后
重算（消失转已消除、复现恢复未处理、新异常保持未处理）、限时认领租约
（认领 / 幂等重复 / 他人冲突 409 / 到期接管 / 主动释放 / 仅认领人可处置 /
消除失效 / 复现未认领）、处置状态机（已处理 / 重新打开）、指纹版本乐观锁
（过期 409）、状态迁移记录（含认领 / 释放 / 接管）、样本删除级联。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-findings-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_findings.db")

import itertools
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.db import get_connection, init_db
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


def _claim(client, fp, version, handler="王敏"):
    return client.post(
        f"/api/findings/{fp}/claim",
        json={"expected_version": version, "handler": handler},
    )


def _release(client, fp, version, handler="王敏"):
    return client.post(
        f"/api/findings/{fp}/release",
        json={"expected_version": version, "handler": handler},
    )


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


def _backdate_expiry(fp: str, seconds_ago: int = 30) -> None:
    """直接写库，把指定发现的认领租约到期时间拨到过去（模拟租约到期）。"""
    expired = (datetime.now() - timedelta(seconds=seconds_ago)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE findings SET claim_expires_at = ? WHERE fingerprint = ?",
            (expired, fp),
        )
        conn.commit()
    finally:
        conn.close()


def test_queue_cross_sample_and_stable_fingerprint(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
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
    # 新发现默认未认领；队列返回认领租约展示字段
    assert item["claimed_by"] is None
    assert item["claim_active"] is False
    assert item["remaining_seconds"] == 0
    assert item["claim_ttl_seconds"] == 900
    assert data["claim_ttl_seconds"] == 900
    assert data["server_time"]

    # 指纹由内容生成、与列表顺序无关：重复获取结果一致
    again = _items_of(_queue(client), sid, "gap")[0]
    assert again["fingerprint"] == item["fingerprint"]


def test_claim_success_and_lease_fields(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    # 认领：版本 +1，租约 15 分钟
    resp = _claim(client, fp, ver)
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["claimed_by"] == "王敏"
    assert detail["claim_active"] is True
    assert 899 <= detail["remaining_seconds"] <= 900
    expected = (datetime.now() + timedelta(seconds=900)).strftime("%Y-%m-%d %H:%M:%S")
    assert detail["claim_expires_at"] == expected
    assert detail["version"] == ver + 1

    # 队列视图反映认领状态
    queued = _items_of(_queue(client), sid, "gap")[0]
    assert queued["claimed_by"] == "王敏"
    assert queued["claim_active"] is True
    assert queued["remaining_seconds"] > 0
    assert _queue(client)["summary"]["claimed"] >= 1

    # 迁移记录中含认领事件
    full = client.get(f"/api/findings/{fp}").json()
    claim_events = [t for t in full["transitions"] if t["event"] == "claim"]
    assert len(claim_events) == 1
    assert claim_events[0]["handler"] == "王敏"
    assert claim_events[0]["event_text"] == "限时认领"
    assert "15" in claim_events[0]["note"]


def test_claim_conflict_before_expiry_and_same_handler_idempotent(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    assert _claim(client, fp, ver, handler="王敏").status_code == 200

    # 租约未到期，其他人认领 / 接管 -> 409
    resp = _claim(client, fp, ver + 1, handler="赵强")
    assert resp.status_code == 409
    assert "王敏" in resp.json()["detail"]

    # 当前认领人重复提交 -> 幂等：版本不递增、不重复留痕
    again = _claim(client, fp, ver + 1, handler="王敏")
    assert again.status_code == 200
    assert again.json()["version"] == ver + 1
    full = client.get(f"/api/findings/{fp}").json()
    assert [t["event"] for t in full["transitions"]].count("claim") == 1

    # 其他人即便携带正确版本也不能处置（租约校验）
    assert _dispose(client, fp, "resolve", ver + 1, handler="赵强").status_code == 409
    # 其他人不能释放
    assert _release(client, fp, ver + 1, handler="赵强").status_code == 409


def test_takeover_after_expiry_increments_version(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    assert _claim(client, fp, ver, handler="王敏").status_code == 200
    # 租约到期
    _backdate_expiry(fp)

    # 到期后队列视图：claim_active 为 False，但保留原认领人
    expired_view = _items_of(_queue(client), sid, "gap")[0]
    assert expired_view["claim_active"] is False
    assert expired_view["claimed_by"] is None
    assert expired_view["last_claimed_by"] == "王敏"

    # 其他人接管成功：版本再 +1
    resp = _claim(client, fp, ver + 1, handler="赵强")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["claimed_by"] == "赵强"
    assert detail["claim_active"] is True
    assert detail["version"] == ver + 2

    full = client.get(f"/api/findings/{fp}").json()
    takeover = [t for t in full["transitions"] if t["event"] == "takeover"]
    assert len(takeover) == 1
    assert takeover[0]["handler"] == "赵强"
    assert "王敏" in takeover[0]["note"]

    # 接管后原认领人反而不能处置
    assert _dispose(client, fp, "resolve", ver + 2, handler="王敏").status_code == 409


def test_only_current_claimer_can_resolve_and_release(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    # 未认领不能直接处置
    assert _dispose(client, fp, "resolve", ver).status_code == 409
    # 未认领不能释放
    assert _release(client, fp, ver).status_code == 409

    # 认领后只有认领人可处置
    assert _claim(client, fp, ver).status_code == 200
    assert _dispose(client, fp, "resolve", ver + 1, note="已补齐手续").status_code == 200
    # 处置成功后租约已清除
    resolved = _items_of(_queue(client, status="resolved"), sid, "gap")[0]
    assert resolved["claimed_by"] is None
    assert resolved["claim_active"] is False


def test_release_returns_unclaimed_and_claim_again(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    assert _claim(client, fp, ver).status_code == 200
    rel = _release(client, fp, ver + 1)
    assert rel.status_code == 200
    assert rel.json()["claimed_by"] is None
    assert rel.json()["claim_active"] is False
    assert rel.json()["version"] == ver + 2

    # 迁移记录含主动释放事件
    full = client.get(f"/api/findings/{fp}").json()
    assert [t["event"] for t in full["transitions"]].count("release") == 1
    # 释放后发现回到未认领，任何人可重新认领
    assert _claim(client, fp, ver + 2, handler="赵强").status_code == 200


def test_claim_with_stale_version_returns_409(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver).status_code == 200
    # 主动释放导致版本递增；持旧版本接管 -> 409
    assert _release(client, fp, ver + 1).status_code == 200
    stale = _claim(client, fp, ver + 1, handler="赵强")  # 旧版本号
    assert stale.status_code == 409


def test_claim_invalid_for_resolved_or_eliminated(client, sample):
    sid, _, e2 = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver).status_code == 200
    assert _dispose(client, fp, "resolve", ver + 1).status_code == 200
    resolved = _items_of(_queue(client, status="resolved"), sid, "gap")[0]
    # 已处理不能认领
    assert _claim(client, fp, resolved["version"]).status_code == 409

    # 修复链路 -> 已消除，不能认领
    client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四",
            "start_time": "2026-09-18 10:00:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    eliminated = _items_of(_queue(client, status="eliminated"), sid, "gap")[0]
    assert _claim(client, fp, eliminated["version"]).status_code == 409


def test_elimination_revokes_lease_and_reappear_stays_unclaimed(client, sample):
    sid, _, e2 = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver).status_code == 200

    # 异常被系统消除 -> 租约自动失效，迁移记录含释放事件
    client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四",
            "start_time": "2026-09-18 10:00:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    eliminated = _items_of(_queue(client, status="eliminated"), sid, "gap")[0]
    assert eliminated["claimed_by"] is None
    full = client.get(f"/api/findings/{fp}").json()
    lease_release = [
        t for t in full["transitions"] if t["event"] == "release"
    ]
    assert lease_release and "自动失效" in lease_release[0]["note"]

    # 同一异常复现 -> 恢复未处理且保持未认领（版本递增）
    client.put(
        f"/api/events/{e2['id']}",
        json={
            "custodian": "李四",
            "start_time": "2026-09-18 10:30:00",
            "end_time": "2026-09-18 11:00:00",
            "note": "",
        },
    )
    back = _items_of(_queue(client), sid, "gap")[0]
    assert back["status"] == "open"
    assert back["claimed_by"] is None
    assert back["claim_active"] is False
    assert back["last_claimed_by"] is None
    assert back["version"] > eliminated["version"]
    # 复现后需要重新认领才能处置
    assert _dispose(client, fp, "resolve", back["version"]).status_code == 409


def test_claim_queue_filters_and_summary(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    _add_event(client, sid, "王五", "2026-09-18 10:45:00", "2026-09-18 12:00:00")
    open_items = _items_of(_queue(client), sid)
    gap = next(it for it in open_items if it["code"] == "gap")
    overlap = next(it for it in open_items if it["code"] == "overlap")

    # 初始全部未认领
    unclaimed = _items_of(_queue(client, claim="unclaimed"), sid)
    assert {it["fingerprint"] for it in unclaimed} == {gap["fingerprint"], overlap["fingerprint"]}
    assert _items_of(_queue(client, claim="claimed"), sid) == []
    assert _items_of(_queue(client, claim="expired"), sid) == []

    # 认领断档 -> 认领中 / 未认领筛选随之变化
    assert _claim(client, gap["fingerprint"], gap["version"]).status_code == 200
    claimed_items = _items_of(_queue(client, claim="claimed"), sid)
    assert [it["fingerprint"] for it in claimed_items] == [gap["fingerprint"]]
    assert [
        it["fingerprint"]
        for it in _items_of(_queue(client, claim="unclaimed"), sid)
    ] == [overlap["fingerprint"]]

    # 认领状态筛选仅对未处理项生效（已处理 / 已消除不出现）
    assert _items_of(_queue(client, status="resolved", claim="claimed"), sid) == []

    # 非法认领状态参数 -> 422（路由层 pattern 拦截）
    bad = client.get("/api/findings/queue", params={"claim": "nope"})
    assert bad.status_code == 422

    # 租约到期 -> 出现在「已过期可接管」
    _backdate_expiry(gap["fingerprint"])
    expired_items = _items_of(_queue(client, claim="expired"), sid)
    assert [it["fingerprint"] for it in expired_items] == [gap["fingerprint"]]
    assert _items_of(_queue(client, claim="claimed"), sid) == []


def test_dispose_resolve_reopen_and_version_conflict(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp, ver = item["fingerprint"], item["version"]

    # 先认领（处置前置条件）
    assert _claim(client, fp, ver).status_code == 200

    # 标记已处理
    resp = _dispose(client, fp, "resolve", ver + 1, note="已补充交接说明")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["status"] == "resolved"
    assert detail["handler"] == "王敏"
    assert detail["note"] == "已补充交接说明"
    assert detail["version"] == ver + 2
    assert detail["resolved_at"]

    # 过期版本再次处置 -> 409 冲突
    assert _dispose(client, fp, "resolve", ver).status_code == 409
    # 当前版本但状态不允许（已处理不能重复标记）-> 409
    assert _dispose(client, fp, "resolve", ver + 2).status_code == 409
    # 重新打开携带旧版本 -> 409
    assert _dispose(client, fp, "reopen", ver).status_code == 409

    # 当前版本重新打开 -> 成功，回到未处理（租约不保留，需重新认领）
    ok = _dispose(client, fp, "reopen", ver + 2, note="复核发现仍需补手续")
    assert ok.status_code == 200
    body = ok.json()
    assert body["status"] == "open"
    assert body["resolved_at"] is None
    assert body["claimed_by"] is None
    assert body["claim_active"] is False
    # 重新打开后未认领不能直接处置
    assert _dispose(client, fp, "resolve", ver + 3).status_code == 409

    # 状态迁移记录完整留痕
    detail = client.get(f"/api/findings/{fp}").json()
    moves = [(t["from_status"], t["to_status"], t["event"]) for t in detail["transitions"]]
    assert (None, "open", "status_change") in moves
    assert ("open", "resolved", "status_change") in moves
    assert ("resolved", "open", "status_change") in moves
    assert ("open", "open", "claim") in moves
    resolve_row = next(
        t
        for t in detail["transitions"]
        if t["from_status"] == "open" and t["to_status"] == "resolved"
    )
    assert resolve_row["handler"] == "王敏"
    assert resolve_row["note"] == "已补充交接说明"


def test_state_kept_when_fingerprint_unchanged(client, sample):
    sid, _, e2 = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]
    assert _claim(client, fp, item["version"]).status_code == 200
    assert _dispose(client, fp, "resolve", item["version"] + 1, note="已核实").status_code == 200

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
    assert _claim(client, item["fingerprint"], item["version"]).status_code == 200
    assert _dispose(client, item["fingerprint"], "resolve", item["version"] + 1).status_code == 200

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
    # 认领 / 释放不存在的发现同样 404
    assert _claim(client, "0" * 64, 1).status_code == 404
    assert _release(client, "0" * 64, 1).status_code == 404


def test_claim_validation(client, sample):
    sid, _, _ = _make_gap_sample(client, sample)
    item = _items_of(_queue(client), sid, "gap")[0]
    fp = item["fingerprint"]
    # 空认领人 -> 422；版本号缺失 -> 422
    assert _claim(client, fp, 1, handler="  ").status_code == 422
    resp = client.post(
        f"/api/findings/{fp}/claim",
        json={"handler": "王敏"},
    )
    assert resp.status_code == 422
    assert _release(client, fp, 1, handler="  ").status_code == 422


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
