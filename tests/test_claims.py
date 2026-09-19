"""异常处置队列 · 限时认领（15 分钟租约）测试。

覆盖：
* 认领成功后版本递增、返回剩余秒数与到期时间；同一认领人重复认领幂等；
* 认领 / 接管在单一事务内先重算发现、再同时校验 expected_version 与租约状态：
  未到期他人认领返回 409；版本过期返回 409；
* 租约到期后他人可接管（版本递增、迁移记录 event=takeover）；
* 只有当前认领人可标记已处理 / 主动释放；非认领人、过期租约均 409；
* 异常被系统消除时租约自动失效（lease_void 留痕），复现后保持未认领；
* 队列按认领状态（unclaimed / claimed / expired）筛选，汇总含 claimed 数；
* 迁移记录写入认领、释放、过期接管、租约失效全部事件。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-claim-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_claim.db")
# 默认保持生产的 15 分钟租约；真实等待到期的用例在用例内临时缩短 TTL
# （claim_ttl_seconds() 每次操作实时读取环境变量）

import itertools
import time

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
def gap(client):
    """新建一个含单条断档（10:00~10:30）的样本，返回 (sid, finding)。"""
    code = f"UT-CLAIM-{next(_seq):03d}"
    s = client.post(
        "/api/samples",
        json={"code": code, "name": "限时认领测试样本", "description": ""},
    ).json()
    sid = s["id"]
    for custodian, start, end in (
        ("张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ("李四", "2026-09-18 10:30:00", "2026-09-18 11:00:00"),
    ):
        r = client.post(
            f"/api/samples/{sid}/events",
            json={"custodian": custodian, "start_time": start, "end_time": end},
        )
        assert r.status_code == 201
    data = client.get("/api/findings/queue", params={"status": "open"}).json()
    items = [it for it in data["items"] if it["sample"]["id"] == sid and it["code"] == "gap"]
    assert len(items) == 1
    return sid, items[0]


def _claim(client, fp, version, handler):
    return client.post(
        f"/api/findings/{fp}/claim",
        json={"expected_version": version, "handler": handler},
    )


def _release(client, fp, version, handler, note=""):
    return client.post(
        f"/api/findings/{fp}/release",
        json={"expected_version": version, "handler": handler, "note": note},
    )


def _resolve(client, fp, version, handler, note=""):
    return client.post(
        f"/api/findings/{fp}/dispose",
        json={"action": "resolve", "expected_version": version,
              "handler": handler, "note": note},
    )


def _events(client, fp):
    d = client.get(f"/api/findings/{fp}").json()
    return [(t["event"], t["handler"], t["from_status"], t["to_status"]) for t in d["transitions"]]


def _backdate_lease(fp, seconds_ago=30 * 60):
    """直接把租约到期时间回退到过去（确定性地模拟 15 分钟已过）。"""
    from datetime import datetime, timedelta

    with get_connection() as conn:
        row = conn.execute("SELECT id, claimed_at FROM findings WHERE fingerprint = ?", (fp,)).fetchone()
        expired = (datetime.now() - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%d %H:%M:%S")
        claimed_at = (
            datetime.now() - timedelta(seconds=seconds_ago + 15 * 60)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE findings SET claimed_at = ?, claim_expires_at = ? WHERE id = ?",
            (claimed_at, expired, row["id"]),
        )


# ---------- 认领 ----------

def test_claim_open_finding_and_view_lease(client, gap):
    sid, item = gap
    fp = item["fingerprint"]
    assert item["claim_state"] == "unclaimed"
    assert item["claim_state_text"] == "未认领"
    assert item["claimed_by"] is None

    resp = _claim(client, fp, item["version"], "王敏")
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["claimed_by"] == "王敏"
    assert d["claimed_at"]
    assert d["claim_expires_at"] > d["claimed_at"]
    assert d["claim_state"] == "claimed"
    assert d["claim_state_text"] == "认领中"
    assert 0 < d["claim_remaining_seconds"] <= 15 * 60
    assert d["claim_ttl_seconds"] == 15 * 60
    assert d["version"] == item["version"] + 1

    events = _events(client, fp)
    assert ("claim", "王敏", "open", "open") in events


def test_claim_conflict_while_lease_active(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200

    # 未到期：其他人认领 -> 409（携带最新版本也不行，租约状态同时被校验）
    other = _claim(client, fp, ver + 1, "李强")
    assert other.status_code == 409
    assert "王敏" in other.json()["detail"]

    # 过期版本认领 -> 409（版本先于租约校验）
    assert _claim(client, fp, ver, "李强").status_code == 409

    # 同一认领人重复认领 -> 幂等成功，不递增版本、不续期
    again = _claim(client, fp, ver + 1, "王敏")
    assert again.status_code == 200
    assert again.json()["version"] == ver + 1


def test_claim_requires_open_status(client, gap):
    sid, item = gap
    fp, ver = item["fingerprint"], item["version"]
    claimed = _claim(client, fp, ver, "王敏").json()
    resolved = _resolve(client, fp, claimed["version"], "王敏")
    assert resolved.status_code == 200
    # 已处理 / 已消除不能认领
    assert _claim(client, fp, resolved.json()["version"], "王敏").status_code == 409


def test_claim_validation(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    # 空认领人 -> 422；版本号缺失 -> 422
    r = client.post(f"/api/findings/{fp}/claim", json={"expected_version": ver, "handler": "  "})
    assert r.status_code == 422
    r = client.post(f"/api/findings/{fp}/claim", json={"handler": "王敏"})
    assert r.status_code == 422
    # 不存在的指纹 -> 404
    assert _claim(client, "f" * 64, 1, "王敏").status_code == 404


# ---------- 过期接管 ----------

def test_takeover_after_expiry(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    _backdate_lease(fp)

    # 队列视图：认领状态为 expired，剩余秒数 0
    queue = client.get("/api/findings/queue", params={"status": "open"}).json()
    row = next(it for it in queue["items"] if it["fingerprint"] == fp)
    assert row["claim_state"] == "expired"
    assert row["claim_state_text"] == "已过期"
    assert row["claim_remaining_seconds"] == 0
    assert row["claimed_by"] == "王敏"  # 字段保留到被接管 / 释放

    # 到期后他人接管：版本递增、认领人换人
    takeover = _claim(client, fp, ver + 1, "李强")
    assert takeover.status_code == 200, takeover.text
    d = takeover.json()
    assert d["claimed_by"] == "李强"
    assert d["claim_state"] == "claimed"
    assert d["version"] == ver + 2

    events = _events(client, fp)
    assert ("claim", "王敏", "open", "open") in events
    assert ("takeover", "李强", "open", "open") in events


def test_takeover_after_real_time_expiry(client, gap, monkeypatch):
    """用 1 秒短租约真实等待到期后接管。"""
    monkeypatch.setenv("FINDING_CLAIM_TTL_SECONDS", "1")
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    time.sleep(1.2)
    resp = _claim(client, fp, ver + 1, "李强")
    assert resp.status_code == 200
    assert resp.json()["claimed_by"] == "李强"
    assert ("takeover", "李强", "open", "open") in _events(client, fp)


def test_takeover_stale_version_conflict(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    _backdate_lease(fp)
    # 租约虽到期，但携带认领前的旧版本 -> 版本校验先失败 -> 409
    assert _claim(client, fp, ver, "李强").status_code == 409


# ---------- 只有当前认领人可处置 / 释放 ----------

def test_only_claim_holder_can_resolve(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]

    # 未认领直接标记已处理 -> 409
    assert _resolve(client, fp, ver, "王敏").status_code == 409

    assert _claim(client, fp, ver, "王敏").status_code == 200
    # 其他人携带最新版本尝试处置 -> 409（租约状态校验）
    assert _resolve(client, fp, ver + 1, "李强").status_code == 409
    # 当前认领人处置成功
    ok = _resolve(client, fp, ver + 1, "王敏", note="补齐交接说明")
    assert ok.status_code == 200
    assert ok.json()["status"] == "resolved"
    assert ok.json()["claimed_by"] is None


def test_resolve_with_expired_lease_rejected(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    _backdate_lease(fp)
    # 原认领人租约到期后处置 -> 409，需重新认领 / 接管
    assert _resolve(client, fp, ver + 1, "王敏").status_code == 409
    # 李强接管后，王敏（旧版本 + 非认领人）仍不能处置
    assert _claim(client, fp, ver + 1, "李强").status_code == 200
    assert _resolve(client, fp, ver + 2, "王敏").status_code == 409
    assert _resolve(client, fp, ver + 2, "李强").status_code == 200


def test_release_by_holder_and_others_blocked(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200

    # 非认领人释放 -> 409
    assert _release(client, fp, ver + 1, "李强").status_code == 409
    # 旧版本 -> 409
    assert _release(client, fp, ver, "王敏").status_code == 409

    # 当前认领人释放成功：版本递增、租约清空、保持未认领
    ok = _release(client, fp, ver + 1, "王敏", note="先让出给同事")
    assert ok.status_code == 200
    d = ok.json()
    assert d["status"] == "open"
    assert d["claimed_by"] is None
    assert d["claim_expires_at"] is None
    assert d["claim_state"] == "unclaimed"
    assert d["version"] == ver + 2
    assert ("release", "王敏", "open", "open") in _events(client, fp)

    # 释放后其他人可立即认领
    assert _claim(client, fp, ver + 2, "李强").status_code == 200


def test_release_unclaimed_or_expired_rejected(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    # 未认领 -> 409
    assert _release(client, fp, ver, "王敏").status_code == 409

    assert _claim(client, fp, ver, "王敏").status_code == 200
    _backdate_lease(fp)
    # 已到期应走接管而非释放 -> 409
    assert _release(client, fp, ver + 1, "王敏").status_code == 409


# ---------- 系统消除 / 复现 ----------

def test_lease_void_on_elimination_and_unclaimed_on_reappear(client, gap):
    sid, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200

    # 修复断档（李四 10:30 -> 10:00）-> 异常被系统消除，租约自动失效
    events = client.get(f"/api/samples/{sid}").json()["events"]
    e2 = next(e for e in events if e["custodian"] == "李四")
    r = client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "李四", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00", "note": ""},
    )
    assert r.status_code == 200

    eliminated = client.get(
        "/api/findings/queue", params={"status": "eliminated"}
    ).json()
    row = next(it for it in eliminated["items"] if it["fingerprint"] == fp)
    assert row["status"] == "eliminated"
    assert row["claimed_by"] is None
    assert row["claim_expires_at"] is None

    events = _events(client, fp)
    assert ("claim", "王敏", "open", "open") in events
    lease_void = [e for e in events if e[0] == "lease_void"]
    assert len(lease_void) == 1 and lease_void[0][1] == "王敏"

    # 同一指纹复现 -> 恢复未处理且保持未认领，任何人可直接认领
    client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "李四", "start_time": "2026-09-18 10:30:00",
              "end_time": "2026-09-18 11:00:00", "note": ""},
    )
    back = client.get("/api/findings/queue", params={"status": "open"}).json()
    row = next(it for it in back["items"] if it["fingerprint"] == fp)
    assert row["status"] == "open"
    assert row["claimed_by"] is None
    assert _claim(client, fp, row["version"], "李强").status_code == 200


# ---------- 队列筛选与汇总 ----------

def test_queue_filter_by_claim_state(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]

    def fprints(params):
        data = client.get("/api/findings/queue", params=params).json()
        return {it["fingerprint"] for it in data["items"]}

    # 认领前：unclaimed 命中，claimed / expired 不命中
    assert fp in fprints({"status": "open", "claim": "unclaimed"})
    assert fp not in fprints({"status": "open", "claim": "claimed"})
    assert fp not in fprints({"status": "open", "claim": "expired"})

    assert _claim(client, fp, ver, "王敏").status_code == 200
    assert fp not in fprints({"status": "open", "claim": "unclaimed"})
    assert fp in fprints({"status": "open", "claim": "claimed"})
    assert fp not in fprints({"status": "open", "claim": "expired"})

    _backdate_lease(fp)
    assert fp in fprints({"status": "open", "claim": "expired"})
    assert fp not in fprints({"status": "open", "claim": "claimed"})

    # 汇总：claimed 只数未到期租约
    summary = client.get("/api/findings/summary").json()
    assert summary["claimed"] >= 0
    claimed_items = client.get(
        "/api/findings/queue", params={"claim": "claimed"}
    ).json()["items"]
    assert all(it["claim_state"] == "claimed" for it in claimed_items)


def test_summary_counts_active_claim(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    before = client.get("/api/findings/summary").json()["claimed"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    after = client.get("/api/findings/summary").json()
    assert after["claimed"] == before + 1
    _backdate_lease(fp)
    # 过期后不再计入 claimed
    client.get("/api/findings/summary")  # 触发重算
    expired_summary = client.get("/api/findings/summary").json()
    assert expired_summary["claimed"] == before


# ---------- 迁移记录事件标签 ----------

def test_transition_event_labels(client, gap):
    _, item = gap
    fp, ver = item["fingerprint"], item["version"]
    assert _claim(client, fp, ver, "王敏").status_code == 200
    assert _release(client, fp, ver + 1, "王敏").status_code == 200
    detail = client.get(f"/api/findings/{fp}").json()
    labels = [(t["event"], t["event_text"]) for t in detail["transitions"]]
    assert ("claim", "限时认领") in labels
    assert ("release", "主动释放") in labels
    # 首次出现为普通状态迁移
    assert ("state", "状态迁移") in labels
