"""批量导入交接事件测试。

覆盖：
* 模板下载（UTF-8 BOM、固定表头）；
* CSV 文件级错误（空文件 / 非 UTF-8 / 表头错误 / 无数据行 / 超行数上限）；
* 逐行校验错误（空经手人、时间格式、起止倒置、列数不符），且预览绝不写库；
* 合法预览返回令牌、录入序预览与导入后审计结论 / 交接确认失效投影；
* 确认导入：按文件顺序分配 seq、单次写库、结论刷新；
* 预览后链路增删改 -> 令牌失效（409，要求重新预览）；
* 令牌一次性使用、篡改 / 跨样本令牌被拒绝；
* 事务原子性：写入中途异常整体回滚，不允许部分落库。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-bulk-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_bulk.db")

import itertools

import pytest
from fastapi.testclient import TestClient

from app import bulk_import
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
    resp = client.post(
        "/api/samples",
        json={"code": f"UT-BULK-{next(_seq):03d}", "name": "批量导入测试样本"},
    )
    assert resp.status_code == 201
    return resp.json()


def _preview(client, sid, content: bytes):
    return client.post(f"/api/samples/{sid}/events/import-preview", content=content)


HEADER = "经手人,开始时间,结束时间,备注\n"
GOOD_CSV = (
    HEADER
    + "张三,2026-09-18 09:00:00,2026-09-18 10:00:00,采集\n"
    + "李四,2026-09-18 10:00:00,2026-09-18 11:30:00,运输\n"
    + "王五,2026-09-18 11:30:00,,仍在保管\n"
)


# ---------- 模板 ----------

def test_template_download(client, sample):
    sid = sample["id"]
    r = client.get(f"/api/samples/{sid}/events/import-template")
    assert r.status_code == 200
    assert r.content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM
    text = r.content.decode("utf-8-sig")
    assert text.splitlines()[0] == "经手人,开始时间,结束时间,备注"
    assert "attachment" in r.headers["content-disposition"]

    # 未知样本 404
    assert client.get("/api/samples/999999/events/import-template").status_code == 404


# ---------- 文件级错误 ----------

def test_file_level_errors(client, sample):
    sid = sample["id"]
    assert _preview(client, sid, b"").status_code == 400
    assert _preview(client, sid, HEADER.encode("utf-8")).status_code == 400
    assert _preview(client, sid, "甲,乙,丙,丁\n1,2,3,4\n".encode("utf-8")).status_code == 400
    # GBK 编码（非 UTF-8）
    assert _preview(client, sid, GOOD_CSV.encode("gbk")).status_code == 400
    # 超过行数上限
    big = HEADER + "".join(
        f"张三,2026-09-18 09:00:00,2026-09-18 10:00:00,备注{i}\n"
        for i in range(bulk_import.MAX_IMPORT_ROWS + 1)
    )
    assert _preview(client, sid, big.encode("utf-8")).status_code == 400


# ---------- 逐行校验 + 预览不写库 ----------

def test_row_level_errors_and_no_write(client, sample):
    sid = sample["id"]
    bad_csv = (
        HEADER
        + ",2026-09-18 09:00:00,2026-09-18 10:00:00,空经手人\n"          # 空经手人
        + "李四,昨天,,坏时间\n"                                            # 时间不可解析
        + "赵六,2026-09-18 12:00:00,2026-09-18 08:00:00,起止倒置\n"       # 倒置
        + "孙七,2026-09-18 09:00:00,2026-09-18 10:00:00,多了一列,意外\n"  # 5 列
    )
    r = _preview(client, sid, bad_csv.encode("utf-8"))
    assert r.status_code == 200
    p = r.json()
    assert p["total_rows"] == 4 and p["valid_rows"] == 0 and p["invalid_rows"] == 4
    assert p["all_valid"] is False and p["token"] is None
    for row in p["rows"]:
        assert row["errors"]
        assert row["seq_preview"] is None

    # 预览绝不写库
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 0


def test_partial_valid_rows_no_token_and_no_write(client, sample):
    sid = sample["id"]
    body = (
        HEADER
        + "张三,2026-09-18 09:00:00,2026-09-18 10:00:00,正常行\n"
        + "李四,bad-time,,错误行\n"
    )
    p = _preview(client, sid, body.encode("utf-8")).json()
    assert p["valid_rows"] == 1 and p["invalid_rows"] == 1
    assert p["all_valid"] is False and p["token"] is None
    # 存在错误行时不展示录入序（该方案不会落库）
    assert all(r["seq_preview"] is None for r in p["rows"])
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 0


def test_valid_preview_shape_and_audit_projection(client, sample):
    sid = sample["id"]
    p = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()
    assert p["all_valid"] is True and p["valid_rows"] == 3
    assert [r["seq_preview"] for r in p["rows"]] == [1, 2, 3]
    assert p["token"] and p["expires_at"] > 0 and p["ttl_seconds"] == 600
    # 当前为空链路，导入后通过
    assert p["current"]["event_count"] == 0
    assert p["current"]["audit"]["status"] == "empty"
    assert p["projected"]["event_count"] == 3
    assert p["projected"]["audit"]["status"] == "pass"
    assert p["projected"]["handover_summary"]["total"] == 2
    # 无新冲突
    assert p["projected"]["new_findings"] == []
    assert all(not r["in_conflict"] for r in p["rows"])


def test_preview_flags_new_conflicts(client, sample):
    sid = sample["id"]
    # 先有一条 09:00-12:00 的事件
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "赵保管", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 12:00:00"},
    )
    body = HEADER + "新经手人,2026-09-18 10:00:00,2026-09-18 11:00:00,并行重叠\n"
    p = _preview(client, sid, body.encode("utf-8")).json()
    assert p["all_valid"] is True
    assert p["current"]["audit"]["status"] == "pass"
    assert p["projected"]["audit"]["status"] == "fail"
    assert any(f["code"] == "overlap" for f in p["projected"]["new_findings"])
    assert p["rows"][0]["in_conflict"] is True
    # 预览 seq 接续现有链路
    assert p["rows"][0]["seq_preview"] == 2
    # 预览不写库
    detail = client.get(f"/api/samples/{sid}").json()
    assert len(detail["events"]) == 1


def test_bom_crlf_and_quoted_commas(client, sample):
    sid = sample["id"]
    body = "﻿" + HEADER.replace("\n", "\r\n") + (
        '张三,2026-09-18 09:00:00,2026-09-18 10:00:00,"备注,含逗号"\r\n'
        '李四,2026-09-18 10:00,2026-09-18 11:00,时间可只到分钟\r\n'
        "\r\n"  # 末尾空行应被忽略
    )
    p = _preview(client, sid, body.encode("utf-8")).json()
    assert p["total_rows"] == 2 and p["all_valid"] is True
    assert p["rows"][0]["note"] == "备注,含逗号"
    assert p["rows"][0]["normalized"]["note"] == "备注,含逗号"


# ---------- 确认导入 ----------

def test_confirm_import_happy_path(client, sample):
    sid = sample["id"]
    p = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": p["token"]}
    )
    assert r.status_code == 201, r.text
    res = r.json()
    assert res["imported_count"] == 3
    assert (res["first_seq"], res["last_seq"]) == (1, 3)
    assert len(res["event_ids"]) == 3

    detail = client.get(f"/api/samples/{sid}").json()
    assert [e["seq"] for e in detail["events"]] == [1, 2, 3]
    assert [e["custodian"] for e in detail["events"]] == ["张三", "李四", "王五"]
    assert detail["audit"]["status"] == "pass"
    # 交接项：张三->李四已无缝；李四->王五无缝（王五开放区间不影响第一项）
    assert detail["handovers"]["summary"]["total"] == 2


def test_confirm_appends_seq_after_existing(client, sample):
    sid = sample["id"]
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "甲", "start_time": "2026-09-18 08:00:00",
              "end_time": "2026-09-18 09:00:00"},
    )
    p = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()
    res = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": p["token"]}
    ).json()
    assert (res["first_seq"], res["last_seq"]) == (2, 4)
    seqs = [e["seq"] for e in client.get(f"/api/samples/{sid}").json()["events"]]
    assert seqs == [1, 2, 3, 4]


def test_stale_token_after_chain_change_rejected(client, sample):
    sid = sample["id"]
    token = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()["token"]

    # 预览后新增事件
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "插一脚", "start_time": "2026-09-18 07:00:00",
              "end_time": "2026-09-18 08:00:00"},
    )
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409
    assert "重新" in r.json()["detail"]

    # 预览后编辑事件
    p = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()
    token = p["token"]
    existing = client.get(f"/api/samples/{sid}").json()["events"][0]
    client.put(
        f"/api/events/{existing['id']}",
        json={"custodian": "插一脚改", "start_time": existing["start_time"],
              "end_time": existing["end_time"], "note": "改过了"},
    )
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409

    # 预览后删除事件
    p = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()
    token = p["token"]
    client.delete(f"/api/events/{existing['id']}")
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409
    # 拒绝时链路只有被删剩下的 0 条（该样本最初仅一条）
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 0


def test_token_single_use_and_tamper(client, sample):
    sid = sample["id"]
    token = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()["token"]
    assert client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    ).status_code == 201
    # 导入后指纹变化，令牌不可复用
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409
    # 篡改签名
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm",
        json={"token": token[:-2] + ("ab" if not token.endswith("ab") else "cd")},
    )
    assert r.status_code == 409
    # 空令牌 422
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": "   "}
    )
    assert r.status_code == 422


def test_token_cross_sample_rejected(client, sample):
    sid = sample["id"]
    other = client.post(
        "/api/samples",
        json={"code": f"UT-BULK-OTHER-{next(_seq):03d}", "name": "另一个样本"},
    ).json()
    token = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()["token"]
    r = client.post(
        f"/api/samples/{other['id']}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409
    assert "样本" in r.json()["detail"]
    # 另一个样本没有被写入
    assert len(client.get(f"/api/samples/{other['id']}").json()["events"]) == 0


def test_expired_token_rejected(client, sample, monkeypatch):
    sid = sample["id"]
    token = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()["token"]
    # 把校验时刻推进到 TTL 之后
    real_time = bulk_import.time.time
    monkeypatch.setattr(
        bulk_import.time, "time", lambda: real_time() + bulk_import.TOKEN_TTL_SECONDS + 1
    )
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 409
    assert "有效期" in r.json()["detail"]


# ---------- 交接确认失效 ----------

def _confirm_pair(client, sid, a, b):
    client.post(
        f"/api/samples/{sid}/handovers/confirm?from_event_id={a}&to_event_id={b}",
        json={"side": "from", "confirmer_name": "交出人",
              "confirmed_at": "2026-09-18 10:01:00"},
    )
    client.post(
        f"/api/samples/{sid}/handovers/confirm?from_event_id={a}&to_event_id={b}",
        json={"side": "to", "confirmer_name": "接收人",
              "confirmed_at": "2026-09-18 10:01:00"},
    )


def test_import_invalidates_adjacency_and_projects_it(client, sample):
    sid = sample["id"]
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "甲", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "乙", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00"},
    )
    events = client.get(f"/api/samples/{sid}").json()["events"]
    a, b = events[0]["id"], events[1]["id"]
    _confirm_pair(client, sid, a, b)
    assert client.get(f"/api/samples/{sid}").json()["handovers"]["summary"]["confirmed"] == 1

    # 预览插入 甲、乙 之间的事件：投影出 1 条失效
    body = HEADER + "丙,2026-09-18 09:30:00,2026-09-18 10:00:00,插入甲乙之间\n"
    p = _preview(client, sid, body.encode("utf-8")).json()
    assert p["projected"]["handover_change"]["newly_invalidated"] == 1
    assert p["current"]["handover_summary"]["invalidated"] == 0
    assert p["projected"]["handover_summary"]["invalidated"] == 1
    # 预览不改库
    assert client.get(f"/api/samples/{sid}").json()["handovers"]["summary"]["invalidated"] == 0

    res = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": p["token"]}
    ).json()
    assert res["invalidated_confirmations"] == 1
    assert res["invalidation_reasons"] == {"adjacency_changed": 1}
    hv = client.get(f"/api/samples/{sid}").json()["handovers"]
    assert hv["summary"]["confirmed"] == 0
    assert hv["summary"]["invalidated"] == 1
    assert hv["history"][0]["reason"] == "adjacency_changed"
    # 原确认内容保留
    assert hv["history"][0]["from_name"] == "交出人"


# ---------- 原子性 ----------

def test_confirm_is_atomic_on_failure(client, sample, monkeypatch):
    sid = sample["id"]
    token = _preview(client, sid, GOOD_CSV.encode("utf-8")).json()["token"]

    call_count = {"n": 0}

    def boom(conn, sample_id, now=None):
        call_count["n"] += 1
        raise RuntimeError("模拟刷新失效状态失败")

    # 不抛出服务端异常，直接拿到 500 响应以验证回滚
    quiet = TestClient(app, raise_server_exceptions=False)
    monkeypatch.setattr(bulk_import, "refresh_handover_validity", boom)
    r = quiet.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 500
    assert call_count["n"] == 1
    monkeypatch.undo()

    # 失败后没有任何部分写入；链路指纹未变，原令牌仍然可用 -> 重新提交成功
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 0
    r = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert r.status_code == 201, r.text
    assert len(client.get(f"/api/samples/{sid}").json()["events"]) == 3
