"""结论签署测试：快照不可变、列表/详情、撤销保留原快照、报告集成。"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-signoff-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_signoff.db")

import pytest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample(client):
    code = "UT-SIGNOFF-001"
    for s in client.get("/api/samples").json():
        if s["code"] == code:
            client.delete(f"/api/samples/{s['id']}")
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "签署测试样本", "description": "含断档链路"},
    )
    assert resp.status_code == 201
    return resp.json()


def _add_event(client, sid, custodian, start, end=None):
    resp = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": custodian, "start_time": start, "end_time": end},
    )
    assert resp.status_code == 201
    return resp.json()


def _sign(client, sid, signer="王敏", signed_at="2026-09-18 15:00:00", remark="复核无误"):
    return client.post(
        f"/api/samples/{sid}/signoffs",
        json={"signer": signer, "signed_at": signed_at, "remark": remark},
    )


def test_signoff_creates_immutable_snapshot(client, sample):
    sid = sample["id"]
    e1 = _add_event(client, sid, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    e2 = _add_event(client, sid, "李四", "2026-09-18 10:30:00", "2026-09-18 11:00:00")

    # 当前链路有 30 分钟断档 -> fail
    assert client.get(f"/api/samples/{sid}").json()["audit"]["summary"]["gaps"] == 1

    resp = _sign(client, sid)
    assert resp.status_code == 201
    signoff = resp.json()
    assert signoff["status"] == "active"
    assert signoff["signer"] == "王敏"
    assert signoff["audit_status"] == "fail"
    assert signoff["summary"]["gaps"] == 1
    assert signoff["event_count"] == 2
    assert len(signoff["digest"]) == 12

    # 签署后修改事件：消除断档、删除一条事件 —— 历史快照不得被改写
    client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "李四", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00"},
    )
    client.delete(f"/api/events/{e1['id']}")
    assert client.get(f"/api/samples/{sid}").json()["audit"]["status"] == "pass"

    detail = client.get(f"/api/signoffs/{signoff['id']}").json()
    snap = detail["snapshot"]
    assert detail["integrity_ok"] is True
    assert len(detail["digest"]) == 64
    # 快照仍是签署时的两条事件与 fail 结论
    assert len(snap["events"]) == 2
    assert snap["audit"]["status"] == "fail"
    assert snap["audit"]["summary"]["gaps"] == 1
    assert snap["sample"]["code"] == sample["code"]


def test_signoff_list_and_detail(client, sample):
    sid = sample["id"]
    assert _sign(client, sid, signer="王敏").status_code == 201
    resp = _sign(client, sid, signer="李雷", remark="第二次签署")
    assert resp.status_code == 201

    items = client.get(f"/api/samples/{sid}/signoffs").json()
    assert len(items) == 2
    first = items[0]  # 按 id 倒序，最新在前
    assert first["signer"] == "李雷"
    assert first["remark"] == "第二次签署"
    assert first["status"] == "active"
    assert "conclusion" in first and "summary" in first

    detail = client.get(f"/api/signoffs/{first['id']}").json()
    assert detail["snapshot"]["sample"]["id"] == sid
    assert "events" in detail["snapshot"] and "audit" in detail["snapshot"]

    # 样本详情接口集成签署摘要
    sample_detail = client.get(f"/api/samples/{sid}").json()
    assert "signoffs" in sample_detail
    assert any(s["id"] == first["id"] for s in sample_detail["signoffs"])

    assert client.get("/api/signoffs/999999").status_code == 404


def test_signoff_validation(client, sample):
    sid = sample["id"]
    # 缺签署人
    resp = client.post(
        f"/api/samples/{sid}/signoffs",
        json={"signer": "  ", "signed_at": "2026-09-18 15:00:00"},
    )
    assert resp.status_code == 422
    # 签署时间格式错误
    resp = client.post(
        f"/api/samples/{sid}/signoffs",
        json={"signer": "王敏", "signed_at": "昨天下午"},
    )
    assert resp.status_code == 422
    # 样本不存在
    resp = client.post(
        "/api/samples/999999/signoffs",
        json={"signer": "王敏", "signed_at": "2026-09-18 15:00:00"},
    )
    assert resp.status_code == 404


def test_revoke_requires_reason_and_keeps_snapshot(client, sample):
    sid = sample["id"]
    signoff = _sign(client, sid, signer="韩梅梅").json()

    # 空原因 -> 422
    resp = client.post(f"/api/signoffs/{signoff['id']}/revoke", json={"reason": "  "})
    assert resp.status_code == 422

    # 正常撤销
    resp = client.post(
        f"/api/signoffs/{signoff['id']}/revoke",
        json={"reason": "签署后发现遗漏事件，需重新审计"},
    )
    assert resp.status_code == 200
    revoked = resp.json()
    assert revoked["status"] == "revoked"
    assert revoked["revoke_reason"] == "签署后发现遗漏事件，需重新审计"
    assert revoked["revoked_at"]

    # 重复撤销 -> 409
    resp = client.post(
        f"/api/signoffs/{signoff['id']}/revoke", json={"reason": "再次撤销"}
    )
    assert resp.status_code == 409

    # 原快照保留，内容不变
    detail = client.get(f"/api/signoffs/{signoff['id']}").json()
    assert detail["status"] == "revoked"
    assert detail["snapshot"]["sample"]["code"] == sample["code"]
    assert detail["integrity_ok"] is True

    # 列表中仍可见（已撤销状态）
    items = client.get(f"/api/samples/{sid}/signoffs").json()
    target = next(s for s in items if s["id"] == signoff["id"])
    assert target["status"] == "revoked"
    assert target["revoke_reason"] == "签署后发现遗漏事件，需重新审计"


def test_report_includes_signoffs(client, sample):
    sid = sample["id"]
    assert _sign(client, sid, signer="李雷").status_code == 201
    revoked = _sign(client, sid, signer="韩梅梅").json()
    client.post(f"/api/signoffs/{revoked['id']}/revoke", json={"reason": "重新审计"})

    md = client.get(f"/api/samples/{sid}/report?format=markdown")
    assert md.status_code == 200
    assert "结论签署" in md.text
    assert "李雷" in md.text
    assert "已撤销" in md.text

    html_resp = client.get(f"/api/samples/{sid}/report?format=html")
    assert "结论签署" in html_resp.text
    assert "李雷" in html_resp.text

    payload = client.get(f"/api/samples/{sid}/report?format=json").json()
    assert "signoffs" in payload
    assert any(s["signer"] == "李雷" for s in payload["signoffs"])


def test_delete_sample_cascades_signoffs(client, sample):
    sid = sample["id"]
    assert client.delete(f"/api/samples/{sid}").status_code == 204
    assert client.get(f"/api/samples/{sid}/signoffs").status_code == 404
