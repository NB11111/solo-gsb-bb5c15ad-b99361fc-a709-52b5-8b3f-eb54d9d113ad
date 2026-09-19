"""API 端到端测试：样本与事件 CRUD、审计接口、报告导出。"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-api-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_api.db")

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
    code = "UT-SAMPLE-001"
    # 清理可能残留的同名样本
    for s in client.get("/api/samples").json():
        if s["code"] == code:
            client.delete(f"/api/samples/{s['id']}")
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "单元测试样本", "description": "链路有冲突"},
    )
    assert resp.status_code == 201
    return resp.json()


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_sample_crud_and_duplicate(client, sample):
    # 重复编号 -> 409
    resp = client.post("/api/samples", json={"code": sample["code"], "name": "重复"})
    assert resp.status_code == 409

    detail = client.get(f"/api/samples/{sample['id']}").json()
    assert detail["sample"]["code"] == sample["code"]
    assert detail["audit"]["status"] == "empty"


def test_event_lifecycle_and_audit(client, sample):
    sid = sample["id"]
    base = "2026-09-18 09:00:00"

    def add(custodian, start, end=None):
        return client.post(
            f"/api/samples/{sid}/events",
            json={"custodian": custodian, "start_time": start, "end_time": end},
        )

    r1 = add("张三", base, "2026-09-18 10:00:00")
    assert r1.status_code == 201
    e1 = r1.json()
    assert e1["seq"] == 1

    # 断档 30 分钟
    r2 = add("李四", "2026-09-18 10:30:00", "2026-09-18 11:00:00")
    e2 = r2.json()

    detail = client.get(f"/api/samples/{sid}").json()
    assert detail["audit"]["summary"]["gaps"] == 1
    assert detail["audit"]["status"] == "fail"

    # 编辑 e2 起始时间到 10:00，断档消失 -> pass
    resp = client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "李四", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00", "note": "已修正"},
    )
    assert resp.status_code == 200
    detail = client.get(f"/api/samples/{sid}").json()
    assert detail["audit"]["status"] == "pass"
    assert detail["events"][1]["note"] == "已修正"

    # 输入校验：结束早于起始 -> 422
    bad = client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "李四", "start_time": "2026-09-18 12:00:00",
              "end_time": "2026-09-18 11:00:00"},
    )
    assert bad.status_code == 422

    # 删除事件
    assert client.delete(f"/api/events/{e1['id']}").status_code == 204
    assert client.delete(f"/api/events/{e1['id']}").status_code == 404


def test_report_export_formats(client, sample):
    sid = sample["id"]
    client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": "王五", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )

    md = client.get(f"/api/samples/{sid}/report?format=markdown")
    assert md.status_code == 200
    assert "样本交接链路审计报告" in md.text
    assert ".md" in md.headers["content-disposition"]

    html_resp = client.get(f"/api/samples/{sid}/report?format=html")
    assert html_resp.status_code == 200
    assert "<table>" in html_resp.text

    json_resp = client.get(f"/api/samples/{sid}/report?format=json")
    assert json_resp.status_code == 200
    payload = json_resp.json()
    assert payload["sample"]["code"] == sample["code"]
    assert "audit" in payload

    assert client.get(f"/api/samples/{sid}/report?format=pdf").status_code == 422


def test_static_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "样本交接链路审计" in resp.text


def test_delete_sample_cascades(client, sample):
    assert client.delete(f"/api/samples/{sample['id']}").status_code == 204
    assert client.get(f"/api/samples/{sample['id']}").status_code == 404
