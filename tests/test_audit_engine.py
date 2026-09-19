"""审计引擎单元测试：断档 / 重叠 / 逆序 / 完整链路 / 开放保管。"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_audit.db")

import pytest

from app.audit import build_audit


def ev(id_, seq, custodian, start, end=None):
    return {
        "id": id_,
        "seq": seq,
        "custodian": custodian,
        "start_time": start,
        "end_time": end,
        "note": "",
    }


def codes(result):
    return [f["code"] for f in result["findings"]]


def test_clean_chain_pass():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ev(2, 2, "李四", "2026-09-18 10:00:00", "2026-09-18 11:30:00"),
        ev(3, 3, "王五", "2026-09-18 11:30:00", "2026-09-18 12:00:00"),
    ])
    assert result["status"] == "pass"
    assert codes(result) == []
    assert result["summary"]["gaps"] == 0
    assert result["summary"]["overlaps"] == 0


def test_open_ended_last_event_passes():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ev(2, 2, "李四", "2026-09-18 10:00:00", None),
    ])
    assert result["status"] == "pass"
    assert result["summary"]["open_holds"] == 1
    assert result["events"][1]["open"] is True
    assert result["events"][1]["duration"] == "进行中（未归还）"


def test_gap_detected():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ev(2, 2, "李四", "2026-09-18 10:30:00", "2026-09-18 11:00:00"),
    ])
    assert result["status"] == "fail"
    assert "gap" in codes(result)
    gap = next(f for f in result["findings"] if f["code"] == "gap")
    assert "30 分钟" in gap["message"]
    assert gap["from"] == "2026-09-18 10:00:00"
    assert gap["to"] == "2026-09-18 10:30:00"


def test_overlap_detected():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 11:00:00"),
        ev(2, 2, "李四", "2026-09-18 10:00:00", "2026-09-18 12:00:00"),
    ])
    assert result["status"] == "fail"
    assert codes(result).count("overlap") >= 1
    assert result["summary"]["overlaps"] >= 1


def test_non_adjacent_parallel_overlap():
    # 三条记录：相邻均无缝，但第 1、3 条并行
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 12:00:00"),
        ev(2, 2, "李四", "2026-09-18 12:00:00", "2026-09-18 13:00:00"),
        ev(3, 3, "王五", "2026-09-18 09:30:00", "2026-09-18 10:30:00"),
    ])
    # 第 2、3 条之间存在断档；第 1、3 条并行重叠
    assert "gap" in codes(result)
    assert "overlap" in codes(result)


def test_out_of_order_entry_warns_but_chain_ok():
    # 录入顺序：先登记 09:00、11:00，再补录 10:00（seq=3），时间链本身连续
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ev(2, 2, "王五", "2026-09-18 11:00:00", "2026-09-18 12:00:00"),
        ev(3, 3, "李四", "2026-09-18 10:00:00", "2026-09-18 11:00:00"),
    ])
    assert result["status"] == "warning"
    assert result["summary"]["out_of_order"] >= 1
    assert result["summary"]["gaps"] == 0
    assert result["summary"]["overlaps"] == 0


def test_open_predecessor_then_new_custody_overlaps():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", None),
        ev(2, 2, "李四", "2026-09-18 10:00:00", "2026-09-18 11:00:00"),
    ])
    assert result["status"] == "fail"
    assert "overlap" in codes(result)


def test_open_event_after_closed_ones_no_phantom_overlap():
    # 末条开放事件开始于所有闭合区间之后：不应产生任何幽灵重叠
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
        ev(2, 2, "李四", "2026-09-18 10:00:00", "2026-09-18 11:30:00"),
        ev(3, 3, "王五", "2026-09-18 11:30:00", None),
    ])
    assert result["status"] == "pass"
    assert "overlap" not in codes(result)
    assert "gap" not in codes(result)
    # 时间轴对开放尾部有延伸，开放条带必须可见
    open_bar = next(b for b in result["timeline"]["bars"] if b["open"])
    assert open_bar["width"] > 1


def test_both_open_events_overlap_open_ended():
    # 两个开放事件先后开始且都未归还 -> 自第二个开始起持续重叠
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 09:00:00", None),
        ev(2, 2, "李四", "2026-09-18 10:00:00", None),
    ])
    assert result["status"] == "fail"
    overlap = next(f for f in result["findings"] if f["code"] == "overlap")
    assert overlap["to"] is None


def test_reversed_interval_event():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 11:00:00", "2026-09-18 09:00:00"),
    ])
    assert result["status"] == "fail"
    assert "reversed_interval" in codes(result)


def test_empty_events():
    result = build_audit([])
    assert result["status"] == "empty"
    assert result["events"] == []
    assert result["timeline"]["bars"] == []


def test_events_sorted_by_time_not_seq():
    result = build_audit([
        ev(1, 1, "张三", "2026-09-18 11:00:00", "2026-09-18 12:00:00"),
        ev(2, 2, "李四", "2026-09-18 09:00:00", "2026-09-18 10:00:00"),
    ])
    assert result["events"][0]["custodian"] == "李四"
    assert result["events"][1]["custodian"] == "张三"
