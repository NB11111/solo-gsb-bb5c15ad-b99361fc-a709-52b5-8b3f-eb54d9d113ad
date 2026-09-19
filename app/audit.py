"""交接链路审计引擎。

一条交接事件表示某个经手人在 [start_time, end_time] 区间内保管样本，
``end_time`` 为空表示当前仍在保管中。系统按起始时间排序后检测：

* 逆序（reversed）  —— 录入顺序晚的事件，起始时间反而更早；
* 断档（gap）       —— 按时间排序后，相邻两段保管区间之间无人负责；
* 重叠（overlap）   —— 两段保管区间在时间上交叉（含并行保管）。

同时为前端时间线生成可直接渲染的几何数据（泳道、事件条、冲突区域、刻度）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

OPEN_LABEL = "（当前仍在保管）"


@dataclass
class ParsedEvent:
    id: int
    custodian: str
    start: datetime
    end: Optional[datetime]  # None 表示仍在保管
    note: str
    seq: int
    raw_end: Optional[str]


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    """解析 ISO/空格分隔的日期时间字符串，统一返回 naive datetime。"""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    text = text.replace("T", " ")
    # 兼容 "2026-09-18 09:00:00.000" 与秒级精度
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"无法解析的时间格式: {value!r}")


def fmt_dt(value: Optional[datetime]) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else OPEN_LABEL


def fmt_duration(seconds: float) -> str:
    """把秒数转成可读中文时长。"""
    seconds = max(0, round(seconds))
    if seconds == 0:
        return "0 秒"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days} 天")
    if hours:
        parts.append(f"{hours} 小时")
    if minutes:
        parts.append(f"{minutes} 分钟")
    if secs and not parts:  # 不足 1 分钟时才显示秒
        parts.append(f"{secs} 秒")
    return " ".join(parts)


def _pct(pos: float, span_start: float, span: float) -> float:
    return round((pos - span_start) / span * 100, 2)


def _intersect(a: ParsedEvent, b: ParsedEvent) -> Optional[tuple[datetime, Optional[datetime]]]:
    """返回两个保管区间的交集 (lo, hi)；无交集返回 None。

    end=None 表示开放区间（保管至无限远），此时 hi 可能为 None。
    端点相等（交接无缝衔接）不算重叠。
    """
    lo = max(a.start, b.start)
    if a.end is None or b.end is None:
        # 只有一端开放时，闭合端的结束时间须晚于较晚的起点才算相交
        closed_end = a.end if b.end is None else b.end
        if closed_end is not None and closed_end <= lo:
            return None
        hi = None  # 任一开放则交集延伸开放
    else:
        hi = min(a.end, b.end)
        if lo >= hi:
            return None
    return lo, hi


def build_audit(events: list[dict[str, Any]]) -> dict[str, Any]:
    """对单一样本的事件列表执行审计。

    入参事件字典需包含 id / custodian / start_time / end_time / note / seq。
    返回结论、发现项、事件审计视图与时间线几何数据。
    """
    findings: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []
    valid: list[ParsedEvent] = []

    # 1. 逐条解析，标记格式错误与起止逆序
    for ev in events:
        try:
            start = parse_dt(ev["start_time"])
        except ValueError as exc:
            findings.append(
                {
                    "kind": "error",
                    "code": "bad_time",
                    "message": f"第 {ev['seq']} 条录入（{ev['custodian']}）起始时间无效：{exc}",
                    "event_ids": [ev["id"]],
                }
            )
            continue
        if start is None:
            findings.append(
                {
                    "kind": "error",
                    "code": "bad_time",
                    "message": f"第 {ev['seq']} 条录入（{ev['custodian']}）缺少起始时间",
                    "event_ids": [ev["id"]],
                }
            )
            continue
        try:
            end = parse_dt(ev.get("end_time"))
        except ValueError as exc:
            findings.append(
                {
                    "kind": "error",
                    "code": "bad_time",
                    "message": f"第 {ev['seq']} 条录入（{ev['custodian']}）结束时间无效：{exc}",
                    "event_ids": [ev["id"]],
                }
            )
            continue

        reversed_interval = end is not None and end < start
        if reversed_interval:
            findings.append(
                {
                    "kind": "conflict",
                    "code": "reversed_interval",
                    "message": (
                        f"第 {ev['seq']} 条录入（{ev['custodian']}）起止时间倒置："
                        f"{fmt_dt(start)} 晚于结束 {fmt_dt(end)}"
                    ),
                    "event_ids": [ev["id"]],
                }
            )
        pe = ParsedEvent(
            id=ev["id"],
            custodian=ev["custodian"],
            start=start,
            end=end,
            note=ev.get("note") or "",
            seq=ev["seq"],
            raw_end=ev.get("end_time"),
        )
        valid.append(pe)

    # 2. 按起始时间排序，检测录入顺序逆序
    by_start = sorted(valid, key=lambda e: (e.start, e.id))
    for a, b in zip(by_start, by_start[1:]):
        if a.start < b.start and a.seq > b.seq:
            findings.append(
                {
                    "kind": "warning",
                    "code": "out_of_order",
                    "message": (
                        f"存在逆序录入：第 {b.seq} 条（{b.custodian}，{fmt_dt(b.start)}）"
                        f"登记在第 {a.seq} 条（{a.custodian}，{fmt_dt(a.start)}）之后，"
                        f"但起始时间反而更早"
                    ),
                    "event_ids": [b.id, a.id],
                }
            )

    # 起止倒置的事件不参与区间链校验，避免污染断档/重叠结果
    chain = [e for e in by_start if not (e.end is not None and e.end < e.start)]

    # 3. 断档与邻接重叠检测
    open_predecessor: Optional[ParsedEvent] = None
    for prev, cur in zip(chain, chain[1:]):
        if prev.end is None:
            findings.append(
                {
                    "kind": "conflict",
                    "code": "overlap",
                    "message": (
                        f"{prev.custodian} 的保管尚未归还（自 {fmt_dt(prev.start)} 起开放），"
                        f"{cur.custodian} 又于 {fmt_dt(cur.start)} 开始保管，两段交接重叠"
                    ),
                    "event_ids": [prev.id, cur.id],
                    "from": fmt_dt(cur.start),
                    "to": None,
                }
            )
            open_predecessor = prev
            continue
        delta = (cur.start - prev.end).total_seconds()
        if delta > 0:
            findings.append(
                {
                    "kind": "conflict",
                    "code": "gap",
                    "message": (
                        f"保管断档 {fmt_duration(delta)}：{prev.custodian} 于 {fmt_dt(prev.end)} 归还后，"
                        f"直到 {fmt_dt(cur.start)} 才由 {cur.custodian} 接手，期间无人负责"
                    ),
                    "event_ids": [prev.id, cur.id],
                    "from": fmt_dt(prev.end),
                    "to": fmt_dt(cur.start),
                }
            )
        elif delta < 0:
            findings.append(
                {
                    "kind": "conflict",
                    "code": "overlap",
                    "message": (
                        f"交接重叠 {fmt_duration(-delta)}：{cur.custodian} 于 {fmt_dt(cur.start)} 接手时，"
                        f"{prev.custodian} 尚未归还（至 {fmt_dt(prev.end)}）"
                    ),
                    "event_ids": [prev.id, cur.id],
                    "from": fmt_dt(cur.start),
                    "to": fmt_dt(prev.end),
                }
            )

    # 4. 非相邻区间的并行重叠（多线交叉）也需标出。
    #    end=None 视为开放区间（延伸至无限远），因此只有当开放事件
    #    在另一事件结束之前就已开始时才算重叠。
    adjacent_pairs = {
        tuple(sorted((a.id, b.id))) for a, b in zip(chain, chain[1:])
    }
    for i, a in enumerate(chain):
        for b in chain[i + 2 :]:
            if tuple(sorted((a.id, b.id))) in adjacent_pairs:
                continue
            cross = _intersect(a, b)
            if cross is not None:
                lo, hi = cross
                hi_label = fmt_dt(hi) if hi is not None else OPEN_LABEL
                findings.append(
                    {
                        "kind": "conflict",
                        "code": "overlap",
                        "message": (
                            f"并行保管重叠：{a.custodian} 与 {b.custodian} 在 "
                            f"{fmt_dt(lo)} ~ {hi_label} 同时持有样本"
                        ),
                        "event_ids": [a.id, b.id],
                        "from": fmt_dt(lo),
                        "to": fmt_dt(hi) if hi is not None else None,
                    }
                )

    # 5. 开放保管（未归还）信息
    open_events = [e for e in valid if e.end is None]

    # 6. 汇总统计
    valid_count = len(valid)
    conflict_ids: set[int] = set()
    for f in findings:
        if f["code"] in ("gap", "overlap", "reversed_interval"):
            conflict_ids.update(f.get("event_ids", []))
    gap_count = sum(1 for f in findings if f["code"] == "gap")
    overlap_count = sum(1 for f in findings if f["code"] == "overlap")
    reversed_count = sum(1 for f in findings if f["code"] == "reversed_interval")
    out_of_order_count = sum(1 for f in findings if f["code"] == "out_of_order")

    # 7. 可读结论
    if valid_count == 0 and events:
        status, conclusion = "fail", "所有交接记录的时间均无法解析，审计无法进行，请先修正时间数据。"
    elif valid_count == 0:
        status, conclusion = "empty", "暂无交接事件，请录入第一条交接记录后再进行审计。"
    elif conflict_ids:
        problems = []
        if gap_count:
            problems.append(f"{gap_count} 处保管断档")
        if overlap_count:
            problems.append(f"{overlap_count} 处交接重叠")
        if reversed_count:
            problems.append(f"{reversed_count} 条起止时间倒置")
        tail = "；另有逆序补录记录，建议核对登记流程。" if out_of_order_count else "。"
        conclusion = (
            f"链路审计未通过：共发现 {'、'.join(problems)}。"
            f"涉及 {len(conflict_ids)} 条交接记录，需核实责任归属并补全手续{tail}"
        )
        status = "fail"
    elif out_of_order_count:
        conclusion = (
            f"链路审计通过：{valid_count} 条交接记录时间连续、无断档与重叠；"
            f"但存在 {out_of_order_count} 处逆序录入（事后补录），建议规范登记顺序。"
        )
        status = "warning"
    else:
        ending = "，样本当前仍在保管中，链路开放。" if open_events else "，样本已完成全流程交接。"
        conclusion = f"链路审计通过：{valid_count} 条交接记录按时间无缝衔接，无断档、重叠或逆序{ending}"
        status = "pass"

    audit_events = [_event_view(e, conflict_ids) for e in by_start]
    timeline = _build_timeline(chain, conflict_ids)

    return {
        "status": status,
        "conclusion": conclusion,
        "findings": findings,
        "events": audit_events,
        "timeline": timeline,
        "summary": {
            "total": len(events),
            "valid": valid_count,
            "gaps": gap_count,
            "overlaps": overlap_count,
            "reversed": reversed_count,
            "out_of_order": out_of_order_count,
            "open_holds": len(open_events),
        },
    }


def _event_view(e: ParsedEvent, conflict_ids: set[int]) -> dict[str, Any]:
    return {
        "id": e.id,
        "seq": e.seq,
        "custodian": e.custodian,
        "start_time": fmt_dt(e.start),
        "end_time": fmt_dt(e.end),
        "open": e.end is None,
        "note": e.note,
        "has_conflict": e.id in conflict_ids,
        "duration": "进行中（未归还）"
        if e.end is None
        else fmt_duration((e.end - e.start).total_seconds()),
    }


def _build_timeline(chain: list[ParsedEvent], conflict_ids: set[int]) -> dict[str, Any]:
    """生成时间线渲染数据：泳道分配 + 事件条 + 断档/重叠区域 + 刻度。"""
    if not chain:
        return {"bars": [], "lanes": 0, "zones": [], "ticks": [], "start": None, "end": None}

    starts = [e.start for e in chain]
    closed_ends = [e.end for e in chain if e.end is not None]
    span_start = min(starts)
    span_end = max(closed_ends + starts)
    span = (span_end - span_start).total_seconds()
    if span <= 0:
        span = 60.0
    # 最新事件仍在保管时，时间轴向右延伸 12%（至少 30 分钟），
    # 让开放条带的斜纹尾部可见
    open_max = max((e.start for e in chain if e.end is None), default=None)
    if open_max is not None and open_max >= span_end:
        pad = max(span * 0.12, 1800.0)
        span_end = span_end + timedelta(seconds=pad)
        span = (span_end - span_start).total_seconds()

    # 贪婪泳道分配：区间不相交的事件放在同一泳道
    lanes: list[list[ParsedEvent]] = []
    lane_end: list[datetime] = []
    bars: list[dict[str, Any]] = []
    for e in chain:
        placed = False
        for i, end_at in enumerate(lane_end):
            if end_at is not None and end_at <= e.start:
                lanes[i].append(e)
                lane_end[i] = e.end or span_end
                bar_lane = i
                placed = True
                break
        if not placed:
            lanes.append([e])
            lane_end.append(e.end or span_end)
            bar_lane = len(lanes) - 1

        if e.end is None:
            left = _pct(e.start.timestamp(), span_start.timestamp(), span)
            width = round(100 - left, 2)
        else:
            left = _pct(e.start.timestamp(), span_start.timestamp(), span)
            width = max(1.2, _pct(e.end.timestamp(), span_start.timestamp(), span) - left)
        bars.append(
            {
                "id": e.id,
                "custodian": e.custodian,
                "lane": bar_lane,
                "left": left,
                "width": width,
                "open": e.end is None,
                "conflict": e.id in conflict_ids,
                "start_label": fmt_dt(e.start),
                "end_label": fmt_dt(e.end),
            }
        )

    # 冲突区域：相邻断档 + 所有两两重叠
    raw_zones: list[tuple[datetime, Optional[datetime], str]] = []
    for prev, cur in zip(chain, chain[1:]):
        if prev.end is None:
            # 重叠窗口只到后一段结束；若后一段也开放，则冲突持续开放
            raw_zones.append((cur.start, cur.end, "overlap"))
        else:
            delta = (cur.start - prev.end).total_seconds()
            if delta > 0:
                raw_zones.append((prev.end, cur.start, "gap"))
            elif delta < 0:
                raw_zones.append((cur.start, prev.end, "overlap"))
    for i, a in enumerate(chain):
        for b in chain[i + 2 :]:
            cross = _intersect(a, b)
            if cross is not None:
                raw_zones.append((cross[0], cross[1], "overlap"))

    # 合并相邻/重叠的同类区域，便于渲染；None（开放）延伸到时间轴末端
    raw_zones.sort(key=lambda z: (z[0], z[1] or span_end))
    zones: list[dict[str, Any]] = []
    for zstart, zend, kind in raw_zones:
        eff_end = zend or span_end
        if zones and zones[-1]["kind"] == kind and zstart <= zones[-1]["_hi"]:
            zones[-1]["_hi"] = max(zones[-1]["_hi"], eff_end)
            zones[-1]["_open"] = zones[-1]["_open"] or zend is None
            hi_label = OPEN_LABEL if zones[-1]["_open"] else fmt_dt(zones[-1]["_hi"])
            zones[-1]["to"] = hi_label
            zones[-1]["width"] = round(
                _pct(zones[-1]["_hi"].timestamp(), span_start.timestamp(), span) - zones[-1]["left"], 2
            )
            continue
        left = _pct(zstart.timestamp(), span_start.timestamp(), span)
        zones.append(
            {
                "kind": kind,
                "from": fmt_dt(zstart),
                "to": OPEN_LABEL if zend is None else fmt_dt(eff_end),
                "left": left,
                "width": max(0.6, _pct(eff_end.timestamp(), span_start.timestamp(), span) - left),
                "_hi": eff_end,
                "_open": zend is None,
            }
        )
    for z in zones:
        z.pop("_hi", None)
        z.pop("_open", None)

    # 5 个等距刻度
    ticks = []
    for i in range(5):
        tick_dt = span_start + (span_end - span_start) * i / 4
        ticks.append(
            {
                "left": round(i / 4 * 100, 2),
                "label": tick_dt.strftime("%m-%d %H:%M"),
            }
        )

    return {
        "bars": bars,
        "lanes": max(1, len(lanes)),
        "zones": zones,
        "ticks": ticks,
        "start": fmt_dt(span_start),
        "end": fmt_dt(span_end),
    }
