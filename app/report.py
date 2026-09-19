"""样本审计报告导出：Markdown / HTML / JSON。"""
from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

from .audit import OPEN_LABEL

STATUS_TEXT = {
    "pass": "审计通过",
    "warning": "审计通过（存在告警）",
    "fail": "审计未通过",
    "empty": "无数据",
}

FINDING_TEXT = {
    "gap": "保管断档",
    "overlap": "交接重叠",
    "reversed_interval": "起止倒置",
    "out_of_order": "逆序录入",
    "bad_time": "时间格式错误",
}

SIGNOFF_STATUS_TEXT = {
    "active": "已签署",
    "revoked": "已撤销",
}

HANDOVER_STATUS_TEXT = {
    "confirmed": "已确认",
    "pending": "待确认",
    "time_mismatch": "时间不一致",
}

HANDOVER_REASON_TEXT = {
    "event_edited": "关联事件被编辑，绑定字段已变化",
    "event_deleted": "关联事件已被删除",
    "adjacency_changed": "事件新增或调整后两条记录不再相邻",
}


def _md_cell(text: Any) -> str:
    """转义 Markdown 表格单元格中的竖线。"""
    return str(text if text not in (None, "") else "—").replace("|", "\\|")


def build_markdown(
    sample: dict[str, Any],
    audit: dict[str, Any],
    signoffs: list[dict[str, Any]] | None = None,
    handovers: dict[str, Any] | None = None,
) -> str:
    s = audit["summary"]
    lines = [
        f"# 样本交接链路审计报告",
        "",
        f"- **样本编号**：{sample['code']}",
        f"- **样本名称**：{sample['name']}",
        f"- **审计结论**：{STATUS_TEXT.get(audit['status'], audit['status'])}",
        f"- **生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 结论",
        "",
        audit["conclusion"],
        "",
        "## 统计",
        "",
        f"| 交接记录 | 有效记录 | 断档 | 重叠 | 起止倒置 | 逆序录入 | 未归还 |",
        f"| --- | --- | --- | --- | --- | --- | --- |",
        f"| {s['total']} | {s['valid']} | {s['gaps']} | {s['overlaps']} | "
        f"{s['reversed']} | {s['out_of_order']} | {s['open_holds']} |",
        "",
    ]
    if audit["findings"]:
        lines += ["## 审计发现", ""]
        for i, f in enumerate(audit["findings"], 1):
            lines.append(f"{i}. **[{FINDING_TEXT.get(f['code'], f['code'])}]** {f['message']}")
        lines.append("")

    lines += ["## 交接事件（按起始时间排序）", ""]
    if audit["events"]:
        lines += [
            "| # | 录入序 | 经手人 | 起始时间 | 结束时间 | 保管时长 | 备注 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for i, e in enumerate(audit["events"], 1):
            end = OPEN_LABEL if e["open"] else e["end_time"]
            mark = " ⚠️" if e["has_conflict"] else ""
            lines.append(
                f"| {i}{mark} | {e['seq']} | {e['custodian']} | {e['start_time']} | "
                f"{end} | {e['duration']} | {e['note'] or '—'} |"
            )
        lines.append("")
    else:
        lines += ["_暂无交接事件。_", ""]

    lines += _signoff_markdown(signoffs)
    lines += _handover_markdown(handovers)
    return "\n".join(lines)


def _handover_markdown(handovers: dict[str, Any] | None) -> list[str]:
    lines = ["## 双向交接确认", ""]
    if not handovers or not handovers.get("items"):
        return lines + ["_暂无交接项（至少需要两条按时间相邻的交接事件）。_", ""]

    hs = handovers["summary"]
    lines += [
        f"共 {hs['total']} 个交接项：**已确认 {hs['confirmed']}**、"
        f"待确认 {hs['pending']}、时间不一致 {hs['time_mismatch']}；"
        f"另有失效历史记录 {hs['invalidated']} 条。",
        "",
        "| # | 交出方 | 交出结束时间 | 接收方 | 接收开始时间 | 时间衔接 | 状态 | "
        "交出确认（姓名 / 时间） | 接收确认（姓名 / 时间） |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in handovers["items"]:
        a, b = item["from_event"], item["to_event"]
        link = "一致" if item["time_consistent"] else "**不一致**"
        conf = item.get("confirmation")
        if conf:
            from_cell = (
                f"{conf['from_name']} / {conf['from_confirmed_at']}"
                if conf["from_name"]
                else "待确认"
            )
            to_cell = (
                f"{conf['to_name']} / {conf['to_confirmed_at']}"
                if conf["to_name"]
                else "待确认"
            )
        else:
            from_cell = to_cell = "待确认"
        lines.append(
            f"| {item['index']} | {_md_cell(a['custodian'])} | "
            f"{_md_cell(a.get('end_time') or '（仍在保管）')} | "
            f"{_md_cell(b['custodian'])} | {_md_cell(b['start_time'])} | {link} | "
            f"{HANDOVER_STATUS_TEXT.get(item['status'], item['status'])} | "
            f"{_md_cell(from_cell)} | {_md_cell(to_cell)} |"
        )
    lines.append("")

    history = handovers.get("history") or []
    if history:
        lines += [
            "### 失效的历史确认（不再计入有效状态，需重新确认）",
            "",
            "| 交出方 | 接收方 | 交出确认 | 接收确认 | 失效原因 | 失效时间 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for h in history:
            lines.append(
                f"| {_md_cell(h.get('from_custodian') or '（事件已删除）')} | "
                f"{_md_cell(h.get('to_custodian') or '（事件已删除）')} | "
                f"{_md_cell(h.get('from_name') or '—')} | "
                f"{_md_cell(h.get('to_name') or '—')} | "
                f"{HANDOVER_REASON_TEXT.get(h.get('reason'), h.get('reason') or '—')} | "
                f"{_md_cell(h.get('invalidated_at'))} |"
            )
        lines.append("")
    return lines


def _signoff_markdown(signoffs: list[dict[str, Any]] | None) -> list[str]:
    lines = ["## 结论签署", ""]
    if not signoffs:
        return lines + ["_尚未有任何签署记录。_", ""]
    lines += [
        "| 签署人 | 签署时间 | 状态 | 签署时审计结论 | 快照校验值 | 备注 | 撤销信息 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in signoffs:
        status = SIGNOFF_STATUS_TEXT.get(s["status"], s["status"])
        audit_txt = STATUS_TEXT.get(s.get("audit_status") or "", s.get("audit_status") or "—")
        revoke = "—"
        if s["status"] == "revoked":
            revoke = f"{s.get('revoked_at') or ''} {s.get('revoke_reason') or ''}".strip()
        lines.append(
            f"| {_md_cell(s['signer'])} | {_md_cell(s['signed_at'])} | {status} | "
            f"{audit_txt} | {_md_cell(s.get('digest'))} | {_md_cell(s.get('remark'))} | "
            f"{_md_cell(revoke)} |"
        )
    lines.append("")
    return lines


def build_html(
    sample: dict[str, Any],
    audit: dict[str, Any],
    signoffs: list[dict[str, Any]] | None = None,
    handovers: dict[str, Any] | None = None,
) -> str:
    s = audit["summary"]
    status_class = {"pass": "ok", "warning": "warn", "fail": "bad", "empty": "muted"}.get(
        audit["status"], "muted"
    )
    finding_rows = ""
    for i, f in enumerate(audit["findings"], 1):
        finding_rows += (
            f"<li><span class='tag tag-{f['code']}'>"
            f"{FINDING_TEXT.get(f['code'], f['code'])}</span>{html.escape(f['message'])}</li>"
        )
    if not finding_rows:
        finding_rows = "<li class='muted'>未发现异常。</li>"

    event_rows = ""
    for i, e in enumerate(audit["events"], 1):
        end = (
            f"<span class='open'>{html.escape(e['end_time'])} 未归还</span>"
            if e["open"]
            else html.escape(e["end_time"])
        )
        row_cls = " class='row-conflict'" if e["has_conflict"] else ""
        event_rows += (
            f"<tr{row_cls}><td>{i}</td><td>{e['seq']}</td>"
            f"<td>{html.escape(e['custodian'])}</td>"
            f"<td>{html.escape(e['start_time'])}</td><td>{end}</td>"
            f"<td>{html.escape(e['duration'])}</td>"
            f"<td>{html.escape(e['note'] or '—')}</td></tr>"
        )

    signoff_rows = ""
    for so in signoffs or []:
        st_cls = "ok" if so["status"] == "active" else "bad"
        st_txt = SIGNOFF_STATUS_TEXT.get(so["status"], so["status"])
        audit_txt = STATUS_TEXT.get(so.get("audit_status") or "", so.get("audit_status") or "—")
        revoke = "—"
        if so["status"] == "revoked":
            revoke = html.escape(
                f"{so.get('revoked_at') or ''} {so.get('revoke_reason') or ''}".strip()
            )
        signoff_rows += (
            f"<tr><td>{html.escape(so['signer'])}</td>"
            f"<td>{html.escape(so['signed_at'])}</td>"
            f"<td><span class='status {st_cls}'>{st_txt}</span></td>"
            f"<td>{html.escape(audit_txt)}</td>"
            f"<td><code>{html.escape(so.get('digest') or '')}</code></td>"
            f"<td>{html.escape(so.get('remark') or '—')}</td>"
            f"<td>{revoke}</td></tr>"
        )
    if not signoff_rows:
        signoff_rows = "<tr><td colspan='7' class='muted'>尚未有任何签署记录。</td></tr>"

    handover_section = _handover_html(handovers)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>审计报告 - {html.escape(sample['code'])}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         margin: 40px; color: #1f2933; background: #fafbfc; }}
  .card {{ background: #fff; border: 1px solid #e4e7eb; border-radius: 10px;
           padding: 24px 28px; margin-bottom: 20px; }}
  h1 {{ margin: 0 0 4px; font-size: 22px; }}
  h2 {{ font-size: 16px; margin: 0 0 12px; }}
  .meta {{ color: #616e7c; font-size: 13px; margin-top: 8px; }}
  .status {{ display: inline-block; padding: 4px 12px; border-radius: 999px;
             font-weight: 600; font-size: 13px; }}
  .ok {{ background: #e6f7ed; color: #1a7f4b; }}
  .warn {{ background: #fff6e0; color: #9a6b00; }}
  .bad {{ background: #fdecec; color: #c0392b; }}
  .muted {{ background: #eef1f4; color: #616e7c; }}
  .conclusion {{ font-size: 15px; line-height: 1.7; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th, td {{ border: 1px solid #e4e7eb; padding: 8px 10px; text-align: left; }}
  th {{ background: #f5f7f9; }}
  .row-conflict {{ background: #fff5f5; }}
  ul.findings {{ margin: 0; padding-left: 0; list-style: none; line-height: 1.9; }}
  .tag {{ display: inline-block; min-width: 64px; text-align: center; padding: 2px 8px;
          border-radius: 4px; font-size: 12px; margin-right: 8px; }}
  .tag-gap {{ background: #f3e8ff; color: #7b3fd4; }}
  .tag-overlap, .tag-reversed_interval {{ background: #fdecec; color: #c0392b; }}
  .tag-out_of_order {{ background: #fff6e0; color: #9a6b00; }}
  .tag-bad_time {{ background: #eef1f4; color: #52606d; }}
  .open {{ color: #b7791f; font-weight: 600; }}
  .hv-confirmed {{ color: #1a7f4b; font-weight: 600; }}
  .hv-pending {{ color: #616e7c; font-weight: 600; }}
  .hv-time_mismatch {{ color: #c0392b; font-weight: 600; }}
  .hv-invalid {{ color: #9a6b00; }}
  .hv-summary {{ margin-bottom: 10px; font-size: 13px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>样本交接链路审计报告</h1>
    <div class="meta">
      样本编号：<b>{html.escape(sample['code'])}</b>　·　样本名称：{html.escape(sample['name'])}　·
      生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
    <p><span class="status {status_class}">{STATUS_TEXT.get(audit['status'], audit['status'])}</span></p>
    <div class="conclusion">{html.escape(audit['conclusion'])}</div>
  </div>
  <div class="card">
    <h2>统计</h2>
    <table>
      <tr><th>交接记录</th><th>有效记录</th><th>断档</th><th>重叠</th><th>起止倒置</th>
          <th>逆序录入</th><th>未归还</th></tr>
      <tr><td>{s['total']}</td><td>{s['valid']}</td><td>{s['gaps']}</td><td>{s['overlaps']}</td>
          <td>{s['reversed']}</td><td>{s['out_of_order']}</td><td>{s['open_holds']}</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>审计发现</h2>
    <ul class="findings">{finding_rows}</ul>
  </div>
  <div class="card">
    <h2>交接事件（按起始时间排序）</h2>
    <table>
      <tr><th>#</th><th>录入序</th><th>经手人</th><th>起始时间</th><th>结束时间</th>
          <th>保管时长</th><th>备注</th></tr>
      {event_rows or '<tr><td colspan="7" class="muted">暂无交接事件。</td></tr>'}
    </table>
  </div>
  <div class="card">
    <h2>结论签署</h2>
    <table>
      <tr><th>签署人</th><th>签署时间</th><th>状态</th><th>签署时审计结论</th>
          <th>快照校验值</th><th>备注</th><th>撤销信息</th></tr>
      {signoff_rows}
    </table>
  </div>
  {handover_section}
</body>
</html>
"""


def _handover_html(handovers: dict[str, Any] | None) -> str:
    if not handovers or not handovers.get("items"):
        return (
            "<div class='card'><h2>双向交接确认</h2>"
            "<p class='muted'>暂无交接项（至少需要两条按时间相邻的交接事件）。</p></div>"
        )

    hs = handovers["summary"]
    rows_html = ""
    for item in handovers["items"]:
        a, b = item["from_event"], item["to_event"]
        link = (
            "<span class='hv-confirmed'>一致</span>"
            if item["time_consistent"]
            else "<span class='hv-time_mismatch'>不一致</span>"
        )
        conf = item.get("confirmation")
        if conf:
            from_cell = (
                f"{html.escape(conf['from_name'])}<br><span class='muted'>"
                f"{html.escape(conf['from_confirmed_at'])}</span>"
                if conf["from_name"]
                else "<span class='muted'>待确认</span>"
            )
            to_cell = (
                f"{html.escape(conf['to_name'])}<br><span class='muted'>"
                f"{html.escape(conf['to_confirmed_at'])}</span>"
                if conf["to_name"]
                else "<span class='muted'>待确认</span>"
            )
        else:
            from_cell = to_cell = "<span class='muted'>待确认</span>"
        end_a = html.escape(a.get("end_time") or "（仍在保管）")
        rows_html += (
            f"<tr><td>{item['index']}</td>"
            f"<td>{html.escape(a['custodian'])}</td><td>{end_a}</td>"
            f"<td>{html.escape(b['custodian'])}</td>"
            f"<td>{html.escape(b['start_time'])}</td><td>{link}</td>"
            f"<td class='hv-{item['status']}'>"
            f"{HANDOVER_STATUS_TEXT.get(item['status'], item['status'])}</td>"
            f"<td>{from_cell}</td><td>{to_cell}</td></tr>"
        )

    history = handovers.get("history") or []
    history_html = ""
    if history:
        hist_rows = ""
        for h in history:
            hist_rows += (
                f"<tr><td>{html.escape(h.get('from_custodian') or '（事件已删除）')}</td>"
                f"<td>{html.escape(h.get('to_custodian') or '（事件已删除）')}</td>"
                f"<td>{html.escape(h.get('from_name') or '—')}</td>"
                f"<td>{html.escape(h.get('to_name') or '—')}</td>"
                f"<td>{html.escape(HANDOVER_REASON_TEXT.get(h.get('reason'), h.get('reason') or '—'))}</td>"
                f"<td>{html.escape(h.get('invalidated_at') or '—')}</td></tr>"
            )
        history_html = (
            "<h2 style='margin-top:18px'>失效的历史确认（不再计入有效状态，需重新确认）</h2>"
            "<table>"
            "<tr><th>交出方</th><th>接收方</th><th>交出确认</th><th>接收确认</th>"
            "<th>失效原因</th><th>失效时间</th></tr>"
            f"{hist_rows}</table>"
        )

    return f"""
  <div class="card">
    <h2>双向交接确认</h2>
    <div class="hv-summary">
      共 {hs['total']} 个交接项：<b class="hv-confirmed">已确认 {hs['confirmed']}</b>、
      <span class="hv-pending">待确认 {hs['pending']}</span>、
      <span class="hv-time_mismatch">时间不一致 {hs['time_mismatch']}</span>；
      另有 <span class="hv-invalid">失效历史记录 {hs['invalidated']} 条</span>。
    </div>
    <table>
      <tr><th>#</th><th>交出方</th><th>交出结束时间</th><th>接收方</th>
          <th>接收开始时间</th><th>时间衔接</th><th>状态</th>
          <th>交出确认（姓名 / 时间）</th><th>接收确认（姓名 / 时间）</th></tr>
      {rows_html}
    </table>
    {history_html}
  </div>
"""


def build_json(
    sample: dict[str, Any],
    audit: dict[str, Any],
    signoffs: list[dict[str, Any]] | None = None,
    handovers: dict[str, Any] | None = None,
) -> str:
    return json.dumps(
        {
            "report": "样本交接链路审计报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sample": sample,
            "audit": audit,
            "signoffs": signoffs or [],
            "handovers": handovers or {"items": [], "history": [], "summary": {}},
        },
        ensure_ascii=False,
        indent=2,
    )
