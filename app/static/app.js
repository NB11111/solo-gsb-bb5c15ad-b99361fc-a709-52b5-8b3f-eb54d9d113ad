/* 样本交接链路审计 —— 前端逻辑（原生 JS，无框架） */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);

  const state = {
    samples: [],
    currentId: null,
    data: null, // { sample, events, audit, signoffs, handovers }
    editingId: null,
    viewSignoffId: null, // 当前弹窗中查看的签署快照 id
    confirmPair: null,   // 当前确认弹窗对应的交接项 { fromId, toId }
    view: "sample",      // 主区域当前视图：sample（样本详情）| queue（异常处置队列）
    queue: {
      filters: { status: "open", code: "", custodian: "", time_from: "", time_to: "" },
      data: null,        // 最近一次队列响应
      dispose: null,     // 当前处置弹窗目标 { fp, version, action }
    },
  };

  // ---------- 工具 ----------

  function toast(msg, isError = false) {
    const el = $("#toast");
    el.textContent = msg;
    el.className = "toast" + (isError ? " error" : "");
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (el.hidden = true), 2600);
  }

  async function api(path, options = {}) {
    const resp = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (resp.status === 204) return null;
    let payload = null;
    try {
      payload = await resp.json();
    } catch (_) {
      /* 非 JSON 响应 */
    }
    if (!resp.ok) {
      const err = new Error(extractError(payload) || `请求失败（${resp.status}）`);
      err.status = resp.status;
      throw err;
    }
    return payload;
  }

  function extractError(payload) {
    if (!payload) return "";
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return payload.detail
        .map((d) => {
          const field = d.loc && d.loc.length > 1 ? d.loc[d.loc.length - 1] : "";
          return field ? `【${field}】${d.msg}` : d.msg;
        })
        .join("；");
    }
    return payload.detail || "";
  }

  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);

  // 存储格式 "YYYY-MM-DD HH:MM:SS" -> datetime-local 格式
  const toLocalInput = (s) => (s ? s.replace(" ", "T").slice(0, 19) : "");

  // 当前本地时间 -> datetime-local 格式（签署时间默认值）
  const nowLocalInput = () => {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  };

  const STATUS_LABEL = { pass: "审计通过", warning: "通过 · 有告警", fail: "审计未通过", empty: "暂无数据" };
  const FINDING_LABEL = {
    gap: "断档", overlap: "重叠", reversed_interval: "起止倒置",
    out_of_order: "逆序录入", bad_time: "时间错误",
  };
  const SIGNOFF_STATUS_LABEL = { active: "已签署", revoked: "已撤销" };
  const HANDOVER_STATUS_LABEL = {
    confirmed: "已确认", pending: "待确认", time_mismatch: "时间不一致",
  };
  const HANDOVER_REASON_LABEL = {
    event_edited: "关联事件被编辑，绑定字段已变化",
    event_deleted: "关联事件已被删除",
    adjacency_changed: "两条记录不再相邻",
  };
  const FINDING_STATUS_LABEL = { open: "未处理", resolved: "已处理", eliminated: "已消除" };

  // ---------- 样本列表 ----------

  async function loadSamples(selectId = null) {
    state.samples = await api("/api/samples");
    const ul = $("#sample-list");
    if (!state.samples.length) {
      ul.innerHTML = `<li class="muted-cell" style="cursor:default">暂无样本，点击右上角新建</li>`;
    } else {
      ul.innerHTML = state.samples
        .map(
          (s) => `
        <li data-id="${s.id}" class="${s.id === state.currentId ? "active" : ""}">
          <div class="s-code">${esc(s.code)}</div>
          <div class="s-name">${esc(s.name)}</div>
          <span class="s-count">${s.event_count} 条交接</span>
        </li>`
        )
        .join("");
    }
    if (selectId) selectSample(selectId);
    else if (state.currentId && !state.samples.some((s) => s.id === state.currentId)) {
      state.currentId = null;
      showEmpty();
    }
    loadQueueBadge(); // 未处理数角标随样本 / 链路变化刷新
  }

  // 主区域视图切换：样本详情 <-> 异常处置队列（跨样本）
  function setView(view) {
    state.view = view;
    $("#btn-queue").classList.toggle("active", view === "queue");
    $("#queue-view").hidden = view !== "queue";
    if (view === "queue") {
      $("#detail").hidden = true;
      $("#empty-state").hidden = true;
      document
        .querySelectorAll("#sample-list li")
        .forEach((li) => li.classList.remove("active"));
    }
  }

  $("#sample-list").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-id]");
    if (li) selectSample(Number(li.dataset.id));
  });

  function showEmpty() {
    setView("sample");
    $("#detail").hidden = true;
    $("#empty-state").hidden = false;
  }

  async function selectSample(id) {
    try {
      state.currentId = id;
      state.data = await api(`/api/samples/${id}`);
      state.editingId = null;
      setView("sample");
      renderAll();
      $("#empty-state").hidden = true;
      $("#detail").hidden = false;
      document.querySelectorAll("#sample-list li").forEach((li) =>
        li.classList.toggle("active", Number(li.dataset.id) === id)
      );
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ---------- 渲染 ----------

  function renderAll() {
    renderSample();
    renderAudit();
    renderHandovers();
    renderTimeline();
    renderEvents();
    renderSignoffs();
    resetForm();
  }

  function renderSample() {
    const { sample } = state.data;
    $("#d-code").textContent = sample.code;
    $("#d-name").textContent = sample.name;
    $("#d-desc").textContent = sample.description || "（无描述）";
  }

  function renderAudit() {
    const { audit } = state.data;
    const badge = $("#audit-badge");
    badge.textContent = STATUS_LABEL[audit.status] || audit.status;
    badge.className = `badge badge-${audit.status}`;
    $("#audit-conclusion").textContent = audit.conclusion;

    const s = audit.summary;
    const stat = (num, lbl, cls = "") =>
      `<div class="stat ${cls}"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`;
    $("#audit-stats").innerHTML = [
      stat(s.total, "交接记录"),
      stat(s.gaps, "断档", s.gaps ? "bad" : ""),
      stat(s.overlaps, "重叠", s.overlaps ? "bad" : ""),
      stat(s.reversed, "起止倒置", s.reversed ? "bad" : ""),
      stat(s.out_of_order, "逆序录入", s.out_of_order ? "warn" : ""),
      stat(s.open_holds, "未归还", s.open_holds ? "warn" : ""),
    ].join("");

    const fl = $("#findings");
    if (!audit.findings.length) {
      fl.innerHTML = `<li class="muted-item">✓ 未发现断档、重叠或逆序问题。</li>`;
    } else {
      fl.innerHTML = audit.findings
        .map(
          (f, i) => `
        <li class="finding-${f.code}" data-ids="${(f.event_ids || []).join(",")}">
          <span class="tag">${FINDING_LABEL[f.code] || f.code}</span>
          <span>${esc(f.message)}</span>
        </li>`
        )
        .join("");
    }
  }

  function renderTimeline() {
    const tl = state.data.audit.timeline;
    const wrap = $("#timeline");
    if (!tl.bars.length) {
      wrap.innerHTML = `<div class="tl-empty">暂无交接事件，登记后将在此显示时间线。</div>`;
      return;
    }

    // 泳道
    const lanes = [];
    for (let i = 0; i < tl.lanes; i++) {
      lanes.push(`<div class="tl-lane"></div>`);
    }

    // 冲突区域贯穿所有泳道
    const zones = tl.zones
      .map(
        (z) => `
      <div class="tl-zone ${z.kind}" style="left:${z.left}%;width:${z.width}%"
           title="${z.kind === "gap" ? "保管断档" : "交接重叠"}：${esc(z.from)} ~ ${esc(z.to)}">
        ${z.kind === "gap" ? "断档" : "重叠"}
      </div>`
      )
      .join("");

    // 事件条
    const bars = tl.bars
      .map((b) => {
        const cls = ["tl-bar"];
        if (b.conflict) cls.push("conflict");
        if (b.open) cls.push("open");
        const tip = `${b.custodian}\n${b.start_label} ~ ${b.end_label}${
          b.conflict ? "\n⚠ 该事件涉及审计冲突" : ""
        }`;
        return `
        <div class="${cls.join(" ")}" data-eid="${b.id}"
             style="left:${b.left}%;width:${b.width}%;top:${b.lane * 42 + 6}px"
             title="${esc(tip)}">
          <span class="bar-id">#${b.id}</span>${esc(b.custodian)}${b.open ? " ◷" : ""}
        </div>`;
      })
      .join("");

    const ticks = tl.ticks
      .map((t) => `<span class="tl-tick" style="left:${t.left}%">${esc(t.label)}</span>`)
      .join("");

    wrap.innerHTML = `
      <div class="tl-scroll">
        <div class="tl-lanes" style="height:${tl.lanes * 42}px">
          <div class="tl-zones">${zones}</div>
          ${bars}
          ${lanes.join("")}
        </div>
        <div class="tl-axis">${ticks}</div>
        <div class="tl-range">时间范围：${esc(tl.start)} ~ ${esc(tl.end)}（仍在保管的事件以斜纹延伸显示）</div>
      </div>`;
  }

  function renderEvents() {
    const { audit } = state.data;
    const tbody = $("#event-tbody");
    if (!audit.events.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="muted-cell" style="text-align:center;padding:22px">暂无交接事件</td></tr>`;
      return;
    }
    tbody.innerHTML = audit.events
      .map((e, idx) => {
        const end = e.open
          ? `<span class="open-tag">仍在保管</span><div class="muted-cell">自 ${esc(e.start_time)} 起</div>`
          : esc(e.end_time);
        return `
        <tr class="${e.has_conflict ? "row-conflict" : ""}" data-eid="${e.id}">
          <td class="col-ord">${idx + 1}</td>
          <td class="col-seq">${e.seq}</td>
          <td>${e.has_conflict ? '<span class="conflict-flag">⚠</span>' : ""}${esc(e.custodian)}</td>
          <td>${esc(e.start_time)}</td>
          <td>${end}</td>
          <td>${esc(e.duration)}</td>
          <td>${esc(e.note || "—")}</td>
          <td>
            <button class="link-btn btn-edit" data-act="edit" data-id="${e.id}">编辑</button>
            <button class="link-btn btn-del" data-act="delete" data-id="${e.id}">删除</button>
          </td>
        </tr>`;
      })
      .join("");
  }

  // 点击审计发现 -> 高亮相关事件条与表格行
  $("#findings").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-ids]");
    if (!li) return;
    const ids = li.dataset.ids.split(",").filter(Boolean).map(Number);
    ids.forEach((id) => {
      document.querySelectorAll(`[data-eid="${id}"]`).forEach((el) => {
        el.style.outline = "2px solid #f59e0b";
        setTimeout(() => (el.style.outline = ""), 1800);
      });
    });
  });

  // ---------- 双向交接确认 ----------

  function renderHandovers() {
    const hv = state.data.handovers || { items: [], history: [], summary: {} };
    const s = hv.summary || {};
    $("#handover-stats").innerHTML = [
      statChip(s.total ?? 0, "交接项", ""),
      statChip(s.confirmed ?? 0, "已确认", "ok"),
      statChip(s.pending ?? 0, "待确认", "muted"),
      statChip(s.time_mismatch ?? 0, "时间不一致", "bad"),
      statChip(s.invalidated ?? 0, "失效历史", "warn"),
    ].join("");

    const tbody = $("#handover-tbody");
    if (!hv.items || !hv.items.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="muted-cell" style="text-align:center;padding:22px">至少需要两条按时间相邻的交接事件才会生成交接项</td></tr>`;
    } else {
      tbody.innerHTML = hv.items.map((item) => renderHandoverRow(item)).join("");
    }

    const historyWrap = $("#handover-history-wrap");
    if (hv.history && hv.history.length) {
      historyWrap.hidden = false;
      $("#handover-history-tbody").innerHTML = hv.history
        .map(
          (h) => `
        <tr class="row-invalid">
          <td>${esc(h.from_custodian || "（事件已删除）")}<div class="muted-cell">${esc(h.from_end_time || "—")}</div></td>
          <td>${esc(h.to_custodian || "（事件已删除）")}<div class="muted-cell">${esc(h.to_start_time || "—")}</div></td>
          <td>${h.from_name ? esc(h.from_name) + `<div class="muted-cell">${esc(h.from_confirmed_at)}</div>` : '<span class="muted-cell">—</span>'}</td>
          <td>${h.to_name ? esc(h.to_name) + `<div class="muted-cell">${esc(h.to_confirmed_at)}</div>` : '<span class="muted-cell">—</span>'}</td>
          <td>${esc(HANDOVER_REASON_LABEL[h.reason] || h.reason_text || h.reason)}</td>
          <td class="muted-cell">${esc(h.invalidated_at)}</td>
          <td><button class="link-btn btn-edit" data-ho-detail="${h.id}">查看记录</button></td>
        </tr>`
        )
        .join("");
    } else {
      historyWrap.hidden = true;
    }
  }

  function statChip(num, label, cls) {
    return `<span class="ho-stat ${cls}"><b>${num}</b> ${label}</span>`;
  }

  function renderHandoverRow(item) {
    const a = item.from_event;
    const b = item.to_event;
    const conf = item.confirmation;
    const badge =
      item.status === "confirmed"
        ? `<span class="badge badge-pass">已确认</span>`
        : item.status === "time_mismatch"
        ? `<span class="badge badge-fail">时间不一致</span>`
        : `<span class="badge badge-empty">待确认</span>`;

    const link = item.time_consistent
      ? `<span class="ho-link ok">结束 = 开始</span>`
      : `<span class="ho-link bad">结束 ≠ 开始</span>`;
    const at = a.end_time
      ? `${esc(a.end_time)}`
      : `<span class="open-tag">交出方仍在保管（无结束时间）</span>`;

    const sideCell = (name, time, role) =>
      name
        ? `<span class="ho-done">${esc(name)}</span><div class="muted-cell">${role} · ${esc(time)}</div>`
        : `<span class="muted-cell">${role}待确认</span>`;
    const fromSide = sideCell(conf?.from_name, conf?.from_confirmed_at, "交出");
    const toSide = sideCell(conf?.to_name, conf?.to_confirmed_at, "接收");

    const invalidHint = item.status === "time_mismatch"
      ? `<div class="muted-cell ho-hint">两侧已确认，但交出结束时间（${esc(a.end_time || "—")}）与接收开始时间（${esc(b.start_time)}）不一致，请核对后重新确认</div>`
      : item.status === "pending"
      ? `<div class="muted-cell ho-hint">${link}${conf ? "，尚有一侧未确认" : "，两侧均未确认"}</div>`
      : `<div class="muted-cell ho-hint">绑定摘要 <code class="digest">${esc(conf?.digest || "")}</code></div>`;

    return `
    <tr class="ho-row ho-${item.status}">
      <td class="col-ord">${item.index}</td>
      <td>${esc(a.custodian)}<div class="muted-cell">至 ${at}</div>${fromSide}</td>
      <td>${esc(b.custodian)}<div class="muted-cell">始于 ${esc(b.start_time)}</div>${toSide}</td>
      <td>${at}</td>
      <td>${badge}${invalidHint}</td>
      <td>
        <button class="link-btn btn-edit" data-ho-from="${a.id}" data-ho-to="${b.id}">
          ${conf ? "补充 / 重新确认" : "填写确认"}
        </button>
        ${conf ? `<button class="link-btn btn-edit" data-ho-detail="${conf.id}">查看记录</button>` : ""}
      </td>
    </tr>`;
  }

  // 打开确认弹窗
  $("#handover-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-ho-from]");
    if (!btn) return;
    const fromId = Number(btn.dataset.hoFrom);
    const toId = Number(btn.dataset.hoTo);
    openHandoverModal(fromId, toId);
  });

  function openHandoverModal(fromId, toId) {
    const hv = state.data.handovers;
    const item = hv.items.find(
      (i) => i.from_event.id === fromId && i.to_event.id === toId
    );
    if (!item) return;
    state.confirmPair = { fromId, toId };
    const a = item.from_event;
    const b = item.to_event;
    $("#handover-modal-body").innerHTML = `
      <div class="ho-modal-pair ${item.time_consistent ? "ok" : "bad"}">
        <div><span class="meta-lbl">交出方</span>${esc(a.custodian)}<div class="muted-cell">结束：${esc(a.end_time || "仍在保管")}</div></div>
        <div class="ho-arrow">→</div>
        <div><span class="meta-lbl">接收方</span>${esc(b.custodian)}<div class="muted-cell">开始：${esc(b.start_time)}</div></div>
      </div>
      <p class="muted-cell ho-modal-hint">
        ${item.time_consistent ? "交接时点一致。" : "交出结束时间与接收开始时间不一致，两侧确认后将标记为「时间不一致」。"}
        确认会绑定两条事件当前的经手人、起止时间与备注摘要；任一事件后续被编辑、删除或不再相邻时，原确认保留为失效记录并需重新确认。
      </p>`;
    $("#handover-form").reset();
    $("#ho-at").value = nowLocalInput();
    $("#handover-modal").hidden = false;
    $("#ho-name").focus();
  }

  const handoverModal = $("#handover-modal");
  $("#btn-close-handover").addEventListener("click", () => (handoverModal.hidden = true));
  handoverModal.addEventListener("click", (e) => {
    if (e.target === handoverModal) handoverModal.hidden = true;
  });

  $("#handover-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.confirmPair) return;
    const side = document.querySelector('input[name="ho-side"]:checked').value;
    const payload = {
      side,
      confirmer_name: $("#ho-name").value.trim(),
      confirmed_at: $("#ho-at").value,
    };
    if (!payload.confirmer_name || !payload.confirmed_at) {
      toast("请填写确认人姓名与确认时间", true);
      return;
    }
    try {
      const { fromId, toId } = state.confirmPair;
      const result = await api(
        `/api/samples/${state.currentId}/handovers/confirm?from_event_id=${fromId}&to_event_id=${toId}`,
        { method: "POST", body: JSON.stringify(payload) }
      );
      state.data.handovers = result.view;
      renderHandovers();
      const item = result.item;
      const otherDone =
        item.status === "confirmed" || item.status === "time_mismatch";
      toast(
        otherDone
          ? item.status === "confirmed"
            ? "两侧均已确认，交接项已确认 ✓"
            : "两侧均已确认，但交接时间不一致"
          : "确认已提交，等待另一侧确认"
      );
      if (otherDone) handoverModal.hidden = true;
    } catch (err) {
      toast(err.message, true);
    }
  });

  // 交接确认记录详情（含失效历史）
  async function openHandoverDetail(id) {
    try {
      const d = await api(`/api/handovers/${id}`);
      const snapA = d.from_event_snapshot || {};
      const snapB = d.to_event_snapshot || {};
      const badge =
        d.status === "active"
          ? `<span class="badge badge-pass">有效</span>`
          : `<span class="badge badge-fail">已失效</span>`;
      const invalid =
        d.status === "invalidated"
          ? `<div class="revoked-info">⚠ 该确认已于 <b>${esc(d.invalidated_at || "")}</b> 失效：
             ${esc(d.invalidated_reason_text || "")}。原记录保留备查，不再计入有效状态，需要两侧重新确认。</div>`
          : "";
      const sideRow = (title, name, at) => `
        <tr><th>${title}</th>
            <td>${name ? esc(name) : '<span class="muted-cell">待确认</span>'}</td>
            <td class="muted-cell">${at ? esc(at) : "—"}</td></tr>`;
      $("#handover-detail-body").innerHTML = `
        <div class="signoff-meta">
          <div><span class="meta-lbl">状态</span>${badge}</div>
          <div><span class="meta-lbl">绑定摘要</span><code class="digest">${esc(d.digest.slice(0, 12))}</code></div>
          <div><span class="meta-lbl">创建时间</span>${esc(d.created_at)}</div>
          <div><span class="meta-lbl">最近更新</span>${esc(d.updated_at)}</div>
        </div>
        <div class="signoff-section">
          <h4>双方确认</h4>
          <div class="table-wrap">
            <table class="event-table">
              <thead><tr><th>角色</th><th>确认人</th><th>确认时间</th></tr></thead>
              <tbody>
                ${sideRow("交出方（事件 #" + d.from_event_id + "）", d.from_name, d.from_confirmed_at)}
                ${sideRow("接收方（事件 #" + d.to_event_id + "）", d.to_name, d.to_confirmed_at)}
              </tbody>
            </table>
          </div>
        </div>
        <div class="signoff-section">
          <h4>确认时绑定的事件关键字段摘要</h4>
          <div class="table-wrap">
            <table class="event-table">
              <thead><tr><th>角色</th><th>经手人</th><th>起始时间</th><th>结束时间</th><th>备注</th></tr></thead>
              <tbody>
                <tr><td>交出方</td><td>${esc(snapA.custodian)}</td><td>${esc(snapA.start_time)}</td>
                    <td>${esc(snapA.end_time || "仍在保管")}</td><td>${esc(snapA.note || "—")}</td></tr>
                <tr><td>接收方</td><td>${esc(snapB.custodian)}</td><td>${esc(snapB.start_time)}</td>
                    <td>${esc(snapB.end_time || "仍在保管")}</td><td>${esc(snapB.note || "—")}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        ${invalid}`;
      $("#handover-detail-modal").hidden = false;
    } catch (err) {
      toast(err.message, true);
    }
  }

  $("#handover-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-ho-detail]");
    if (btn) openHandoverDetail(Number(btn.dataset.hoDetail));
  });
  $("#handover-history-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-ho-detail]");
    if (btn) openHandoverDetail(Number(btn.dataset.hoDetail));
  });
  const handoverDetailModal = $("#handover-detail-modal");
  $("#btn-close-handover-detail").addEventListener("click", () => (handoverDetailModal.hidden = true));
  handoverDetailModal.addEventListener("click", (e) => {
    if (e.target === handoverDetailModal) handoverDetailModal.hidden = true;
  });

  // ---------- 异常处置队列（跨样本） ----------

  async function loadQueueBadge() {
    try {
      const s = await api("/api/findings/summary");
      updateQueueBadge(s);
    } catch (_) {
      /* 角标刷新失败不阻塞主流程 */
    }
  }

  function updateQueueBadge(summary) {
    const badge = $("#queue-badge");
    const n = (summary && summary.open) || 0;
    badge.textContent = n > 99 ? "99+" : String(n);
    badge.hidden = n === 0;
  }

  $("#btn-queue").addEventListener("click", () => {
    setView("queue");
    loadQueue();
  });

  async function loadQueue() {
    const f = state.queue.filters;
    const params = new URLSearchParams();
    params.set("status", f.status);
    if (f.code) params.set("code", f.code);
    if (f.custodian) params.set("custodian", f.custodian);
    if (f.time_from) params.set("time_from", f.time_from);
    if (f.time_to) params.set("time_to", f.time_to);
    try {
      const data = await api(`/api/findings/queue?${params.toString()}`);
      state.queue.data = data;
      renderQueue();
      updateQueueBadge(data.summary);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderQueue() {
    const data = state.queue.data;
    if (!data) return;
    const s = data.summary || {};
    $("#queue-stats").innerHTML = [
      statChip(s.open ?? 0, "未处理", s.open ? "bad" : ""),
      statChip(s.resolved ?? 0, "已处理", "ok"),
      statChip(s.eliminated ?? 0, "已消除", "muted"),
      statChip(s.total ?? 0, "累计发现", ""),
    ].join("");
    $("#queue-synced").textContent = data.synced_at
      ? `已按当前链路重算 · ${data.synced_at}`
      : "";

    // 经手人候选（跨样本去重，由服务端返回）
    $("#q-custodian-list").innerHTML = (data.custodians || [])
      .map((c) => `<option value="${esc(c)}"></option>`)
      .join("");

    const tbody = $("#queue-tbody");
    if (!data.items.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="muted-cell" style="text-align:center;padding:22px">当前筛选条件下没有审计发现</td></tr>`;
      return;
    }
    tbody.innerHTML = data.items.map(renderQueueRow).join("");
  }

  function renderQueueRow(it) {
    const statusBadge =
      it.status === "open"
        ? `<span class="badge badge-fail">未处理</span>`
        : it.status === "resolved"
        ? `<span class="badge badge-pass">已处理</span>`
        : `<span class="badge badge-empty">已消除</span>`;
    const timeRange = `${esc(it.time_from || "—")}<div class="muted-cell">至 ${esc(
      it.time_to || "开放（仍在保管）"
    )}</div>`;
    const disposeInfo =
      it.status === "eliminated"
        ? `<span class="muted-cell">链路变更后消除</span><div class="muted-cell">${esc(
            it.eliminated_at || ""
          )}</div>`
        : it.handler
        ? `${esc(it.handler)}${
            it.note ? `<div class="muted-cell">${esc(it.note)}</div>` : ""
          }<div class="muted-cell">${esc(it.resolved_at || it.updated_at || "")}</div>`
        : `<span class="muted-cell">—</span>`;
    const actions = [];
    if (it.status === "open") {
      actions.push(
        `<button class="link-btn btn-edit" data-dispose="resolve" data-fp="${it.fingerprint}" data-ver="${it.version}">处置</button>`
      );
    } else if (it.status === "resolved") {
      actions.push(
        `<button class="link-btn btn-edit" data-dispose="reopen" data-fp="${it.fingerprint}" data-ver="${it.version}">重新打开</button>`
      );
    }
    actions.push(
      `<button class="link-btn btn-edit" data-history="${it.fingerprint}">迁移记录</button>`
    );
    const rowCls =
      it.status === "open" ? "row-conflict" : it.status === "eliminated" ? "row-invalid" : "";
    return `
      <tr class="${rowCls}">
        <td><div class="s-code">${esc(it.sample.code)}</div><div class="muted-cell">${esc(it.sample.name)}</div></td>
        <td><span class="finding-tag finding-tag-${esc(it.code)}">${esc(FINDING_LABEL[it.code] || it.code)}</span></td>
        <td>${esc(it.message)}<div class="muted-cell">指纹 <code class="digest">${esc(
          it.fingerprint.slice(0, 12)
        )}</code> · v${it.version}</div></td>
        <td>${it.custodians.map(esc).join("、") || "—"}</td>
        <td>${timeRange}</td>
        <td>${statusBadge}<div class="muted-cell">首次 ${esc(it.first_seen_at)}</div></td>
        <td>${disposeInfo}</td>
        <td style="white-space:nowrap">${actions.join("")}</td>
      </tr>`;
  }

  // 筛选表单
  $("#queue-filter-form").addEventListener("submit", (e) => {
    e.preventDefault();
    state.queue.filters = {
      status: $("#q-status").value,
      code: $("#q-code").value,
      custodian: $("#q-custodian").value.trim(),
      time_from: $("#q-from").value,
      time_to: $("#q-to").value,
    };
    loadQueue();
  });
  $("#btn-queue-reset").addEventListener("click", () => {
    $("#queue-filter-form").reset();
    $("#q-status").value = "open";
    state.queue.filters = { status: "open", code: "", custodian: "", time_from: "", time_to: "" };
    loadQueue();
  });
  $("#btn-queue-refresh").addEventListener("click", loadQueue);

  // 队列行操作：处置 / 重新打开 / 迁移记录
  $("#queue-tbody").addEventListener("click", (e) => {
    const disposeBtn = e.target.closest("button[data-dispose]");
    if (disposeBtn) {
      openDisposeModal(
        disposeBtn.dataset.fp,
        Number(disposeBtn.dataset.ver),
        disposeBtn.dataset.dispose
      );
      return;
    }
    const histBtn = e.target.closest("button[data-history]");
    if (histBtn) openFindingHistory(histBtn.dataset.history);
  });

  function openDisposeModal(fp, version, action) {
    const items = (state.queue.data && state.queue.data.items) || [];
    const it = items.find((x) => x.fingerprint === fp);
    if (!it) return;
    state.queue.dispose = { fp, version, action };
    $("#dispose-title").textContent =
      action === "resolve" ? "处置审计发现（标记已处理）" : "重新打开审计发现";
    $("#dispose-body").innerHTML = `
      <div class="dispose-finding">
        <div><span class="meta-lbl">样本</span>${esc(it.sample.code)} · ${esc(it.sample.name)}</div>
        <div><span class="meta-lbl">类型</span>${esc(FINDING_LABEL[it.code] || it.code)}</div>
        <div><span class="meta-lbl">发现</span>${esc(it.message)}</div>
        <div><span class="meta-lbl">指纹版本</span><code class="digest">${esc(
          it.fingerprint.slice(0, 12)
        )}</code> · v${it.version}</div>
      </div>
      <p class="muted-cell ho-modal-hint">提交时服务端将校验该指纹版本；若期间链路或状态已变化，将返回冲突并自动刷新队列。</p>`;
    $("#dp-submit").textContent = action === "resolve" ? "标记已处理" : "重新打开";
    $("#dispose-form").reset();
    $("#dispose-modal").hidden = false;
    $("#dp-handler").focus();
  }

  const disposeModal = $("#dispose-modal");
  $("#btn-close-dispose").addEventListener("click", () => (disposeModal.hidden = true));
  disposeModal.addEventListener("click", (e) => {
    if (e.target === disposeModal) disposeModal.hidden = true;
  });

  $("#dispose-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = state.queue.dispose;
    if (!d) return;
    const payload = {
      action: d.action,
      expected_version: d.version,
      handler: $("#dp-handler").value.trim(),
      note: $("#dp-note").value.trim(),
    };
    if (!payload.handler) {
      toast("请填写处置人", true);
      return;
    }
    try {
      await api(`/api/findings/${d.fp}/dispose`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      disposeModal.hidden = true;
      state.queue.dispose = null;
      toast(d.action === "resolve" ? "已标记为已处理" : "已重新打开，恢复为未处理");
      await loadQueue();
    } catch (err) {
      // 指纹版本过期 / 状态冲突：提示并刷新队列（过期请求返回冲突并刷新）
      if (err.status === 409 || err.status === 404) {
        disposeModal.hidden = true;
        state.queue.dispose = null;
        await loadQueue();
        toast(err.message, true);
      } else {
        toast(err.message, true);
      }
    }
  });

  // 状态迁移记录
  async function openFindingHistory(fp) {
    try {
      const d = await api(`/api/findings/${fp}`);
      const rows = (d.transitions || [])
        .map((t) => {
          const move = t.from_status
            ? `${FINDING_STATUS_LABEL[t.from_status] || t.from_status} → ${
                FINDING_STATUS_LABEL[t.to_status] || t.to_status
              }`
            : `首次出现（${FINDING_STATUS_LABEL[t.to_status] || t.to_status}）`;
          return `<tr>
            <td>${esc(t.created_at)}</td>
            <td>${esc(move)}</td>
            <td>${t.handler ? esc(t.handler) : '<span class="muted-cell">系统</span>'}</td>
            <td>${esc(t.note || "—")}</td>
          </tr>`;
        })
        .join("");
      $("#finding-history-body").innerHTML = `
        <div class="signoff-meta">
          <div><span class="meta-lbl">样本</span>${esc(d.sample.code)} · ${esc(d.sample.name)}</div>
          <div><span class="meta-lbl">异常类型</span>${esc(FINDING_LABEL[d.code] || d.code)}</div>
          <div><span class="meta-lbl">当前状态</span>${esc(
            FINDING_STATUS_LABEL[d.status] || d.status
          )}（v${d.version}）</div>
          <div><span class="meta-lbl">稳定指纹</span><code class="digest">${esc(d.fingerprint)}</code></div>
          <div><span class="meta-lbl">首次出现</span>${esc(d.first_seen_at)}</div>
          <div><span class="meta-lbl">最近出现</span>${esc(d.last_seen_at)}</div>
        </div>
        <p class="conclusion">${esc(d.message)}</p>
        <div class="table-wrap">
          <table class="event-table">
            <thead><tr><th>时间</th><th>状态迁移</th><th>操作人</th><th>备注</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
      $("#finding-history-modal").hidden = false;
    } catch (err) {
      toast(err.message, true);
    }
  }

  const findingHistoryModal = $("#finding-history-modal");
  $("#btn-close-finding-history").addEventListener(
    "click",
    () => (findingHistoryModal.hidden = true)
  );
  findingHistoryModal.addEventListener("click", (e) => {
    if (e.target === findingHistoryModal) findingHistoryModal.hidden = true;
  });

  // ---------- 事件增 / 改 / 删 ----------

  function resetForm() {
    $("#event-form").reset();
    $("#f-event-id").value = "";
    state.editingId = null;
    $("#btn-submit-event").textContent = "登记交接事件";
    $("#btn-cancel-edit").hidden = true;
  }

  $("#btn-cancel-edit").addEventListener("click", resetForm);

  $("#event-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      custodian: $("#f-custodian").value.trim(),
      start_time: $("#f-start").value,
      end_time: $("#f-end").value || null,
      note: $("#f-note").value.trim(),
    };
    if (!payload.custodian || !payload.start_time) {
      toast("请填写经手人与起始时间", true);
      return;
    }
    try {
      if (state.editingId) {
        await api(`/api/events/${state.editingId}`, { method: "PUT", body: JSON.stringify(payload) });
        toast("交接事件已更新");
      } else {
        await api(`/api/samples/${state.currentId}/events`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast("交接事件已登记");
      }
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#event-tbody").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const id = Number(btn.dataset.id);

    if (btn.dataset.act === "edit") {
      const ev = state.data.events.find((x) => x.id === id);
      if (!ev) return;
      state.editingId = id;
      $("#f-event-id").value = id;
      $("#f-custodian").value = ev.custodian;
      $("#f-start").value = toLocalInput(ev.start_time);
      $("#f-end").value = toLocalInput(ev.end_time);
      $("#f-note").value = ev.note || "";
      $("#btn-submit-event").textContent = "保存修改";
      $("#btn-cancel-edit").hidden = false;
      $("#f-custodian").scrollIntoView({ behavior: "smooth", block: "center" });
      $("#f-custodian").focus();
      return;
    }

    if (btn.dataset.act === "delete") {
      if (!confirm("确定删除这条交接事件？删除后将重新审计链路。")) return;
      try {
        await api(`/api/events/${id}`, { method: "DELETE" });
        toast("事件已删除");
        await refresh();
      } catch (err) {
        toast(err.message, true);
      }
    }
  });

  async function refresh() {
    await loadSamples(state.currentId); // 事件数更新
    if (state.currentId) {
      state.data = await api(`/api/samples/${state.currentId}`);
      renderAll();
    }
  }

  // ---------- 样本新建 / 删除 ----------

  const modal = $("#modal-mask");
  $("#btn-new-sample").addEventListener("click", () => {
    $("#sample-form").reset();
    modal.hidden = false;
    $("#s-code").focus();
  });
  $("#btn-cancel-sample").addEventListener("click", () => (modal.hidden = true));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.hidden = true;
  });

  $("#sample-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      code: $("#s-code").value.trim(),
      name: $("#s-name").value.trim(),
      description: $("#s-desc").value.trim(),
    };
    try {
      const created = await api("/api/samples", { method: "POST", body: JSON.stringify(payload) });
      modal.hidden = true;
      toast("样本已创建");
      await loadSamples(created.id);
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#btn-delete-sample").addEventListener("click", async () => {
    const { sample } = state.data;
    if (!confirm(`确定删除样本 ${sample.code} 及其全部交接事件？此操作不可恢复。`)) return;
    try {
      await api(`/api/samples/${state.currentId}`, { method: "DELETE" });
      toast("样本已删除");
      state.currentId = null;
      await loadSamples();
      showEmpty();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // ---------- 结论签署 ----------

  function renderSignoffs() {
    const signoffs = state.data.signoffs || [];
    // 签署时间默认填当前时间（不覆盖用户正在输入的值）
    if (!$("#g-signed-at").value) $("#g-signed-at").value = nowLocalInput();

    const tbody = $("#signoff-tbody");
    if (!signoffs.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="muted-cell" style="text-align:center;padding:18px">暂无签署记录，可在上方表单签署当前审计结论</td></tr>`;
      return;
    }
    tbody.innerHTML = signoffs
      .map((s, i) => {
        const badge =
          s.status === "active"
            ? `<span class="badge badge-pass">已签署</span>`
            : `<span class="badge badge-fail">已撤销</span>`;
        const revokeInfo =
          s.status === "revoked"
            ? `<div class="muted-cell">原因：${esc(s.revoke_reason || "—")}</div>`
            : "";
        const sum = s.summary || {};
        const brief =
          `${STATUS_LABEL[s.audit_status] || s.audit_status || "—"} · ` +
          `${s.event_count} 条事件 · 断档 ${sum.gaps ?? 0} · 重叠 ${sum.overlaps ?? 0}`;
        return `
        <tr>
          <td class="col-ord">${signoffs.length - i}</td>
          <td>${esc(s.signer)}${s.remark ? `<div class="muted-cell">${esc(s.remark)}</div>` : ""}</td>
          <td>${esc(s.signed_at)}</td>
          <td>${esc(brief)}</td>
          <td>${badge}${revokeInfo}</td>
          <td><code class="digest">${esc(s.digest)}</code></td>
          <td><button class="link-btn btn-edit" data-signoff="${s.id}">详情 / 撤销</button></td>
        </tr>`;
      })
      .join("");
  }

  $("#signoff-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      signer: $("#g-signer").value.trim(),
      signed_at: $("#g-signed-at").value,
      remark: $("#g-remark").value.trim(),
    };
    if (!payload.signer || !payload.signed_at) {
      toast("请填写签署人与签署时间", true);
      return;
    }
    try {
      await api(`/api/samples/${state.currentId}/signoffs`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast("已签署，快照已固化保存");
      $("#signoff-form").reset();
      $("#g-signed-at").value = nowLocalInput();
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // 打开快照详情弹窗
  $("#signoff-tbody").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-signoff]");
    if (!btn) return;
    try {
      const detail = await api(`/api/signoffs/${btn.dataset.signoff}`);
      state.viewSignoffId = detail.id;
      renderSignoffDetail(detail);
      $("#signoff-modal").hidden = false;
    } catch (err) {
      toast(err.message, true);
    }
  });

  function renderSignoffDetail(d) {
    const snap = d.snapshot || {};
    const sample = snap.sample || {};
    const audit = snap.audit || {};
    const events = audit.events || [];
    const findings = audit.findings || [];
    const sum = audit.summary || {};

    const statusBadge =
      d.status === "active"
        ? `<span class="badge badge-pass">已签署</span>`
        : `<span class="badge badge-fail">已撤销</span>`;
    const integrity = d.integrity_ok
      ? `<span class="integrity-ok">✓ 快照完整，未被篡改</span>`
      : `<span class="integrity-bad">✗ 快照校验不一致！</span>`;

    const findingItems = findings.length
      ? findings
          .map(
            (f) => `
          <li class="finding-${f.code}">
            <span class="tag">${FINDING_LABEL[f.code] || f.code}</span>
            <span>${esc(f.message)}</span>
          </li>`
          )
          .join("")
      : `<li class="muted-item">✓ 签署时未发现断档、重叠或逆序问题。</li>`;

    const eventRows = events.length
      ? events
          .map(
            (e, i) => `
          <tr class="${e.has_conflict ? "row-conflict" : ""}">
            <td class="col-ord">${i + 1}</td>
            <td class="col-seq">${e.seq}</td>
            <td>${e.has_conflict ? '<span class="conflict-flag">⚠</span>' : ""}${esc(e.custodian)}</td>
            <td>${esc(e.start_time)}</td>
            <td>${e.open ? '<span class="open-tag">仍在保管</span>' : esc(e.end_time)}</td>
            <td>${esc(e.duration)}</td>
            <td>${esc(e.note || "—")}</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="7" class="muted-cell" style="text-align:center">签署时暂无交接事件</td></tr>`;

    $("#signoff-detail").innerHTML = `
      <div class="signoff-meta">
        <div><span class="meta-lbl">状态</span>${statusBadge}</div>
        <div><span class="meta-lbl">签署人</span>${esc(d.signer)}</div>
        <div><span class="meta-lbl">签署时间</span>${esc(d.signed_at)}</div>
        <div><span class="meta-lbl">备注</span>${esc(d.remark || "—")}</div>
        <div><span class="meta-lbl">样本</span>${esc(sample.code || "")} · ${esc(sample.name || "")}</div>
        <div><span class="meta-lbl">快照校验值</span><code class="digest">${esc(d.digest)}</code> ${integrity}</div>
      </div>
      <div class="signoff-section">
        <h4>签署时审计结论（${STATUS_LABEL[audit.status] || audit.status || "—"}）</h4>
        <p class="conclusion">${esc(audit.conclusion || "")}</p>
        <div class="stats">
          <div class="stat"><div class="num">${sum.total ?? 0}</div><div class="lbl">交接记录</div></div>
          <div class="stat ${sum.gaps ? "bad" : ""}"><div class="num">${sum.gaps ?? 0}</div><div class="lbl">断档</div></div>
          <div class="stat ${sum.overlaps ? "bad" : ""}"><div class="num">${sum.overlaps ?? 0}</div><div class="lbl">重叠</div></div>
          <div class="stat ${sum.reversed ? "bad" : ""}"><div class="num">${sum.reversed ?? 0}</div><div class="lbl">起止倒置</div></div>
          <div class="stat ${sum.out_of_order ? "warn" : ""}"><div class="num">${sum.out_of_order ?? 0}</div><div class="lbl">逆序录入</div></div>
        </div>
        <ul class="findings">${findingItems}</ul>
      </div>
      <div class="signoff-section">
        <h4>签署时交接事件（共 ${events.length} 条，快照内容不随后续变更改写）</h4>
        <div class="table-wrap">
          <table class="event-table">
            <thead>
              <tr><th>排序#</th><th>录入序</th><th>经手人</th><th>起始时间</th><th>结束时间</th><th>时长</th><th>备注</th></tr>
            </thead>
            <tbody>${eventRows}</tbody>
          </table>
        </div>
      </div>`;

    // 撤销区：仅有效签署可撤销；已撤销的展示原因
    const active = d.status === "active";
    $("#revoke-zone").hidden = !active;
    $("#revoked-info").hidden = active;
    if (active) {
      $("#revoke-reason").value = "";
    } else {
      $("#revoked-info").innerHTML =
        `⚠ 该签署已于 <b>${esc(d.revoked_at || "")}</b> 撤销，原因：${esc(d.revoke_reason || "—")}。` +
        `原快照仍完整保留，仅供追溯。`;
    }
  }

  const signoffModal = $("#signoff-modal");
  $("#btn-close-signoff").addEventListener("click", () => (signoffModal.hidden = true));
  signoffModal.addEventListener("click", (e) => {
    if (e.target === signoffModal) signoffModal.hidden = true;
  });

  $("#btn-revoke").addEventListener("click", async () => {
    const reason = $("#revoke-reason").value.trim();
    if (!reason) {
      toast("请填写撤销原因", true);
      return;
    }
    if (!confirm("确定撤销该签署？撤销后原快照保留，但状态将标记为已撤销。")) return;
    try {
      await api(`/api/signoffs/${state.viewSignoffId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      toast("签署已撤销，原快照已保留");
      const detail = await api(`/api/signoffs/${state.viewSignoffId}`);
      renderSignoffDetail(detail);
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // ---------- 报告导出 ----------

  document.querySelectorAll("[data-export]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fmt = btn.dataset.export;
      const url = `/api/samples/${state.currentId}/report?format=${fmt}`;
      const a = document.createElement("a");
      a.href = url;
      a.download = "";
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
  });

  // ---------- 批量导入交接事件 ----------

  const importState = { token: null, preview: null, fileName: "" };

  const AUDIT_STATUS_LABEL = STATUS_LABEL;

  function statPill(num, label, cls = "") {
    return `<span class="ho-stat ${cls}"><b>${num}</b> ${label}</span>`;
  }

  function openImportModal() {
    $("#import-file").value = "";
    $("#import-summary").hidden = true;
    $("#import-preview-wrap").hidden = true;
    $("#import-audit-change").hidden = true;
    $("#import-result").hidden = true;
    $("#btn-confirm-import").disabled = true;
    importState.token = null;
    importState.preview = null;
    $("#import-modal").hidden = false;
  }

  $("#btn-bulk-import").addEventListener("click", openImportModal);

  $("#btn-download-template").addEventListener("click", () => {
    const a = document.createElement("a");
    a.href = `/api/samples/${state.currentId}/events/import-template`;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  });

  const importModal = $("#import-modal");
  $("#btn-close-import").addEventListener("click", () => (importModal.hidden = true));
  importModal.addEventListener("click", (e) => {
    if (e.target === importModal) importModal.hidden = true;
  });

  $("#btn-preview-import").addEventListener("click", async () => {
    const fileInput = $("#import-file");
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      toast("请先选择要导入的 UTF-8 CSV 文件", true);
      return;
    }
    try {
      const buf = await file.arrayBuffer();
      const resp = await fetch(
        `/api/samples/${state.currentId}/events/import-preview`,
        { method: "POST", body: buf }
      );
      const payload = await resp.json().catch(() => null);
      if (!resp.ok) throw new Error(extractError(payload) || `预览失败（${resp.status}）`);
      importState.preview = payload;
      importState.token = payload.token;
      importState.fileName = file.name;
      renderImportPreview(payload);
    } catch (err) {
      toast(err.message, true);
    }
  });

  function renderImportPreview(p) {
    // 汇总条
    const sumEl = $("#import-summary");
    const okCls = p.all_valid ? "ok" : "bad";
    sumEl.className = "import-summary " + (p.all_valid ? "import-ok" : "import-bad");
    sumEl.hidden = false;
    sumEl.innerHTML = `
      ${statPill(p.total_rows, "数据行", "")}
      ${statPill(p.valid_rows, "校验通过", p.all_valid && p.valid_rows ? "ok" : "muted")}
      ${statPill(p.invalid_rows, "校验错误", p.invalid_rows ? "bad" : "muted")}
      <span class="import-sum-msg">
        ${p.all_valid
          ? `全部行校验通过，录入序将按文件顺序分配为 <b>${p.rows[0].seq_preview} ~ ${p.rows[p.rows.length - 1].seq_preview}</b>`
          : "存在校验错误的行，无法导入；请修正文件后重新预览（预览不会写库）"}
      </span>`;

    // 逐行表格
    $("#import-preview-wrap").hidden = false;
    $("#import-preview-tbody").innerHTML = p.rows
      .map((r) => {
        const end = r.end_time ? esc(r.end_time) : '<span class="open-tag">仍在保管（留空）</span>';
        const result = r.errors.length
          ? `<ul class="import-err-list">${r.errors.map((m) => `<li>✗ ${esc(m)}</li>`).join("")}</ul>`
          : `<span class="import-ok-mark">✓ 校验通过</span>${
              r.in_conflict ? `<div class="import-conflict-hint">⚠ 导入后将卷入审计冲突（见下方结论变化）</div>` : ""
            }`;
        return `
        <tr class="${r.errors.length ? "import-row-err" : r.in_conflict ? "import-row-conflict" : ""}">
          <td class="col-ord">${r.line}</td>
          <td class="col-seq">${r.seq_preview ?? "—"}</td>
          <td>${esc(r.custodian || "（空）")}</td>
          <td>${esc(r.start_time || "（空）")}</td>
          <td>${end}</td>
          <td>${esc(r.note || "—")}</td>
          <td>${result}</td>
        </tr>`;
      })
      .join("");

    renderImportAuditChange(p);

    $("#import-result").hidden = true;
    $("#btn-confirm-import").disabled = !p.all_valid;
  }

  function renderImportAuditChange(p) {
    const el = $("#import-audit-change");
    el.hidden = false;
    const cur = p.current.audit;
    const proj = p.projected.audit;
    const curHs = p.current.handover_summary;
    const projHs = p.projected.handover_summary;
    const change = p.projected.handover_change;

    const delta = (a, b) => {
      const d = b - a;
      if (d > 0) return `<span class="import-delta up">+${d}</span>`;
      if (d < 0) return `<span class="import-delta down">${d}</span>`;
      return `<span class="import-delta flat">±0</span>`;
    };

    const findingsHtml = p.projected.new_findings.length
      ? `<div class="import-new-findings">
           <div class="import-sub-lbl">导入后涉及新行的审计发现：</div>
           <ul>${p.projected.new_findings
             .map((f) => `<li class="finding-${f.code}"><span class="tag">${esc(FINDING_LABEL[f.code] || f.code)}</span>${esc(f.message)}</li>`)
             .join("")}</ul>
         </div>`
      : `<div class="import-sub-lbl muted-cell">新行未引入断档 / 重叠 / 倒置发现。</div>`;

    const invalidHtml = change.newly_invalidated
      ? `<div class="import-invalid-warn">⚠ 导入后将有 <b>${change.newly_invalidated}</b> 条原交接确认因相邻关系变化失效（原记录保留，需两侧重新确认）</div>`
      : `<div class="import-sub-lbl muted-cell">现有交接确认不会因本次导入失效。</div>`;

    el.innerHTML = `
      <div class="import-sub-lbl">导入后审计结论变化（预览，不写库）：</div>
      <div class="import-compare">
        <div class="import-side">
          <div class="muted-cell">当前（${p.current.event_count} 条事件）</div>
          <span class="badge badge-${cur.status}">${esc(AUDIT_STATUS_LABEL[cur.status] || cur.status)}</span>
          <p class="import-conclusion">${esc(cur.conclusion)}</p>
          <div class="import-mini-stats">
            断档 ${cur.summary.gaps} · 重叠 ${cur.summary.overlaps} · 倒置 ${cur.summary.reversed} · 逆序 ${cur.summary.out_of_order}
          </div>
          <div class="import-mini-stats">交接确认：已确认 ${curHs.confirmed} / 待确认 ${curHs.pending} / 时间不一致 ${curHs.time_mismatch} / 失效 ${curHs.invalidated}</div>
        </div>
        <div class="import-arrow">➜</div>
        <div class="import-side">
          <div class="muted-cell">导入后（${p.projected.event_count} 条事件）</div>
          <span class="badge badge-${proj.status}">${esc(AUDIT_STATUS_LABEL[proj.status] || proj.status)}</span>
          <p class="import-conclusion">${esc(proj.conclusion)}</p>
          <div class="import-mini-stats">
            断档 ${proj.summary.gaps} ${delta(cur.summary.gaps, proj.summary.gaps)} ·
            重叠 ${proj.summary.overlaps} ${delta(cur.summary.overlaps, proj.summary.overlaps)} ·
            倒置 ${proj.summary.reversed} ${delta(cur.summary.reversed, proj.summary.reversed)} ·
            逆序 ${proj.summary.out_of_order} ${delta(cur.summary.out_of_order, proj.summary.out_of_order)}
          </div>
          <div class="import-mini-stats">交接确认：已确认 ${projHs.confirmed} / 待确认 ${projHs.pending} / 时间不一致 ${projHs.time_mismatch} / 失效 ${projHs.invalidated} ${delta(curHs.invalidated, projHs.invalidated)}</div>
        </div>
      </div>
      ${findingsHtml}
      ${invalidHtml}`;
  }

  $("#btn-confirm-import").addEventListener("click", async () => {
    if (!importState.token) {
      toast("请先完成预览", true);
      return;
    }
    const p = importState.preview;
    if (
      !confirm(
        `确认将 ${p.valid_rows} 行按文件顺序导入（录入序 ${p.rows[0].seq_preview} ~ ${
          p.rows[p.rows.length - 1].seq_preview
        }）？导入在单一事务内完成，任一失败全部回滚。`
      )
    )
      return;
    const btn = $("#btn-confirm-import");
    btn.disabled = true;
    try {
      const resp = await fetch(
        `/api/samples/${state.currentId}/events/import-confirm`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: importState.token }),
        }
      );
      const payload = await resp.json().catch(() => null);
      if (!resp.ok) {
        btn.disabled = false;
        throw new Error(extractError(payload) || `导入失败（${resp.status}）`);
      }
      renderImportResult(payload);
      importState.token = null; // 令牌一次性使用
      await refresh();
    } catch (err) {
      toast(err.message + "（数据未写入，请重新预览）", true);
      // 链路已变化时旧预览作废
      importState.token = null;
      $("#btn-confirm-import").disabled = true;
    }
  });

  function renderImportResult(res) {
    const el = $("#import-result");
    el.hidden = false;
    el.className = "import-result import-ok";
    const reasonText = {
      event_edited: "关联事件被编辑",
      event_deleted: "关联事件被删除",
      adjacency_changed: "事件不再相邻",
    };
    const invalidDetail = res.invalidated_confirmations
      ? `；另有 <b>${res.invalidated_confirmations}</b> 条原交接确认失效（${Object.entries(
          res.invalidation_reasons
        )
          .map(([k, v]) => `${reasonText[k] || k} ${v} 条`)
          .join("，")}），需两侧重新确认`
      : "";
    el.innerHTML = `
      ✓ 导入完成：成功写入 <b>${res.imported_count}</b> 条交接事件，
      录入序 <b>${res.first_seq} ~ ${res.last_seq}</b>${invalidDetail}。
      <div class="import-mini-stats">导入后审计结论：
        <span class="badge badge-${res.audit.status}">${esc(STATUS_LABEL[res.audit.status] || res.audit.status)}</span>
        ${esc(res.audit.conclusion)}
      </div>`;
    $("#btn-confirm-import").disabled = true;
  }

  // ---------- 启动 ----------

  (async function init() {
    try {
      await loadSamples();
      if (state.samples.length) await selectSample(state.samples[0].id);
      else showEmpty();
    } catch (err) {
      toast("初始化失败：" + err.message, true);
    }
  })();
})();
