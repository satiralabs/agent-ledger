const $ = (s, r=document) => r.querySelector(s);
const trunc = h => h ? h.slice(0,6) + "…" + h.slice(-4) : "—";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const parseJson = (t, fallback={}) => { try { return t && t.trim() ? JSON.parse(t) : fallback; } catch { return {raw: t}; } };

async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  return {res, data};
}

// Tabs
$("#tabs").addEventListener("click", e => {
  const btn = e.target.closest(".tab"); if (!btn) return;
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t === btn));
  document.querySelectorAll(".screen").forEach(s => s.classList.toggle("active", s.id === "screen-" + btn.dataset.screen));
  if (btn.dataset.screen === "ledger") loadBlocks();
  if (btn.dataset.screen === "receipts") loadReceipts();
  if (btn.dataset.screen === "verify") loadVerify();
  if (btn.dataset.screen === "policy") loadPolicy();
});

async function loadStats() {
  const {data} = await api("/api/stats");
  $("#statBlocks").textContent = data.blocks ?? "–";
  $("#statAgents").textContent = data.agents ?? "–";
  $("#statChain").textContent = data.chain_status ?? "–";
  const last = data.last_block;
  $("#statLast").textContent = last ? "#" + last.index + " · " + last.agent_id : "No blocks yet";
  $("#statLast").title = last ? new Date(last.timestamp * 1000).toLocaleString() : "";
  const pill = $("#chainPill");
  pill.textContent = data.chain_status || "…";
  pill.className = "pill " + (data.chain_valid ? "pill-ok" : "pill-bad");
}
loadStats();

$("#logForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  const {res, data} = await api("/api/log", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({agent: f.get("agent"), tool: f.get("tool"), params: parseJson(f.get("params")),
      result: f.get("result") && f.get("result").trim() ? parseJson(f.get("result")) : null, approve: f.get("approve") === "on"})});
  $("#logMsg").textContent = data.blocked ? data.status + ": " + data.reason
    : res.ok ? "Recorded block #" + data.block_index + " (" + trunc(data.block_hash) + ")" : "Error";
  loadStats();
});

function blockCard(b) {
  const status = b.action_type === "policy_block" ? '<span class="pill pill-bad">blocked</span>'
    : b.action_type === "receipt" ? '<span class="pill pill-gold">receipt</span>' : "";
  return `<div class="block"><div class="block-head"><span class="pill pill-blue">#${b.index}</span>` +
    `<span class="pill">${esc(b.agent_id)}</span><span class="pill">${esc(b.action_type)}</span>${status}` +
    `<span class="hash" title="${esc(b.block_hash)}">${trunc(b.block_hash)}</span>` +
    `<span class="hash">${new Date(b.timestamp*1000).toLocaleString()}</span></div>` +
    `<p class="payload">${esc(JSON.stringify(b.payload)).slice(0, 280)}</p></div>`;
}

async function loadBlocks() {
  const f = new FormData($("#filterForm"));
  const qs = new URLSearchParams({agent: f.get("agent") || "", action: f.get("action") || "", limit: 100});
  const {data} = await api("/api/blocks?" + qs);
  $("#blockList").innerHTML = data.blocks && data.blocks.length
    ? data.blocks.map(blockCard).join("")
    : '<div class="empty">No blocks yet. <button class="primary" onclick="document.querySelector(\'[data-screen=dashboard]\').click()">Log the first action</button></div>';
}
$("#filterForm").addEventListener("submit", e => { e.preventDefault(); loadBlocks(); });

async function loadVerify() {
  const {data} = await api("/api/verify");
  $("#verifyStatus").textContent = data.chain_valid ? "VERIFIED" : "BROKEN";
  $("#verifyStatus").style.color = data.chain_valid ? "var(--ok)" : "var(--bad)";
  $("#verifyDetail").textContent = data.chain_valid
    ? data.count + " blocks · " + data.signatures_checked + " signatures checked" + (data.signatures_valid === false ? " · signature problem" : "")
    : (data.error || "Verification failed");
  const root = await api("/api/root");
  const el = $("#merkleRoot");
  el.textContent = root.data.root ? trunc(root.data.root) : "(empty ledger)";
  el.title = root.data.root || "";
}
$("#verifyBtn").addEventListener("click", loadVerify);

$("#receiptForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  const {res, data} = await api("/api/receipt", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({agent: f.get("agent"), prompt: f.get("prompt"), tool: f.get("tool"),
      model: f.get("model") || undefined, params: parseJson(f.get("params")), result: parseJson(f.get("result")),
      append: f.get("append") === "on"})});
  $("#receiptMsg").textContent = res.ok ? JSON.stringify(data, null, 2) : (data.error || "Error");
  loadReceipts(); loadStats();
});

async function loadReceipts() {
  const {data} = await api("/api/blocks?action=receipt&limit=50");
  $("#receiptList").innerHTML = data.blocks && data.blocks.length
    ? data.blocks.map(blockCard).join("")
    : '<div class="empty">No receipts yet.</div>';
}

async function loadPolicy() {
  const {data} = await api("/api/policy");
  const list = (arr, label) => `<div><b>${label}:</b> ${arr && arr.length ? arr.map(x => `<span class="pill">${esc(x)}</span>`).join(" ") : "—"}</div>`;
  $("#policyRules").innerHTML = '<div class="rules">' + list(data.blocked_tools, "Blocked tools") +
    list(data.prohibited_params, "Blocked patterns") + list(data.require_approval_for, "Needs approval") +
    `<div><b>Cost limit:</b> <span class="pill pill-gold">$${data.max_cost_usd} — above this needs approval</span></div></div>`;
}
$("#policyForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  const {data} = await api("/api/policy-check", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({tool: f.get("tool"), params: parseJson(f.get("params"))})});
  $("#policyMsg").textContent = data.status + ": " + data.reason;
});
