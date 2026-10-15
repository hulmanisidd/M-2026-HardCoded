"use strict";
// Local-only mock mode: http://localhost:5500/webapp/static/index.html?mock=1
const LOCAL = ["localhost", "127.0.0.1"].includes(location.hostname);
const MOCK = LOCAL && new URLSearchParams(location.search).get("mock") === "1";
const ENABLE_FAIL = false; // set true once /api/analyze supports ?fail=true

const NS = "http://www.w3.org/2000/svg";
const W = 170, H = 46, GX = 250, GY = 110, PX = 40, PY = 50;
const VISUALS = ["confirmed", "stale", "unknown", "expired", "conditional", "inferred", "invalidated"];
const CRITS = ["critical", "high", "medium", "low", "unknown"];
const FEAS = ["feasible_under_model", "conditional", "blocked"];
const DASHED = ["stale", "unknown", "expired", "conditional"];
const pick = (v, allowed, dflt) => (allowed.includes(v) ? v : dflt);
const css = v => `var(--${v})`;
const $ = id => document.getElementById(id);

const svg = $("svg"), tipEl = $("tip"), stateEl = $("state");
let D = null, edgeEls = {}, nodeEls = {}, reqId = 0;

function el(tag, attrs = {}, parent = svg, text) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text != null) e.textContent = String(text);
  parent.appendChild(e);
  return e;
}
function div(cls, parent, text) {
  const d = document.createElement("div");
  if (cls) d.className = cls;
  if (text != null) d.textContent = text;
  parent.appendChild(d);
  return d;
}
function setTip(node, text) {
  node.addEventListener("mousemove", ev => {
    tipEl.textContent = text; tipEl.style.display = "block";
    tipEl.style.left = ev.clientX + 14 + "px"; tipEl.style.top = ev.clientY + 14 + "px";
  });
  node.addEventListener("mouseleave", () => { tipEl.style.display = "none"; });
}

function showState(msg, retry) {
  stateEl.replaceChildren();
  const p = document.createElement("div"); p.textContent = msg; stateEl.appendChild(p);
  if (retry) {
    const b = document.createElement("button"); b.type = "button"; b.textContent = "Try again";
    b.addEventListener("click", retry); stateEl.appendChild(b);
  }
  stateEl.hidden = false;
}
const hideState = () => { stateEl.hidden = true; };

function clearView() {
  svg.replaceChildren(); $("paths").replaceChildren();
  edgeEls = {}; nodeEls = {}; tipEl.style.display = "none";
}

function validate(d) {
  if (!d || !Array.isArray(d.nodes) || !Array.isArray(d.edges) || !Array.isArray(d.paths)) throw new Error("bad shape");
}

function render(data) {
  validate(data); D = data; clearView();
  $("ttl").textContent = "Attack-path graph" + (D.title ? " · " + String(D.title).replace(/_/g, " ") : "");
  const sub = $("sub");
  sub.textContent = "Synthetic AWS org · edges are possible paths under the model, not proof.";
  if (D.version) { sub.appendChild(document.createElement("br")); sub.appendChild(document.createTextNode("snapshot " + D.version)); }

  const byKey = new Map(D.nodes.map(n => [n.key, n]));
  const pos = n => ({ x: PX + (+n.col || 0) * GX, y: PY + (+n.row || 0) * GY });
  const maxX = PX + Math.max(0, ...D.nodes.map(n => +n.col || 0)) * GX + W + 40;
  const maxY = PY + Math.max(0, ...D.nodes.map(n => +n.row || 0)) * GY + H + 60;
  svg.setAttribute("viewBox", `0 0 ${maxX} ${maxY}`);
  svg.style.width = "100%"; svg.style.height = "100%";

  const defs = el("defs");
  VISUALS.forEach(s => {
    const m = el("marker", { id: "a-" + s, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
    el("path", { d: "M0 0L10 5L0 10z", fill: css("s-" + s) }, m);
  });

  D.edges.forEach(e => {
    const sn = byKey.get(e.src), dn = byKey.get(e.dst);
    if (!sn || !dn) return;
    const vis = pick(e.visual, VISUALS, "unknown");
    const a = pos(sn), b = pos(dn);
    const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2, dx = Math.max(60, (x2 - x1) / 2);
    const g = el("g");
    el("path", { d: `M${x1} ${y1}C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`, fill: "none", stroke: css("s-" + vis),
      "stroke-width": 2.4, "stroke-dasharray": DASHED.includes(vis) ? "7 5" : "none", "marker-end": `url(#a-${vis})` }, g);
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2 + (y1 === y2 ? -6 : 0);
    el("rect", { x: mx - 17, y: my - 9, width: 34, height: 17, rx: 8, fill: "var(--bg)", stroke: css("s-" + vis), "stroke-width": 1 }, g);
    el("text", { x: mx, y: my + 3.5, "text-anchor": "middle", "font-size": 10.5, fill: "var(--fg)" }, g, e.key);
    g.style.cursor = "help";
    let info = `${e.key}: ${sn.name} —${e.rel}→ ${dn.name}\nStatus: ${vis}`;
    if (e.conditions && Object.keys(e.conditions).length) info += `\nConditions: ${JSON.stringify(e.conditions)}`;
    if (e.valid_until) info += `\nValid until: ${String(e.valid_until).slice(0, 10)}`;
    setTip(g, info); edgeEls[e.key] = g;
  });

  D.nodes.forEach(n => {
    const p = pos(n), g = el("g"), crit = pick(n.crit, CRITS, "unknown");
    el("rect", { x: p.x, y: p.y, width: W, height: H, rx: 10, fill: "var(--card)", stroke: css("c-" + crit), "stroke-width": 3 }, g);
    el("text", { x: p.x + W / 2, y: p.y + 20, "text-anchor": "middle", "font-size": 13, "font-weight": 600, fill: "var(--fg)" }, g, n.name);
    el("text", { x: p.x + W / 2, y: p.y + 36, "text-anchor": "middle", "font-size": 10.5, fill: "var(--mut)" }, g, String(n.type).replace(/_/g, " ") + " · " + crit);
    setTip(g, `${n.name}\n${n.id}\nCriticality: ${crit}\nAccount: ${n.account || "?"}`);
    nodeEls[n.key] = g;
  });

  const pl = $("paths");
  D.paths.forEach((p, i) => {
    const first = D.edges.find(x => x.key === p.edges[0]), last = D.edges.find(x => x.key === p.edges[p.edges.length - 1]);
    if (!first || !last || !byKey.has(first.src) || !byKey.has(last.dst)) return;
    const d = div("path", pl), feas = pick(p.feasibility, FEAS, "blocked");
    d.tabIndex = 0;
    const badge = document.createElement("span"); badge.className = "badge b-" + feas;
    badge.textContent = feas.replace(/_under_model/, ""); d.appendChild(badge);
    const b1 = document.createElement("b"); b1.textContent = byKey.get(first.src).name; d.appendChild(b1);
    d.appendChild(document.createTextNode(" → "));
    const b2 = document.createElement("b"); b2.textContent = byKey.get(last.dst).name; d.appendChild(b2);
    d.appendChild(document.createElement("br"));
    const meta = document.createElement("span"); meta.className = "meta"; meta.textContent = p.edges.join(" → "); d.appendChild(meta);
    d.addEventListener("click", () => highlight(i));
    d.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); highlight(i); } });
  });
  if (!D.paths.length) { const p = document.createElement("p"); p.className = "sub"; p.textContent = "No attack paths found for this input."; pl.appendChild(p); }
}

function highlight(i) {
  document.querySelectorAll(".path").forEach((p, j) => p.classList.toggle("on", j === i));
  const all = i < 0, es = new Set(all ? [] : D.paths[i].edges), ns = new Set();
  es.forEach(k => { const e = D.edges.find(x => x.key === k); if (e) { ns.add(e.src); ns.add(e.dst); } });
  for (const k in edgeEls) edgeEls[k].classList.toggle("dim", !all && !es.has(k));
  for (const k in nodeEls) nodeEls[k].classList.toggle("dim", !all && !ns.has(k));
}

async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

async function load() {
  const name = $("scenario").value;
  if (!name) return;
  const my = ++reqId; // ignore out-of-order responses
  showState("Loading…");
  try {
    let data;
    if (MOCK) data = await getJSON("../../mock/analyze_demo.json");
    else {
      let url = "/api/analyze/" + encodeURIComponent(name);
      if (ENABLE_FAIL && $("fail").checked) url += "?fail=true";
      data = await getJSON(url);
    }
    if (my !== reqId) return;
    render(data); hideState();
  } catch (err) {
    if (my !== reqId) return;
    clearView();
    showState("Couldn't load this scenario. Please try again.", load);
  }
}

async function init() {
  const sel = $("scenario");
  showState("Loading scenarios…");
  try {
    const s = MOCK ? { scenarios: [{ name: "demo", label: "Demo (mock data)" }] } : await getJSON("/api/samples");
    if (!s || !Array.isArray(s.scenarios) || !s.scenarios.length) throw new Error("no scenarios");
    s.scenarios.forEach(x => { const o = document.createElement("option"); o.value = x.name; o.textContent = x.label || x.name; sel.appendChild(o); });
    sel.disabled = false;
    await load();
  } catch (err) {
    showState("Couldn't load scenarios. Please try again.", init);
  }
}

{
  $("scenario").addEventListener("change", load);
  $("fail").addEventListener("change", load);
  $("failRow").hidden = !ENABLE_FAIL;
  $("clear").addEventListener("click", () => { if (D) highlight(-1); });
}

function legend(id, items, build) {
  const c = $(id);
  items.forEach(([label, v]) => { const r = div("leg", c); build(r, v); r.appendChild(document.createTextNode(label)); });
}
legend("legE", [["confirmed", "confirmed"], ["stale (freshness window passed)", "stale"], ["unknown (collection failed)", "unknown"],
  ["expired (outside validity window)", "expired"], ["has unresolved conditions", "conditional"]], (r, v) => {
  const s = document.createElement("span"); s.className = "sw" + (DASHED.includes(v) ? " dashed" : ""); s.style.borderColor = css("s-" + v); r.appendChild(s);
});
legend("legN", [["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"]], (r, v) => {
  const s = document.createElement("span"); s.className = "dot"; s.style.background = css("c-" + v); r.appendChild(s);
});

init();