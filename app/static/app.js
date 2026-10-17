"use strict";
/* ReconForge dashboard. All data is inserted with textContent / text nodes, never innerHTML. */
const app = document.getElementById("app");
const ctx = document.body.dataset;

const SVG_NS = "http://www.w3.org/2000/svg";

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") el.style.cssText = v;   // CSSOM is allowed by our CSP; a style="" attribute set via setAttribute is blocked
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else if (k === "selected") el.selected = !!v;
    else if (k === "disabled") el.disabled = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(2)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function svgIcon(paths, size = 20) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("width", String(size));
  s.setAttribute("height", String(size));
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.75");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true");
  if (!paths) return s;
  const list = Array.isArray(paths) ? paths : [paths];
  for (const d of list) {
    if (!d) continue;
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", d);
    s.appendChild(p);
  }
  return s;
}

const ICONS = {
  overview: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M3 14h7v7H3z", "M14 14h7v7h-7z"],
  projects: ["M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"],
  scans: ["M22 12h-4l-3 9L9 3l-3 9H2"],
  assets: ["M12 2a10 10 0 100 20 10 10 0 000-20z", "M2 12h20", "M12 2a15 15 0 010 20 15 15 0 010-20z"],
  findings: ["M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z", "M12 9v4", "M12 17h.01"],
  tools: ["M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"],
  radar: ["M12 2a10 10 0 1010 10A10 10 0 0012 2zm0 18a8 8 0 118-8 8 8 0 01-8 8zm0-14a6 6 0 106 6 6 6 0 00-6-6zm0 8a2 2 0 112-2 2 2 0 01-2 2z"],
  target: ["M12 22a10 10 0 10-10-10 10 10 0 0010 10zm0-18a8 8 0 11-8 8 8 8 0 018-8zm0 14a6 6 0 10-6-6 6 6 0 006 6zm0-10a4 4 0 11-4 4 4 4 0 014-4zm0 6a2 2 0 10-2-2 2 2 0 002 2z"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
  terminal: ["M4 17l6-6-6-6", "M12 19h8"],
  clock: ["M12 22a10 10 0 100-20 10 10 0 000 20z", "M12 6v6l4 2"],
  copy: ["M8 4v12a2 2 0 002 2h8a2 2 0 002-2V7.5L16.5 4H10a2 2 0 00-2 2z", "M4 8v12a2 2 0 002 2h8"],
  check: ["M20 6L9 17l-5-5"],
  diff: ["M16 3h5v5", "M4 20L21 3", "M21 16v5h-5", "M15 15l6 6", "M4 4l5 5"],
  fileText: ["M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z", "M14 2v6h6", "M16 13H8", "M16 17H8", "M10 9H8"],
  play: ["M5 3l14 9-14 9V3z"],
  pause: ["M6 4h4v16H6z", "M14 4h4v16h-4z"],
  refresh: ["M23 4v6h-6", "M1 20v-6h6", "M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"],
  filter: ["M22 3H2l8 9.46V19l4 2v-8.54L22 3z"],
  alert: ["M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"]
};

function copyToClipboard(text, msg = "Copied to clipboard") {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast(msg)).catch(() => {
      prompt("Copy to clipboard:", text);
    });
  } else {
    prompt("Copy to clipboard:", text);
  }
}

function createTabs(tabDefs, defaultKey, onchange) {
  let active = defaultKey || (tabDefs[0] && tabDefs[0].key);
  const nav = h("div", { class: "tabs-nav", role: "tablist" });
  const container = h("div", { class: "tabs-container" });
  const buttons = {};
  const panes = {};

  function select(key) {
    active = key;
    for (const [k, btn] of Object.entries(buttons)) {
      const isSel = k === key;
      btn.classList.toggle("active", isSel);
      btn.setAttribute("aria-selected", isSel ? "true" : "false");
    }
    for (const [k, p] of Object.entries(panes)) {
      p.classList.toggle("active", k === key);
    }
    if (onchange) onchange(key);
  }

  tabDefs.forEach((t) => {
    const btn = h("button", {
      type: "button",
      class: "tab-btn" + (t.key === active ? " active" : ""),
      role: "tab",
      "aria-selected": t.key === active ? "true" : "false",
      onclick: () => select(t.key)
    },
      t.icon ? svgIcon(t.icon, 16) : null,
      h("span", {}, t.label),
      t.count !== undefined && t.count !== null ? h("span", { class: "tab-count" }, String(t.count)) : null
    );
    buttons[t.key] = btn;
    nav.append(btn);

    const pane = h("div", { class: "tab-pane" + (t.key === active ? " active" : ""), role: "tabpanel" }, t.pane || null);
    panes[t.key] = pane;
    container.append(pane);
  });

  return {
    nav,
    container,
    panes,
    buttons,
    select,
    get activeKey() { return active; },
    updateCount(key, count) {
      const btn = buttons[key];
      if (!btn) return;
      let countEl = btn.querySelector(".tab-count");
      if (count === undefined || count === null) {
        if (countEl) countEl.remove();
      } else {
        if (!countEl) {
          countEl = h("span", { class: "tab-count" });
          btn.append(countEl);
        }
        countEl.textContent = String(count);
      }
    }
  };
}

async function api(path, method = "GET", payload) {
  const opt = { method, headers: { "X-ReconForge": "1" } };
  if (payload !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(payload); }
  const r = await fetch(path, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) {
    let msg = data && data.detail;
    if (Array.isArray(msg)) msg = msg.map((x) => (x.loc ? x.loc.slice(1).join(".") + ": " : "") + x.msg).join("; ");
    throw new Error(msg || "Request failed (" + r.status + ")");
  }
  return data;
}

function toast(msg, err) {
  const t = document.getElementById("toast");
  const d = h("div", { class: err ? "err" : "" }, msg);
  t.append(d);
  setTimeout(() => d.remove(), err ? 9000 : 3500);
}

const attempt = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const fmtTime = (s) => (s ? new Date(s).toLocaleString() : "");

function ago(s) {
  if (!s) return "";
  const sec = Math.max(0, (Date.now() - new Date(s).getTime()) / 1000);
  if (sec < 90) return "just now";
  if (sec < 5400) return Math.round(sec / 60) + " min ago";
  if (sec < 172800) return Math.round(sec / 3600) + " h ago";
  return Math.round(sec / 86400) + " days ago";
}

const STATUS = {
  pending: "Waiting",
  running: "Running",
  completed: "Completed",
  empty: "Completed, nothing found",
  partial: "Partial results",
  failed: "Failed",
  missing_tool: "Tool missing",
  skipped: "Skipped",
  cached: "Cached",
  cancelled: "Cancelled",
  queued: "Queued",
  paused: "Paused",
  completed_with_issues: "Completed with issues"
};

const pill = (s) => h("span", { class: "pill s-" + s }, STATUS[s] || s);
const sev = (s) => h("span", { class: "sev sev-" + s }, s);
const VALID = {
  unvalidated: "Potential (unvalidated)",
  confirmed: "Confirmed by analyst",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed"
};
const link = (href, text) => h("a", { href }, text);

const empty = (msg, ...extra) => h(
  "div",
  { class: "empty" },
  svgIcon([
    "M12 2L3 6.5v5.5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6.5L12 2z",
    "M9 12h6"
  ], 28),
  h("p", {}, msg),
  ...extra
);

function pageHead(title, subtitleNode, ...actions) {
  return h(
    "div",
    { class: "page-head" },
    h(
      "div",
      { class: "page-head-titles" },
      h("h1", {}, title),
      subtitleNode ? (subtitleNode.nodeType ? subtitleNode : h("p", { class: "muted" }, subtitleNode)) : null
    ),
    actions.filter(Boolean).length ? h("div", { class: "page-head-actions" }, ...actions.filter(Boolean)) : null
  );
}

function table(heads, rows, opts = {}) {
  const t = h("table", {}, h("thead", {}, h("tr", {}, heads.map((x) => {
    const label = typeof x === "string" ? x : x.label;
    let cls = "";
    if (x && x.sort) {
      cls = "sortable";
      if (opts.sort === x.sort) cls += opts.order === "desc" ? " sort-desc" : " sort-asc";
    }
    const th = h("th", { class: cls }, label);
    if (x && x.sort && opts.onsort) th.addEventListener("click", () => opts.onsort(x.sort));
    return th;
  }))), h("tbody", {}, rows));
  return h("div", { class: "wrap" }, t);
}

const field = (label, input, hint) => h("div", {}, h("label", { class: "f" }, label), hint ? h("div", { class: "hint" }, hint) : null, input);
const check = (id, label, checked, hint) => h("label", { class: "chk" }, h("input", { type: "checkbox", id, checked }), h("span", {}, label, hint ? h("div", { class: "hint" }, hint) : null));
const val = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ shell controls */
const THEME_KEY = "reconforge_theme";
const PROJECT_KEY = "reconforge_active_project";
let cachedProjects = null;

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "dark" || mode === "light") {
    root.setAttribute("data-theme", mode);
  } else {
    root.removeAttribute("data-theme");
  }
  const lbl = document.getElementById("theme-label");
  if (lbl) {
    const nice = mode === "dark" ? "Dark" : mode === "light" ? "Light" : "Auto";
    lbl.textContent = "Theme: " + nice;
  }
}

function initThemeToggle() {
  const saved = localStorage.getItem(THEME_KEY) || "auto";
  applyTheme(saved);
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const cur = localStorage.getItem(THEME_KEY) || "auto";
    const next = cur === "auto" ? "dark" : cur === "dark" ? "light" : "auto";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  });
}

function initMobileNav() {
  const btn = document.getElementById("nav-toggle");
  const rail = document.getElementById("sidebar");
  if (!btn || !rail) return;
  btn.addEventListener("click", () => {
    const isOpen = rail.classList.toggle("open");
    btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
  });
}

async function getProjectsList(force = false) {
  if (!force && Array.isArray(cachedProjects)) return cachedProjects;
  cachedProjects = await api("/api/projects");
  return cachedProjects;
}

async function initTopbarProjectSwitcher() {
  const sel = document.getElementById("global-project-select");
  const scanBtn = document.getElementById("topbar-new-scan");
  if (!sel || !scanBtn) return;

  let ps = [];
  try {
    ps = await getProjectsList();
  } catch (e) {
    return;
  }

  clear(sel);
  if (!ps.length) {
    sel.append(h("option", { value: "" }, "No projects yet"));
    sel.disabled = true;
    scanBtn.disabled = true;
    scanBtn.title = "Create a project with authorised scope first";
    return;
  }

  sel.disabled = false;
  sel.append(h("option", { value: "" }, "Select project..."));
  ps.forEach((p) => {
    sel.append(h("option", { value: String(p.id) }, p.name));
  });

  // Determine current project from URL context or localStorage
  const activePid = ctx.pid || localStorage.getItem(PROJECT_KEY) || "";
  const validPid = ps.some((p) => String(p.id) === String(activePid)) ? String(activePid) : String(ps[0].id);

  if (validPid) {
    sel.value = validPid;
    localStorage.setItem(PROJECT_KEY, validPid);
  }

  function syncScanButton() {
    const chosen = ps.find((p) => String(p.id) === String(sel.value));
    if (!chosen) {
      scanBtn.disabled = true;
      scanBtn.title = "Select a project first";
    } else if (!chosen.scope_entries) {
      scanBtn.disabled = true;
      scanBtn.title = "Add an authorised scope entry to this project before scanning";
    } else {
      scanBtn.disabled = false;
      scanBtn.title = "Configure and start a scan for " + chosen.name;
    }
  }

  syncScanButton();

  sel.addEventListener("change", () => {
    const pid = sel.value;
    if (pid) {
      localStorage.setItem(PROJECT_KEY, pid);
      syncScanButton();
      if (ctx.page === "project") location.href = "/projects/" + pid;
      else if (ctx.page === "wizard") location.href = "/projects/" + pid + "/scan";
    } else {
      localStorage.removeItem(PROJECT_KEY);
      syncScanButton();
    }
  });

  scanBtn.addEventListener("click", () => {
    const pid = sel.value || localStorage.getItem(PROJECT_KEY);
    if (pid) location.href = "/projects/" + pid + "/scan";
  });
}

async function projectSelect(selected, onchange) {
  const ps = await getProjectsList();
  const initial = selected !== "" && selected !== undefined ? selected : "";
  return h("select", { onchange }, h("option", { value: "" }, "All projects"),
    ps.map((p) => h("option", { value: p.id, selected: String(p.id) === String(initial) }, p.name)));
}

/* ------------------------------------------------------------------ pages */
const pages = {};

function renderDonutChart(bySev, total) {
  const box = h("div", { class: "donut-chart-box" });
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 42 42");
  svg.setAttribute("width", "120");
  svg.setAttribute("height", "120");

  const bgCircle = document.createElementNS(SVG_NS, "circle");
  bgCircle.setAttribute("cx", "21");
  bgCircle.setAttribute("cy", "21");
  bgCircle.setAttribute("r", "15.91549430918954");
  bgCircle.setAttribute("fill", "transparent");
  bgCircle.setAttribute("stroke", "var(--line)");
  bgCircle.setAttribute("stroke-width", "5");
  svg.appendChild(bgCircle);

  const colors = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
    info: "var(--info)"
  };

  const order = ["critical", "high", "medium", "low", "info"];
  let offset = 25;

  if (total > 0) {
    for (const s of order) {
      const count = bySev[s] || 0;
      if (!count) continue;
      const pct = (count / total) * 100;
      const c = document.createElementNS(SVG_NS, "circle");
      c.setAttribute("cx", "21");
      c.setAttribute("cy", "21");
      c.setAttribute("r", "15.91549430918954");
      c.setAttribute("fill", "transparent");
      c.setAttribute("stroke", colors[s] || "var(--accent)");
      c.setAttribute("stroke-width", "5");
      c.setAttribute("stroke-dasharray", `${pct} ${100 - pct}`);
      c.setAttribute("stroke-dashoffset", String(offset));
      svg.appendChild(c);
      offset -= pct;
    }
  }

  box.appendChild(svg);
  box.appendChild(
    h("div", { class: "donut-center-metric" },
      h("span", { class: "donut-center-num" }, String(total)),
      h("span", { class: "donut-center-label" }, "Total")
    )
  );
  return box;
}

function renderOverviewRadarHUD(o, activePid) {
  const isScanning = (o.active_scans || 0) > 0;
  const projectName = (o.recent_scans && o.recent_scans.length) ? o.recent_scans[0].project : (activePid ? "Project #" + activePid : "Authorised Scope");

  const radarScreen = h("div", { class: "radar-screen" },
    h("div", { class: "radar-ring r1" }),
    h("div", { class: "radar-ring r2" }),
    h("div", { class: "radar-ring r3" }),
    h("div", { class: "radar-axis-x" }),
    h("div", { class: "radar-axis-y" }),
    h("div", { class: "radar-sweep " + (isScanning ? "active-sweep" : "standby-sweep") }),
    h("div", { class: "radar-blip b1" }),
    (o.assets > 0) ? h("div", { class: "radar-blip b2" }) : null,
    h("div", { class: "radar-blip b3" }),
    (o.open_findings > 0) ? h("div", { class: "radar-blip b4" }) : null
  );

  const statusText = isScanning
    ? "ACTIVE SURFACE RECON SCANNING"
    : "RADAR SURVEILLANCE STANDBY";

  const telemetry = h("div", { class: "radar-telemetry" },
    h("div", { class: "radar-telemetry-head" },
      h("div", { class: "bar", style: "margin:0" },
        h("span", { class: "radar-badge" + (isScanning ? " active" : "") },
          h("span", { class: "pulse-beacon" }),
          isScanning ? "RADAR SWEEP ACTIVE" : "TACTICAL RADAR ONLINE"
        ),
        h("span", { class: "radar-freq" }, "LOCAL-FIRST RECON ENGINE \u00B7 127.0.0.1")
      ),
      h("span", { class: "radar-status-text" }, statusText)
    ),
    h("div", { class: "radar-data-grid" },
      h("div", { class: "radar-data-item" },
        h("span", { class: "radar-data-label" }, "Target Scope"),
        h("span", { class: "radar-data-val mono" }, projectName)
      ),
      h("div", { class: "radar-data-item" },
        h("span", { class: "radar-data-label" }, "Discovered Assets"),
        h("span", { class: "radar-data-val" }, String(o.assets || 0) + " hosts")
      ),
      h("div", { class: "radar-data-item" },
        h("span", { class: "radar-data-label" }, "HTTP Endpoints"),
        h("span", { class: "radar-data-val" }, String(o.endpoints || 0) + " URLs")
      ),
      h("div", { class: "radar-data-item" },
        h("span", { class: "radar-data-label" }, "Conservative Ping"),
        h("span", { class: "radar-data-val" }, "2 req/s budget")
      ),
      h("div", { class: "radar-data-item" },
        h("span", { class: "radar-data-label" }, "Sensors"),
        h("span", { class: "radar-data-val" }, "11 Tool Adapters")
      )
    )
  );

  return h("div", { class: "radar-container" }, radarScreen, telemetry);
}

pages.overview = async () => {
  const o = await api("/api/overview");
  const total = o.open_findings || 0;
  const order = ["critical", "high", "medium", "low", "info"];
  const activePid = localStorage.getItem(PROJECT_KEY);

  // 1. Welcome Banner
  const banner = h("div", { class: "welcome-banner" },
    h("div", {},
      h("h1", { class: "welcome-title" }, "Welcome back, Security Researcher!"),
      h("p", { class: "welcome-subtitle" }, "Here's what's happening with your targets and security scans.")
    ),
    h("div", { class: "bar", style: "margin:0" },
      h("a", { class: "btn secondary", href: "/projects" }, svgIcon(ICONS.target, 14), "+ Add Target"),
      o.projects
        ? h("a", { class: "btn primary", href: activePid ? "/projects/" + activePid + "/scan" : "/projects" }, svgIcon(ICONS.play, 14), "New Scan")
        : null
    )
  );
  app.append(banner);

  if (!o.projects) {
    app.append(empty("No projects configured yet. Define an authorised target scope to begin reconnaissance.", h("p", {}, link("/projects", "Create your first project"))));
    return;
  }

  // Target URL for live scanning
  const liveScanHref = (o.recent_scans && o.recent_scans.length)
    ? "/scans/" + o.recent_scans[0].id
    : (activePid ? "/projects/" + activePid + "/scan" : "/scans");

  // 2. Row 1: 4 Top Stat KPI Cards (Clickable)
  const statCards = h("div", { class: "stat-grid-4" },
    h("a", { class: "stat-card clickable", href: "/projects", title: "View and manage targets & scopes" },
      h("div", { class: "stat-icon" }, svgIcon(ICONS.target, 22)),
      h("div", { class: "stat-info" },
        h("span", { class: "stat-value" }, String(o.projects || 0)),
        h("span", { class: "stat-label" }, "Total Targets")
      )
    ),
    h("a", { class: "stat-card clickable", href: "/assets", title: "View discovered subdomains and assets" },
      h("div", { class: "stat-icon" }, svgIcon(ICONS.assets, 22)),
      h("div", { class: "stat-info" },
        h("span", { class: "stat-value" }, String(o.assets || 0)),
        h("span", { class: "stat-label" }, "Subdomains & Assets")
      )
    ),
    h("a", { class: "stat-card clickable", href: "/assets", title: "View discovered HTTP endpoints" },
      h("div", { class: "stat-icon" }, svgIcon(ICONS.overview, 22)),
      h("div", { class: "stat-info" },
        h("span", { class: "stat-value" }, String(o.endpoints || 0)),
        h("span", { class: "stat-label" }, "HTTP Endpoints")
      )
    ),
    h("a", { class: "stat-card clickable", href: liveScanHref, title: "Open live scanning & execution matrix" },
      h("div", { class: "stat-icon" }, svgIcon(ICONS.scans, 22)),
      h("div", { class: "stat-info" },
        h("span", { class: "stat-value" }, o.active_scans ? String(o.active_scans) + " Active" : (o.assets ? "1 Live" : "0")),
        h("span", { class: "stat-label" }, "Live Scanning")
      )
    )
  );
  app.append(statCards);

  // 3. Row 2: 5 Severity Breakdown Cards (Clickable)
  const sevCards = h("div", { class: "sev-grid-5" },
    h("a", { class: "sev-card sev-total clickable", href: "/findings", title: "View all findings" },
      h("div", { class: "sev-card-label" }, h("span", { class: "sev-dot total" }), "Total Findings"),
      h("span", { class: "sev-card-val mono" }, String(total))
    ),
    h("a", { class: "sev-card sev-crit clickable", href: "/findings?severity=critical", title: "Filter Critical findings" },
      h("div", { class: "sev-card-label" }, h("span", { class: "sev-dot critical" }), "Critical"),
      h("span", { class: "sev-card-val mono", style: "color:var(--critical)" }, String(o.findings_by_severity.critical || 0))
    ),
    h("a", { class: "sev-card sev-high clickable", href: "/findings?severity=high", title: "Filter High findings" },
      h("div", { class: "sev-card-label" }, h("span", { class: "sev-dot high" }), "High"),
      h("span", { class: "sev-card-val mono", style: "color:var(--high)" }, String(o.findings_by_severity.high || 0))
    ),
    h("a", { class: "sev-card sev-med clickable", href: "/findings?severity=medium", title: "Filter Medium findings" },
      h("div", { class: "sev-card-label" }, h("span", { class: "sev-dot medium" }), "Medium"),
      h("span", { class: "sev-card-val mono", style: "color:var(--medium)" }, String(o.findings_by_severity.medium || 0))
    ),
    h("a", { class: "sev-card sev-low clickable", href: "/findings?severity=low", title: "Filter Low findings" },
      h("div", { class: "sev-card-label" }, h("span", { class: "sev-dot low" }), "Low"),
      h("span", { class: "sev-card-val mono", style: "color:var(--low)" }, String(o.findings_by_severity.low || 0))
    )
  );
  app.append(sevCards);

  // 4. Middle 3-Column Grid: Donut Chart | Radar HUD | Recent Activity
  const cardDonut = h("div", { class: "card" },
    h("div", { class: "card-header" },
      h("h3", { class: "card-title" }, svgIcon(ICONS.findings, 18), "Findings by Severity"),
      link("/findings", "View all \u2192")
    ),
    h("div", { class: "donut-container" },
      renderDonutChart(o.findings_by_severity, total),
      h("div", { class: "donut-legend" },
        order.map((s) => {
          const count = o.findings_by_severity[s] || 0;
          const pct = total ? Math.round((count / total) * 100) : 0;
          return h("a", { class: "donut-legend-item clickable-row", href: "/findings?severity=" + s, title: "Filter " + s + " findings" },
            h("div", { class: "donut-legend-left" },
              h("span", { class: "sev-dot " + s }),
              h("span", { style: "text-transform:capitalize" }, s)
            ),
            h("span", { class: "mono small" }, count + " (" + pct + "%)")
          );
        })
      )
    )
  );

  const cardRadar = h("div", { class: "card" },
    h("div", { class: "card-header" },
      h("h3", { class: "card-title" }, svgIcon(ICONS.radar, 18), "Radar & Surveillance HUD"),
      h("a", { class: "small", href: liveScanHref }, (o.active_scans || 0) > 0 ? "View live \u2192" : "Live scans \u2192")
    ),
    h("a", { class: "radar-wrap-link", href: liveScanHref, title: "Open live scanner & execution matrix" },
      renderOverviewRadarHUD(o, activePid)
    )
  );

  const recentScansList = o.recent_scans || [];
  const cardActivity = h("div", { class: "card" },
    h("div", { class: "card-header" },
      h("h3", { class: "card-title" }, svgIcon(ICONS.scans, 18), "Recent Activity"),
      link("/scans", "History \u2192")
    ),
    h("div", { class: "activity-feed" },
      recentScansList.length
        ? recentScansList.slice(0, 3).map((s) => h("a", { class: "activity-item clickable-row", href: "/scans/" + s.id, title: "Open scan #" + s.id },
            h("div", { class: "activity-icon-wrap" }, svgIcon(ICONS.radar, 14)),
            h("div", { class: "activity-content" },
              h("div", { class: "activity-title" }, "Scan #" + s.id + " (" + s.profile + ") - " + s.project),
              h("div", { class: "bar", style: "margin:2px 0" },
                pill(s.status),
                h("span", { class: "small muted" }, s.summary.assets ? s.summary.assets + " assets discovered" : "Pipeline complete")
              ),
              h("span", { class: "activity-time" }, ago(s.completed_at || s.created_at))
            )
          ))
        : h("a", { class: "activity-item clickable-row", href: "/projects", title: "View projects & scopes" },
            h("div", { class: "activity-icon-wrap" }, svgIcon(ICONS.projects, 14)),
            h("div", { class: "activity-content" },
              h("div", { class: "activity-title" }, "Target Scope Initialized"),
              h("span", { class: "activity-time" }, "Ready for automated assessment")
            )
          )
    )
  );

  app.append(h("div", { class: "dashboard-mid-grid" }, cardDonut, cardRadar, cardActivity));

  // 5. Bottom 2-Column Grid: Quick Actions | Next Up
  const cardQuickActions = h("div", { class: "card" },
    h("div", { class: "card-header" },
      h("h3", { class: "card-title" }, svgIcon(ICONS.terminal, 18), "Quick Actions"),
      h("span", { class: "chip" }, "Operations")
    ),
    h("div", { class: "quick-action-grid" },
      h("a", { class: "quick-action-btn", href: activePid ? "/projects/" + activePid + "/scan" : "/projects" },
        h("span", { class: "quick-action-btn-title" }, svgIcon(ICONS.play, 14), "Start Recon"),
        h("span", { class: "quick-action-btn-desc" }, "Launch passive asset discovery & DNS mapping.")
      ),
      h("a", { class: "quick-action-btn", href: activePid ? "/projects/" + activePid + "/scan" : "/projects" },
        h("span", { class: "quick-action-btn-title" }, svgIcon(ICONS.scans, 14), "Run Web Scan"),
        h("span", { class: "quick-action-btn-desc" }, "Probing with Nuclei exposure & misconfig tags.")
      ),
      h("a", { class: "quick-action-btn", href: "/findings" },
        h("span", { class: "quick-action-btn-title" }, svgIcon(ICONS.findings, 14), "View Findings"),
        h("span", { class: "quick-action-btn-desc" }, "Review potential detections requiring validation.")
      ),
      h("a", { class: "quick-action-btn", href: "/projects" },
        h("span", { class: "quick-action-btn-title" }, svgIcon(ICONS.projects, 14), "Manage Scopes"),
        h("span", { class: "quick-action-btn-desc" }, "Maintain authorized domain & IP boundaries.")
      )
    )
  );

  const cardNextUp = h("div", { class: "card" },
    h("div", { class: "card-header" },
      h("h3", { class: "card-title" }, svgIcon(ICONS.shield, 18), "Security Guidance & Next Up"),
      h("span", { class: "chip chip-safe" }, "Analyst Checklist")
    ),
    h("div", { class: "checklist-feed" },
      h("div", { class: "checklist-item" },
        svgIcon(ICONS.findings, 16),
        h("div", {},
          h("b", {}, "Review unvalidated scanner matches: "),
          h("span", {}, "Tools report potential findings. Confirm exploitability manually before reporting.")
        )
      ),
      h("div", { class: "checklist-item" },
        svgIcon(ICONS.projects, 16),
        h("div", {},
          h("b", {}, "Re-validate target boundaries: "),
          h("span", {}, "Always verify program authorizations and wildcard rules before launching active stages.")
        )
      ),
      h("div", { class: "checklist-item" },
        svgIcon(ICONS.tools, 16),
        h("div", {},
          h("b", {}, "Check local scanner health: "),
          h("span", {}, "Ensure Subfinder, Katana, and Nuclei are detected in PATH on Kali Linux.")
        )
      )
    )
  );

  app.append(h("div", { class: "dashboard-bottom-grid" }, cardQuickActions, cardNextUp));
};

pages.projects = async () => {
  const ps = await getProjectsList(true);
  app.append(
    pageHead(
      "Projects",
      "Each project defines an explicit authorised scope boundary and retains its own assets, findings, and scan history.",
      h("button", { class: "secondary", onclick: () => { const el = val("p-name"); if (el) el.focus(); } }, "New project")
    )
  );

  app.append(ps.length ? table(["Project", "Scope entries", "Assets", "Open findings", "Scans", "Created"], ps.map((p) => h("tr", {},
    h("td", {}, h("b", {}, link("/projects/" + p.id, p.name))),
    h("td", {}, p.scope_entries),
    h("td", {}, p.assets),
    h("td", {}, p.open_findings),
    h("td", {}, p.scans),
    h("td", { class: "muted" }, ago(p.created_at)))))
    : empty("No projects yet."));

  app.append(h("h2", {}, "New project"), h("div", { class: "panel" },
    h("div", { class: "grid2" },
      field("Name", h("input", { id: "p-name", type: "text", maxlength: 100, size: 40, placeholder: "e.g. Acme External Perimeter" })),
      field("Description", h("input", { id: "p-desc", type: "text", size: 60, placeholder: "Optional context or assessment reference" }))
    ),
    field("Authorised scope, one per line", h("textarea", { id: "p-scope", placeholder: "example.com\n*.example.com\n203.0.113.10" }),
      "example.com covers only that exact host. *.example.com covers its subdomains but not example.com itself. IP addresses and CIDR ranges must be listed explicitly. Nothing outside this list is ever tested."),
    field("Exclusions, one per line (optional)", h("textarea", { id: "p-excl", placeholder: "admin.example.com" })),
    check("p-auth", "I confirm I have permission to test every target listed above, and I will follow the program's rules and rate limits.", false),
    field("Where is the permission documented? (optional)", h("input", { id: "p-note", type: "text", size: 60, placeholder: "Bug bounty program URL, engagement ID" })),
    h("div", { class: "bar" }, h("button", { class: "primary", onclick: attempt(async () => {
      const split = (id) => val(id).value.split("\n").map((x) => x.trim()).filter(Boolean);
      const r = await api("/api/projects", "POST", { name: val("p-name").value.trim(), description: val("p-desc").value, scope: split("p-scope"), exclusions: split("p-excl"),
        authorization_confirmed: val("p-auth").checked, authorization_note: val("p-note").value });
      localStorage.setItem(PROJECT_KEY, String(r.id));
      location.href = "/projects/" + r.id;
    }) }, "Create project"))));
};

pages.project = async () => {
  localStorage.setItem(PROJECT_KEY, String(ctx.pid));
  const p = await api("/api/projects/" + ctx.pid);
  const reload = () => location.reload();
  const inc = p.scope.filter((e) => !e.excluded), exc = p.scope.filter((e) => e.excluded);

  app.append(
    pageHead(
      p.name,
      p.description || "Project authorised scope boundary and execution history.",
      inc.length
        ? h("a", { class: "btn primary", href: "/projects/" + p.id + "/scan" }, svgIcon(ICONS.play, 14), "New scan")
        : h("span", { class: "muted small" }, "Add an authorised scope entry to start a scan."),
      h("button", { class: "danger sm", onclick: attempt(async () => {
        if (confirm("Delete this project and all of its assets, findings and scan history?")) {
          await api("/api/projects/" + p.id, "DELETE");
          if (localStorage.getItem(PROJECT_KEY) === String(p.id)) localStorage.removeItem(PROJECT_KEY);
          location.href = "/projects";
        }
      }) }, "Delete project")
    )
  );

  // Project Quick Metric Cards
  app.append(
    h("div", { class: "card-grid" },
      [
        ["In-Scope Targets", inc.length, ICONS.target],
        ["Excluded Targets", exc.length, ICONS.filter],
        ["Discovered Assets", p.assets ?? 0, ICONS.assets],
        ["Open Findings", p.open_findings ?? 0, ICONS.findings],
        ["Completed Scans", p.scans ? p.scans.length : 0, ICONS.scans]
      ].map(([label, val, icon]) => h("div", { class: "stat-card" },
        h("div", { class: "stat-icon" }, svgIcon(icon, 20)),
        h("div", { class: "stat-info" },
          h("span", { class: "stat-value" }, String(val)),
          h("span", { class: "stat-label" }, label)
        )
      ))
    )
  );

  const row = (e) => h("tr", {},
    h("td", { class: "mono" }, e.display),
    h("td", {}, h("code", {}, e.kind)),
    h("td", {}, e.excluded
      ? h("span", { class: "pill s-cancelled" }, "excluded")
      : h("span", { class: "pill s-ok" }, "authorised " + ago(e.authorized_at))),
    h("td", { class: "muted" }, e.authorization_note || ""),
    h("td", {}, h("button", { class: "sm secondary", onclick: attempt(async () => { await api("/api/projects/" + p.id + "/scope/" + e.id, "DELETE"); reload(); }) }, "Remove")));

  // Scope Tab Pane
  const paneScope = h("div", {},
    p.scope.length ? table(["Entry", "Type", "State", "Permission note", ""], [...inc, ...exc].map(row)) : empty("No scope entries yet. Add domain or IP targets below."),
    h("div", { class: "card", style: "margin-top:var(--sp-4)" },
      h("div", { class: "card-header" },
        h("h3", { class: "card-title" }, svgIcon(ICONS.target, 18), "Add Authorised Target or Exclusion"),
        h("span", { class: "chip" }, "Permission Required")
      ),
      field("Target entries (one per line)", h("textarea", { id: "s-entries", placeholder: "sub.example.com\n198.51.100.0/24" })),
      check("s-excl", "These are exclusions (never tested or contacted)", false),
      check("s-auth", "I confirm I have permission to test every listed target.", false),
      field("Permission documentation note (optional)", h("input", { id: "s-note", type: "text", size: 50, placeholder: "e.g. Bug bounty policy link, assessment authorization ticket" })),
      h("div", { class: "bar" }, h("button", { class: "primary", onclick: attempt(async () => {
        await api("/api/projects/" + p.id + "/scope", "POST", { entries: val("s-entries").value.split("\n").map((x) => x.trim()).filter(Boolean), excluded: val("s-excl").checked,
          authorization_confirmed: val("s-auth").checked, authorization_note: val("s-note").value });
        reload();
      }) }, "Add target scope"))
    )
  );

  // Scans Tab Pane
  const paneScans = h("div", {},
    p.scans.length ? table(["Scan", "Profile", "Status", "Created", "Assets", "Findings"], p.scans.map((s) => h("tr", {},
      h("td", { class: "mono" }, link("/scans/" + s.id, "#" + s.id)),
      h("td", {}, s.profile),
      h("td", {}, pill(s.status)),
      h("td", { class: "muted" }, ago(s.created_at)),
      h("td", {}, s.summary.assets ?? ""),
      h("td", {}, s.summary.findings_by_severity ? Object.values(s.summary.findings_by_severity).reduce((a, b) => a + b, 0) : ""))))
      : empty("No scans yet for this project.", inc.length ? h("p", {}, link("/projects/" + p.id + "/scan", "Launch your first scan")) : null)
  );

  const tabs = createTabs([
    { key: "scope", label: "Scope & Boundaries", icon: ICONS.target, count: p.scope.length, pane: paneScope },
    { key: "scans", label: "Scan History", icon: ICONS.scans, count: p.scans.length, pane: paneScans }
  ], "scope");

  app.append(tabs.nav, tabs.container);
};

const PROFILE_INFO = {
  passive: ["Passive Recon", "Public sources only. Sends nothing to the target. Finds subdomains of wildcard entries and, if enabled, historical URLs."],
  standard: ["Standard Recon", "Adds DNS resolution, HTTP probing and port discovery. Sends DNS, HTTP and TCP traffic to authorised targets."],
  vulnerability: ["Vulnerability Assessment", "Standard Recon plus Nuclei template checks (non-intrusive templates only). Needs a separate confirmation."],
  web: ["Web Assessment", "Standard Recon plus crawling and Nuclei. Optional content discovery and ZAP. Needs a separate confirmation."],
};
const STAGE_LABEL = { subfinder: "Subfinder", gau: "gau", dnsx: "dnsx", httpx: "httpx", naabu: "Naabu", nmap: "Nmap", katana: "Katana", ffuf: "FFUF", testssl: "testssl.sh", zap: "ZAP", nuclei: "Nuclei", enrichment: "Provider enrichment" };
function planStages(profile, o) {
  const s = ["subfinder"]; if (o.enable_gau) s.push("gau");
  if (profile !== "passive") {
    s.push("dnsx", "httpx", "naabu"); if (o.enable_nmap) s.push("nmap"); if (profile === "web") s.push("katana"); if (o.enable_ffuf) s.push("ffuf");
    if (o.enable_testssl) s.push("testssl"); if (o.enable_zap) s.push("zap"); if (profile !== "standard") s.push("nuclei");
  }
  if (o.enable_enrichment) s.push("enrichment");
  return s;
}
pages.wizard = async () => {
  localStorage.setItem(PROJECT_KEY, String(ctx.pid));
  const [p, st] = await Promise.all([api("/api/projects/" + ctx.pid), api("/api/settings")]);
  const inc = p.scope.filter((e) => !e.excluded), exc = p.scope.filter((e) => e.excluded);
  const L = st.limits;

  app.append(
    pageHead(
      "New scan",
      h("p", { class: "muted" }, "Project: ", link("/projects/" + p.id, p.name)),
      h("a", { class: "btn secondary", href: "/projects/" + p.id }, "Back to project")
    )
  );

  const profileCards = Object.entries(PROFILE_INFO).map(([k, [name, desc]], i) => {
    const sendsTraffic = k !== "passive";
    return h(
      "label",
      { class: "profile-card" + (i === 0 ? " selected" : "") },
      h("input", { type: "radio", name: "profile", value: k, checked: i === 0, onchange: refresh }),
      h(
        "div",
        {},
        h(
          "div",
          { class: "bar", style: "margin:0 0 4px" },
          h("b", {}, name),
          h("span", { class: "pill " + (sendsTraffic ? "s-warn" : "s-ok") }, sendsTraffic ? "Sends traffic" : "No target traffic")
        ),
        h("div", { class: "hint" }, desc)
      )
    );
  });

  const trafficBanner = h("div", { class: "traffic-warn", style: "display:none" });

  const form = h("div", {},
    h("h2", {}, "1. Scope"),
    h("div", { class: "panel" },
      h("p", { class: "hint" }, "Only checked entries are tested. Exclusions below always apply."),
      inc.length
        ? h("div", { class: "grid2" }, inc.map((e) => h("label", { class: "chk" }, h("input", { type: "checkbox", class: "scope-pick", value: e.id, checked: true }), h("span", { class: "mono" }, e.display))))
        : h("p", { class: "muted small" }, "No authorised scope entries in this project."),
      exc.length ? h("p", { class: "small muted" }, "Project exclusions: " + exc.map((e) => e.display).join(", ")) : null,
      field("Extra exclusions for this scan (one per line)", h("textarea", { id: "w-excl", style: "min-height:60px", placeholder: "staging.example.com" }))
    ),

    h("h2", {}, "2. Profile"),
    h("div", { class: "panel" },
      h("div", { class: "profile-cards" }, profileCards),
      trafficBanner
    ),

    h("h2", {}, "3. Limits and modules"),
    h("div", { class: "panel" },
      h("div", { class: "grid2" },
        field("Requests per second", h("input", { id: "w-rps", type: "number", step: "0.5", min: "0.1", max: st.hard_max.requests_per_second, value: L.requests_per_second }), "Applied to httpx, Katana, Nuclei and FFUF."),
        field("Maximum assets", h("input", { id: "w-assets", type: "number", min: "1", max: st.hard_max.max_assets, value: L.max_assets })),
        field("Maximum duration (minutes)", h("input", { id: "w-mins", type: "number", min: "1", value: Math.round(L.max_scan_seconds / 60) })),
        field("Ports", h("select", { id: "w-ports" }, h("option", { value: "top100" }, "Top 100"), h("option", { value: "top1000" }, "Top 1000"), h("option", { value: "custom" }, "Custom list")), "Port discovery uses a TCP connect scan.")
      ),
      h("h3", {}, "Optional modules"),
      check("w-gau", "Historical URLs (gau). Queries public archives only.", false),
      check("w-nmap", "Service detection (Nmap) on discovered open ports", false, "Sends service-probe packets to open ports on the target."),
      check("w-testssl", "TLS assessment (testssl.sh)", false, "Connects to target TLS endpoints to enumerate ciphers and certificates."),
      check("w-enrich", "Provider enrichment (Shodan, urlscan.io). Sends in-scope hostnames and IPs to the providers you enabled in Settings.", false),
      check("w-ffuf", "Content discovery (FFUF, Web Assessment only)", false, "Actively fuzzes paths on target HTTP endpoints."),
      check("w-zap", "OWASP ZAP quick scan (Web Assessment only). Spiders and actively tests; this is intrusive and its request rate is not controlled by ReconForge.", false),

      h("details", {},
        h("summary", {}, "Advanced options (custom ports, crawl depth, cache, Nuclei filters, wordlists)"),
        h("div", { class: "grid2", style: "margin-top:10px" },
          field("Custom ports", h("input", { id: "w-cports", type: "text", placeholder: "80,443,8080-8090" })),
          field("Crawl depth", h("input", { id: "w-depth", type: "number", min: "1", max: "5", value: 2 }))
        ),
        check("w-cache", "Reuse recent passive discovery results (subdomains, historical URLs, DNS), up to " + L.cache_ttl_hours + " h old. Scan evidence is never reused.", true),
        check("w-resolved", "Allow port scanning IPs that in-scope hostnames resolve to, even if not listed in scope", false, "Leave this off for sites on hosting platforms (Vercel, Netlify, Cloudflare, GitHub Pages, cloud load balancers). The owner of the site can authorise testing the site, not scanning the platform's servers."),
        field("FFUF wordlist path", h("input", { id: "w-wl", type: "text", size: 50, placeholder: st.wordlist_dirs[0] ? st.wordlist_dirs[0] + "/common.txt" : "" }), "Must be inside: " + (st.wordlist_dirs.join(", ") || "no wordlist directory is configured")),
        field("Nuclei tags (comma separated)", h("input", { id: "w-tags", type: "text", value: "exposure,misconfig,takeover", size: 40 }), "An unfiltered Nuclei run is thousands of requests per URL. At 2 requests/second it will usually hit the tool timeout with nothing to show. This starting set is narrower; clear it to run everything and raise the per-tool timeout in Settings. List valid tags with: nuclei -tgl"),
        field("Nuclei severities", h("div", {}, ["info", "low", "medium", "high", "critical"].map((s) => h("label", { class: "chk", style: "display:inline-flex;margin-right:14px" }, h("input", { type: "checkbox", class: "w-sev", value: s, checked: s !== "info" }), sev(s)))))
      )
    ),

    h("h2", {}, "4. Stages that will run"),
    h("div", { class: "panel", id: "w-plan" }),

    h("h2", {}, "5. Confirm"),
    h("div", { class: "panel" },
      check("w-auth", "I confirm I have permission to test the selected scope and I will follow the program's rules.", false),
      h("div", { id: "w-active-box", class: "traffic-warn" },
        check("w-active", "I understand this profile sends active vulnerability checks to the target and I want to run them now.", false)
      ),
      h("div", { class: "bar" }, h("button", { class: "primary", onclick: attempt(submit) }, "Start scan"))
    )
  );

  app.append(form);

  const profile = () => document.querySelector("input[name=profile]:checked").value;
  const opts = () => ({ enable_gau: val("w-gau").checked, enable_nmap: val("w-nmap").checked, enable_testssl: val("w-testssl").checked, enable_ffuf: val("w-ffuf").checked, enable_zap: val("w-zap").checked, enable_enrichment: val("w-enrich").checked });

  function refresh() {
    const pr = profile(), o = opts();
    document.querySelectorAll(".profile-card").forEach((lbl) => {
      const inp = lbl.querySelector("input[name=profile]");
      lbl.classList.toggle("selected", !!(inp && inp.checked));
    });

    if (pr === "passive") {
      trafficBanner.style.display = "none";
      clear(trafficBanner);
    } else {
      trafficBanner.style.display = "";
      clear(trafficBanner).append(
        h("b", {}, "Active network traffic warning: "),
        pr === "standard"
          ? "Standard Recon sends direct DNS, HTTP, and TCP port-discovery packets to in-scope targets."
          : "This profile sends active reconnaissance and vulnerability assessment requests directly to in-scope targets. Ensure rate limits match your rules of engagement."
      );
    }

    val("w-active-box").style.display = pr === "vulnerability" || pr === "web" ? "" : "none";
    const planned = planStages(pr, o);
    clear(val("w-plan")).append(
      h("ol", { class: "ladder" }, planned.map((s, idx) => h(
        "li",
        { class: "pending" },
        h("span", { class: "n" }, idx + 1),
        h("div", {}, h("b", {}, STAGE_LABEL[s]), " ", h("code", {}, s)),
        h("div", {}, h("span", { class: "pill s-pending" }, "Planned"))
      ))),
      h("p", { class: "hint" }, "Stages that need a missing tool are reported as 'Tool missing' and skipped. Check Tool health first.")
    );
  }

  document.querySelectorAll("#app input[type=checkbox]").forEach((c) => c.addEventListener("change", refresh));
  refresh();

  async function submit() {
    const pr = profile(); const ports = val("w-ports").value === "custom" ? val("w-cports").value.trim() : val("w-ports").value;
    const body = { profile: pr, scope_entry_ids: [...document.querySelectorAll(".scope-pick:checked")].map((c) => Number(c.value)),
      extra_exclusions: val("w-excl").value.split("\n").map((x) => x.trim()).filter(Boolean), authorization_confirmed: val("w-auth").checked,
      active_testing_confirmed: val("w-active").checked && (pr === "vulnerability" || pr === "web"),
      options: { ...opts(), requests_per_second: Number(val("w-rps").value), max_assets: Number(val("w-assets").value), max_scan_seconds: Number(val("w-mins").value) * 60, ports,
        use_cache: val("w-cache").checked, allow_resolved_ips: val("w-resolved").checked, crawl_depth: Number(val("w-depth").value), ffuf_wordlist: val("w-wl").value.trim(),
        nuclei_tags: val("w-tags").value.trim(), nuclei_severity: [...document.querySelectorAll(".w-sev:checked")].map((c) => c.value) } };
    const r = await api("/api/projects/" + p.id + "/scans", "POST", body);
    location.href = "/scans/" + r.id;
  }
};

function renderCompare(box, c) {
  clear(box);
  const panel = h("div", { class: "panel" },
    h("h2", { style: "margin-top:0" }, "Scan #" + c.older_scan + " compared with #" + c.newer_scan),
    c.note ? h("div", { class: "notice" }, c.note) : null
  );
  const list = (title, items, fmt) => h("div", { class: "panel", style: "background:var(--panel2)" },
    h("h3", { style: "margin-top:0" }, title + " (" + items.length + ")"),
    items.length ? h("ul", { class: "mono small" }, items.slice(0, 200).map((i) => h("li", {}, fmt(i)))) : h("p", { class: "muted small" }, "None")
  );
  panel.append(
    h("div", { class: "grid2" },
      list("New assets", c.assets_new, (a) => a.kind + " " + a.value),
      list("Assets not seen again", c.assets_disappeared, (a) => a.kind + " " + a.value),
      list("New findings", c.findings_new, (f) => f.severity + ": " + f.title + " on " + f.asset),
      list("Findings not detected again", c.findings_not_detected, (f) => f.severity + ": " + f.title + " on " + f.asset)
    ),
    h("p", { class: "muted small" }, c.assets_unchanged + " assets and " + c.findings_unchanged + " findings appear in both. 'Not seen again' only means a scan did not observe it; it does not prove it was removed or fixed.")
  );
  box.append(panel);
}

function fmtDuration(startIso, endIso) {
  if (!startIso || !endIso) return "";
  const ms = Math.max(0, new Date(endIso).getTime() - new Date(startIso).getTime());
  const sec = Math.round(ms / 1000);
  if (sec < 60) return sec + "s";
  const m = Math.floor(sec / 60), rem = sec % 60;
  return m + "m " + rem + "s";
}

pages.scan = async () => {
  const sid = ctx.sid;
  const heroBox = h("div", {});
  const cmpBox = h("div", {});
  let matrixViewMode = "grid"; // "grid" | "ladder"

  // Tab Panes
  const paneMatrix = h("div", {});
  const paneResults = h("div", {});
  const paneRuns = h("div", {});
  const paneLogs = h("div", {});
  const paneCompare = h("div", {}, cmpBox);

  const tabs = createTabs([
    { key: "matrix", label: "Pipeline Matrix", icon: ICONS.radar, count: "0/0", pane: paneMatrix },
    { key: "results", label: "Findings & Results", icon: ICONS.shield, count: 0, pane: paneResults },
    { key: "runs", label: "Tool Runs", icon: ICONS.terminal, count: 0, pane: paneRuns },
    { key: "logs", label: "Execution Log", icon: ICONS.fileText, count: 0, pane: paneLogs },
    { key: "compare", label: "Comparison", icon: ICONS.diff, pane: paneCompare }
  ], "matrix");

  app.append(heroBox, tabs.nav, tabs.container);

  const act = (path, msg) => attempt(async () => {
    await api("/api/scans/" + sid + "/" + path, "POST");
    if (msg) toast(msg);
    load();
  });

  function renderRadarHUD(s, currentStage, active, sm, totalStages, doneStages) {
    const radarScreen = h("div", { class: "radar-screen" },
      h("div", { class: "radar-ring r1" }),
      h("div", { class: "radar-ring r2" }),
      h("div", { class: "radar-ring r3" }),
      h("div", { class: "radar-axis-x" }),
      h("div", { class: "radar-axis-y" }),
      h("div", { class: "radar-sweep " + (active ? "active-sweep" : "standby-sweep") }),
      h("div", { class: "radar-blip b1" }),
      h("div", { class: "radar-blip b2" }),
      h("div", { class: "radar-blip b3" }),
      (active || (sm.new_findings && sm.new_findings > 0)) ? h("div", { class: "radar-blip b4" }) : null
    );

    const scopeTarget = s.scope[0] || "Target Perimeter";
    const sweepStatus = active
      ? "ACTIVE 360° SURFACE SWEEP"
      : (s.status === "completed" ? "SWEEP COMPLETE - ALL TARGETS PROBED" : "RADAR STANDBY - " + (STATUS[s.status] || s.status).toUpperCase());

    const telemetry = h("div", { class: "radar-telemetry" },
      h("div", { class: "radar-telemetry-head" },
        h("div", { class: "bar", style: "margin:0" },
          h("span", { class: "radar-badge" + (active ? " active" : "") },
            active ? h("span", { class: "pulse-beacon" }) : null,
            active ? "RADAR SWEEP ACTIVE" : "RADAR STANDBY"
          ),
          h("span", { class: "radar-freq" }, "SECTOR SWEEP \u00B7 RECONFORGE RADAR")
        ),
        h("span", { class: "radar-status-text" }, sweepStatus)
      ),
      h("div", { class: "radar-data-grid" },
        h("div", { class: "radar-data-item" },
          h("span", { class: "radar-data-label" }, "Target Sector"),
          h("span", { class: "radar-data-val mono" }, scopeTarget + (s.scope.length > 1 ? " (+" + (s.scope.length - 1) + ")" : ""))
        ),
        h("div", { class: "radar-data-item" },
          h("span", { class: "radar-data-label" }, "Active Probe"),
          h("span", { class: "radar-data-val mono" }, currentStage ? currentStage.tool : "None")
        ),
        h("div", { class: "radar-data-item" },
          h("span", { class: "radar-data-label" }, "Discovered Targets"),
          h("span", { class: "radar-data-val" }, (sm.assets || 0) + " assets")
        ),
        h("div", { class: "radar-data-item" },
          h("span", { class: "radar-data-label" }, "Ping Rate"),
          h("span", { class: "radar-data-val" }, s.limits.requests_per_second + " req/s")
        ),
        h("div", { class: "radar-data-item" },
          h("span", { class: "radar-data-label" }, "Stage Coverage"),
          h("span", { class: "radar-data-val" }, doneStages + " / " + totalStages)
        )
      )
    );

    return h("div", { class: "radar-container" }, radarScreen, telemetry);
  }

  function renderMatrixCard(g, i, mr, isActiveScan) {
    const isRunning = g.status === "running";
    const dur = mr && mr.started_at && mr.completed_at
      ? fmtDuration(mr.started_at, mr.completed_at)
      : (g.duration_seconds ? Math.round(g.duration_seconds) + "s" : (isRunning ? "Running..." : ""));

    return h("div", { class: "matrix-card " + g.status },
      h("div", { class: "matrix-card-head" },
        h("div", { class: "matrix-card-title" },
          h("span", { class: "matrix-step-badge" + (isRunning ? " radar-active" : "") }, String(i + 1)),
          h("div", { style: "display:flex;flex-direction:column;gap:2px;min-width:0;flex:1" },
            h("div", { class: "bar", style: "margin:0;gap:6px;align-items:center" },
              h("span", { class: "matrix-tool-name" }, g.label),
              isRunning ? h("span", { class: "pulse-beacon" }) : null
            ),
            h("div", { class: "bar", style: "margin:0;gap:4px;align-items:center" },
              h("code", { class: "small" }, g.tool),
              dur ? h("span", { class: "mono small muted" }, " \u00B7 " + dur) : null
            )
          )
        ),
        pill(g.status)
      ),
      h("div", { class: "matrix-card-body" },
        h("div", { class: "matrix-chips" },
          g.touches_target
            ? h("span", { class: "chip chip-target", title: "Sends active traffic directly to target" }, svgIcon(ICONS.target, 12), "Contacts target")
            : h("span", { class: "chip chip-safe", title: "Passive public sources or local evaluation only" }, svgIcon(ICONS.shield, 12), "Passive / Safe"),
          (g.status === "completed" || g.status === "partial" || g.status === "cached") && g.items !== undefined && g.items !== null
            ? h("span", { class: "chip chip-items" }, "+" + g.items + (g.items === 1 ? " item" : " items"))
            : null,
          g.cached_from_scan
            ? h("span", { class: "chip", title: "Cached result" }, "from #" + g.cached_from_scan)
            : null
        ),
        h("div", { class: "matrix-card-msg" },
          g.message || g.traffic_note || "Stage queued for execution.",
          g.attempts > 1 ? " (Attempt " + g.attempts + ")" : ""
        )
      )
    );
  }

  async function load() {
    const [s, runs] = await Promise.all([
      api("/api/scans/" + sid),
      api("/api/scans/" + sid + "/runs")
    ]);
    if (s.project_id) localStorage.setItem(PROJECT_KEY, String(s.project_id));

    const active = ["queued", "running", "paused"].includes(s.status);
    const totalStages = s.stages.length || 1;
    const doneStages = s.stages.filter((g) => !["pending", "running"].includes(g.status)).length;
    const runningIdx = s.stages.findIndex((g) => g.status === "running");
    const currentStage = runningIdx >= 0 ? s.stages[runningIdx] : null;
    const pct = currentStage
      ? Math.min(98, Math.round(((doneStages + 0.5) / totalStages) * 100))
      : Math.round((doneStages / totalStages) * 100);

    const sm = s.summary || {};
    const sevs = sm.findings_by_severity || {};
    const totalFindings = sm.stage_status ? Object.values(sevs).reduce((a, b) => a + b, 0) : 0;

    // Actions
    const actions = [
      active && s.status !== "paused" ? h("button", { class: "secondary sm", onclick: act("pause", "Will pause before the next stage") }, svgIcon(ICONS.pause, 14), "Pause") : null,
      s.status === "paused" ? h("button", { class: "primary sm", onclick: act("resume") }, svgIcon(ICONS.play, 14), "Resume") : null,
      active ? h("button", { class: "danger sm", onclick: act("cancel") }, "Cancel") : null,
      !active ? h("button", { class: "secondary sm", onclick: act("retry", "Unfinished stages re-queued") }, svgIcon(ICONS.refresh, 14), "Retry unfinished") : null,
      !active ? h("a", { class: "btn secondary sm", href: "/scans/" + sid + "/report.html", target: "_blank", rel: "noopener" }, "HTML Report") : null,
      !active ? h("a", { class: "btn secondary sm", href: "/api/scans/" + sid + "/report.json" }, "JSON Report") : null
    ];

    const progressFill = h("div", { class: "scan-progress-fill" + (active ? " running" : "") });
    progressFill.style.setProperty("width", pct + "%");

    const statusHeadline = currentStage
      ? h("span", {}, h("span", { class: "pulse-beacon" }), "Stage " + (runningIdx + 1) + " of " + totalStages + ": ", h("b", {}, currentStage.label), " (", currentStage.tool, ")")
      : h("span", {}, doneStages + " of " + totalStages + " stages completed" + (s.completed_at && s.started_at ? " in " + fmtDuration(s.started_at, s.completed_at) : ""));

    clear(heroBox).append(
      h("div", { class: "scan-hero" + (active ? " is-running" : "") },
        h("div", { class: "scan-hero-top" },
          h("div", { class: "scan-hero-info" },
            h("h1", {}, "Scan #" + s.id + " ", pill(s.status)),
            h("div", { class: "scan-hero-meta" },
              link("/projects/" + s.project_id, s.project),
              h("span", {}, "\u00B7 Profile: ", h("b", {}, s.profile)),
              h("span", {}, "\u00B7 Created " + fmtTime(s.created_at)),
              s.completed_at ? h("span", {}, "\u00B7 Finished " + fmtTime(s.completed_at)) : null,
              s.started_at && !s.completed_at ? h("span", {}, "\u00B7 Started " + fmtTime(s.started_at)) : null
            )
          ),
          h("div", { class: "scan-hero-actions" }, ...actions.filter(Boolean))
        ),
        // Shimmer Animated Progress Bar
        h("div", { class: "scan-progress-wrap" },
          h("div", { class: "scan-progress-labels" },
            h("b", {}, statusHeadline),
            h("span", { class: "mono small muted" }, pct + "%")
          ),
          h("div", { class: "scan-progress-track" }, progressFill)
        ),
        // Real-Time KPI Bar
        h("div", { class: "scan-kpi-bar" },
          h("div", { class: "scan-kpi-item" }, h("span", { class: "label" }, "Active Phase"), h("span", { class: "val" }, currentStage ? currentStage.tool : s.status)),
          h("div", { class: "scan-kpi-item" }, h("span", { class: "label" }, "Discovered Assets"), h("span", { class: "val" }, String(sm.assets ?? 0))),
          h("div", { class: "scan-kpi-item" }, h("span", { class: "label" }, "Potential Findings"), h("span", { class: "val" }, String(totalFindings))),
          h("div", { class: "scan-kpi-item" }, h("span", { class: "label" }, "Target Rate Limit"), h("span", { class: "val" }, s.limits.requests_per_second + " req/s")),
          h("div", { class: "scan-kpi-item" }, h("span", { class: "label" }, "Max Assets"), h("span", { class: "val" }, String(s.limits.max_assets)))
        ),
        // Scope summary
        h("div", { class: "panel", style: "margin:var(--sp-3) 0 0;background:var(--panel2);padding:var(--sp-2) var(--sp-3)" },
          h("p", { class: "small", style: "margin:0" },
            h("b", {}, "Scope: "),
            s.scope.map((sc, idx) => h("span", {}, idx ? ", " : "", h("code", {}, sc))),
            s.exclusions.length ? h("span", {}, "   \u00B7   ", h("b", {}, "Exclusions: "), s.exclusions.map((ex, idx) => h("span", {}, idx ? ", " : "", h("code", {}, ex)))) : null
          )
        ),
        s.error ? h("div", { class: "notice bad" }, s.error) : null
      )
    );

    // Map tool runs by stage name
    const runByStage = {};
    runs.forEach((r) => { runByStage[r.stage_name] = r; });

    // Update Tab Counts
    tabs.updateCount("matrix", doneStages + "/" + totalStages);
    tabs.updateCount("results", totalFindings);
    tabs.updateCount("runs", runs.length);
    tabs.updateCount("logs", s.logs.length);

    // Render Tab 1: Progress Matrix
    function updateMatrixTab() {
      clear(paneMatrix);
      const radarHUD = renderRadarHUD(s, currentStage, active, sm, totalStages, doneStages);

      const toolbar = h("div", { class: "matrix-toolbar" },
        h("div", {},
          h("h2", { style: "margin:0" }, "Pipeline Progress Matrix"),
          h("p", { class: "muted small", style: "margin:2px 0 0" }, "Real-time execution status and parameters across all scanner stages.")
        ),
        h("div", { class: "bar", style: "margin:0" },
          h("button", {
            type: "button",
            class: "sm" + (matrixViewMode === "grid" ? " primary" : " secondary"),
            onclick: () => { matrixViewMode = "grid"; updateMatrixTab(); }
          }, "Matrix Cards"),
          h("button", {
            type: "button",
            class: "sm" + (matrixViewMode === "ladder" ? " primary" : " secondary"),
            onclick: () => { matrixViewMode = "ladder"; updateMatrixTab(); }
          }, "Linear Timeline")
        )
      );
      paneMatrix.append(radarHUD, toolbar);

      if (matrixViewMode === "grid") {
        const grid = h("div", { class: "matrix-grid" },
          s.stages.map((g, i) => {
            const mr = runByStage[g.name] || runByStage[g.tool];
            return renderMatrixCard(g, i, mr, active);
          })
        );
        paneMatrix.append(grid);
      } else {
        const ladderList = h("ol", { class: "ladder" }, s.stages.map((g, i) => {
          const mr = runByStage[g.name] || runByStage[g.tool];
          const dur = mr && mr.started_at && mr.completed_at ? fmtDuration(mr.started_at, mr.completed_at) : (g.duration_seconds ? Math.round(g.duration_seconds) + "s" : "");
          return h("li", { class: g.status },
            h("span", { class: "n" }, i + 1),
            h("div", {},
              g.status === "running" ? h("span", { class: "pulse-beacon" }) : null,
              h("b", {}, g.label), " ",
              h("code", {}, g.tool), " ",
              h("span", { class: "muted small" }, g.touches_target ? "\u00B7 contacts target" : "\u00B7 passive / safe"),
              dur ? h("span", { class: "mono small muted" }, " \u00B7 " + dur) : null
            ),
            h("div", {},
              pill(g.status),
              (g.status === "completed" || g.status === "partial" || g.status === "cached") && g.items !== undefined ? h("span", { class: "mono small" }, " " + g.items + " items") : ""
            ),
            h("div", { class: "msg" },
              g.message || g.traffic_note,
              g.cached_from_scan ? " (cached from #" + g.cached_from_scan + ", " + ago(g.cached_at) + ")" : "",
              g.attempts > 1 ? " \u00B7 Attempt " + g.attempts : ""
            )
          );
        }));
        paneMatrix.append(ladderList);
      }
    }
    updateMatrixTab();

    // Render Tab 2: Findings & Results
    clear(paneResults);
    paneResults.append(
      h("div", { class: "tiles" },
        [
          ["Assets seen", sm.assets ?? 0, ICONS.assets],
          ["New assets", sm.new_assets ?? 0, ICONS.target],
          ["Findings detected", totalFindings, ICONS.findings],
          ["New findings", sm.new_findings ?? 0, ICONS.shield],
          ["Rejected out-of-scope", sm.rejected_out_of_scope ?? 0, ICONS.filter]
        ].map(([k, v, icon]) => h("div", { class: "tile" },
          h("div", { class: "bar", style: "margin:0;justify-content:space-between" },
            h("span", {}, k),
            icon ? svgIcon(icon, 16) : null
          ),
          h("b", {}, v)
        ))
      )
    );

    const order = ["critical", "high", "medium", "low", "info"];
    if (totalFindings > 0) {
      const bar = h("div", { class: "sevbar" });
      order.filter((sevKey) => sevs[sevKey]).forEach((sevKey) => {
        const seg = h("i", { class: "i-" + sevKey, title: sevKey + ": " + sevs[sevKey] });
        seg.style.setProperty("width", (100 * sevs[sevKey] / totalFindings) + "%");
        bar.append(seg);
      });
      paneResults.append(
        h("div", { class: "panel" },
          h("h3", { style: "margin-top:0" }, "Findings by Severity"),
          bar,
          h("div", { class: "bar" },
            order.filter((sevKey) => sevs[sevKey]).map((sevKey) => h("span", {}, sev(sevKey), " ", h("b", {}, sevs[sevKey]))),
            h("span", { class: "grow" }),
            link("/findings?scan=" + sid, "Open full findings page \u2192")
          )
        )
      );
    } else {
      paneResults.append(
        h("div", { class: "panel" },
          h("p", { class: "muted" },
            active
              ? "Scanning in progress... Any detections will appear here in real time as scanner stages finish."
              : "No potential findings recorded for this scan. Detections depend on enabled checks and target response."
          )
        )
      );
    }

    // Discovered Findings List
    try {
      const scanFindings = await api("/api/findings?scan_id=" + sid);
      if (scanFindings.length) {
        paneResults.append(
          h("h3", {}, "Discovered Scanner Findings (" + scanFindings.length + ")"),
          h("p", { class: "muted small" }, "Matches are potential findings until validated by an analyst."),
          h("div", { class: "findings-list" },
            scanFindings.map((f) => h("div", { class: "finding-card sev-" + f.severity },
              h("div", { style: "display:flex;flex-direction:column;gap:4px" },
                h("div", { class: "bar", style: "margin:0" },
                  sev(f.severity),
                  h("b", {}, f.title),
                  h("span", { class: "muted small" }, "(" + (VALID[f.validation_status] || f.validation_status) + ")")
                ),
                h("div", { class: "small mono muted" },
                  f.asset, f.url ? " \u00B7 " + f.url : "", " \u00B7 Source: ", f.source, " / ", f.template_id
                )
              ),
              h("a", { class: "btn sm secondary", href: "/findings?open=" + f.id }, "Review")
            ))
          )
        );
      }
    } catch (e) { /* ignore */ }

    // Render Tab 3: Tool Runs
    clear(paneRuns);
    if (!runs.length) {
      paneRuns.append(empty("No tool execution runs recorded yet. Tool executions appear once a stage begins running."));
    } else {
      paneRuns.append(
        h("div", {},
          runs.map((r) => {
            const cmdStr = r.argv.join(" ");
            const dur = r.started_at && r.completed_at ? fmtDuration(r.started_at, r.completed_at) : "";
            const isOk = r.exit_code === 0;
            return h("div", { class: "run-card" },
              h("div", { class: "run-card-summary" },
                h("div", { class: "bar", style: "margin:0" },
                  h("b", { class: "mono" }, r.stage_name),
                  r.version ? h("span", { class: "chip" }, r.version) : null,
                  pill(r.status)
                ),
                h("div", { class: "bar", style: "margin:0" },
                  dur ? h("span", { class: "mono small muted" }, dur + " \u00B7 ") : null,
                  h("span", { class: "pill " + (isOk ? "s-ok" : "s-bad") }, "exit " + (r.exit_code === null ? "none" : r.exit_code)),
                  h("span", { class: "mono small muted" }, r.stdout_bytes + " bytes")
                )
              ),
              h("div", { class: "run-card-body" },
                h("div", {},
                  h("div", { class: "bar", style: "margin:0 0 var(--sp-1);justify-content:space-between" },
                    h("span", { class: "small muted" }, "Executed command line:"),
                    h("button", {
                      type: "button",
                      class: "sm secondary",
                      onclick: () => copyToClipboard(cmdStr, "Command copied to clipboard")
                    }, svgIcon(ICONS.copy, 12), "Copy command")
                  ),
                  h("div", { class: "terminal-box" },
                    h("span", { class: "cmd-tag" }, "$ "),
                    cmdStr
                  )
                ),
                r.error ? h("div", { class: "notice bad" }, "Error: " + r.error) : null,
                r.stderr_tail ? h("div", {},
                  h("p", { class: "small muted", style: "margin:4px 0" }, "Last error output (stderr):"),
                  h("pre", { class: "ev" }, r.stderr_tail)
                ) : null,
                h("details", {},
                  h("summary", {}, "First part of tool stdout (" + (r.stdout_bytes || 0) + " bytes)"),
                  h("pre", { class: "ev" }, r.stdout_head || "(no output)")
                )
              )
            );
          })
        )
      );
    }

    // Render Tab 4: Logs
    clear(paneLogs);
    let logFilter = "";
    let logAutoScroll = true;

    const logToolbar = h("div", { class: "log-toolbar" },
      h("div", { class: "bar", style: "margin:0" },
        h("span", { class: "small muted" }, "Lines: " + s.logs.length),
        h("input", {
          type: "search",
          placeholder: "Filter logs...",
          class: "sm",
          oninput: (e) => {
            logFilter = e.target.value.toLowerCase();
            renderLogLines();
          }
        })
      ),
      h("div", { class: "bar", style: "margin:0" },
        h("label", { class: "chk small", style: "margin:0" },
          h("input", {
            type: "checkbox",
            checked: true,
            onchange: (e) => { logAutoScroll = e.target.checked; }
          }),
          "Auto-scroll"
        ),
        h("button", {
          type: "button",
          class: "sm secondary",
          onclick: () => {
            const allText = s.logs.map((l) => l.ts + " " + l.level.toUpperCase() + " " + l.message).join("\n");
            copyToClipboard(allText, "Logs copied to clipboard");
          }
        }, svgIcon(ICONS.copy, 12), "Copy all")
      )
    );

    const logTerminal = h("pre", { class: "log-terminal" });

    function renderLogLines() {
      const filtered = logFilter
        ? s.logs.filter((l) => (l.message + " " + l.level).toLowerCase().includes(logFilter))
        : s.logs;
      logTerminal.textContent = filtered.length
        ? filtered.map((l) => l.ts.slice(11, 19) + " " + l.level.toUpperCase().padEnd(7) + l.message).join("\n")
        : (s.logs.length ? "No matching log entries." : "No log entries yet.");
      if (logAutoScroll) logTerminal.scrollTop = logTerminal.scrollHeight;
    }
    renderLogLines();

    paneLogs.append(logToolbar, logTerminal);

    // Render Tab 5: Comparison
    clear(paneCompare);
    const compareCard = h("div", { class: "panel" },
      h("div", { class: "bar", style: "margin-top:0;justify-content:space-between" },
        h("div", {},
          h("h3", { style: "margin:0" }, "Scan Comparison"),
          h("p", { class: "muted small", style: "margin:2px 0 0" }, "Compare this scan with the previous scan of the same project to inspect asset and finding diffs.")
        ),
        !active ? h("button", {
          class: "primary sm",
          onclick: attempt(async () => {
            renderCompare(cmpBox, await api("/api/scans/" + sid + "/compare"));
          })
        }, svgIcon(ICONS.diff, 14), "Run Comparison") : null
      ),
      cmpBox
    );
    paneCompare.append(compareCard);

    if (active) setTimeout(load, 2000);
  }

  await load();
};

pages.scans = async () => {
  const sel = await projectSelect("", () => load());
  const box = h("div", {}), cmp = h("div", {});
  app.append(h("h1", {}, "Scan history"), h("div", { class: "bar" }, sel), box, cmp);
  async function load() {
    const rows = await api("/api/scans" + (sel.value ? "?project_id=" + sel.value : ""));
    clear(box).append(rows.length ? table(["Scan", "Project", "Profile", "Status", "Created", "Assets", "New assets", "Findings", "New findings", ""], rows.map((s) => {
      const sm = s.summary || {}, sevs = sm.findings_by_severity || {};
      return h("tr", {}, h("td", {}, link("/scans/" + s.id, "#" + s.id)), h("td", {}, s.project), h("td", {}, s.profile), h("td", {}, pill(s.status)), h("td", {}, fmtTime(s.created_at)),
        h("td", {}, sm.assets ?? ""), h("td", {}, sm.new_assets ?? ""), h("td", {}, sm.stage_status ? Object.values(sevs).reduce((a, b) => a + b, 0) : ""), h("td", {}, sm.new_findings ?? ""),
        h("td", {}, ["completed", "completed_with_issues"].includes(s.status) ? h("button", { onclick: attempt(async () => renderCompare(cmp, await api("/api/scans/" + s.id + "/compare"))) }, "Compare with previous") : ""));
    })) : empty("No scans have been run yet."));
  }
  await load();
};

pages.scans = async () => {
  const sel = await projectSelect("", () => load());
  const box = h("div", {}), cmp = h("div", {});
  const activePid = localStorage.getItem(PROJECT_KEY);

  app.append(
    pageHead(
      "Scan history",
      "All completed, running, and queued scan runs across your projects.",
      activePid ? h("a", { class: "btn primary", href: "/projects/" + activePid + "/scan" }, "New scan") : null
    ),
    h("div", { class: "bar" }, h("span", { class: "muted small" }, "Filter by project:"), sel),
    box,
    cmp
  );

  async function load() {
    const rows = await api("/api/scans" + (sel.value ? "?project_id=" + sel.value : ""));
    clear(box).append(rows.length ? table(["Scan", "Project", "Profile", "Status", "Created", "Assets", "New assets", "Findings", "New findings", ""], rows.map((s) => {
      const sm = s.summary || {}, sevs = sm.findings_by_severity || {};
      return h("tr", {},
        h("td", { class: "mono" }, link("/scans/" + s.id, "#" + s.id)),
        h("td", {}, s.project_id ? link("/projects/" + s.project_id, s.project) : s.project),
        h("td", {}, s.profile),
        h("td", {}, pill(s.status)),
        h("td", { class: "muted" }, fmtTime(s.created_at)),
        h("td", {}, sm.assets ?? ""),
        h("td", {}, sm.new_assets ?? ""),
        h("td", {}, sm.stage_status ? Object.values(sevs).reduce((a, b) => a + b, 0) : ""),
        h("td", {}, sm.new_findings ?? ""),
        h("td", {}, ["completed", "completed_with_issues"].includes(s.status)
          ? h("button", { class: "sm secondary", onclick: attempt(async () => { renderCompare(cmp, await api("/api/scans/" + s.id + "/compare")); cmp.scrollIntoView(); }) }, "Compare with previous")
          : "")
      );
    })) : empty("No scans have been run yet."));
  }
  await load();
};

pages.assets = async () => {
  const state = { sort: "value", order: "asc", activeId: null };
  const sel = await projectSelect("", () => load());
  const kind = h("select", { onchange: () => load() },
    h("option", { value: "" }, "All types"),
    h("option", { value: "domain" }, "Domains"),
    h("option", { value: "ip" }, "IP addresses")
  );
  const search = h("input", { type: "search", placeholder: "Search assets", oninput: () => { clearTimeout(state.t); state.t = setTimeout(load, 250); } });
  const box = h("div", {}), detail = h("div", {});

  app.append(
    pageHead("Asset inventory", "In-scope domains and IP addresses discovered or verified across scans."),
    h("div", { class: "bar" }, sel, kind, search),
    h("div", { class: "split" }, box, detail)
  );

  async function load() {
    const qs = new URLSearchParams({ q: search.value, kind: kind.value, sort: state.sort, order: state.order });
    if (sel.value) qs.set("project_id", sel.value);
    const rows = await api("/api/assets?" + qs);
    clear(box).append(rows.length ? table(
      [
        { label: "Asset", sort: "value" },
        { label: "Type", sort: "kind" },
        "IPs",
        { label: "Ports", sort: "ports" },
        { label: "Open findings", sort: "findings" },
        { label: "First seen", sort: "first_seen" },
        { label: "Last seen", sort: "last_seen" }
      ],
      rows.map((a) => h("tr", {
        class: "row" + (String(state.activeId) === String(a.id) ? " sel" : ""),
        onclick: attempt((ev) => {
          box.querySelectorAll("tr.row").forEach((tr) => tr.classList.remove("sel"));
          ev.currentTarget.classList.add("sel");
          state.activeId = a.id;
          return show(a.id);
        })
      },
        h("td", { class: "mono" }, a.value),
        h("td", {}, h("code", {}, a.kind)),
        h("td", { class: "mono small" }, a.ips || ""),
        h("td", {}, a.ports),
        h("td", {}, a.findings),
        h("td", { class: "muted" }, ago(a.first_seen)),
        h("td", { class: "muted" }, ago(a.last_seen))
      )),
      {
        sort: state.sort,
        order: state.order,
        onsort: (k) => {
          state.order = state.sort === k && state.order === "asc" ? "desc" : "asc";
          state.sort = k;
          load();
        }
      }
    ) : empty("No assets match. Assets appear after a scan discovers them or from the exact domains and IPs in a scan's scope."));
  }

  async function show(id) {
    const a = await api("/api/assets/" + id);
    clear(detail).append(h("div", { class: "panel" },
      h("div", { class: "bar", style: "margin-top:0;justify-content:space-between" },
        h("h3", { class: "mono", style: "margin:0" }, a.value),
        h("code", {}, a.kind || "asset")
      ),
      h("p", { class: "muted small" }, "First seen " + fmtTime(a.first_seen) + ". Last seen " + fmtTime(a.last_seen) + " (scan #" + a.last_scan_id + "). Sources: " + a.sources),
      h("h3", {}, "DNS"),
      a.dns.length ? h("ul", {}, a.dns.map((d) => h("li", { class: "mono small" }, h("code", {}, d.rtype), " " + d.value))) : h("p", { class: "muted small" }, "No DNS records recorded."),
      h("h3", {}, "Open ports"),
      a.ports.length ? h("ul", {}, a.ports.map((p) => h("li", { class: "mono small" }, h("b", {}, p.port + "/" + p.protocol), (p.ip ? " on " + p.ip : "") + " " + [p.service, p.product, p.version].filter(Boolean).join(" ") + " (" + p.source + ")"))) : h("p", { class: "muted small" }, "None recorded."),
      h("h3", {}, "HTTP endpoints"),
      a.endpoints.length ? h("ul", {}, a.endpoints.slice(0, 40).map((e) => h("li", { class: "small" }, h("span", { class: "mono" }, e.url), e.status_code ? h("span", {}, " ", h("code", {}, e.status_code)) : "", e.title ? " " + e.title : ""))) : h("p", { class: "muted small" }, "None recorded."),
      h("h3", {}, "Findings"),
      a.findings.length ? h("ul", {}, a.findings.map((f) => h("li", {}, sev(f.severity), " ", link("/findings?open=" + f.id, f.title), " ", h("span", { class: "muted small" }, "(" + (VALID[f.validation_status] || f.validation_status) + ")")))) : h("p", { class: "muted small" }, "None recorded."),
      a.intel.length ? h("div", {},
        h("h3", {}, "Third-party intelligence"),
        h("p", { class: "hint" }, "Reported by the provider. Not verified by ReconForge."),
        a.intel.map((i) => h("details", {},
          h("summary", {}, i.provider + " for " + i.subject + " (" + ago(i.fetched_at) + ")"),
          h("pre", { class: "ev" }, JSON.stringify(i.payload, null, 2))
        ))
      ) : null
    ));
  }
  await load();
};

pages.findings = async () => {
  const params = new URLSearchParams(location.search);
  let activeId = params.get("open") || null;
  const initialSev = params.get("severity") || "";
  const initialProj = params.get("project_id") || "";
  const sel = await projectSelect(initialProj, () => load());
  const sevSel = h("select", { onchange: () => { updatePills(); load(); } },
    h("option", { value: "" }, "All severities"),
    ["critical", "high", "medium", "low", "info"].map((s) => h("option", { value: s, selected: s === initialSev }, s))
  );
  if (initialSev) sevSel.value = initialSev;
  const stSel = h("select", { onchange: () => load() },
    h("option", { value: "" }, "Any status"),
    Object.entries(VALID).map(([k, v]) => h("option", { value: k }, v))
  );
  const search = h("input", { type: "search", placeholder: "Search title, asset, template", oninput: () => { clearTimeout(search.t); search.t = setTimeout(load, 250); } });
  const box = h("div", {}), detail = h("div", {});

  const sevPillsBox = h("div", { class: "bar", style: "margin:var(--sp-2) 0" });
  function updatePills() {
    clear(sevPillsBox).append(
      h("span", { class: "small muted" }, "Filter severity:"),
      ...["", "critical", "high", "medium", "low", "info"].map((s) => h("button", {
        type: "button",
        class: "sm" + (sevSel.value === s ? " primary" : " secondary"),
        onclick: () => { sevSel.value = s; updatePills(); load(); }
      }, s ? s.toUpperCase() : "ALL"))
    );
  }
  updatePills();

  app.append(
    pageHead("Findings", "These are scanner detections. A finding is only a potential finding until you validate it."),
    sevPillsBox,
    h("div", { class: "bar" }, sel, sevSel, stSel, search),
    h("div", { class: "split" }, box, detail)
  );

  async function load() {
    const qs = new URLSearchParams({ severity: sevSel.value, status: stSel.value, text: search.value });
    if (sel.value) qs.set("project_id", sel.value);
    if (params.get("scan")) qs.set("scan_id", params.get("scan"));
    const rows = await api("/api/findings?" + qs);
    clear(box).append(rows.length ? table(["Severity", "Title", "Asset", "Status", "Source", "Last seen"], rows.map((f) => h("tr", {
      class: "row" + (String(activeId) === String(f.id) ? " sel" : ""),
      onclick: attempt((ev) => {
        box.querySelectorAll("tr.row").forEach((tr) => tr.classList.remove("sel"));
        ev.currentTarget.classList.add("sel");
        activeId = f.id;
        return show(f.id);
      })
    },
      h("td", {}, sev(f.severity)),
      h("td", {}, h("b", {}, f.title)),
      h("td", { class: "mono" }, f.asset),
      h("td", {}, h("span", { class: "pill " + (f.validation_status === "confirmed" ? "s-bad" : f.validation_status === "fixed" || f.validation_status === "false_positive" ? "s-ok" : "s-pending") }, VALID[f.validation_status] || f.validation_status)),
      h("td", {}, h("code", {}, f.source)),
      h("td", { class: "muted" }, ago(f.last_seen))
    ))) : empty("No findings match. If no scan has run, there is nothing to show; if scans ran, nothing was detected with the enabled checks."));
  }

  async function show(id) {
    const f = await api("/api/findings/" + id);
    const st = h("select", { id: "f-status" }, Object.entries(VALID).map(([k, v]) => h("option", { value: k, selected: k === f.validation_status }, v)));
    clear(detail).append(h("div", { class: "panel" },
      h("div", { class: "bar", style: "margin-top:0" }, sev(f.severity), h("h3", { style: "margin:0" }, f.title)),
      h("p", { class: "muted small" }, f.potential ? "Potential finding. A scanner reported this and nobody has validated it." : (VALID[f.validation_status] || f.validation_status)),
      h("div", { class: "panel", style: "background:var(--panel2)" },
        h("p", { style: "margin:2px 0" }, h("b", {}, "Asset: "), h("span", { class: "mono" }, f.asset)),
        f.url ? h("p", { style: "margin:2px 0" }, h("b", {}, "URL: "), h("span", { class: "mono" }, f.url)) : null,
        h("p", { class: "small muted", style: "margin:4px 0 0" },
          "Source " + f.source + " / " + f.template_id + ". Scanner confidence: " + f.confidence +
          ". Tool " + (f.tool_version || "unknown") + (f.template_version ? ", templates " + f.template_version : "") +
          ". First seen " + fmtTime(f.first_seen) + ", last seen " + fmtTime(f.last_seen) +
          ". Detected in scans: " + f.scans.map((x) => "#" + x).join(", ")
        )
      ),
      f.description ? h("p", {}, f.description) : null,
      h("h3", {}, "Evidence"),
      h("pre", { class: "ev" }, f.evidence || "(none recorded)"),
      f.details ? h("details", {}, h("summary", {}, "Request and response"), h("pre", { class: "ev" }, f.details)) : null,
      f.refs.length ? h("div", {}, h("h3", {}, "References"), f.refs.map((r) => h("div", { class: "mono small" }, r))) : null,
      h("h3", {}, "Analyst validation"),
      field("Status", st),
      field("Notes", h("textarea", { id: "f-notes" }, f.analyst_notes || "")),
      h("div", { class: "bar" }, h("button", { class: "primary", onclick: attempt(async () => {
        await api("/api/findings/" + id, "PATCH", { validation_status: val("f-status").value, analyst_notes: val("f-notes").value });
        toast("Saved");
        load();
        show(id);
      }) }, "Save"))
    ));
  }

  await load();
  if (params.get("open")) show(params.get("open")).catch(() => {});
};

pages.tools = async () => {
  const box = h("div", {});
  let toolView = "grid";

  app.append(
    pageHead(
      "Tool health",
      "ReconForge never installs or downloads tools automatically. Each binary is resolved on PATH, confirmed by identity regex, and version-checked.",
      h("button", { class: "primary sm", onclick: attempt(() => load(true)) }, svgIcon(ICONS.refresh, 14), "Re-check PATH")
    ),
    box
  );

  async function load(refresh) {
    clear(box).append(h("div", { class: "panel" }, h("p", { class: "muted" }, "Checking installed binaries on PATH...")));
    const tools = await api("/api/tools" + (refresh ? "?refresh=1" : ""));
    const core = tools.filter((t) => t.core);
    const opt = tools.filter((t) => !t.core);
    const coreOk = core.filter((t) => t.installed).length;
    const optOk = opt.filter((t) => t.installed).length;
    const missingCount = tools.filter((t) => !t.installed).length;

    function renderToolCard(t) {
      const aptCmd = "sudo apt install " + t.kali_package;
      return h("div", { class: "tool-card " + (t.installed ? "installed" : "missing") },
        h("div", { class: "tool-card-head" },
          h("div", {},
            h("h3", { class: "tool-card-title" }, t.label),
            h("span", { class: "small mono muted" }, t.name)
          ),
          h("div", { class: "bar", style: "margin:0" },
            t.core ? h("span", { class: "chip chip-target" }, "Core") : h("span", { class: "chip" }, "Optional"),
            h("span", { class: "pill " + (t.installed ? "s-ok" : "s-bad") }, t.installed ? "Installed" : "Missing")
          )
        ),
        h("div", { class: "tool-card-body" },
          h("p", { style: "margin:0" }, t.description),
          h("div", { class: "matrix-chips", style: "margin-top:var(--sp-2)" },
            t.installed
              ? h("span", { class: "chip chip-items" }, t.version || "Installed")
              : h("span", { class: "chip chip-target" }, t.problem || "Not found on PATH"),
            t.template_version ? h("span", { class: "chip" }, "templates " + t.template_version) : null,
            t.touches_target
              ? h("span", { class: "chip chip-target", title: "Sends active network traffic to target" }, "Contacts target")
              : h("span", { class: "chip chip-safe", title: "Passive or offline only" }, "Passive / Safe")
          ),
          t.path ? h("div", { class: "small mono muted", style: "margin-top:6px;word-break:break-all" }, "Path: ", t.path) : null
        ),
        h("div", { style: "display:flex;flex-direction:column;gap:6px;margin-top:auto" },
          !t.installed ? h("div", { class: "tool-card-install" },
            h("span", {}, aptCmd),
            h("button", {
              type: "button",
              class: "sm secondary",
              onclick: () => copyToClipboard(aptCmd, "Install command copied")
            }, svgIcon(ICONS.copy, 12), "Copy")
          ) : null,
          h("div", { class: "bar", style: "margin:0;justify-content:space-between" },
            h("span", { class: "small muted" }, "Package: ", h("code", {}, t.kali_package)),
            h("a", { class: "small", href: t.install_url, target: "_blank", rel: "noopener noreferrer" }, "Official docs \u2197")
          )
        )
      );
    }

    function renderView() {
      clear(box).append(
        h("div", { class: "card-grid" },
          [
            ["Core Tools Installed", coreOk + " / " + core.length, ICONS.shield],
            ["Optional Modules", optOk + " / " + opt.length, ICONS.tools],
            ["Missing Binaries", String(missingCount), ICONS.alert]
          ].map(([label, val, icon]) => h("div", { class: "stat-card" },
            h("div", { class: "stat-icon" }, svgIcon(icon, 20)),
            h("div", { class: "stat-info" },
              h("span", { class: "stat-value" }, val),
              h("span", { class: "stat-label" }, label)
            )
          ))
        ),
        h("div", { class: "bar", style: "margin:var(--sp-4) 0 var(--sp-2);justify-content:space-between" },
          h("h2", { style: "margin:0" }, "Core Reconnaissance Pipeline"),
          h("div", { class: "bar", style: "margin:0" },
            h("button", {
              type: "button",
              class: "sm" + (toolView === "grid" ? " primary" : " secondary"),
              onclick: () => { toolView = "grid"; renderView(); }
            }, "Card Grid"),
            h("button", {
              type: "button",
              class: "sm" + (toolView === "table" ? " primary" : " secondary"),
              onclick: () => { toolView = "table"; renderView(); }
            }, "Dense Table")
          )
        )
      );

      if (toolView === "grid") {
        box.append(
          h("div", { class: "tool-grid" }, core.map(renderToolCard)),
          h("h2", { style: "margin-top:var(--sp-6)" }, "Optional Assessment Modules"),
          h("div", { class: "tool-grid" }, opt.map(renderToolCard))
        );
      } else {
        const renderTable = (list) => table(
          ["Tool", "Status", "Version", "Path", "Contacts target", "Kali package / Upstream"],
          list.map((t) => h("tr", {},
            h("td", {}, h("b", {}, t.label), h("div", { class: "small muted" }, t.description)),
            h("td", {},
              h("span", { class: "pill " + (t.installed ? "s-ok" : "s-bad") }, t.installed ? "Installed" : "Missing"),
              t.problem ? h("div", { class: "small muted" }, t.problem) : null
            ),
            h("td", { class: "mono" }, t.version || ""),
            h("td", { class: "mono small" }, t.path || ""),
            h("td", {}, t.touches_target ? h("span", { class: "pill s-warn" }, "Yes") : h("span", { class: "pill s-pending" }, "No")),
            h("td", {},
              h("code", {}, t.kali_package), " ",
              h("a", { href: t.install_url, target: "_blank", rel: "noopener noreferrer" }, "official page"),
              t.template_version ? h("div", { class: "small muted" }, "templates " + t.template_version) : null
            )
          ))
        );
        box.append(
          renderTable(core),
          h("h2", { style: "margin-top:var(--sp-6)" }, "Optional Assessment Modules"),
          renderTable(opt)
        );
      }
    }

    renderView();
  }
  await load(false);
};

pages.settings = async () => {
  const s = await api("/api/settings");
  const L = s.limits, H = s.hard_max;
  const defs = [
    ["requests_per_second", "Requests per second (HTTP tools)"],
    ["per_host_rps", "Per-host requests per second"],
    ["max_concurrent_jobs", "Concurrent scans (restart required)"],
    ["max_concurrent_target_jobs", "Concurrent target-contacting tools (restart required)"],
    ["dns_qps", "DNS queries per second"],
    ["port_scan_pps", "Port scan packets per second"],
    ["max_assets", "Maximum assets per scan"],
    ["max_scan_seconds", "Maximum scan duration (seconds)"],
    ["tool_timeout_seconds", "Per-tool timeout (seconds)"],
    ["max_output_bytes", "Maximum output per tool (bytes)"],
    ["cache_ttl_hours", "Discovery cache lifetime (hours)"],
    ["max_retries", "Retries for transient failures"],
    ["retry_base_seconds", "Retry base delay (seconds)"]
  ];

  app.append(
    pageHead(
      "Settings",
      "Defaults are deliberately conservative. Set them lower if the program's rules require it. Values above the built-in maximum are clamped by the server. The server listens on " + s.bind + "."
    ),
    h("h2", {}, "Execution limits"),
    h("div", { class: "panel" },
      h("div", { class: "grid2" }, defs.map(([k, label]) => field(label, h("input", { id: "l-" + k, type: "number", step: "any", value: L[k] }), "Maximum " + H[k]))),
      h("div", { class: "bar" }, h("button", { class: "primary", onclick: attempt(async () => {
        const limits = {};
        defs.forEach(([k]) => { limits[k] = Number(val("l-" + k).value); });
        const r = await api("/api/settings/limits", "PUT", { limits });
        toast(r.note);
      }) }, "Save limits"))
    )
  );

  app.append(
    h("h2", {}, "Optional intelligence providers"),
    h("p", { class: "muted" }, "Off by default. The scan pipeline works without any of them. Keys are stored on this machine only and are never shown again. Enabling a provider lets scans that opt in send in-scope hostnames or IPs to it.")
  );

  s.integrations.forEach((i) => {
    app.append(h("div", { class: "panel" },
      h("div", { class: "bar", style: "margin-top:0;justify-content:space-between" },
        h("h3", { style: "margin:0" }, i.label),
        h("div", { class: "bar", style: "margin:0" },
          h("span", { class: "pill " + (i.configured ? "s-ok" : "s-pending") }, i.configured ? "Credential configured" : "Not configured"),
          h("span", { class: "pill " + (i.enabled ? "s-running" : "s-cancelled") }, i.enabled ? "Enabled" : "Disabled")
        )
      ),
      h("p", { class: "small muted" }, "Sends: " + i.sends + ". ", h("a", { href: i.docs, target: "_blank", rel: "noopener noreferrer" }, "API documentation")),
      h("p", { class: "small" },
        "Last successful lookup: " + (i.last_success ? fmtTime(i.last_success) : "never") +
        (i.last_error ? "   \u00B7   Last error: " + i.last_error : "") +
        (i.backoff_until ? "   \u00B7   Backing off until " + fmtTime(i.backoff_until) : "")
      ),
      Object.keys(i.usage).length ? h("p", { class: "small mono" }, "Provider-reported usage: " + JSON.stringify(i.usage)) : null,
      h("div", { class: "bar" },
        h("input", { type: "password", id: "k-" + i.name, placeholder: i.configured ? "Enter a new key to replace the stored one" : "API key", autocomplete: "off", size: 36 }),
        h("button", { class: "primary", onclick: attempt(async () => {
          const k = val("k-" + i.name).value;
          if (!k.trim()) throw new Error("Enter a key first.");
          await api("/api/integrations/" + i.name, "PUT", { api_key: k });
          toast("Key stored locally");
          location.reload();
        }) }, "Save key"),
        i.configured ? h("button", { class: "danger", onclick: attempt(async () => {
          await api("/api/integrations/" + i.name, "PUT", { api_key: "" });
          location.reload();
        }) }, "Remove key") : null,
        h("button", { class: "secondary", onclick: attempt(async () => {
          await api("/api/integrations/" + i.name, "PUT", { enabled: !i.enabled });
          location.reload();
        }) }, i.enabled ? "Disable" : "Enable"),
        i.configured ? h("button", { class: "secondary", onclick: attempt(async () => {
          const r = await api("/api/integrations/" + i.name + "/test", "POST");
          toast(r.ok ? "Credential works" : r.error, !r.ok);
          setTimeout(() => location.reload(), 1200);
        }) }, "Test") : null
      )
    ));
  });

  app.append(
    h("h2", {}, "Wordlists"),
    h("div", { class: "panel" },
      h("p", { class: "small", style: "margin:0" },
        "FFUF wordlists must live under: ",
        s.wordlist_dirs.length
          ? s.wordlist_dirs.map((d, idx) => h("span", {}, idx ? ", " : "", h("code", {}, d)))
          : "no directory configured (set RECONFORGE_WORDLIST_DIRS)"
      )
    ),
    h("h2", { style: "margin-top:var(--sp-5)" }, "About & Developer"),
    h("div", { class: "panel" },
      h("div", { class: "bar", style: "margin-top:0;justify-content:space-between;flex-wrap:wrap" },
        h("div", {},
          h("h3", { style: "margin:0 0 4px" }, "ReconForge v1.0.0"),
          h("p", { class: "muted small", style: "margin:0" }, "Local-first attack surface & reconnaissance orchestration platform.")
        ),
        h("span", { class: "chip chip-safe" }, "Developed by Anil Kashyap")
      ),
      h("div", { class: "bar", style: "margin-top:var(--sp-3);gap:var(--sp-3)" },
        h("a", { class: "btn secondary sm", href: "https://github.com/anilkashyap01", target: "_blank", rel: "noopener noreferrer" },
          svgIcon(ICONS.terminal, 14), "GitHub: anilkashyap01"
        ),
        h("a", { class: "btn secondary sm", href: "https://linkedin.com/in/anilkashyap01", target: "_blank", rel: "noopener noreferrer" },
          svgIcon(ICONS.target, 14), "LinkedIn: anilkashyap01"
        )
      )
    )
  );
};

(async () => {
  initThemeToggle();
  initMobileNav();
  document.querySelectorAll(".rail a[data-nav]").forEach((a) => {
    if (a.dataset.nav.split(" ").includes(ctx.page)) a.classList.add("on");
  });
  initTopbarProjectSwitcher();
  try {
    clear(app);
    await pages[ctx.page]();
  } catch (e) {
    clear(app).append(h("div", { class: "notice bad" }, "Could not load this page: " + e.message));
  }
})();
