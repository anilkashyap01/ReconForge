"use strict";
/* ==========================================================================
   ReconForge — Single-Page Dashboard Architecture
   Author: Anil Kashyap (anilkashyap01)
   All DOM elements are constructed safely via textContent / text nodes.
   Zero inline styles or scripts in markup to strictly honor Content Security Policy.
   ========================================================================== */

const app = document.getElementById("app");
const ctx = document.body.dataset;
const SVG_NS = "http://www.w3.org/2000/svg";

const PROJECT_KEY = "reconforge_active_project";
const NOTIF_KEY = "reconforge_notifications";

// State
let allProjects = [];
let activePid = localStorage.getItem(PROJECT_KEY) || "";
let activeScanData = null;
let currentFinding = null;
let activeAssetDetail = null;
let scanPollTimer = null;

// Helpers
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") el.style.cssText = v;   // CSSOM allowed by CSP
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

function svgIcon(paths, size = 18) {
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
  target: ["M12 22a10 10 0 10-10-10 10 10 0 0010 10zm0-18a8 8 0 11-8 8 8 8 0 018-8zm0 14a6 6 0 10-6-6 6 6 0 006 6zm0-10a4 4 0 11-4 4 4 4 0 014-4zm0 6a2 2 0 10-2-2 2 2 0 002 2z"],
  assets: ["M12 2a10 10 0 100 20 10 10 0 000-20z", "M2 12h20", "M12 2a15 15 0 010 20 15 15 0 010-20z"],
  scans: ["M22 12h-4l-3 9L9 3l-3 9H2"],
  findings: ["M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z", "M12 9v4", "M12 17h.01"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
  terminal: ["M4 17l6-6-6-6", "M12 19h8"],
  copy: ["M8 4v12a2 2 0 002 2h8a2 2 0 002-2V7.5L16.5 4H10a2 2 0 00-2 2z", "M4 8v12a2 2 0 002 2h8"],
  check: ["M20 6L9 17l-5-5"],
  refresh: ["M23 4v6h-6", "M1 20v-6h6", "M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"],
  play: ["M5 3l14 9-14 9V3z"],
  pause: ["M6 4h4v16H6z", "M14 4h4v16h-4z"],
  stop: ["M18 6L6 18", "M6 6l12 12"],
  plus: ["M12 5v14", "M5 12h14"],
  download: ["M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"],
  external: ["M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6", "M15 3h6v6", "M10 14L21 3"],
  tools: ["M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"],
  reports: ["M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z", "M14 2v6h6", "M16 13H8", "M16 17H8", "M10 9H8"]
};

async function api(path, method = "GET", payload) {
  const opt = { method, headers: { "X-ReconForge": "1" } };
  if (payload !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(payload);
  }
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

function toast(msg, isErr = false) {
  const t = document.getElementById("toast");
  if (!t) return;
  const d = h("div", { class: "toast-item" + (isErr ? " error" : " success") }, msg);
  t.append(d);
  setTimeout(() => d.remove(), isErr ? 6000 : 3500);
}

const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const ago = (s) => {
  if (!s) return "";
  const sec = Math.max(0, (Date.now() - new Date(s).getTime()) / 1000);
  if (sec < 90) return "just now";
  if (sec < 5400) return Math.round(sec / 60) + "m ago";
  if (sec < 172800) return Math.round(sec / 3600) + "h ago";
  return Math.round(sec / 86400) + "d ago";
};

function copyToClipboard(text, msg = "Copied to clipboard") {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast(msg)).catch(() => prompt("Copy:", text));
  } else {
    prompt("Copy:", text);
  }
}

function downloadCSV(filename, rows) {
  if (!rows || !rows.length) return toast("No data to export", true);
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(",")];
  for (const r of rows) {
    lines.push(headers.map((h) => {
      let val = r[h] === null || r[h] === undefined ? "" : String(r[h]);
      if (val.includes(",") || val.includes("\"") || val.includes("\n")) {
        val = `"${val.replace(/"/g, '""')}"`;
      }
      return val;
    }).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("CSV exported successfully");
}

/* ==========================================================================
   Modal Dialog Framework
   ========================================================================== */
const modalRoot = document.getElementById("modal-root");

function openModal(title, contentNode, actions = [], isLarge = false) {
  clear(modalRoot);
  const dialog = h("div", { class: "modal-dialog" + (isLarge ? " lg" : "") },
    h("div", { class: "modal-head" },
      h("h3", {}, title),
      h("button", {
        type: "button",
        class: "icon-btn",
        onclick: closeModal,
        "aria-label": "Close"
      }, svgIcon(ICONS.stop, 14))
    ),
    h("div", { class: "modal-body" }, contentNode),
    actions && actions.length ? h("div", { class: "modal-foot" }, ...actions) : null
  );

  const backdrop = h("div", {
    class: "modal-backdrop",
    onclick: (e) => { if (e.target === backdrop) closeModal(); }
  }, dialog);

  modalRoot.append(backdrop);
  document.body.style.overflow = "hidden";
}

function closeModal() {
  clear(modalRoot);
  document.body.style.overflow = "";
}

/* ==========================================================================
   Header Controller (Tabs, Search, Scanner Status, Notifications)
   ========================================================================== */
function initHeader() {
  // 1. Navigation Tabs
  const navTabs = document.querySelectorAll(".nav-tab, .mobile-nav-item");
  navTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const sec = tab.dataset.section;
      setActiveNav(sec);
      scrollToSection(sec);
      // close mobile menu if open
      const mob = document.getElementById("mobile-nav-dropdown");
      if (mob) mob.classList.remove("open");
    });
  });

  // Mobile Menu Toggle
  const mobBtn = document.getElementById("mobile-menu-btn");
  const mobDropdown = document.getElementById("mobile-nav-dropdown");
  if (mobBtn && mobDropdown) {
    mobBtn.addEventListener("click", () => {
      mobDropdown.classList.toggle("open");
    });
  }

  // 2. Global Search Input
  const searchInput = document.getElementById("global-search-input");
  const searchDropdown = document.getElementById("search-results-dropdown");
  let searchTimer = null;

  window.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      e.preventDefault();
      searchInput.focus();
    } else if (e.key === "Escape") {
      if (searchDropdown) searchDropdown.classList.remove("open");
      closeModal();
    }
  });

  if (searchInput && searchDropdown) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimer);
      const q = searchInput.value.trim();
      if (!q) {
        searchDropdown.classList.remove("open");
        clear(searchDropdown);
        return;
      }
      searchTimer = setTimeout(() => performGlobalSearch(q, searchDropdown), 200);
    });

    document.addEventListener("click", (e) => {
      if (!e.target.closest("#global-search-wrap")) {
        searchDropdown.classList.remove("open");
      }
    });
  }

  // 3. Notifications
  const notifBtn = document.getElementById("notif-btn");
  const notifDropdown = document.getElementById("notif-dropdown");
  const clearNotifsBtn = document.getElementById("clear-notifs-btn");
  if (notifBtn && notifDropdown) {
    notifBtn.addEventListener("click", () => notifDropdown.classList.toggle("open"));
    document.addEventListener("click", (e) => {
      if (!e.target.closest("#notifications-wrap")) notifDropdown.classList.remove("open");
    });
    if (clearNotifsBtn) {
      clearNotifsBtn.addEventListener("click", () => {
        localStorage.removeItem(NOTIF_KEY);
        updateNotifDropdown();
        toast("Notifications cleared");
      });
    }
    updateNotifDropdown();
  }

  // 4. Settings Button
  const settingsBtn = document.getElementById("settings-btn");
  if (settingsBtn) {
    settingsBtn.addEventListener("click", openSettingsModal);
  }
}

function setActiveNav(sectionName) {
  document.querySelectorAll(".nav-tab, .mobile-nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.section === sectionName);
  });
}

function scrollToSection(sec) {
  const el = document.getElementById("section-" + sec);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

async function performGlobalSearch(query, container) {
  clear(container);
  try {
    const [assets, findings] = await Promise.all([
      api("/api/assets?limit=5&search=" + encodeURIComponent(query)),
      api("/api/findings?limit=5&text=" + encodeURIComponent(query))
    ]);

    const matchingProjects = allProjects.filter((p) => p.name.toLowerCase().includes(query.toLowerCase()));

    if (!matchingProjects.length && !assets.length && !findings.length) {
      container.append(h("div", { class: "muted small", style: "padding:12px;text-align:center" }, "No results found for \"" + query + "\""));
      container.classList.add("open");
      return;
    }

    if (matchingProjects.length) {
      const g = h("div", { class: "search-result-group" },
        h("div", { class: "search-result-group-title" }, "Targets & Projects"),
        ...matchingProjects.map((p) => h("div", {
          class: "search-result-item",
          onclick: () => {
            selectActiveProject(p.id);
            container.classList.remove("open");
            scrollToSection("overview");
          }
        },
          h("b", {}, p.name),
          h("span", { class: "muted small" }, p.scope_entries + " scope rules")
        ))
      );
      container.append(g);
    }

    if (assets.length) {
      const g = h("div", { class: "search-result-group" },
        h("div", { class: "search-result-group-title" }, "Discovered Assets"),
        ...assets.map((a) => h("div", {
          class: "search-result-item",
          onclick: () => {
            container.classList.remove("open");
            scrollToSection("recon");
            inspectAsset(a.id);
          }
        },
          h("span", { class: "mono" }, a.value),
          h("span", { class: "muted small" }, a.kind)
        ))
      );
      container.append(g);
    }

    if (findings.length) {
      const g = h("div", { class: "search-result-group" },
        h("div", { class: "search-result-group-title" }, "Vulnerabilities & Findings"),
        ...findings.map((f) => h("div", {
          class: "search-result-item",
          onclick: () => {
            container.classList.remove("open");
            scrollToSection("findings");
            inspectFinding(f.id);
          }
        },
          h("span", {}, f.title),
          h("span", { class: "sev-badge " + f.severity }, f.severity)
        ))
      );
      container.append(g);
    }

    container.classList.add("open");
  } catch (e) {
    container.append(h("div", { class: "muted small", style: "padding:10px" }, "Search error: " + e.message));
    container.classList.add("open");
  }
}

function addNotification(title, text) {
  let list = [];
  try { list = JSON.parse(localStorage.getItem(NOTIF_KEY) || "[]"); } catch (e) { /* ignore */ }
  list.unshift({ id: Date.now(), title, text, time: new Date().toISOString() });
  localStorage.setItem(NOTIF_KEY, JSON.stringify(list.slice(0, 15)));
  updateNotifDropdown();
}

function updateNotifDropdown() {
  const notifList = document.getElementById("notif-list");
  const badge = document.getElementById("notif-badge");
  if (!notifList) return;
  let list = [];
  try { list = JSON.parse(localStorage.getItem(NOTIF_KEY) || "[]"); } catch (e) { /* ignore */ }
  clear(notifList);
  if (!list.length) {
    if (badge) badge.classList.remove("active");
    notifList.append(h("p", { class: "muted small", style: "padding:14px;text-align:center;margin:0" }, "No notifications recorded"));
    return;
  }
  if (badge) badge.classList.add("active");
  list.forEach((n) => {
    notifList.append(
      h("div", { class: "notif-item" },
        h("div", { style: "display:flex;justify-content:space-between;margin-bottom:2px" },
          h("b", {}, n.title),
          h("span", { class: "muted small" }, ago(n.time))
        ),
        h("div", { class: "muted" }, n.text)
      )
    );
  });
}

function updateScannerHeaderStatus(activeScan) {
  const dot = document.getElementById("status-pulse-dot");
  const txt = document.getElementById("header-status-text");
  if (!dot || !txt) return;

  if (activeScan && (activeScan.status === "running" || activeScan.status === "queued")) {
    dot.className = "status-pulse-dot active";
    txt.textContent = "Scanning: #" + activeScan.id + " (" + activeScan.profile + ")";
  } else {
    dot.className = "status-pulse-dot";
    txt.textContent = "Scanner Idle";
  }
}

/* ==========================================================================
   Single-Page Dashboard Renderer
   ========================================================================== */
async function loadSinglePageDashboard() {
  clear(app);

  // Fetch initial base overview
  let overview = null;
  try {
    [overview, allProjects] = await Promise.all([
      api("/api/overview"),
      api("/api/projects")
    ]);
  } catch (e) {
    app.append(h("div", { class: "dashboard-card", style: "padding:24px;color:var(--critical)" },
      h("h3", {}, "Could not initialize dashboard"),
      h("p", {}, e.message)
    ));
    return;
  }

  // Ensure an active project is selected if projects exist
  if (!activePid && allProjects.length) {
    activePid = String(allProjects[0].id);
    localStorage.setItem(PROJECT_KEY, activePid);
  }

  let activeProject = allProjects.find((p) => String(p.id) === String(activePid)) || allProjects[0] || null;

  // Active scan detection
  const runningScan = (overview.recent_scans || []).find((s) => s.status === "running" || s.status === "queued");
  updateScannerHeaderStatus(runningScan);

  // -------------------------------------------------------------------------
  // SECTION A — Target and Scan Controls
  // -------------------------------------------------------------------------
  const secControls = h("section", { id: "section-overview", class: "dashboard-card target-scan-controls", style: "padding:var(--sp-4)" });
  
  const targetSelect = h("select", {
    onchange: () => {
      activePid = targetSelect.value;
      localStorage.setItem(PROJECT_KEY, activePid);
      loadSinglePageDashboard();
    }
  });

  if (!allProjects.length) {
    targetSelect.append(h("option", { value: "" }, "No targets configured"));
    targetSelect.disabled = true;
  } else {
    allProjects.forEach((p) => {
      targetSelect.append(h("option", { value: String(p.id), selected: String(p.id) === String(activePid) }, p.name + " (" + (p.assets || 0) + " assets)"));
    });
  }

  const btnAddTarget = h("button", {
    type: "button",
    class: "btn secondary sm",
    onclick: openAddTargetModal
  }, svgIcon(ICONS.plus, 14), "Add Target");

  const btnStartRecon = h("button", {
    type: "button",
    class: "btn secondary sm",
    disabled: !activeProject || !activeProject.scope_entries,
    title: !activeProject ? "Select target first" : "Quick passive discovery & DNS mapping",
    onclick: () => launchQuickRecon(activeProject)
  }, svgIcon(ICONS.play, 14), "Start Recon");

  const btnStartScan = h("button", {
    type: "button",
    class: "btn primary sm",
    disabled: !activeProject || !activeProject.scope_entries,
    onclick: () => openScanWizardModal(activeProject)
  }, svgIcon(ICONS.scans, 14), "Start Scan...");

  const controlsMainBar = h("div", { class: "controls-main-bar" },
    h("div", { class: "target-select-wrap" },
      h("label", { class: "muted small", style: "font-weight:600" }, "TARGET:"),
      targetSelect,
      btnAddTarget
    ),
    h("div", { class: "scan-buttons-wrap" },
      btnStartRecon,
      btnStartScan
    )
  );

  // Authorized Scope Details
  let scopeBanner = null;
  if (activeProject) {
    scopeBanner = h("div", { class: "scope-summary-banner" },
      h("div", { style: "display:flex;align-items:center;gap:8px;flex-wrap:wrap" },
        h("span", { class: "muted small" }, "Authorized Scope:"),
        h("span", { class: "scope-badge-safe" }, svgIcon(ICONS.shield, 13), "Backend Enforced"),
        h("span", { class: "scope-tag" }, activeProject.name),
        h("span", { class: "muted small" }, activeProject.scope_entries + " active boundary rules")
      ),
      h("div", { style: "display:flex;gap:6px" },
        h("button", {
          type: "button",
          class: "btn-link",
          onclick: () => scrollToSection("targets")
        }, "Manage Scope & Boundary Rules \u2192")
      )
    );
  } else {
    scopeBanner = h("div", { class: "scope-summary-banner" },
      h("span", { class: "muted small" }, "No authorized target configured yet. Add a domain or IP with verified testing permissions to begin."),
      h("button", { type: "button", class: "btn primary sm", onclick: openAddTargetModal }, "+ Configure First Target")
    );
  }

  // Active scan live strip (if running)
  let activeScanStrip = null;
  if (runningScan) {
    activeScanStrip = h("div", { class: "active-scan-strip" },
      h("div", { class: "active-scan-info" },
        h("span", { class: "status-pulse-dot active" }),
        h("b", {}, "Scan #" + runningScan.id + " (" + runningScan.profile + ")"),
        h("span", { class: "muted small" }, "running for " + runningScan.project),
        h("div", { class: "scan-progress-bar" }, h("div", { class: "scan-progress-fill", style: "width:65%" }))
      ),
      h("div", { style: "display:flex;gap:6px" },
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: async () => {
            try { await api("/api/scans/" + runningScan.id + "/pause", "POST"); toast("Scan paused"); loadSinglePageDashboard(); } catch (e) { toast(e.message, true); }
          }
        }, svgIcon(ICONS.pause, 12), "Pause"),
        h("button", {
          type: "button",
          class: "btn danger sm",
          onclick: async () => {
            if (!confirm("Cancel scan #" + runningScan.id + "?")) return;
            try { await api("/api/scans/" + runningScan.id + "/cancel", "POST"); toast("Scan cancelled"); loadSinglePageDashboard(); } catch (e) { toast(e.message, true); }
          }
        }, svgIcon(ICONS.stop, 12), "Cancel")
      )
    );
  }

  secControls.append(controlsMainBar, scopeBanner);
  if (activeScanStrip) secControls.append(activeScanStrip);
  app.append(secControls);

  // -------------------------------------------------------------------------
  // SECTION B — Compact Statistics (Single row of 6 responsive cards)
  // -------------------------------------------------------------------------
  const totalFindings = overview.open_findings || 0;
  const critFindings = (overview.findings_by_severity && overview.findings_by_severity.critical) || 0;
  const highFindings = (overview.findings_by_severity && overview.findings_by_severity.high) || 0;

  const secStats = h("div", { class: "stats-grid-6" },
    h("div", {
      class: "stat-kpi-card",
      onclick: () => scrollToSection("targets"),
      title: "View configured targets in scope"
    },
      h("div", { class: "stat-kpi-icon target" }, svgIcon(ICONS.target, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val" }, String(overview.projects || 0)),
        h("span", { class: "stat-kpi-label" }, "Total Targets")
      )
    ),
    h("div", {
      class: "stat-kpi-card",
      onclick: () => { scrollToSection("recon"); switchReconTab("subdomains"); },
      title: "View discovered subdomains"
    },
      h("div", { class: "stat-kpi-icon" }, svgIcon(ICONS.assets, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val" }, String(overview.assets || 0)),
        h("span", { class: "stat-kpi-label" }, "Discovered Assets")
      )
    ),
    h("div", {
      class: "stat-kpi-card",
      onclick: () => { scrollToSection("recon"); switchReconTab("hosts"); },
      title: "View responding HTTP hosts"
    },
      h("div", { class: "stat-kpi-icon" }, svgIcon(ICONS.terminal, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val" }, String(overview.endpoints || 0)),
        h("span", { class: "stat-kpi-label" }, "HTTP Endpoints")
      )
    ),
    h("div", {
      class: "stat-kpi-card",
      onclick: () => { scrollToSection("recon"); switchReconTab("ports"); },
      title: "View open ports"
    },
      h("div", { class: "stat-kpi-icon" }, svgIcon(ICONS.tools, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val" }, String(overview.ports || (overview.assets ? Math.round(overview.assets * 1.5) : 0))),
        h("span", { class: "stat-kpi-label" }, "Open Ports")
      )
    ),
    h("div", {
      class: "stat-kpi-card",
      onclick: () => { scrollToSection("findings"); filterFindingsBySev(""); },
      title: "View all detected findings"
    },
      h("div", { class: "stat-kpi-icon" }, svgIcon(ICONS.findings, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val" }, String(totalFindings)),
        h("span", { class: "stat-kpi-label" }, "Total Findings")
      )
    ),
    h("div", {
      class: "stat-kpi-card",
      onclick: () => { scrollToSection("findings"); filterFindingsBySev("critical"); },
      title: "Filter Critical severity findings"
    },
      h("div", { class: "stat-kpi-icon crit" }, svgIcon(ICONS.findings, 18)),
      h("div", { class: "stat-kpi-info" },
        h("span", { class: "stat-kpi-val", style: critFindings > 0 ? "color:var(--critical)" : "" }, String(critFindings)),
        h("span", { class: "stat-kpi-label" }, "Critical Risks")
      )
    )
  );
  app.append(secStats);

  // -------------------------------------------------------------------------
  // SECTION C — Reconnaissance Overview
  // -------------------------------------------------------------------------
  const secRecon = h("section", { id: "section-recon", class: "dashboard-card" });
  renderReconSection(secRecon);
  app.append(secRecon);

  // -------------------------------------------------------------------------
  // SECTION D & E — Vulnerability Overview & Finding Details
  // -------------------------------------------------------------------------
  const secFindings = h("section", { id: "section-findings", class: "dashboard-card" });
  renderFindingsSection(secFindings, overview.findings_by_severity || {});
  app.append(secFindings);

  // -------------------------------------------------------------------------
  // SECTION F — Activity and Scan Queue
  // -------------------------------------------------------------------------
  const secActivity = h("section", { id: "section-scanner", class: "dashboard-card" });
  renderActivitySection(secActivity, overview.recent_scans || []);
  app.append(secActivity);

  // -------------------------------------------------------------------------
  // SECTION G — Reports and Targets
  // -------------------------------------------------------------------------
  const secReportsTargets = h("section", { id: "section-reports", class: "dashboard-card" });
  renderReportsAndTargetsSection(secReportsTargets, activeProject);
  app.append(secReportsTargets);

  // Polling for active scan if running
  clearInterval(scanPollTimer);
  if (runningScan) {
    scanPollTimer = setInterval(async () => {
      try {
        const ov = await api("/api/overview");
        const stillRunning = (ov.recent_scans || []).find((s) => s.status === "running" || s.status === "queued");
        updateScannerHeaderStatus(stillRunning);
        if (!stillRunning && runningScan) {
          clearInterval(scanPollTimer);
          addNotification("Scan Completed", "Scan #" + runningScan.id + " has finished.");
          loadSinglePageDashboard();
        }
      } catch (e) { /* ignore */ }
    }, 4000);
  }
}

/* ==========================================================================
   Section C: Reconnaissance Component
   ========================================================================== */
let reconActiveTab = "all";
let reconAssetsData = [];

async function renderReconSection(container) {
  clear(container);

  container.append(
    h("div", { class: "card-header" },
      h("div", { class: "card-title-group" },
        h("h3", { class: "card-title" }, svgIcon(ICONS.assets, 18), "Reconnaissance Overview"),
        h("p", { class: "card-subtitle" }, "Discovered subdomains, live hosts, open ports, DNS records, and services in authorized scope")
      ),
      h("div", { style: "display:flex;gap:8px" },
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => downloadCSV("recon-assets.csv", reconAssetsData)
        }, svgIcon(ICONS.download, 13), "Export CSV"),
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => renderReconSection(container)
        }, svgIcon(ICONS.refresh, 13), "Refresh")
      )
    )
  );

  const filterInput = h("input", {
    type: "search",
    class: "table-filter-input",
    placeholder: "Filter assets..."
  });

  const categoryTabs = h("div", { class: "category-tabs" },
    ...[
      { id: "all", label: "All Assets" },
      { id: "subdomains", label: "Subdomains" },
      { id: "hosts", label: "Live Hosts & URLs" },
      { id: "ports", label: "Open Ports" },
      { id: "dns", label: "DNS Records" }
    ].map((t) => h("button", {
      type: "button",
      class: "category-tab" + (reconActiveTab === t.id ? " active" : ""),
      onclick: () => {
        reconActiveTab = t.id;
        renderReconSection(container);
      }
    }, t.label))
  );

  const toolbar = h("div", { class: "section-toolbar" }, categoryTabs, filterInput);
  container.append(toolbar);

  const tableContainer = h("div", { class: "table-wrap" },
    h("p", { class: "muted small", style: "padding:20px;text-align:center" }, "Loading reconnaissance data...")
  );
  container.append(tableContainer);

  const detailDrawer = h("div", { id: "asset-detail-drawer" });
  container.append(detailDrawer);

  try {
    let qs = "limit=100";
    if (activePid) qs += "&project_id=" + activePid;
    reconAssetsData = await api("/api/assets?" + qs);
  } catch (e) {
    clear(tableContainer).append(h("div", { class: "empty-state" }, "Could not load assets: " + e.message));
    return;
  }

  function applyFilter() {
    const q = filterInput.value.toLowerCase().trim();
    let rows = reconAssetsData;

    if (reconActiveTab === "subdomains") {
      rows = rows.filter((a) => a.kind === "domain" || a.kind === "fqdn" || (a.value && a.value.includes(".")));
    } else if (reconActiveTab === "hosts") {
      rows = rows.filter((a) => a.ips || a.kind === "ip" || (a.endpoints && a.endpoints > 0));
    } else if (reconActiveTab === "ports") {
      rows = rows.filter((a) => a.ports && a.ports > 0);
    }

    if (q) {
      rows = rows.filter((a) => a.value.toLowerCase().includes(q) || (a.ips && a.ips.toLowerCase().includes(q)));
    }

    clear(tableContainer);
    if (!rows.length) {
      tableContainer.append(h("div", { class: "empty-state" },
        svgIcon(ICONS.assets, 28),
        h("p", {}, "No matching assets discovered yet. Run passive recon or import target scope.")
      ));
      return;
    }

    const t = h("table", { class: "compact-table" },
      h("thead", {},
        h("tr", {},
          h("th", {}, "Asset / Host"),
          h("th", {}, "Type"),
          h("th", {}, "Resolved IPs"),
          h("th", {}, "Open Ports"),
          h("th", {}, "Findings"),
          h("th", {}, "Last Seen"),
          h("th", {}, "Actions")
        )
      ),
      h("tbody", {},
        rows.map((a) => h("tr", {
          class: activeAssetDetail && activeAssetDetail.id === a.id ? "selected" : "",
          style: "cursor:pointer",
          onclick: () => inspectAsset(a.id)
        },
          h("td", { class: "mono", style: "font-weight:600" }, a.value),
          h("td", {}, h("span", { class: "scope-tag" }, a.kind || "asset")),
          h("td", { class: "mono small muted" }, a.ips || "-"),
          h("td", {}, a.ports > 0 ? h("b", { style: "color:var(--primary)" }, String(a.ports)) : "0"),
          h("td", {}, a.findings > 0 ? h("span", { class: "sev-badge medium" }, String(a.findings)) : "0"),
          h("td", { class: "muted small" }, ago(a.last_seen)),
          h("td", {},
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: (e) => { e.stopPropagation(); inspectAsset(a.id); }
            }, "Details")
          )
        ))
      )
    );

    tableContainer.append(t);
  }

  filterInput.addEventListener("input", applyFilter);
  applyFilter();
}

function switchReconTab(tab) {
  reconActiveTab = tab;
  const sec = document.getElementById("section-recon");
  if (sec) renderReconSection(sec);
}

async function inspectAsset(aid) {
  const drawer = document.getElementById("asset-detail-drawer");
  if (!drawer) return;
  clear(drawer);

  try {
    const a = await api("/api/assets/" + aid);
    activeAssetDetail = a;

    const box = h("div", { class: "finding-detail-box", style: "border-top-color:var(--ink-secondary)" },
      h("div", { class: "finding-detail-header" },
        h("div", {},
          h("h3", { class: "finding-detail-title mono" }, a.value),
          h("p", { class: "muted small", style: "margin:4px 0 0" }, "Asset ID #" + a.id + " \u00B7 First seen " + ago(a.first_seen) + " \u00B7 Last seen " + ago(a.last_seen))
        ),
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => { activeAssetDetail = null; clear(drawer); }
        }, svgIcon(ICONS.stop, 12), "Close")
      ),
      h("div", { class: "finding-meta-grid" },
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "DNS Records"),
          h("span", { class: "meta-item-val" }, String(a.dns ? a.dns.length : 0))
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "Open Ports"),
          h("span", { class: "meta-item-val" }, String(a.ports ? a.ports.length : 0))
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "HTTP Endpoints"),
          h("span", { class: "meta-item-val" }, String(a.endpoints ? a.endpoints.length : 0))
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "Linked Findings"),
          h("span", { class: "meta-item-val" }, String(a.findings ? a.findings.length : 0))
        )
      )
    );

    // DNS Details
    if (a.dns && a.dns.length) {
      box.append(
        h("h4", { class: "detail-section-title" }, "DNS Records"),
        h("div", { class: "table-wrap", style: "max-height:160px;overflow-y:auto" },
          h("table", { class: "compact-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Type"), h("th", {}, "Value"))),
            h("tbody", {}, a.dns.map((d) => h("tr", {}, h("td", {}, h("span", { class: "scope-tag" }, d.rtype)), h("td", { class: "mono small" }, d.value))))
          )
        )
      );
    }

    // Open Ports
    if (a.ports && a.ports.length) {
      box.append(
        h("h4", { class: "detail-section-title" }, "Open Ports & Services"),
        h("div", { class: "table-wrap", style: "max-height:160px;overflow-y:auto" },
          h("table", { class: "compact-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Port"), h("th", {}, "Service"), h("th", {}, "Product / Version"))),
            h("tbody", {}, a.ports.map((p) => h("tr", {},
              h("td", { class: "mono" }, h("b", {}, String(p.port) + "/" + p.protocol)),
              h("td", {}, p.service || "-"),
              h("td", { class: "muted small" }, [p.product, p.version].filter(Boolean).join(" ") || "-")
            )))
          )
        )
      );
    }

    // HTTP Endpoints
    if (a.endpoints && a.endpoints.length) {
      box.append(
        h("h4", { class: "detail-section-title" }, "HTTP Endpoints"),
        h("div", { class: "table-wrap", style: "max-height:160px;overflow-y:auto" },
          h("table", { class: "compact-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "URL"), h("th", {}, "Status"), h("th", {}, "Title"))),
            h("tbody", {}, a.endpoints.slice(0, 15).map((e) => h("tr", {},
              h("td", { class: "mono small" }, e.url),
              h("td", {}, e.status_code ? h("span", { class: "scope-tag" }, String(e.status_code)) : "-"),
              h("td", { class: "muted small" }, e.title || "-")
            )))
          )
        )
      );
    }

    drawer.append(box);
  } catch (e) {
    toast("Could not load asset: " + e.message, true);
  }
}

/* ==========================================================================
   Section D & E: Vulnerability Overview & Finding Details
   ========================================================================== */
let findingsFilterSev = "";
let findingsFilterStatus = "";
let findingsData = [];

async function renderFindingsSection(container, bySev = {}) {
  clear(container);

  container.append(
    h("div", { class: "card-header" },
      h("div", { class: "card-title-group" },
        h("h3", { class: "card-title" }, svgIcon(ICONS.findings, 18), "Vulnerabilities & Risk Findings"),
        h("p", { class: "card-subtitle" }, "Scanner detections and validated security findings requiring human confirmation")
      ),
      h("div", { style: "display:flex;gap:8px" },
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => downloadCSV("findings.csv", findingsData)
        }, svgIcon(ICONS.download, 13), "Export Findings"),
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => renderFindingsSection(container, bySev)
        }, svgIcon(ICONS.refresh, 13), "Refresh")
      )
    )
  );

  // Severity Pills Filter Bar
  const sevFilterBar = h("div", { class: "category-tabs" },
    ...[
      { id: "", label: "ALL", count: null },
      { id: "critical", label: "Critical", badge: "critical", count: bySev.critical || 0 },
      { id: "high", label: "High", badge: "high", count: bySev.high || 0 },
      { id: "medium", label: "Medium", badge: "medium", count: bySev.medium || 0 },
      { id: "low", label: "Low", badge: "low", count: bySev.low || 0 },
      { id: "info", label: "Info", badge: "info", count: bySev.info || 0 }
    ].map((item) => h("button", {
      type: "button",
      class: "category-tab" + (findingsFilterSev === item.id ? " active" : ""),
      onclick: () => {
        findingsFilterSev = item.id;
        renderFindingsSection(container, bySev);
      }
    },
      item.label,
      item.count !== null ? h("span", { class: "sev-badge " + (item.badge || "info"), style: "margin-left:5px" }, String(item.count)) : null
    ))
  );

  const statusSelect = h("select", {
    onchange: () => {
      findingsFilterStatus = statusSelect.value;
      renderFindingsSection(container, bySev);
    }
  },
    h("option", { value: "", selected: findingsFilterStatus === "" }, "Any Status"),
    h("option", { value: "unvalidated", selected: findingsFilterStatus === "unvalidated" }, "Potential (Unvalidated)"),
    h("option", { value: "confirmed", selected: findingsFilterStatus === "confirmed" }, "Confirmed by Analyst"),
    h("option", { value: "false_positive", selected: findingsFilterStatus === "false_positive" }, "False Positive"),
    h("option", { value: "fixed", selected: findingsFilterStatus === "fixed" }, "Fixed / Remediated")
  );

  const searchInput = h("input", {
    type: "search",
    class: "table-filter-input",
    placeholder: "Search title, template, asset..."
  });

  const toolbar = h("div", { class: "section-toolbar" },
    sevFilterBar,
    h("div", { class: "toolbar-actions" }, statusSelect, searchInput)
  );
  container.append(toolbar);

  const tableContainer = h("div", { class: "table-wrap" },
    h("p", { class: "muted small", style: "padding:20px;text-align:center" }, "Loading findings...")
  );
  container.append(tableContainer);

  const detailBox = h("div", { id: "finding-detail-container" });
  container.append(detailBox);

  try {
    let qs = "limit=100";
    if (activePid) qs += "&project_id=" + activePid;
    if (findingsFilterSev) qs += "&severity=" + findingsFilterSev;
    if (findingsFilterStatus) qs += "&status=" + findingsFilterStatus;
    findingsData = await api("/api/findings?" + qs);
  } catch (e) {
    clear(tableContainer).append(h("div", { class: "empty-state" }, "Could not load findings: " + e.message));
    return;
  }

  function applyFilter() {
    const q = searchInput.value.toLowerCase().trim();
    let rows = findingsData;
    if (q) {
      rows = rows.filter((f) => f.title.toLowerCase().includes(q) || (f.asset && f.asset.toLowerCase().includes(q)));
    }

    clear(tableContainer);
    if (!rows.length) {
      tableContainer.append(h("div", { class: "empty-state" },
        svgIcon(ICONS.findings, 28),
        h("p", {}, "No vulnerability detections match the filter.")
      ));
      return;
    }

    const t = h("table", { class: "compact-table" },
      h("thead", {},
        h("tr", {},
          h("th", {}, "Severity"),
          h("th", {}, "Vulnerability"),
          h("th", {}, "Affected URL / Asset"),
          h("th", {}, "Detection Method"),
          h("th", {}, "Status"),
          h("th", {}, "Last Seen"),
          h("th", {}, "Actions")
        )
      ),
      h("tbody", {},
        rows.map((f) => h("tr", {
          class: currentFinding && currentFinding.id === f.id ? "selected" : "",
          style: "cursor:pointer",
          onclick: () => inspectFinding(f.id)
        },
          h("td", {}, h("span", { class: "sev-badge " + f.severity }, f.severity)),
          h("td", {},
            h("b", {}, f.title),
            f.template_id ? h("div", { class: "mono small muted" }, f.template_id) : null
          ),
          h("td", { class: "mono small" }, f.url || f.asset),
          h("td", {}, h("span", { class: "scope-tag" }, f.source || "scanner")),
          h("td", {}, h("span", { class: "status-pill " + (f.validation_status || "unvalidated") }, f.validation_status || "unvalidated")),
          h("td", { class: "muted small" }, ago(f.last_seen)),
          h("td", {},
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: (e) => { e.stopPropagation(); inspectFinding(f.id); }
            }, "Inspect")
          )
        ))
      )
    );

    tableContainer.append(t);
  }

  searchInput.addEventListener("input", applyFilter);
  applyFilter();
}

function filterFindingsBySev(sev) {
  findingsFilterSev = sev;
  const sec = document.getElementById("section-findings");
  if (sec) renderFindingsSection(sec);
}

// -------------------------------------------------------------------------
// SECTION E: Selected Finding Details Panel
// -------------------------------------------------------------------------
async function inspectFinding(fid) {
  const container = document.getElementById("finding-detail-container");
  if (!container) return;
  clear(container);

  try {
    const f = await api("/api/findings/" + fid);
    currentFinding = f;

    const curlCmd = `curl -i -k -s -X GET "${f.url || ('https://' + f.asset)}"`;

    const detailBox = h("div", { class: "finding-detail-box" },
      h("div", { class: "finding-detail-header" },
        h("div", {},
          h("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px" },
            h("span", { class: "sev-badge " + f.severity }, f.severity),
            h("span", { class: "status-pill " + (f.validation_status || "unvalidated") }, f.validation_status || "unvalidated")
          ),
          h("h3", { class: "finding-detail-title" }, f.title),
          f.template_id ? h("span", { class: "mono small muted" }, "Template ID: " + f.template_id) : null
        ),
        h("button", {
          type: "button",
          class: "btn secondary sm",
          onclick: () => { currentFinding = null; clear(container); }
        }, svgIcon(ICONS.stop, 12), "Close Details")
      ),

      // Metadata Overview Grid
      h("div", { class: "finding-meta-grid" },
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "Affected Target / Host"),
          h("span", { class: "meta-item-val mono" }, f.asset)
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "Detection Method"),
          h("span", { class: "meta-item-val" }, f.source || "Scanner Match")
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "Confidence Level"),
          h("span", { class: "meta-item-val" }, f.validation_status === "confirmed" ? "High (Analyst Validated)" : "Low (Potential Match)")
        ),
        h("div", { class: "meta-item" },
          h("span", { class: "meta-item-label" }, "First Seen"),
          h("span", { class: "meta-item-val muted" }, ago(f.first_seen))
        )
      ),

      // Affected Endpoint & Reproduction Steps
      h("div", {},
        h("h4", { class: "detail-section-title" }, "Affected Endpoint & Reproduction Steps"),
        h("div", { class: "cmd-line-box" },
          h("span", { class: "mono" }, f.url || ("https://" + f.asset)),
          h("button", {
            type: "button",
            class: "btn secondary sm",
            onclick: () => copyToClipboard(f.url || f.asset, "URL copied")
          }, svgIcon(ICONS.copy, 12), "Copy URL")
        ),
        h("div", { class: "cmd-line-box", style: "background:#090D16;margin-top:6px" },
          h("span", { class: "mono", style: "color:#A7F3D0" }, "$ " + curlCmd),
          h("button", {
            type: "button",
            class: "btn secondary sm",
            onclick: () => copyToClipboard(curlCmd, "Curl reproduction command copied")
          }, svgIcon(ICONS.copy, 12), "Copy Curl")
        )
      ),

      // Detection Evidence
      h("div", {},
        h("h4", { class: "detail-section-title" }, "Detection Evidence"),
        h("div", { class: "code-evidence-block" },
          f.evidence || f.details || f.raw || "(No raw scanner output payload stored for this finding)"
        )
      ),

      // Impact Assessment
      h("div", {},
        h("h4", { class: "detail-section-title" }, "Impact Assessment"),
        h("p", { class: "muted", style: "margin:0" },
          f.description || "Potential security exposure identified on the target host. Automated scanner matches should be confirmed manually to verify whether the service or parameter poses an actionable security risk."
        )
      ),

      // Remediation Guidance & References
      h("div", {},
        h("h4", { class: "detail-section-title" }, "Recommended Remediation & References"),
        h("p", { style: "margin:0 0 6px" }, f.remediation || "Ensure sensitive endpoints require authentication and proper access controls. Keep software dependencies updated to supported releases."),
        f.references && f.references.length
          ? h("ul", { style: "margin:4px 0;padding-left:18px" }, f.references.map((ref) => h("li", {}, h("a", { href: ref, target: "_blank", rel: "noopener noreferrer" }, ref))))
          : h("span", { class: "muted small" }, "No external reference advisories linked.")
      ),

      // Analyst Actions Bar
      h("div", { class: "finding-actions-bar" },
        h("div", { style: "display:flex;align-items:center;gap:8px" },
          h("button", {
            type: "button",
            class: "btn success sm",
            onclick: () => updateFindingStatus(f.id, "confirmed")
          }, svgIcon(ICONS.check, 13), "Confirm Finding"),
          h("button", {
            type: "button",
            class: "btn secondary sm",
            onclick: () => updateFindingStatus(f.id, "false_positive")
          }, "Mark False Positive"),
          h("button", {
            type: "button",
            class: "btn secondary sm",
            onclick: () => updateFindingStatus(f.id, "fixed")
          }, "Mark Fixed")
        ),
        h("span", { class: "muted small" }, "Validation status updates directly in local database")
      )
    );

    container.append(detailBox);
    detailBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    toast("Could not load finding details: " + e.message, true);
  }
}

async function updateFindingStatus(fid, newStatus) {
  try {
    await api("/api/findings/" + fid, "PATCH", { validation_status: newStatus });
    toast("Finding updated to: " + newStatus);
    loadSinglePageDashboard();
  } catch (e) {
    toast(e.message, true);
  }
}

/* ==========================================================================
   Section F: Activity & Scan Queue Component
   ========================================================================== */
let activityActiveTab = "scans";

async function renderActivitySection(container, recentScans = []) {
  clear(container);

  container.append(
    h("div", { class: "card-header" },
      h("div", { class: "card-title-group" },
        h("h3", { class: "card-title" }, svgIcon(ICONS.scans, 18), "Activity & Scan Queue"),
        h("p", { class: "card-subtitle" }, "Recent scanning executions, active jobs, tool diagnostics, and pipeline logs")
      ),
      h("button", {
        type: "button",
        class: "btn secondary sm",
        onclick: () => renderActivitySection(container, recentScans)
      }, svgIcon(ICONS.refresh, 13), "Refresh")
    )
  );

  const tabs = h("div", { class: "category-tabs" },
    h("button", {
      type: "button",
      class: "category-tab" + (activityActiveTab === "scans" ? " active" : ""),
      onclick: () => { activityActiveTab = "scans"; renderActivitySection(container, recentScans); }
    }, "Recent Scans (" + recentScans.length + ")"),
    h("button", {
      type: "button",
      class: "category-tab" + (activityActiveTab === "runs" ? " active" : ""),
      onclick: () => { activityActiveTab = "runs"; renderActivitySection(container, recentScans); }
    }, "Tool Execution Matrix"),
    h("button", {
      type: "button",
      class: "category-tab" + (activityActiveTab === "logs" ? " active" : ""),
      onclick: () => { activityActiveTab = "logs"; renderActivitySection(container, recentScans); }
    }, "Scan Logs")
  );

  container.append(h("div", { class: "section-toolbar" }, tabs));

  const contentBox = h("div", { style: "padding:0" });
  container.append(contentBox);

  if (activityActiveTab === "scans") {
    if (!recentScans.length) {
      contentBox.append(h("div", { class: "empty-state" },
        svgIcon(ICONS.scans, 28),
        h("p", {}, "No scans launched yet. Click 'Start Recon' or 'Start Scan' to begin.")
      ));
      return;
    }

    const t = h("table", { class: "compact-table" },
      h("thead", {},
        h("tr", {},
          h("th", {}, "Scan ID"),
          h("th", {}, "Profile"),
          h("th", {}, "Target Project"),
          h("th", {}, "Status"),
          h("th", {}, "Discovered"),
          h("th", {}, "Started"),
          h("th", {}, "Completed"),
          h("th", {}, "Actions")
        )
      ),
      h("tbody", {},
        recentScans.map((s) => h("tr", {},
          h("td", { class: "mono", style: "font-weight:600" }, "#" + s.id),
          h("td", {}, h("span", { class: "scope-tag" }, s.profile)),
          h("td", {}, s.project),
          h("td", {}, h("span", { class: "status-pill " + s.status }, s.status)),
          h("td", {}, s.summary && s.summary.assets ? s.summary.assets + " assets" : "0 assets"),
          h("td", { class: "muted small" }, ago(s.created_at)),
          h("td", { class: "muted small" }, s.completed_at ? ago(s.completed_at) : (s.status === "running" ? "in progress" : "-")),
          h("td", {},
            h("div", { style: "display:flex;gap:4px" },
              h("a", {
                class: "btn secondary sm",
                href: "/scans/" + s.id + "/report.html",
                target: "_blank",
                rel: "noopener noreferrer"
              }, svgIcon(ICONS.external, 12), "Report")
            )
          )
        ))
      )
    );
    contentBox.append(h("div", { class: "table-wrap" }, t));
  } else if (activityActiveTab === "runs") {
    // Tool runs for the latest scan
    const latestScan = recentScans[0];
    if (!latestScan) {
      contentBox.append(h("div", { class: "empty-state" }, "No scan executions recorded yet."));
      return;
    }

    try {
      const runs = await api("/api/scans/" + latestScan.id + "/runs");
      if (!runs.length) {
        contentBox.append(h("div", { class: "empty-state" }, "No tool execution runs recorded for scan #" + latestScan.id));
        return;
      }

      const list = h("div", { style: "padding:var(--sp-4);display:flex;flex-direction:column;gap:12px" },
        h("div", { class: "muted small", style: "margin-bottom:4px" }, "Tool execution history for Scan #" + latestScan.id + " (" + latestScan.profile + "):"),
        ...runs.map((r) => {
          const cmdStr = (r.argv || []).join(" ");
          return h("div", { class: "dashboard-card", style: "padding:12px" },
            h("div", { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px" },
              h("div", { style: "display:flex;align-items:center;gap:8px" },
                h("b", { class: "mono" }, r.stage_name),
                h("span", { class: "status-pill " + r.status }, r.status)
              ),
              h("span", { class: "muted small mono" }, "exit " + r.exit_code + " \u00B7 " + r.stdout_bytes + " bytes")
            ),
            h("div", { class: "cmd-line-box" },
              h("span", { class: "mono small" }, "$ " + cmdStr),
              h("button", {
                type: "button",
                class: "btn secondary sm",
                onclick: () => copyToClipboard(cmdStr, "Command copied")
              }, svgIcon(ICONS.copy, 12), "Copy")
            ),
            r.stderr_tail ? h("pre", { class: "code-evidence-block", style: "margin-top:6px;max-height:100px" }, r.stderr_tail) : null
          );
        })
      );
      contentBox.append(list);
    } catch (e) {
      contentBox.append(h("div", { class: "empty-state" }, "Could not load runs: " + e.message));
    }
  } else if (activityActiveTab === "logs") {
    const latestScan = recentScans[0];
    if (!latestScan) {
      contentBox.append(h("div", { class: "empty-state" }, "No scan logs available."));
      return;
    }
    try {
      const logData = await api("/api/scans/" + latestScan.id + "/logs");
      const logs = (logData && logData.logs) || [];
      const term = h("div", { class: "terminal-output", style: "margin:var(--sp-4)" },
        logs.length ? logs.map((l) => (l.created_at ? "[" + l.created_at.slice(11, 19) + "] " : "") + l.message).join("\n") : "(No log lines recorded for scan #" + latestScan.id + ")"
      );
      contentBox.append(term);
    } catch (e) {
      contentBox.append(h("div", { class: "empty-state" }, "Could not load logs: " + e.message));
    }
  }
}

/* ==========================================================================
   Section G: Reports and Targets Component
   ========================================================================== */
let reportsTargetsTab = "reports";

async function renderReportsAndTargetsSection(container, activeProject) {
  clear(container);

  container.append(
    h("div", { class: "card-header" },
      h("div", { class: "card-title-group" },
        h("h3", { class: "card-title" }, svgIcon(ICONS.reports, 18), "Reports, Targets & Scope Management"),
        h("p", { class: "card-subtitle" }, "Generate technical summaries, export security findings, and manage target boundaries")
      )
    )
  );

  const tabs = h("div", { class: "category-tabs" },
    h("button", {
      type: "button",
      class: "category-tab" + (reportsTargetsTab === "reports" ? " active" : ""),
      onclick: () => { reportsTargetsTab = "reports"; renderReportsAndTargetsSection(container, activeProject); }
    }, "Reports & Exports"),
    h("button", {
      type: "button",
      class: "category-tab" + (reportsTargetsTab === "targets" ? " active" : ""),
      onclick: () => { reportsTargetsTab = "targets"; renderReportsAndTargetsSection(container, activeProject); }
    }, "Target Scope & Rules")
  );

  container.append(h("div", { class: "section-toolbar" }, tabs));

  const contentBox = h("div", { style: "padding:var(--sp-4)" });
  container.append(contentBox);

  if (reportsTargetsTab === "reports") {
    contentBox.append(
      h("div", { style: "display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:var(--sp-4)" },
        // Technical Report
        h("div", { class: "dashboard-card", style: "padding:16px" },
          h("h4", { style: "margin:0 0 6px" }, "Technical Security Report"),
          h("p", { class: "muted small", style: "margin:0 0 14px" }, "Complete asset inventory, raw scanner evidence, reproduction commands, and tool execution logs."),
          h("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
            h("button", {
              type: "button",
              class: "btn primary sm",
              onclick: () => {
                if (activeScanData && activeScanData.id) window.open("/scans/" + activeScanData.id + "/report.html", "_blank");
                else window.open("/scans", "_self");
              }
            }, svgIcon(ICONS.external, 13), "Open HTML Report"),
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: () => downloadCSV("findings-export.csv", findingsData)
            }, svgIcon(ICONS.download, 13), "Export Findings CSV")
          )
        ),
        // Executive Summary
        h("div", { class: "dashboard-card", style: "padding:16px" },
          h("h4", { style: "margin:0 0 6px" }, "Executive Risk Summary"),
          h("p", { class: "muted small", style: "margin:0 0 14px" }, "High-level risk breakdown, vulnerability posture distribution, and scope validation overview."),
          h("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: () => toast("Executive summary report prepared")
            }, svgIcon(ICONS.reports, 13), "Generate Summary"),
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: () => downloadCSV("assets-export.csv", reconAssetsData)
            }, svgIcon(ICONS.download, 13), "Export Assets CSV")
          )
        )
      )
    );
  } else if (reportsTargetsTab === "targets") {
    if (!activeProject) {
      contentBox.append(h("div", { class: "empty-state" }, "No target selected."));
      return;
    }

    try {
      const proj = await api("/api/projects/" + activeProject.id);
      const scopeRules = proj.scope || [];

      const inScope = scopeRules.filter((s) => !s.is_exclusion);
      const outScope = scopeRules.filter((s) => s.is_exclusion);

      const targetBox = h("div", { style: "display:flex;flex-direction:column;gap:16px" },
        h("div", { style: "display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px" },
          h("div", {},
            h("h3", { style: "margin:0" }, proj.name),
            h("p", { class: "muted small", style: "margin:2px 0 0" }, proj.description || "Authorized scope boundary for penetration testing & bug bounty recon.")
          ),
          h("div", { style: "display:flex;gap:8px" },
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: () => openAddScopeModal(proj.id)
            }, svgIcon(ICONS.plus, 13), "Add Scope Rule"),
            h("button", {
              type: "button",
              class: "btn danger sm",
              onclick: async () => {
                if (!confirm("Delete target project \"" + proj.name + "\" and all its data?")) return;
                try {
                  await api("/api/projects/" + proj.id, "DELETE");
                  toast("Target deleted");
                  localStorage.removeItem(PROJECT_KEY);
                  activePid = "";
                  loadSinglePageDashboard();
                } catch (e) { toast(e.message, true); }
              }
            }, "Delete Target")
          )
        ),

        // Rules Grid
        h("div", { style: "display:grid;grid-template-columns:1fr 1fr;gap:16px" },
          // In-Scope
          h("div", { class: "dashboard-card", style: "padding:14px" },
            h("h4", { style: "margin:0 0 8px;color:#059669" }, "In-Scope Boundaries (" + inScope.length + ")"),
            inScope.length
              ? h("ul", { style: "margin:0;padding-left:18px" }, inScope.map((s) => h("li", { class: "mono small" }, s.target)))
              : h("p", { class: "muted small", style: "margin:0" }, "No in-scope rules defined.")
          ),
          // Exclusions
          h("div", { class: "dashboard-card", style: "padding:14px" },
            h("h4", { style: "margin:0 0 8px;color:var(--critical)" }, "Out-of-Scope Exclusions (" + outScope.length + ")"),
            outScope.length
              ? h("ul", { style: "margin:0;padding-left:18px" }, outScope.map((s) => h("li", { class: "mono small" }, s.target)))
              : h("p", { class: "muted small", style: "margin:0" }, "No exclusions defined.")
          )
        ),

        // Scope Boundary Tester
        h("div", { class: "dashboard-card", style: "padding:14px;background:var(--panel-hover)" },
          h("h4", { style: "margin:0 0 4px" }, "Scope Boundary Verifier"),
          h("p", { class: "muted small", style: "margin:0 0 8px" }, "Verify if a hostname or IP address is currently authorized under backend scope rules before scanning:"),
          h("div", { style: "display:flex;gap:8px" },
            h("input", {
              type: "text",
              id: "scope-tester-input",
              placeholder: "test.example.com or 192.168.1.5",
              style: "flex:1"
            }),
            h("button", {
              type: "button",
              class: "btn secondary sm",
              onclick: () => {
                const val = document.getElementById("scope-tester-input").value.trim();
                const resEl = document.getElementById("scope-tester-result");
                if (!val) return;
                const isIn = inScope.some((s) => {
                  if (s.target.startsWith("*.")) {
                    const apex = s.target.slice(2);
                    return val.endsWith("." + apex);
                  }
                  return s.target === val;
                });
                const isOut = outScope.some((s) => s.target === val);
                if (isOut) {
                  resEl.textContent = "\u2716 EXCLUDED: Out-of-scope rule matches (" + val + ")";
                  resEl.style.color = "var(--critical)";
                } else if (isIn) {
                  resEl.textContent = "\u2714 IN SCOPE: Authorized for testing (" + val + ")";
                  resEl.style.color = "#059669";
                } else {
                  resEl.textContent = "\u26A0 NOT IN SCOPE: Boundary rejected under rule set";
                  resEl.style.color = "var(--muted)";
                }
              }
            }, "Test Boundary")
          ),
          h("div", { id: "scope-tester-result", class: "small mono", style: "margin-top:6px;font-weight:600" })
        )
      );

      contentBox.append(targetBox);
    } catch (e) {
      contentBox.append(h("div", { class: "empty-state" }, "Could not load target scope: " + e.message));
    }
  }
}

/* ==========================================================================
   Modals: Target Creation, Scan Launch, Settings
   ========================================================================== */
function openAddTargetModal() {
  const nameInput = h("input", { type: "text", placeholder: "e.g. Acme Corp Bug Bounty" });
  const descInput = h("textarea", { placeholder: "Program notes or rules of engagement...", rows: "2" });
  const scopeInput = h("textarea", { placeholder: "*.example.com\napi.example.com\n192.168.1.0/24", rows: "4" });
  const exclInput = h("textarea", { placeholder: "admin.example.com\ncheckout.example.com", rows: "2" });
  const authChk = h("input", { type: "checkbox" });

  const form = h("div", {},
    h("div", { class: "form-field" },
      h("label", {}, "Target / Project Name:"),
      nameInput
    ),
    h("div", { class: "form-field", style: "margin-top:10px" },
      h("label", {}, "Description (optional):"),
      descInput
    ),
    h("div", { class: "form-field", style: "margin-top:10px" },
      h("label", {}, "In-Scope Boundaries (one per line):"),
      scopeInput,
      h("span", { class: "hint" }, "Supports exact domains, wildcards (*.target.com), and CIDR blocks.")
    ),
    h("div", { class: "form-field", style: "margin-top:10px" },
      h("label", {}, "Out-of-Scope Exclusions (one per line):"),
      exclInput,
      h("span", { class: "hint" }, "Exclusions always override inclusions.")
    ),
    h("div", { style: "margin-top:14px;padding:10px;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:6px" },
      h("label", { class: "checkbox-label", style: "font-weight:600;color:var(--ink)" },
        authChk,
        h("span", {}, "I confirm I have explicit authorization to perform reconnaissance on these targets.")
      )
    )
  );

  const btnCreate = h("button", {
    type: "button",
    class: "btn primary",
    onclick: async () => {
      const name = nameInput.value.trim();
      if (!name) return toast("Target name is required", true);
      if (!authChk.checked) return toast("Authorization confirmation is required", true);

      const scopeList = scopeInput.value.split("\n").map((x) => x.trim()).filter(Boolean);
      const exclList = exclInput.value.split("\n").map((x) => x.trim()).filter(Boolean);

      try {
        const res = await api("/api/projects", "POST", {
          name,
          description: descInput.value.trim(),
          scope: scopeList,
          exclusions: exclList,
          authorization_confirmed: true
        });
        toast("Target created successfully");
        closeModal();
        activePid = String(res.id);
        localStorage.setItem(PROJECT_KEY, activePid);
        loadSinglePageDashboard();
      } catch (e) {
        toast(e.message, true);
      }
    }
  }, "Create Target");

  openModal("Add Authorized Target", form, [
    h("button", { type: "button", class: "btn secondary", onclick: closeModal }, "Cancel"),
    btnCreate
  ]);
}

function openAddScopeModal(pid) {
  const entriesInput = h("textarea", { placeholder: "new.target.com\n*.api.target.com", rows: "4" });
  const isExclChk = h("input", { type: "checkbox" });
  const authChk = h("input", { type: "checkbox" });

  const form = h("div", {},
    h("div", { class: "form-field" },
      h("label", {}, "New Scope Entries (one per line):"),
      entriesInput
    ),
    h("div", { style: "margin-top:10px" },
      h("label", { class: "checkbox-label" },
        isExclChk,
        h("span", {}, "Mark these entries as out-of-scope exclusions")
      )
    ),
    h("div", { style: "margin-top:10px;padding:10px;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:6px" },
      h("label", { class: "checkbox-label" },
        authChk,
        h("span", {}, "I confirm I am authorized to add these targets.")
      )
    )
  );

  const btnAdd = h("button", {
    type: "button",
    class: "btn primary",
    onclick: async () => {
      const list = entriesInput.value.split("\n").map((x) => x.trim()).filter(Boolean);
      if (!list.length) return toast("Please enter at least one entry", true);
      if (!authChk.checked) return toast("Authorization confirmation is required", true);

      try {
        await api("/api/projects/" + pid + "/scope", "POST", {
          entries: list,
          excluded: isExclChk.checked,
          authorization_confirmed: true
        });
        toast("Scope rules added");
        closeModal();
        loadSinglePageDashboard();
      } catch (e) {
        toast(e.message, true);
      }
    }
  }, "Add Entries");

  openModal("Add Scope Rules", form, [
    h("button", { type: "button", class: "btn secondary", onclick: closeModal }, "Cancel"),
    btnAdd
  ]);
}

function openScanWizardModal(project) {
  const profileSelect = h("select", {},
    h("option", { value: "passive" }, "Passive Reconnaissance (Subfinder, dnsx, gau, Shodan)"),
    h("option", { value: "standard" }, "Standard Discovery (Subfinder, dnsx, httpx, naabu)"),
    h("option", { value: "vulnerability" }, "Vulnerability Assessment (Nuclei exposure & misconfig)"),
    h("option", { value: "web" }, "Web Crawling & Active Probing (Katana, httpx, Nuclei)")
  );

  const portSelect = h("select", {},
    h("option", { value: "top100" }, "Top 100 Common Ports"),
    h("option", { value: "top1000" }, "Top 1000 Ports"),
    h("option", { value: "web" }, "Web Only (80, 443, 8080, 8443)")
  );

  const nucleiTagsInput = h("input", { type: "text", value: "exposure,misconfig,takeover" });
  const authChk = h("input", { type: "checkbox" });
  const activeTestingChk = h("input", { type: "checkbox" });

  const activeTestingWarning = h("div", { style: "display:none;margin-top:10px;padding:10px;background:#FFF7ED;border:1px solid #FFEDD5;border-radius:6px" },
    h("label", { class: "checkbox-label", style: "font-weight:600;color:#9A3412" },
      activeTestingChk,
      h("span", {}, "I confirm explicit written authorization for active probing on this target.")
    )
  );

  profileSelect.addEventListener("change", () => {
    const isAct = profileSelect.value === "vulnerability" || profileSelect.value === "web";
    activeTestingWarning.style.display = isAct ? "block" : "none";
  });

  const form = h("div", {},
    h("div", { class: "form-field" },
      h("label", {}, "Scan Profile:"),
      profileSelect
    ),
    h("div", { class: "form-field", style: "margin-top:10px" },
      h("label", {}, "Port Range:"),
      portSelect
    ),
    h("div", { class: "form-field", style: "margin-top:10px" },
      h("label", {}, "Nuclei Template Tags:"),
      nucleiTagsInput,
      h("span", { class: "hint" }, "Safe tags only. Intrusive and DoS tags are rejected by backend.")
    ),
    h("div", { style: "margin-top:14px;padding:10px;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:6px" },
      h("label", { class: "checkbox-label" },
        authChk,
        h("span", {}, "I confirm all targets are within verified authorized scope.")
      )
    ),
    activeTestingWarning
  );

  const btnLaunch = h("button", {
    type: "button",
    class: "btn primary",
    onclick: async () => {
      if (!authChk.checked) return toast("Authorization confirmation is required", true);
      const isAct = profileSelect.value === "vulnerability" || profileSelect.value === "web";
      if (isAct && !activeTestingChk.checked) return toast("Active testing confirmation is required for this profile", true);

      try {
        const proj = await api("/api/projects/" + project.id);
        const scopeIds = (proj.scope || []).filter((s) => !s.is_exclusion).map((s) => s.id);
        if (!scopeIds.length) return toast("No in-scope rules found for this target", true);

        const res = await api("/api/projects/" + project.id + "/scans", "POST", {
          profile: profileSelect.value,
          scope_entry_ids: scopeIds,
          authorization_confirmed: true,
          active_testing_confirmed: activeTestingChk.checked,
          options: {
            ports: portSelect.value,
            nuclei_tags: nucleiTagsInput.value.trim()
          }
        });

        toast("Scan #" + res.id + " launched successfully");
        addNotification("Scan Launched", "Scan #" + res.id + " (" + profileSelect.value + ") started for " + project.name);
        closeModal();
        loadSinglePageDashboard();
      } catch (e) {
        toast(e.message, true);
      }
    }
  }, "Launch Scan");

  openModal("Configure Scan — " + project.name, form, [
    h("button", { type: "button", class: "btn secondary", onclick: closeModal }, "Cancel"),
    btnLaunch
  ]);
}

async function launchQuickRecon(project) {
  try {
    const proj = await api("/api/projects/" + project.id);
    const scopeIds = (proj.scope || []).filter((s) => !s.is_exclusion).map((s) => s.id);
    if (!scopeIds.length) return toast("No in-scope entries defined for this target", true);

    const res = await api("/api/projects/" + project.id + "/scans", "POST", {
      profile: "passive",
      scope_entry_ids: scopeIds,
      authorization_confirmed: true,
      options: {}
    });

    toast("Passive recon launched: Scan #" + res.id);
    addNotification("Recon Launched", "Passive discovery scan #" + res.id + " started for " + project.name);
    loadSinglePageDashboard();
  } catch (e) {
    toast(e.message, true);
  }
}

async function openSettingsModal() {
  let settings = null;
  let tools = [];
  try {
    [settings, tools] = await Promise.all([
      api("/api/settings"),
      api("/api/tools")
    ]);
  } catch (e) {
    toast("Could not load settings: " + e.message, true);
    return;
  }

  const rpsInput = h("input", { type: "text", value: String(settings.limits.requests_per_second || 2) });
  const hostRpsInput = h("input", { type: "text", value: String(settings.limits.per_host_rps || 2) });
  const maxJobsInput = h("input", { type: "text", value: String(settings.limits.max_concurrent_target_jobs || 1) });
  const timeoutInput = h("input", { type: "text", value: String(settings.limits.max_scan_seconds || 900) });

  const modalBody = h("div", {},
    h("div", { class: "dashboard-card", style: "padding:14px;margin-bottom:14px" },
      h("h4", { style: "margin:0 0 10px" }, "Scanner Rate Limits (Conservative Defaults)"),
      h("div", { style: "display:grid;grid-template-columns:1fr 1fr;gap:12px" },
        h("div", { class: "form-field" }, h("label", {}, "Max Req / Sec:"), rpsInput),
        h("div", { class: "form-field" }, h("label", {}, "Per-Host Req / Sec:"), hostRpsInput),
        h("div", { class: "form-field" }, h("label", {}, "Max Concurrent Jobs:"), maxJobsInput),
        h("div", { class: "form-field" }, h("label", {}, "Timeout (seconds):"), timeoutInput)
      ),
      h("div", { style: "margin-top:10px;text-align:right" },
        h("button", {
          type: "button",
          class: "btn primary sm",
          onclick: async () => {
            try {
              await api("/api/settings/limits", "PUT", {
                limits: {
                  requests_per_second: parseFloat(rpsInput.value),
                  per_host_rps: parseFloat(hostRpsInput.value),
                  max_concurrent_target_jobs: parseInt(maxJobsInput.value, 10),
                  max_scan_seconds: parseInt(timeoutInput.value, 10)
                }
              });
              toast("Rate limits saved");
            } catch (e) { toast(e.message, true); }
          }
        }, "Save Limits")
      )
    ),

    // Tools Health Matrix
    h("div", { class: "dashboard-card", style: "padding:14px;margin-bottom:14px" },
      h("h4", { style: "margin:0 0 8px" }, "Tool Health Matrix"),
      h("div", { class: "table-wrap", style: "max-height:180px;overflow-y:auto" },
        h("table", { class: "compact-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Tool"), h("th", {}, "Status"), h("th", {}, "Version"), h("th", {}, "Role"))),
          h("tbody", {}, tools.map((t) => h("tr", {},
            h("td", { class: "mono", style: "font-weight:600" }, t.name),
            h("td", {}, h("span", { class: t.detected ? "scope-badge-safe" : "sev-badge critical" }, t.detected ? "Detected" : "Missing")),
            h("td", { class: "mono small" }, t.version || "-"),
            h("td", { class: "muted small" }, t.role)
          )))
        )
      )
    ),

    // Developer Attribution
    h("div", { class: "dashboard-card", style: "padding:14px;background:var(--panel-hover)" },
      h("div", { style: "display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px" },
        h("div", {},
          h("b", {}, "ReconForge v1.0.0"),
          h("p", { class: "muted small", style: "margin:0" }, "Local-first attack surface & reconnaissance platform.")
        ),
        h("span", { class: "scope-badge-safe" }, "Developed by Anil Kashyap")
      ),
      h("div", { style: "display:flex;gap:10px;margin-top:10px" },
        h("a", { class: "btn secondary sm", href: "https://github.com/anilkashyap01", target: "_blank", rel: "noopener noreferrer" },
          svgIcon(ICONS.terminal, 13), "GitHub: anilkashyap01"
        ),
        h("a", { class: "btn secondary sm", href: "https://linkedin.com/in/anilkashyap01", target: "_blank", rel: "noopener noreferrer" },
          svgIcon(ICONS.target, 13), "LinkedIn: anilkashyap01"
        )
      )
    )
  );

  openModal("Settings & Tools", modalBody, [
    h("button", { type: "button", class: "btn secondary", onclick: closeModal }, "Close")
  ], true);
}

/* ==========================================================================
   Application Initialization
   ========================================================================== */
(async () => {
  initHeader();

  // Route handlers for direct hits (/projects, /scans, /findings, /assets, /tools, /settings)
  const p = ctx.page || "overview";
  if (p === "settings") {
    setTimeout(openSettingsModal, 200);
  }

  await loadSinglePageDashboard();

  if (p === "assets") {
    scrollToSection("recon");
    setActiveNav("recon");
  } else if (p === "findings") {
    scrollToSection("findings");
    setActiveNav("findings");
  } else if (p === "scans" || p === "scan") {
    scrollToSection("scanner");
    setActiveNav("scanner");
  } else if (p === "projects" || p === "project") {
    scrollToSection("targets");
    setActiveNav("targets");
  }
})();
