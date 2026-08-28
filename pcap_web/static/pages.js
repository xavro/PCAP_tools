/* Pages StratusServer v2 — navigation partagée (tiroir identique à la console) + helpers. */
(() => {
  "use strict";
  const BASE = location.pathname.replace(/[^/]*$/, "");          // "/" ou "/console/"
  const ROOT = BASE.replace(/api\/$/, "").replace(/console\/$/, "");   // racine des pages v2 (/api/docs, /console/… → /)
  const U = p => ROOT + String(p).replace(/^\//, "");
  const $ = id => document.getElementById(id);
  const api = async (p, opt) => { const r = await fetch(U(p), opt); const j = await r.json().catch(() => ({})); if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status)); return j; };
  const hhmm = t => t ? new Date(t * 1000).toISOString().slice(11, 16) + "Z" : "—";
  const ymd = t => t ? new Date(t * 1000).toISOString().slice(0, 10) : "—";
  const dur = s => s == null ? "—" : s >= 3600 ? `${Math.floor(s / 3600)}h${String(Math.floor(s % 3600 / 60)).padStart(2, "0")}` : s >= 60 ? `${Math.floor(s / 60)}m${String(Math.round(s % 60)).padStart(2, "0")}` : `${Math.round(s)}s`;
  const size = b => b >= 1e9 ? (b / 1e9).toFixed(2) + " Go" : b >= 1e6 ? (b / 1e6).toFixed(0) + " Mo" : (b / 1e3).toFixed(0) + " Ko";

  // ── tiroir ──
  const page = document.body.dataset.page || "";
  const NAV = [
    ["missions", "Missions", "captures, relecture, GPX", "M3 4h18v4H3zM4 9h16v11H4zM9 12h6"],
    ["console", "Console pcap", "analyse, rejeu, écoute, banc GMTI", "M4 6l6 6-6 6M12 18h8"],
    ["replay", "Relecture", "page opérateur : carte, vidéo, barre de temps", "M5 4l14 8-14 8z"],
    ["docs", "Documentation API", "endpoints v2 : capture, suivi, live, GMTI", "M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 0-3 3zM5 4v16M8 9h8M8 13h8"],
    ["health", "Health Check", "état des services", "M12 21s-7-4.5-9-9a5 5 0 0 1 9-3 5 5 0 0 1 9 3c-2 4.5-9 9-9 9z"]
  ];
  const HREF = { missions: "missions", console: "", replay: "replay", docs: "api/docs", health: "health" };   // console pcap = racine du serveur de relecture
  const nav = document.createElement("div");
  nav.innerHTML = `<div class="stx-drawer-backdrop" id="stx-backdrop" hidden></div>
  <aside class="stx-drawer" id="stx-drawer" aria-hidden="true">
    <div class="stx-drawer-head"><img src="${U("static/stratus.png")}" alt=""><div><b>StratusServer</b><small>v2 · STANAG 4609 · 4607</small></div><button type="button" class="stx-close" id="stx-close" aria-label="Fermer">✕</button></div>
    <ul class="stx-links">${NAV.map(([k, t, s, d]) => `<li><a href="${U(HREF[k])}" class="${k === page ? "is-active" : ""}"><svg viewBox="0 0 24 24"><path d="${d}" fill="none" stroke="currentColor" stroke-width="2"/></svg> ${t} <small>${s}</small></a></li>`).join("")}</ul>
    <div class="stx-drawer-foot"><a href="${U("api/health")}">&lt;/&gt; /api/health</a><a href="${U("api/missions")}">⌖ /api/missions</a><a href="${U("api/capture/status")}">● /api/capture/status</a></div>
  </aside>`;
  document.body.appendChild(nav);
  const burger = $("stx-burger"), drawer = $("stx-drawer"), backdrop = $("stx-backdrop");
  const open = on => { drawer.classList.toggle("open", on); backdrop.hidden = !on; burger.setAttribute("aria-expanded", on ? "true" : "false"); drawer.setAttribute("aria-hidden", on ? "false" : "true"); };
  burger.addEventListener("click", () => open(!drawer.classList.contains("open")));
  $("stx-close").addEventListener("click", () => open(false)); backdrop.addEventListener("click", () => open(false));
  document.addEventListener("keydown", e => { if (e.key === "Escape") open(false); });

  // ── état de l'API (chip) ──
  const apiChip = $("api-chip");
  const ping = async () => { try { await api("/api/config"); apiChip.className = "pg-chip"; apiChip.innerHTML = '<span class="dot ok"></span> API en ligne'; } catch (e) { apiChip.innerHTML = '<span class="dot err"></span> API hors ligne'; } };
  if (apiChip) { ping(); setInterval(ping, 15000); }

  window.STX = { U, api, hhmm, ymd, dur, size, $ };
})();
