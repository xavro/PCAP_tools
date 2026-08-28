/* app.js — console web : vidéo 4609 (mpegts.js) + KLV 0601 synchronisés + carte Leaflet
   + rejeu UDP réel (moteur pcap_replay) piloté en HTTP, événements par WebSocket. */
(function () {
  "use strict";
  // Contrat DOM tolérant : un élément absent de la page (page opérateur replay.html, qui n'embarque pas
  // les panneaux d'analyse) est remplacé par un élément détaché — le moteur reste identique.
  const _dummies = {}, _dummyRoot = document.createElement("div");           // conteneur détaché : parentElement/closest valides
  const $ = id => document.getElementById(id) || (_dummies[id] || (_dummies[id] = _dummyRoot.appendChild(Object.assign(document.createElement("div"), { id }))));
  const OP = document.body.classList.contains("operator");
  const video = $("video");
  // Relocalisable : la page peut être servie à la racine (http://hôte:8765/) ou sous un préfixe derrière
  // un reverse proxy (https://stratus/console/) → toutes les URL sont relatives à BASE (dossier de la page).
  const BASE = location.pathname.replace(/[^/]*$/, "");
  const U = p => BASE + String(p).replace(/^\//, "");
  const WS = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + BASE.replace(/\/$/, "");
  // Navigation StratusServer : seulement si la console est servie sous un préfixe (/console/) ; liens relatifs (../)
  if (BASE !== "/") {
    const fav = $("favicon"); if (fav) fav.href = BASE + "../static/images/favicon.ico";   // favicon StratusServer
    const logo = document.querySelector(".stx-drawer-head img"); if (logo) { logo.onerror = () => { logo.onerror = null; logo.src = U("static/stratus.png"); }; logo.src = BASE + "../static/images/Stratus%20Server.png"; }
  }
  if (!document.body.classList.contains("operator")) {   // tiroir de la console (la page opérateur utilise celui de pages.js) : pages v2 (racine) ou pages du serveur parent (/console/)
    const burger = $("stx-burger"), drawer = $("stx-drawer"), backdrop = $("stx-backdrop");
    burger.hidden = false;
    const root = BASE === "/" ? "" : "../";
    drawer.querySelectorAll("a[data-page]").forEach(a => { const k = a.dataset.page; a.href = k === "console" ? "./" : (k === "missions" ? (BASE === "/" ? "missions" : "../") : root + ({ docs: "api/docs", health: "health" }[k])); });
    drawer.querySelectorAll(".stx-drawer-foot a[data-api]").forEach(a => { a.href = root + a.dataset.api; });
    const open = on => { drawer.classList.toggle("open", on); backdrop.hidden = !on; burger.setAttribute("aria-expanded", on ? "true" : "false"); drawer.setAttribute("aria-hidden", on ? "false" : "true"); };
    burger.addEventListener("click", () => open(!drawer.classList.contains("open")));
    $("stx-close").addEventListener("click", () => open(false)); backdrop.addEventListener("click", () => open(false));
    document.addEventListener("keydown", e => { if (e.key === "Escape") open(false); });
  }
  const state = { cfg: null, pcap: "", streams: [], cur: null, track: null, player: null,
    mode: "file", sets: [], applied: -1, tableAt: 0, flows: [], flowsDur: 0, replay: null,
    bmLayer: null, bmOverlay: null, bmCfg: null, evws: null, log: [], retries: 0, seeking: false, videoOn: false, emitting: false };

  const status = (msg, warn) => { const s = $("status"); s.textContent = msg; s.style.color = warn ? "var(--warn)" : ""; s.title = msg; };
  // Pastille d'état de lecture/rejeu (barre sous l'en-tête) : ■ arrêt · ▶ lecture · ● rejeu + émission · ⏸ pause
  function setState(kind, text) { const el = $("sb-state"); el.className = "sb-state " + kind; el.textContent = text; }
  // ── Écoute réseau (live) : source, flux découverts, suivi à chaud ─────────────
  const lv = { on: false, checked: new Set(), keys: "", ifaces: [] };
  const isLive = () => $("source").value === "live";
  function liveUi() {
    const on = isLive();
    document.body.classList.toggle("live-mode", on);
    $("live-ctl").hidden = !on; $("live-opts").hidden = !on || !lv.optsOpen;
    $("btn-play").textContent = on ? "▶ Écouter" : "▶ Lire";
    if (on && !lv.ifaces.length) api("/api/live/ifaces").then(r => { lv.ifaces = r.ifaces || []; const sel = $("live-iface"); sel.innerHTML = "";
      r.ifaces.forEach(i => { const o = document.createElement("option"); o.value = i.name; o.dataset.ip = i.ip || ""; o.textContent = i.ip && i.ip !== i.name ? `${i.name} (${i.ip})` : i.name; sel.appendChild(o); });
      const o = document.createElement("option"); o.value = ""; o.textContent = "(toutes / auto)"; sel.insertBefore(o, sel.firstChild); sel.value = "";
      status(`écoute réseau : ${r.raw_hint}`); }).catch(e => status("interfaces : " + e.message, true));
    if (on) { $("flows-body").innerHTML = `<tr><td class="muted">▶ Écouter : les flux reçus apparaissent ici au fil de l'eau.</td></tr>`; $("replay-sum").textContent = "écoute arrêtée"; }
    drawTimeline();
  }
  function liveRecord() {
    if (!$("live-rec").checked) return null;
    return { dir: $("live-rec-dir").value.trim() || null, max_mb: parseInt($("live-rec-mb").value, 10) || 200, keep: parseInt($("live-rec-keep").value, 10) || 5 };
  }
  async function liveStart() {
    stopPlayer(); playbackStop();
    const iface = $("live-iface").value || null; const opt = $("live-iface").selectedOptions[0]; const ip = opt && opt.dataset.ip || null;
    const groups = $("live-groups").value.split(",").map(s => s.trim()).filter(Boolean);
    const ports = $("live-ports").value.split(",").map(s => parseInt(s, 10)).filter(n => n > 0);
    const track = $("gmti-live").checked ? { profile: $("gmti-profile").value || "defaut", overrides: gs.ov } : null;
    state.log = []; $("replay-log").textContent = ""; resetCot(); resetGmti(); resetLive(); fitOnce = false; state.retries = 0;
    lv.checked = new Set(); lv.keys = ""; state.flows = []; state.cur = null; state.videoOn = false; state.emitting = false; state.mode = "replay";
    try {
      const st = await withBusy("démarrage de l'écoute réseau…", () => api("/api/live/start", { iface: iface || null, ip: ip || null,
        groups, ports, backend: $("live-backend").value, record: liveRecord(), taps: [], watch: null, track }), ["btn-play"]);
      lv.on = true; state.replay = st; renderReplay();
      status(`écoute réseau active (${st.mode || ""})${st.recording ? " · enregistrement " + st.recording : ""}${track && !st.track ? " · pistage indisponible (voir journal)" : ""}`);
      $("mode-badge").textContent = "● ÉCOUTE RÉSEAU — cliquer un flux vidéo pour le lire"; $("mode-badge").className = "overlay live";
      if (track && st.track) { showTab("gmti"); $("gmti-live-body").textContent = `pistage temps réel actif — profil ${track.profile}`; }
    } catch (e) { status("écoute : " + e.message, true); }
  }
  async function liveStop() {
    lv.on = false; stopPlayer();
    try { const st = await api("/api/live/stop", {}); if (st.rec_files && st.rec_files.length) { status(`écoute arrêtée — enregistrement : ${st.rec_files[st.rec_files.length - 1]}`); $("pcap").value = st.rec_files[st.rec_files.length - 1]; } else status("écoute arrêtée"); }
    catch (e) { status("arrêt écoute : " + e.message, true); }
    setState("stopped", "■ arrêt");
  }
  async function liveFollow(patch) {
    if (!lv.on) return;
    try { await api("/api/live/follow", patch); } catch (e) { status("suivi : " + e.message, true); }
  }
  function liveWatchList() {   // coché = suivi ; rien coché → tout
    const all = state.flows.map(f => `${f.proto.toLowerCase()}/${f.dport}`);
    const sel = all.filter(k => lv.checked.has(k));
    return sel.length ? sel : all;
  }
  async function liveTap(fl) {
    if (!(fl.proto === "UDP" && /MPEG/.test(fl.dominant))) return;
    state.cur = { dport: fl.dport, dst: (fl.dsts || [])[0] || "", duration_s: 0 };
    state.videoOn = true; state.retries = 0;
    await liveFollow({ taps: [fl.dport] });               // le suivi (coches) est inchangé : seule la vidéo est tapée
    $("video-wrap").hidden = false; $("right").style.gridTemplateRows = ""; setTimeout(() => map.invalidateSize(), 50);
    startPlayer(`${WS}/ws/video?dport=${fl.dport}`, true); showTab("fmv"); markTapRow();
    status(`vidéo live : udp/${fl.dport}`);
  }
  function liveFlows(rows) {
    if (!rows) return;
    state.flows = rows.map(r => Object.assign({}, r, { live: true }));
    const keys = state.flows.map(f => `${f.proto.toLowerCase()}/${f.dport}`).join("|");
    if (keys !== lv.keys) { lv.keys = keys; renderFlows(); renderLiveInventory(); }
    else document.querySelectorAll("#flows-body tr[data-i]").forEach(tr => { const f = state.flows[tr.dataset.i]; const c = tr.querySelector(".cnt"); if (c) c.textContent = f.pkts; const rt = tr.querySelector(".rate"); if (rt) rt.textContent = liveRate(f); });
    $("replay-sum").textContent = `● écoute — ${state.flows.length} flux · t=${((state.replay && state.replay.t) || 0).toFixed(0)} s`;
  }
  const liveRate = f => f.rate >= 1000 ? `${(f.rate / 1000).toFixed(1)} Mb/s` : `${(f.rate || 0).toFixed(0)} kb/s`;
  function renderLiveInventory() {
    const body = $("inv-body"); body.innerHTML = "";
    const vids = state.flows.filter(f => f.proto === "UDP" && /MPEG/.test(f.dominant));
    $("inv-sum").textContent = `${vids.length} flux TS`;
    if (!vids.length) { body.innerHTML = `<div class="muted">aucun flux MPEG-TS reçu pour l'instant.</div>`; return; }
    vids.forEach(s => {
      const d = document.createElement("div"); d.className = "stream" + (state.cur && state.cur.dport === s.dport ? " sel" : "");
      d.innerHTML = `<div class="hd">UDP → ${(s.dsts || []).join(", ")}:${s.dport}</div><div>${(s.bytes / 1e6).toFixed(1)} Mo · ${s.pkts} datagrammes · ${liveRate(s)} · de ${(s.srcs || []).join(", ")}</div><div class="muted">clic = lecture (KLV décodé dans le navigateur)</div>`;
      d.onclick = () => liveTap(s);
      body.appendChild(d);
    });
  }
  const fmt = (v, d = 5) => (v == null || isNaN(v)) ? "—" : Number(v).toFixed(d);
  const utc = us => us ? new Date(us / 1000).toISOString().replace("T", " ").replace("Z", "") : "—";
  // ── Indicateur d'activité (barre + pastille), compteur d'opérations en cours ──
  let busyN = 0; const busyStack = [];
  function busy(label) {
    busyN++; busyStack.push(label || "en cours…");
    $("busy-txt").textContent = busyStack[busyStack.length - 1]; $("busy").hidden = false; $("busybar").hidden = false; document.body.classList.add("is-busy");
    let done = false;
    return () => { if (done) return; done = true; busyN = Math.max(0, busyN - 1); const i = busyStack.indexOf(label || "en cours…"); if (i >= 0) busyStack.splice(i, 1);
      if (busyN === 0) { $("busy").hidden = true; $("busybar").hidden = true; document.body.classList.remove("is-busy"); } else $("busy-txt").textContent = busyStack[busyStack.length - 1]; };
  }
  async function withBusy(label, fn, disable = []) {
    const end = busy(label); disable.forEach(id => { const b = $(id); if (b) b.disabled = true; });
    try { return await fn(); } finally { end(); disable.forEach(id => { const b = $(id); if (b) b.disabled = false; }); }
  }
  async function download(url, filename, label) {
    return withBusy(label || "export…", async () => {
      const r = await fetch(U(url)); if (!r.ok) { let m = r.statusText; try { m = (await r.json()).error || m; } catch (e) {} throw new Error(m); }
      const blob = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    });
  }
  const api = async (url, body) => {
    const r = await fetch(U(url), body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
    const j = await r.json(); if (j.error) throw new Error(j.error); return j;
  };

  // panneaux repliables (Rejeu) + onglets par source
  document.querySelectorAll("#left .panel h2").forEach(h => h.addEventListener("click", e => {
    if (e.target.closest("button,select,input")) return; h.parentElement.classList.toggle("collapsed"); }));
  const TAB_ID = { fmv: "inv", gmti: "gmti", cot: "cot" };
  function showTab(name) {
    document.querySelectorAll(".tabbar button").forEach(b => b.classList.toggle("on", b.dataset.tab === name));
    Object.entries(TAB_ID).forEach(([k, id]) => $(id).classList.toggle("on", k === name));
    localStorage.setItem("tab", name);
  }
  document.querySelectorAll(".tabbar button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));
  showTab(localStorage.getItem("tab") || "fmv");

  // ── Carte (EPSG:3857 : tuiles ArcGIS Online ; export MapServer demandé en 3857) ─
  const map = L.map("map", { attributionControl: true, zoomSnap: 0.25, preferCanvas: true }).setView([46, 2], 5);
  const LY = {};                                       // clé légende → groupe de couches
  ["trace", "foot", "center", "plots", "dwell", "tracks", "live", "contacts", "ab", "cot"].forEach(k => { LY[k] = L.layerGroup().addTo(map); });
  const lyInspect = L.layerGroup().addTo(map);          // surbrillance de la piste inspectée
  const lyTrace = LY.trace, lyFoot = LY.foot, lyCenter = LY.center, lyPlots = LY.plots, lyDwell = LY.dwell, lyCot = LY.cot;
  const canvasR = L.canvas({ padding: 0.3 });
  map.attributionControl.setPrefix("");
  L.control.scale({ imperial: false }).addTo(map);
  const fullTrack = L.polyline([], { color: "#00c8ff", weight: 1, opacity: .35, dashArray: "3 5" }).addTo(lyTrace);
  const trace = L.polyline([], { color: "#00c8ff", weight: 2, opacity: .9 }).addTo(lyTrace);
  const footprint = L.polygon([], { color: "#ffd54f", weight: 1.5, fillOpacity: .12 }).addTo(lyFoot);
  const los = L.polyline([], { color: "#ffd54f", weight: 1, dashArray: "4 4", opacity: .7 }).addTo(lyCenter);
  const sensor = L.circleMarker([0, 0], { radius: 6, color: "#00c8ff", fillColor: "#00c8ff", fillOpacity: 1, weight: 1 }).addTo(lyTrace);
  const center = L.circleMarker([0, 0], { radius: 4, color: "#ff5252", fillColor: "#ff5252", fillOpacity: 1, weight: 1 }).addTo(lyCenter);
  sensor.bindTooltip("", { permanent: false, direction: "top" });
  // Légende cliquable : chaque entrée allume/éteint sa couche (état mémorisé).
  const legendState = JSON.parse(localStorage.getItem("legend") || "{}");
  function applyLegend() {
    document.querySelectorAll(".legend [data-ly]").forEach(el => {
      const k = el.dataset.ly, on = legendState[k] !== false;
      el.classList.toggle("off", !on);
      if (k === "labels") $("map").classList.toggle("no-cot-lbl", !on);
      else if (LY[k]) { if (on && !map.hasLayer(LY[k])) LY[k].addTo(map); if (!on && map.hasLayer(LY[k])) LY[k].remove(); }
    });
    localStorage.setItem("legend", JSON.stringify(legendState));
  }
  document.querySelectorAll(".legend [data-ly]").forEach(el => el.addEventListener("click", () => { legendState[el.dataset.ly] = legendState[el.dataset.ly] === false; applyLegend(); }));
  applyLegend();

  // ── CoT : un marqueur + traîne par uid, coloré par affiliation (MIL-STD-2525) ─
  const AFF = { FRIEND: "#00c8ff", ASSUMED_FRIEND: "#00c8ff", JOKER: "#00c8ff", HOSTILE: "#ff5252", SUSPECT: "#ff5252",
    FAKER: "#ff5252", NEUTRAL: "#7cff6b", UNKNOWN: "#ffd54f", PENDING: "#ffd54f" };
  const cot = { rows: new Map(), tableAt: 0, total: 0 };            // uid -> {ev, marker, trail, pts, t}
  function onCotBatch(b) {
    cot.total = b.total;
    // Gros lot (saut / analyse statique) : on détache la couche le temps d'ajouter les marqueurs
    // (les infobulles permanentes provoquent sinon un reflow par objet → plusieurs secondes).
    const bulk = b.events.length > 40, hadLayer = bulk && map.hasLayer(lyCot);
    const manyLabels = b.events.length > 200;              // > 200 objets d'un coup : étiquettes au survol seulement (coût DOM)
    if (hadLayer) lyCot.remove();
    b.events.forEach(ev => {
      const key = ev.uid || "(sans uid)"; let r = cot.rows.get(key);
      const col = AFF[ev.aff] || "#8a8f98";
      if (!r) {
        r = { ev, pts: [], t: 0 };
        r.marker = L.circleMarker([0, 0], { radius: 5, color: col, fillColor: col, fillOpacity: .9, weight: 1.5, renderer: canvasR });
        r.trail = L.polyline([], { color: col, weight: 1, opacity: .55, renderer: canvasR });
        r.marker.bindTooltip("", { permanent: !manyLabels, direction: "right", offset: [6, 0], className: "cot-lbl" });
        cot.rows.set(key, r);
      }
      r.ev = ev; r.t = b.t;
      if (ev.lat != null && ev.lon != null && !(ev.lat === 0 && ev.lon === 0)) {
        if (!r.marker._map) { r.trail.addTo(lyCot); r.marker.addTo(lyCot); }
        r.marker.setLatLng([ev.lat, ev.lon]);
        r.marker.setStyle({ color: col, fillColor: col });
        r.marker.setTooltipContent((ev.callsign || ev.uid || "?") + (ev.speed != null ? " · " + ev.speed.toFixed(0) + " m/s" : ""));
        const last = r.pts[r.pts.length - 1];
        if (!last || last[0] !== ev.lat || last[1] !== ev.lon) { r.pts.push([ev.lat, ev.lon]); if (r.pts.length > 400) r.pts.shift(); r.trail.setLatLngs(r.pts); }
      }
    });
    if (hadLayer) lyCot.addTo(map);
    if (performance.now() - cot.tableAt > 300 || bulk) { renderCot(b.t); cot.tableAt = performance.now(); }
  }
  function renderCot(tnow) {
    const rows = Array.from(cot.rows.values()).sort((a, b) => b.t - a.t).slice(0, 300);
    $("cot-body").innerHTML = rows.map(r => { const e = r.ev, col = AFF[e.aff] || "#8a8f98";
      const age = r.t < 0 ? "—" : (tnow - r.t).toFixed(0) + " s";
      return `<tr data-uid="${e.uid || "(sans uid)"}" class="${r.t >= 0 && tnow - r.t > 60 ? "stale" : ""}${cs.sel === (e.uid || "(sans uid)") ? " sel" : ""}" style="color:${col}"><td title="${e.uid}">${e.uid || "—"}</td><td title="${e.type}">${e.type}</td><td>${e.aff || ""}</td><td>${e.callsign || ""}</td><td>${age}</td></tr>`; }).join("");
    $("cot-sum").textContent = `${cot.rows.size} obj · ${cot.total} ev`;
  }
  function resetCot() { cot.rows.clear(); cot.total = 0; lyCot.clearLayers(); $("cot-body").innerHTML = ""; $("cot-sum").textContent = "—"; }

  // ── GMTI : plots (canvas, tampon glissant) + capteur ─────────────────────────
  const gmti = { stats: { pkts: 0, plots: 0, cls: {} }, dots: [] };
  const gmtiSensor = L.circleMarker([0, 0], { radius: 6, color: "#7cff6b", fillColor: "#7cff6b", fillOpacity: .9, weight: 1, renderer: canvasR });
  gmtiSensor.bindTooltip("capteur GMTI", { direction: "top" });
  const GMTI_MAX = 6000, DWELL_KEEP = 12;
  gmti.dwells = [];                                    // polygones des dernières dwells (fondu)
  const dwellLine = L.polyline([], { color: "#7cff6b", weight: 1, dashArray: "3 5", opacity: .7, renderer: canvasR });
  function onGmtiBatch(b) {
    gmti.stats.pkts = b.total_pkts; gmti.stats.plots = b.total_plots; gmti.stats.dwells = b.total_dwells || 0;
    if ($("gmti-dwell").checked && b.dwells && b.dwells.length) {
      b.dwells.forEach(d => {
        let ly;
        // Non interactifs (pas d'infobulle ni de survol) : les dwells défilent sans cesse sous la souris.
        if (d.poly) ly = L.polygon(d.poly, { color: "#7cff6b", weight: 1.2, fillColor: "#7cff6b", fillOpacity: .10, opacity: .9, renderer: canvasR, interactive: false });
        else ly = L.circleMarker(d.center, { radius: 5, color: "#7cff6b", weight: 1, fill: false, renderer: canvasR, interactive: false });
        ly.addTo(lyDwell);
        gmti.dwells.push(ly);
        if (b.sensor && d.center) { dwellLine.setLatLngs([b.sensor, d.center]); if (!dwellLine._map) dwellLine.addTo(lyDwell); }
      });
      while (gmti.dwells.length > DWELL_KEEP) lyDwell.removeLayer(gmti.dwells.shift());
      gmti.dwells.forEach((ly, i) => { const k = (i + 1) / gmti.dwells.length; ly.setStyle({ opacity: .25 + .65 * k, fillOpacity: ly instanceof L.Polygon ? .03 + .10 * k : 0 }); });
    }
    b.plots.forEach(p => {
      const v = p[2] || 0, col = v > 0 ? "#7cff6b" : "#ffb347";                    // signe de la vitesse radiale
      const d = L.circleMarker([p[0], p[1]], { radius: 2, color: col, fillColor: col, fillOpacity: .9, weight: 0, renderer: canvasR }).addTo(lyPlots);
      gmti.dots.push(d); const c = p[4] == null ? "?" : p[4]; gmti.stats.cls[c] = (gmti.stats.cls[c] || 0) + 1;
    });
    while (gmti.dots.length > GMTI_MAX) lyPlots.removeLayer(gmti.dots.shift());
    if (b.sensor && b.sensor[0] != null) { gmtiSensor.setLatLng(b.sensor); if (!gmtiSensor._map) gmtiSensor.addTo(lyDwell); }
    if (b.live) renderLive(b.live);
    const cls = Object.entries(gmti.stats.cls).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `cls ${k}: <b>${v}</b>`).join(" · ");
    $("gmti-body").innerHTML = `paquets 4607 <b>${gmti.stats.pkts}</b> · dwells <b>${gmti.stats.dwells}</b> · plots <b>${gmti.stats.plots}</b> (affichés ${gmti.dots.length}) · t=<b>${b.t.toFixed(1)}</b> s<br>` +
      (b.sensor ? `capteur <b>${b.sensor[0].toFixed(4)} ${b.sensor[1].toFixed(4)}</b><br>` : "") + cls;
    $("gmti-sum").textContent = `${gmti.stats.plots} plots`;
  }
  // ── Pistes temps réel (moteur de rejeu) : marqueur + traîne, couleur = état ─
  const live = { layers: new Map() };                 // id → {mk, tail, seen}
  const LIVE_COL = { SOLID: "#00e5a8", CONFIRMED: "#00c8ff", COASTING: "#ffd54f", TENTATIVE: "#8a8f98" };
  // ── Projection de trajectoire (position prédite à état constant) ────────────
  const projLayers = [];
  function projectSec() { try { const prof = $("gmti-profile").value || "defaut"; const v = ("projectSec" in gs.ov) ? gs.ov.projectSec : (gs.prof ? effective(prof).projectSec : 60); return v == null ? 0 : +v; } catch (e) { return 60; } }
  function destPoint(lat, lon, bearingDeg, distM) {
    const R = 6371000, br = bearingDeg * Math.PI / 180, la1 = lat * Math.PI / 180, lo1 = lon * Math.PI / 180, dr = distM / R;
    const la2 = Math.asin(Math.sin(la1) * Math.cos(dr) + Math.cos(la1) * Math.sin(dr) * Math.cos(br));
    const lo2 = lo1 + Math.atan2(Math.sin(br) * Math.sin(dr) * Math.cos(la1), Math.cos(dr) - Math.sin(la1) * Math.sin(la2));
    return [la2 * 180 / Math.PI, lo2 * 180 / Math.PI];
  }
  function drawProjection(group, lat, lon, speed, heading, col) {
    const sec = projectSec(); if (!sec || speed == null || heading == null || speed < 0.5) return null;
    const end = destPoint(lat, lon, heading, speed * sec), mid = destPoint(lat, lon, heading, speed * sec / 2);
    const pl = L.polyline([[lat, lon], end], { color: col, weight: 1.5, dashArray: "6 5", opacity: .8, renderer: canvasR, interactive: false }).addTo(group);
    const tip = L.circleMarker(end, { radius: 3, color: col, weight: 1, fillColor: col, fillOpacity: .6, renderer: canvasR, interactive: false }).addTo(group);
    return [pl, tip, mid];
  }
  // ── Écart piste ↔ centre image vidéo (vérité KLV quand le capteur fixe la cible) ─
  const vidgap = { n: 0, sum: 0, max: 0, last: null, id: null };
  function resetVidgap() { vidgap.n = 0; vidgap.sum = 0; vidgap.max = 0; vidgap.last = null; vidgap.id = null; }
  function updateVidgap(tracks) {
    if (!state.klvCenter || !tracks.length) return;
    let best = Infinity, bid = null;
    tracks.forEach(t => { if (!t.ever || t.state === "TENTATIVE") return; const d = MGRS.distBearing(state.klvCenter[0], state.klvCenter[1], t.lat, t.lon).d; if (d < best) { best = d; bid = t.id; } });
    if (bid == null || best > 5000) return;              // aucune piste à moins de 5 km du centre image : le capteur ne regarde pas une cible pistée
    vidgap.n++; vidgap.sum += best; vidgap.max = Math.max(vidgap.max, best); vidgap.last = best; vidgap.id = bid;
  }
  function vidgapText() { return vidgap.n ? ` · écart piste↔centre image : <b>${vidgap.last.toFixed(0)} m</b> (piste ${vidgap.id}, moy ${(vidgap.sum / vidgap.n).toFixed(0)} m, max ${vidgap.max.toFixed(0)} m sur ${vidgap.n} éch.)` : ""; }

  function renderLive(lv) {
    const showTent = $("gmti-live-tent").checked, seen = new Set(); live.last = lv.tracks || [];
    projLayers.forEach(l => LY.live.removeLayer(l)); projLayers.length = 0;
    updateVidgap(lv.tracks || []);
    (lv.tracks || []).forEach(t => {
      if (t.state === "TENTATIVE" && !showTent) return;
      if (!t.ever && !showTent) return;                 // pas encore confirmée une fois → tentative
      const col = t.is_air ? "#ff9f43" : t.is_rotator ? "#e58cff" : (t.ever ? LIVE_COL[t.state] : LIVE_COL.TENTATIVE);
      let e = live.layers.get(t.id);
      if (!e) {
        e = { mk: L.circleMarker([t.lat, t.lon], { radius: 5, weight: 1.5, color: col, fillColor: col, fillOpacity: .9, renderer: canvasR }).addTo(LY.live),
              tail: L.polyline(t.tail, { color: col, weight: 2, opacity: .8, renderer: canvasR }).addTo(LY.live) };
        e.mk.bindTooltip("", { permanent: true, direction: "right", offset: [6, 0], className: "live-lbl" });
        e.mk.on("click", () => { const cur = live.last && live.last.find(x => x.id === t.id); if (!cur) return; showTab("gmti");
          $("gmti-inspect").hidden = false; $("ins-title").textContent = `piste live ${cur.id} · ${cur.state} · ${cur.hits} hits · ${cur.misses} miss consécutifs`;
          $("ins-stats").innerHTML = `vitesse <b>${cur.speed}</b> m/s · cap <b>${cur.heading}°</b> · dernière MAJ il y a <b>${cur.age_s}</b> s · confirmée une fois : <b>${cur.ever ? "oui" : "non"}</b>` + (cur.contact != null ? ` · contact <b>${cur.contact}</b>` : "") + (cur.is_air ? " · aérien" : "") + (cur.is_rotator ? " · rotateur" : "");
          $("ins-strip").innerHTML = ""; $("ins-table").innerHTML = ""; lyInspect.clearLayers(); L.polyline(cur.tail, { color: "#fff", weight: 5, opacity: .35 }).addTo(lyInspect); ins.d = null; });
        live.layers.set(t.id, e);
      }
      e.mk.setLatLng([t.lat, t.lon]); e.mk.setStyle({ color: col, fillColor: col, fillOpacity: t.state === "COASTING" ? .35 : .9 });
      e.tail.setLatLngs(t.tail); e.tail.setStyle({ color: col });
      e.mk.setTooltipContent(`${t.contact != null ? "C" + t.contact + "·" : ""}${t.id} ${t.state[0]}${t.hits}` + (t.speed >= 1 ? ` ${t.speed.toFixed(0)}m/s` : ""));
      if (t.ever && t.state !== "TENTATIVE") { const pr = drawProjection(LY.live, t.lat, t.lon, t.speed, t.heading, col); if (pr) { projLayers.push(pr[0], pr[1]); } }
      seen.add(t.id);
    });
    live.layers.forEach((e, id) => { if (!seen.has(id)) { LY.live.removeLayer(e.mk); LY.live.removeLayer(e.tail); live.layers.delete(id); } });
    const st = lv.stats || {};
    $("gmti-live-body").innerHTML = st.error ? `pistage temps réel : <span style="color:var(--danger)">${st.error}</span>` :
      `pistage temps réel · profil <b>${st.profile}${Object.keys(st.overrides || {}).length ? "*" : ""}</b> · dwells <b>${st.n_dwells}</b> · pistes vivantes <b>${st.displayable}</b> ` +
      `(solides <b>${st.solid}</b>, confirmées <b>${st.confirmed}</b>, coasting <b>${st.coasting}</b>, tentatives ${st.tentative}) · archivées ${st.archived}` +
      (lv.contacts ? ` · contacts fusionnés <b>${lv.contacts.length}</b>` : "") + (st.n_resets ? ` · resets ${st.n_resets}` : "") + (st.n_filtered ? ` · filtrés ${st.n_filtered}` : "") + (st.n_ghosts ? ` · fantômes ${st.n_ghosts}` : "") + (st.n_absorbed ? ` · pistes absorbées ${st.n_absorbed}` : "") + (st.n_swallowed ? ` · échos avalés ${st.n_swallowed}` : "") + (st.n_clustered ? ` · échos regroupés ${st.n_clustered}` : "") + vidgapText();
  }
  function resetLive() { live.layers.clear(); LY.live.clearLayers(); projLayers.length = 0; resetVidgap(); $("gmti-live-body").textContent = ""; }

  function resetGmti() { gmti.dots.forEach(d => lyPlots.removeLayer(d)); gmti.dots = []; gmti.dwells.forEach(d => lyDwell.removeLayer(d)); gmti.dwells = []; if (dwellLine._map) lyDwell.removeLayer(dwellLine); gmti.stats = { pkts: 0, plots: 0, dwells: 0, cls: {} }; if (gmtiSensor._map) lyDwell.removeLayer(gmtiSensor); }
  let fitOnce = false;

  // ── Analyse statique GMTI : décodage + tracker (profil) ─────────────────────
  const lyTracks = LY.tracks;                          // pistes + zone job / porteur (statique)
  const lyRawStatic = L.layerGroup().addTo(lyPlots);   // plots bruts du tracker (statique) — sous « plots GMTI »
  const gs = { decoded: null, res: null, resB: null, prof: null, ov: {}, abProfile: "" };   // prof = /api/gmti/profiles ; ov = surcharges (noms Java)
  const ETAT_COL = { confirmee: "#00c8ff", coasting: "#ffd54f", tentative: "#8a8f98" };
  function trackColor(t) { return t.is_air ? "#ff9f43" : t.is_rotator ? "#e58cff" : (ETAT_COL[t.etat] || "#00c8ff"); }
  async function gmtiDecode() {
    showTab("gmti"); $("gmti-status").textContent = "décodage GMTI…";
    try { gs.decoded = await withBusy("décodage GMTI 4607 (extracteur)…", () => api(`/api/gmti/decode?pcap=${encodeURIComponent(state.pcap)}${limQ()}`), ["gmti-decode", "gmti-track"]); }
    catch (e) { return $("gmti-status").textContent = "erreur : " + e.message; }
    const d = gs.decoded;
    if (!d.decoded) { $("gmti-status").textContent = d.error || "aucun GMTI"; return; }
    await loadProfiles();
    $("gmti-status").textContent = `GMTI décodé (${d.mode}) : ${d.n_plots} plots, ${d.dwells || "?"} dwells · tracker ${d.tracker} — choisir un profil puis 2. Tracker`;
    $("gmti-inv").textContent = d.rapport || "(inventaire indisponible en mode streaming)"; $("gmti-inv").hidden = false;   // inventaire 4607 affiché dès le décodage
    $("gmti-sum").textContent = `${d.n_plots} plots décodés`;
    return d;
  }
  async function gmtiTrack() {
    if (!gs.decoded || !gs.decoded.decoded) { const d = await gmtiDecode(); if (!d || !d.decoded) return; }
    const profile = $("gmti-profile").value || "defaut";
    const ovq = Object.keys(gs.ov).length ? `&overrides=${encodeURIComponent(JSON.stringify(gs.ov))}` : "";
    $("gmti-status").textContent = `tracker en cours (profil ${profile}${ovq ? " + surcharges" : ""})…`;
    try { gs.res = await withBusy(`tracker GMTI — profil ${profile}${ovq ? " + surcharges" : ""}…`, () => api(`/api/gmti/track?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${ovq}${limQ()}`), ["gmti-track", "ed-run", "gmti-decode"]); }
    catch (e) { return $("gmti-status").textContent = "tracker : " + e.message; }
    gs.resB = null;
    if (gs.abProfile) {
      try { gs.resB = await withBusy(`tracker GMTI — profil B ${gs.abProfile}…`, () => api(`/api/gmti/track?pcap=${encodeURIComponent(state.pcap)}&profile=${gs.abProfile}${limQ()}`)); } catch (e) { status("A/B : " + e.message, true); }
    }
    drawTracks(); fitTracks(); renderMetrics();
    const r = gs.res, m = r.metrics || {};
    $("gmti-status").textContent = `profil ${profile}${ovq ? " (surchargé)" : ""} : ${r.n_kept} pistes, ${r.n_rejected} rejetées (${r.n_raw} plots)` +
      (m.contacts != null ? ` · ${m.contacts} contacts (${m.contacts_multi} fusionnés)` : "") + (r.zone.length ? " · zone job" : "") + (r.porteur.length ? ` · porteur ${r.porteur.length} pos` : "");
    $("gmti-sum").textContent = `${r.n_kept} pistes · profil ${profile}${ovq ? "*" : ""}`;
  }

  // ── Inspection d'une piste (analyse statique) ───────────────────────────────
  const ins = { d: null, rows: [], sel: -1 };
  function ellipsePts(lat, lon, a, b, angDeg, n = 36) {
    const kx = 111320 * Math.cos(lat * Math.PI / 180), ky = 110540, th = angDeg * Math.PI / 180, out = [];
    for (let i = 0; i < n; i++) { const p = 2 * Math.PI * i / n, ex = a * Math.cos(p), ey = b * Math.sin(p);
      const x = ex * Math.cos(th) - ey * Math.sin(th), y = ex * Math.sin(th) + ey * Math.cos(th); out.push([lat + y / ky, lon + x / kx]); }
    return out;
  }
  const d2col = d2 => d2 == null ? "#8a8f98" : d2 < 2 ? "#7cff6b" : d2 < 6 ? "#ffd54f" : "#ff5252";
  async function inspectTrack(id) {
    if (!gs.res) return;
    const profile = gs.res.profile, ovq = Object.keys(gs.res.overrides || {}).length ? `&overrides=${encodeURIComponent(JSON.stringify(gs.res.overrides))}` : "";
    let d; try { d = await withBusy(`inspection de la piste ${id}…`, () => api(`/api/gmti/track/detail?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${ovq}&id=${id}${limQ()}`)); }
    catch (e) { return status("inspection : " + e.message, true); }
    ins.d = d; showTab("gmti"); $("gmti-inspect").hidden = false; $("gmti-editor").hidden = true;
    lyInspect.clearLayers();
    const t = gs.res.tracks.find(x => x.id === id);
    if (t) L.polyline(t.pts, { color: "#ffffff", weight: 5, opacity: .35 }).addTo(lyInspect);
    d.gates.forEach(g => L.polygon(ellipsePts(g[1], g[2], g[3], g[4], g[5]), { color: "#ffd54f", weight: 1, opacity: .5, fill: false, dashArray: "3 3" }).addTo(lyInspect));
    d.assoc.forEach(a => L.circleMarker([a[1], a[2]], { radius: 4, color: "#000", weight: 1, fillColor: d2col(a[3]), fillOpacity: 1 }).addTo(lyInspect)
      .bindTooltip(`t=${a[0].toFixed(2)} s · d²=${a[3]} · v_LOS ${a[4] ?? "—"} m/s · SNR ${a[5] ?? "—"} · classe ${a[6] ?? "—"}`));
    const dur = (d.t1 != null && d.t0 != null) ? d.t1 - d.t0 : 0;
    $("ins-title").textContent = `piste ${d.id} · ${d.hits} hits · ${d.n_miss} miss · profil ${profile}${ovq ? "*" : ""}` + (d.is_air ? " · aérien" : "") + (d.is_rotator ? " · rotateur" : "");
    $("ins-stats").innerHTML = `durée <b>${dur.toFixed(1)} s</b> · dwells vus <b>${d.n_hist}</b> · vitesse moy <b>${d.speed_mean != null ? d.speed_mean.toFixed(1) : "—"}</b> / max <b>${d.speed_max != null ? d.speed_max.toFixed(1) : "—"}</b> m/s · gate χ² <b>${d.gate_chi2}</b> · plafond gate <b>${d.gate_max_m} m</b>` +
      (d.assoc.length > 1 ? ` · d² moyen <b>${(d.assoc.slice(1).reduce((s_, a) => s_ + (a[3] || 0), 0) / (d.assoc.length - 1)).toFixed(2)}</b>` : "");
    const strip = $("ins-strip"); strip.innerHTML = "";
    d.hist.forEach((h, i) => { const el = document.createElement("i"); el.className = (h[4] ? "hit " : "miss ") + h[3]; el.title = `#${i} t=${h[0].toFixed(2)} s · ${h[3]} · ${h[4] ? "plot associé" : "miss"}${h[5] != null ? " · " + h[5].toFixed(1) + " m/s" : ""}`; el.onclick = () => insSelect(i); strip.appendChild(el); });
    const tb = $("ins-table"); tb.innerHTML = `<tr><th>#</th><th>t (s)</th><th>Δt</th><th>état</th><th>hit</th><th>v m/s</th><th>d²</th><th>v_LOS</th><th>SNR</th><th>cls</th></tr>`;
    let k = 0; ins.rows = [];
    d.hist.forEach((h, i) => {
      let a = null; if (h[4] && k < d.assoc.length) { a = d.assoc[k]; k++; }
      const tr = document.createElement("tr"); tr.className = h[4] ? "" : "miss"; tr.dataset.i = i;
      tr.innerHTML = `<td>${i}</td><td>${h[0].toFixed(2)}</td><td>${i ? (h[0] - d.hist[i - 1][0]).toFixed(2) : "—"}</td><td>${h[3]}</td><td>${h[4] ? "●" : "·"}</td><td>${h[5] != null ? h[5].toFixed(1) : ""}</td><td>${a && a[3] != null ? a[3] : ""}</td><td>${a && a[4] != null ? a[4] : ""}</td><td>${a && a[5] != null ? a[5] : ""}</td><td>${a && a[6] != null ? a[6] : ""}</td>`;
      tr.onclick = () => insSelect(i); tb.appendChild(tr); ins.rows.push(tr);
    });
    status(`piste ${d.id} inspectée — ${d.hits} plots associés, ${d.gates.length} gates`);
  }
  function insSelect(i) {
    const d = ins.d; if (!d) return; ins.sel = i;
    document.querySelectorAll("#ins-strip i").forEach((el, j) => el.classList.toggle("cur", j === i));
    ins.rows.forEach((tr, j) => tr.style.outline = j === i ? "1px solid var(--accent)" : "");
    const h = d.hist[i]; if (h) map.panTo([h[1], h[2]]);
  }
  $("ins-close").addEventListener("click", () => { $("gmti-inspect").hidden = true; lyInspect.clearLayers(); ins.d = null; });
  $("ins-fit").addEventListener("click", () => { const d = ins.d; if (d && d.hist.length) map.fitBounds(L.latLngBounds(d.hist.map(h => [h[1], h[2]])).pad(0.3)); });

  // ── Profils (source unique gmti_profiles.json) + éditeur de paramètres ─────
  async function loadProfiles() {
    try { gs.prof = await api("/api/gmti/profiles"); } catch (e) { return status("profils : " + e.message, true); }
    const sel = $("gmti-profile"), cur = sel.value; sel.innerHTML = "";
    gs.prof.names.forEach(pn => { const o = document.createElement("option"); o.value = o.textContent = pn; sel.appendChild(o); });
    sel.value = gs.prof.names.includes(cur) ? cur : (gs.prof.names.includes("maritime") ? "maritime" : gs.prof.names[0]);
    const ab = $("gmti-ab"), curB = ab.value; ab.innerHTML = '<option value="">—</option>';
    gs.prof.names.forEach(pn => { const o = document.createElement("option"); o.value = o.textContent = pn; ab.appendChild(o); });
    ab.value = gs.prof.names.includes(curB) ? curB : "";
    renderEditor();
  }
  const GROUPS = { gate: "Gate & cinématique", vie: "Confirmation & suppression", aerien: "Aérien / rotateur", cluster: "Pré-clustering des plots (cibles étendues)", fusion: "Fusion de pistes (1 contact = 1 piste)", filtre: "Filtres processor", affichage: "Affichage" };
  function effective(profile) { return Object.assign({}, gs.prof.defaults, (gs.prof.effective || {})[profile] || {}); }
  function renderEditor() {
    if (!gs.prof) return;
    const profile = $("gmti-profile").value || "defaut"; $("ed-prof").textContent = profile;
    const eff = effective(profile), params = gs.prof.params || {}; const box = $("ed-groups"); box.innerHTML = "";
    const byGroup = {}; Object.keys(params).forEach(k => { (byGroup[params[k].group] = byGroup[params[k].group] || []).push(k); });
    Object.entries(GROUPS).forEach(([g, title]) => {
      const keys = byGroup[g]; if (!keys) return;
      const div = document.createElement("div"); div.className = "grp"; div.innerHTML = `<h4>${title}</h4>`;
      const grid = document.createElement("div"); grid.className = "prm";
      keys.forEach(k => {
        const info = params[k], v = k in gs.ov ? gs.ov[k] : eff[k]; const isMod = k in gs.ov;
        const lab = document.createElement("label"); lab.textContent = k; lab.title = (info.doc || "") + (isMod ? `\n(profil : ${eff[k]})` : ""); grid.appendChild(lab);
        let inp;
        if (info.unit === "bool") { inp = document.createElement("input"); inp.type = "checkbox"; inp.checked = !!v; inp.style.justifySelf = "end"; }
        else { inp = document.createElement("input"); inp.type = "text"; inp.value = v == null ? "" : (Array.isArray(v) ? v.join(",") : v); }
        inp.dataset.k = k; if (isMod) inp.classList.add("mod");
        inp.addEventListener("change", () => onParamChange(k, inp, info, eff[k]));
        grid.appendChild(inp);
        const u = document.createElement("span"); u.className = "u"; u.textContent = info.unit === "bool" ? "" : info.unit || ""; grid.appendChild(u);
      });
      div.appendChild(grid); box.appendChild(div);
    });
    $("ed-name").value = profile;
  }
  function onParamChange(k, inp, info, base) {
    let v;
    if (info.unit === "bool") v = inp.checked;
    else if (info.unit === "liste") v = inp.value.split(",").map(x => x.trim()).filter(Boolean).map(Number).filter(n => !isNaN(n));
    else if (inp.value.trim() === "") v = null;
    else { v = Number(inp.value.replace(",", ".")); if (isNaN(v)) { inp.value = base == null ? "" : base; return; } }
    const same = JSON.stringify(v) === JSON.stringify(base == null ? null : base);
    if (same) { delete gs.ov[k]; inp.classList.remove("mod"); } else { gs.ov[k] = v; inp.classList.add("mod"); }
    $("ed-msg").textContent = Object.keys(gs.ov).length ? `${Object.keys(gs.ov).length} surcharge(s) : ${Object.keys(gs.ov).join(", ")} — Relancer pour appliquer` : "";
  }
  $("gmti-params-btn").addEventListener("click", () => { $("gmti-editor").hidden = !$("gmti-editor").hidden; if (!$("gmti-editor").hidden) renderEditor(); });
  $("gmti-profile").addEventListener("change", () => { gs.ov = {}; $("ed-msg").textContent = ""; renderEditor(); });
  $("gmti-ab").addEventListener("change", () => { gs.abProfile = $("gmti-ab").value; if (gs.res) gmtiTrack(); });
  $("ed-run").addEventListener("click", gmtiTrack);
  $("ed-reset").addEventListener("click", () => { gs.ov = {}; $("ed-msg").textContent = ""; renderEditor(); });
  $("ed-save").addEventListener("click", async () => {
    if (!gs.prof) return; const name = $("ed-name").value.trim(); if (!name) return $("ed-msg").textContent = "nom de profil requis";
    const params = Object.assign(effective($("gmti-profile").value || "defaut"), gs.ov);
    try { gs.prof = await api("/api/gmti/profiles", { name, params }); gs.ov = {}; await loadProfiles(); $("gmti-profile").value = name; renderEditor();
      $("ed-msg").textContent = `profil « ${name} » enregistré dans ${gs.prof.path.split(/[\\/]/).pop()} (lu aussi par le processor Java)`; }
    catch (e) { $("ed-msg").textContent = "enregistrement : " + e.message; }
  });
  $("ed-del").addEventListener("click", async () => {
    const name = $("gmti-profile").value; if (!name || name === "defaut") return $("ed-msg").textContent = "ce profil ne peut pas être supprimé";
    if (!confirm(`Supprimer le profil « ${name} » de gmti_profiles.json ?`)) return;
    try { gs.prof = await api("/api/gmti/profiles", { name, params: null }); gs.ov = {}; await loadProfiles(); renderEditor(); $("ed-msg").textContent = `profil « ${name} » supprimé`; }
    catch (e) { $("ed-msg").textContent = "suppression : " + e.message; }
  });
  $("ed-parity").addEventListener("click", () => {
    if (!state.pcap) return status("analyser un pcap d'abord", true);
    const profile = $("gmti-profile").value || "defaut", ovq = Object.keys(gs.ov).length ? `&overrides=${encodeURIComponent(JSON.stringify(gs.ov))}` : "";
    const name = ($("ed-name").value.trim() || profile);
    const secs = prompt("Fenêtre du cas de parité (secondes de dwell_time depuis le premier plot ; 0 = capture entière — attention, le test JUnit est en O(n²) par dwell) :", "300"); if (secs === null) return;
    download(`/api/gmti/parity.zip?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${ovq}&name=${encodeURIComponent(name)}&seconds=${encodeURIComponent(secs)}${limQ()}`, `parity_${name}.zip`, "oracle de parité (rejeu du tracker Python)…").then(() => status("oracle de parité exporté")).catch(e => status("oracle : " + e.message, true));
  });
  $("ed-export").addEventListener("click", () => {
    if (!gs.prof) return; const profile = $("gmti-profile").value || "defaut";
    const cfg = Object.assign(effective(profile), gs.ov); const blob = new Blob([JSON.stringify({ profile, config: cfg }, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `gmti_profile_${profile}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });

  // ── Métriques (A et éventuellement B) ───────────────────────────────────────
  const MET = [["n_tracks", "pistes confirmées", 0, "hi"], ["n_rejected", "pistes rejetées (tentatives)", 0, "lo"], ["n_plots", "plots", 0, ""],
    ["plots_per_track", "plots / piste", 1, ""], ["hits_mean", "hits moyens", 1, "hi"], ["hits_median", "hits médians", 0, "hi"], ["short_tracks", "pistes < 5 hits", 0, "lo"],
    ["dur_mean_s", "durée moyenne (s)", 0, "hi"], ["dur_max_s", "durée max (s)", 0, ""], ["len_mean_m", "longueur moyenne (m)", 0, ""],
    ["coast_ratio", "part de coasting", 2, "lo"], ["solid", "état Solide", 0, ""], ["confirmed", "état Confirmée", 0, ""], ["coasting_end", "finies en coasting", 0, ""],
    ["air", "aériennes", 0, ""], ["rotator", "rotateurs", 0, ""], ["contacts", "contacts (fusion)", 0, ""], ["contacts_multi", "contacts multi-pistes", 0, ""], ["n_filtered", "plots filtrés (SNR/classe)", 0, ""], ["n_clustered", "échos regroupés (pré-clustering)", 0, ""], ["n_ghosts", "échos fantômes rejetés (ghostSnrDb)", 0, ""], ["n_absorbed", "pistes absorbées (absorbDwells)", 0, ""], ["n_swallowed", "échos avalés par une piste étendue", 0, ""]];
  function renderMetrics() {
    const a = gs.res && gs.res.metrics, b = gs.resB && gs.resB.metrics; const el = $("gmti-metrics");
    if (!a) { el.hidden = true; return; }
    const f = (v, d) => v == null ? "—" : (typeof v === "number" ? v.toFixed(d) : v);
    let h = `<table class="met"><tr><th>métrique</th><th class="a">${gs.res.profile}${Object.keys(gs.res.overrides || {}).length ? "*" : ""}</th>${b ? `<th class="b">${gs.resB.profile}</th>` : ""}</tr>`;
    MET.forEach(([k, lab, d, pref]) => {
      if (a[k] == null && !(b && b[k] != null)) return;
      let cls = ""; if (b && pref && a[k] != null && b[k] != null && a[k] !== b[k]) cls = ((pref === "hi") === (a[k] > b[k])) ? "better-a" : "better-b";
      h += `<tr class="${cls}"><td>${lab}</td><td class="a">${f(a[k], d)}</td>${b ? `<td class="b">${f(b[k], d)}</td>` : ""}</tr>`;
    });
    el.innerHTML = h + "</table>"; el.hidden = false;
  }
  function drawTracks() {
    lyTracks.clearLayers(); lyRawStatic.clearLayers(); LY.contacts.clearLayers(); LY.ab.clearLayers(); lyInspect.clearLayers(); $("gmti-inspect").hidden = true; ins.d = null; const r = gs.res; if (!r) return;
    if (r.contacts) r.contacts.forEach(c => { if (c.pts.length < 2) return;
      L.polyline(c.pts, { color: "#e58cff", weight: 5, opacity: .35, renderer: canvasR }).addTo(LY.contacts)
        .bindTooltip(`contact ${c.id} · ${c.n_max} piste(s) max · ${c.hits} hits · pistes ${c.members.slice(0, 6).join(",")}${c.members.length > 6 ? "…" : ""}`, { sticky: true }); });
    if (gs.resB) gs.resB.tracks.forEach(t => { if (t.pts.length < 2) return;
      L.polyline(t.pts, { color: "#ff5cf0", weight: 1.5, dashArray: "5 4", opacity: .9, renderer: canvasR }).addTo(LY.ab)
        .bindTooltip(`B ${gs.resB.profile} · piste ${t.id} · ${t.hits} hits · ${t.etat}`, { sticky: true }); });
    if ($("gmti-ovl").checked) {
      if (r.zone.length) L.polygon(r.zone, { color: "#8a8f98", weight: 1, dashArray: "6 4", fill: false }).addTo(lyTracks);
      if (r.porteur.length) L.polyline(r.porteur, { color: "#e6edf3", weight: 1, opacity: .6, dashArray: "2 6" }).addTo(lyTracks);
    }
    if ($("gmti-raw").checked) r.raw.forEach(pt => L.circleMarker([pt[0], pt[1]], { radius: 1.5, weight: 0, fillOpacity: .55, fillColor: "#7cff6b", renderer: canvasR }).addTo(lyRawStatic));
    const smooth = $("gmti-smooth").checked;
    r.tracks.forEach(t => {
      const pts = smooth && t.smooth.length ? t.smooth : t.pts; if (pts.length < 2) return;
      const col = trackColor(t);
      const pl = L.polyline(pts, { color: col, weight: 2, opacity: .95, renderer: canvasR }).addTo(lyTracks);
      pl.bindTooltip(`piste ${t.id} · ${t.hits} hits · ${t.etat}${t.is_air ? " · aérien" : ""}${t.is_rotator ? " · rotateur" : ""} — cliquer pour inspecter`, { sticky: true });
      pl.on("click", () => inspectTrack(t.id));
      L.circleMarker(pts[pts.length - 1], { radius: 3, color: col, fillColor: col, fillOpacity: 1, weight: 1, renderer: canvasR }).addTo(lyTracks);
      if (t.speed != null && t.heading != null) drawProjection(lyTracks, pts[pts.length - 1][0], pts[pts.length - 1][1], t.speed, t.heading, col);
    });
  }
  function fitTracks() {
    const r = gs.res; if (!r) return; let pts = []; r.tracks.forEach(t => pts.push(...t.pts)); if (!pts.length) r.raw.slice(0, 2000).forEach(p => pts.push([p[0], p[1]]));
    if (!pts.length) return;
    // robuste aux plots aberrants (sentinelles 0,0 / octets mal décodés) : médiane des PLOTS BRUTS,
    // puis on ne garde que les points à moins de 3° de cette médiane
    const med = a => { const b = a.slice().sort((x, y) => x - y); return b[b.length >> 1]; };
    const ref = r.raw.length ? r.raw : pts; const mla = med(ref.map(p => p[0])), mlo = med(ref.map(p => p[1]));
    const core = pts.filter(p => Math.abs(p[0] - mla) < 3 && Math.abs(p[1] - mlo) < 3);
    const outliers = r.tracks.filter(t => t.pts.length && (Math.abs(t.pts[0][0] - mla) >= 3 || Math.abs(t.pts[0][1] - mlo) >= 3)).length;
    if (outliers) status(`${outliers} piste(s) hors zone (plots aberrants : sentinelles 0,0 / octets mal décodés) — non prises dans le cadrage`, true);
    map.fitBounds(L.latLngBounds(core.length ? core : pts).pad(0.1));
  }
  const limQ = () => state.cfg && state.cfg.default_limit ? `&limit=${state.cfg.default_limit}` : "";

  $("gmti-decode").addEventListener("click", gmtiDecode);
  $("gmti-track").addEventListener("click", gmtiTrack);
  ["gmti-raw", "gmti-smooth", "gmti-ovl"].forEach(id => $(id).addEventListener("change", drawTracks));

  // ── Analyse statique CoT : objets, traces, inventaire des types, XML ─────────
  const cs = { data: null, sel: null };
  async function cotScan() {
    showTab("cot"); $("cot-status").textContent = "analyse CoT…";
    const flt = $("cot-filter").value.trim();
    try { cs.data = await withBusy("analyse CoT (parse XML de toute la capture)…", () => api(`/api/cot/scan?pcap=${encodeURIComponent(state.pcap)}&filter=${encodeURIComponent(flt)}`), ["cot-scan"]); }
    catch (e) { return $("cot-status").textContent = "erreur : " + e.message; }
    resetCot(); const d = cs.data;
    const hadLayer = map.hasLayer(lyCot); if (hadLayer) lyCot.remove();
    d.rows.forEach(row => {
      const ev = { uid: row.uid, type: row.type, aff: row.affiliation, callsign: row.callsign, lat: +row.lat, lon: +row.lon, speed: row.speed != null ? +row.speed : null };
      const key = ev.uid || "(sans uid)"; const col = AFF[ev.aff] || "#8a8f98";
      const r = { ev, pts: (d.tracks[row.uid] || []).slice(-400), t: -1 };
      r.marker = L.circleMarker([0, 0], { radius: 5, color: col, fillColor: col, fillOpacity: .9, weight: 1.5, renderer: canvasR });
      r.trail = L.polyline(r.pts, { color: col, weight: 1, opacity: .55, renderer: canvasR });
      r.marker.bindTooltip((ev.callsign || ev.uid || "?"), { permanent: d.rows.length <= 200, direction: "right", offset: [6, 0], className: "cot-lbl" });
      if (!isNaN(ev.lat) && !isNaN(ev.lon) && !(ev.lat === 0 && ev.lon === 0)) { r.marker.setLatLng([ev.lat, ev.lon]); r.trail.addTo(lyCot); r.marker.addTo(lyCot); }
      r.marker.on("click", () => cotSelect(key));
      cot.rows.set(key, r);
    });
    if (hadLayer) lyCot.addTo(map);
    cot.total = d.kept; renderCot(-1);
    $("cot-status").textContent = `${d.kept} events · ${d.types.length} types · ${d.rows.length} objets · malformés ${d.malformed}` + (d.tcp_recovered ? ` · TCP réassemblés ${d.tcp_recovered}` : "");
    const inv = [`INVENTAIRE CoT — ${d.kept} events, ${d.types.length} types, ${d.rows.length} objets (malformés ${d.malformed})`, "",
      "type".padEnd(24) + "count".padStart(6) + "  " + "affiliation".padEnd(14) + "dim"];
    d.types.forEach(t => inv.push(t.type.padEnd(24) + String(t.n).padStart(6) + "  " + (t.affiliation || "").padEnd(14) + t.dimension));
    $("cot-detail").textContent = inv.join("\n"); $("cot-detail").hidden = false;
    fitView();
  }
  async function cotSelect(key) {
    cs.sel = key; document.querySelectorAll("#cot-body tr").forEach(tr => tr.classList.toggle("sel", tr.dataset.uid === key));
    const r = cot.rows.get(key); if (r && r.marker._map) map.panTo(r.marker.getLatLng());
    try {
      const flt = $("cot-filter").value.trim();
      const e = await api(`/api/cot/event?pcap=${encodeURIComponent(state.pcap)}&uid=${encodeURIComponent(key)}&filter=${encodeURIComponent(flt)}`);
      $("cot-detail").textContent = (e.xml || "(event non disponible — analyser CoT d'abord)").replace(/></g, ">\n<"); $("cot-detail").hidden = false;
    } catch (err) { $("cot-detail").textContent = "erreur : " + err.message; }
  }
  $("cot-scan").addEventListener("click", cotScan);
  $("cot-filter").addEventListener("keydown", e => { if (e.key === "Enter") cotScan(); });
  $("cot-body").addEventListener("click", e => { const tr = e.target.closest("tr"); if (tr && tr.dataset.uid != null) cotSelect(tr.dataset.uid); });

  // ── Exports ─────────────────────────────────────────────────────────────────
  $("btn-geojson").addEventListener("click", () => {
    if (!state.pcap) return status("analyser un pcap d'abord", true);
    const profile = $("gmti-profile").value || "defaut";
    download(`/api/fused/export.geojson?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${limQ()}`, "fusion.geojson", "export GeoJSON fusion (GMTI + CoT + vidéo)…").then(() => status("GeoJSON exporté")).catch(e => status("export : " + e.message, true));
  });
  $("btn-publish").addEventListener("click", async () => {
    const url = $("stratus-url").value.trim();
    $("publish-msg").textContent = "publication…";
    try { const r = await withBusy("publication des profils vers StratusServer…", () => api("/api/gmti/publish", { url }), ["btn-publish"]);
      $("publish-msg").textContent = `OK → ${r.remote && r.remote.path ? r.remote.path : r.url} · profils : ${(r.profiles || []).join(", ")}`; status("profils publiés vers StratusServer"); }
    catch (e) { $("publish-msg").textContent = "échec : " + e.message; status("publication : " + e.message, true); }
  });
  $("btn-ts").addEventListener("click", () => {
    if (!state.cur) return status("pas de flux vidéo sélectionné", true);
    const a = document.createElement("a"); a.href = U(`/video.ts?pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur.dport}&download=1`); a.download = `flux_${state.cur.dport}.ts`; a.click();
  });

  const AGOL = "https://server.arcgisonline.com/ArcGIS/rest/services/{layer}/MapServer/tile/{z}/{y}/{x}";
  function applyBasemap() {
    if (state.bmLayer) { state.bmLayer.remove(); state.bmLayer = null; }
    if (state.bmOverlay) { state.bmOverlay.remove(); state.bmOverlay = null; }
    const cfg = state.bmCfg; if (!cfg || !$("basemap").checked || cfg.provider === "none") return;
    if (cfg.provider === "arcgis_online") {
      state.bmLayer = L.tileLayer(AGOL.replace("{layer}", cfg.layer || "World_Imagery"), { maxZoom: 19, attribution: "Esri, Maxar, Earthstar Geographics — ArcGIS Online" }).addTo(map);
      state.bmLayer.on("tileerror", () => status("tuiles ArcGIS Online injoignables (internet ?)", true));
      state.bmLayer.bringToBack();
    } else if (cfg.provider === "mapserver") refreshExport();
  }
  function refreshExport() {
    const cfg = state.bmCfg; if (!cfg || cfg.provider !== "mapserver" || !$("basemap").checked) return;
    const b = map.getBounds(), sz = map.getSize();
    const sw = L.CRS.EPSG3857.project(b.getSouthWest()), ne = L.CRS.EPSG3857.project(b.getNorthEast());
    const url = U(`/basemap?bbox=${sw.x},${sw.y},${ne.x},${ne.y}&w=${sz.x}&h=${sz.y}&sr=3857&_=${Date.now()}`);
    const img = new Image();
    img.onload = () => {
      const ov = L.imageOverlay(url, [[b.getSouth(), b.getWest()], [b.getNorth(), b.getEast()]], { opacity: .95 }).addTo(map);
      ov.bringToBack(); if (state.bmOverlay) state.bmOverlay.remove(); state.bmOverlay = ov;
    };
    img.onerror = () => status("MapServer injoignable — vérifier ⚙ fond de carte", true);
    img.src = url;
  }
  let bmTimer = null;
  map.on("moveend", () => { clearTimeout(bmTimer); bmTimer = setTimeout(refreshExport, 250); });
  $("basemap").addEventListener("change", applyBasemap);
  $("fulltrack").addEventListener("change", () => fullTrack.setStyle({ opacity: $("fulltrack").checked ? .35 : 0 }));
  $("btn-fit").addEventListener("click", fitView);

  // dialogue fond de carte
  function bmDialogFill() {
    const c = state.bmCfg || {}; $("bm-provider").value = c.provider || "arcgis_online"; $("bm-layer").value = c.layer || "World_Imagery";
    $("bm-url").value = c.url || ""; $("bm-token").value = c.token || ""; $("bm-insecure").checked = c.insecure !== false; bmDialogRows();
  }
  function bmDialogRows() { const p = $("bm-provider").value; $("bm-layer-row").hidden = p !== "arcgis_online"; $("bm-ms-rows").hidden = p !== "mapserver"; }
  $("bm-provider").addEventListener("change", bmDialogRows);
  $("btn-settings").addEventListener("click", () => { const st = $("settings"); st.hidden = !st.hidden; if (!st.hidden) { bmDialogFill(); renderFilesInfo(); } });
  $("st-close").addEventListener("click", () => { $("settings").hidden = true; });
  document.addEventListener("keydown", e => { if (e.key === "Escape") $("settings").hidden = true; });
  document.addEventListener("mousedown", e => { const st = $("settings"); if (!st.hidden && !st.contains(e.target) && !$("btn-settings").contains(e.target)) st.hidden = true; });
  function renderFilesInfo() {
    const c = state.cfg || {};
    $("st-files").innerHTML = `profils tracker : <b>${(gs.prof && gs.prof.path) || "gmti_profiles.json"}</b><br>` +
      `dernier pcap : <b>${state.pcap || "—"}</b><br>fond de carte : basemap.json · réglages : pcap_web_settings.json (dossier de pcap_web.py)` +
      (c.default_limit ? `<br>limite d'analyse : ${c.default_limit} paquets (--limit)` : "");
  }
  $("bm-save").addEventListener("click", async () => {
    const cfg = { provider: $("bm-provider").value, layer: $("bm-layer").value, url: $("bm-url").value.trim(),
      token: $("bm-token").value.trim() || null, insecure: $("bm-insecure").checked };
    try { state.bmCfg = await api("/api/basemap", cfg); $("bm-msg").textContent = "enregistré (basemap.json)"; applyBasemap(); }
    catch (e) { $("bm-msg").textContent = "erreur : " + e.message; }
  });

  function fitView() {
    const pts = [];
    cot.rows.forEach(r => { if (r.pts.length) pts.push(r.pts[r.pts.length - 1]); else if (r.marker._map) pts.push(r.marker.getLatLng()); }); gmti.dots.slice(-500).forEach(d => pts.push(d.getLatLng()));
    if (gs.res) gs.res.tracks.forEach(t => pts.push(...t.pts.slice(0, 50)));
    (state.track ? state.track.sets : []).forEach(s => { pts.push([s.lat, s.lon]); if (s.corners) s.corners.forEach(c => pts.push(c)); });
    state.sets.forEach(s => { if (s.num.lat != null) pts.push([s.num.lat, s.num.lon]); if (s.num.corners) s.num.corners.forEach(c => pts.push(c)); });
    if (pts.length) map.fitBounds(L.latLngBounds(pts).pad(0.15));
  }

  // ── Analyse : flux applicatifs (routage) + flux TS (vidéo) ──────────────────
  async function load() {
    state.pcap = $("pcap").value.trim();
    if (!state.pcap) return status("indiquer un pcap", true);
    status("analyse du pcap…");
    let r, f;
    try {
      const lim = state.cfg && state.cfg.default_limit ? `&limit=${state.cfg.default_limit}` : "";
      [r, f] = await withBusy("analyse du pcap (flux TS + protocoles)…", () => Promise.all([api(`/api/streams?pcap=${encodeURIComponent(state.pcap)}${lim}`),
                                  api(`/api/flows?pcap=${encodeURIComponent(state.pcap)}${lim}`)]), ["btn-load", "btn-browse"]);
    } catch (e) { return status("erreur : " + e.message, true); }
    state.streams = r.streams; state.flows = f.flows; state.flowsDur = f.duration_s;
    api("/api/settings").then(st => fillRecent(st.recent)).catch(() => {});
    if (!gs.prof) loadProfiles();
    gs.decoded = null; gs.res = null; gs.resB = null; gs.ov = {}; lyTracks.clearLayers(); lyRawStatic.clearLayers(); LY.contacts.clearLayers(); LY.ab.clearLayers(); $("gmti-metrics").hidden = true; $("gmti-status").textContent = "Décoder le GMTI du pcap, puis lancer le tracker (profil de tuning)."; $("gmti-inv").hidden = true;
    cs.data = null; resetCot(); $("cot-detail").hidden = true; $("cot-status").textContent = "";
    const sel = $("stream"); sel.innerHTML = "";
    r.streams.forEach(s => { const o = document.createElement("option"); o.value = s.dport;
      o.textContent = `vidéo ${s.dst}:${s.dport} · ${(s.bytes / 1e6).toFixed(1)} Mo`; sel.appendChild(o); });
    renderInventory(); renderFlows();
    $("inv-sum").textContent = `${r.streams.length} flux TS`;
    $("replay-sum").textContent = `${f.flows.length} flux · ${f.duration_s.toFixed(1)} s`;
    $("video-wrap").hidden = !r.streams.length; $("right").style.gridTemplateRows = r.streams.length ? "" : "1fr"; setTimeout(() => map.invalidateSize(), 50);
    if (r.streams.length) selectStream(r.streams[0].dport); else { state.cur = null; status("aucun flux MPEG-TS (rejeu possible, pas de vidéo)", true); }
  }

  const isApp = fl => !/^(binaire|vide|gzip|JSON)$/.test(fl.dominant);
  function renderFlows() {
    const body = $("flows-body"); body.innerHTML = "";
    const all = $("flows-all").checked;
    const order = state.flows.map((fl, i) => i).sort((a, b) => (isApp(state.flows[b]) - isApp(state.flows[a])) || (state.flows[b].bytes - state.flows[a].bytes));
    let hidden = 0;
    order.forEach(i => {
      const fl = state.flows[i];
      if (!all && !isApp(fl)) { hidden++; return; }
      const tr = document.createElement("tr"); tr.dataset.i = i;
      // Cibles pré-remplies avec les destinations ORIGINALES du pcap (IP:port), modifiables ;
      // « + » ajoute un destinataire (fan-out). L'émission n'a lieu que si « émettre » est coché.
      const dsts = (fl.dsts && fl.dsts.length ? fl.dsts : []).map(d => `${d}:${fl.dport}`);
      if (fl.live) {
        const key = `${fl.proto.toLowerCase()}/${fl.dport}`; const vid = fl.proto === "UDP" && /MPEG/.test(fl.dominant);
        if (vid) tr.classList.add("vid");
        tr.innerHTML = `<td><input type="checkbox" class="fl-on" title="coché = suivi (décodé / affiché) ; rien de coché = tout"${lv.checked.has(key) ? " checked" : ""}></td>` +
          `<td class="name" title="${vid ? "clic = lire cette vidéo" : ""}">${key} ${fl.dominant}${vid ? " ▶" : ""}</td><td class="cnt">${fl.pkts}</td><td class="rate">${liveRate(fl)}</td>`;
        body.appendChild(tr);
        tr.querySelector(".fl-on").addEventListener("change", ev => { if (ev.target.checked) lv.checked.add(key); else lv.checked.delete(key); liveFollow({ watch: liveWatchList() }); });
        if (vid) tr.querySelector(".name").addEventListener("click", () => liveTap(fl));
        return;
      }
      tr.innerHTML = `<td><input type="checkbox" class="fl-on" title="coché = rejoué (affiché dans l'IHM)"></td><td class="name">${fl.proto.toLowerCase()}/${fl.dport} ${fl.dominant}</td>` +
        `<td class="cnt">${fl.pkts}</td><td class="tg"><div class="tgbox">` +
        `<span class="tgs">${(dsts.length ? dsts : [""]).map(d => `<span class="tgw"><input type="text" class="fl-tg" value="${d}" placeholder="IP[:port]" title="cible IP[:port] — pré-remplie avec la destination du pcap ; modifiable"><button class="tg-del" title="retirer cette cible">×</button></span>`).join("")}</span>` +
        `<button class="tg-add" title="ajouter un destinataire (fan-out)">+</button></div></td>`;
      body.appendChild(tr);
      tr.querySelector(".tg-add").addEventListener("click", () => {
        const w = document.createElement("span"); w.className = "tgw";
        w.innerHTML = `<input type="text" class="fl-tg" value="" placeholder="IP[:port]"><button class="tg-del" title="retirer cette cible">×</button>`;
        tr.querySelector(".tgs").appendChild(w); w.querySelector("input").focus(); wireDel(w);
      });
      tr.querySelectorAll(".tgw").forEach(wireDel);
      function wireDel(w) { w.querySelector(".tg-del").addEventListener("click", () => { const all = tr.querySelectorAll(".tgw"); if (all.length > 1) w.remove(); else w.querySelector("input").value = ""; }); }

    });
    $("flows-all").parentElement.title = hidden ? `${hidden} flux non applicatifs (binaire/vide) masqués` : "tous les flux affichés";
    $("flows-all-n").textContent = hidden ? ` (+${hidden})` : "";
    markTapRow();
  }
  $("flows-all").addEventListener("change", renderFlows);
  function markTapRow() {
    document.querySelectorAll("#flows-body tr[data-i]").forEach(tr => {
      const fl = state.flows[tr.dataset.i]; tr.classList.toggle("tap", !!(state.cur && fl.proto === "UDP" && fl.dport === state.cur.dport)); });
  }
  // Coché = rejoué : émis vers les cibles si renseignées, sinon vu seulement dans l'IHM.
  function checkedFlows() {
    if (OP) return state.flows.filter(f => f.proto === "UDP" && ((state.cur && f.dport === state.cur.dport) || /GMTI|4607|CoT/i.test(f.dominant)))
      .map(f => ({ proto: f.proto, dport: f.dport, dominant: f.dominant, targets: [], key: `${f.proto.toLowerCase()}/${f.dport}` }));
    return Array.from(document.querySelectorAll("#flows-body tr[data-i]")).filter(tr => tr.querySelector(".fl-on").checked).map(tr => {
      const fl = state.flows[tr.dataset.i];
      const targets = Array.from(tr.querySelectorAll(".fl-tg")).flatMap(i => i.value.split(",")).map(s => s.trim()).filter(Boolean);
      return { proto: fl.proto, dport: fl.dport, dominant: fl.dominant, targets, key: `${fl.proto.toLowerCase()}/${fl.dport}` }; });
  }
  function routesFromUI() { return checkedFlows().filter(f => f.targets.length).map(f => ({ proto: f.proto, dport: f.dport, targets: f.targets })); }

  function renderInventory() {
    const body = $("inv-body"); body.innerHTML = "";
    state.streams.forEach(s => {
      const d = document.createElement("div"); d.className = "stream" + (state.cur && state.cur.dport === s.dport ? " sel" : "");
      const els = s.elements.map(e => `<div class="pid">  PID ${e.pid} : ${e.name}${e.pid === s.klv_pid ? " ← KLV 0601" : ""}</div>`).join("");
      const cc = s.cc_errors ? `<span class="warn">erreurs continuité ${s.cc_errors}</span>` : "continuité OK";
      d.innerHTML = `<div class="hd">UDP → ${s.dst}:${s.dport}</div>` +
        `<div>${(s.bytes / 1e6).toFixed(1)} Mo · ${s.datagrams} datagrammes · ${s.duration_s.toFixed(1)} s · ${cc}</div>` + els +
        (s.klv_pid == null ? `<div class="warn">  pas de KLV</div>` : "");
      d.onclick = () => { $("stream").value = s.dport; selectStream(s.dport); };
      body.appendChild(d);
    });
  }

  async function selectStream(dport) {
    state.cur = state.streams.find(s => s.dport === Number(dport));
    renderInventory(); markTapRow(); showTab("fmv"); playbackStop();
    document.querySelectorAll("#flows-body tr.tap .fl-on").forEach(cb => { cb.checked = true; });   // flux vidéo choisi → coché (IHM seule si cible vide)
    stopPlayer();
    if (state.cur.first_klv) renderTable(state.cur.first_klv.map(f => ({ tag: f.tag, name: f.name, value: f.value, unit: "" })), false);
    status("trace KLV…");
    try { state.track = await withBusy("trace KLV du flux vidéo…", () => api(`/api/klv?pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur.dport}`)); }
    catch (e) { state.track = null; return status("erreur KLV : " + e.message, true); }
    fullTrack.setLatLngs(state.track.sets.map(s => [s.lat, s.lon]));
    $("klv-sum").textContent = `${state.track.n} sets · ${state.track.n && (state.track.n / state.cur.duration_s).toFixed(1)} Hz`;
    $("tl-d").textContent = state.cur.duration_s.toFixed(1);
    fitView();
    status(`flux ${state.cur.dst}:${state.cur.dport} prêt — ▶ Lire`);
    drawTimeline();
  }

  // ── Lecteur mpegts.js (fichier : /video.ts ; rejeu : ws tap) + KLV synchrone ──
  function startPlayer(url, live, dvr) {
    stopPlayer();
    if (!mpegts.isSupported()) return status("MSE non supporté par ce navigateur", true);
    // dvr : ressource relue depuis le disque (fichier suivi) → lazyLoad = mpegts.js suspend le chargement
    // au-delà de 60 s d'avance et reprend par Range (octets cumulés côté serveur) ; mémoire bornée.
    const player = mpegts.createPlayer({ type: "mpegts", isLive: live, url }, {
      enableWorker: false, lazyLoad: !!dvr, lazyLoadMaxDuration: 60, lazyLoadRecoverDuration: 20, enableStashBuffer: !live, stashInitialSize: 128 * 1024,
      liveBufferLatencyChasing: live, liveBufferLatencyMaxLatency: 1.5, liveBufferLatencyMinRemain: 0.4,
      autoCleanupSourceBuffer: live || !!dvr, seekType: "range" });
    player.attachMediaElement(video);
    player.on(mpegts.Events.SYNCHRONOUS_KLV_METADATA_ARRIVED, onKlv);
    player.on(mpegts.Events.ASYNCHRONOUS_KLV_METADATA_ARRIVED, onKlv);
    player.on(mpegts.Events.ERROR, (t, d, i) => {
      status(`erreur lecteur : ${t} / ${d} ${i && i.msg || ""}`, true);
      if (live && ((state.replay && state.replay.running) || (pb.follow && pb.edge)) && state.retries < 5) {      // tap live : on se raccroche
        state.retries++; setTimeout(() => { if ((state.replay && state.replay.running) || (pb.follow && pb.edge)) startPlayer(url, true); }, 600);
      } else if (!live && pb.on && state.retries < 5) {                               // lecture fichier : relance au même instant
        state.retries++; const at = Math.max(0, pb.t - pb.vOffset);
        setTimeout(() => { if (pb.on) { startPlayer(url, false); video.playbackRate = speedVal() || 1; const go = () => { video.currentTime = at; video.removeEventListener("loadedmetadata", go); }; video.addEventListener("loadedmetadata", go); if (pb.paused) video.pause(); } }, 500);
      }
    });
    player.on(mpegts.Events.MEDIA_INFO, mi => status(`${live ? "LIVE (tap du rejeu)" : "lecture fichier"} — ${mi.videoCodec || ""} ${mi.width || ""}×${mi.height || ""} ${mi.fps ? mi.fps.toFixed(1) + " fps" : ""}`));
    player.load(); player.play().catch(() => {});
    state.player = player; state.sets = []; state.applied = -1; trace.setLatLngs([]);
    if (!live && !pb.on) state.retries = 0;
    $("mode-badge").textContent = live ? "● LIVE — flux tapé sur le moteur de rejeu" : "FICHIER";
    $("mode-badge").className = "overlay" + (live ? " live" : "");
  }
  function stopPlayer() {
    if (state.player) { try { state.player.pause(); state.player.unload(); state.player.detachMediaElement(); state.player.destroy(); } catch (e) {} }
    state.player = null;
  }
  video.addEventListener("ended", () => { if (pb.on && pb.follow && !pb.edge) return pb.liveMission ? goEdge() : playbackPause(true); if (pb.on && !pb.follow && $("loop").checked) playbackSeek(0); });

  async function play() {
    if (isLive()) return liveStart();
    if (!state.pcap) return status("analyser un pcap d'abord", true);
    const sel = $("mode").value; const emitting = sel === "emit";
    if (sel === "play") return playbackStart();
    if (sel === "follow") return followStart();
    state.mode = "replay";
    const q = `pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur ? state.cur.dport : 0}`;
    // Rejeu : seuls les flux COCHÉS sont rejoués (émis si cible, sinon vus dans l'IHM).
    // Le lecteur ws est ouvert AVANT le start pour ne rien rater.
    const checked = checkedFlows();
    if (!checked.length) return status("cocher au moins un flux à rejouer", true);
    const routes = emitting ? routesFromUI() : [];                        // IHM seule : aucune émission
    if (emitting && !routes.length) return status("mode émission : renseigner au moins une cible IP:port sur un flux coché", true);
    const watch = checked.map(f => f.key);
    const videoOn = state.cur && checked.some(f => f.proto === "UDP" && f.dport === state.cur.dport);
    state.videoOn = !!videoOn; state.emitting = emitting;
    const taps = videoOn ? [state.cur.dport] : [];
    if (videoOn) startPlayer(`${WS}/ws/video?dport=${state.cur.dport}`, true);
    else { stopPlayer(); $("mode-badge").textContent = "flux vidéo non coché — pas de lecture"; $("mode-badge").className = "overlay"; }
    state.log = []; $("replay-log").textContent = ""; resetCot(); resetGmti(); resetLive(); fitOnce = false; state.retries = 0;
    const gmtiChecked = checked.some(f => /GMTI|4607/i.test(f.dominant));
    const track = (gmtiChecked && $("gmti-live").checked) ? { profile: $("gmti-profile").value || "defaut", overrides: gs.ov } : null;
    try {
      await api("/api/replay/start", { pcap: state.pcap, routes, speed: parseFloat($("speed").value), loop: $("loop").checked,
        rebase: $("rebase").checked, taps, watch, track });
      if (track) { showTab("gmti"); $("gmti-live-body").textContent = `pistage temps réel actif — profil ${track.profile}${Object.keys(track.overrides).length ? " + surcharges" : ""}`; }
      $("btn-pause").disabled = false; $("btn-pause").textContent = "⏸";
      $("tl-mode").textContent = `rejeu ×${$("speed").value || "max"} — ` + (emitting ? `${routes.length} route(s) émise(s) en UDP/TCP` : "IHM seule (aucune émission)") + (taps.length ? " + vidéo" : "") + " · clic sur la timeline = saut, ⏸ = pause";
      status(`rejeu ${emitting ? "avec émission" : "IHM seule"} : ${checked.map(f => f.key).join(", ")}`);
      $("mode-badge").textContent = (videoOn ? "● LIVE — flux tapé sur le moteur de rejeu" : "flux vidéo non coché — pas de lecture") + (emitting ? " · ÉMISSION UDP/TCP" : " · IHM seule");
    } catch (e) { stopPlayer(); status("rejeu : " + e.message, true); }
  }
  // ── Transport du rejeu : pause / vitesse à chaud / saut sur la timeline ────────
  $("btn-pause").addEventListener("click", async () => {
    if (pb.on) return playbackPause(!pb.paused);
    const paused = !(state.replay && state.replay.paused);
    try { await api("/api/replay/pause", { paused }); if (state.player && state.videoOn) { if (paused) video.pause(); else video.play().catch(() => {}); } status(paused ? "rejeu en pause" : "rejeu repris"); }
    catch (e) { status("pause : " + e.message, true); }
  });
  $("speed").addEventListener("change", async () => {
    if (pb.on) return playbackSpeed();
    if (state.replay && state.replay.running) { try { await api("/api/replay/speed", { speed: parseFloat($("speed").value) }); status(`vitesse ×${$("speed").value || "max"} appliquée`); } catch (e) { status("vitesse : " + e.message, true); } }
  });
  async function seekReplay(t) {
    if (!(state.replay && state.replay.running)) return;
    state.seeking = true;
    state.seekEnd = busy(`saut à t=${t.toFixed(0)} s — rembobinage à blanc (pistes / CoT reconstitués)…`);
    resetCot(); resetGmti(); resetLive();
    try {
      await api("/api/replay/seek", { t });
      if (state.videoOn && state.cur) startPlayer(`${WS}/ws/video?dport=${state.cur.dport}`, true);   // nouveau flux tapé
      status(`saut à t=${t.toFixed(0)} s`);
    } catch (e) { state.seeking = false; if (state.seekEnd) { state.seekEnd(); state.seekEnd = null; } status("saut : " + e.message, true); }
  }

  // ── Lecture — IHM seule : ligne de temps préchargée, horloge côté navigateur ───
  const pb = { on: false, tl: null, tracks: [], t: 0, paused: false, wall: 0, cotIdx: 0, dwIdx: 0, videoOn: false, vOffset: 0, lastT: -1, tentShown: false,
    follow: false, edge: false, timer: null, seq: null, edgeAge: null };
  async function playbackStart() {
    const checked = checkedFlows();
    if (!checked.length) return status("cocher au moins un flux à lire", true);
    stopPlayer(); if (state.replay && state.replay.running) { try { await api("/api/replay/stop", {}); } catch (e) {} }
    const watch = checked.map(f => f.key).join(",");
    const gmtiChecked = checked.some(f => /GMTI|4607/i.test(f.dominant));
    const profile = $("gmti-profile").value || "defaut", ovq = Object.keys(gs.ov).length ? `&overrides=${encodeURIComponent(JSON.stringify(gs.ov))}` : "";
    const trackQ = (gmtiChecked && $("gmti-live").checked) ? `&profile=${profile}${ovq}` : "";
    let tl;
    try { tl = await withBusy("préchargement de la ligne de temps (CoT, GMTI, pistes, vidéo)…", () => api(`/api/timeline?pcap=${encodeURIComponent(state.pcap)}&watch=${encodeURIComponent(watch)}${trackQ}${limQ()}`), ["btn-play"]); }
    catch (e) { return status("lecture : " + e.message, true); }
    pb.tl = tl; pb.tracks = tl.tracks || []; pb.on = true; pb.paused = false; pb.t = 0; pb.wall = performance.now(); pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; state.retries = 0;
    state.mode = "play"; resetCot(); resetGmti(); resetLive(); fitOnce = false;
    pb.videoOn = !!(state.cur && checked.some(f => f.proto === "UDP" && f.dport === state.cur.dport));
    const vinfo = pb.videoOn ? (tl.video || []).find(v => v.dport === state.cur.dport) : null;
    pb.vOffset = vinfo ? vinfo.t_offset : 0;
    if (pb.videoOn) { startPlayer(U(`/video.ts?pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur.dport}`), false); video.playbackRate = speedVal() || 1; }
    else { $("mode-badge").textContent = "LECTURE — sans vidéo"; $("mode-badge").className = "overlay"; }
    if (pb.videoOn) { $("mode-badge").textContent = "LECTURE — vidéo fichier (seek image) · IHM seule"; }
    $("btn-pause").disabled = false; $("btn-pause").textContent = "⏸";
    setState("playing", `▶ lecture ×${$("speed").value || "max"} · IHM seule`);
    $("tl-mode").textContent = `lecture ×${$("speed").value || "max"} — ${checked.length} flux, ${tl.cot.length} events CoT, ${tl.dwells.length} dwells, ${pb.tracks.length} pistes` + (tl.tracks_error ? ` (pistes : ${tl.tracks_error})` : "") + " · clic timeline = saut, ⏸ = pause";
    $("tl-d").textContent = tl.duration.toFixed(1);
    if (gmtiChecked && trackQ) { showTab("gmti"); $("gmti-live-body").textContent = `lecture : pistes du run hors ligne (profil ${profile}${ovq ? "*" : ""}) datées sur la capture`; }
    status(`lecture IHM seule démarrée : ${checked.map(f => f.key).join(", ")}`);
    fitTimeline();
  }
  const speedVal = () => parseFloat($("speed").value);
  function fitTimeline() {
    const pts = []; (pb.tl.cot || []).slice(0, 2000).forEach(c => { if (c[5] != null && c[6] != null && !(c[5] === 0 && c[6] === 0)) pts.push([c[5], c[6]]); });
    (pb.tl.dwells || []).slice(0, 500).forEach(d => { if (d[2]) pts.push(d[2]); if (d[1] && d[1][0] != null) pts.push(d[1]); });
    if (!state.cur && pts.length) map.fitBounds(L.latLngBounds(pts).pad(0.15));
  }
  function playbackStop() { if (pb.follow) followStop(); if (pb.on) setState("stopped", "■ arrêt"); pb.on = false; $("btn-pause").disabled = true; }

  // ── Suivi d'un fichier EN COURS D'ÉCRITURE (capture maître StratusServer v2) : DVR pendant le live ──
  // Le serveur rattrape le fichier puis suit sa croissance (et le segment suivant) ; l'IHM précharge la
  // ligne de temps comme en lecture, reçoit les ajouts chaque seconde (delta) et joue la vidéo soit au
  // bord (flux poussé sur /ws/video, comme le live), soit en retour arrière (HTTP Range sur le tampon).
  async function followStart(opts) {
    opts = opts || {};
    const checked = checkedFlows();
    if (!checked.length) return status("cocher au moins un flux à suivre", true);
    stopPlayer(); if (state.replay && state.replay.running) { try { await api("/api/replay/stop", {}); } catch (e) {} }
    const watch = checked.map(f => f.key);
    const gmtiChecked = checked.some(f => /GMTI|4607/i.test(f.dominant));
    const track = (gmtiChecked && $("gmti-live").checked) ? { profile: $("gmti-profile").value || "defaut", overrides: gs.ov } : null;
    pb.videoOn = !!(state.cur && checked.some(f => f.proto === "UDP" && f.dport === state.cur.dport));
    const taps = pb.videoOn ? [state.cur.dport] : [];
    let tl;
    try {
      let st0;
      if (opts.pre) { st0 = opts.pre; pb.fid = st0.id; if (taps.length) await api("/api/follow/follow", { id: pb.fid, taps }); }   // déjà ouvert (page opérateur)
      else { st0 = await withBusy("démarrage du suivi du fichier…", () => api("/api/follow/start", { pcap: state.pcap, watch, track, taps }), ["btn-play"]); pb.fid = st0.id; }
      if (st0.joined) status("suivi déjà en cours pour cette mission : rejoint");
      tl = await withBusy("rattrapage du fichier (CoT, GMTI, pistes, vidéo)…", followWaitCatchup, ["btn-play"]);
    } catch (e) { return status("suivi : " + e.message, true); }
    pb.tl = tl; pb.tracks = tl.tracks || []; pb.seq = tl.seq; pb.on = true; pb.follow = true; pb.paused = false; pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; state.retries = 0;
    if (tl.klv && tl.klv.length) fullTrack.setLatLngs(tl.klv.map(k => [k[1], k[2]]));          // trace plateforme complète (journal KLV)
    state.mode = "play"; resetCot(); resetGmti(); resetLive(); fitOnce = false;
    pb.liveMission = opts.live !== false;                                       // false : mission terminée (lecture depuis le début, pas de « direct »)
    $("btn-edge").hidden = !pb.liveMission; $("btn-pause").disabled = false; $("btn-pause").textContent = "⏸";
    if (gmtiChecked && track) { showTab("gmti"); $("gmti-live-body").textContent = `suivi : pistes du tracker temps réel (profil ${track.profile}) datées sur la capture`; }
    if (pb.liveMission) goEdge(); else { pb.edge = false; pb.t = 0; pb.wall = performance.now(); goDvr(0); resetCot(); resetGmti(); resetLive(); pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; }
    if (pb.timer) clearInterval(pb.timer); pb.timer = setInterval(followPoll, 1000); followPoll();
    status(`suivi du fichier démarré : ${checked.map(f => f.key).join(", ")} — ${tl.duration.toFixed(0)} s déjà capturées`);
    fitTimeline();
  }
  async function followWaitCatchup() {                  // attend la fin du rattrapage côté serveur, puis charge la ligne de temps
    for (let i = 0; i < 7200; i++) {
      const st = await api(`/api/follow/status?id=${pb.fid}`); if (!st.running) throw new Error("suivi arrêté");
      if (!st.catching_up) break;
      status(`rattrapage… ${st.n_packets} paquets · ${(st.duration || 0).toFixed(0)} s · ${((st.bytes_read || 0) / 1e6).toFixed(0)} Mo`);
      await new Promise(r => setTimeout(r, 500));
    }
    return api(`/api/follow/timeline?id=${pb.fid}`);
  }
  async function followPoll() {
    if (!pb.on || !pb.follow || !pb.seq) return;
    let d; try { d = await api(`/api/follow/delta?id=${pb.fid}&cot=${pb.seq.cot}&dw=${pb.seq.dw}&tr=${pb.seq.tr}&k=${pb.seq.k || 0}`); } catch (e) { return; }
    if (!pb.on || !pb.follow) return;
    if (d.cot.length) pb.tl.cot.push(...d.cot);
    if (d.dwells.length) pb.tl.dwells.push(...d.dwells);
    if (d.klv && d.klv.length) { pb.tl.klv = (pb.tl.klv || []).concat(d.klv); d.klv.forEach(k => fullTrack.addLatLng([k[1], k[2]])); }
    (d.track_meta || []).forEach(m => { let tr = pb.tracks.find(t => t.id === m.id); if (!tr) pb.tracks.push({ id: m.id, air: m.air, rot: m.rot, hits: m.hits, hist: [] }); else { tr.hits = m.hits; tr.air = m.air; tr.rot = m.rot; } });
    (d.track_rows || []).forEach(([id, row]) => { const tr = pb.tracks.find(t => t.id === id); if (tr) tr.hist.push(row); });
    pb.seq = d.seq; pb.tl.duration = d.duration; pb.tl.video = d.video; pb.edgeAge = d.edge_age_s; if (d.coverage) pb.tl.coverage = d.coverage;
    if (d.closed && pb.liveMission) {                                            // capture close (silence) : plus de direct
      pb.liveMission = false; $("btn-edge").hidden = true;
      if (pb.edge) { pb.edge = false; stopPlayer(); playbackPause(true); $("mode-badge").textContent = "FIN DE MISSION — lecture depuis le début possible"; $("mode-badge").className = "overlay"; }
      status("mission terminée");
    }
    $("tl-mode").textContent = `suivi du fichier${d.segment ? " · " + d.segment : ""} — ${pb.tl.cot.length} events CoT, ${pb.tl.dwells.length} dwells, ${pb.tracks.length} pistes · `
      + (pb.edge ? "● DIRECT" : (pb.liveMission ? `DVR t=${pb.t.toFixed(0)} s` : `lecture t=${pb.t.toFixed(0)} s`)) + (pb.liveMission ? ` · bord ${d.duration.toFixed(0)} s` : ` · ${d.duration.toFixed(0)} s`)
      + (d.edge_age_s != null && d.edge_age_s > 5 ? ` (fichier figé depuis ${d.edge_age_s.toFixed(0)} s)` : "") + " · clic timeline = retour arrière, ⟫ = direct";
  }
  function goEdge() {                                      // recolle au bord : lecteur ws (flux poussé au fil de l'écriture), état reconstitué à t = bord
    if (!pb.follow) return;
    pb.edge = true; const D = pb.tl.duration;
    if (pb.videoOn && state.cur) { pb.vOffset = D; startPlayer(`${WS}/ws/video?dport=${state.cur.dport}&follow=${pb.fid}`, true); $("mode-badge").textContent = "● DIRECT — suivi du fichier (flux poussé au fil de l'écriture)"; $("mode-badge").className = "overlay live"; }
    else { stopPlayer(); $("mode-badge").textContent = "● DIRECT — suivi du fichier (sans vidéo)"; $("mode-badge").className = "overlay live"; }
    pb.t = D; pb.wall = performance.now(); pb.paused = false; $("btn-pause").textContent = "⏸";
    resetCot(); resetGmti(); resetLive(); pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; playbackRender(D, true);
    setState("playing", "● direct · suivi du fichier");
  }
  function goDvr(t) {                                      // retour arrière : lecteur fichier (HTTP Range) sur le tampon actuel (instantané)
    pb.edge = false;
    if (pb.videoOn && state.cur) {
      // le serveur sert le TS à partir du datagramme daté t (index du tampon) : le lecteur démarre à 0 = t (saut exact)
      pb.vOffset = t;
      startPlayer(U(`/video.ts?follow=${pb.fid}&dport=${state.cur.dport}&from=${t.toFixed(3)}&_=${Date.now()}`), false, true); video.playbackRate = speedVal() || 1;
      $("mode-badge").textContent = pb.liveMission ? "DVR — retour arrière sur le fichier en cours (⟫ Direct pour recoller)" : "LECTURE — mission terminée (relecture depuis le disque)"; $("mode-badge").className = "overlay";
    }
    setState("playing", pb.liveMission ? `▶ DVR · t=${t.toFixed(0)} s · ⟫ = direct` : `▶ lecture · t=${t.toFixed(0)} s`);
  }
  async function followStop() {
    if (pb.timer) { clearInterval(pb.timer); pb.timer = null; }
    pb.follow = false; pb.edge = false; $("btn-edge").hidden = true;
    try { await api("/api/follow/stop", { id: pb.fid, force: !OP }); } catch (e) {}   // opérateur : se détache ; analyste : arrêt
  }
  $("btn-edge").addEventListener("click", () => { if (pb.follow) { goEdge(); status("retour au direct"); } });
  function playbackSeek(t) {
    if (!pb.on) return; t = Math.max(0, Math.min(t, pb.tl.duration));
    if (pb.follow) {
      if (pb.liveMission && t >= pb.tl.duration - 3) { goEdge(); return status("retour au direct"); }
      pb.t = t; pb.wall = performance.now(); goDvr(t);
      resetCot(); resetGmti(); resetLive(); pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; playbackRender(t, true);
      return status(`DVR : saut à t=${t.toFixed(1)} s`);
    }
    pb.t = t; pb.wall = performance.now();
    if (pb.videoOn && state.player) { video.currentTime = Math.max(0, t - pb.vOffset); }
    // état reconstitué depuis le début (rapide : listes en mémoire)
    const T0 = performance.now(); resetCot(); resetGmti(); resetLive(); pb.cotIdx = 0; pb.dwIdx = 0; pb.lastT = -1; const T1 = performance.now();
    playbackRender(t, true); const T2 = performance.now(); pb.dbg = { reset: Math.round(T1 - T0), render: Math.round(T2 - T1) };
    status(`saut à t=${t.toFixed(1)} s`);
  }
  function playbackPause(paused) {
    pb.paused = paused; if (pb.videoOn && state.player) { if (paused) video.pause(); else video.play().catch(() => {}); }
    if (!paused) pb.wall = performance.now();
    $("btn-pause").textContent = paused ? "▶" : "⏸"; status(paused ? "lecture en pause" : "lecture reprise");
    setState(paused ? "paused" : "playing", paused ? `⏸ lecture en pause · t=${pb.t.toFixed(1)} s` : `▶ lecture ×${$("speed").value || "max"} · IHM seule`);
  }
  function playbackSpeed() { if (pb.videoOn && state.player) video.playbackRate = speedVal() || 16; pb.wall = performance.now(); if (pb.on && !pb.paused) setState("playing", `▶ lecture ×${$("speed").value || "max"} · IHM seule`); }
  function playbackTick() {
    if (!pb.on) return;
    let t;
    if (pb.videoOn && state.player && !video.paused && !video.ended) t = pb.vOffset + video.currentTime;
    else if (pb.paused) t = pb.t;
    else { const now = performance.now(); const sp = pb.follow ? 1 : (speedVal() || 16); t = pb.t + (now - pb.wall) / 1000 * sp; pb.wall = now; if (t >= pb.tl.duration) { t = pb.tl.duration; if (!pb.follow && $("loop").checked) { playbackSeek(0); return; } } }
    if (pb.follow && t > pb.tl.duration) t = pb.tl.duration;
    pb.t = t; playbackRender(t, false);
  }
  const ST_NAME = { T: "TENTATIVE", C: "CONFIRMED", S: "SOLID", K: "COASTING", D: "DEAD" };
  function playbackRender(t, jump) {
    const tl = pb.tl; const P0 = performance.now(); let P1 = P0, P2 = P0;
    // CoT : événements écoulés depuis le dernier rendu (dernier par uid)
    if (tl.cot.length && pb.cotIdx < tl.cot.length && tl.cot[pb.cotIdx][0] <= t) {
      const evs = new Map(); let n = 0;
      while (pb.cotIdx < tl.cot.length && tl.cot[pb.cotIdx][0] <= t) { const c = tl.cot[pb.cotIdx++]; n++;
        evs.set(c[1] || ("#" + pb.cotIdx), { uid: c[1], type: c[2], aff: c[3], callsign: c[4], lat: c[5], lon: c[6], speed: c[7], course: c[8], src: c[9] }); }
      onCotBatch({ t, events: Array.from(evs.values()), total: pb.cotIdx });
    }
    P1 = performance.now();
    // GMTI : dwells / plots écoulés
    if (tl.dwells.length && pb.dwIdx < tl.dwells.length && tl.dwells[pb.dwIdx][0] <= t) {
      const dws = [], plots = []; let sensor = null;
      while (pb.dwIdx < tl.dwells.length && tl.dwells[pb.dwIdx][0] <= t) { const d = tl.dwells[pb.dwIdx++];
        if (d[1]) sensor = d[1]; if (d[2]) dws.push({ center: d[2], poly: d[3], n: d[4] }); if (d[6]) plots.push(...d[6]); }
      if (jump) { dws.splice(0, Math.max(0, dws.length - 12)); plots.splice(0, Math.max(0, plots.length - 600)); }   // saut : seuls les derniers plots/dwells sont redessinés
      onGmtiBatch({ t, dwells: dws, plots, sensor, pkts: 0, total_pkts: pb.dwIdx, total_plots: gmti.stats.plots + plots.length, total_dwells: pb.dwIdx });
    }
    P2 = performance.now();
    // Pistes (run hors ligne) : état à t
    if (pb.tracks.length) {
      const out = []; const cnt = { TENTATIVE: 0, CONFIRMED: 0, SOLID: 0, COASTING: 0, EVER: 0 };
      pb.tracks.forEach(tr => {
        const h = tr.hist; if (!h.length || h[0][0] > t) return;
        let lo = 0, hi = h.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (h[m][0] <= t) lo = m; else hi = m - 1; }
        const e = h[lo]; if (t - e[0] > 120) return;                    // morte depuis longtemps
        const st = ST_NAME[e[3]] || "TENTATIVE"; if (st === "DEAD") return;
        cnt[st] = (cnt[st] || 0) + 1; if (e[5]) cnt.EVER++;
        let hits = 0; for (let i = 0; i <= lo; i++) hits += h[i][4];
        const tail = h.slice(Math.max(0, lo - 30), lo + 1).map(x => [x[1], x[2]]);
        const prev = lo > 0 ? h[lo - 1] : e; const dt = e[0] - prev[0];
        const sp = dt > 0 ? MGRS.distBearing(prev[1], prev[2], e[1], e[2]).d / dt : 0;
        out.push({ id: tr.id, lat: e[1], lon: e[2], speed: e[6] != null ? e[6] : Math.round(sp * 10) / 10, heading: e[7] != null ? e[7] : 0, state: st, hits, misses: 0, ever: !!e[5], is_air: tr.air, is_rotator: tr.rot, age_s: Math.round((t - e[0]) * 10) / 10, tail });
      });
      renderLive({ tracks: out, stats: { profile: ($("gmti-profile").value || "defaut") + " (hors ligne)", overrides: gs.ov, n_dwells: pb.dwIdx, displayable: cnt.EVER, solid: cnt.SOLID, confirmed: cnt.CONFIRMED, coasting: cnt.COASTING, tentative: cnt.TENTATIVE, archived: 0 } });
    }
    pb.lastT = t; if (jump) pb.dbg2 = { cot: Math.round(P1 - P0), gmti: Math.round(P2 - P1), tracks: Math.round(performance.now() - P2) };
  }

  async function stopAll() {
    if (lv.on) return liveStop();
    playbackStop(); setState("stopped", "■ arrêt");
    stopPlayer();
    try { await api("/api/replay/stop", {}); } catch (e) {}
    status("arrêté");
  }

  function onKlv(ev) {
    const r = KLV0601.decode(ev.data); if (!r) return;
    const pts = ev.pts != null ? ev.pts : video.currentTime * 1000;
    state.sets.push({ pts, num: r.num, fields: r.fields });
    if (state.sets.length > 20000) { state.sets.splice(0, 5000); state.applied = Math.max(-1, state.applied - 5000); }
    $("tl-n").textContent = state.sets.length;
  }
  function indexAt(tms) {
    const a = state.sets; let lo = 0, hi = a.length - 1, ans = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (a[m].pts <= tms) { ans = m; lo = m + 1; } else hi = m - 1; }
    return ans;
  }
  function apply(idx, tms) {
    const s = state.sets[idx], n = s.num;
    if (n.lat != null) { sensor.setLatLng([n.lat, n.lon]); sensor.setTooltipContent(`${fmt(n.lat)} ${fmt(n.lon)} · ${fmt(n.alt, 0)} m · cap ${fmt(n.hdg, 1)}°`); }
    if (n.fc_lat != null) { center.setLatLng([n.fc_lat, n.fc_lon]); if (n.lat != null) los.setLatLngs([[n.lat, n.lon], [n.fc_lat, n.fc_lon]]); state.klvCenter = [n.fc_lat, n.fc_lon]; }
    if (n.corners) footprint.setLatLngs(n.corners);
    follow(n);
    if (idx === state.applied + 1) { if (n.lat != null) trace.addLatLng([n.lat, n.lon]); }
    else trace.setLatLngs(state.sets.slice(0, idx + 1).filter((x, i) => x.num.lat != null && (i % 3 === 0 || i === idx)).map(x => [x.num.lat, x.num.lon]));
    $("hud").textContent = `capteur ${fmt(n.lat)} ${fmt(n.lon)}  alt ${fmt(n.alt, 0)} m\ncap ${fmt(n.hdg, 1)}°  tang ${fmt(n.pitch, 1)}°  roul ${fmt(n.roll, 1)}°\nFOV ${fmt(n.hfov, 2)}°×${fmt(n.vfov, 2)}°  portée ${fmt(n.slant, 0)} m\ncentre ${fmt(n.fc_lat)} ${fmt(n.fc_lon)}` + (vidgap.last != null ? `\npiste ${vidgap.id} à ${vidgap.last.toFixed(0)} m du centre image` : "");
    $("tl-utc").textContent = utc(n.ts_us);
    $("tl-lag").textContent = (tms - s.pts).toFixed(0);
    if (performance.now() - state.tableAt > 120) { renderTable(s.fields, true); state.tableAt = performance.now(); }
    state.applied = idx;
  }
  function follow(n) {
    const m = $("follow").value; if (m === "none") return;
    const inner = map.getBounds().pad(-0.3);
    if (m === "sensor" && n.lat != null && !inner.contains([n.lat, n.lon])) map.panTo([n.lat, n.lon], { animate: true, duration: .3 });
    else if (m === "center" && n.fc_lat != null && !inner.contains([n.fc_lat, n.fc_lon])) map.panTo([n.fc_lat, n.fc_lon], { animate: true, duration: .3 });
    else if (m === "both" && n.lat != null && n.fc_lat != null) {
      const b = L.latLngBounds([[n.lat, n.lon], [n.fc_lat, n.fc_lon]]); if (n.corners) n.corners.forEach(c => b.extend(c));
      if (!map.getBounds().contains(b)) map.fitBounds(b.pad(0.4), { animate: true, duration: .3 });
    }
  }
  $("follow").addEventListener("change", () => { if (state.applied >= 0) follow(state.sets[state.applied].num); });

  const HL = new Set([2, 5, 13, 14, 15, 16, 17, 21, 23, 24, 25]);
  function renderTable(fields, live) {
    $("klv-body").innerHTML = fields.map(f => {
      let v = f.value; if (typeof v === "number") v = Number.isInteger(v) ? String(v) : v.toFixed(Math.abs(v) < 10 ? 4 : 3);
      return `<tr class="${HL.has(f.tag) ? "hl" : ""}"><td class="tag">${f.tag}</td><td class="name" title="${f.name}">${f.name}</td><td class="val">${v}</td><td class="unit">${f.unit || ""}</td></tr>`;
    }).join("");
    if (!live) $("klv-sum").textContent = "1er set (statique)";
  }

  // ── WebSocket d'événements (moteur de rejeu) ─────────────────────────────────
  function connectEvents() {
    const ws = new WebSocket(`${WS}/ws/events`); state.evws = ws;
    ws.onmessage = e => { const ev = JSON.parse(e.data); onEvent(ev); };
    ws.onclose = () => { state.evws = null; setTimeout(connectEvents, 2000); };
    ws.onerror = () => ws.close();
  }
  function onEvent(ev) {
    if (ev.type === "hello") { state.replay = ev.replay; renderReplay(); }
    else if (ev.type === "replay" && ev.live) { state.replay = ev; if (ev.running) { lv.on = true; liveFlows(ev.flows_live); setState("playing", `● écoute réseau · ${ev.mode || ""} · ${ev.captured || 0} trames · t=${(ev.t || 0).toFixed(0)} s` + (ev.recording ? " · ⏺" : "")); if (ev.error) status("écoute : " + ev.error, true); } else { lv.on = false; } }
    else if (ev.type === "replay") { state.replay = ev; renderReplay(); if (state.seeking && ev.t > 0) { state.seeking = false; if (state.seekEnd) { state.seekEnd(); state.seekEnd = null; } }
      $("btn-pause").textContent = ev.paused ? "▶" : "⏸"; $("btn-pause").disabled = !ev.running;
      if (ev.running && !pb.on) setState(ev.paused ? "paused" : (state.emitting ? "emitting" : "playing"), (ev.paused ? "⏸ rejeu en pause" : (state.emitting ? "● rejeu + émission UDP/TCP" : "● rejeu IHM")) + ` ×${ev.speed || "max"} · t=${(ev.t || 0).toFixed(1)} s` + (ev.sent ? ` · ${ev.sent} émis` : "")); }
    else if (ev.type === "log") { state.log.push(ev.msg); if (state.log.length > 200) state.log.shift();
      const el = $("replay-log"); el.textContent = state.log.slice(-40).join("\n"); el.scrollTop = el.scrollHeight; }
    else if (ev.type === "cot") { onCotBatch(ev); if (!fitOnce && !state.cur) { fitOnce = true; fitView(); } }
    else if (ev.type === "gmti") { onGmtiBatch(ev); if (!fitOnce && (!state.cur || lv.on)) { fitOnce = true; fitView(); } }
    else if (ev.type === "end" && ev.live) { lv.on = false; stopPlayer(); state.replay = { running: false }; setState("stopped", "■ arrêt"); $("replay-sum").textContent = `écoute arrêtée — ${state.flows.length} flux vus`; }
    else if (ev.type === "end") {
      if (state.seeking) return;                          // fin du run interrompu par un saut : ignorée
      status(ev.stopped ? "rejeu arrêté" : "rejeu terminé"); if (state.mode === "replay") stopPlayer(); state.replay = { running: false }; renderReplay(); $("btn-pause").disabled = true; setState("stopped", ev.stopped ? "■ arrêt" : "■ terminé"); }
  }
  function renderReplay() {
    const r = state.replay || {};
    if (!r.running) { $("replay-sum").textContent = state.flows.length ? `${state.flows.length} flux · moteur arrêté` : "moteur arrêté"; $("tl-replay").textContent = ""; $("replay-stats").innerHTML = r.sent ? `dernier rejeu : <b>${r.sent}</b> msg · passe ${r.passes || 1}` : ""; return; }
    const pps = r.wall ? (r.sent / r.wall).toFixed(0) : "—";
    $("replay-sum").textContent = `● en cours ×${r.speed || "max"} — t=${(r.t || 0).toFixed(1)} s`;
    const flows = Object.entries(r.flows || {}).map(([k, v]) => `${k}: <b>${v}</b>`).join(" · ");
    $("replay-stats").innerHTML = `émis <b>${r.sent || 0}</b> msg · <b>${((r.bytes || 0) / 1e6).toFixed(1)}</b> Mo · <b>${pps}</b> msg/s · passe <b>${r.passes || 1}</b><br>${flows || "<span class=muted>aucune route (tap IHM seul)</span>"}`;
    $("tl-replay").innerHTML = `rejeu : t=<b>${(r.t || 0).toFixed(1)}</b> s · <b>${r.sent || 0}</b> émis`;
  }

  // ── Timeline ────────────────────────────────────────────────────────────────
  const tl = $("timeline"), ctx = tl.getContext("2d");
  // Mode rejeu : le lecteur vidéo (flux tapé) repart de 0 à chaque (re)démarrage ; on décale son
  // temps du start_at du rejeu pour rester en temps de capture sur la timeline.
  const vOff = () => pb.on ? pb.vOffset : ((state.mode === "replay" && state.replay && state.replay.start_at) ? state.replay.start_at : 0);
  function duration() {
    if (lv.on) return Math.max(10, (state.replay && state.replay.t) || 0);
    if (pb.on && pb.tl) return pb.tl.duration || (state.flowsDur || 0);
    if (state.mode === "replay") return Math.max(state.flowsDur || 0, (state.replay && state.replay.t) || 0, vOff() + video.currentTime);
    return (isFinite(video.duration) && video.duration > 0) ? video.duration : (state.cur ? state.cur.duration_s : 0);
  }
  // Origine absolue de la ligne de temps (epoch s) : horodatage RÉEL de la mission sur la règle
  const tlT0 = () => (pb.on && pb.tl && pb.tl.t0) ? pb.tl.t0 : null;
  const hhmmss = t => { const d = new Date(t * 1000); return isNaN(d) ? "" : d.toISOString().slice(11, 19); };
  const fmtT = t => { const t0 = tlT0(); return t0 ? hhmmss(t0 + t) : (t >= 3600 ? `${Math.floor(t / 3600)}h${String(Math.floor(t % 3600 / 60)).padStart(2, "0")}` : t >= 60 ? `${Math.floor(t / 60)}m${String(Math.round(t % 60)).padStart(2, "0")}` : `${Math.round(t)}s`); };
  const LANE_X0 = 30;                                                         // pistes de couverture (bas de la barre)
  const lanes = H => { const h = H >= 90 ? 11 : 7, g = { y: H - h - 3, h }; return { g, v: { y: g.y - h - 3, h } }; };
  function drawBands(bands, lane, color, label, W, x) {
    ctx.fillStyle = "rgba(255,255,255,.05)"; ctx.fillRect(LANE_X0, lane.y, W - LANE_X0, lane.h);
    ctx.fillStyle = color;
    (bands || []).forEach(([a, b]) => { const xa = Math.max(LANE_X0, x(a)), xb = Math.max(xa + 1, x(b)); ctx.fillRect(xa, lane.y, xb - xa, lane.h); });
    ctx.fillStyle = "#8a9098"; ctx.font = "9px Consolas"; ctx.fillText(label, 2, lane.y + lane.h - 1);
  }
  function drawTimeline() {
    const W = tl.clientWidth || 800; if (tl.width !== W) tl.width = W; const H = tl.height;
    ctx.clearRect(0, 0, W, H); ctx.fillStyle = "#0e1216"; ctx.fillRect(0, 0, W, H);
    const D = duration(); if (!D) return;
    const x = t => t / D * W; const LN = lanes(H); const TOP = 14, BASE = LN.v.y - 4;   // règle · activité · couverture (bas)
    if (pb.on && pb.tl) {                                    // densité CoT + dwells (lecture)
      const bins = new Float32Array(W); pb.tl.cot.forEach(c => { const i = Math.floor(x(c[0])); if (i >= 0 && i < W) bins[i]++; }); pb.tl.dwells.forEach(d => { const i = Math.floor(x(d[0])); if (i >= 0 && i < W) bins[i] += 2; });
      const mx = Math.max(1, ...bins); ctx.fillStyle = "rgba(124,255,107,.35)";
      for (let i = 0; i < W; i++) if (bins[i]) { const h = 3 + 18 * bins[i] / mx; ctx.fillRect(i, BASE - h, 1, h); }
    }
    if (state.track && state.track.sets.length && (state.mode === "file" || pb.on)) {
      ctx.fillStyle = "rgba(255,213,79,.55)";
      const bins = new Float32Array(W); state.track.sets.forEach(s => { const i = Math.floor(x(s.t)); if (i >= 0 && i < W) bins[i]++; });
      const mx = Math.max(1, ...bins);
      for (let i = 0; i < W; i++) if (bins[i]) { const h = 4 + 18 * bins[i] / mx; ctx.fillRect(i, BASE - h, 1, h); }
    }
    const off = vOff();
    ctx.fillStyle = "rgba(0,200,255,.25)";                    // tampon vidéo du lecteur
    for (let i = 0; i < video.buffered.length; i++) ctx.fillRect(x(off + video.buffered.start(i)), BASE + 1, x(video.buffered.end(i)) - x(video.buffered.start(i)), 2);
    if (state.mode === "replay" || pb.on) {
      ctx.fillStyle = "rgba(255,213,79,.7)"; state.sets.forEach(s => ctx.fillRect(x(off + s.pts / 1000), TOP + 2, 1, 6));
    }
    // couverture : réception vidéo 4609 (flux affiché, sinon union) et dwells radar 4607
    const cov = pb.on && pb.tl && pb.tl.coverage;
    if (cov) {
      const vd = cov.video || {}; let vb = state.cur && vd[String(state.cur.dport)];
      if (!vb) { vb = []; Object.values(vd).forEach(b => vb.push(...b)); vb.sort((a, b) => a[0] - b[0]); }
      drawBands(vb, LN.v, "rgba(0,200,255,.75)", "4609", W, x);
      drawBands(cov.gmti, LN.g, "rgba(124,255,107,.8)", "4607", W, x);
    }
    // règle : horodatage réel de la mission (UTC) si connu, sinon temps relatif
    ctx.fillStyle = "#8a9098"; ctx.font = "10px Consolas";
    const steps = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200]; let step = steps.find(s => x(s) >= 70) || 7200;
    const t0 = tlT0(); const first = t0 ? (step - ((t0 % 86400) % step)) % step : 0;      // graduations alignées sur l'heure ronde
    for (let t = first; t <= D; t += step) { ctx.fillStyle = "#3a4450"; ctx.fillRect(x(t), TOP, 1, H - TOP); ctx.fillStyle = "#8a9098"; ctx.fillRect(x(t), 0, 1, 6); ctx.fillText(fmtT(t), x(t) + 2, 11); }
    ctx.fillStyle = "#5a6470"; ctx.fillRect(0, TOP, W, 1);
    // curseurs
    if (pb.on && pb.tl) { ctx.fillStyle = "#ff9f43"; ctx.fillRect(x(pb.t) - 1, 0, 2, H); ctx.fillText(pb.follow && pb.edge ? "direct" : "lecture", x(pb.t) + 4, BASE - 2); }
    if ((state.mode === "replay") && state.replay && state.replay.running) { ctx.fillStyle = "#ff9f43"; ctx.fillRect(x(state.replay.t || 0) - 1, 0, 2, H); ctx.fillText("rejeu", x(state.replay.t || 0) + 4, BASE - 2); }
    ctx.fillStyle = "#00c8ff"; ctx.fillRect(x(off + video.currentTime) - 1, 0, 2, H);
  }
  tl.addEventListener("mousemove", ev => { const D = duration(); if (!D) { tl.title = ""; return; } const t = (ev.offsetX / tl.clientWidth) * D; tl.title = (tlT0() ? hhmmss(tlT0() + t) + " UTC · " : "") + `t=${t.toFixed(1)} s`; });
  tl.addEventListener("click", ev => {
    const D = duration(); if (!D) return;
    const t = (ev.offsetX / tl.clientWidth) * D;
    if (pb.on) return playbackSeek(t);
    if (lv.on) return;                                     // écoute live : pas de saut
    if (state.replay && state.replay.running) seekReplay(t);
  });
  tl.style.cursor = "pointer";
  function frame() {
    playbackTick();
    const tms = video.currentTime * 1000;
    if (state.sets.length) { const idx = indexAt(tms + 20); if (idx >= 0 && idx !== state.applied) apply(idx, tms); }
    $("tl-t").textContent = (vOff() + video.currentTime).toFixed(3);
    $("tl-mutc").textContent = tlT0() ? hhmmss(tlT0() + (pb.on ? pb.t : vOff() + video.currentTime)) : "—";
    if (pb.on) $("tl-d").textContent = (pb.tl.duration || 0).toFixed(1); else if (state.mode === "file" && isFinite(video.duration)) $("tl-d").textContent = video.duration.toFixed(1);
    drawTimeline();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  window.addEventListener("resize", () => { map.invalidateSize(); drawTimeline(); });

  // ── Poignée : largeur de la colonne gauche (mémorisée) ─────────────────────
  const app = $("app"), gutter = $("gutter");
  const setLeft = w => { w = Math.max(240, Math.min(w, window.innerWidth * 0.6)); app.style.gridTemplateColumns = `${w}px 6px 1fr`; localStorage.setItem("leftw", w); };
  setLeft(parseInt(localStorage.getItem("leftw") || "420", 10));
  gutter.addEventListener("mousedown", e => {
    e.preventDefault(); const move = ev => setLeft(ev.clientX); const up = () => { document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); map.invalidateSize(); drawTimeline(); };
    document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
  });
  gutter.addEventListener("dblclick", () => { setLeft(420); map.invalidateSize(); });
  $("st-leftw").addEventListener("click", () => { setLeft(420); map.invalidateSize(); });

  // Les contrôles posés sur la carte (boutons, légende, dialogues) ne doivent pas
  // transmettre leurs clics / molette à la carte (sinon : point de mesure sous le bouton).
  document.querySelectorAll("#map .map-ctl, #map .legend, #map .coords").forEach(el => {
    L.DomEvent.disableClickPropagation(el); L.DomEvent.disableScrollPropagation(el); });

  // ── Coordonnées au survol (MGRS + lat/lon) ─────────────────────────────────
  let lastMgrs = "";
  map.on("mousemove", e => {
    const m = MGRS.toMGRS(e.latlng.lat, e.latlng.lng, 5);
    lastMgrs = m || ""; $("c-mgrs").textContent = m ? m.replace(/^(\d+[A-Z])([A-Z]{2})(\d{5})(\d{5})$/, "$1 $2 $3 $4") : "hors zone UTM";
    $("c-ll").textContent = `${e.latlng.lat.toFixed(5)}  ${e.latlng.lng.toFixed(5)}`;
  });
  $("coords").addEventListener("click", () => { if (lastMgrs && navigator.clipboard) navigator.clipboard.writeText(lastMgrs).then(() => status("MGRS copié : " + lastMgrs)); });

  // ── Mesure de distance (clics successifs, double-clic / Échap = fin) ────────
  const meas = { on: false, pts: [], line: null, tmp: null, marks: [], done: [] };
  const fmtDist = d => d >= 1000 ? (d / 1000).toFixed(d >= 10000 ? 1 : 2) + " km" : d.toFixed(0) + " m";
  function measStart() {
    meas.on = true; meas.pts = []; $("btn-measure").classList.add("on"); $("map").classList.add("measuring"); map.doubleClickZoom.disable();
    meas.line = L.polyline([], { color: "#ffd54f", weight: 2, dashArray: "6 4" }).addTo(map);
    meas.tmp = L.polyline([], { color: "#ffd54f", weight: 1, dashArray: "2 6", opacity: .7 }).addTo(map);
    status("mesure : cliquer les points, double-clic ou Échap pour terminer");
  }
  function measStop() {
    if (!meas.on) return; meas.on = false; $("btn-measure").classList.remove("on"); $("map").classList.remove("measuring"); map.doubleClickZoom.enable();
    if (meas.tmp) { meas.tmp.remove(); meas.tmp = null; }
    if (meas.pts.length < 2 && meas.line) meas.line.remove(); else if (meas.line) meas.done.push(meas.line);
    meas.line = null;
  }
  function measClear() { measStop(); meas.done.forEach(l => l.remove()); meas.done = []; meas.marks.forEach(m => m.remove()); meas.marks = []; }
  function measTotal(pts) { let t = 0; for (let i = 1; i < pts.length; i++) t += MGRS.distBearing(pts[i - 1].lat, pts[i - 1].lng, pts[i].lat, pts[i].lng).d; return t; }
  map.on("click", e => {
    if (!meas.on) return;
    const p = e.latlng, prev = meas.pts[meas.pts.length - 1];
    meas.pts.push(p); meas.line.setLatLngs(meas.pts);
    let txt = "départ";
    if (prev) { const db = MGRS.distBearing(prev.lat, prev.lng, p.lat, p.lng); txt = `${fmtDist(db.d)} · ${db.bearing.toFixed(0)}°` + (meas.pts.length > 2 ? ` · Σ ${fmtDist(measTotal(meas.pts))}` : ""); }
    const mk = L.circleMarker(p, { radius: 4, color: "#ffd54f", fillColor: "#ffd54f", fillOpacity: 1, weight: 1 }).addTo(map);
    mk.bindTooltip(txt, { permanent: true, direction: "right", offset: [6, 0], className: "measure-lbl" }); meas.marks.push(mk);
  });
  map.on("mousemove", e => { if (meas.on && meas.pts.length) { const prev = meas.pts[meas.pts.length - 1]; meas.tmp.setLatLngs([prev, e.latlng]);
    const db = MGRS.distBearing(prev.lat, prev.lng, e.latlng.lat, e.latlng.lng); $("c-ll").textContent += `   ↔ ${fmtDist(db.d)} · ${db.bearing.toFixed(0)}°`; } });
  map.on("dblclick", () => { if (meas.on) measStop(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && meas.on) measStop(); });
  $("btn-measure").addEventListener("click", () => meas.on ? measStop() : measStart());
  $("btn-measure-clear").addEventListener("click", measClear);

  // ── Taille du texte des panneaux (A− / A+, mémorisée) ─────────────────────────
  let panelZoom = parseFloat(localStorage.getItem("panelZoom") || "1");
  const applyZoom = () => { document.documentElement.style.setProperty("--panel-zoom", panelZoom); localStorage.setItem("panelZoom", panelZoom); setTimeout(() => { map.invalidateSize(); drawTimeline(); }, 50); };
  $("fs-minus").addEventListener("click", () => { panelZoom = Math.max(0.8, +(panelZoom - 0.1).toFixed(2)); applyZoom(); });
  $("fs-plus").addEventListener("click", () => { panelZoom = Math.min(1.6, +(panelZoom + 0.1).toFixed(2)); applyZoom(); });
  applyZoom();

  // ── Parcourir… : explorateur côté serveur, chemin mémorisé (récents) ──────────
  const fmtSize = n => n > 1e9 ? (n / 1e9).toFixed(2) + " Go" : n > 1e6 ? (n / 1e6).toFixed(1) + " Mo" : (n / 1e3).toFixed(0) + " Ko";
  async function browseTo(dir) {
    let r; try { r = await api(`/api/browse${dir != null ? "?dir=" + encodeURIComponent(dir) : ""}`); } catch (e) { return status("parcourir : " + e.message, true); }
    $("bd-dir").textContent = r.dir === "::drives" ? "Lecteurs" : r.dir; $("bd-dir").title = r.dir;
    const ul = $("bd-list"); ul.innerHTML = "";
    if (r.parent != null) { const li = document.createElement("li"); li.className = "dir"; li.textContent = "⬑ .."; li.onclick = () => browseTo(r.parent); ul.appendChild(li); }
    r.dirs.forEach(d => { const li = document.createElement("li"); li.className = "dir"; li.textContent = "📁 " + d; li.onclick = () => browseTo(r.dir === "::drives" ? d : r.dir.replace(/[\\/]$/, "") + (r.dir.includes("\\") || /^[A-Z]:/.test(r.dir) ? "\\" : "/") + d); ul.appendChild(li); });
    r.files.forEach(f => { const li = document.createElement("li"); li.className = "file"; li.innerHTML = `<span>📄 ${f.name}</span><span class="sz">${fmtSize(f.size)} · ${new Date(f.mtime * 1000).toLocaleString()}</span>`;
      li.onclick = () => { const sep = /^[A-Z]:/.test(r.dir) || r.dir.includes("\\") ? "\\" : "/"; $("pcap").value = r.dir.replace(/[\\/]$/, "") + sep + f.name; $("browse-dlg").hidden = true; load(); }; ul.appendChild(li); });
    $("browse-dlg").hidden = false;
  }
  $("btn-browse").addEventListener("click", () => browseTo(null));
  $("bd-close").addEventListener("click", () => { $("browse-dlg").hidden = true; });
  document.addEventListener("keydown", e => { if (e.key === "Escape") $("browse-dlg").hidden = true; });
  function fillRecent(list) { const dl = $("recent"); dl.innerHTML = ""; (list || []).forEach(r => { const o = document.createElement("option"); o.value = r; dl.appendChild(o); }); }

  window.__dbg = { state, gs, map, fitTracks, drawTracks, pb, lv };          // accès console (débogage / tests)
  window.__op = { pb, seek: playbackSeek, edge: goEdge, pause: playbackPause, load, play, state,
    seekRel: dt => { if (pb.on) playbackSeek(pb.t + dt); },
    seekFrac: f => { const D = duration(); if (pb.on && D) playbackSeek(Math.max(0, Math.min(1, f)) * D); } };
  // ── Mode opérateur (replay.html) : mission/pcap et mode lus dans l'URL, enchaînement automatique ──
  async function operatorStart(c) {
    const qs = new URLSearchParams(location.search);
    let pcap = qs.get("pcap") || "", name = qs.get("mission") || "";
    try {
      if (!pcap && name) { const r = await api(`/api/mission/resolve?name=${encodeURIComponent(name)}`); pcap = r.pcap; }
      if (!pcap && c.follows && c.follows.length) pcap = (c.follows.find(f => f.running) || c.follows[0]).pcap;
      if (!pcap && c.default_pcap) pcap = c.default_pcap;
    } catch (e) { return status("mission : " + e.message, true); }
    if (!pcap) return status("aucune mission : ouvrir replay?mission=NOM ou replay?pcap=/chemin.pcap", true);
    $("op-mission").textContent = name || pcap.split(/[\\/]/).slice(-3, -1).join(" / ") || pcap;
    document.title = `STRATUS - ${name || pcap.split(/[\\/]/).pop()}`;
    if (qs.get("profile")) { const s = $("gmti-profile"); s.innerHTML = `<option value="${qs.get("profile")}">${qs.get("profile")}</option>`; s.value = qs.get("profile"); }
    $("gmti-live").checked = true;
    $("pcap").value = pcap; state.pcap = pcap; stopPlayer();
    const live = qs.get("live") === "1" || qs.get("live") === "true";
    // Ouverture PAR LE SUIVI (live ou terminée) : index + journal, lecture disque — aucune analyse, rien en RAM.
    const track = { profile: $("gmti-profile").value || "defaut", overrides: {} };
    let st;
    try {
      st = await withBusy("ouverture de la mission…", () => api("/api/follow/start", { pcap, watch: null, track, taps: [] }), ["btn-play"]);
      pb.fid = st.id;
      for (let i = 0; i < 7200 && st.catching_up; i++) { await new Promise(r => setTimeout(r, 500)); st = await api(`/api/follow/status?id=${pb.fid}`); if (!st.running) throw new Error("suivi arrêté"); status(`rattrapage… ${(st.duration || 0).toFixed(0)} s · ${((st.bytes_read || 0) / 1e6).toFixed(0)} Mo`); }
    } catch (e) { return status("mission : " + e.message, true); }
    state.flows = (st.flows || []).map(f => ({ proto: f.proto, dport: f.dport, dominant: f.dominant, pkts: f.pkts, bytes: f.bytes, dsts: f.dsts }));
    state.streams = (st.streams || []).map(v => ({ dport: v.dport, dst: v.dst, bytes: v.bytes, duration_s: v.duration }));
    state.cur = state.streams.length ? state.streams.reduce((a, b) => (b.bytes > a.bytes ? b : a)) : null;
    state.flowsDur = st.duration || 0;
    $("mode").value = "follow"; state.mode = "play";
    if (!state.flows.length) return status("mission vide (aucun flux)", true);
    if (qs.get("autoplay") !== "0") followStart({ pre: st, live });
  }

  // ── Init ─────────────────────────────────────────────────────────────────────
  $("btn-load").addEventListener("click", load);
  $("source").addEventListener("change", liveUi);
  $("live-more").addEventListener("click", () => { lv.optsOpen = !lv.optsOpen; $("live-opts").hidden = !lv.optsOpen; });
  $("live-rec").addEventListener("change", () => { $("live-rec-opts").style.opacity = $("live-rec").checked ? "1" : ".5"; });
  $("gmti-live").addEventListener("change", () => { if (lv.on) liveFollow({ track: $("gmti-live").checked ? { profile: $("gmti-profile").value || "defaut", overrides: gs.ov } : false }); });
  $("pcap").addEventListener("keydown", e => { if (e.key === "Enter") load(); });
  $("stream").addEventListener("change", e => selectStream(e.target.value));
  $("btn-play").addEventListener("click", play);
  $("btn-stop").addEventListener("click", stopAll);
  $("mode").addEventListener("change", () => { state.mode = $("mode").value === "emit" ? "replay" : "play"; drawTimeline(); document.body.classList.toggle("emit-mode", $("mode").value === "emit"); });
  const qs0 = new URLSearchParams(location.search);
  api("/api/config").then(c => {
    state.cfg = c; state.bmCfg = c.basemap; state.replay = c.replay; applyBasemap(); renderReplay();
    fillRecent(c.settings && c.settings.recent);
    if (c.settings && c.settings.stratus_url) $("stratus-url").value = c.settings.stratus_url;
    if (OP) return operatorStart(c);
    if (c.live && c.live.running) { $("source").value = "live"; liveUi(); lv.on = true; state.mode = "replay"; state.replay = c.live; if (!gs.prof) loadProfiles(); status("écoute réseau en cours (reprise de session)"); return; }
    if (qs0.get("source") === "live") { $("source").value = "live"; liveUi(); if (!gs.prof) loadProfiles(); return; }
    const qs = new URLSearchParams(location.search), auto = qs.get("autoplay");   // ?autoplay=file|replay · ?tab=gmti · ?track=<profil>[&ab=<profil>][&editor=1]
    if (c.default_pcap) { $("pcap").value = c.default_pcap; load().then(async () => {
      if (qs.get("tab")) showTab(qs.get("tab"));
      if (qs.get("track")) { await loadProfiles(); $("gmti-profile").value = qs.get("track"); if (qs.get("ab")) { $("gmti-ab").value = qs.get("ab"); gs.abProfile = qs.get("ab"); } await gmtiTrack(); }
      if (qs.get("editor")) { $("gmti-editor").hidden = false; renderEditor(); }
      if (auto) { $("mode").value = (auto === "replay" || auto === "file") ? "play" : auto; setTimeout(play, 800); } }); }
  });
  connectEvents();
})();
