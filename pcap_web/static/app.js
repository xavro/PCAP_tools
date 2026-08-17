/* app.js — console web : vidéo 4609 (mpegts.js) + KLV 0601 synchronisés + carte Leaflet
   + rejeu UDP réel (moteur pcap_replay) piloté en HTTP, événements par WebSocket. */
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const video = $("video");
  const WS = (location.protocol === "https:" ? "wss://" : "ws://") + location.host;
  const state = { cfg: null, pcap: "", streams: [], cur: null, track: null, player: null,
    mode: "file", sets: [], applied: -1, tableAt: 0, flows: [], flowsDur: 0, replay: null,
    bmLayer: null, bmOverlay: null, bmCfg: null, evws: null, log: [], retries: 0 };

  const status = (msg, warn) => { const s = $("status"); s.textContent = msg; s.style.color = warn ? "var(--warn)" : ""; };
  const fmt = (v, d = 5) => (v == null || isNaN(v)) ? "—" : Number(v).toFixed(d);
  const utc = us => us ? new Date(us / 1000).toISOString().replace("T", " ").replace("Z", "") : "—";
  const api = async (url, body) => {
    const r = await fetch(url, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
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
  ["trace", "foot", "center", "plots", "dwell", "tracks", "contacts", "ab", "cot"].forEach(k => { LY[k] = L.layerGroup().addTo(map); });
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
    b.events.forEach(ev => {
      const key = ev.uid || "(sans uid)"; let r = cot.rows.get(key);
      const col = AFF[ev.aff] || "#8a8f98";
      if (!r) {
        r = { ev, pts: [], t: 0 };
        r.marker = L.circleMarker([0, 0], { radius: 5, color: col, fillColor: col, fillOpacity: .9, weight: 1.5, renderer: canvasR });
        r.trail = L.polyline([], { color: col, weight: 1, opacity: .55, renderer: canvasR });
        r.marker.bindTooltip("", { permanent: true, direction: "right", offset: [6, 0], className: "cot-lbl" });
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
    if (performance.now() - cot.tableAt > 300) { renderCot(b.t); cot.tableAt = performance.now(); }
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
        if (d.poly) ly = L.polygon(d.poly, { color: "#7cff6b", weight: 1.2, fillColor: "#7cff6b", fillOpacity: .10, opacity: .9, renderer: canvasR });
        else ly = L.circleMarker(d.center, { radius: 5, color: "#7cff6b", weight: 1, fill: false, renderer: canvasR });
        ly.addTo(lyDwell); ly.bindTooltip(`dwell ${d.dwell != null ? d.dwell : ""} · revisit ${d.revisit != null ? d.revisit : ""} · ${d.n} cible(s)` +
          (d.range_he_km != null ? ` · ±${d.range_he_km.toFixed(2)} km / ±${(d.angle_he_deg || 0).toFixed(2)}°` : ""), { sticky: true });
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
    const cls = Object.entries(gmti.stats.cls).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `cls ${k}: <b>${v}</b>`).join(" · ");
    $("gmti-body").innerHTML = `paquets 4607 <b>${gmti.stats.pkts}</b> · dwells <b>${gmti.stats.dwells}</b> · plots <b>${gmti.stats.plots}</b> (affichés ${gmti.dots.length}) · t=<b>${b.t.toFixed(1)}</b> s<br>` +
      (b.sensor ? `capteur <b>${b.sensor[0].toFixed(4)} ${b.sensor[1].toFixed(4)}</b><br>` : "") + cls;
    $("gmti-sum").textContent = `${gmti.stats.plots} plots`;
  }
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
    try { gs.decoded = await api(`/api/gmti/decode?pcap=${encodeURIComponent(state.pcap)}${limQ()}`); }
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
    try { gs.res = await api(`/api/gmti/track?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${ovq}${limQ()}`); }
    catch (e) { return $("gmti-status").textContent = "tracker : " + e.message; }
    gs.resB = null;
    if (gs.abProfile) {
      try { gs.resB = await api(`/api/gmti/track?pcap=${encodeURIComponent(state.pcap)}&profile=${gs.abProfile}${limQ()}`); } catch (e) { status("A/B : " + e.message, true); }
    }
    drawTracks(); fitTracks(); renderMetrics();
    const r = gs.res, m = r.metrics || {};
    $("gmti-status").textContent = `profil ${profile}${ovq ? " (surchargé)" : ""} : ${r.n_kept} pistes, ${r.n_rejected} rejetées (${r.n_raw} plots)` +
      (m.contacts != null ? ` · ${m.contacts} contacts (${m.contacts_multi} fusionnés)` : "") + (r.zone.length ? " · zone job" : "") + (r.porteur.length ? ` · porteur ${r.porteur.length} pos` : "");
    $("gmti-sum").textContent = `${r.n_kept} pistes · profil ${profile}${ovq ? "*" : ""}`;
  }

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
  const GROUPS = { gate: "Gate & cinématique", vie: "Confirmation & suppression", aerien: "Aérien / rotateur", fusion: "Fusion de pistes (1 contact = 1 piste)", filtre: "Filtres processor" };
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
    ["air", "aériennes", 0, ""], ["rotator", "rotateurs", 0, ""], ["contacts", "contacts (fusion)", 0, ""], ["contacts_multi", "contacts multi-pistes", 0, ""], ["n_filtered", "plots filtrés (SNR/classe)", 0, ""]];
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
    lyTracks.clearLayers(); lyRawStatic.clearLayers(); LY.contacts.clearLayers(); LY.ab.clearLayers(); const r = gs.res; if (!r) return;
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
      pl.bindTooltip(`piste ${t.id} · ${t.hits} hits · ${t.etat}${t.is_air ? " · aérien" : ""}${t.is_rotator ? " · rotateur" : ""}`, { sticky: true });
      L.circleMarker(pts[pts.length - 1], { radius: 3, color: col, fillColor: col, fillOpacity: 1, weight: 1, renderer: canvasR }).addTo(lyTracks);
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
  window.__dbg = { state, gs, map, fitTracks, drawTracks };          // accès console (débogage / tests)
  $("gmti-decode").addEventListener("click", gmtiDecode);
  $("gmti-track").addEventListener("click", gmtiTrack);
  ["gmti-raw", "gmti-smooth", "gmti-ovl"].forEach(id => $(id).addEventListener("change", drawTracks));

  // ── Analyse statique CoT : objets, traces, inventaire des types, XML ─────────
  const cs = { data: null, sel: null };
  async function cotScan() {
    showTab("cot"); $("cot-status").textContent = "analyse CoT…";
    const flt = $("cot-filter").value.trim();
    try { cs.data = await api(`/api/cot/scan?pcap=${encodeURIComponent(state.pcap)}&filter=${encodeURIComponent(flt)}`); }
    catch (e) { return $("cot-status").textContent = "erreur : " + e.message; }
    resetCot(); const d = cs.data;
    d.rows.forEach(row => {
      const ev = { uid: row.uid, type: row.type, aff: row.affiliation, callsign: row.callsign, lat: +row.lat, lon: +row.lon, speed: row.speed != null ? +row.speed : null };
      const key = ev.uid || "(sans uid)"; const col = AFF[ev.aff] || "#8a8f98";
      const r = { ev, pts: (d.tracks[row.uid] || []).slice(-400), t: -1 };
      r.marker = L.circleMarker([0, 0], { radius: 5, color: col, fillColor: col, fillOpacity: .9, weight: 1.5, renderer: canvasR });
      r.trail = L.polyline(r.pts, { color: col, weight: 1, opacity: .55, renderer: canvasR });
      r.marker.bindTooltip((ev.callsign || ev.uid || "?"), { permanent: true, direction: "right", offset: [6, 0], className: "cot-lbl" });
      if (!isNaN(ev.lat) && !isNaN(ev.lon) && !(ev.lat === 0 && ev.lon === 0)) { r.marker.setLatLng([ev.lat, ev.lon]); r.trail.addTo(lyCot); r.marker.addTo(lyCot); }
      r.marker.on("click", () => cotSelect(key));
      cot.rows.set(key, r);
    });
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
    status("export GeoJSON (fusion GMTI + CoT + vidéo)… peut prendre quelques secondes");
    const a = document.createElement("a"); a.href = `/api/fused/export.geojson?pcap=${encodeURIComponent(state.pcap)}&profile=${profile}${limQ()}`; a.download = "fusion.geojson"; a.click();
  });
  $("btn-ts").addEventListener("click", () => {
    if (!state.cur) return status("pas de flux vidéo sélectionné", true);
    const a = document.createElement("a"); a.href = `/video.ts?pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur.dport}&download=1`; a.download = `flux_${state.cur.dport}.ts`; a.click();
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
    const url = `/basemap?bbox=${sw.x},${sw.y},${ne.x},${ne.y}&w=${sz.x}&h=${sz.y}&sr=3857&_=${Date.now()}`;
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
  $("btn-bm").addEventListener("click", () => { bmDialogFill(); $("bm-dlg").hidden = !$("bm-dlg").hidden; });
  $("bm-close").addEventListener("click", () => { $("bm-dlg").hidden = true; });
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
      [r, f] = await Promise.all([api(`/api/streams?pcap=${encodeURIComponent(state.pcap)}${lim}`),
                                  api(`/api/flows?pcap=${encodeURIComponent(state.pcap)}${lim}`)]);
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
      const dst = fl.dsts && fl.dsts.length ? fl.dsts[0] : "";
      tr.innerHTML = `<td><input type="checkbox" class="fl-on"></td><td class="name">${fl.proto.toLowerCase()}/${fl.dport} ${fl.dominant}</td>` +
        `<td class="cnt">${fl.pkts}</td><td class="tg"><input type="text" class="fl-tg" placeholder="${dst ? "cible (ex. " + dst + ") — vide = IHM seule" : "IP[:port] — vide = IHM seule"}" title="cible(s) IP[:port], virgule = fan-out ; vide = pas d'émission, affichage IHM seul"></td>`;
      body.appendChild(tr);
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
    return Array.from(document.querySelectorAll("#flows-body tr[data-i]")).filter(tr => tr.querySelector(".fl-on").checked).map(tr => {
      const fl = state.flows[tr.dataset.i];
      const targets = tr.querySelector(".fl-tg").value.split(",").map(s => s.trim()).filter(Boolean);
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
    renderInventory(); markTapRow(); showTab("fmv");
    document.querySelectorAll("#flows-body tr.tap .fl-on").forEach(cb => { cb.checked = true; });   // flux vidéo choisi → coché (IHM seule si cible vide)
    stopPlayer();
    if (state.cur.first_klv) renderTable(state.cur.first_klv.map(f => ({ tag: f.tag, name: f.name, value: f.value, unit: "" })), false);
    status("trace KLV…");
    try { state.track = await api(`/api/klv?pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur.dport}`); }
    catch (e) { state.track = null; return status("erreur KLV : " + e.message, true); }
    fullTrack.setLatLngs(state.track.sets.map(s => [s.lat, s.lon]));
    $("klv-sum").textContent = `${state.track.n} sets · ${state.track.n && (state.track.n / state.cur.duration_s).toFixed(1)} Hz`;
    $("tl-d").textContent = state.cur.duration_s.toFixed(1);
    fitView();
    status(`flux ${state.cur.dst}:${state.cur.dport} prêt — ▶ Lire`);
    drawTimeline();
  }

  // ── Lecteur mpegts.js (fichier : /video.ts ; rejeu : ws tap) + KLV synchrone ──
  function startPlayer(url, live) {
    stopPlayer();
    if (!mpegts.isSupported()) return status("MSE non supporté par ce navigateur", true);
    const player = mpegts.createPlayer({ type: "mpegts", isLive: live, url }, {
      enableWorker: false, lazyLoad: false, enableStashBuffer: !live, stashInitialSize: 128 * 1024,
      liveBufferLatencyChasing: live, liveBufferLatencyMaxLatency: 1.5, liveBufferLatencyMinRemain: 0.4,
      autoCleanupSourceBuffer: live, seekType: "range" });
    player.attachMediaElement(video);
    player.on(mpegts.Events.SYNCHRONOUS_KLV_METADATA_ARRIVED, onKlv);
    player.on(mpegts.Events.ASYNCHRONOUS_KLV_METADATA_ARRIVED, onKlv);
    player.on(mpegts.Events.ERROR, (t, d, i) => {
      status(`erreur lecteur : ${t} / ${d} ${i && i.msg || ""}`, true);
      if (live && state.replay && state.replay.running && state.retries < 5) {      // tap live : on se raccroche
        state.retries++; setTimeout(() => { if (state.replay && state.replay.running) startPlayer(url, true); }, 600);
      }
    });
    player.on(mpegts.Events.MEDIA_INFO, mi => status(`${live ? "LIVE (tap du rejeu)" : "lecture fichier"} — ${mi.videoCodec || ""} ${mi.width || ""}×${mi.height || ""} ${mi.fps ? mi.fps.toFixed(1) + " fps" : ""}`));
    player.load(); player.play().catch(() => {});
    state.player = player; state.sets = []; state.applied = -1; trace.setLatLngs([]);
    if (!live) state.retries = 0;
    $("mode-badge").textContent = live ? "● LIVE — flux tapé sur le moteur de rejeu" : "FICHIER";
    $("mode-badge").className = "overlay" + (live ? " live" : "");
  }
  function stopPlayer() {
    if (state.player) { try { state.player.pause(); state.player.unload(); state.player.detachMediaElement(); state.player.destroy(); } catch (e) {} }
    state.player = null;
  }
  video.addEventListener("ended", () => { if (state.mode === "file" && $("loop").checked && state.player) { video.currentTime = 0; video.play(); } });

  async function play() {
    if (!state.pcap) return status("analyser un pcap d'abord", true);
    state.mode = $("mode").value;
    const q = `pcap=${encodeURIComponent(state.pcap)}&dport=${state.cur ? state.cur.dport : 0}`;
    if (state.mode === "file") {
      if (!state.cur) return status("pas de flux vidéo", true);
      $("tl-mode").textContent = "fichier : cliquer la timeline pour se déplacer";
      return startPlayer(`/video.ts?${q}`, false);
    }
    // Rejeu : seuls les flux COCHÉS sont rejoués (émis si cible, sinon vus dans l'IHM).
    // Le lecteur ws est ouvert AVANT le start pour ne rien rater.
    const checked = checkedFlows();
    if (!checked.length) return status("cocher au moins un flux à rejouer (cible vide = IHM seule)", true);
    const routes = routesFromUI();
    const watch = checked.map(f => f.key);
    const videoOn = state.cur && checked.some(f => f.proto === "UDP" && f.dport === state.cur.dport);
    const taps = videoOn ? [state.cur.dport] : [];
    if (videoOn) startPlayer(`${WS}/ws/video?dport=${state.cur.dport}`, true);
    else { stopPlayer(); $("mode-badge").textContent = "flux vidéo non coché — pas de lecture"; $("mode-badge").className = "overlay"; }
    state.log = []; $("replay-log").textContent = ""; resetCot(); resetGmti(); fitOnce = false; state.retries = 0;
    try {
      await api("/api/replay/start", { pcap: state.pcap, routes, speed: parseFloat($("speed").value), loop: $("loop").checked,
        rebase: $("rebase").checked, taps, watch });
      const ihmOnly = checked.length - routes.length;
      $("tl-mode").textContent = `rejeu ×${$("speed").value || "max"} — ${routes.length} route(s) émise(s)` + (ihmOnly ? ` + ${ihmOnly} IHM seule` : "") + (taps.length ? " + vidéo" : "");
      status(`rejeu démarré : ${checked.map(f => f.key).join(", ")}`);
    } catch (e) { stopPlayer(); status("rejeu : " + e.message, true); }
  }
  async function stopAll() {
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
    if (n.fc_lat != null) { center.setLatLng([n.fc_lat, n.fc_lon]); if (n.lat != null) los.setLatLngs([[n.lat, n.lon], [n.fc_lat, n.fc_lon]]); }
    if (n.corners) footprint.setLatLngs(n.corners);
    follow(n);
    if (idx === state.applied + 1) { if (n.lat != null) trace.addLatLng([n.lat, n.lon]); }
    else trace.setLatLngs(state.sets.slice(0, idx + 1).filter((x, i) => x.num.lat != null && (i % 3 === 0 || i === idx)).map(x => [x.num.lat, x.num.lon]));
    $("hud").textContent = `capteur ${fmt(n.lat)} ${fmt(n.lon)}  alt ${fmt(n.alt, 0)} m\ncap ${fmt(n.hdg, 1)}°  tang ${fmt(n.pitch, 1)}°  roul ${fmt(n.roll, 1)}°\nFOV ${fmt(n.hfov, 2)}°×${fmt(n.vfov, 2)}°  portée ${fmt(n.slant, 0)} m\ncentre ${fmt(n.fc_lat)} ${fmt(n.fc_lon)}`;
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
    else if (ev.type === "replay") { state.replay = ev; renderReplay(); }
    else if (ev.type === "log") { state.log.push(ev.msg); if (state.log.length > 200) state.log.shift();
      const el = $("replay-log"); el.textContent = state.log.slice(-40).join("\n"); el.scrollTop = el.scrollHeight; }
    else if (ev.type === "cot") { onCotBatch(ev); if (!fitOnce && !state.cur) { fitOnce = true; fitView(); } }
    else if (ev.type === "gmti") { onGmtiBatch(ev); if (!fitOnce && !state.cur) { fitOnce = true; fitView(); } }
    else if (ev.type === "end") { status(ev.stopped ? "rejeu arrêté" : "rejeu terminé"); if (state.mode === "replay") stopPlayer(); state.replay = { running: false }; renderReplay(); }
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
  function duration() {
    if (state.mode === "replay") return Math.max(state.flowsDur || 0, (state.replay && state.replay.t) || 0, video.currentTime);
    return (isFinite(video.duration) && video.duration > 0) ? video.duration : (state.cur ? state.cur.duration_s : 0);
  }
  function drawTimeline() {
    const W = tl.clientWidth || 800; if (tl.width !== W) tl.width = W; const H = tl.height;
    ctx.clearRect(0, 0, W, H); ctx.fillStyle = "#0e1216"; ctx.fillRect(0, 0, W, H);
    const D = duration(); if (!D) return;
    const x = t => t / D * W;
    if (state.track && state.track.sets.length && state.mode === "file") {
      ctx.fillStyle = "rgba(255,213,79,.55)";
      const bins = new Float32Array(W); state.track.sets.forEach(s => { const i = Math.floor(x(s.t)); if (i >= 0 && i < W) bins[i]++; });
      const mx = Math.max(1, ...bins);
      for (let i = 0; i < W; i++) if (bins[i]) { const h = 4 + 14 * bins[i] / mx; ctx.fillRect(i, H - 12 - h, 1, h); }
    }
    ctx.fillStyle = "rgba(0,200,255,.18)";
    for (let i = 0; i < video.buffered.length; i++) ctx.fillRect(x(video.buffered.start(i)), H - 10, x(video.buffered.end(i)) - x(video.buffered.start(i)), 6);
    if (state.mode === "replay") {
      ctx.fillStyle = "rgba(255,213,79,.7)"; state.sets.forEach(s => ctx.fillRect(x(s.pts / 1000), H - 30, 1, 10));
      if (state.replay && state.replay.running) { ctx.fillStyle = "#ff9f43"; ctx.fillRect(x(state.replay.t || 0) - 1, 0, 2, H); ctx.fillText("rejeu", x(state.replay.t || 0) + 4, H - 2); }
    }
    ctx.fillStyle = "#8a9098"; ctx.font = "10px Consolas"; const step = D > 600 ? 120 : D > 120 ? 30 : D > 30 ? 10 : 5;
    for (let t = 0; t <= D; t += step) { ctx.fillRect(x(t), 0, 1, 6); ctx.fillText(t + "s", x(t) + 2, 12); }
    ctx.fillStyle = "#00c8ff"; ctx.fillRect(x(video.currentTime) - 1, 0, 2, H);
  }
  tl.addEventListener("click", ev => {
    if (state.mode !== "file" || !state.player) return;
    const D = duration(); if (!D) return; video.currentTime = (ev.offsetX / tl.clientWidth) * D;
  });
  function frame() {
    const tms = video.currentTime * 1000;
    if (state.sets.length) { const idx = indexAt(tms + 20); if (idx >= 0 && idx !== state.applied) apply(idx, tms); }
    $("tl-t").textContent = video.currentTime.toFixed(3);
    if (state.mode === "file" && isFinite(video.duration)) $("tl-d").textContent = video.duration.toFixed(1);
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

  // Les contrôles posés sur la carte (boutons, légende, dialogues) ne doivent pas
  // transmettre leurs clics / molette à la carte (sinon : point de mesure sous le bouton).
  document.querySelectorAll("#map .map-ctl, #map .legend, #map .coords, #map .bm-dlg").forEach(el => {
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

  // ── Init ─────────────────────────────────────────────────────────────────────
  $("btn-load").addEventListener("click", load);
  $("pcap").addEventListener("keydown", e => { if (e.key === "Enter") load(); });
  $("stream").addEventListener("change", e => selectStream(e.target.value));
  $("btn-play").addEventListener("click", play);
  $("btn-stop").addEventListener("click", stopAll);
  $("mode").addEventListener("change", () => { state.mode = $("mode").value; drawTimeline(); });
  api("/api/config").then(c => {
    state.cfg = c; state.bmCfg = c.basemap; state.replay = c.replay; applyBasemap(); renderReplay();
    fillRecent(c.settings && c.settings.recent);
    const qs = new URLSearchParams(location.search), auto = qs.get("autoplay");   // ?autoplay=file|replay · ?tab=gmti · ?track=<profil>[&ab=<profil>][&editor=1]
    if (c.default_pcap) { $("pcap").value = c.default_pcap; load().then(async () => {
      if (qs.get("tab")) showTab(qs.get("tab"));
      if (qs.get("track")) { await loadProfiles(); $("gmti-profile").value = qs.get("track"); if (qs.get("ab")) { $("gmti-ab").value = qs.get("ab"); gs.abProfile = qs.get("ab"); } await gmtiTrack(); }
      if (qs.get("editor")) { $("gmti-editor").hidden = false; renderEditor(); }
      if (auto) { $("mode").value = auto; setTimeout(play, 800); } }); }
  });
  connectEvents();
})();
