// Page opérateur : redimensionnement carte/vidéo, inversion, plein écran, raccourcis, horloge UTC.
// Le moteur (lecture, suivi/DVR, carte, timeline) est app.js ; il expose window.__op.
(() => {
  const $ = id => document.getElementById(id);
  const main = $("op-main"), gutter = $("op-gutter");
  // ── poignée carte | vidéo (proportion mémorisée) ──
  const setSplit = f => { f = Math.max(0.2, Math.min(0.8, f)); main.style.gridTemplateColumns = `${(f * 100).toFixed(2)}fr 6px ${((1 - f) * 100).toFixed(2)}fr`; localStorage.setItem("op.split", f); if (window.__dbg) window.__dbg.map.invalidateSize(); };
  setSplit(parseFloat(localStorage.getItem("op.split") || "0.55"));
  gutter.addEventListener("mousedown", e => {
    e.preventDefault(); gutter.classList.add("drag");
    const r = main.getBoundingClientRect(); const swapped = main.classList.contains("swapped");
    const move = ev => { let f = (ev.clientX - r.left) / r.width; setSplit(swapped ? 1 - f : f); };
    const up = () => { gutter.classList.remove("drag"); document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
    document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
  });
  // ── inversion carte / vidéo ──
  if (localStorage.getItem("op.swapped") === "1") main.classList.add("swapped");
  $("op-swap").addEventListener("click", () => { main.classList.toggle("swapped"); localStorage.setItem("op.swapped", main.classList.contains("swapped") ? "1" : "0"); if (window.__dbg) window.__dbg.map.invalidateSize(); });
  // ── plein écran ──
  const full = () => { if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen().catch(() => {}); };
  $("op-full").addEventListener("click", full);
  document.addEventListener("fullscreenchange", () => { if (window.__dbg) setTimeout(() => window.__dbg.map.invalidateSize(), 100); });
  // ── horloge UTC ──
  const clock = () => { $("op-clock").textContent = new Date().toISOString().slice(11, 19) + " UTC"; };
  clock(); setInterval(clock, 1000);
  // ── raccourcis : espace = pause, ← → = ±10 s, L = direct, F = plein écran ──
  document.addEventListener("keydown", e => {
    if (e.target && /INPUT|SELECT|TEXTAREA/.test(e.target.tagName)) return;
    const op = window.__op; if (!op) return;
    if (e.code === "Space") { e.preventDefault(); $("btn-pause").click(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); op.seekRel(-10); }
    else if (e.key === "ArrowRight") { e.preventDefault(); op.seekRel(10); }
    else if (e.key === "l" || e.key === "L") { if (!$("btn-edge").hidden) $("btn-edge").click(); }
    else if (e.key === "f" || e.key === "F") full();
  });
  // ── glisser sur la barre de temps = navigation continue ──
  const tl = $("timeline"); let dragging = false;
  tl.addEventListener("mousedown", ev => { if (ev.button === 0 && !(window.__op && window.__op.clipAt(ev))) dragging = true; });
  document.addEventListener("mouseup", () => { dragging = false; });
  tl.addEventListener("mousemove", ev => { if (dragging && window.__op) window.__op.seekFrac(ev.offsetX / tl.clientWidth); });

  // ══ Vignettes : survol de la barre de temps → image du flux à cet instant (sprites 10×10 du serveur, 1 / 10 s) ══
  const prev = $("tl-preview"), prevC = prev.querySelector("canvas"), prevT = $("tl-preview-t"), pctx = prevC.getContext("2d");
  const thumbs = { mission: null, idx: null, imgs: new Map(), lastFetch: -1e9 };
  async function loadThumbIndex(force) {
    const pb = window.__op && window.__op.pb; const m = pb && pb.on && pb.tl && pb.tl.mission; if (!m) { thumbs.idx = null; return; }
    if (thumbs.mission !== m) { thumbs.mission = m; thumbs.idx = null; thumbs.imgs.clear(); thumbs.lastFetch = -1e9; }
    if (!force && performance.now() - thumbs.lastFetch < 60000) return;
    thumbs.lastFetch = performance.now();
    try { const r = await fetch(`api/thumbnails/${encodeURIComponent(m)}/index`); const j = await r.json(); if (r.ok) thumbs.idx = j; } catch (e) { /* silencieux */ }
  }
  setInterval(() => { loadThumbIndex(false); }, 5000);
  const spriteImg = sp => {                                  // cache d'images par (fichier, version)
    const key = `${sp.file}?v=${sp.ver}`; let img = thumbs.imgs.get(key);
    if (!img) { img = new Image(); img.src = `api/thumbnails/${encodeURIComponent(thumbs.mission)}/${key}`; thumbs.imgs.set(key, img); if (thumbs.imgs.size > 40) thumbs.imgs.delete(thumbs.imgs.keys().next().value); }
    return img;
  };
  function drawThumb(tRel) {
    const idx = thumbs.idx; pctx.fillStyle = "#000"; pctx.fillRect(0, 0, 160, 90);
    if (!idx || !idx.available) { pctx.fillStyle = "#8a9098"; pctx.font = "11px Consolas"; pctx.fillText(idx && idx.enabled ? "vignettes en préparation…" : "vignettes indisponibles", 8, 50); return; }
    const k = Math.floor(tRel / idx.window_s), sp = idx.sprites[String(k)];
    if (!sp) { pctx.fillStyle = "#8a9098"; pctx.font = "11px Consolas"; pctx.fillText("pas encore générée", 24, 50); return; }
    const i = Math.min(sp.n - 1, Math.floor((tRel - k * idx.window_s) / idx.interval)); const cx = i % idx.cols, cy = Math.floor(i / idx.cols);
    const img = spriteImg(sp);
    const draw = () => { pctx.drawImage(img, cx * idx.w, cy * idx.h, idx.w, idx.h, 0, 0, 160, 90); };
    if (img.complete && img.naturalWidth) draw(); else { pctx.fillStyle = "#8a9098"; pctx.font = "11px Consolas"; pctx.fillText("chargement…", 40, 50); img.addEventListener("load", draw, { once: true }); }
  }
  tl.addEventListener("mousemove", ev => {
    const pb = window.__op && window.__op.pb; const D = pb && pb.on && pb.tl ? pb.tl.duration : 0;
    if (!D || !pb.tl.mission) { prev.hidden = true; return; }
    const tRel = Math.max(0, Math.min(1, ev.offsetX / tl.clientWidth)) * D; const r = tl.getBoundingClientRect();
    prev.hidden = false; prev.style.left = Math.max(88, Math.min(window.innerWidth - 88, ev.clientX)) + "px"; prev.style.top = (r.top - 90 - 34) + "px";
    prevT.textContent = (pb.tl.t0 ? hms(pb.tl.t0 + tRel) + "Z" : `t=${tRel.toFixed(0)} s`);
    loadThumbIndex(false); drawThumb(tRel);
  });
  tl.addEventListener("mouseleave", () => { prev.hidden = true; });

  // ══ Clips : extraction d'un créneau UTC (GDH) en .ts, liste sur la barre de temps, menu contextuel ══
  const CLIP_MAX_S = 3600;
  const panel = $("clip-panel"), menu = $("clip-menu"), msg = $("clip-msg");
  const inS = $("clip-start"), inE = $("clip-end"), inN = $("clip-name"), meta = $("clip-meta"), go = $("clip-go");
  const op = () => window.__op, pbOf = () => (window.__op && window.__op.pb) || null;
  const tlT0 = () => { const pb = pbOf(); return pb && pb.on && pb.tl && pb.tl.t0 ? pb.tl.t0 : null; };
  const tlDur = () => { const pb = pbOf(); return pb && pb.tl ? (pb.tl.duration || 0) : 0; };
  const mission = () => { const pb = pbOf(); return pb && pb.tl && pb.tl.mission; };
  const hms = t => new Date(t * 1000).toISOString().slice(11, 19);
  const fmtDur = s => s >= 3600 ? `${Math.floor(s / 3600)}h${String(Math.floor(s % 3600 / 60)).padStart(2, "0")}m` : s >= 60 ? `${Math.floor(s / 60)}m${String(Math.round(s % 60)).padStart(2, "0")}s` : `${Math.round(s)}s`;
  const autoColon = el => { const d = el.value.replace(/[^0-9]/g, "").slice(0, 6); el.value = d.length > 4 ? `${d.slice(0, 2)}:${d.slice(2, 4)}:${d.slice(4)}` : d.length > 2 ? `${d.slice(0, 2)}:${d.slice(2)}` : d; };
  // HH:MM:SS (UTC) → epoch, sur le jour de la mission ; passage de minuit géré (instant avant t0 − 1 h → jour suivant)
  const toEpoch = v => {
    const m = /^(\d{2}):(\d{2}):(\d{2})$/.exec(v.trim()); const t0 = tlT0(); if (!m || !t0) return null;
    const h = +m[1], mi = +m[2], s = +m[3]; if (h > 23 || mi > 59 || s > 59) return null;
    let t = Math.floor(t0 / 86400) * 86400 + h * 3600 + mi * 60 + s;
    if (t < t0 - 3600) t += 86400;
    return t;
  };
  const setMsg = (text, cls) => { msg.textContent = ""; msg.className = "muted " + (cls || ""); if (typeof text === "string") msg.textContent = text; else msg.appendChild(text); };
  function validate() {
    const pb = pbOf(); const t0 = tlT0(); const D = tlDur();
    pb && (pb.clipSel = null);
    if (!t0) { setMsg("aucune mission suivie", "err"); go.disabled = true; return null; }
    const a = toEpoch(inS.value), b = toEpoch(inE.value);
    $("clip-dur").textContent = a != null && b != null && b > a ? fmtDur(b - a) : "—";
    let err = null;
    if (a == null || b == null) err = inS.value || inE.value ? "format attendu HH:MM:SS (UTC)" : "";
    else if (b <= a) err = "la fin doit être postérieure au début";
    else if (a < t0 - 1 || b > t0 + D + 1) err = `créneau hors mission (${hms(t0)}Z – ${hms(t0 + D)}Z)`;
    else if (b - a > CLIP_MAX_S) err = `durée maximale ${fmtDur(CLIP_MAX_S)}`;
    else if (inN.value && !/^[A-Za-z0-9_-]{1,100}$/.test(inN.value)) err = "nom : lettres, chiffres, _ et - uniquement";
    setMsg(err || "", err ? "err" : ""); go.disabled = !!err || a == null;
    if (!err && a != null) { pb.clipSel = [a, b]; if (op().redraw) op().redraw(); }
    return err ? null : { a, b };
  }
  [inS, inE].forEach(el => el.addEventListener("input", () => { autoColon(el); validate(); }));
  inN.addEventListener("input", validate);
  $("clip-start-cur").addEventListener("click", () => { const pb = pbOf(); if (tlT0()) { inS.value = hms(tlT0() + pb.t); validate(); } });
  $("clip-end-cur").addEventListener("click", () => { const pb = pbOf(); if (tlT0()) { inE.value = hms(tlT0() + pb.t); validate(); } });
  const openPanel = () => {
    const pb = pbOf(); if (!tlT0()) return;
    panel.hidden = false; $("btn-clip").classList.add("on");
    inS.value = hms(tlT0() + pb.t); inE.value = ""; inN.value = ""; validate(); inE.focus();
  };
  const closePanel = () => { panel.hidden = true; $("btn-clip").classList.remove("on"); const pb = pbOf(); if (pb) { pb.clipSel = null; if (op().redraw) op().redraw(); } };
  $("btn-clip").addEventListener("click", () => panel.hidden ? openPanel() : closePanel());
  $("clip-close").addEventListener("click", closePanel);
  async function refreshClips() {
    const m = mission(); const pb = pbOf(); if (!m || !pb || !pb.tl) return;
    try { const r = await fetch(`api/clips/${encodeURIComponent(m)}/list`); const j = await r.json(); if (r.ok && j.clips) { pb.tl.clips = j.clips; if (op().redraw) op().redraw(); } } catch (e) { /* silencieux */ }
  }
  setInterval(refreshClips, 30000);                      // clips extraits par d'autres opérateurs
  go.addEventListener("click", async () => {
    const v = validate(); const m = mission(); if (!v || !m) return;
    const st = op().state; const dport = st && st.cur ? st.cur.dport : null;
    go.disabled = true; setMsg("extraction en cours…");
    try {
      const r = await fetch("api/clips/extract", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mission: m, start_utc: v.a, end_utc: v.b, name: inN.value || null, include_metadata: meta.checked, dport }) });
      const j = await r.json();
      if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status));
      const span = document.createElement("span");
      span.append(`✔ ${j.name} · ${fmtDur(j.duration)} · ${(j.bytes / 1e6).toFixed(1)} Mo — `);
      const a = document.createElement("a"); a.href = `api/clips/${encodeURIComponent(m)}/${encodeURIComponent(j.file)}`; a.textContent = "télécharger"; span.appendChild(a);
      if (j.csv) { span.append(" · "); const c = document.createElement("a"); c.href = `api/clips/${encodeURIComponent(m)}/${encodeURIComponent(j.name + "_klv.csv")}`; c.textContent = "CSV KLV"; span.appendChild(c); }
      setMsg(span, "ok"); inN.value = "";
      await refreshClips();
    } catch (e) { setMsg("erreur : " + e.message, "err"); go.disabled = false; }
  });
  // ══ Captures SNAP : image + métadonnées à l'instant courant → PNG + slide PowerPoint ; lane « snaps » ; agent poste ══
  const sPanel = $("snap-panel"), sMenu = $("snap-menu"), sMsg = $("snap-msg"), sDesc = $("snap-desc"), sAgent = $("snap-agent"), sGo = $("snap-go");
  sAgent.checked = localStorage.getItem("op.snapAgent") !== "0";                 // coché par défaut (agent poste StratusSnap)
  sAgent.addEventListener("change", () => localStorage.setItem("op.snapAgent", sAgent.checked ? "1" : "0"));
  const setSMsg = (text, cls) => { sMsg.textContent = ""; sMsg.className = "muted " + (cls || ""); if (typeof text === "string") sMsg.textContent = text; else sMsg.appendChild(text); };
  const agentUrl = (m, id) => `stratus-snap://capture?server=${encodeURIComponent(location.origin)}&mission=${encodeURIComponent(m)}&id=${encodeURIComponent(id)}`;
  // Lancement de l'agent poste par le protocole stratus-snap:// (location.assign : la page reste affichée ; sans
  // agent enregistré, le navigateur ignore ou signale « aucune application »).
  const callAgent = (m, id) => { try { window.location.assign(agentUrl(m, id)); } catch (e) { /* protocole non enregistré */ } };
  async function refreshSnaps() {
    const m = mission(); const pb = pbOf(); if (!m || !pb || !pb.tl) return;
    try { const r = await fetch(`api/captures/${encodeURIComponent(m)}/list`); const j = await r.json(); if (r.ok && j.captures) { pb.tl.captures = j.captures; if (op().redraw) op().redraw(); } } catch (e) { /* silencieux */ }
  }
  setInterval(refreshSnaps, 30000);
  const openSnap = () => { const pb = pbOf(); if (!tlT0()) return; sPanel.hidden = false; $("btn-snap").classList.add("on"); $("snap-t").textContent = hms(tlT0() + pb.t) + "Z"; setSMsg(""); sDesc.focus(); };
  const closeSnap = () => { sPanel.hidden = true; $("btn-snap").classList.remove("on"); };
  $("btn-snap").addEventListener("click", () => sPanel.hidden ? openSnap() : closeSnap());
  $("snap-close").addEventListener("click", closeSnap);
  setInterval(() => { if (!sPanel.hidden && tlT0()) $("snap-t").textContent = hms(tlT0() + pbOf().t) + "Z"; }, 500);
  document.addEventListener("keydown", e => { if (e.target && /INPUT|SELECT|TEXTAREA/.test(e.target.tagName)) return; if ((e.key === "s" || e.key === "S") && !e.ctrlKey && !e.altKey && window.__op && tlT0()) { e.preventDefault(); if (sPanel.hidden) openSnap(); } });
  sDesc.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); sGo.click(); } });
  sGo.addEventListener("click", async () => {
    const pb = pbOf(); const m = mission(); const t0 = tlT0(); if (!m || !t0) return;
    const t = t0 + pb.t; const st = op().state; const dport = st && st.cur ? st.cur.dport : null;
    sGo.disabled = true; setSMsg("capture en cours…"); if (!pb.paused && op().pause) op().pause(true);
    try {
      const r = await fetch("api/captures/snap", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mission: m, t_utc: t, description: sDesc.value.trim() || null, dport }) });
      const j = await r.json(); if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status));
      const span = document.createElement("span");
      span.append(`✔ ${hms(j.t_klv || j.t_utc)}Z · ${j.mgrs_fmt || "sans position"}${j.slide ? " · slide " + j.slide : ""}${j.share_png ? " · partage ✓" : ""} — `);
      const a = document.createElement("a"); a.href = `api/captures/${encodeURIComponent(m)}/${encodeURIComponent(j.png)}?download=1`; a.textContent = "PNG"; span.appendChild(a);
      span.append(" · "); const b = document.createElement("a"); b.href = `api/captures/${encodeURIComponent(m)}/deck.pptx`; b.textContent = "deck PPTX"; span.appendChild(b);
      if (j.deck_error) span.append(` · deck : ${j.deck_error}`);
      setSMsg(span, "ok"); sDesc.value = "";
      if (sAgent.checked) callAgent(m, j.id);
      await refreshSnaps();
    } catch (e) { setSMsg("erreur : " + e.message, "err"); }
    sGo.disabled = false;
  });
  let sCur = null, sDel = false;
  const hideSMenu = () => { sMenu.hidden = true; sCur = null; sDel = false; sMenu.querySelector('[data-act="del"]').textContent = "✕ Supprimer"; };
  tl.addEventListener("contextmenu", ev => {
    const c = op() && op().snapAt(ev); if (!c) return;
    ev.preventDefault(); ev.stopImmediatePropagation(); sCur = c; sDel = false;
    $("sm-title").textContent = `📸 ${hms(c.t_utc)}Z${c.description ? " · " + c.description : ""}${c.mgrs_fmt ? " · " + c.mgrs_fmt : ""}`;
    sMenu.hidden = false; const r = sMenu.getBoundingClientRect();
    sMenu.style.left = Math.min(ev.clientX, window.innerWidth - r.width - 8) + "px"; sMenu.style.top = Math.max(8, ev.clientY - r.height - 8) + "px";
  }, true);
  document.addEventListener("mousedown", ev => { if (!sMenu.hidden && !sMenu.contains(ev.target)) hideSMenu(); });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") { hideSMenu(); if (!sPanel.hidden) closeSnap(); } });
  sMenu.addEventListener("click", async ev => {
    const b = ev.target.closest("button"); if (!b || !sCur) return;
    const m = mission(); const act = b.dataset.act;
    if (act === "seek") { op().seek(sCur.t_utc - (tlT0() || 0)); hideSMenu(); }
    else if (act === "png") { window.open(`api/captures/${encodeURIComponent(m)}/${encodeURIComponent(sCur.png)}?download=1`, "_blank"); hideSMenu(); }
    else if (act === "deck") { window.open(`api/captures/${encodeURIComponent(m)}/deck.pptx`, "_blank"); hideSMenu(); }
    else if (act === "agent") { callAgent(m, sCur.id); hideSMenu(); }
    else if (act === "del") {
      if (!sDel) { sDel = true; b.textContent = "✕ Confirmer la suppression (la slide du deck est conservée)"; return; }
      try { const r = await fetch(`api/captures/${encodeURIComponent(m)}/${encodeURIComponent(sCur.id)}/delete`, { method: "POST" }); const j = await r.json(); if (!r.ok || j.error) throw new Error(j.error || r.status); }
      catch (e) { $("status").textContent = "suppression impossible : " + e.message; }
      hideSMenu(); refreshSnaps();
    }
  });

  // ── menu contextuel sur un clip de la barre de temps ──
  let cur = null, delArmed = false;
  const hideMenu = () => { menu.hidden = true; cur = null; delArmed = false; menu.querySelector('[data-act="del"]').textContent = "✕ Supprimer"; };
  tl.addEventListener("contextmenu", ev => {
    const c = op() && op().clipAt(ev); if (!c) return;
    ev.preventDefault(); cur = c; delArmed = false;
    $("cm-title").textContent = `✂ ${c.name} · ${hms(c.start_utc)}Z – ${hms(c.end_utc)}Z · ${fmtDur(c.duration)} · ${(c.bytes / 1e6).toFixed(1)} Mo`;
    $("cm-csv").hidden = !c.csv;
    menu.hidden = false; const r = menu.getBoundingClientRect();
    menu.style.left = Math.min(ev.clientX, window.innerWidth - r.width - 8) + "px"; menu.style.top = Math.max(8, ev.clientY - r.height - 8) + "px";
  });
  document.addEventListener("mousedown", ev => { if (!menu.hidden && !menu.contains(ev.target)) hideMenu(); });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") { hideMenu(); if (!panel.hidden) closePanel(); } });
  menu.addEventListener("click", async ev => {
    const b = ev.target.closest("button"); if (!b || !cur) return;
    const m = mission(); const act = b.dataset.act;
    if (act === "seek") { op().seek(cur.start_utc - (tlT0() || 0)); hideMenu(); }
    else if (act === "ts") { window.open(`api/clips/${encodeURIComponent(m)}/${encodeURIComponent(cur.file)}`, "_blank"); hideMenu(); }
    else if (act === "csv") { window.open(`api/clips/${encodeURIComponent(m)}/${encodeURIComponent(cur.name + "_klv.csv")}`, "_blank"); hideMenu(); }
    else if (act === "del") {
      if (!delArmed) { delArmed = true; b.textContent = "✕ Confirmer la suppression"; return; }
      try { const r = await fetch(`api/clips/${encodeURIComponent(m)}/${encodeURIComponent(cur.name)}/delete`, { method: "POST" }); const j = await r.json(); if (!r.ok || j.error) throw new Error(j.error || r.status); }
      catch (e) { $("status").textContent = "suppression impossible : " + e.message; }
      hideMenu(); refreshClips();
    }
  });
})();
