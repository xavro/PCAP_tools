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
  const inS = $("clip-start"), inE = $("clip-end"), meta = $("clip-meta"), go = $("clip-go");
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
    setMsg(err || "", err ? "err" : ""); go.disabled = !!err || a == null;
    if (!err && a != null) { pb.clipSel = [a, b]; if (op().redraw) op().redraw(); }
    return err ? null : { a, b };
  }
  [inS, inE].forEach(el => el.addEventListener("input", () => { autoColon(el); validate(); }));
  // 📍 placer le début / la fin à la souris sur la barre de temps (ligne de visée ; clic = fixe ; Échap = annule)
  let pick = null;
  const setPick = w => {
    pick = w; tl.classList.toggle("pick", !!w);
    $("clip-start-cur").classList.toggle("accent", w === "start"); $("clip-end-cur").classList.toggle("accent", w === "end");
    $("clip-start-cur").textContent = w === "start" ? "📍 cliquer sur la barre…" : "📍"; $("clip-end-cur").textContent = w === "end" ? "📍 cliquer sur la barre…" : "📍";
    const pb = pbOf(); if (pb && !w) { pb.clipAim = null; if (op().redraw) op().redraw(); }
  };
  $("clip-start-cur").addEventListener("click", () => setPick(pick === "start" ? null : "start"));
  $("clip-end-cur").addEventListener("click", () => setPick(pick === "end" ? null : "end"));
  const tlFrac = ev => Math.max(0, Math.min(1, ev.offsetX / tl.clientWidth));
  tl.addEventListener("mousemove", ev => { if (!pick) return; const pb = pbOf(); const D = tlDur(); if (pb && D) { pb.clipAim = tlFrac(ev) * D; if (op().redraw) op().redraw(); } }, true);
  tl.addEventListener("mouseleave", () => { const pb = pbOf(); if (pick && pb) { pb.clipAim = null; if (op().redraw) op().redraw(); } });
  ["mousedown", "click"].forEach(evn => tl.addEventListener(evn, ev => {
    if (!pick || ev.button !== 0) return;
    ev.stopImmediatePropagation(); ev.preventDefault();
    if (evn !== "mousedown") return;
    const t0 = tlT0(); const D = tlDur(); if (!t0 || !D) return;
    const t = t0 + tlFrac(ev) * D; (pick === "start" ? inS : inE).value = hms(t); setPick(null); validate();
  }, true));
  const openPanel = () => {
    const pb = pbOf(); if (!tlT0()) return;
    panel.hidden = false; $("btn-clip").classList.add("on");
    inS.value = hms(tlT0() + pb.t); inE.value = ""; validate(); inE.focus();
  };
  const closePanel = () => { panel.hidden = true; $("btn-clip").classList.remove("on"); setPick(null); const pb = pbOf(); if (pb) { pb.clipSel = null; if (op().redraw) op().redraw(); } };
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
        body: JSON.stringify({ mission: m, start_utc: v.a, end_utc: v.b, name: null, include_metadata: meta.checked, dport }) });
      const j = await r.json();
      if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status));
      const span = document.createElement("span");
      span.append(`✔ ${j.name} · ${fmtDur(j.duration)} · ${(j.bytes / 1e6).toFixed(1)} Mo — `);
      const a = document.createElement("a"); a.href = `api/clips/${encodeURIComponent(m)}/${encodeURIComponent(j.file)}`; a.textContent = "télécharger"; span.appendChild(a);
      if (j.csv) { span.append(" · "); const c = document.createElement("a"); c.href = `api/clips/${encodeURIComponent(m)}/${encodeURIComponent(j.name + "_klv.csv")}`; c.textContent = "CSV KLV"; span.appendChild(c); }
      setMsg(span, "ok");
      await refreshClips();
    } catch (e) { setMsg("erreur : " + e.message, "err"); go.disabled = false; }
  });
  // ══ Captures SNAP : image + métadonnées à l'instant courant → PNG + slide PowerPoint ; lane « snaps » ; agent poste ══
  const sMenu = $("snap-menu"), vToast = $("v-toast"); let toastTimer = null;
  const toast = (text, cls, ms) => { vToast.textContent = text; vToast.className = cls || ""; vToast.hidden = false; if (toastTimer) clearTimeout(toastTimer); toastTimer = setTimeout(() => { vToast.hidden = true; }, ms || 3000); };
  const agentUrl = (m, id) => `stratus-snap://capture?server=${encodeURIComponent(location.origin)}&mission=${encodeURIComponent(m)}&id=${encodeURIComponent(id)}`;
  // Lancement de l'agent poste par le protocole stratus-snap:// (location.assign : la page reste affichée ; sans
  // agent enregistré, le navigateur ignore ou signale « aucune application »).
  const callAgent = (m, id) => { try { window.location.assign(agentUrl(m, id)); } catch (e) { /* protocole non enregistré */ } };
  async function refreshSnaps() {
    const m = mission(); const pb = pbOf(); if (!m || !pb || !pb.tl) return;
    try { const r = await fetch(`api/captures/${encodeURIComponent(m)}/list`); const j = await r.json(); if (r.ok && j.captures) { pb.tl.captures = j.captures; if (op().redraw) op().redraw(); } } catch (e) { /* silencieux */ }
  }
  setInterval(refreshSnaps, 30000);
  // 📸 = capture immédiate à l'instant courant (la lecture continue) ; S ou Ctrl+Shift+C ; message éphémère sur la vidéo
  let snapBusy = false;
  const doSnap = async () => {
    const pb = pbOf(); const m = mission(); const t0 = tlT0(); if (!m || !t0 || snapBusy) return;
    const t = t0 + pb.t; const st = op().state; const dport = st && st.cur ? st.cur.dport : null;
    snapBusy = true; $("btn-snap").classList.add("busy"); toast(`📸 capture ${hms(t)}Z…`, "busy", 30000);
    try {
      const r = await fetch("api/captures/snap", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mission: m, t_utc: t, description: null, dport }) });
      const j = await r.json(); if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status));
      toast(`✔ SNAP ${hms(j.t_klv || j.t_utc)}Z · ${j.mgrs_fmt || "sans position"}`, "ok", 3000);
      callAgent(m, j.id);                                                  // agent poste StratusSnap (PowerPoint ouvert) — sans effet s'il n'est pas installé
      await refreshSnaps();
    } catch (e) { toast("capture : " + e.message, "err", 8000); }
    snapBusy = false; $("btn-snap").classList.remove("busy");
  };
  $("btn-snap").addEventListener("click", () => { doSnap(); });
  document.addEventListener("keydown", e => {
    if (e.target && /INPUT|SELECT|TEXTAREA/.test(e.target.tagName)) return;
    const plain = (e.key === "s" || e.key === "S") && !e.ctrlKey && !e.altKey && !e.shiftKey;
    const combo = e.ctrlKey && e.shiftKey && (e.key === "c" || e.key === "C" || e.code === "KeyC");
    if ((plain || combo) && window.__op && tlT0()) { e.preventDefault(); doSnap(); }
  });
  let sCur = null;
  const hideSMenu = () => { sMenu.hidden = true; sCur = null; };
  tl.addEventListener("contextmenu", ev => {
    const c = op() && op().snapAt(ev); if (!c) return;
    ev.preventDefault(); ev.stopImmediatePropagation(); sCur = c; sDel = false;
    $("sm-title").textContent = `📸 ${hms(c.t_utc)}Z${c.description ? " · " + c.description : ""}${c.mgrs_fmt ? " · " + c.mgrs_fmt : ""}`;
    sMenu.hidden = false; const r = sMenu.getBoundingClientRect();
    sMenu.style.left = Math.min(ev.clientX, window.innerWidth - r.width - 8) + "px"; sMenu.style.top = Math.max(8, ev.clientY - r.height - 8) + "px";
  }, true);
  document.addEventListener("mousedown", ev => { if (!sMenu.hidden && !sMenu.contains(ev.target)) hideSMenu(); });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") { hideSMenu(); setPick(null); } });
  sMenu.addEventListener("click", async ev => {
    const b = ev.target.closest("button"); if (!b || !sCur) return;
    const m = mission(); const act = b.dataset.act;
    if (act === "png") { window.open(`api/captures/${encodeURIComponent(m)}/${encodeURIComponent(sCur.png)}?download=1`, "_blank"); hideSMenu(); }
    else if (act === "agent") { callAgent(m, sCur.id); hideSMenu(); }
  });

  // ══ Vidéo : MGRS sous le curseur (homographie sur les coins KLV), menu clic droit, mesure tracée sur la vidéo ══
  const vcol = $("video-col"), video = $("video"), vCur = $("v-cursor"), vMeas = $("v-meas"), vMenu = $("video-menu");
  const kNum = () => { const st = op() && op().state; const s = st && st.sets && st.applied >= 0 ? st.sets[st.applied] : null; return s ? s.num : null; };
  const solve = (M, b) => {                                                 // Gauss (8×8) pour l'homographie
    const n = b.length; const A = M.map((r, i) => [...r, b[i]]);
    for (let c = 0; c < n; c++) {
      let p = c; for (let r = c + 1; r < n; r++) if (Math.abs(A[r][c]) > Math.abs(A[p][c])) p = r;
      if (Math.abs(A[p][c]) < 1e-12) return null;
      [A[c], A[p]] = [A[p], A[c]];
      for (let r = 0; r < n; r++) { if (r === c) continue; const f = A[r][c] / A[c][c]; for (let k = c; k <= n; k++) A[r][k] -= f * A[c][k]; }
    }
    return A.map((r, i) => r[n] / r[i]);
  };
  const rad = d => d * Math.PI / 180;
  const homog = corners => {                                                // (u,v) ↔ mètres locaux autour du coin 1 (HG, HD, BD, BG)
    if (!corners || corners.length !== 4) return null;
    const lat0 = corners[0][0], lon0 = corners[0][1], kx = 111320 * Math.cos(rad(lat0)), ky = 110540;
    const P = corners.map(([la, lo]) => [(lo - lon0) * kx, (la - lat0) * ky]); const S = [[0, 0], [1, 0], [1, 1], [0, 1]];
    const M = [], b = [], M2 = [], b2 = [];
    for (let i = 0; i < 4; i++) { const [su, sv] = S[i], [x, y] = P[i]; M.push([su, sv, 1, 0, 0, 0, -su * x, -sv * x]); b.push(x); M.push([0, 0, 0, su, sv, 1, -su * y, -sv * y]); b.push(y); M2.push([x, y, 1, 0, 0, 0, -x * su, -y * su]); b2.push(su); M2.push([0, 0, 0, x, y, 1, -x * sv, -y * sv]); b2.push(sv); }
    const h = solve(M, b), hi = solve(M2, b2); if (!h || !hi) return null;
    return {
      toLL: (u, v) => { const w = h[6] * u + h[7] * v + 1; if (Math.abs(w) < 1e-9) return null; return [lat0 + ((h[3] * u + h[4] * v + h[5]) / w) / ky, lon0 + ((h[0] * u + h[1] * v + h[2]) / w) / kx]; },
      toUV: (lat, lon) => { const x = (lon - lon0) * kx, y = (lat - lat0) * ky; const w = hi[6] * x + hi[7] * y + 1; if (Math.abs(w) < 1e-9) return null; return [(hi[0] * x + hi[1] * y + hi[2]) / w, (hi[3] * x + hi[4] * y + hi[5]) / w]; }
    };
  };
  const frame = () => {                                                     // cadre de l'image affichée (object-fit: contain) en px de #video-col
    if (!video.videoWidth || !video.videoHeight) return null;
    const box = vcol.getBoundingClientRect(), vr = video.getBoundingClientRect(), sc = Math.min(vr.width / video.videoWidth, vr.height / video.videoHeight);
    const dw = video.videoWidth * sc, dh = video.videoHeight * sc;
    return { ox: vr.left - box.left + (vr.width - dw) / 2, oy: vr.top - box.top + (vr.height - dh) / 2, dw, dh, box };
  };
  const geoAt = ev => {
    const fr = frame(); const n = kNum(); if (!fr || !n || !n.corners) return null;
    const x = ev.clientX - fr.box.left, y = ev.clientY - fr.box.top, u = (x - fr.ox) / fr.dw, v = (y - fr.oy) / fr.dh;
    if (u < 0 || u > 1 || v < 0 || v > 1) return null;
    const H = homog(n.corners); const ll = H && H.toLL(u, v); return ll ? { x, y, ll } : null;
  };
  const fmtM = m => m ? m.replace(/^(\d{1,2}[A-Z])([A-Z]{2})(\d{5})(\d{5})$/, "$1 $2 $3 $4") : "—";
  const fmtDistV = m => m >= 10000 ? `${(m / 1000).toFixed(1)} km` : m >= 1000 ? `${(m / 1000).toFixed(2)} km` : `${m.toFixed(0)} m`;
  // mesure vidéo (indépendante de la carte) : A au clic droit, B = curseur puis clic gauche ; Échap annule
  let meas = null, lastCur = null;
  const drawMeas = () => {
    if (!meas) { vMeas.hidden = true; vMeas.innerHTML = ""; return; }
    const fr = frame(); const n = kNum(); const H = fr && n && n.corners ? homog(n.corners) : null; if (!H) { vMeas.hidden = true; return; }
    const px = p => { const uv = H.toUV(p[0], p[1]); return uv ? [fr.ox + uv[0] * fr.dw, fr.oy + uv[1] * fr.dh] : null; };
    const b = meas.fixed ? meas.b : (lastCur ? lastCur.ll : null); const pa = px(meas.a), pb = b ? px(b) : null; if (!pa) { vMeas.hidden = true; return; }
    let svg = "";
    if (pb) { const db = MGRS.distBearing(meas.a[0], meas.a[1], b[0], b[1]); const col = meas.fixed ? "#7cff6b" : "#ffd54f";
      svg += `<line x1="${pa[0]}" y1="${pa[1]}" x2="${pb[0]}" y2="${pb[1]}" stroke="#000" stroke-width="3" stroke-opacity=".5"/><line x1="${pa[0]}" y1="${pa[1]}" x2="${pb[0]}" y2="${pb[1]}" stroke="${col}" stroke-width="1.5"${meas.fixed ? "" : ' stroke-dasharray="6 4"'}/><circle cx="${pb[0]}" cy="${pb[1]}" r="4" fill="${col}" stroke="#000"/>`;
      svg += `<text x="${(pa[0] + pb[0]) / 2 + 8}" y="${(pa[1] + pb[1]) / 2 - 8}" fill="#fff" stroke="#000" stroke-width="3" paint-order="stroke" font-family="Consolas" font-size="12">${fmtDistV(db.d)} — ${db.bearing.toFixed(0).padStart(3, "0")}°</text>`; }
    svg += `<circle cx="${pa[0]}" cy="${pa[1]}" r="4" fill="#ffd54f" stroke="#000"/>`;
    vMeas.innerHTML = svg; vMeas.hidden = false;
  };
  setInterval(() => { if (meas) drawMeas(); }, 120);                       // suit les coins KLV (le capteur bouge)
  vcol.addEventListener("mousemove", ev => {
    const g = geoAt(ev); lastCur = g; vcol.classList.toggle("geo", !!(kNum() && kNum().corners)); vcol.classList.toggle("measuring", !!(meas && !meas.fixed));
    if (!g) { vCur.hidden = true; return; }
    const m = MGRS.toMGRS(g.ll[0], g.ll[1], 5);
    vCur.innerHTML = `${meas && !meas.fixed ? "📏 clic = point B · " : ""}${fmtM(m)} <small>${g.ll[0].toFixed(5)} ${g.ll[1].toFixed(5)}</small>`;
    vCur.style.left = g.x + "px"; vCur.style.top = g.y + "px"; vCur.hidden = !vMenu.hidden; if (meas && !meas.fixed) drawMeas();
  });
  vcol.addEventListener("mouseleave", () => { vCur.hidden = true; lastCur = null; });
  vcol.addEventListener("click", ev => { if (!meas || meas.fixed) return; const g = geoAt(ev); if (!g) return; ev.preventDefault(); ev.stopPropagation(); meas.b = g.ll; meas.fixed = true; drawMeas(); const db = MGRS.distBearing(meas.a[0], meas.a[1], g.ll[0], g.ll[1]); toast(`📏 ${fmtDistV(db.d)} — ${db.bearing.toFixed(0).padStart(3, "0")}°`, "ok", 3000); }, true);
  let vm = null;
  const hideVMenu = () => { vMenu.hidden = true; vm = null; };
  vcol.addEventListener("contextmenu", ev => {
    const g = geoAt(ev); if (!g) return;
    ev.preventDefault(); ev.stopPropagation(); vm = g; const m = MGRS.toMGRS(g.ll[0], g.ll[1], 5);
    $("vm-title").textContent = `${fmtM(m)} · ${g.ll[0].toFixed(5)} ${g.ll[1].toFixed(5)}`;
    vMenu.querySelector('[data-act="meas-clear"]').hidden = !meas;
    vMenu.hidden = false; vCur.hidden = true; const r = vMenu.getBoundingClientRect();
    vMenu.style.left = Math.min(ev.clientX, window.innerWidth - r.width - 8) + "px"; vMenu.style.top = Math.min(ev.clientY, window.innerHeight - r.height - 8) + "px";
  }, true);
  document.addEventListener("mousedown", ev => { if (!vMenu.hidden && !vMenu.contains(ev.target)) hideVMenu(); });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") { hideVMenu(); if (meas && !meas.fixed) { meas = null; drawMeas(); } } });
  vMenu.addEventListener("click", ev => {
    const b = ev.target.closest("button"); if (!b || !vm) return; const act = b.dataset.act; const m = MGRS.toMGRS(vm.ll[0], vm.ll[1], 5);
    const copy = (txt, what) => { try { navigator.clipboard && navigator.clipboard.writeText(txt); } catch (e) { /* */ } toast(`📋 ${what} copié : ${txt}`, "ok", 2500); };
    if (act === "mgrs") copy(fmtM(m), "MGRS");
    else if (act === "ll") copy(`${vm.ll[0].toFixed(6)} ${vm.ll[1].toFixed(6)}`, "lat/lon");
    else if (act === "meas") { meas = { a: vm.ll, b: null, fixed: false }; drawMeas(); toast("📏 mesure : déplacez la souris sur la vidéo, clic gauche pour figer (Échap pour annuler)", "busy", 4000); }
    else if (act === "meas-clear") { meas = null; drawMeas(); }
    hideVMenu();
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
