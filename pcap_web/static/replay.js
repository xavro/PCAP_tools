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
  tl.addEventListener("mousedown", () => { dragging = true; });
  document.addEventListener("mouseup", () => { dragging = false; });
  tl.addEventListener("mousemove", ev => { if (dragging && window.__op) window.__op.seekFrac(ev.offsetX / tl.clientWidth); });
})();
