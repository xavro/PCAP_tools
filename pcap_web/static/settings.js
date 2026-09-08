/* Paramètres d'environnement — panneau partagé par toutes les pages StratusServer v2.
 *
 * POURQUOI ICI. Un déploiement se règle dans `docker/.env` : ports par CR, services cartographiques.
 * Les changer demandait un accès au serveur, une édition de fichier et un redémarrage de la pile — et
 * aucune page ne disait quelle configuration tournait réellement. Ce panneau, ouvert depuis le bandeau de
 * n'importe quelle page, lit `/api/env` : la configuration EFFECTIVE, les défauts d'environnement, et la
 * comparaison entre ce que le démon de capture fait vivre et ce qui est voulu.
 *
 * CE QU'IL NE FAIT PAS. Il n'applique rien à chaud. Les ports de capture sont des sockets ouvertes une
 * fois au démarrage : les rebinder pendant un enregistrement ferait perdre des datagrammes sans que
 * personne ne le sache. Le panneau enregistre donc le VOULU et annonce le redémarrage nécessaire tant que
 * le vif en diffère — un réglage enregistré n'est pas un réglage appliqué, et la nuance doit se voir.
 *
 * Fichier autonome (style compris) : il s'ajoute à une page en une ligne, console comprise, sans dépendre
 * de la feuille de style de celle-ci.
 */
(() => {
  "use strict";
  if (window.__stxSettings) return;                       // déjà chargé (page qui inclut deux fois)
  window.__stxSettings = true;

  const BASE = location.pathname.replace(/[^/]*$/, "");
  const ROOT = BASE.replace(/api\/$/, "").replace(/console\/$/, "");
  const U = p => ROOT + String(p).replace(/^\//, "");
  const esc = v => String(v == null ? "" : v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const CSS = `
  .stx-set-btn { display: inline-flex; align-items: center; gap: 5px; }
  .stx-set-back { position: fixed; inset: 0; background: rgba(4,8,12,.62); z-index: 4000; }
  .stx-set { position: fixed; z-index: 4001; top: 50%; left: 50%; transform: translate(-50%,-50%);
    width: min(820px, 94vw); max-height: 88vh; overflow: auto; background: var(--panel, #161b22);
    color: var(--fg, #e6edf3); border: 1px solid var(--border, #2a323d); border-radius: 10px;
    box-shadow: 0 18px 60px rgba(0,0,0,.55); font: 14px/1.45 "Segoe UI", system-ui, sans-serif; }
  .stx-set h3 { margin: 0; padding: 12px 16px; border-bottom: 1px solid var(--border, #2a323d);
    font-size: 14px; letter-spacing: .04em; text-transform: uppercase; display: flex; align-items: center; gap: 8px; }
  .stx-set h3 .sp { flex: 1; }
  .stx-set section { padding: 12px 16px; border-bottom: 1px solid var(--border, #2a323d); }
  .stx-set h4 { margin: 0 0 8px; font-size: 12px; letter-spacing: .05em; text-transform: uppercase; color: var(--muted, #8a8f98); }
  .stx-set p.hint { margin: 6px 0 0; color: var(--muted, #8a8f98); font-size: 11.5px; line-height: 1.5; }
  .stx-set table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .stx-set th { text-align: left; color: var(--muted, #8a8f98); font-weight: 500; font-size: 11px;
    text-transform: uppercase; letter-spacing: .04em; padding: 0 6px 4px 0; }
  .stx-set td { padding: 3px 6px 3px 0; vertical-align: middle; }
  .stx-set input[type=text], .stx-set input[type=number] { width: 100%; background: var(--panel2, #1c232c);
    color: var(--fg, #e6edf3); border: 1px solid var(--border, #2a323d); border-radius: 6px; padding: 4px 7px;
    font: 12.5px var(--mono, Consolas, monospace); }
  .stx-set td.st { font: 11.5px var(--mono, Consolas, monospace); white-space: nowrap; }
  .stx-set .vif { color: var(--ok, #7cff6b); } .stx-set .att { color: var(--warn, #ffd54f); }
  .stx-set .err { color: var(--danger, #ff5252); }
  .stx-set button { font: inherit; color: var(--fg, #e6edf3); background: var(--panel2, #1c232c);
    border: 1px solid var(--border, #2a323d); border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12.5px; }
  .stx-set button:hover { border-color: var(--accent, #00c8ff); }
  .stx-set button.accent { background: var(--accent, #00c8ff); color: #001018; border-color: var(--accent, #00c8ff); font-weight: 600; }
  .stx-set button.lnk { background: none; border: none; color: var(--muted, #8a8f98); padding: 2px 6px; }
  .stx-set button.lnk:hover { color: var(--danger, #ff5252); }
  .stx-set footer { padding: 10px 16px; display: flex; align-items: center; gap: 8px; }
  .stx-set footer .sp { flex: 1; }
  .stx-set .banner { margin: 0 0 10px; padding: 7px 10px; border-radius: 6px; font-size: 12px;
    border: 1px solid var(--warn, #ffd54f); color: var(--warn, #ffd54f); background: rgba(255,213,79,.10); }
  .stx-set .banner.err { border-color: var(--danger, #ff5252); color: var(--danger, #ff5252); background: rgba(255,82,82,.10); }
  .stx-set .path { font: 11px var(--mono, Consolas, monospace); color: var(--muted, #8a8f98); }
  .stx-set label.lbl { display: flex; align-items: center; gap: 8px; margin: 4px 0; font-size: 12.5px; color: var(--muted, #8a8f98); }
  .stx-set label.lbl > select, .stx-set label.lbl > input[type=text] { flex: 1; min-width: 0; }
  .stx-set label.lbl.chk { color: var(--muted, #8a8f98); }
  .stx-set select { background: var(--panel2, #1c232c); color: var(--fg, #e6edf3);
    border: 1px solid var(--border, #2a323d); border-radius: 6px; padding: 4px 7px; font-size: 12.5px; }`;

  const style = document.createElement("style");
  style.textContent = CSS;
  document.head.appendChild(style);

  let state = null;                                        // dernier /api/env reçu
  let bm = null;                                           // dernier /api/basemap reçu (source du fond)
  let box = null, back = null;

  const api = async (path, opt) => {
    const r = await fetch(U(path), opt);
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  };

  /** Ports d'un CR : [vidéo, GMTI, …] → {video, gmti}. Le 1er port est la vidéo (clé de session). */
  const split = ports => ({ video: (ports || [])[0] ?? "", gmti: (ports || [])[1] ?? "" });

  /** Même ensemble de ports, dans le même ordre ? (comparaison vif ↔ voulu) */
  const same = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || []);

  function rowsCapture () {
    const cfg = (state.config && state.config.capture_sets) || {};
    const vif = state.capture && state.capture.vif;
    return Object.keys(cfg).map(cr => {
      const p = split(cfg[cr]);
      let st = '<span class="path">—</span>';
      if (vif && vif[cr]) st = same(vif[cr], cfg[cr]) ? '<span class="vif">● vif</span>'
        : '<span class="att">⚠ vif ' + esc(vif[cr].join("+")) + "</span>";
      else if (vif) st = '<span class="att">⚠ absent du démon</span>';
      return `<tr data-cr="${esc(cr)}">
        <td><input type="text" class="c-nom" value="${esc(cr)}" spellcheck="false"></td>
        <td><input type="number" class="c-video" min="1" max="65535" value="${esc(p.video)}"></td>
        <td><input type="number" class="c-gmti" min="1" max="65535" value="${esc(p.gmti)}" placeholder="—"></td>
        <td class="st">${st}</td>
        <td><button type="button" class="lnk c-del" title="retirer ce CR">✕</button></td></tr>`;
    }).join("");
  }

  function rowsMap () {
    const list = (state.config && state.config.mapservers) || [];
    return list.map((m, i) => `<tr data-i="${i}">
      <td style="width:26%"><input type="text" class="m-nom" value="${esc(m.nom)}" spellcheck="false"></td>
      <td><input type="text" class="m-url" value="${esc(m.url)}" spellcheck="false" placeholder="https://…/MapServer"></td>
      <td style="width:78px;text-align:center"><input type="radio" name="m-def" class="m-def"${m.defaut ? " checked" : ""}></td>
      <td><button type="button" class="lnk m-del" title="retirer ce service">✕</button></td></tr>`).join("");
  }

  function render () {
    const cap = state.capture || {};
    const bandeaux = [];
    if (state.erreur) bandeaux.push(`<div class="banner err">${esc(state.erreur)}</div>`);
    if (cap.vif_erreur) bandeaux.push(`<div class="banner">Démon de capture injoignable (${esc(cap.vif_erreur)}) — la colonne « vif » ne peut pas être comparée.</div>`);
    if (cap.redemarrage_requis) bandeaux.push('<div class="banner">La configuration enregistrée diffère de celle qui tourne : redémarrer <b>stratus2-capture</b> pour l\'appliquer.</div>');

    box.innerHTML = `
      <h3>⚙ Paramètres d'environnement <span class="sp"></span><button type="button" id="s-close" class="lnk" title="Fermer">✕</button></h3>
      <section>
        <h4>Capture — ports par CR</h4>
        ${bandeaux.join("")}
        <table><thead><tr><th style="width:22%">CR</th><th style="width:22%">Vidéo 4609</th><th style="width:22%">GMTI 4607</th><th>État</th><th></th></tr></thead>
        <tbody id="s-cap">${rowsCapture()}</tbody></table>
        <div style="margin-top:8px"><button type="button" id="s-cap-add">+ ajouter un CR</button></div>
        <p class="hint">Le 1<sup>er</sup> port est la vidéo (clé de session d'enregistrement), le 2<sup>e</sup> le GMTI 4607.
        Ces ports sont des sockets ouvertes au démarrage : l'enregistrement se fait <b>au redémarrage du service de capture</b>,
        jamais à chaud — rebinder pendant une capture perdrait des datagrammes sans le dire.
        Équivalent <span class="path">CAPTURE_SETS=${esc(cap.spec || "")}</span></p>
      </section>
      <section>
        <h4>Fond de carte</h4>
        <label class="lbl">Source
          <select id="s-bm-provider">
            <option value="arcgis_online">ArcGIS Online (internet)</option>
            <option value="mapserver">MapServer ArcGIS dynamique — export (réseau local, via proxy)</option>
            <option value="none">Aucun</option>
          </select></label>
        <label class="lbl" id="s-bm-layer-row">Couche
          <select id="s-bm-layer">
            <option value="World_Imagery">Imagerie</option>
            <option value="World_Topo_Map">Topographique</option>
            <option value="World_Street_Map">Rues</option>
            <option value="Canvas/World_Dark_Gray_Base">Gris foncé (canvas)</option>
          </select></label>
        <div id="s-bm-ms">
          <label class="lbl">Service <select id="s-bm-service"></select></label>
          <label class="lbl">URL <input type="text" id="s-bm-url" placeholder="https://serveur/arcgis/rest/services/X/MapServer"></label>
          <label class="lbl">Jeton <input type="text" id="s-bm-token" placeholder="(optionnel)"></label>
          <label class="lbl chk"><input type="checkbox" id="s-bm-insecure"> accepter un certificat auto-signé</label>
        </div>
        <p class="hint" id="s-bm-hint"></p>
      </section>
      <section>
        <h4>Services cartographiques (MapServer)</h4>
        <table><thead><tr><th>Nom</th><th>URL du service</th><th>Défaut</th><th></th></tr></thead>
        <tbody id="s-map">${rowsMap()}</tbody></table>
        <div style="margin-top:8px"><button type="button" id="s-map-add">+ ajouter un service</button></div>
        <p class="hint">Services proposés aux fonds de carte des pages (console, rejeu). Celui marqué « défaut » est
        proposé en premier. Prend effet au rechargement de la page, sans redémarrage.</p>
      </section>
      <footer>
        <span class="path">${esc(state.fichier || "")}</span>
        <span class="sp"></span>
        <span id="s-msg" class="path"></span>
        <button type="button" id="s-cancel">Fermer</button>
        <button type="button" class="accent" id="s-save">Enregistrer</button>
      </footer>`;

    fillBasemap();
    box.querySelector("#s-bm-provider").onchange = bmRows;
    box.querySelector("#s-bm-service").onchange = bmService;
    box.querySelector("#s-close").onclick = close;
    box.querySelector("#s-cancel").onclick = close;
    box.querySelector("#s-save").onclick = save;
    box.querySelector("#s-cap-add").onclick = () => {
      const tb = box.querySelector("#s-cap");
      const n = tb.querySelectorAll("tr").length + 1;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><input type="text" class="c-nom" value="CR${n}" spellcheck="false"></td>
        <td><input type="number" class="c-video" min="1" max="65535" value=""></td>
        <td><input type="number" class="c-gmti" min="1" max="65535" value="" placeholder="—"></td>
        <td class="st"><span class="att">⚠ nouveau</span></td>
        <td><button type="button" class="lnk c-del" title="retirer ce CR">✕</button></td>`;
      tb.appendChild(tr);
    };
    box.querySelector("#s-map-add").onclick = () => {
      const tb = box.querySelector("#s-map");
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><input type="text" class="m-nom" value="" spellcheck="false" placeholder="Ortho"></td>
        <td><input type="text" class="m-url" value="" spellcheck="false" placeholder="https://…/MapServer"></td>
        <td style="text-align:center"><input type="radio" name="m-def" class="m-def"></td>
        <td><button type="button" class="lnk m-del" title="retirer ce service">✕</button></td>`;
      tb.appendChild(tr);
    };
    box.addEventListener("click", e => {
      const t = e.target;
      if (t && t.classList && (t.classList.contains("c-del") || t.classList.contains("m-del"))) {
        const tr = t.closest("tr"); if (tr) tr.remove();
      }
    });
  }

  /** Remplit la section « Fond de carte » depuis /api/basemap (le catalogue vient de la section voisine). */
  function fillBasemap () {
    const c = bm || {}, svc = c.services || [];
    box.querySelector("#s-bm-provider").value = c.provider || "arcgis_online";
    box.querySelector("#s-bm-layer").value = c.layer || "World_Imagery";
    box.querySelector("#s-bm-url").value = c.url || "";
    box.querySelector("#s-bm-token").value = c.token || "";
    box.querySelector("#s-bm-insecure").checked = c.insecure !== false;
    const sel = box.querySelector("#s-bm-service");
    sel.innerHTML = '<option value="">— URL libre —</option>' +
      svc.map(m => `<option value="${esc(m.nom)}">${esc(m.nom)}${m.defaut ? " (défaut)" : ""}</option>`).join("");
    sel.value = svc.some(m => m.nom === c.service) ? c.service : "";
    // Le service choisi a disparu du catalogue : le dire, sinon la carte affiche un fond de repli sans que
    // rien n'explique pourquoi ce n'est plus celui qui avait été choisi.
    box.querySelector("#s-bm-hint").innerHTML = c.service_absent
      ? `<b>service « ${esc(c.service_absent)} » absent du catalogue</b> — repli sur le service par défaut.`
      : "Tant qu'aucun choix n'est fait ici, le service marqué « défaut » du catalogue ci-dessous s'applique.";
    bmService(); bmRows();
  }
  function bmRows () {
    const p = box.querySelector("#s-bm-provider").value;
    box.querySelector("#s-bm-layer-row").hidden = p !== "arcgis_online";
    box.querySelector("#s-bm-ms").hidden = p !== "mapserver";
  }
  /** URL verrouillée quand elle vient du catalogue : la vérité est la liste, pas ce champ recopié. */
  function bmService () {
    const svc = (bm && bm.services) || [];
    const m = svc.find(x => x.nom === box.querySelector("#s-bm-service").value);
    const url = box.querySelector("#s-bm-url");
    url.readOnly = !!m;
    if (m) url.value = m.url;
  }

  /** Lecture des tableaux → charge utile POST. Les champs vides sont ignorés (un GMTI sans port est licite). */
  function collect () {
    const sets = {};
    box.querySelectorAll("#s-cap tr").forEach(tr => {
      const nom = (tr.querySelector(".c-nom").value || "").trim();
      const v = (tr.querySelector(".c-video").value || "").trim();
      const g = (tr.querySelector(".c-gmti").value || "").trim();
      if (!nom || !v) return;
      sets[nom] = g ? [Number(v), Number(g)] : [Number(v)];
    });
    const map = [];
    box.querySelectorAll("#s-map tr").forEach(tr => {
      const url = (tr.querySelector(".m-url").value || "").trim();
      if (!url) return;
      map.push({ nom: (tr.querySelector(".m-nom").value || "").trim() || url,
        url, defaut: tr.querySelector(".m-def").checked });
    });
    return { capture_sets: sets, mapservers: map };
  }

  async function save () {
    const msg = box.querySelector("#s-msg");
    const btn = box.querySelector("#s-save");
    msg.className = "path"; msg.textContent = "enregistrement…"; btn.disabled = true;
    try {
      // Le catalogue d'abord : le choix de fond peut désigner un service que l'on vient d'ajouter.
      state = await api("api/env", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(collect()) });
      bm = await api("api/basemap", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: box.querySelector("#s-bm-provider").value,
          layer: box.querySelector("#s-bm-layer").value,
          url: (box.querySelector("#s-bm-url").value || "").trim(),
          token: (box.querySelector("#s-bm-token").value || "").trim() || null,
          insecure: box.querySelector("#s-bm-insecure").checked,
          // `service` part MÊME vide : il marque le choix explicite et fige le fond contre le défaut.
          service: box.querySelector("#s-bm-service").value }) });
      render();
      // La page qui héberge une carte la rafraîchit sans rechargement (console, rejeu).
      if (typeof window.stxBasemapReload === "function") void window.stxBasemapReload();
      const m2 = box.querySelector("#s-msg");
      m2.className = "path vif";
      m2.textContent = state.capture && state.capture.redemarrage_requis
        ? "enregistré — redémarrage de la capture nécessaire" : "enregistré";
    } catch (e) {
      msg.className = "path err"; msg.textContent = String(e.message || e);
    } finally { btn.disabled = false; }
  }

  function close () {
    if (back) back.remove();
    if (box) box.remove();
    back = box = null;
    document.removeEventListener("keydown", onKey);
  }
  const onKey = e => { if (e.key === "Escape") close(); };

  async function open () {
    if (box) return;
    back = document.createElement("div"); back.className = "stx-set-back"; back.onclick = close;
    box = document.createElement("div"); box.className = "stx-set";
    box.innerHTML = '<h3>⚙ Paramètres d\'environnement</h3><section class="path">chargement…</section>';
    document.body.append(back, box);
    document.addEventListener("keydown", onKey);
    try {
      const [env, base] = await Promise.all([api("api/env"), api("api/basemap")]);
      state = env; bm = base;
      render();
    } catch (e) {
      box.innerHTML = `<h3>⚙ Paramètres d'environnement</h3><section><div class="banner err">${esc(e.message || e)}</div></section>
        <footer><span class="sp"></span><button type="button" id="s-cancel">Fermer</button></footer>`;
      box.querySelector("#s-cancel").onclick = close;
    }
  }
  window.stxSettings = { open, close };

  // ── Point d'entrée ──
  // Une seule roue dentée par en-tête. Les pages (missions, health, docs, rejeu) ont une barre `.pg-nav`
  // et rien d'autre : on y pose une icône seule. La console, elle, a DÉJÀ sa roue dentée — celle de ses
  // paramètres — et en ajouter une seconde à côté ne dirait pas à l'opérateur laquelle ouvre quoi : on se
  // greffe alors DANS son panneau, à la suite de ses propres réglages.
  const GEAR = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2">' +
    '<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>';
  const TITRE = "Paramètres d'environnement (ports par CR, services cartographiques)";

  function mount () {
    if (document.getElementById("stx-set-btn") || document.getElementById("stx-set-row")) return;

    // Console (et rejeu) : panneau de paramètres déjà présent → on s'y range, pas de seconde roue.
    const body = document.querySelector("#settings .st-body");
    if (body && document.getElementById("btn-settings")) {
      const sec = document.createElement("section");
      sec.id = "stx-set-row";
      sec.innerHTML = '<h4>Environnement (déploiement)</h4>' +
        '<div class="row"><button type="button" id="stx-set-open" title="' + TITRE + '">' + GEAR +
        " Ports par CR &amp; services cartographiques…</button></div>" +
        '<div class="row"><span class="muted">Réglages du SERVEUR, partagés par toutes les pages et par le service de capture ' +
        "(fichier <span class=\"mono\">environnement.json</span>), à distinguer des réglages locaux ci-dessus.</span></div>";
      body.appendChild(sec);
      sec.querySelector("#stx-set-open").onclick = () => { void open(); };
      return;
    }

    const b = document.createElement("button");
    b.id = "stx-set-btn";
    b.type = "button";
    b.title = TITRE;
    b.setAttribute("aria-label", TITRE);       // icône seule : le lecteur d'écran a besoin du libellé
    b.className = "stx-set-btn";
    b.innerHTML = GEAR;
    b.onclick = () => { void open(); };
    const nav = document.querySelector(".pg-nav");
    if (nav) { b.classList.add("btn"); nav.appendChild(b); return; }
    const head = document.querySelector("#app > header") || document.querySelector("header");
    if (head) head.appendChild(b);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
