/* Fond animé des pages StratusServer.
 *
 * Le fond est une page HTML autonome (canvas), posée en IFRAME sous le contenu : elle garde son propre
 * document, ses styles et sa boucle d'animation sans rien partager avec la page hôte — pas de collision de
 * sélecteurs, et une erreur dans le fond ne casse pas la page. L'iframe est inerte aux clics, hors du
 * parcours clavier, et invisible aux lecteurs d'écran : c'est un décor, pas un contenu.
 *
 * Où il s'applique est un RÉGLAGE, pas une décision de ce fichier : la console et le rejeu sont des
 * surfaces de travail denses, où une animation derrière des panneaux translucides gêne plus qu'elle
 * n'habille — ils sont donc hors du défaut, sans être interdits.
 *
 * La configuration vient de `/api/ui`, route ouverte sans session : la page de CONNEXION doit pouvoir
 * l'afficher, et elle est par définition non authentifiée.
 */
(() => {
  "use strict";
  if (window.__stxBackground) return;
  window.__stxBackground = true;

  const BASE = location.pathname.replace(/[^/]*$/, "");
  const ROOT = BASE.replace(/api\/$/, "").replace(/console\/$/, "");

  /** Nom de page, tel que le réglage le désigne. */
  function pageKey () {
    const p = location.pathname.replace(/\/+$/, "");
    if (/\/login(\.html)?$/.test(p)) return "login";
    if (/\/replay(\.html)?$/.test(p)) return "replay";
    if (/\/(missions|health)(\.html)?$/.test(p) || /\/(api\/docs|docs|apidocs\.html)$/.test(p)) return "pages";
    if (document.body && document.body.dataset && document.body.dataset.page) {
      return document.body.dataset.page === "console" ? "console" : "pages";
    }
    return "console";                                      // racine du serveur = console pcap
  }

  const CSS = `
  .stx-bg-frame { position: fixed; inset: 0; width: 100%; height: 100%; border: 0; z-index: -1;
    pointer-events: none; background: var(--bg, #0e1216); }
  /* Le fond ne se voit que si les surfaces au-dessus le laissent passer. On n'allège QUE les grandes
     étendues (corps de page, tableaux) : les panneaux d'analyse, eux, doivent rester lisibles. */
  body.stx-bg { background: transparent !important; }
  body.stx-bg table.pg { background: rgba(22,27,34,.82); backdrop-filter: blur(2px); }
  body.stx-bg .pg-nav { background: rgba(22,27,34,.86); backdrop-filter: blur(3px); }
  body.stx-bg .pg-card, body.stx-bg .card { background: rgba(22,27,34,.82); backdrop-filter: blur(2px); }
  body.stx-bg .lg { background: rgba(22,27,34,.90); backdrop-filter: blur(4px); }`;

  function mount (url) {
    if (document.querySelector(".stx-bg-frame")) return;
    const st = document.createElement("style");
    st.textContent = CSS;
    document.head.appendChild(st);
    const f = document.createElement("iframe");
    f.className = "stx-bg-frame";
    f.src = url;
    f.setAttribute("aria-hidden", "true");
    f.setAttribute("tabindex", "-1");
    f.setAttribute("scrolling", "no");
    f.setAttribute("loading", "lazy");
    // Décor tiers : on lui retire tout pouvoir (scripts autorisés, rien d'autre — ni navigation, ni
    // formulaire, ni accès au document hôte).
    f.setAttribute("sandbox", "allow-scripts");
    document.body.classList.add("stx-bg");
    document.body.insertBefore(f, document.body.firstChild);
  }

  async function init () {
    let cfg = null;
    try {
      const r = await fetch(ROOT + "api/ui", { cache: "no-store" });
      cfg = await r.json();
    } catch { return; }                                    // fond absent : la page reste telle quelle
    const f = (cfg && cfg.fond) || {};
    if (!f.url || !Array.isArray(f.pages) || f.pages.indexOf(pageKey()) < 0) return;
    // URL relative servie par ce serveur, ou absolue vers un hôte choisi dans les paramètres.
    mount(/^https?:\/\//i.test(f.url) ? f.url : ROOT + String(f.url).replace(/^\//, ""));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => { void init(); });
  else void init();
})();
