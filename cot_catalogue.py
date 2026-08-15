#!/usr/bin/env python3
"""Genere le catalogue des symboles CoT / MIL-STD-2525 reconstruits par le receiver.

POC ISRBOX / 33e ESRA — reference consultable type CoT <-> SIDC 2525 <-> libelle.

Source : les memes tables de marshalling APP-6 (app6/marshalling/*.csv) que le
receiver et que cot_deltasuite_sim.py. Chaque ligne est un symbole que le receiver
sait produire, avec le SIDC et le nom EXACTS qu'il en tire (aucun ecart).

Deux perimetres :
  - defaut : les ICONES de base (schema + affiliation + dimension + fonction),
    dedupliquees des variantes de statut/echelon -> catalogue humainement lisible ;
  - --modifiers : TOUTES les combinaisons (statut x taille x mobilite), reservees
    au CSV (des centaines de milliers de lignes, non consultables en HTML).

Sorties :
  python cot_catalogue.py                 # -> catalogue-cot-2525.html + .csv (icones)
  python cot_catalogue.py --format csv --modifiers   # CSV complet (toutes combinaisons)
  python cot_catalogue.py --out mondossier/cat       # prefixe de sortie personnalise
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

from cot_deltasuite_sim import App6Tables

# Schemas de codage 2525C (1er caractere du SIDC).
SCHEME_LABELS = {
    "S": "Combat (Warfighting)",
    "G": "Symboles tactiques (Tactical Graphics)",
    "W": "Meteo / oceano (METOC)",
    "I": "Renseignement (SIGINT)",
    "O": "Operations de stabilisation",
    "E": "Gestion des situations d'urgence",
}

COLUMNS = ["Nom", "Type CoT", "SIDC", "Affiliation", "Dimension de bataille", "Schema"]


def build_rows(tables: App6Tables, identities: list[str], modifiers: bool) -> list[list[str]]:
    index = tables.build_index(identities)      # {type -> (SIDC, nom, dimension)}

    if modifiers:
        items = list(index.items())
    else:
        # Une entree par icone de base : schema+affiliation+dimension+fonction
        # (SIDC pos 1-3 et 5-10), en gardant le type le plus court (symbole nominal).
        best: dict[str, tuple] = {}
        for cot_type, val in index.items():
            sidc = val[0]
            if not sidc:
                continue
            key = sidc[:3] + sidc[4:10]
            dashes = cot_type.count("-")
            if key not in best or dashes < best[key][1]:
                best[key] = ((cot_type, val), dashes)
        items = [entry[0] for entry in best.values()]

    rows: list[list[str]] = []
    for cot_type, (sidc, name, bd) in items:
        if not sidc:
            continue
        aff_char = cot_type.split("-")[1][0].lower() if "-" in cot_type else "?"
        aff = tables.identity_name.get(aff_char, aff_char.upper())
        scheme = SCHEME_LABELS.get(sidc[0], sidc[0])
        rows.append([name or "(marqueur)", cot_type, sidc, aff, bd or "", scheme])

    rows.sort(key=lambda r: (r[3], r[4], r[1]))
    return rows


def write_csv(rows: list[list[str]], path: str) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(COLUMNS)
        w.writerows(rows)


def load_modifier_options(tables_dir: str) -> dict:
    """[(libelle, gabarit 15 car.)] par famille de modificateur, pour recomposer
    le SIDC en direct dans le HTML (statut / echelon / mobilite)."""
    def rows(fname):
        out = []
        for r in App6Tables._load(tables_dir, fname):
            e = (r.get("encode") or "").split("/")[0]
            if len(e) != 15:
                continue
            label = r.get("name_fr") or r.get("name") or ""
            out.append([label, e])
        return out
    return {"status": rows("status.csv"), "size": rows("size.csv"),
            "mobility": rows("mobility.csv")}


def write_html(rows: list[list[str]], path: str, modifiers: bool,
               milsymbol_js: str = "", modifier_options: dict | None = None,
               ident_names: dict | None = None, core_templates: list | None = None,
               identity_templates: dict | None = None) -> None:
    data_json = json.dumps(rows, ensure_ascii=False)
    mods_json = json.dumps(modifier_options or {}, ensure_ascii=False)
    ident_json = json.dumps(ident_names or {}, ensure_ascii=False)
    scheme_json = json.dumps(SCHEME_LABELS, ensure_ascii=False)
    cores_json = json.dumps(core_templates or [], ensure_ascii=False)
    identtpl_json = json.dumps(identity_templates or {}, ensure_ascii=False)
    affiliations = sorted({r[3] for r in rows})
    dimensions = sorted({r[4] for r in rows if r[4]})
    schemes = sorted({r[5] for r in rows})

    def options(values):
        return "".join(f"<option value=\"{v}\">{v}</option>" for v in values)

    def mod_options(family):
        got = (modifier_options or {}).get(family, [])
        return "".join(f"<option value=\"{enc}\">{lbl}</option>" for lbl, enc in got)

    scope = ("toutes les combinaisons statut/taille/mobilite"
             if modifiers else "icones de base — modificateurs applicables en direct")

    html_doc = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Catalogue CoT / MIL-STD-2525 — receiver ISRBOX</title>
<style>
  :root {{
    --bg:#f6f7f9; --fg:#1c2128; --muted:#5b6673; --card:#ffffff; --line:#e2e6ea;
    --accent:#1d6fb8; --hover:#eef4fb; --chip:#eef1f4; --mono:#0b3d66;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0f1419; --fg:#e6e9ec; --muted:#93a1af; --card:#161b22; --line:#2a323c;
      --accent:#4a9fe0; --hover:#1b2530; --chip:#20262e; --mono:#8fc7f2;
    }}
  }}
  :root[data-theme="light"] {{
    --bg:#f6f7f9; --fg:#1c2128; --muted:#5b6673; --card:#ffffff; --line:#e2e6ea;
    --accent:#1d6fb8; --hover:#eef4fb; --chip:#eef1f4; --mono:#0b3d66;
  }}
  :root[data-theme="dark"] {{
    --bg:#0f1419; --fg:#e6e9ec; --muted:#93a1af; --card:#161b22; --line:#2a323c;
    --accent:#4a9fe0; --hover:#1b2530; --chip:#20262e; --mono:#8fc7f2;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:22px 20px 10px; max-width:1200px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); font-size:13.5px; }}
  .wrap {{ max-width:1200px; margin:0 auto; padding:0 20px 40px; }}
  .controls {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center;
    position:sticky; top:0; background:var(--bg); padding:12px 0; z-index:5;
    border-bottom:1px solid var(--line); }}
  input, select {{ font:inherit; padding:8px 10px; border:1px solid var(--line);
    border-radius:8px; background:var(--card); color:var(--fg); }}
  input#q {{ flex:1 1 240px; min-width:200px; }}
  .count {{ color:var(--muted); font-size:13px; margin-left:auto; white-space:nowrap; }}
  button {{ font:inherit; padding:8px 12px; border:1px solid var(--line);
    border-radius:8px; background:var(--card); color:var(--fg); cursor:pointer; }}
  button:hover {{ background:var(--hover); }}
  .tablewrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:10px;
    margin-top:14px; background:var(--card); }}
  table {{ border-collapse:collapse; width:100%; font-size:14px; }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line);
    white-space:nowrap; }}
  th {{ position:sticky; top:64px; background:var(--card); cursor:pointer;
    user-select:none; font-weight:600; }}
  th:hover {{ color:var(--accent); }}
  tbody tr:hover {{ background:var(--hover); }}
  td.mono, td.sidc {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color:var(--mono); cursor:copy; }}
  td.name {{ white-space:normal; min-width:220px; }}
  td.sym {{ width:46px; text-align:center; padding:4px; }}
  td.sym svg {{ height:34px; width:auto; vertical-align:middle; }}
  .toggle {{ display:flex; align-items:center; gap:6px; font-size:13px; color:var(--muted); }}
  .chip {{ display:inline-block; padding:1px 8px; border-radius:20px;
    background:var(--chip); font-size:12px; }}
  .lookup {{ display:flex; flex-wrap:wrap; gap:16px; align-items:center;
    background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 16px; margin-top:12px; }}
  .lookup label {{ display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }}
  .lk-in {{ flex:1 1 320px; }}
  .lk-in input {{ width:100%; font-family:ui-monospace,Consolas,monospace; }}
  .lk-out {{ display:flex; align-items:center; gap:14px; min-height:64px; }}
  .lk-sym svg {{ height:64px; width:auto; }}
  .lk-txt {{ font-size:13px; line-height:1.6; }}
  .lk-txt .mono {{ font-family:ui-monospace,Consolas,monospace; color:var(--mono); }}
  .modbar {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:10px;
    font-size:13px; color:var(--muted); }}
  .modbar b {{ color:var(--fg); }}
  .pager {{ display:flex; gap:10px; align-items:center; justify-content:center;
    margin-top:14px; flex-wrap:wrap; }}
  .pager button[disabled] {{ opacity:.4; cursor:default; }}
  .foot {{ color:var(--muted); font-size:12.5px; margin-top:14px; }}
  .foot code {{ font-family:ui-monospace,Consolas,monospace; }}
  #toast {{ position:fixed; bottom:20px; left:50%; transform:translateX(-50%);
    background:var(--accent); color:#fff; padding:8px 14px; border-radius:8px;
    opacity:0; transition:opacity .2s; pointer-events:none; }}
</style>
</head>
<body>
<header>
  <h1>Catalogue CoT &rarr; MIL-STD-2525</h1>
  <div class="sub">Correspondance <b>type CoT</b> (format Delta Suite) &rarr;
    <b>SIDC 2525</b> &rarr; <b>libelle</b>, telle que la reconstruit le receiver
    ISRBOX. Perimetre : {scope}.</div>
</header>
<div class="wrap">
  <div class="lookup">
    <div class="lk-in">
      <label>Recherche inversee &mdash; collez un SIDC <b>ou</b> un type CoT, le symbole s'affiche</label>
      <input id="sidcin" placeholder="SIDC ex. SHGPIBN---HK---  /  type ex. a-f-G-P-I-B-N-H-K" autocomplete="off">
    </div>
    <div class="lk-out">
      <div id="lksym" class="lk-sym"></div>
      <div id="lktxt" class="lk-txt"></div>
    </div>
  </div>
  <div class="controls">
    <input id="q" type="search" placeholder="Rechercher (nom, type, SIDC)..." autocomplete="off">
    <select id="faff"><option value="">Toute affiliation</option>{options(affiliations)}</select>
    <select id="fsch"><option value="">Tout schema</option>{options(schemes)}</select>
    <select id="fdim"><option value="">Toute dimension</option>{options(dimensions)}</select>
    <label class="toggle"><input type="checkbox" id="showsym" checked> Symboles</label>
    <button id="reset">Reinitialiser</button>
    <span class="count" id="count"></span>
  </div>
  <div class="modbar">
    <b>Modificateurs</b> (appliques a tout le tableau, comme Delta Suite les composerait) :
    <select id="mstatus"><option value="">Statut : Present (defaut)</option>{mod_options("status")}</select>
    <select id="msize"><option value="">Echelon : aucun</option>{mod_options("size")}</select>
    <select id="mmob"><option value="">Mobilite : aucune</option>{mod_options("mobility")}</select>
  </div>
  <div class="tablewrap">
    <table>
      <thead><tr id="head"></tr></thead>
      <tbody id="body"></tbody>
    </table>
  </div>
  <div class="pager">
    <button id="first">&laquo;</button>
    <button id="prev">&lsaquo; Precedent</button>
    <span id="pageinfo"></span>
    <button id="next">Suivant &rsaquo;</button>
    <button id="last">&raquo;</button>
    <select id="psize">
      <option value="50">50 / page</option>
      <option value="100" selected>100 / page</option>
      <option value="200">200 / page</option>
    </select>
  </div>
  <div class="foot">
    {len(rows)} icones de base. Applique un <b>echelon</b> ou une <b>mobilite</b>
    ci-dessus et chaque symbole se recompose &mdash; c'est ainsi qu'on atteint
    <i>toutes</i> les combinaisons sans alourdir le fichier. Symboles rendus par
    <a href="https://www.spatialillusions.com/milsymbol/" target="_blank" rel="noopener">milsymbol</a>
    (MIT, &copy; M&aring;ns Beckman) depuis le SIDC. Clic colonne = tri ; clic sur
    <code>type</code>/<code>SIDC</code> = copie. Genere par <code>cot_catalogue.py</code>.
  </div>
</div>
<div id="toast"></div>
<!--MILSYMBOL-->
<script>
const COLS = {json.dumps(COLUMNS, ensure_ascii=False)};
const DATA = {data_json};
const MODS = {mods_json};          // {{status,size,mobility}} -> [[libelle, gabarit]]
const IDENT = {ident_json};        // lettre affiliation -> libelle
const SCHEMES = {scheme_json};     // 1er caractere SIDC -> libelle schema
const CORES = {cores_json};        // [[gabarit fonction, nom]] pour reconstruire type->SIDC
const IDENT_TPL = {identtpl_json}; // lettre affiliation -> gabarit 15 car.
const STATUS = MODS.status.map(m => m[1]), SIZE = MODS.size.map(m => m[1]),
      MOBIL = MODS.mobility.map(m => m[1]);
const HAS_MS = (typeof ms !== 'undefined');
const svgCache = {{}};
let sortCol = -1, sortDir = 1, page = 1, pageSize = 100;

const $ = id => document.getElementById(id);
const q = $('q'), faff = $('faff'), fsch = $('fsch'), fdim = $('fdim'),
      showsym = $('showsym'), mstatus = $('mstatus'), msize = $('msize'), mmob = $('mmob'),
      body = $('body'), count = $('count'), head = $('head'),
      pageinfo = $('pageinfo'), psize = $('psize'),
      sidcin = $('sidcin'), lksym = $('lksym'), lktxt = $('lktxt');

// Index nom par icone (SIDC pos 1-3 + 5-10) pour la recherche inversee.
const NAMEBYICON = {{}};
DATA.forEach(r => {{ const k = r[2].slice(0,3) + r[2].slice(4,10);
                     if (!(k in NAMEBYICON)) NAMEBYICON[k] = r[0]; }});

// En-tete : colonne symbole (non triable) + colonnes de donnees.
const thSym = document.createElement('th'); thSym.textContent = 'Symbole'; head.appendChild(thSym);
COLS.forEach((c, i) => {{
  const th = document.createElement('th'); th.textContent = c;
  th.onclick = () => {{ sortDir = (sortCol === i) ? -sortDir : 1; sortCol = i; render(); }};
  head.appendChild(th);
}});

function esc(s) {{ return String(s).replace(/[&<>"]/g, c =>
  ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c])); }}

// Superpose un gabarit 15 car. sur le SIDC (non-tiret l'emporte).
function overlay(base, tpl) {{
  const a = base.split('');
  for (let i = 0; i < 15 && i < tpl.length; i++) if (tpl[i] !== '-') a[i] = tpl[i];
  return a.join('');
}}
// SIDC -> type CoT : retire tirets, ecarte le schema (pos 1), affiliation en minuscule.
function compact(sidc) {{
  const ch = [...sidc].filter(c => c !== '-');
  if (ch.length <= 1) return ch.length ? 'a' : '';
  let out = 'a';
  for (let i = 1; i < ch.length; i++) out += '-' + (i === 1 ? ch[i].toLowerCase() : ch[i]);
  return out;
}}
function applyMods(sidc) {{
  let out = sidc;
  [mstatus.value, msize.value, mmob.value].forEach(enc => {{ if (enc) out = overlay(out, enc); }});
  return out;
}}
// Statut position 4 -> P si vide (defaut 2525, aligne le receiver).
function present(sidc) {{
  return (sidc[3] === '-') ? sidc.slice(0, 3) + 'P' + sidc.slice(4) : sidc;
}}
// type CoT -> SIDC : rejoue la recherche du receiver (meme ordre, premier gagnant).
function reconstruct(type) {{
  const seg = type.split('-');
  if (seg.length < 2 || seg[0] !== 'a' || !seg[1]) return null;
  const idt = IDENT_TPL[seg[1][0].toLowerCase()];
  if (!idt) return null;
  for (const [core, name] of CORES) {{
    const base0 = overlay(idt, core);
    if (compact(base0) === type) return {{sidc: present(base0), name}};
    for (const st of STATUS) {{
      const base = overlay(base0, st);
      if (compact(base) === type) return {{sidc: present(base), name}};
      for (const sz of SIZE) {{ const w = overlay(base, sz); if (compact(w) === type) return {{sidc: present(w), name}}; }}
      for (const mb of MOBIL) {{ const w = overlay(base, mb); if (compact(w) === type) return {{sidc: present(w), name}}; }}
    }}
  }}
  return null;
}}
function looksLikeType(v) {{ return /^[a-z](-[A-Za-z0-9]+)+$/.test(v); }}
function symbolSVG(sidc) {{
  if (!HAS_MS || !showsym.checked) return '';
  if (sidc in svgCache) return svgCache[sidc];
  let svg = '';
  try {{ svg = new ms.Symbol(sidc, {{size: 22}}).asSVG(); }} catch (e) {{ svg = ''; }}
  svgCache[sidc] = svg;
  return svg;
}}

function toast(msg) {{
  const t = $('toast'); t.textContent = msg; t.style.opacity = 1;
  setTimeout(() => t.style.opacity = 0, 900);
}}

function filtered() {{
  const term = q.value.trim().toLowerCase();
  const a = faff.value, s = fsch.value, d = fdim.value;
  let rows = DATA.filter(r =>
    (!a || r[3] === a) && (!s || r[5] === s) && (!d || r[4] === d) &&
    (!term || (r[0] + ' ' + r[1] + ' ' + r[2]).toLowerCase().includes(term)));
  if (sortCol >= 0) rows = rows.slice().sort((x, y) =>
    x[sortCol] < y[sortCol] ? -sortDir : x[sortCol] > y[sortCol] ? sortDir : 0);
  return rows;
}}

function render() {{
  const rows = filtered();
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (page > pages) page = pages;
  if (page < 1) page = 1;
  const start = (page - 1) * pageSize;
  const shown = rows.slice(start, start + pageSize);
  const modOn = mstatus.value || msize.value || mmob.value;
  body.innerHTML = shown.map(r => {{
    const eff = applyMods(r[2]);
    const type = modOn ? compact(eff) : r[1];
    return '<tr>' +
      '<td class="sym">' + symbolSVG(eff) + '</td>' +
      '<td class="name">' + esc(r[0]) + '</td>' +
      '<td class="mono" data-copy="' + esc(type) + '">' + esc(type) + '</td>' +
      '<td class="sidc" data-copy="' + esc(eff) + '">' + esc(eff) + '</td>' +
      '<td><span class="chip">' + esc(r[3]) + '</span></td>' +
      '<td>' + esc(r[4]) + '</td>' +
      '<td>' + esc(r[5]) + '</td></tr>';
  }}).join('');
  count.textContent = total + ' resultat' + (total > 1 ? 's' : '');
  pageinfo.textContent = 'Page ' + page + ' / ' + pages +
    '  (' + (total ? start + 1 : 0) + '-' + Math.min(start + pageSize, total) + ')';
  $('first').disabled = $('prev').disabled = (page <= 1);
  $('last').disabled = $('next').disabled = (page >= pages);
}}

// --- Recherche inversee : SIDC OU type CoT colle -> symbole + decodage ---
function doLookup() {{
  const raw = sidcin.value.trim();
  if (!raw) {{ lksym.innerHTML = ''; lktxt.innerHTML = ''; return; }}
  let s, name, src;
  if (looksLikeType(raw)) {{
    // Entree = type CoT (ex a-f-G-P-I-B-N-H-K) -> on reconstruit le SIDC.
    const rec = reconstruct(raw);
    if (!rec) {{
      lksym.innerHTML = '';
      lktxt.innerHTML = '<div style="color:var(--muted)">Type CoT non reconstructible ' +
        '(inconnu de la marshalling Delta Suite).</div>';
      return;
    }}
    s = rec.sidc; name = rec.name; src = 'type CoT';
  }} else {{
    // Entree = SIDC (tirets tolares, complete a 15 car.).
    s = (raw.toUpperCase() + '---------------').slice(0, 15);
    name = NAMEBYICON[s.slice(0, 3) + s.slice(4, 10)]; src = 'SIDC';
  }}
  let svg = '';
  if (HAS_MS) try {{ svg = new ms.Symbol(s, {{size: 60}}).asSVG(); }} catch (e) {{}}
  lksym.innerHTML = svg || '<span style="color:var(--muted)">non rendu</span>';
  lktxt.innerHTML =
    '<div><b>' + esc(name || 'Fonction hors catalogue') + '</b> ' +
      '<span style="color:var(--muted)">(' + src + ')</span></div>' +
    '<div>' + esc(SCHEMES[s[0]] || s[0]) + ' &middot; ' +
      esc(IDENT[s[1].toLowerCase()] || ('affiliation ' + s[1])) +
      ' &middot; dimension ' + esc(s[2]) + ' &middot; statut ' + esc(s[3]) + '</div>' +
    '<div class="mono">SIDC ' + esc(s) + ' &harr; type ' + esc(compact(s)) + '</div>';
}}

body.addEventListener('click', e => {{
  const td = e.target.closest('[data-copy]'); if (!td) return;
  navigator.clipboard && navigator.clipboard.writeText(td.dataset.copy);
  toast('Copie : ' + td.dataset.copy);
}});

// Filtres / tri / modificateurs -> retour page 1.
[q, faff, fsch, fdim].forEach(el => el.addEventListener('input', () => {{ page = 1; render(); }}));
[showsym, mstatus, msize, mmob].forEach(el => el.addEventListener('change', () => {{ page = 1; render(); }}));
sidcin.addEventListener('input', doLookup);
psize.addEventListener('change', () => {{ pageSize = +psize.value; page = 1; render(); }});
$('first').onclick = () => {{ page = 1; render(); }};
$('prev').onclick  = () => {{ page--; render(); }};
$('next').onclick  = () => {{ page++; render(); }};
$('last').onclick  = () => {{ page = 1e9; render(); }};
$('reset').onclick = () => {{
  q.value = ''; faff.value = ''; fsch.value = ''; fdim.value = '';
  mstatus.value = ''; msize.value = ''; mmob.value = ''; showsym.checked = true;
  sortCol = -1; sortDir = 1; page = 1; render();
}};
render();
</script>
</body>
</html>"""
    inject = ("<script>\n" + milsymbol_js + "\n</script>") if milsymbol_js else ""
    html_doc = html_doc.replace("<!--MILSYMBOL-->", inject)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Genere le catalogue CoT/2525 (HTML + CSV)")
    ap.add_argument("--tables", default=None,
                    help="dossier des CSV APP-6 (defaut : app6/marshalling a cote du script)")
    ap.add_argument("--identities", default="f,h,n,u", help="affiliations couvertes")
    ap.add_argument("--modifiers", action="store_true",
                    help="TOUTES les combinaisons (statut/taille/mobilite) — CSV conseille")
    ap.add_argument("--format", choices=["html", "csv", "both"], default="both")
    ap.add_argument("--out", default="catalogue-cot-2525",
                    help="prefixe des fichiers de sortie (defaut : catalogue-cot-2525)")
    ap.add_argument("--milsymbol", default=None,
                    help="chemin de milsymbol.js a embarquer (defaut : vendor/milsymbol.js)")
    ap.add_argument("--no-symbols", action="store_true",
                    help="ne pas embarquer milsymbol (HTML sans rendu d'icones)")
    args = ap.parse_args(argv)

    tables_dir = args.tables or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "app6", "marshalling")
    if not os.path.isdir(tables_dir):
        ap.error(f"dossier de tables introuvable : {tables_dir}")

    print("Construction du catalogue (rejeu de la marshalling APP-6)...", flush=True)
    tables = App6Tables(tables_dir)
    identities = [x.strip() for x in args.identities.split(",") if x.strip()]
    rows = build_rows(tables, identities, args.modifiers)
    scope = "toutes combinaisons" if args.modifiers else "icones de base"
    print(f"{len(rows)} entrees ({scope}).")

    outdir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(outdir, exist_ok=True)
    if args.format in ("csv", "both"):
        p = args.out + ".csv"
        write_csv(rows, p)
        print(f"CSV  : {os.path.abspath(p)}")
    if args.format in ("html", "both"):
        if args.modifiers and len(rows) > 100000:
            print("HTML ignore : trop de lignes en mode --modifiers (utilisez le CSV).")
        else:
            milsymbol_js = ""
            if not args.no_symbols:
                ms_path = args.milsymbol or os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "vendor", "milsymbol.js")
                if os.path.isfile(ms_path):
                    with open(ms_path, encoding="utf-8") as mf:
                        milsymbol_js = mf.read()
                else:
                    print(f"milsymbol introuvable ({ms_path}) — HTML sans icones. "
                          f"Telechargez-le dans vendor/ ou passez --milsymbol.")
            p = args.out + ".html"
            mod_opts = load_modifier_options(tables_dir)
            core_tpls = [[e, nm] for (e, nm, _bd) in tables.cores]
            write_html(rows, p, args.modifiers, milsymbol_js,
                       modifier_options=mod_opts, ident_names=tables.identity_name,
                       core_templates=core_tpls, identity_templates=tables.identity)
            print(f"HTML : {os.path.abspath(p)}"
                  + (" (avec symboles)" if milsymbol_js else " (sans symboles)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
