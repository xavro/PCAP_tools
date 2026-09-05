#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compare_tracker_versions.py — banc de comparaison v8 / v9 sur un CSV de plots GMTI.

Répond aux critères d'acceptation du brief (§6.2 et §6.3) et sert à mesurer l'apport de CHAQUE brique
v9 séparément (§7) : le tracker v9 expose quatre interrupteurs (`cluster_enabled`, `doppler_enabled`,
`observability_enabled`, `merge_enabled`) que ce banc active un par un.

    python compare_tracker_versions.py plots.csv --profile maritime --ladder -o rapport.md
    python compare_tracker_versions.py plots.csv --profile routier_zone --v8 --v9      # non-régression

RÉFÉRENCE DE CIBLE. Aucune vérité terrain n'accompagne les captures : on la reconstruit depuis les plots,
indépendamment des deux trackers, par une recherche de trajectoires RECTILIGNES (type Hough : couples de
plots séparés de 5 à 60 s, vote sur la vitesse, extraction gloutonne des plots à moins de `--tol` mètres
de la droite). Le mobile dominant — celui qui explique le plus de plots — sert de cible de référence.
Sur la capture maritime, il regroupe 150 des 185 plots à 13 km/h cap ~130° : c'est le cargo, dont la coque
de ~250 m produit plusieurs alignements parallèles que l'on fusionne (option `--hull`).

Les indicateurs suivent le brief : nombre de pistes confirmées simultanément près de la cible, nombre
d'identifiants distincts l'ayant portée, écart-type du cap et de la vitesse sur fenêtre glissante,
jitter position filtrée / position lissée, et durée de vie rapportée à la durée d'observation.
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------------
# Chargement des deux trackers (dossiers frères, mêmes noms de modules)
# ----------------------------------------------------------------------
def load_tracker(version):
    """Charge `prototype_tracker_gmti_v<version>/track_run.py` sous un nom de module distinct."""
    d = os.path.join(HERE, "prototype_tracker_gmti_v%s" % version)
    if not os.path.isdir(d):
        raise SystemExit("dossier introuvable : %s" % d)
    saved = list(sys.path)
    sys.path.insert(0, d)
    try:
        for mod in ("tracker", "track_run"):
            sys.modules.pop(mod, None)
        spec = importlib.util.spec_from_file_location("track_run_v%s" % version, os.path.join(d, "track_run.py"))
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path[:] = saved


# ----------------------------------------------------------------------
# Référence de cible reconstruite depuis les plots
# ----------------------------------------------------------------------
def read_plots(csv_path):
    import csv as _csv
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in _csv.DictReader(f, delimiter=";"):
            rows.append(r)
    lat0, lon0 = float(rows[0]["lat"]), float(rows[0]["lon"])
    kx, ky = 111320.0 * math.cos(math.radians(lat0)), 110540.0
    P = []
    for r in rows:
        t = float(r["dwell_time_ms"]) / 1000.0
        la, lo = float(r["lat"]), float(r["lon"])
        P.append((t, (lo - lon0) * kx, (la - lat0) * ky))
    P.sort()
    return np.array([p[0] for p in P]), np.array([p[1] for p in P]), np.array([p[2] for p in P]), (lat0, lon0, kx, ky)


def dominant_movers(t, X, Y, tol=120.0, vmax_mps=15.0, min_plots=6, n_max=6):
    """Trajectoires rectilignes expliquant les plots, de la plus fournie à la moins fournie."""
    n = len(t)
    used = np.zeros(n, bool)
    out = []
    for _ in range(n_max):
        free = np.where(~used)[0]
        if len(free) < min_plots:
            break
        best = None
        for a in range(len(free)):
            i = free[a]
            for b in range(a + 1, len(free)):
                j = free[b]
                dt = t[j] - t[i]
                if not (5.0 < dt < 60.0):
                    continue
                vx, vy = (X[j] - X[i]) / dt, (Y[j] - Y[i]) / dt
                if math.hypot(vx, vy) > vmax_mps:
                    continue
                d = np.hypot(X[free] - (X[i] + vx * (t[free] - t[i])),
                             Y[free] - (Y[i] + vy * (t[free] - t[i])))
                inl = free[d < tol]
                if best is None or len(inl) > len(best[0]):
                    best = (inl, vx, vy)
        if best is None or len(best[0]) < min_plots:
            break
        inl, vx, vy = best
        used[inl] = True
        out.append({"idx": inl, "n": len(inl), "t0": float(t[inl].min()), "t1": float(t[inl].max()),
                    "vx": float(vx), "vy": float(vy),
                    "speed_kmh": 3.6 * math.hypot(vx, vy),
                    "heading_deg": (math.degrees(math.atan2(vx, vy)) + 360) % 360})
    return out


def hull_reference(movers, t, X, Y, hull_dv_kmh=8.0, hull_dhdg_deg=45.0):
    """Fusionne les alignements parallèles d'une même coque (cible étendue) en UNE référence.

    Un navire de 250 m produit plusieurs droites parallèles distantes de sa longueur : les garder
    séparées ferait croire à plusieurs cibles. On agrège au mobile dominant ceux qui vont dans le même
    sens, à la même vitesse, et on ajuste une droite unique sur l'union des plots."""
    if not movers:
        return None
    base = movers[0]
    idx = list(base["idx"])
    for m in movers[1:]:
        if (abs(m["speed_kmh"] - base["speed_kmh"]) <= hull_dv_kmh
                and abs((m["heading_deg"] - base["heading_deg"] + 180) % 360 - 180) <= hull_dhdg_deg):
            idx += list(m["idx"])
    idx = np.array(sorted(set(idx)))
    A = np.c_[np.ones(len(idx)), t[idx] - t[idx].mean()]
    cx = np.linalg.lstsq(A, X[idx], rcond=None)[0]
    cy = np.linalg.lstsq(A, Y[idx], rcond=None)[0]
    res = float(np.sqrt(((X[idx] - A @ cx) ** 2 + (Y[idx] - A @ cy) ** 2).mean()))
    return {"idx": idx, "n": len(idx), "t0": float(t[idx].min()), "t1": float(t[idx].max()),
            "tm": float(t[idx].mean()), "x0": float(cx[0]), "y0": float(cy[0]),
            "vx": float(cx[1]), "vy": float(cy[1]), "residual_m": res,
            "speed_kmh": 3.6 * math.hypot(cx[1], cy[1]),
            "heading_deg": (math.degrees(math.atan2(cx[1], cy[1])) + 360) % 360}


def ref_pos(ref, t):
    return ref["x0"] + ref["vx"] * (t - ref["tm"]), ref["y0"] + ref["vy"] * (t - ref["tm"])


# ----------------------------------------------------------------------
# Indicateurs (brief §6.2)
# ----------------------------------------------------------------------
def track_states(res, track_id):
    """Suite (t, x, y, vx, vy) de l'état FILTRÉ d'une piste. v8 et v9 exposent tous deux leurs objets
    `Track` (`res["_objs"]`), dont `states` = [(t, [px, py, vx, vy], P)] : on mesure donc la même
    chose des deux côtés, et non un cap recalculé par différences de positions (qui mesurerait surtout
    le bruit de mesure)."""
    tr = (res.get("_objs") or {}).get(track_id)
    if tr is None or not getattr(tr, "states", None):
        return []
    return [(float(t), float(x[0]), float(x[1]), float(x[2]), float(x[3])) for (t, x, _P) in tr.states]


def evaluate(res, ref, near_m=500.0, window_s=60.0):
    """Confronte un résultat de tracker à la cible de référence (brief §6.2)."""
    tracks = res["tracks"]
    out = {"n_tracks": len(tracks)}
    if ref is None or not tracks:
        return out

    # Pistes passant près de la cible : on utilise l'état filtré, daté dwell par dwell.
    near = {}
    for tk in tracks:
        st = track_states(res, tk["id"])
        keep = [(t, x, y, vx, vy) for (t, x, y, vx, vy) in st
                if ref["t0"] - 1 <= t <= ref["t1"] + 1
                and math.hypot(x - ref_pos(ref, t)[0], y - ref_pos(ref, t)[1]) <= near_m]
        if keep:
            near[tk["id"]] = keep
    out["ids_on_target"] = len(near)

    grid = np.arange(ref["t0"], ref["t1"], 1.0)
    counts = []
    for tt in grid:
        counts.append(sum(1 for pts in near.values() if any(abs(p[0] - tt) < 1.5 for p in pts)))
    out["simultaneous_max"] = int(max(counts)) if counts else 0
    out["simultaneous_median"] = float(np.median(counts)) if counts else 0.0

    if not near:
        return out
    main_id = max(near, key=lambda k: near[k][-1][0] - near[k][0][0])
    pts = sorted(near[main_id])
    main = next(tk for tk in tracks if tk["id"] == main_id)
    out["main_id"] = main_id
    out["main_hits"] = main["hits"]
    out["coverage"] = (pts[-1][0] - pts[0][0]) / max(ref["t1"] - ref["t0"], 1e-6)

    t_arr = np.array([p[0] for p in pts])
    hd = np.array([(math.degrees(math.atan2(p[3], p[4])) + 360) % 360 for p in pts])
    sp = np.array([3.6 * math.hypot(p[3], p[4]) for p in pts])
    # Écart-type sur fenêtre glissante de `window_s` : c'est la stabilité vue par l'opérateur, pas la
    # dispersion sur toute la mission (une cible qui vire lentement ne doit pas être pénalisée).
    hstd, sstd = [], []
    for i, tt in enumerate(t_arr):
        m = np.abs(t_arr - tt) <= window_s / 2
        if m.sum() >= 5:
            hstd.append(_circular_std(hd[m]))
            sstd.append(float(np.std(sp[m])))
    if hstd:
        out["heading_std_deg"] = float(np.median(hstd))
        out["speed_std_kmh"] = float(np.median(sstd))
    out["speed_mean_kmh"] = float(np.median(sp))
    out["heading_err_deg"] = float(abs((_circular_mean(hd) - ref["heading_deg"] + 180) % 360 - 180))
    out["speed_err_kmh"] = float(abs(np.median(sp) - ref["speed_kmh"]))

    # Jitter : écart entre position filtrée (affichée) et position lissée RTS (référence non causale).
    sm = main.get("smooth") or []
    if len(sm) >= 3 and len(main["pts"]) >= 3:
        k = min(len(sm), len(main["pts"]))
        d = [math.hypot(main["pts"][i][0] - sm[i][0], main["pts"][i][1] - sm[i][1]) for i in range(k)]
        out["jitter_m"] = float(np.std(d))

    err = [math.hypot(x - ref_pos(ref, t)[0], y - ref_pos(ref, t)[1]) for (t, x, y, _vx, _vy) in pts]
    out["pos_err_mean_m"] = float(np.mean(err))

    # Étage « contact » : c'est lui que voit l'opérateur. Un contact qui couvre toute la fenêtre avec un
    # identifiant unique vaut mieux que trois pistes internes, tant que le filtre reste stable.
    cts, cts_t = res.get("contacts"), res.get("contacts_t")
    if cts and cts_t:
        spans = []
        for c in cts:
            ts = cts_t.get(c["id"]) or []
            hit = [tt for tt, (x, y) in zip(ts, c["pts"])
                   if ref["t0"] - 1 <= tt <= ref["t1"] + 1
                   and math.hypot(x - ref_pos(ref, tt)[0], y - ref_pos(ref, tt)[1]) <= near_m]
            if hit:
                spans.append((max(hit) - min(hit)) / max(ref["t1"] - ref["t0"], 1e-6))
        out["contacts_on_target"] = len(spans)
        out["contact_coverage"] = max(spans) if spans else 0.0
    return out


def _circular_mean(deg):
    a = np.radians(np.asarray(deg, dtype=float))
    return (math.degrees(math.atan2(np.mean(np.sin(a)), np.mean(np.cos(a)))) + 360) % 360


def _circular_std(deg):
    a = np.radians(deg)
    return math.degrees(math.sqrt(max(-2.0 * math.log(max(abs(np.mean(np.exp(1j * a))), 1e-9)), 0.0)))


# ----------------------------------------------------------------------
# Rapport
# ----------------------------------------------------------------------
LADDER = [
    ("v9 — aucune brique (position seule)", dict(cluster_enabled=False, doppler_enabled=False,
                                                 observability_enabled=False, merge_enabled=False)),
    ("v9 + clustering", dict(cluster_enabled=True, doppler_enabled=False,
                             observability_enabled=False, merge_enabled=False)),
    ("v9 + clustering + EKF Doppler", dict(cluster_enabled=True, doppler_enabled=True,
                                           observability_enabled=False, merge_enabled=False)),
    ("v9 + ... + observabilité", dict(cluster_enabled=True, doppler_enabled=True,
                                      observability_enabled=True, merge_enabled=False)),
    ("v9 complet (+ fusion)", dict(cluster_enabled=True, doppler_enabled=True,
                                   observability_enabled=True, merge_enabled=True)),
]

COLS = [("n_tracks", "pistes", "%d"), ("ids_on_target", "ID sur cible", "%d"),
        ("contacts_on_target", "contacts", "%d"), ("contact_coverage", "couv. contact", "%.0f %%"),
        ("simultaneous_max", "simult. max", "%d"), ("coverage", "couverture", "%.0f %%"),
        ("heading_std_deg", "σ cap", "%.1f°"), ("speed_std_kmh", "σ vitesse", "%.1f km/h"),
        ("jitter_m", "jitter", "%.0f m"), ("pos_err_mean_m", "écart réf.", "%.0f m"),
        ("speed_mean_kmh", "vitesse", "%.1f km/h"), ("heading_err_deg", "erreur cap", "%.1f°")]


def fmt_row(label, ev):
    cells = []
    for key, _title, f in COLS:
        v = ev.get(key)
        if v is None:
            cells.append("—")
        elif key in ("coverage", "contact_coverage"):
            cells.append(f % (100.0 * v))
        else:
            cells.append(f % v)
    return "| %s | %s |" % (label, " | ".join(cells))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Comparaison des trackers GMTI v8 / v9 sur un CSV de plots.")
    ap.add_argument("csv")
    ap.add_argument("--profile", default="maritime")
    ap.add_argument("--ladder", action="store_true", help="activer les briques v9 une par une (brief §7)")
    ap.add_argument("--tol", type=float, default=120.0, help="tolérance d'alignement de la référence (m)")
    ap.add_argument("--near", type=float, default=500.0, help="distance « sur la cible » (m)")
    ap.add_argument("--overrides", default="", help="surcharges v9, ex. sigma_vr_floor_mps=4,gate_max_m=500")
    ap.add_argument("--no-ref", action="store_true", help="pas de cible de référence (non-régression volumétrique)")
    ap.add_argument("--ref-max-plots", type=int, default=2000,
                    help="au-delà, la recherche de référence (quadratique) est sautée")
    ap.add_argument("-o", "--out", help="fichier Markdown de sortie")
    a = ap.parse_args(argv)

    t, X, Y, _frame = read_plots(a.csv)
    # La recherche de référence est quadratique : sur une capture routière de 11 000 plots elle n'a de
    # toute façon pas de sens (des centaines de mobiles), on la saute et le rapport devient volumétrique.
    if a.no_ref or len(t) > a.ref_max_plots:
        movers, ref = [], None
    else:
        movers = dominant_movers(t, X, Y, tol=a.tol)
        ref = hull_reference(movers, t, X, Y)

    lines = ["# Comparaison tracker GMTI v8 / v9", "",
             "Capture : `%s` — %d plots, %.0f s." % (os.path.basename(a.csv), len(t), t.max() - t.min()),
             "Profil : `%s`." % a.profile, ""]
    lines += ["## Cible de référence (reconstruite depuis les plots, sans tracker)", ""]
    if ref:
        lines += ["Mobile dominant : **%d plots** sur %d, de %.0f s à %.0f s, **%.1f km/h cap %.1f°**, "
                  "résidu d'alignement %.0f m." % (ref["n"], len(t), ref["t0"] - t.min(), ref["t1"] - t.min(),
                                                   ref["speed_kmh"], ref["heading_deg"], ref["residual_m"]), ""]
        lines += ["Alignements détectés (avant fusion de coque) :", ""]
        for i, m in enumerate(movers, 1):
            lines.append("- %d : %d plots, %.1f km/h, cap %.1f°" % (i, m["n"], m["speed_kmh"], m["heading_deg"]))
        lines.append("")
    else:
        lines += ["Aucun mobile rectiligne dominant — indicateurs « sur cible » indisponibles.", ""]

    over = {}
    for kv in filter(None, a.overrides.split(",")):
        k, _, v = kv.partition("=")
        over[k.strip()] = float(v) if v.replace(".", "", 1).replace("-", "", 1).isdigit() else v

    rows = []
    v8 = load_tracker("8.1")
    r8 = v8.run_tracking(a.csv, a.profile if a.profile in v8.PROFILES else "defaut")
    rows.append(("v8.1 (référence)", evaluate(r8, ref, a.near), r8))

    v9 = load_tracker("9")
    runs = LADDER if a.ladder else [("v9 complet", {})]
    for label, switches in runs:
        r9 = v9.run_tracking(a.csv, a.profile if a.profile in v9.PROFILES else "defaut", {**switches, **over})
        rows.append((label, evaluate(r9, ref, a.near), r9))

    lines += ["## Indicateurs", "",
              "| variante | %s |" % " | ".join(c[1] for c in COLS),
              "|%s" % ("---|" * (len(COLS) + 1))]
    for label, ev, _res in rows:
        lines.append(fmt_row(label, ev))
    lines += ["", "Cibles du brief (§6.2) : 1 seule piste simultanée sur la cible, 1 seul identifiant, "
                  "σ cap < 5°, σ vitesse < 2 km/h, jitter < 40 m, couverture > 90 %.", ""]

    lines += ["## Détail par variante", ""]
    for label, ev, res in rows:
        m = res["metrics"]
        lines.append("**%s** — %d pistes confirmées, %d rejetées, %d dwells, %d plots."
                     % (label, m["n_tracks"], m["n_rejected"], m.get("n_dwells", 0), m["n_plots"]))
        extra = [k for k in ("n_clustered", "n_obs_miss", "n_unobservable", "n_merged") if k in m]
        if extra:
            lines.append("  Briques : %s." % ", ".join("%s = %s" % (k, m[k]) for k in extra))
        top = sorted(res["tracks"], key=lambda x: -x["hits"])[:5]
        for tk in top:
            lines.append("  - piste %d : %d hits, %.0f s, %.1f km/h, cap %.1f°%s"
                         % (tk["id"], tk["hits"], tk["t1"] - tk["t0"], math.hypot(*tk["vel"]) * 3.6,
                            (math.degrees(math.atan2(tk["vel"][0], tk["vel"][1])) + 360) % 360,
                            (" ± %.1f" % tk["heading_std_deg"]) if "heading_std_deg" in tk else ""))
        lines.append("")

    report = "\n".join(lines)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print("rapport écrit : %s" % a.out)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
