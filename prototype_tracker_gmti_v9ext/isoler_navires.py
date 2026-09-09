#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
isoler_navires.py — extraire des cas de navires exploitables d'une mission longue.

Une mission de plusieurs heures ne se juge pas d'un bloc : la référence de trajectoire du banc de
comparaison est quadratique et ne veut rien dire sur une scène à plusieurs centaines de mobiles. Il faut
d'abord découper des cas propres — un navire, sa fenêtre de temps, et le fouillis qui l'entoure.

    python isoler_navires.py m1_*.csv -o cas/
    python ../compare_tracker_versions.py cas/navire_01.csv --profile maritime --ext

Méthode, sans tracker : sur des fenêtres glissantes courtes on cherche les trajectoires RECTILIGNES
(même recherche de type Hough que le banc), on ne garde que celles dont la vitesse est celle d'un navire,
puis on recoud les fenêtres consécutives qui décrivent le même mobile. Utiliser un tracker pour préparer
l'évaluation d'un tracker reviendrait à lui faire noter sa propre copie.

Le CSV exporté contient TOUT le tube spatio-temporel autour du navire, pas seulement les plots alignés :
le tracker doit voir le fouillis, sinon la comparaison est faussée en sa faveur.
"""
import argparse
import csv
import glob
import math
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import compare_tracker_versions as C  # noqa: E402


def charger(motifs):
    lignes = []
    for motif in motifs:
        for f in sorted(glob.glob(motif)):
            with open(f, newline="", encoding="utf-8") as fh:
                lignes += list(csv.DictReader(fh, delimiter=";"))
    if not lignes:
        raise SystemExit("aucun plot lu : vérifier les fichiers passés en argument")
    lignes.sort(key=lambda r: float(r["dwell_time_ms"]))
    lat0, lon0 = float(lignes[0]["lat"]), float(lignes[0]["lon"])
    kx, ky = 111320.0 * math.cos(math.radians(lat0)), 110540.0
    t = np.array([float(r["dwell_time_ms"]) / 1000.0 for r in lignes])
    X = np.array([(float(r["lon"]) - lon0) * kx for r in lignes])
    Y = np.array([(float(r["lat"]) - lat0) * ky for r in lignes])
    return lignes, t, X, Y


def candidats(t, X, Y, a):
    """Segments rectilignes à vitesse de navire, sur fenêtres glissantes à recouvrement de moitié."""
    out = []
    t0, k = t.min(), 0
    while t0 + k * a.pas < t.max():
        d, f = t0 + k * a.pas, t0 + k * a.pas + a.fenetre
        k += 1
        sel = np.where((t >= d) & (t < f))[0]
        # Trop peu de plots : rien à voir. Trop : zone dense, ce n'est pas un navire isolé et la
        # recherche quadratique y coûterait cher pour rien.
        if not (a.min_plots <= len(sel) <= a.max_plots):
            continue
        for m in C.dominant_movers(t[sel], X[sel], Y[sel], tol=a.tol, vmax_mps=a.vmax / 3.6,
                                   min_plots=a.min_plots, n_max=3):
            if not (a.vmin <= m["speed_kmh"] <= a.vmax):
                continue
            idx = sel[m["idx"]]
            out.append({"idx": set(idx.tolist()), "t0": float(t[idx].min()), "t1": float(t[idx].max()),
                        "n": len(idx), "v": m["speed_kmh"], "cap": m["heading_deg"],
                        "x": float(X[idx].mean()), "y": float(Y[idx].mean())})
    return out


def recoudre(cands):
    """Deux segments consécutifs allant au même endroit à la même vitesse sont le même navire."""
    cands.sort(key=lambda c: c["t0"])
    pistes = []
    for c in cands:
        for p in pistes:
            if (c["t0"] - p["t1"] < 300
                    and abs(c["v"] - p["v"]) < 8
                    and abs((c["cap"] - p["cap"] + 180) % 360 - 180) < 40
                    and math.hypot(c["x"] - p["x"], c["y"] - p["y"]) < 6000):
                p["idx"] |= c["idx"]
                p["t1"] = max(p["t1"], c["t1"])
                p["x"], p["y"] = c["x"], c["y"]
                p["v"] = 0.5 * (p["v"] + c["v"])
                p["n"] = len(p["idx"])
                break
        else:
            pistes.append(dict(c))
    return pistes


def main(argv=None):
    ap = argparse.ArgumentParser(description="Isoler des cas de navires dans une mission longue.")
    ap.add_argument("csv", nargs="+", help="CSV de plots (motifs acceptés)")
    ap.add_argument("-o", "--out", default="cas", help="dossier de sortie")
    ap.add_argument("--fenetre", type=float, default=400.0, help="durée d'une fenêtre d'analyse (s)")
    ap.add_argument("--pas", type=float, default=200.0, help="décalage entre fenêtres (s)")
    ap.add_argument("--vmin", type=float, default=3.0, help="vitesse minimale retenue (km/h)")
    ap.add_argument("--vmax", type=float, default=40.0, help="vitesse maximale retenue (km/h)")
    ap.add_argument("--tol", type=float, default=120.0, help="tolérance d'alignement (m)")
    ap.add_argument("--tube", type=float, default=1500.0, help="rayon du tube exporté (m)")
    ap.add_argument("--duree-min", type=float, default=240.0, help="durée minimale d'un cas (s)")
    ap.add_argument("--min-plots", type=int, default=12)
    ap.add_argument("--max-plots", type=int, default=1200)
    ap.add_argument("-n", "--nombre", type=int, default=8, help="nombre de cas exportés")
    a = ap.parse_args(argv)

    lignes, t, X, Y = charger(a.csv)
    print("%d plots, %.1f h" % (len(t), (t.max() - t.min()) / 3600))
    pistes = [p for p in recoudre(candidats(t, X, Y, a))
              if p["t1"] - p["t0"] >= a.duree_min and p["n"] >= 25]
    pistes.sort(key=lambda p: -(p["t1"] - p["t0"]))
    print("%d navires candidats" % len(pistes))

    os.makedirs(a.out, exist_ok=True)
    entete = list(lignes[0].keys())
    for i, p in enumerate(pistes[:a.nombre], 1):
        idx = np.array(sorted(p["idx"]))
        A = np.c_[np.ones(len(idx)), t[idx] - t[idx].mean()]
        cx = np.linalg.lstsq(A, X[idx], rcond=None)[0]
        cy = np.linalg.lstsq(A, Y[idx], rcond=None)[0]
        tm = t[idx].mean()
        proche = (np.hypot(X - (cx[0] + cx[1] * (t - tm)), Y - (cy[0] + cy[1] * (t - tm))) < a.tube)
        garde = np.where((t >= p["t0"] - 30) & (t <= p["t1"] + 30) & proche)[0]
        chemin = os.path.join(a.out, "navire_%02d.csv" % i)
        with open(chemin, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, entete, delimiter=";")
            w.writeheader()
            for j in garde:
                w.writerow(lignes[j])
        la = float(np.mean([float(lignes[j]["lat"]) for j in idx]))
        lo = float(np.mean([float(lignes[j]["lon"]) for j in idx]))
        # La revisite réelle conditionne tout le réglage : on l'annonce avec le cas.
        tr = np.unique(np.round(t[idx], 3))
        ecarts = np.diff(tr)
        print("  navire_%02d.csv : %5.1f min, %4d plots (%3d sur la droite), %5.1f km/h cap %5.1f°, "
              "%.3f N %.3f E, détections toutes les %.1f s (90e centile %.1f s)"
              % (i, (p["t1"] - p["t0"]) / 60, len(garde), len(idx), p["v"], p["cap"], la, lo,
                 np.median(ecarts) if len(ecarts) else float("nan"),
                 np.percentile(ecarts, 90) if len(ecarts) else float("nan")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
