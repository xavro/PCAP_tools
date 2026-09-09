#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cas_verifies.py — decouper des cas d'evaluation dont la reference est VERIFIEE.

Le probleme mis au jour : sur 5 a 16 minutes, un navire ou un vehicule ne suit pas une droite a vitesse
constante. Ajuster une droite sur une telle duree produit une « reference » que ni les positions ni la
vitesse radiale ne confirment (residus 141 a 431 m, desaccord de 8 a 80 km/h entre les deux canaux).
Toute comparaison de trackers fondee la-dessus mesure surtout le bruit de la reference.

Sur 90 secondes en revanche, l'hypothese rectiligne redevient raisonnable. On garde donc uniquement les
fenetres ou UN meme mouvement rectiligne explique LES DEUX canaux, physiquement independants :
positions a moins de `--res-pos` metres, vitesse radiale a moins de `--res-vr` m/s. Un cas qui passe ce
double test est une vraie cible unique ; les autres ne servent a rien et sont ecartes.

    python cas_verifies.py plots_*.csv -o cas/ --vmax 40          # maritime
    python cas_verifies.py plots_*.csv -o cas/ --vmin 10 --tol 80 # routier
"""
import argparse
import csv as _csv
import glob
import math
import os
import sys

import numpy as np

TOOLS = r"C:\Users\xavco\Documents\Mes Projets\DATA\Tools"
sys.path.insert(0, TOOLS)
import compare_tracker_versions as C  # noqa: E402

SIG_POS, SIG_VR = 100.0, 1.0


def charger(motifs):
    lignes = []
    for m in motifs:
        for f in sorted(glob.glob(m)):
            with open(f, newline="", encoding="utf-8") as fh:
                lignes += list(_csv.DictReader(fh, delimiter=";"))
    lignes.sort(key=lambda r: float(r["dwell_time_ms"]))
    lat0, lon0 = float(lignes[0]["lat"]), float(lignes[0]["lon"])
    kx, ky = 111320.0 * math.cos(math.radians(lat0)), 110540.0
    t = np.array([float(r["dwell_time_ms"]) / 1000.0 for r in lignes])
    X = np.array([(float(r["lon"]) - lon0) * kx for r in lignes])
    Y = np.array([(float(r["lat"]) - lat0) * ky for r in lignes])
    S = np.array([[(float(r["sensor_lon"]) - lon0) * kx, (float(r["sensor_lat"]) - lat0) * ky] for r in lignes])
    V = np.array([float(r["vel_los_cms"] or 0) / 100.0 for r in lignes])
    return lignes, t, X, Y, S, V


def ajuste(idx, t, X, Y, S, V):
    """Mouvement rectiligne uniforme ajuste sur les deux canaux. Renvoie (solution, res_pos, res_vr)."""
    tm = float(np.mean(t[idx]))
    A, b, U, vr = [], [], [], []
    for k in idx:
        dx, dy = X[k] - S[k][0], Y[k] - S[k][1]
        rho = math.hypot(dx, dy)
        if rho < 1:
            continue
        dt = t[k] - tm
        A.append([1, 0, dt, 0]); b.append(X[k])
        A.append([0, 1, 0, dt]); b.append(Y[k])
        U.append([dx / rho, dy / rho]); vr.append(V[k])
    if len(U) < 8:
        return None
    A, b = np.array(A, float), np.array(b, float)
    Ad, vr = np.c_[np.zeros((len(U), 2)), np.array(U, float)], np.array(vr, float)
    M = np.vstack([A / SIG_POS, Ad / SIG_VR])
    y = np.concatenate([b / SIG_POS, vr / SIG_VR])
    sol = np.linalg.lstsq(M, y, rcond=None)[0]
    return (sol, tm, float(np.sqrt(np.mean((A @ sol - b) ** 2))),
            float(np.sqrt(np.mean((Ad @ sol - vr) ** 2))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("-o", "--out", default="solides")
    ap.add_argument("--fenetre", type=float, default=90.0)
    ap.add_argument("--pas", type=float, default=45.0)
    ap.add_argument("--vmin", type=float, default=3.0)
    ap.add_argument("--vmax", type=float, default=130.0)
    ap.add_argument("--tol", type=float, default=100.0)
    ap.add_argument("--res-pos", type=float, default=120.0)
    ap.add_argument("--res-vr", type=float, default=3.0)
    ap.add_argument("--min-plots", type=int, default=12)
    ap.add_argument("--tube", type=float, default=700.0)
    a = ap.parse_args()

    lignes, t, X, Y, S, V = charger(a.csv)
    print("%d plots, %.1f h" % (len(t), (t.max() - t.min()) / 3600))
    os.makedirs(a.out, exist_ok=True)
    entete = list(lignes[0].keys())
    n_test = n_ok = 0
    t0, k = t.min(), 0
    fiches = []
    while t0 + k * a.pas < t.max():
        d, f = t0 + k * a.pas, t0 + k * a.pas + a.fenetre
        k += 1
        sel = np.where((t >= d) & (t < f))[0]
        if not (a.min_plots <= len(sel) <= 900):
            continue
        for m in C.dominant_movers(t[sel], X[sel], Y[sel], tol=a.tol, vmax_mps=a.vmax / 3.6,
                                   min_plots=a.min_plots, n_max=3):
            if not (a.vmin <= m["speed_kmh"] <= a.vmax):
                continue
            idx = sel[m["idx"]]
            n_test += 1
            r = ajuste(idx, t, X, Y, S, V)
            if r is None:
                continue
            sol, tm, rp, rv = r
            if rp > a.res_pos or rv > a.res_vr:
                continue
            n_ok += 1
            # Tube : tous les plots autour de la trajectoire ajustee, fouillis compris.
            px = sol[0] + sol[2] * (t - tm)
            py = sol[1] + sol[3] * (t - tm)
            garde = np.where((t >= t[idx].min() - 10) & (t <= t[idx].max() + 10)
                             & (np.hypot(X - px, Y - py) < a.tube))[0]
            nom = "cas_%03d.csv" % n_ok
            with open(os.path.join(a.out, nom), "w", newline="", encoding="utf-8") as fh:
                w = _csv.DictWriter(fh, entete, delimiter=";")
                w.writeheader()
                for j in garde:
                    w.writerow(lignes[j])
            tr = np.unique(np.round(t[idx], 3))
            ec = np.diff(tr)
            fiches.append((nom, len(garde), len(idx), 3.6 * math.hypot(sol[2], sol[3]),
                           (math.degrees(math.atan2(sol[2], sol[3])) + 360) % 360, rp, rv,
                           float(np.median(ec)) if len(ec) else float("nan")))
    print("%d fenetres candidates testees, %d retenues (les deux canaux d'accord)" % (n_test, n_ok))
    print("%-12s %6s %6s %9s %7s %8s %9s %9s" % ("cas", "plots", "sur ref", "vitesse", "cap", "res pos", "res v_LOS", "cadence"))
    for x in fiches:
        print("%-12s %6d %6d %6.1f km/h %6.1f° %6.0f m %7.2f m/s %7.1f s" % x)
    if fiches:
        print("\ncadence mediane des cas retenus : %.1f s" % np.median([x[7] for x in fiches]))


if __name__ == "__main__":
    main()
