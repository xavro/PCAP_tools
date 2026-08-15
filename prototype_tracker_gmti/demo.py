# -*- coding: utf-8 -*-
"""
Demo du tracker sur donnees synthetiques + lecteur du CSV exporte par GeoEvent.

  python3 demo.py                    -> scenario simule (3 cibles + fausses alarmes)
  python3 demo.py plots_geoevent.csv -> vos plots reels

Format CSV attendu (une ligne par plot, delimiteur ';') :
  dwell_time_ms;revisit_idx;dwell_idx;lat;lon;vel_los_cms;snr_db;classification;
  sig_range_cm;sig_xrange_dm;sig_rvel_cms;sensor_lat;sensor_lon
Les colonnes d'incertitude/capteur sont optionnelles (defauts appliques).
"""
import csv
import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from tracker import Tracker, Plot, Params, LocalFrame, covariance_from_4607


# ----------------------------------------------------------------------
# 1) Scenario synthetique : 3 cibles manoeuvrantes + clutter
# ----------------------------------------------------------------------
def synthetic_dwells(n_revisits=40, revisit_s=10.0, fa_per_dwell=6, seed=42):
    rng = np.random.default_rng(seed)
    targets = [
        dict(p=np.array([-3000., -2000.]), v=np.array([14., 6.])),    # ~54 km/h
        dict(p=np.array([2500., -3500.]),  v=np.array([-8., 12.])),
        dict(p=np.array([-1000., 3000.]),  v=np.array([10., -10.])),
    ]
    sigma = 35.0                                   # bruit de mesure (m)
    for k in range(n_revisits):
        t = k * revisit_s
        plots = []
        for tg in targets:
            tg["p"] = tg["p"] + tg["v"] * revisit_s
            if k == 20:                            # manoeuvre a mi-parcours
                tg["v"] = tg["v"] @ np.array([[0, -1], [1, 0]])
            if rng.random() < 0.9:                 # Pd = 0.9 (trous MDV simules)
                m = tg["p"] + rng.normal(0, sigma, 2)
                plots.append(Plot(m[0], m[1], r_pos=sigma))
        for _ in range(rng.poisson(fa_per_dwell)):  # fausses alarmes uniformes
            fa = rng.uniform(-6000, 6000, 2)
            plots.append(Plot(fa[0], fa[1], r_pos=sigma))
        yield t, plots


# ----------------------------------------------------------------------
# 2) Lecture du CSV GeoEvent, groupe par dwell, conversion plan local
# ----------------------------------------------------------------------
def csv_dwells(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f, delimiter=";"):
            rows.append(r)
    if not rows:
        raise SystemExit("CSV vide")
    frame = LocalFrame(float(rows[0]["lat"]), float(rows[0]["lon"]))

    def fget(r, key, default):
        v = r.get(key, "")
        return float(v) if v not in ("", None) else default

    from collections import defaultdict
    dwells = defaultdict(list)
    for r in rows:
        key = (int(r["revisit_idx"]), int(r["dwell_idx"]))
        dwells[key].append(r)

    for key in sorted(dwells, key=lambda k: min(int(r["dwell_time_ms"]) for r in dwells[k])):
        grp = dwells[key]
        t = min(int(r["dwell_time_ms"]) for r in grp) / 1000.0
        plots = []
        for r in grp:
            x, y = frame.to_xy(float(r["lat"]), float(r["lon"]))
            sig_r = fget(r, "sig_range_cm", Params.R_POS_DEFAULT * 100) / 100.0
            sig_x = fget(r, "sig_xrange_dm", Params.R_POS_DEFAULT * 10) / 10.0
            R = None
            if "sensor_lat" in r and r["sensor_lat"]:
                sx, sy = frame.to_xy(float(r["sensor_lat"]), float(r["sensor_lon"]))
                R = covariance_from_4607((sx, sy), (x, y), sig_r, sig_x)
            plots.append(Plot(x, y, r_pos=max(sig_r, sig_x), R=R,
                              vel_los=fget(r, "vel_los_cms", 0) / 100.0,
                              snr=fget(r, "snr_db", None),
                              classification=r.get("classification")))
        yield t, plots


# ----------------------------------------------------------------------
# 3) Boucle + rendu
# ----------------------------------------------------------------------
def run(source, png="tracker_result.png", csv_out="tracks_out.csv"):
    tk = Tracker()
    raw = []
    for t, plots in source:
        raw += [(p.x, p.y) for p in plots]
        tk.step(t, plots)

    all_tracks = tk.archive + tk.tracks
    kept = [tr for tr in all_tracks if tr.confirmed_ever]

    # --- Export trajets (track_id, t, x, y, etat) ---
    with open(csv_out, "w", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["track_id", "t_s", "x_m", "y_m", "etat"])
        for tr in kept:
            for (t, x, y, st) in tr.history:
                w.writerow([tr.id, f"{t:.1f}", f"{x:.1f}", f"{y:.1f}", st])

    # --- Figure : plots bruts vs pistes correlees ---
    fig, ax = plt.subplots(figsize=(9, 9))
    rx, ry = zip(*raw) if raw else ([], [])
    ax.scatter(rx, ry, s=6, c="#B8BEC6", label=f"Plots bruts ({len(raw)})")
    cmap = plt.cm.tab10
    for i, tr in enumerate(kept):
        xs = [h[1] for h in tr.history]
        ys = [h[2] for h in tr.history]
        ax.plot(xs, ys, "-", lw=1.8, c=cmap(i % 10),
                label=f"Piste #{tr.id} ({tr.hits} hits)")
        ax.plot(xs[-1], ys[-1], "o", ms=7, c=cmap(i % 10))
    ax.set_title("Tracker GMTI — plots MTI vs pistes correlees (ID persistants)")
    ax.set_xlabel("Est (m)"); ax.set_ylabel("Nord (m)")
    ax.legend(loc="best", fontsize=8); ax.set_aspect("equal"); ax.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(png, dpi=140)

    n_fa_tracks = sum(1 for tr in all_tracks if not tr.confirmed_ever)
    print(f"Pistes retenues : {len(kept)}  |  ebauches rejetees (bruit) : {n_fa_tracks}")
    print(f"-> {png}  |  -> {csv_out}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(csv_dwells(sys.argv[1]))
    else:
        run(synthetic_dwells())
