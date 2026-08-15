# -*- coding: utf-8 -*-
"""
Demo du tracker sur donnees synthetiques + lecteur du CSV exporte par GeoEvent.

  python3 demo.py                             -> scenario simule
  python3 demo.py plots_geoevent.csv          -> plots reels, profil par defaut (terrestre)
  python3 demo.py plots_geoevent.csv maritime -> plots reels, profil maritime

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

from tracker import Tracker, Plot, Params, LocalFrame, covariance_from_4607, rts_smooth
from track_run import PROFILES, apply_profile   # source unique des profils de tuning


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
            for (t, x, y, st, hit) in tr.trajectory():
                w.writerow([tr.id, f"{t:.1f}", f"{x:.1f}", f"{y:.1f}", st])
    # trajet lisse RTS (produit debriefing, non causal)
    with open(csv_out.replace(".csv", "_lisse.csv"), "w", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["track_id", "t_s", "x_m", "y_m"])
        for tr in kept:
            for (t, x, y) in rts_smooth(tr):
                w.writerow([tr.id, f"{t:.1f}", f"{x:.1f}", f"{y:.1f}"])

    # --- Figure : temps reel filtre + trajet lisse RTS ---
    fig, axes = plt.subplots(1, 2, figsize=(16, 8), sharex=True, sharey=True)
    rx, ry = zip(*raw) if raw else ([], [])
    cmap = plt.cm.tab10
    kept = sorted(kept, key=lambda t: -t.hits)
    for ax, mode in zip(axes, ["filtre", "lisse"]):
        ax.scatter(rx, ry, s=6, c="#C2C8CE", label=f"Plots bruts ({len(raw)})")
        for i, tr in enumerate(kept):
            pts = ([(h[0], h[1], h[2]) for h in tr.trajectory()]
                   if mode == "filtre" else rts_smooth(tr))
            xs = [p[1] for p in pts]; ys = [p[2] for p in pts]
            ax.plot(xs, ys, "-", lw=1.9, c=cmap(i % 10),
                    label=f"#{tr.id} ({tr.hits} hits)")
            ax.plot(xs[-1], ys[-1], "o", ms=7, c=cmap(i % 10))
        ax.set_title("Temps réel — filtré" if mode == "filtre"
                     else "Produit trajet — lissage RTS")
        ax.set_xlabel("Est (m)"); ax.set_ylabel("Nord (m)")
        ax.set_aspect("equal"); ax.grid(alpha=.3)
        ax.legend(loc="best", fontsize=8)
    fig.tight_layout(); fig.savefig(png, dpi=140)

    n_fa_tracks = sum(1 for tr in all_tracks if not tr.confirmed_ever)
    print(f"Pistes retenues : {len(kept)}  |  ebauches rejetees (bruit) : {n_fa_tracks}")
    print(f"-> {png}  |  -> {csv_out}")


if __name__ == "__main__":
    args = sys.argv[1:]
    profil = args.pop() if (args and args[-1] in PROFILES) else "defaut"
    apply_profile(profil)
    print(f"Profil applique : {profil} {PROFILES[profil] or '(defauts)'}")
    if args:
        run(csv_dwells(args[0]))
    else:
        run(synthetic_dwells())
