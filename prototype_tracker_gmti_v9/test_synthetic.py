#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_synthetic.py — non-régression du tracker v9 sur les scénarios synthétiques du brief (§6.1).

Le module de référence `docs/gmti_tracker_v9_ref.py` obtient sur ces scénarios : une seule piste
confirmée du dwell 2 au dwell 119, 90 hits, cap 135,6° ± 0,9 (vrai 135), 28,7 km/h (vrai 28,8), et deux
pistes pour deux navires parallèles à 600 m. Ce test rejoue les mêmes scénarios contre CE module : il
vérifie que le portage est fidèle, indépendamment de ce que donnent les captures réelles.

Scénario A : cargo de 250 m (3 diffuseurs), cap 135°, 8 m/s, bruit anisotrope (10 m en distance, 100 m
en travers), Doppler bruité à 1 m/s, un dwell sur quatre appartient à un autre job pointé ailleurs, faux
plot de mer périodique.
Scénario B : deux navires parallèles à 600 m, même cap et même vitesse → deux pistes attendues.

    python test_synthetic.py
"""
import collections
import math

import numpy as np

import tracker as T
import track_run as R

LAT0, LON0 = 43.0, 5.0
SENS_XY, SENS_ALT = (-20000.0, 22000.0), 8000.0
HDG, V = math.radians(135), 8.0
VX, VY = V * math.sin(HDG), V * math.cos(HDG)
DT, N_DWELL = 1.5, 120


def ship_plots(frame, cx, cy, rng, snr=20.0):
    dx, dy, rho, r = T.los_geometry(SENS_XY[0], SENS_XY[1], SENS_ALT, cx, cy)
    u, n = np.array([dx, dy]) / rho, np.array([-dy, dx]) / rho
    vr_true = (dx * VX + dy * VY) / r
    out = []
    for off in (-110.0, 0.0, 110.0):
        px, py = cx + off * math.sin(HDG), cy + off * math.cos(HDG)
        noise = u * rng.standard_normal() * 10 + n * rng.standard_normal() * 100
        x, y = px + noise[0], py + noise[1]
        lat, lon = frame.to_ll(x, y)
        out.append(T.Plot(lat=lat, lon=lon, x=x, y=y, vr=vr_true + rng.standard_normal() * 1.0,
                          snr_db=snr + 5 * rng.random()))
    return out


def dwell_at(frame, t, cx, cy, plots, job=1):
    slat, slon = frame.to_ll(*SENS_XY)
    clat, clon = frame.to_ll(cx, cy)
    return T.Dwell(t=t, sensor_lat=slat, sensor_lon=slon, sensor_alt_m=SENS_ALT,
                   center_lat=clat, center_lon=clon, half_range_m=8000.0, half_angle_deg=1.3,
                   mdv_mps=3.0, job_id=job, plots=plots)


def scenario_a(frame, rng):
    dwells = []
    for k in range(N_DWELL):
        t, cx, cy = k * DT, VX * k * DT, VY * k * DT
        if k % 4 == 3:                                     # dwell d'un autre job, pointé ailleurs
            dwells.append(dwell_at(frame, t, 15000.0, -15000.0, [], job=2))
            continue
        plots = ship_plots(frame, cx, cy, rng)
        if k % 7 == 0:                                     # faux plot de mer
            x, y = cx + 1500, cy - 900
            la, lo = frame.to_ll(x, y)
            plots.append(T.Plot(lat=la, lon=lo, x=x, y=y, vr=3.0, snr_db=8))
        dwells.append(dwell_at(frame, t, cx, cy, plots))
    return dwells


def scenario_b(frame, rng):
    dwells = []
    for k in range(N_DWELL):
        t = k * DT
        plots = []
        for off_n in (0.0, 600.0):
            cx = VX * t + off_n * math.cos(HDG)
            cy = VY * t - off_n * math.sin(HDG)
            plots += ship_plots(frame, cx, cy, rng)
        dwells.append(dwell_at(frame, t, VX * t, VY * t, plots))
    return dwells


def run(dwells, profile="maritime"):
    prof = R.PROFILES[profile]
    frame = T.LocalFrame(LAT0, LON0)
    T.Track._ids = __import__("itertools").count(1)
    tk = T.Tracker(prof, frame)
    snaps = []
    for d in dwells:
        tk.step(d)
        snaps.append(tk.snapshot(d.t))
    return snaps


def main():
    frame = T.LocalFrame(LAT0, LON0)
    # Le profil livré vise la capture réelle, dont le Doppler est inexploitable (cf. track_run.py) ; le
    # scénario synthétique suit la convention du brief — Doppler propre à 1 m/s — donc on rétablit ici
    # les conditions nominales : EKF Doppler actif, σ du flux respecté, critère Doppler du clustering.
    R.PROFILES["maritime"] = T.profile_with(R.PROFILES["maritime"], doppler_enabled=True,
                                            sigma_vr_floor_mps=0.0, cluster_eps_vr_mps=3.0)
    snaps = run(scenario_a(frame, np.random.default_rng(1)))
    spans = collections.OrderedDict()
    for k, sn in enumerate(snaps):
        for s in sn:
            if s["state"] != T.TENTATIVE:
                spans.setdefault(s["track_id"], [k, k])[1] = k
    n_conf = collections.Counter(sum(1 for s in sn if s["state"] != T.TENTATIVE) for sn in snaps)
    main_trk = max(snaps[-1], key=lambda s: s["hits"])
    tid = main_trk["track_id"]
    h = [s["heading_deg"] for sn in snaps[-60:] for s in sn if s["track_id"] == tid]
    sp = [s["speed_kmh"] for sn in snaps[-60:] for s in sn if s["track_id"] == tid]
    print("[A] pistes confirmées (id : dwell début→fin) :", dict(spans))
    print("[A] nb de pistes confirmées par dwell :", dict(n_conf))
    print("[A] piste principale %d : %d hits, cap %.1f° ± %.2f (vrai 135), vitesse %.1f km/h (vrai 28.8)"
          % (tid, main_trk["hits"], np.mean(h), np.std(h), np.mean(sp)))
    ok_a = len(spans) == 1 and abs(np.mean(h) - 135) < 1.5 and np.std(h) < 2 and abs(np.mean(sp) - 28.8) < 1.5

    snaps_b = run(scenario_b(frame, np.random.default_rng(2)))
    n_b = sum(1 for s in snaps_b[-1] if s["state"] != T.TENTATIVE)
    print("[B] deux navires à 600 m → pistes confirmées :", n_b)
    ok_b = n_b == 2

    print("RESULTAT :", "OK" if ok_a and ok_b else "ECHEC")
    return 0 if (ok_a and ok_b) else 1


if __name__ == "__main__":
    raise SystemExit(main())
