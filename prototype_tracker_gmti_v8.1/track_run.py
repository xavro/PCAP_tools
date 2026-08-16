# -*- coding: utf-8 -*-
"""Noyau d'exécution du tracker v8 SANS matplotlib — réutilisable (GUI, CLI, tests).

Sépare le CALCUL (décodage CSV -> pistes) du RENDU. La console Tkinter
`pcap_console.py` l'utilise pour dessiner les pistes sur un Canvas natif.

v8.1 : détection candidat aérien / rotateur fixe (flags is_air / is_rotator exposés,
en plus des mécanismes grande zone v6-v7). Dépendances : numpy + scipy (via
`tracker`). Pas de matplotlib.
"""
import csv
import itertools
from collections import defaultdict

import tracker as T

# Profils de tuning par environnement (alignés sur demo.py v8).
PROFILES = {
    "defaut":    {},
    "maritime":  dict(Q_ACCEL=0.05, V_INIT_STD=4.0, CONFIRM_M=4, CONFIRM_N=6,
                      DELETE_MISSES=12, GATE_CHI2=7.0, GATE_MAX_M=250.0),
    "routier":   dict(Q_ACCEL=2.0, V_INIT_STD=12.0, CONFIRM_M=3, CONFIRM_N=5,
                      DELETE_MISSES=8, GATE_CHI2=9.21, GATE_MAX_M=300.0),
    "convoi":    dict(Q_ACCEL=0.5, V_INIT_STD=10.0, CONFIRM_M=4, CONFIRM_N=6,
                      DELETE_MISSES=6, GATE_CHI2=5.0, GATE_MAX_M=150.0),
    "personnel": dict(Q_ACCEL=0.3, V_INIT_STD=2.0, CONFIRM_M=3, CONFIRM_N=6,
                      DELETE_MISSES=15, GATE_CHI2=7.0, GATE_MAX_M=120.0),
    "aerien":    dict(Q_ACCEL=4.0, V_INIT_STD=40.0, CONFIRM_M=3, CONFIRM_N=5,
                      DELETE_MISSES=4, GATE_CHI2=9.21, GATE_MAX_M=800.0),
    "routier_zone": dict(Q_ACCEL=2.0, V_INIT_STD=12.0, GATE_CHI2=9.21,
                         GATE_MAX_M=250.0, GATE_GROW_MPS=25.0,
                         CONFIRM_M=5, CONFIRM_BY_HITS=True,
                         DELETE_SEC=60.0, SOLID_HITS=15),
}

# Instantané des défauts de Params (capte aussi les AIR_*/ROT_* de v8), pour
# repartir propre à chaque run (le profil mute la classe globale).
_DEFAULTS = {k: getattr(T.Params, k) for k in dir(T.Params) if k.isupper()}


def apply_profile(name, overrides=None):
    for k, v in _DEFAULTS.items():
        setattr(T.Params, k, v)
    for k, v in PROFILES.get(name, {}).items():
        setattr(T.Params, k, v)
    if overrides:
        for k, v in overrides.items():
            if v is not None:
                setattr(T.Params, k, v)


def csv_dwells(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f, delimiter=";"):
            rows.append(r)
    if not rows:
        raise ValueError("CSV vide")
    frame = T.LocalFrame(float(rows[0]["lat"]), float(rows[0]["lon"]))

    def fget(r, key, default):
        v = r.get(key, "")
        return float(v) if v not in ("", None) else default

    dwells = defaultdict(list)
    for r in rows:
        dwells[(int(r["revisit_idx"]), int(r["dwell_idx"]))].append(r)

    for key in sorted(dwells, key=lambda k: min(int(r["dwell_time_ms"]) for r in dwells[k])):
        grp = dwells[key]
        t = min(int(r["dwell_time_ms"]) for r in grp) / 1000.0
        plots = []
        for r in grp:
            x, y = frame.to_xy(float(r["lat"]), float(r["lon"]))
            sig_r = fget(r, "sig_range_cm", T.Params.R_POS_DEFAULT * 100) / 100.0
            sig_x = fget(r, "sig_xrange_dm", T.Params.R_POS_DEFAULT * 10) / 10.0
            R = None
            if r.get("sensor_lat"):
                sx, sy = frame.to_xy(float(r["sensor_lat"]), float(r["sensor_lon"]))
                R = T.covariance_from_4607((sx, sy), (x, y), sig_r, sig_x)
            plots.append(T.Plot(x, y, r_pos=max(sig_r, sig_x), R=R,
                                vel_los=fget(r, "vel_los_cms", 0) / 100.0,
                                snr=fget(r, "snr_db", None),
                                classification=r.get("classification")))
        yield t, plots, frame


def run_tracking(path, profile="defaut", overrides=None):
    """Décode le CSV et déroule le tracker. Données Python pures prêtes à dessiner :
      {raw:[(x,y)], tracks:[{id,hits,pts,smooth,is_air,is_rotator}],
       n_kept, n_rejected, frame}
    """
    apply_profile(profile, overrides)
    T.Track._ids = itertools.count(1)
    tk = T.Tracker()
    raw = []
    frame = None
    for t, plots, fr in csv_dwells(path):
        frame = fr
        raw += [(float(p.x), float(p.y)) for p in plots]
        tk.step(t, plots)

    all_tracks = tk.archive + tk.tracks
    kept = sorted((tr for tr in all_tracks if tr.confirmed_ever), key=lambda tr: -tr.hits)
    tracks = []
    for tr in kept:
        tracks.append({
            "id": tr.id,
            "hits": tr.hits,
            "pts": [(float(x), float(y)) for (_t, x, y, _st, _hit) in tr.trajectory()],
            "smooth": [(float(x), float(y)) for (_t, x, y) in T.rts_smooth(tr)],
            "is_air": bool(getattr(tr, "is_air", False)),
            "is_rotator": bool(getattr(tr, "is_rotator", False)),
        })
    n_rejected = sum(1 for tr in all_tracks if not tr.confirmed_ever)
    return {"raw": raw, "tracks": tracks, "n_kept": len(kept),
            "n_rejected": n_rejected, "frame": frame}
