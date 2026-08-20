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
import json
import math
import os
from collections import defaultdict

import tracker as T

# ── Profils : SOURCE UNIQUE = gmti_profiles.json (racine Tools), partagée avec le
# processor Java (TrackerConfig/Profiles). Noms de champs Java ; traduits vers Params.
JAVA2PY = {
    "gateChi2": "GATE_CHI2", "gateMaxM": "GATE_MAX_M", "gateGrowMps": "GATE_GROW_MPS",
    "accelStd": "Q_ACCEL", "initVelStd": "V_INIT_STD", "measPosStd": "R_POS_DEFAULT",
    "confirmM": "CONFIRM_M", "confirmN": "CONFIRM_N", "confirmByHits": "CONFIRM_BY_HITS",
    "deleteMisses": "DELETE_MISSES", "deleteSec": "DELETE_SEC", "solidHits": "SOLID_HITS",
    "airSpeedMps": "AIR_SPEED_MPS", "airVlosMps": "AIR_VLOS_MPS", "airConfirm": "AIR_CONFIRM",
    "airQAccel": "AIR_Q_ACCEL", "airGateMaxM": "AIR_GATE_MAX_M", "airMinGround": "AIR_MIN_GROUND",
    "rotMaxGround": "ROT_MAX_GROUND",
    "absorbDwells": "ABSORB_DWELLS", "absorbDistM": "ABSORB_DIST_M", "absorbDvMps": "ABSORB_DV_MPS",
    "absorbHeadingDeg": "ABSORB_HD_DEG", "absorbSlowMps": "ABSORB_SLOW_MPS",
}
PY2JAVA = {v: k for k, v in JAVA2PY.items()}
# Paramètres « processor » (hors noyau Kalman) : déclutter, fusion, affichage — portés ici
# pour que le banc de réglage reflète la prod. Défauts = TrackerConfig.java.
PROC_DEFAULTS = {"mergeMaxDistM": 0.0, "mergeMaxDvMps": 2.0, "mergeMaxHeadingDeg": 30.0, "mergeSlowMps": 3.0,
                 "minSnrDb": 0, "minTrackSpeedMps": 0.0, "classFilter": [],
                 "measPosStdMin": 5.0, "measPosStdMax": 200.0,
                 "clusterDistM": 0.0, "clusterDvMps": 2.5, "clusterMaxSpanM": 400.0, "projectSec": 60.0,
                 "ghostSnrDb": 0.0, "ghostDistM": 400.0, "snrRefDb": 0.0, "snrScaleMax": 4.0}
EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gmti_profiles.json")
PROFILES_JSON = os.environ.get("GMTI_PROFILES") or EMBEDDED_JSON
CURRENT = {}          # config effective (noms Java) du dernier apply_profile — lue par run_tracking

# Profils de tuning par environnement (repli si gmti_profiles.json absent ; alignés sur demo.py v8).
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


_JSON = {"defaults": {}, "profiles": {}, "params": {}}


def load_profiles(path=None):
    """Charge gmti_profiles.json → met à jour PROFILES (noms Params) et _JSON. Repli sur les
    profils embarqués si le fichier manque. Renvoie le dict JSON (defaults/profiles/params)."""
    global _JSON
    path = path or PROFILES_JSON
    if not os.path.isfile(path) and path != EMBEDDED_JSON and os.path.isfile(EMBEDDED_JSON):
        # dépôt (GMTI_PROFILES, ex. /data/gmti/gmti_profiles.json) pas encore créé : amorcé depuis la
        # copie embarquée pour que console et service partagent d'emblée le même fichier éditable
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(EMBEDDED_JSON, encoding="utf-8") as f:
                seed = f.read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(seed)
        except OSError:
            path = EMBEDDED_JSON                        # volume absent / lecture seule : repli embarqué
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return _JSON
    _JSON = data
    PROFILES.clear()
    for name, prof in (data.get("profiles") or {}).items():
        PROFILES[name] = {JAVA2PY[k]: v for k, v in prof.items() if k in JAVA2PY}
    return _JSON


def java_config(name, overrides=None):
    """Config effective en noms Java : defaults(JSON|TrackerConfig) + profil + surcharges."""
    cfg = dict(PROC_DEFAULTS)
    cfg.update({PY2JAVA[k]: v for k, v in _DEFAULTS.items() if k in PY2JAVA})
    cfg.update(_JSON.get("defaults") or {})
    cfg.update((_JSON.get("profiles") or {}).get(name) or {PY2JAVA[k]: v for k, v in PROFILES.get(name, {}).items() if k in PY2JAVA})
    for k, v in (overrides or {}).items():
        if v is None and k != "deleteSec":
            continue
        cfg[PY2JAVA.get(k, k)] = v
    return cfg


def apply_profile(name, overrides=None):
    """Applique un profil (+ surcharges, noms Java OU Params) à la classe globale Params.
    Les paramètres « processor » restent dans CURRENT (déclutter, fusion, affichage)."""
    global CURRENT
    if not _JSON.get("profiles"):
        load_profiles()
    cfg = java_config(name, overrides)
    for k, v in _DEFAULTS.items():
        setattr(T.Params, k, v)
    for jk, v in cfg.items():
        pk = JAVA2PY.get(jk)
        if pk is not None:
            setattr(T.Params, pk, v)
    CURRENT = cfg
    return cfg


def cluster_plots(plots, cfg=None):
    """Pré-clustering des plots d'UN dwell pour cibles étendues (gros navire = plusieurs échos).
    Liaison simple : deux plots sont liés s'ils sont à moins de clusterDistM ET si leurs vitesses
    radiales sont compatibles (|Δv_LOS| < clusterDvMps, quand toutes deux connues). Un groupe dont
    l'étalement dépasse clusterMaxSpanM n'est PAS fusionné (banc de véhicules). Le plot fusionné =
    centroïde (poids égaux), R = moyenne des R + dispersion des membres, r_pos = max(r_pos, √disp),
    v_LOS moyenne, SNR max, classe majoritaire ; attributs n_echoes / span_m. clusterDistM ≤ 0 →
    passe-plat (identique à l'existant : routier, personnel…)."""
    cfg = cfg or CURRENT
    dmax = float(cfg.get("clusterDistM") or 0.0)
    if dmax <= 0.0 or len(plots) < 2:
        for p in plots:
            if not hasattr(p, "n_echoes"):
                p.n_echoes, p.span_m = 1, 0.0
        return plots
    dv = float(cfg.get("clusterDvMps") or 2.5)
    span_max = float(cfg.get("clusterMaxSpanM") or 400.0)
    n = len(plots)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    for i in range(n):
        pi = plots[i]
        for j in range(i + 1, n):
            pj = plots[j]
            if math.hypot(pi.x - pj.x, pi.y - pj.y) >= dmax:
                continue
            if pi.vel_los is not None and pj.vel_los is not None and abs(pi.vel_los - pj.vel_los) >= dv:
                continue
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[max(ri, rj)] = min(ri, rj)
    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(plots[i])
    out = []
    import numpy as np
    for g in groups.values():
        if len(g) == 1:
            p = g[0]; p.n_echoes, p.span_m = 1, 0.0; out.append(p); continue
        xs = np.array([p.x for p in g]); ys = np.array([p.y for p in g])
        span = float(math.hypot(xs.max() - xs.min(), ys.max() - ys.min()))
        if span > span_max:                          # trop étalé : on ne fusionne pas
            for p in g:
                p.n_echoes, p.span_m = 1, 0.0
            out.extend(g); continue
        # centroïde pondéré par l'amplitude, R élargie de la dispersion… (tracker.merge_plots,
        # partagé avec la mise à jour d'une piste étendue)
        for p in g:
            p.n_echoes = 1
        out.append(T.merge_plots(g))
    return out


def suppress_ghosts(plots, cfg=None):
    """Suppression des échos fantômes d'UN dwell (lobes secondaires / ambiguïtés Doppler d'un écho
    fort) : un plot est rejeté s'il existe dans le même dwell un plot plus fort d'au moins
    ghostSnrDb à moins de ghostDistM. ghostSnrDb ≤ 0 → passe-plat. Retourne (plots, n_rejetés)."""
    cfg = cfg or CURRENT
    dsnr = float(cfg.get("ghostSnrDb") or 0.0)
    if dsnr <= 0.0 or len(plots) < 2:
        return plots, 0
    dmax = float(cfg.get("ghostDistM") or 400.0)
    keep = []
    for p in plots:
        ghost = False
        if p.snr is not None:
            for q in plots:
                if q is p or q.snr is None:
                    continue
                if q.snr - p.snr >= dsnr and math.hypot(p.x - q.x, p.y - q.y) < dmax:
                    ghost = True; break
        if not ghost:
            keep.append(p)
    return keep, len(plots) - len(keep)


def scale_by_snr(plots, cfg=None):
    """Pondération de la mesure par le SNR : σ_mesure × clamp(10^((snrRefDb − SNR)/20), 1, snrScaleMax).
    Un écho faible est cru moins précisément (gate plus large, mise à jour plus douce), un écho
    ≥ snrRefDb garde ses incertitudes 4607. snrRefDb ≤ 0 → passe-plat."""
    cfg = cfg or CURRENT
    ref = float(cfg.get("snrRefDb") or 0.0)
    if ref <= 0.0:
        return plots
    fmax = max(1.0, float(cfg.get("snrScaleMax") or 4.0))
    for p in plots:
        if p.snr is None:
            continue
        f = min(fmax, max(1.0, 10.0 ** ((ref - float(p.snr)) / 20.0)))
        if f > 1.0:
            p.R = p.R * (f * f); p.r_pos = p.r_pos * f
    return plots


def prepare_plots(plots, cfg=None):
    """Étage d'entrée COMMUN (banc hors ligne, pistage temps réel, oracle de parité) appliqué aux
    plots d'un dwell, dans cet ordre : déclutter (minSnrDb, classFilter) → fantômes (ghostSnrDb)
    → pondération SNR (snrRefDb) → pré-clustering (clusterDistM). Retourne (plots, stats) avec
    stats = {filtered, ghosts, clustered}."""
    cfg = cfg or CURRENT
    st = {"filtered": 0, "ghosts": 0, "clustered": 0}
    min_snr = float(cfg.get("minSnrDb") or 0)
    cls_filter = set(int(c) for c in (cfg.get("classFilter") or []))
    if min_snr > 0 or cls_filter:
        kept = [p for p in plots if (min_snr <= 0 or (p.snr is not None and p.snr >= min_snr))
                and (not cls_filter or (p.classification not in (None, "") and int(float(p.classification)) in cls_filter))]
        st["filtered"] = len(plots) - len(kept); plots = kept
    plots, st["ghosts"] = suppress_ghosts(plots, cfg)
    plots = scale_by_snr(plots, cfg)
    n = len(plots)
    plots = cluster_plots(plots, cfg)
    st["clustered"] = n - len(plots)
    return plots, st


class TrackMerger:
    """Port Python de TrackMerger.java : fusion « 1 contact = 1 piste » des pistes
    affichables d'un dwell (proches ET co-mobiles), identité de contact stable par
    proximité. Travaille en coordonnées locales métriques (x, y)."""

    def __init__(self, cfg):
        self.max_d = float(cfg.get("mergeMaxDistM") or 0.0)
        self.max_dv = float(cfg.get("mergeMaxDvMps") or 2.0)
        self.max_hd = float(cfg.get("mergeMaxHeadingDeg") or 30.0)
        self.slow = float(cfg.get("mergeSlowMps") or 3.0)
        self.prev = {}                    # contact_id -> (x, y)
        self.next_id = 1

    def enabled(self):
        return self.max_d > 0.0

    @staticmethod
    def _hd(h1, h2):
        d = abs(h1 - h2) % 360.0
        return 360.0 - d if d > 180.0 else d

    def _same(self, a, b):
        if math.hypot(a["x"] - b["x"], a["y"] - b["y"]) >= self.max_d:
            return False
        if abs(a["speed"] - b["speed"]) >= self.max_dv:
            return False
        both_slow = min(a["speed"], b["speed"]) < self.slow
        return both_slow or self._hd(a["heading"], b["heading"]) < self.max_hd

    def merge(self, outs):
        """outs : liste de dicts {track_id, x, y, speed, heading, state, hits, is_air, is_rotator}
        → liste de contacts {id, x, y, speed, heading, state, hits, n, members, is_air, is_rotator}."""
        if not self.enabled() or not outs:
            return [dict(o, id=o["track_id"], n=1, members=[o["track_id"]]) for o in outs]
        n = len(outs)
        parent = list(range(n))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]; i = parent[i]
            return i
        for i in range(n):
            for j in range(i + 1, n):
                if self._same(outs[i], outs[j]):
                    ra, rb = find(i), find(j)
                    if ra != rb:
                        parent[max(ra, rb)] = min(ra, rb)
        groups = defaultdict(list)
        for i in range(n):
            groups[find(i)].append(outs[i])
        rank = {"SOLID": 3, "CONFIRMED": 2, "COASTING": 1}
        fused = []
        for g in groups.values():
            rep = max(g, key=lambda o: o["hits"])
            fused.append({"x": sum(o["x"] for o in g) / len(g), "y": sum(o["y"] for o in g) / len(g),
                          "speed": rep["speed"], "heading": rep["heading"],
                          "state": max((o["state"] for o in g), key=lambda st: rank.get(st, 0)),
                          "hits": max(o["hits"] for o in g), "n": len(g), "members": [o["track_id"] for o in g],
                          "is_air": any(o["is_air"] for o in g), "is_rotator": any(o["is_rotator"] for o in g),
                          "track_id": rep["track_id"]})
        fused.sort(key=lambda c: -c["hits"])
        nxt, claimed = {}, set()
        for c in fused:
            best, cid = self.max_d, -1
            for pid, (px, py) in self.prev.items():
                if pid in claimed:
                    continue
                d = math.hypot(c["x"] - px, c["y"] - py)
                if d < best:
                    best, cid = d, pid
            if cid < 0:
                cid = self.next_id; self.next_id += 1
            claimed.add(cid); c["id"] = cid; nxt[cid] = (c["x"], c["y"])
        self.prev = nxt
        return fused


def _state_name(st):
    return {T.TENTATIVE: "TENTATIVE", T.CONFIRMED: "CONFIRMED", T.SOLID: "SOLID",
            T.COASTING: "COASTING", T.DEAD: "DEAD"}.get(st, str(st))


def _clamp_std(v):
    lo = float(CURRENT.get("measPosStdMin", PROC_DEFAULTS["measPosStdMin"]) or 0.0)
    hi = float(CURRENT.get("measPosStdMax", PROC_DEFAULTS["measPosStdMax"]) or 1e9)
    return min(max(v, lo), hi)


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
                # Parité Java (Tracker.measurementCov / clampStd) : les incertitudes portée/travers
                # sont BORNÉES à [measPosStdMin, measPosStdMax] pour la covariance orientée
                # (P0 garde max(σ) non borné, comme le Java).
                R = T.covariance_from_4607((sx, sy), (x, y), _clamp_std(sig_r), _clamp_std(sig_x))
            plots.append(T.Plot(x, y, r_pos=max(sig_r, sig_x), R=R,
                                vel_los=fget(r, "vel_los_cms", 0) / 100.0,
                                snr=fget(r, "snr_db", None),
                                classification=r.get("classification")))
        yield t, plots, frame


def run_tracking(path, profile="defaut", overrides=None):
    """Décode le CSV et déroule le tracker. Données Python pures prêtes à dessiner :
      {raw:[(x,y)], tracks:[{id,hits,pts,smooth,is_air,is_rotator,etat,t0,t1}],
       n_kept, n_rejected, frame, config (noms Java), contacts (fusion, si mergeMaxDistM>0),
       metrics}
    Le déclutter (minSnrDb, classFilter) et la fusion TrackMerger reproduisent le processor.
    """
    cfg = apply_profile(profile, overrides)
    T.Track._ids = itertools.count(1)
    tk = T.Tracker()
    raw = []
    frame = None
    min_snr = float(cfg.get("minSnrDb") or 0)
    cls_filter = set(int(c) for c in (cfg.get("classFilter") or []))
    min_speed = float(cfg.get("minTrackSpeedMps") or 0.0)
    merger = TrackMerger(cfg)
    contacts = defaultdict(lambda: {"pts": [], "n_max": 1, "hits": 0, "members": set()})
    n_dwells = 0; n_filtered = 0; n_clustered = 0; n_ghosts = 0
    for t, plots, fr in csv_dwells(path):
        frame = fr
        raw += [(float(p.x), float(p.y)) for p in plots]
        n_dwells += 1
        plots, pst = prepare_plots(plots, cfg)              # déclutter → fantômes → SNR → clustering
        n_filtered += pst["filtered"]; n_ghosts += pst["ghosts"]; n_clustered += pst["clustered"]
        tk.step(t, plots)
        if merger.enabled():                                # étage post-pistage (comme le processor)
            outs = []
            for tr in tk.tracks:
                st = tr.state
                if st not in (T.CONFIRMED, T.SOLID, T.COASTING):
                    continue
                sp = tr.speed()
                if min_speed > 0 and sp < min_speed:
                    continue
                outs.append({"track_id": tr.id, "x": float(tr.x[0]), "y": float(tr.x[1]), "speed": sp,
                             "heading": (math.degrees(math.atan2(tr.x[2], tr.x[3])) + 360.0) % 360.0,
                             "state": _state_name(st), "hits": tr.hits, "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator)})
            for c in merger.merge(outs):
                cc = contacts[c["id"]]
                cc["pts"].append((t, c["x"], c["y"])); cc["n_max"] = max(cc["n_max"], c["n"]); cc["hits"] = max(cc["hits"], c["hits"])
                cc["members"].update(c["members"])

    all_tracks = tk.archive + tk.tracks
    kept = sorted((tr for tr in all_tracks if tr.confirmed_ever), key=lambda tr: -tr.hits)
    tracks = []
    for tr in kept:
        traj = tr.trajectory()
        etat = traj[-1][3] if traj else ""      # état à la dernière détection réelle
        tracks.append({
            "id": tr.id,
            "hits": tr.hits,
            "etat": etat,
            "vel": (float(tr.x[2]), float(tr.x[3])),        # dernier état (m/s ENU) : projection
            "absorbed": list(tr.absorbed), "extent_m": round(float(tr.extent), 1),
            "absorbed_into": getattr(tr, "absorbed_into", None),
            "pts": [(float(x), float(y)) for (_t, x, y, _st, _hit) in traj],
            "smooth": [(float(x), float(y)) for (_t, x, y) in T.rts_smooth(tr)],
            "is_air": bool(getattr(tr, "is_air", False)),
            "is_rotator": bool(getattr(tr, "is_rotator", False)),
        })
    n_rejected = sum(1 for tr in all_tracks if not tr.confirmed_ever)
    for d, tr in zip(tracks, kept):                          # bornes temporelles (métriques)
        h = tr.trajectory()
        d["t0"], d["t1"] = (float(h[0][0]), float(h[-1][0])) if h else (0.0, 0.0)
        d["n_coast"] = sum(1 for (_t, _x, _y, st, hit) in h if not hit)
    res = {"raw": raw, "tracks": tracks, "n_kept": len(kept), "n_rejected": n_rejected, "frame": frame,
           "_objs": {tr.id: tr for tr in kept},           # objets Track (inspection : assoc, gates, historique)
           "config": cfg, "n_dwells": n_dwells, "n_filtered": n_filtered, "n_clustered": n_clustered, "n_ghosts": n_ghosts, "n_swallowed": tk.n_swallowed,
           "contacts": [{"id": cid, "pts": [(float(x), float(y)) for (_t, x, y) in c["pts"]],
                         "n_max": c["n_max"], "hits": c["hits"], "members": sorted(c["members"])}
                        for cid, c in contacts.items()] if merger.enabled() else None}
    res["metrics"] = metrics(res)
    return res


def track_detail(res, track_id):
    """Détail d'une piste du dernier run (inspection) : historique complet (t, lat, lon, état, hit,
    vitesse), plots associés (t, lat, lon, d² Mahalanobis, v_LOS, SNR, classe), gates 2σ
    (t, lat, lon, demi-axes m, orientation °) et résumé."""
    tr = (res.get("_objs") or {}).get(int(track_id))
    fr = res.get("frame")
    if tr is None or fr is None:
        return None
    names = {T.TENTATIVE: "TENTATIVE", T.CONFIRMED: "CONFIRMED", T.SOLID: "SOLID", T.COASTING: "COASTING", T.DEAD: "DEAD"}
    hist = []
    for i, (t, x, y, st, hit) in enumerate(tr.history):
        la, lo = fr.to_ll(float(x), float(y))
        sp = None
        if i < len(tr.states):
            xs = tr.states[i][1]; sp = float(math.hypot(xs[2], xs[3]))
        hist.append([round(float(t), 3), round(la, 6), round(lo, 6), names.get(st, str(st)), bool(hit), None if sp is None else round(sp, 1)])
    assoc = []
    for (t, x, y, d2, vlos, snr, cls) in tr.assoc:
        la, lo = fr.to_ll(float(x), float(y))
        assoc.append([round(float(t), 3), round(la, 6), round(lo, 6), None if d2 != d2 else round(float(d2), 2),
                      None if vlos is None else round(float(vlos), 1), snr, cls])
    gates = []
    import numpy as np
    chi2 = float(T.Params.GATE_CHI2)
    for (t, S, d2), (ta, x, y, *_r) in zip(tr.gates, tr.assoc[1:]):
        try:
            w, v = np.linalg.eigh(S)
            a, b = math.sqrt(max(w[1], 0) * chi2), math.sqrt(max(w[0], 0) * chi2)
            ang = math.degrees(math.atan2(v[1, 1], v[0, 1]))
        except Exception:
            continue
        # centre = position predite (avant mise a jour) ~ etat de l'historique precedent ; on prend le plot associe comme repere
        la, lo = fr.to_ll(float(x), float(y))
        gates.append([round(float(t), 3), round(la, 6), round(lo, 6), round(a, 1), round(b, 1), round(ang, 1), None if d2 != d2 else round(float(d2), 2)])
    speeds = [h[5] for h in hist if h[5] is not None]
    return {"id": tr.id, "hits": tr.hits, "misses": tr.misses, "confirmed_ever": bool(tr.confirmed_ever),
            "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator),
            "t0": hist[0][0] if hist else None, "t1": hist[-1][0] if hist else None,
            "n_hist": len(hist), "n_miss": sum(1 for h in hist if not h[4]),
            "speed_mean": (sum(speeds) / len(speeds)) if speeds else None, "speed_max": max(speeds) if speeds else None,
            "hist": hist, "assoc": assoc, "gates": gates, "gate_chi2": chi2, "gate_max_m": float(tr.gate_max)}


def metrics(res):
    """Indicateurs de qualité de pistage (indépendants du repère) pour comparer des profils."""
    tr = res["tracks"]
    n = len(tr)
    if not n:
        return {"n_tracks": 0, "n_rejected": res["n_rejected"], "n_plots": len(res["raw"])}
    def length(pts):
        return sum(math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]) for i in range(1, len(pts)))
    hits = [t["hits"] for t in tr]
    durs = [max(0.0, t["t1"] - t["t0"]) for t in tr]
    lens = [length(t["pts"]) for t in tr]
    coast = sum(t.get("n_coast", 0) for t in tr); pts_total = sum(len(t["pts"]) for t in tr)
    m = {"n_tracks": n, "n_rejected": res["n_rejected"], "n_plots": len(res["raw"]), "n_dwells": res.get("n_dwells", 0),
         "n_filtered": res.get("n_filtered", 0), "n_clustered": res.get("n_clustered", 0), "n_ghosts": res.get("n_ghosts", 0),
         "n_absorbed": sum(1 for t in res["tracks"] if t.get("absorbed_into")), "n_swallowed": res.get("n_swallowed", 0),
         "hits_total": sum(hits), "hits_mean": sum(hits) / n, "hits_median": sorted(hits)[n // 2],
         "solid": sum(1 for t in tr if t["etat"] == T.SOLID), "confirmed": sum(1 for t in tr if t["etat"] == T.CONFIRMED),
         "coasting_end": sum(1 for t in tr if t["etat"] == T.COASTING),
         "dur_mean_s": sum(durs) / n, "dur_max_s": max(durs), "len_mean_m": sum(lens) / n,
         "coast_ratio": (coast / pts_total) if pts_total else 0.0,
         "plots_per_track": len(res["raw"]) / n, "air": sum(1 for t in tr if t["is_air"]),
         "rotator": sum(1 for t in tr if t["is_rotator"]),
         "short_tracks": sum(1 for t in tr if t["hits"] < 5)}
    if res.get("contacts") is not None:
        m["contacts"] = len(res["contacts"]); m["contacts_multi"] = sum(1 for c in res["contacts"] if c["n_max"] > 1)
    return m


# Chargement au démarrage : PROFILES reflète gmti_profiles.json si présent.
load_profiles()
