"""
track_run.py — pilotage du tracker GMTI v9 depuis un CSV de plots.

Même contrat que le v8 (`PROFILES`, `apply_profile`, `run_tracking`, `metrics`, `track_detail`) : la
console pcap détecte automatiquement le dossier `prototype_tracker_gmti_v<N>` le plus élevé et n'a donc
rien à changer pour passer au v9.

Entrée : le CSV de plots produit par l'extracteur 4607 (`stanag4607_extract.write_csv` ou
`gmti_pcap_to_csv`). Les sept colonnes de DWELL ajoutées pour le v9 — `sensor_alt_m`,
`dwell_center_lat/lon`, `dwell_range_he_km`, `dwell_angle_he_deg`, `mdv_mps`, `job_id` — sont
facultatives : sans elles, le test d'observabilité est neutralisé (toute piste est réputée observable) et
le comportement redevient celui du v8 sur ce point.

Sentinelles 4607 : les incertitudes tout-à-1 (65535) et les valeurs nulles sont ramenées à None, et c'est
le profil qui fournit alors σ. Mesuré sur les captures : la routière donne σ_distance = 3,2 m et
σ_travers = 30 m, la maritime σ_distance = 101 m et σ_travers = 42 à 93 m — d'où une covariance orientée
ligne de vue plutôt qu'un σ unique.
"""
from __future__ import annotations

import csv
import itertools
import json
import math
import os
from collections import OrderedDict, defaultdict

import tracker as T

HERE = os.path.dirname(os.path.abspath(__file__))
SENTINEL_U16 = 65535


# ----------------------------------------------------------------------
# Profils — dérivés des deux profils de référence du brief (§5)
# ----------------------------------------------------------------------
def _profiles():
    maritime = T.Profile(
        "maritime",
        # Clustering spatial seul : le critère Doppler du brief (3 m/s) refuserait de lier la proue et la
        # poupe, qui diffèrent de 10 m/s sur cette capture (micro-Doppler des diffuseurs, mesuré).
        cluster_eps_xy_m=350.0, cluster_eps_vr_mps=25.0,
        # EKF Doppler DÉSACTIVÉ par défaut sur ce profil — décision prise sur mesure, pas par principe.
        # Sur la capture de référence (20260812_CaptureALL_CR2, port 5454), deux échos SIMULTANÉS de la
        # même coque diffèrent de 2,9 m/s (à moins de 150 m) à 10,5 m/s (150-300 m) alors que le flux
        # annonce σ = 0,23 à 0,51 m/s : D32.7 y décrit l'agitation des diffuseurs, pas la translation du
        # navire. Injecté dans le filtre, il stabilise le cap mais DOUBLE la vitesse affichée (25 km/h
        # mesurés pour 13 km/h réels). Sur un capteur dont le Doppler est propre — le scénario synthétique
        # du brief, vérifié par test_synthetic.py — `doppler_enabled=True` est meilleur : σ cap 0,9°.
        doppler_enabled=False,
        sigma_range_m=15.0, sigma_cross_m=120.0, sigma_vr_mps=1.5,
        sigma_vr_floor_mps=4.0,                                   # dispersion réelle du v_LOS sur la coque
        q_accel_mps2=0.05,                                        # cargo quasi inertiel
        v_init_cross_std_mps=8.0, gate_max_m=400.0,
        confirm_m=3, confirm_n=5, miss_delete_n=6,
        coast_after_sec=10.0, delete_sec=240.0, tentative_delete_sec=20.0,
        merge_chi2=9.21, merge_dv_mps=4.0, merge_k=2,
        merge_max_dist_m=450.0, merge_hdg_deg=40.0,               # co-mobilité (absorption v8 : 450 m)
        mdv_floor_mps=0.5,                                        # la capture cargo annonce MDV = 0
    )
    routier_zone = T.Profile(
        "routier_zone",
        cluster_eps_xy_m=30.0, cluster_eps_vr_mps=2.0,            # deux véhicules à 40 m restent distincts
        sigma_range_m=15.0, sigma_cross_m=80.0, sigma_vr_mps=1.5,
        q_accel_mps2=0.5, v_init_cross_std_mps=15.0, gate_max_m=250.0,
        confirm_m=3, confirm_n=5, miss_delete_n=6,
        coast_after_sec=10.0, delete_sec=90.0, tentative_delete_sec=10.0,
        merge_chi2=9.21, merge_dv_mps=8.0, merge_k=2,
    )
    # Les autres profils dérivent de ces deux-là (brief §5).
    defaut = T.profile_with(routier_zone, name="defaut", cluster_eps_xy_m=60.0, gate_max_m=300.0,
                            delete_sec=120.0, tentative_delete_sec=15.0)
    routier = T.profile_with(routier_zone, name="routier", delete_sec=60.0, coast_after_sec=6.0)
    convoi = T.profile_with(routier_zone, name="convoi", cluster_eps_xy_m=20.0, cluster_eps_vr_mps=1.0,
                            merge_dv_mps=3.0, merge_k=3)          # ne JAMAIS coller deux véhicules d'un convoi
    personnel = T.profile_with(routier_zone, name="personnel", cluster_eps_xy_m=15.0, q_accel_mps2=0.3,
                               v_init_cross_std_mps=5.0, gate_max_m=120.0, mdv_margin_mps=0.5,
                               delete_sec=45.0)
    aerien = T.profile_with(routier_zone, name="aerien", cluster_enabled=False,   # pas de cible étendue en l'air
                            q_accel_mps2=4.0, v_init_cross_std_mps=50.0, gate_max_m=800.0,
                            merge_enabled=False, delete_sec=60.0, coast_after_sec=8.0)
    return OrderedDict((p.name, p) for p in (defaut, maritime, routier, convoi, personnel, aerien, routier_zone))


PROFILES = _profiles()

# Surcharges venues de la console : noms Java du v8 (TrackerConfig) acceptés quand ils ont un
# équivalent v9 exact. Les autres sont ignorées — le v9 n'a pas les mêmes leviers, et faire semblant
# de les appliquer donnerait des comparaisons fausses.
JAVA2V9 = {
    "accelStd": "q_accel_mps2", "gateMaxM": "gate_max_m", "gateChi2": "gate_chi2_pos",
    "confirmM": "confirm_m", "confirmN": "confirm_n", "deleteSec": "delete_sec",
    "solidHits": "solid_hits", "initVelStd": "v_init_cross_std_mps",
    "minSnrDb": "min_snr_db", "classFilter": "class_filter",
}


def load_profiles(path=None):
    """Surcharge éventuelle des profils v9 par un fichier JSON (section « v9 » de gmti_profiles.json,
    ou fichier dédié via GMTI_PROFILES_V9). Absent = valeurs du module."""
    path = path or os.environ.get("GMTI_PROFILES_V9") or os.path.join(os.path.dirname(HERE), "gmti_profiles.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return PROFILES
    v9 = (data or {}).get("v9") or {}
    for name, over in v9.items():
        base = PROFILES.get(name) or PROFILES["defaut"]
        PROFILES[name] = T.profile_with(base, name=name, **{k: v for k, v in over.items()
                                                            if hasattr(base, k)})
    return PROFILES


def apply_profile(name, overrides=None):
    """Profil effectif : profil nommé + surcharges (noms v9 ou noms Java équivalents)."""
    prof = PROFILES.get(name) or PROFILES["defaut"]
    kw = {}
    for k, v in (overrides or {}).items():
        key = k if hasattr(prof, k) else JAVA2V9.get(k)
        if key and hasattr(prof, key):
            if key == "class_filter":
                kw[key] = tuple(int(c) for c in (v or ()))
            elif isinstance(getattr(prof, key), bool):
                kw[key] = bool(v)
            elif isinstance(getattr(prof, key), int) and not isinstance(getattr(prof, key), bool):
                kw[key] = int(v)
            else:
                kw[key] = float(v)
    return T.profile_with(prof, **kw) if kw else prof


def config_dict(prof: T.Profile):
    """Configuration effective, pour affichage dans la console."""
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in prof.__dict__.items()}


# ----------------------------------------------------------------------
# Lecture du CSV
# ----------------------------------------------------------------------
def _f(row, key, default=None):
    v = row.get(key, "")
    if v in ("", None):
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _sigma(row, key, scale, sentinel=SENTINEL_U16):
    """Incertitude 4607 → mètres (ou m/s). Sentinelle tout-à-1 ou valeur nulle → None : le profil prend
    le relais, ce qui vaut mieux qu'une précision annoncée de 655 m ou de 0."""
    v = _f(row, key)
    if v is None or v >= sentinel or v <= 0:
        return None
    return v / scale


def csv_dwells(path, prof: T.Profile):
    """CSV → suite de `Dwell` ordonnés dans le temps, plots convertis en repère local."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f, delimiter=";"))
    if not rows:
        raise ValueError("CSV vide")
    frame = T.LocalFrame(float(rows[0]["lat"]), float(rows[0]["lon"]))

    groups = defaultdict(list)
    for r in rows:
        groups[(int(r["revisit_idx"]), int(r["dwell_idx"]))].append(r)

    n_filtered = 0
    dwells = []
    for key in sorted(groups, key=lambda k: min(float(r["dwell_time_ms"]) for r in groups[k])):
        grp = groups[key]
        t = min(float(r["dwell_time_ms"]) for r in grp) / 1000.0
        head = grp[0]
        plots = []
        for r in grp:
            snr = _f(r, "snr_db")
            cls = _f(r, "classification")
            if prof.min_snr_db and snr is not None and snr < prof.min_snr_db:
                n_filtered += 1
                continue
            if prof.class_filter and cls is not None and int(cls) not in prof.class_filter:
                n_filtered += 1
                continue
            lat, lon = float(r["lat"]), float(r["lon"])
            x, y = frame.to_xy(lat, lon)
            vr = _f(r, "vel_los_cms")
            plots.append(T.Plot(
                lat=lat, lon=lon, x=x, y=y,
                vr=None if vr is None else vr / 100.0,             # cm/s → m/s
                snr_db=snr, classification=None if cls is None else int(cls),
                sigma_range_m=_sigma(r, "sig_range_cm", 100.0),    # cm → m
                sigma_cross_m=_sigma(r, "sig_xrange_dm", 10.0),    # dm → m
                sigma_vr_mps=_sigma(r, "sig_rvel_cms", 100.0),     # cm/s → m/s
            ))
        d = T.Dwell(
            t=t,
            sensor_lat=_f(head, "sensor_lat", 0.0), sensor_lon=_f(head, "sensor_lon", 0.0),
            sensor_alt_m=_f(head, "sensor_alt_m", 0.0) or 0.0,
            center_lat=_f(head, "dwell_center_lat"), center_lon=_f(head, "dwell_center_lon"),
            half_range_m=(_f(head, "dwell_range_he_km") or 0.0) * 1000.0 if _f(head, "dwell_range_he_km") else None,
            half_angle_deg=_f(head, "dwell_angle_he_deg"),
            mdv_mps=_f(head, "mdv_mps"),
            job_id=int(_f(head, "job_id")) if _f(head, "job_id") is not None else None,
            plots=plots,
        )
        dwells.append(d)
    return dwells, frame, n_filtered


# ----------------------------------------------------------------------
# Exécution
# ----------------------------------------------------------------------
def run_tracking(path, profile="defaut", overrides=None):
    """Déroule le tracker v9 sur un CSV de plots. Sortie identique au v8 (la console la dessine telle
    quelle), enrichie des indicateurs v9 : `n_plots_last`, `heading_std_deg`, `pos_std_m`, `merged_from`."""
    prof = apply_profile(profile, overrides)
    T.Track._ids = itertools.count(1)
    dwells, frame, n_filtered = csv_dwells(path, prof)
    tk = T.Tracker(prof, frame)

    raw = []
    for d in dwells:
        raw += [(p.x, p.y) for p in d.plots]
        tk.step(d)

    all_tracks = tk.archive + tk.tracks
    kept = sorted((tr for tr in all_tracks if tr.confirmed_ever), key=lambda tr: -tr.hits)
    tracks = []
    for tr in kept:
        traj = tr.trajectory()
        tracks.append({
            "id": tr.id, "hits": tr.hits,
            "etat": traj[-1][3] if traj else "",
            "vel": (float(tr.x[2]), float(tr.x[3])),
            "pts": [(x, y) for (_t, x, y, _st, _hit) in traj],
            "smooth": [(x, y) for (_t, x, y) in T.rts_smooth(tr)],
            "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator),
            # v9 : ce qui manquait pour juger une piste sans la regarder sur la carte
            "n_plots_last": tr.n_plots_last, "heading_deg": tr.heading_deg(),
            "heading_std_deg": tr.heading_std_deg(), "pos_std_m": tr.pos_std_m(),
            "merged_from": list(tr.merged_from), "absorbed_into": tr.absorbed_into,
            "absorbed": list(tr.merged_from), "extent_m": 0.0,
            "jobs": sorted(j for j in tr.job_ids if j is not None),
            "t0": traj[0][0] if traj else 0.0, "t1": traj[-1][0] if traj else 0.0,
            "n_coast": sum(1 for (_t, _x, _y, _st, hit) in traj if not hit),
        })
    res = {
        "raw": raw, "tracks": tracks, "n_kept": len(kept),
        "n_rejected": sum(1 for tr in all_tracks if not tr.confirmed_ever),
        "frame": frame, "_objs": {tr.id: tr for tr in kept},
        "config": config_dict(prof), "n_dwells": len(dwells), "n_filtered": n_filtered,
        "n_clustered": tk.n_clustered, "n_ghosts": 0, "n_swallowed": tk.n_clustered,
        "n_obs_miss": tk.n_obs_miss, "n_unobservable": tk.n_unobservable, "n_merged": tk.n_merged,
        "contacts": None, "version": "v9",
    }
    res["metrics"] = metrics(res)
    return res


def metrics(res):
    """Mêmes indicateurs que le v8, plus ceux qui disent ce que les briques v9 ont fait."""
    tr = res["tracks"]
    n = len(tr)
    base = {"n_tracks": n, "n_rejected": res["n_rejected"], "n_plots": len(res["raw"]),
            "n_dwells": res.get("n_dwells", 0), "n_filtered": res.get("n_filtered", 0),
            "n_clustered": res.get("n_clustered", 0), "n_ghosts": 0,
            "n_absorbed": sum(1 for t in tr if t.get("absorbed_into")),
            "n_swallowed": res.get("n_swallowed", 0),
            "n_obs_miss": res.get("n_obs_miss", 0), "n_unobservable": res.get("n_unobservable", 0),
            "n_merged": res.get("n_merged", 0)}
    if not n:
        return base

    def length(pts):
        return sum(math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]) for i in range(1, len(pts)))

    hits = [t["hits"] for t in tr]
    durs = [max(0.0, t["t1"] - t["t0"]) for t in tr]
    lens = [length(t["pts"]) for t in tr]
    coast = sum(t.get("n_coast", 0) for t in tr)
    pts_total = sum(len(t["pts"]) for t in tr)
    base.update({
        "hits_total": sum(hits), "hits_mean": sum(hits) / n, "hits_median": sorted(hits)[n // 2],
        "solid": sum(1 for t in tr if t["etat"] == T.SOLID),
        "confirmed": sum(1 for t in tr if t["etat"] == T.CONFIRMED),
        "coasting_end": sum(1 for t in tr if t["etat"] == T.COASTING),
        "dur_mean_s": sum(durs) / n, "dur_max_s": max(durs), "len_mean_m": sum(lens) / n,
        "coast_ratio": (coast / pts_total) if pts_total else 0.0,
        "plots_per_track": len(res["raw"]) / n,
        "air": sum(1 for t in tr if t["is_air"]), "rotator": sum(1 for t in tr if t["is_rotator"]),
        "short_tracks": sum(1 for t in tr if t["hits"] < 5),
        "heading_std_mean_deg": sum(t["heading_std_deg"] for t in tr) / n,
        "pos_std_mean_m": sum(t["pos_std_m"] for t in tr) / n,
    })
    return base


def track_detail(res, track_id):
    """Détail d'une piste du dernier run (inspection console) : historique et résumé."""
    tr = (res.get("_objs") or {}).get(int(track_id))
    if tr is None:
        raise ValueError("piste %s inconnue" % track_id)
    fr = res["frame"]
    hist = [{"t": t, "lat": round(la, 7), "lon": round(lo, 7), "etat": st, "hit": bool(hit)}
            for (t, x, y, st, hit) in tr.trajectory()
            for (la, lo) in [fr.to_ll(x, y)]]
    return {"id": tr.id, "hits": tr.hits, "etat": tr.state, "speed_mps": tr.speed(),
            "heading_deg": tr.heading_deg(), "heading_std_deg": tr.heading_std_deg(),
            "pos_std_m": tr.pos_std_m(), "classification": tr.classification,
            "is_air": tr.is_air, "is_rotator": tr.is_rotator,
            "merged_from": list(tr.merged_from), "jobs": sorted(j for j in tr.job_ids if j is not None),
            "history": hist}


load_profiles()


if __name__ == "__main__":                                  # usage direct : résumé d'un CSV
    import argparse
    ap = argparse.ArgumentParser(description="Tracker GMTI v9 sur un CSV de plots.")
    ap.add_argument("csv")
    ap.add_argument("--profile", default="maritime")
    a = ap.parse_args()
    r = run_tracking(a.csv, a.profile)
    m = r["metrics"]
    print("profil %s : %d dwells, %d plots → %d pistes confirmées (%d rejetées)"
          % (a.profile, m["n_dwells"], m["n_plots"], m["n_tracks"], m["n_rejected"]))
    print("  clustering : %d plots agrégés | miss observables : %d | miss évités (hors vue) : %d | fusions : %d"
          % (m["n_clustered"], m["n_obs_miss"], m["n_unobservable"], m["n_merged"]))
    for t in r["tracks"][:10]:
        print("  piste %3d : %3d hits, %6.1f s, cap %5.1f° ± %4.1f, %5.1f km/h, σpos %5.1f m, %s"
              % (t["id"], t["hits"], t["t1"] - t["t0"], t["heading_deg"], t["heading_std_deg"],
                 math.hypot(*t["vel"]) * 3.6, t["pos_std_m"], t["etat"]))
