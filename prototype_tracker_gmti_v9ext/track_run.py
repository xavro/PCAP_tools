#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
track_run.py — pilote du tracker à cible étendue sur un CSV de plots (lot A).

Même signature et même sortie que `prototype_tracker_gmti_v9/track_run.py`, à quatre champs près par
piste (`extent_len_m`, `extent_wid_m`, `extent_hdg_deg`, `hull_heading_deg`) : le banc de comparaison
`compare_tracker_versions.py` le charge donc comme une version de plus, sans traitement particulier.

    python track_run.py cargo.csv --profile maritime
    python compare_tracker_versions.py cargo.csv --profile maritime --ext

La lecture du CSV, les profils, l'étage « contact » et les indicateurs sont ceux du v9, importés et non
recopiés : ce prototype doit mesurer l'apport de l'étendue, pas celui d'un code différent.
"""
from __future__ import annotations

import itertools
import math
from collections import defaultdict

from tracker_ext import T, R9, ExtTracker, ExtProfile, ext_profile, extent_axes  # noqa: F401

PROFILES = R9.PROFILES
JAVA2V9 = R9.JAVA2V9

# Réglages d'étendue conseillés par profil. Ailleurs, les défauts de `ExtProfile` s'appliquent.
EXT_TUNING = {
    # Cargo : coque de ~250 m, 1 à 3 échos par dwell. L'ellipse doit pouvoir grandir jusqu'à la coque
    # entière sans jamais couvrir deux navires distincts (600 m dans le scénario synthétique).
    "maritime": dict(ext_init_m=150.0, ext_min_m=60.0, ext_max_m=400.0, ext_tau_s=60.0),
}


def apply_profile(name, overrides=None):
    """Profil v9 nommé + surcharges, y compris les réglages `ext_*` que le v9 ignorerait."""
    over = dict(overrides or {})
    ext_keys = {f for f in ExtProfile.__dataclass_fields__ if f not in T.Profile.__dataclass_fields__}
    ext_over = {k: over.pop(k) for k in list(over) if k in ext_keys}
    prof9 = R9.apply_profile(name, over)
    kw = dict(EXT_TUNING.get(name, {}))
    for k, v in ext_over.items():
        default = getattr(ExtProfile, k, None)
        kw[k] = bool(v) if isinstance(default, bool) else float(v)
    return ext_profile(prof9, **kw)


def config_dict(prof):
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in prof.__dict__.items()}


def run_tracking(path, profile="defaut", overrides=None):
    """Déroule le tracker à cible étendue sur un CSV de plots. Sortie compatible v8/v9."""
    prof = apply_profile(profile, overrides)
    T.Track._ids = itertools.count(1)
    dwells, frame, n_filtered = R9.csv_dwells(path, prof)
    tk = ExtTracker(prof, frame)

    raw = []
    merger = R9.ContactMerger(prof)
    contacts = defaultdict(lambda: {"pts": [], "n_max": 1, "hits": 0, "members": set()})
    for d in dwells:
        raw += [(p.x, p.y) for p in d.plots]
        tk.step(d)
        if merger.enabled():
            outs = [{"track_id": tr.id, "x": float(tr.x[0]), "y": float(tr.x[1]), "speed": tr.speed(),
                     "heading": tr.heading_deg(), "state": tr.state, "hits": tr.hits,
                     "is_air": tr.is_air, "is_rotator": tr.is_rotator}
                    for tr in tk.tracks if tr.state != T.TENTATIVE]
            for c in merger.merge(outs, d.t):
                cc = contacts[c["id"]]
                cc["pts"].append((d.t, c["x"], c["y"]))
                cc["n_max"] = max(cc["n_max"], c["n"])
                cc["hits"] = max(cc["hits"], c["hits"])
                cc["members"].update(c["members"])

    all_tracks = tk.archive + tk.tracks
    kept = sorted((tr for tr in all_tracks if tr.confirmed_ever), key=lambda tr: -tr.hits)
    tracks = []
    for tr in kept:
        traj = tr.trajectory()
        length, width, ext_hdg = extent_axes(tr.X)
        hull = tr.hull_heading_deg()
        tracks.append({
            "id": tr.id, "hits": tr.hits,
            "etat": traj[-1][3] if traj else "",
            "vel": (float(tr.x[2]), float(tr.x[3])),
            "pts": [(x, y) for (_t, x, y, _st, _hit) in traj],
            "smooth": [(x, y) for (_t, x, y) in T.rts_smooth(tr)],
            "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator),
            "n_plots_last": tr.n_plots_last, "heading_deg": tr.reported_heading_deg(),
            "heading_std_deg": tr.heading_std_deg(), "pos_std_m": tr.pos_std_m(),
            "merged_from": list(tr.merged_from), "absorbed_into": tr.absorbed_into,
            "absorbed": list(tr.merged_from), "extent_m": round(float(tr.extent), 1),
            # Ce que l'estimateur apporte en propre : la forme, et le cap qu'elle donne.
            "extent_len_m": round(length, 1), "extent_wid_m": round(width, 1),
            "extent_hdg_deg": round(ext_hdg, 1),
            "hull_heading_deg": None if hull is None else round(hull, 1),
            "kin_heading_deg": tr.heading_deg(), "n_echoes": tr.n_echoes, "nu": round(tr.nu, 1),
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
        "n_absorbed_meas": tk.n_absorbed_meas, "n_births_blocked": tk.n_births_blocked,
        "n_multi_echo": tk.n_multi_echo, "n_extra_echo": tk.n_extra_echo,
        "contacts": ([{"id": cid, "pts": [(x, y) for (_t, x, y) in c["pts"]], "n_max": c["n_max"],
                       "hits": c["hits"], "members": sorted(c["members"])}
                      for cid, c in contacts.items()] if merger.enabled() else None),
        "contacts_t": ({cid: [t for (t, _x, _y) in c["pts"]] for cid, c in contacts.items()}
                       if merger.enabled() else None),
        "version": "v9ext",
    }
    res["metrics"] = metrics(res)
    return res


def metrics(res):
    """Indicateurs du v9, plus ceux qui décrivent l'étendue estimée."""
    base = R9.metrics(res)
    tr = res["tracks"]
    base.update({"n_multi_echo": res.get("n_multi_echo", 0), "n_extra_echo": res.get("n_extra_echo", 0)})
    if tr:
        lens = [t["extent_len_m"] for t in tr]
        base["extent_len_mean_m"] = sum(lens) / len(lens)
        base["extent_len_max_m"] = max(lens)
        base["n_hull_heading"] = sum(1 for t in tr if t["hull_heading_deg"] is not None)
    return base


def track_detail(res, track_id):
    return R9.track_detail(res, track_id)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Tracker GMTI à cible étendue (lot A) sur un CSV de plots.")
    ap.add_argument("csv")
    ap.add_argument("--profile", default="maritime")
    ap.add_argument("--overrides", default="", help="ex. ext_z=0.25,heading_from_extent=1")
    a = ap.parse_args(argv)
    over = {}
    for kv in filter(None, a.overrides.split(",")):
        k, _, v = kv.partition("=")
        over[k.strip()] = v
    res = run_tracking(a.csv, a.profile, over)
    m = res["metrics"]
    print("%d dwells, %d plots → %d pistes confirmées (%d rejetées)"
          % (m["n_dwells"], m["n_plots"], m["n_tracks"], m["n_rejected"]))
    print("échos surnuméraires absorbés : %d ; naissances refusées dans une ellipse : %d"
          % (m["n_extra_echo"], m["n_births_blocked"]))
    for t in res["tracks"][:10]:
        print("  piste %d : %d hits, %d échos, %.1f km/h cap %.1f° | coque %.0f × %.0f m, axe %.0f°%s"
              % (t["id"], t["hits"], t["n_echoes"], math.hypot(*t["vel"]) * 3.6, t["heading_deg"],
                 t["extent_len_m"], t["extent_wid_m"], t["extent_hdg_deg"],
                 "" if t["hull_heading_deg"] is None else " → cap coque %.0f°" % t["hull_heading_deg"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
