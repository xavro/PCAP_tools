#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_extended.py — l'estimateur d'étendue mesure-t-il la bonne coque ?

Sur les captures réelles il n'y a pas de vérité terrain : impossible d'y distinguer « l'ellipse est
juste » de « l'ellipse est fausse mais le suivi tient quand même ». On rejoue donc les scénarios
synthétiques du v9, dont la géométrie est connue :

  A — un navire de 220 m (diffuseurs à -110 / 0 / +110 m le long de la coque), cap 135°, 28,8 km/h,
      bruit anisotrope 10 m en distance / 100 m en travers ;
  B — deux navires PARALLÈLES distants de 600 m : l'étendue doit s'arrêter à la coque, pas avaler
      le voisin. C'est le garde-fou qui empêche l'estimateur de « réussir » en fusionnant tout.

Attendus : A → une seule piste, longueur estimée dans [150, 320] m (la vraie coque vue par le radar
fait 220 m entre diffuseurs extrêmes), cap de coque à moins de 20° de 135° ; B → deux pistes.

    python test_extended.py
"""
import collections
import math
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import tracker_ext as X                                    # noqa: E402

# Le générateur de scénarios vit dans le v9 : on le réutilise tel quel plutôt que de le recopier (une
# copie divergerait, et c'est justement la comparaison avec le v9 qui nous intéresse). On lui présente
# LES MÊMES objets modules que ceux qu'utilise `tracker_ext`, pour n'avoir qu'un seul `tracker` en vie.
sys.modules["tracker"] = X.T
sys.modules["track_run"] = X.R9
sys.path.insert(0, X.V9_DIR)
import test_synthetic as S                                 # noqa: E402

T = X.T
LONGUEUR_VRAIE = 220.0                                     # -110 → +110 m entre diffuseurs extrêmes


def run_ext(dwells, prof):
    T.Track._ids = __import__("itertools").count(1)
    tk = X.ExtTracker(prof, T.LocalFrame(S.LAT0, S.LON0))
    snaps = []
    for d in dwells:
        tk.step(d)
        snaps.append(tk.snapshot(d.t))
    return tk, snaps


def profil(**kw):
    """Profil maritime du v9 + étendue. Conditions nominales du brief pour le Doppler, comme le test v9
    (la capture réelle a un Doppler inexploitable ; le scénario, lui, suit la convention)."""
    base = T.profile_with(X.R9.PROFILES["maritime"], doppler_enabled=True, sigma_vr_floor_mps=0.0,
                          cluster_eps_vr_mps=3.0)
    return X.ext_profile(base, **kw)


def main():
    ok = True
    prof = profil()

    frame = T.LocalFrame(S.LAT0, S.LON0)
    tk, snaps = run_ext(S.scenario_a(frame, np.random.default_rng(1)), prof)
    spans = collections.OrderedDict()
    for k, sn in enumerate(snaps):
        for s in sn:
            if s["state"] != T.TENTATIVE:
                spans.setdefault(s["track_id"], [k, k])[1] = k
    main_trk = max(snaps[-1], key=lambda s: s["hits"])
    tid = main_trk["track_id"]
    tail = [s for sn in snaps[-60:] for s in sn if s["track_id"] == tid]
    lon_est = float(np.median([s["extent_len_m"] for s in tail]))
    lar_est = float(np.median([s["extent_wid_m"] for s in tail]))
    hulls = [s["hull_heading_deg"] for s in tail if s["hull_heading_deg"] is not None]
    hdg = [s["heading_deg"] for s in tail]
    spd = [s["speed_kmh"] for s in tail]

    print("[A] pistes confirmées (id : dwell début→fin) :", dict(spans))
    print("[A] piste principale %d : %d hits, %d échos" % (tid, main_trk["hits"], main_trk["n_echoes"]))
    print("[A] coque estimée : %.0f × %.0f m (vraie longueur %.0f m), allongement %.2f"
          % (lon_est, lar_est, LONGUEUR_VRAIE, lon_est / max(lar_est, 1e-6)))
    print("[A] cap de coque : %s (vrai 135°) sur %d/%d instantanés"
          % ("%.1f°" % np.mean(hulls) if hulls else "indisponible", len(hulls), len(tail)))
    print("[A] cinématique : cap %.1f° ± %.2f, vitesse %.1f km/h (vrai 135° / 28.8 km/h)"
          % (np.mean(hdg), np.std(hdg), np.mean(spd)))

    ok_ids = len(spans) == 1
    ok_len = 150.0 <= lon_est <= 320.0
    ok_hdg = bool(hulls) and abs((np.mean(hulls) - 135 + 180) % 360 - 180) <= 20
    ok_kin = abs(np.mean(spd) - 28.8) < 4.0
    for label, cond in (("une seule identité", ok_ids), ("longueur plausible", ok_len),
                        ("cap de coque", ok_hdg), ("cinématique", ok_kin)):
        print("   %-22s %s" % (label, "OK" if cond else "ECHEC"))
        ok = ok and cond

    tk_b, snaps_b = run_ext(S.scenario_b(frame, np.random.default_rng(2)), prof)
    n_b = sum(1 for s in snaps_b[-1] if s["state"] != T.TENTATIVE)
    lens_b = [s["extent_len_m"] for s in snaps_b[-1] if s["state"] != T.TENTATIVE]
    print("[B] deux navires à 600 m → %d piste(s), coques %s"
          % (n_b, ", ".join("%.0f m" % v for v in lens_b)))
    ok_b = n_b == 2 and all(v < 500 for v in lens_b)      # ne pas « réussir » en avalant le voisin
    print("   %-22s %s" % ("deux cibles séparées", "OK" if ok_b else "ECHEC"))
    ok = ok and ok_b

    print("RESULTAT :", "OK" if ok else "ECHEC")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
