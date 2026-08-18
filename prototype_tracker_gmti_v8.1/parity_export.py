# -*- coding: utf-8 -*-
"""parity_export.py — oracle de PARITÉ pour le portage Java du tracker.

Rejoue un CSV de plots (schéma gmti_pcap_to_csv) dwell par dwell avec le tracker
de référence v8.1 et exporte, POUR CHAQUE DWELL, l'état des pistes AFFICHABLES
(confirmée / solide / coasting — ce que le processor Java émet). Le fichier produit
sert d'oracle au test JUnit TrackerParityTest côté Receiver4607.

Usage :
  python parity_export.py <plots.csv> <profil> <sortie.csv>
Ex. :
  python parity_export.py ../plots.csv routier parity_expected_routier.csv

Sortie (délimiteur ';') :
  dwell_time_ms;track_id;state;lat;lon;hits;aerien;rotateur
Les identifiants de piste NE coïncident PAS avec ceux du Java (compteurs distincts) :
le comparateur apparie les pistes par proximité de position, pas par id.
"""
import sys

import tracker as T
import track_run as TR

# États affichables (mêmes que le fan-out Java : tout sauf TENTATIVE/DEAD).
DISPLAYABLE = {T.CONFIRMED, T.SOLID, T.COASTING}


def export(csv_in, profile, csv_out, overrides=None):
    """`overrides` : surcharges (noms Java TrackerConfig ou Params) — mêmes que le banc web."""
    TR.apply_profile(profile, overrides)
    import itertools
    T.Track._ids = itertools.count(1)
    tk = T.Tracker()
    rows = []
    for t, plots, frame in TR.csv_dwells(csv_in):
        tk.step(t, plots)
        ms = int(round(t * 1000.0))
        for tr in tk.tracks:
            st = tr.state
            # Affichable au sens du processor Java : confirmée AU MOINS une fois
            # (une piste seulement TENTATIVE n'est jamais émise ; seule une piste
            # déjà confirmée peut passer COASTING).
            if st not in DISPLAYABLE or not tr.confirmed_ever:
                continue
            lat, lon = frame.to_ll(tr.x[0], tr.x[1])
            rows.append((ms, tr.id, st, lat, lon, tr.hits,
                         int(bool(tr.is_air)), int(bool(tr.is_rotator))))
    with open(csv_out, "w", encoding="utf-8") as f:
        f.write("dwell_time_ms;track_id;state;lat;lon;hits;aerien;rotateur\n")
        for ms, tid, st, lat, lon, hits, air, rot in rows:
            f.write("%d;%d;%s;%.7f;%.7f;%d;%d;%d\n" % (ms, tid, st, lat, lon, hits, air, rot))
    print("parity_export : %d lignes (%s) -> %s" % (len(rows), profile, csv_out))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    export(sys.argv[1], sys.argv[2], sys.argv[3])
