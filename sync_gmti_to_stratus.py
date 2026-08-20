# -*- coding: utf-8 -*-
"""sync_gmti_to_stratus.py — copie les modules GMTI (source unique = ce dépôt) dans le paquet
`docker/app/gmti/` de StratusServer, avec les seules adaptations nécessaires (imports relatifs,
chemin du fichier de profils, lecteur pcap optionnel).

    python sync_gmti_to_stratus.py [chemin/vers/StratusServer]

Fichiers synchronisés :
  gmti_pcap_to_csv.py                      -> gmti/decode4607.py   (décodage 4607, filtre plausibilité)
  prototype_tracker_gmti_v8.1/tracker.py   -> gmti/tracker.py      (Kalman / association / absorption)
  prototype_tracker_gmti_v8.1/track_run.py -> gmti/track_run.py    (profils, prepare_plots, fusion)
  gmti_live.py                             -> gmti/live.py         (LiveTracker temps réel, géométrie dwells)
  gmti_profiles.json                       -> gmti/gmti_profiles.json (source unique, aussi lue par le processor Java)
Ne PAS éditer les copies : modifier ici puis relancer la synchro."""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.normpath(os.path.join(HERE, "..", "..", "StratusServer"))


def _tracker_dir():
    dirs = [d for d in os.listdir(HERE) if re.match(r"prototype_tracker_gmti_v[\d.]+$", d)
            and os.path.isfile(os.path.join(HERE, d, "track_run.py"))]
    dirs.sort(key=lambda d: [int(x) for x in re.findall(r"\d+", d)])
    return os.path.join(HERE, dirs[-1])


def main(argv):
    root = argv[1] if len(argv) > 1 else DEFAULT
    dst = os.path.join(root, "docker", "app", "gmti")
    if not os.path.isdir(os.path.join(root, "docker", "app")):
        print("StratusServer introuvable :", root); return 2
    os.makedirs(dst, exist_ok=True)
    tdir = _tracker_dir()
    hdr = "# GÉNÉRÉ par PCAP_tools/sync_gmti_to_stratus.py — NE PAS ÉDITER (source : %s)\n"

    s = open(os.path.join(HERE, "gmti_pcap_to_csv.py"), encoding="utf-8").read()
    s = s.replace("from pcap_frames import iter_frames, udp_payload  # noqa: E402  (lecteur commun pcap/pcapng)",
                  "try:\n    from pcap_frames import iter_frames, udp_payload  # noqa: E402  (lecteur pcap : optionnel côté service)\nexcept ImportError:  # pragma: no cover\n    iter_frames = udp_payload = None")
    open(os.path.join(dst, "decode4607.py"), "w", encoding="utf-8").write(hdr % "gmti_pcap_to_csv.py" + s)

    s = open(os.path.join(tdir, "tracker.py"), encoding="utf-8").read()
    open(os.path.join(dst, "tracker.py"), "w", encoding="utf-8").write(hdr % (os.path.basename(tdir) + "/tracker.py") + s)

    s = open(os.path.join(tdir, "track_run.py"), encoding="utf-8").read()
    s = s.replace("import tracker as T\n", "try:\n    from . import tracker as T\nexcept ImportError:  # exécution hors paquet\n    import tracker as T\n")
    # côté Stratus, gmti_profiles.json embarqué est dans le même dossier que track_run.py (pas au-dessus)
    s = s.replace('EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gmti_profiles.json")',
                  'EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gmti_profiles.json")')
    assert 'EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gmti_profiles.json")' in s, "EMBEDDED_JSON non adapté"
    open(os.path.join(dst, "track_run.py"), "w", encoding="utf-8").write(hdr % (os.path.basename(tdir) + "/track_run.py") + s)

    s = open(os.path.join(HERE, "gmti_live.py"), encoding="utf-8").read()
    open(os.path.join(dst, "live.py"), "w", encoding="utf-8").write(hdr % "gmti_live.py" + s)

    open(os.path.join(dst, "gmti_profiles.json"), "w", encoding="utf-8").write(open(os.path.join(HERE, "gmti_profiles.json"), encoding="utf-8").read())
    print("synchronisé ->", dst, "(tracker :", os.path.basename(tdir) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
