# -*- coding: utf-8 -*-
"""sync_gmti_to_stratus.py — copie les modules GMTI (source unique = ce dépôt) dans le paquet
`docker/app/gmti/` de StratusServer, avec les seules adaptations nécessaires (imports relatifs,
chemin du fichier de profils, lecteur pcap optionnel).

    python sync_gmti_to_stratus.py [chemin/vers/StratusServer] [--tracker prototype_tracker_gmti_vX]

Le dossier de tracker retenu est le PLUS RECENT present ici. Comme cela peut faire changer de version
la chaine en service sans qu'on l'ait voulu (le v9 a ete cree bien apres la derniere synchro, qui avait
depose du v8.1), la synchro REFUSE de changer de version sans `--tracker` explicite.

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


def _version_deployee(dst):
    """Version du tracker actuellement deposee, lue dans l'en-tete genere. None si rien n'est depose."""
    try:
        tete = open(os.path.join(dst, "tracker.py"), encoding="utf-8").readline()
    except OSError:
        return None
    m = re.search(r"source : (prototype_tracker_gmti_v[\d.]+)/", tete)
    return m.group(1) if m else None


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    choisi = None
    for a in argv[1:]:
        if a.startswith("--tracker="):
            choisi = a.split("=", 1)[1]
        elif a == "--tracker":
            choisi = argv[argv.index(a) + 1]
            args = [x for x in args if x != choisi]
    root = args[0] if args else DEFAULT
    dst = os.path.join(root, "docker", "app", "gmti")
    if not os.path.isdir(os.path.join(root, "docker", "app")):
        print("StratusServer introuvable :", root); return 2
    os.makedirs(dst, exist_ok=True)
    tdir = os.path.join(HERE, choisi) if choisi else _tracker_dir()
    if not os.path.isdir(tdir):
        print("dossier de tracker introuvable :", tdir); return 2
    # Garde-fou : deposer une AUTRE version que celle en service est une decision, pas un effet de bord
    # d'un `sync` de routine. On l'exige explicite.
    en_service = _version_deployee(dst)
    if choisi is None and en_service and en_service != os.path.basename(tdir):
        print("REFUS : la chaine en service utilise %s, la synchro deposerait %s."
              % (en_service, os.path.basename(tdir)))
        print("        Changer de version est une decision separee. Relancer avec :")
        print("          --tracker %s   (garder la version en service)" % en_service)
        print("          --tracker %s   (passer a la nouvelle version)" % os.path.basename(tdir))
        return 3
    hdr = "# GÉNÉRÉ par PCAP_tools/sync_gmti_to_stratus.py — NE PAS ÉDITER (source : %s)\n"

    s = open(os.path.join(HERE, "gmti_pcap_to_csv.py"), encoding="utf-8").read()
    s = s.replace("from pcap_frames import iter_frames, udp_payload  # noqa: E402  (lecteur commun pcap/pcapng)",
                  "try:\n    from pcap_frames import iter_frames, udp_payload  # noqa: E402  (lecteur pcap : optionnel côté service)\nexcept ImportError:  # pragma: no cover\n    iter_frames = udp_payload = None")
    open(os.path.join(dst, "decode4607.py"), "w", encoding="utf-8").write(hdr % "gmti_pcap_to_csv.py" + s)

    s = open(os.path.join(tdir, "tracker.py"), encoding="utf-8").read()
    open(os.path.join(dst, "tracker.py"), "w", encoding="utf-8").write(hdr % (os.path.basename(tdir) + "/tracker.py") + s)

    s = open(os.path.join(tdir, "track_run.py"), encoding="utf-8").read()
    s = s.replace("import tracker as T\n", "try:\n    from . import tracker as T\nexcept ImportError:  # exécution hors paquet\n    import tracker as T\n")
    # Côté Stratus, gmti_profiles.json embarqué est dans le même dossier que track_run.py, pas au-dessus.
    # Les deux générations nomment cette constante différemment (v8.1 : EMBEDDED_JSON ; v9 : PROFILES_JSON
    # calculé depuis HERE) : on adapte celle qui est présente, et on refuse de livrer si aucune ne l'est —
    # un service qui cherche ses profils au mauvais endroit repart silencieusement sur ses valeurs par défaut.
    remplacements = [
        ('EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gmti_profiles.json")',
         'EMBEDDED_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gmti_profiles.json")'),
        ('PROFILES_JSON = os.environ.get("GMTI_PROFILES") or os.path.join(os.path.dirname(HERE), "gmti_profiles.json")',
         'PROFILES_JSON = os.environ.get("GMTI_PROFILES") or os.path.join(HERE, "gmti_profiles.json")'),
    ]
    adapte = False
    for avant, apres in remplacements:
        if avant in s:
            s = s.replace(avant, apres)
            adapte = True
    assert adapte, "chemin du fichier de profils non adapté : la source a changé, vérifier track_run.py"
    open(os.path.join(dst, "track_run.py"), "w", encoding="utf-8").write(hdr % (os.path.basename(tdir) + "/track_run.py") + s)

    s = open(os.path.join(HERE, "gmti_live.py"), encoding="utf-8").read()
    open(os.path.join(dst, "live.py"), "w", encoding="utf-8").write(hdr % "gmti_live.py" + s)

    open(os.path.join(dst, "gmti_profiles.json"), "w", encoding="utf-8").write(open(os.path.join(HERE, "gmti_profiles.json"), encoding="utf-8").read())
    print("synchronisé ->", dst, "(tracker :", os.path.basename(tdir) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
