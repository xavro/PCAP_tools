# -*- coding: utf-8 -*-
"""Le pistage TEMPS REEL fonctionne-t-il sous v9 ? Ce chemin n'a jamais tourne en service.

`live.py` detecte la generation et suit deux chemins : le v8 recoit `step(t, plots)`, le v9 un pistage
par DWELL avec les champs d'empreinte. Basculer la preprod sans avoir exerce ce chemin reviendrait a en
decouvrir les defauts en operation. On rejoue donc une capture pcap reelle a travers le LiveTracker,
exactement comme le service le fait sur le flux : decodage 4607 -> step_dwells -> snapshot."""
import os, sys, time
TOOLS = r"C:\Users\xavco\Documents\Mes Projets\DATA\Tools"
sys.path.insert(0, TOOLS)
import gmti_pcap_to_csv as G
import gmti_live as L

PCAP = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\xavco\Documents\Mes Projets\StratusServer-v2\docker\data\captures\20260902_0737Z_CR1\Capture\20260902_0737Z_CR1_003.pcap"
PORT = 5454
ok = fail = 0
def chk(l, c, d=""):
    global ok, fail
    if c: ok += 1; print("  OK    %s" % l)
    else: fail += 1; print("  ECHEC %s  %s" % (l, d))

for gen, dossier in (("v8.1", "prototype_tracker_gmti_v8.1"), ("v9", "prototype_tracker_gmti_v9")):
    sys.path.insert(0, os.path.join(TOOLS, dossier))
    for m in ("tracker", "track_run"):
        sys.modules.pop(m, None)
    import importlib
    T = importlib.import_module("tracker"); R = importlib.import_module("track_run")
    lt = L.LiveTracker(R, T, profile="maritime")
    print("\n%s — LiveTracker se declare %s" % (gen, "v9" if getattr(lt, "v9", False) else "v8"))
    chk("generation correctement detectee", getattr(lt, "v9", False) == (gen == "v9"))
    n_dwells = n_plots = 0
    t0 = time.time()
    for _ts, lien, frame in G.iter_frames(PCAP):
        r = G.udp_payload(lien, frame)
        if not r or r[0] != PORT:
            continue
        dw = G.decode_packet_dwells(r[1])
        if not dw:
            continue
        try:
            lt.step_dwells(dw)
        except Exception as e:
            chk("step_dwells sans erreur", False, "%s: %s" % (type(e).__name__, e)); break
        n_dwells += len(dw); n_plots += sum(len(d["rows"]) for d in dw)
        if n_dwells >= 4000:
            break
    else:
        chk("step_dwells sans erreur", True)
    dt = time.time() - t0
    try:
        snap = lt.snapshot()
        pistes = snap.get("tracks") or []
        chk("snapshot exploitable", isinstance(pistes, list))
        conf = [p for p in pistes if p.get("ever")]
        print("    %d dwells, %d plots en %.1f s (%.0f dwells/s) -> %d pistes dont %d confirmees"
              % (n_dwells, n_plots, dt, n_dwells / max(dt, 1e-9), len(pistes), len(conf)))
        if gen == "v9":
            chk("des pistes confirmees sont produites", len(conf) > 0, "%d pistes" % len(pistes))
        else:
            # Le v8.1 ne confirme rien sur ce flux maritime : chaque dwell pointe ailleurs compte comme
            # un manque, faute de brique d'observabilite. Ce n'est pas un defaut du test, c'est la
            # mesure qui a motive le passage au v9 — on la journalise plutot que de l'exiger.
            print("    (v8.1 : %d confirmees — la brique d'observabilite lui manque sur ce flux)" % len(conf))
        if conf:
            p = max(conf, key=lambda x: x.get("hits", 0))
            # Champs que le widget ExB et le processor consomment : les deux generations doivent les fournir.
            champs = ("id", "lat", "lon", "speed", "heading", "state", "hits", "ever", "tail")
            chk("champs attendus par le widget presents", all(c in p for c in champs),
                sorted(set(champs) - set(p)))
    except Exception as e:
        chk("snapshot sans erreur", False, "%s: %s" % (type(e).__name__, e))
    sys.path.remove(os.path.join(TOOLS, dossier))

print("\n%d controles OK, %d echecs" % (ok, fail))
sys.exit(1 if fail else 0)
