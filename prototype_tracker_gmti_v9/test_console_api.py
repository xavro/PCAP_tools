#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_console_api.py — le tracker v9 est-il vraiment interchangeable avec le v8 pour la console ?

Trois essais serveur de suite ont échoué sur le même motif : le tracker sélectionné n'est pas seulement
un algorithme, c'est un CONTRAT avec `pcap_web` (analyse d'un pcap, inspection d'une piste, barre de temps,
profils) et avec `gmti_live` (pistage direct de la console et du service GMTI). Une constante manquante
suffit à ne plus produire aucune piste, sans que rien d'autre ne le signale.

Ce test parcourt ce contrat de bout en bout avec le v9 sélectionné, sur une vraie capture. À lancer après
toute modification du tracker, du chargeur de version ou de `gmti_live` :

    python test_console_api.py [capture.pcap] [--port 5454] [--profile maritime]
"""
import argparse
import importlib.util
import itertools
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
DEFAULT_PCAP = os.path.join(os.path.dirname(os.path.dirname(TOOLS)),
                            "StratusServer-v2", "docker", "data", "captures", "20260812_CaptureALL_CR2.pcap")

ok_count = fail = 0


def check(label, cond, detail=""):
    global ok_count, fail
    if cond:
        ok_count += 1
        print("  OK    %s%s" % (label, (" — " + detail) if detail else ""))
    else:
        fail += 1
        print("  ECHEC %s%s" % (label, (" — " + detail) if detail else ""))


def load_pcap_web():
    spec = importlib.util.spec_from_file_location("pcap_web_test", os.path.join(TOOLS, "pcap_web.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv=None):
    ap = argparse.ArgumentParser(description="Contrat console du tracker GMTI sélectionné.")
    ap.add_argument("pcap", nargs="?", default=DEFAULT_PCAP)
    ap.add_argument("--port", type=int, default=5454)
    ap.add_argument("--profile", default="maritime")
    a = ap.parse_args(argv)
    os.chdir(TOOLS)

    print("== sélection de version ==")
    pw = load_pcap_web()
    print("  tracker retenu :", pw.tracker_version())
    check("extracteur 4607 localisé", bool(pw._tool_dir("stanag4607_extract.py")))
    check("oracle de parité localisé", bool(pw._tool_dir("parity_export.py")))

    print("\n== module tracker : attributs utilisés par la console ==")
    tr = pw.load_track_run()
    T = sys.modules["tracker"]
    for name in ("TENTATIVE", "CONFIRMED", "SOLID", "COASTING", "DEAD",
                 "LocalFrame", "Plot", "Track", "Tracker", "rts_smooth", "rts_tail"):
        check("tracker.%s" % name, hasattr(T, name))
    for name in ("PROFILES", "PROFILES_JSON", "load_profiles", "apply_profile", "java_config",
                 "run_tracking", "track_detail", "metrics"):
        check("track_run.%s" % name, hasattr(tr, name))
    check("un étage de fusion existe", hasattr(tr, "ContactMerger") or hasattr(tr, "TrackMerger"))
    check("profils exposés", set(tr.PROFILES) >= {"defaut", "maritime", "routier_zone"},
          ", ".join(sorted(tr.PROFILES)))

    print("\n== analyse d'un pcap (onglet GMTI) ==")
    if not os.path.isfile(a.pcap):
        print("  capture absente : %s — étapes suivantes ignorées" % a.pcap)
        return 1 if fail else 0
    entry = pw.gmti_decode(a.pcap)
    check("décodage GMTI", entry.get("csv") is not None, "%d plots, %d dwells" % (entry["n_plots"], entry["dwells"]))
    out = pw.gmti_track(entry, a.profile, None)
    check("pistage hors ligne", len(out["tracks"]) > 0, "%d pistes, %d plots affichés" % (len(out["tracks"]), out["n_raw"]))
    check("métriques présentes", isinstance(out.get("metrics"), dict) and out["metrics"].get("n_tracks") is not None)

    print("\n== inspection d'une piste ==")
    res = entry["res"][list(entry["res"])[0]]
    d = tr.track_detail(res, out["tracks"][0]["id"])
    for k in ("hist", "assoc", "gates", "gate_chi2", "gate_max_m", "n_hist", "speed_mean", "misses"):
        check("track_detail.%s" % k, d is not None and k in d)
    check("historique non vide", bool(d and d["hist"]), "%d points, %d associations" % (len(d["hist"]), len(d["assoc"])))

    print("\n== barre de temps (pistes datées sur la capture) ==")
    tl = {"dwell_offset": 0.0, "t0": 0.0}
    try:
        rows = pw.timeline_tracks(entry, a.profile, None, tl)
        check("timeline_tracks", isinstance(rows, list), "%d pistes" % len(rows))
    except Exception as e:
        check("timeline_tracks", False, "%s : %s" % (type(e).__name__, e))

    print("\n== pistage TEMPS RÉEL (console en écoute, service GMTI) ==")
    sys.path.insert(0, TOOLS)
    import gmti_live
    import gmti_pcap_to_csv as G
    from pcap_frames import iter_frames
    lt = gmti_live.LiveTracker(tr, T, a.profile)
    n_pkt = 0
    try:
        for _ts, lk, frame in iter_frames(a.pcap):
            r = G.udp_payload(lk, frame)
            if not r or r[0] != a.port or not G.looks_like_4607(r[1]):
                continue
            n_pkt += 1
            lt.step_dwells(G.decode_packet_dwells(r[1]))
        snap = lt.snapshot()
        check("dwells traités", lt.n_dwells > 0, "%d dwells, %d plots" % (lt.n_dwells, lt.n_plots))
        check("pistes vivantes en direct", len(snap["tracks"]) > 0, "%d pistes" % len(snap["tracks"]))
        check("traîne d'affichage", all(t["tail"] for t in snap["tracks"]))
        check("champs d'affichage", all({"id", "lat", "lon", "speed", "heading", "state", "hits",
                                         "misses", "ever", "is_air", "is_rotator"} <= set(t) for t in snap["tracks"]))
        check("statistiques", isinstance(snap["stats"], dict) and "n_dwells" in snap["stats"])
    except Exception as e:
        check("pistage direct", False, "%s : %s" % (type(e).__name__, e))

    print("\n%d contrôles OK, %d échecs" % (ok_count, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
