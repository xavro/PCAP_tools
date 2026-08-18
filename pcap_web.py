#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap_web.py — console web pcap : analyse (4607 GMTI → pistes, 4609 vidéo + KLV, CoT),
rejeu UDP/TCP routé avec vue « ce que voit le client », carte unique, exports.

Serveur HTTP local (bibliothèque standard) + page web (pcap_web/static) :
  • le navigateur lit le MPEG-TS/H.264 avec mpegts.js (MSE) — pas de ffmpeg ;
  • mpegts.js remonte les sets KLV synchrones avec leur PTS recalé sur la timeline
    vidéo → décodage MISB 0601 côté navigateur, synchro exacte image/métadonnées ;
  • carte Leaflet (position capteur, empreinte, centre image, trace plateforme),
    fond ArcGIS via proxy (arcgis_basemap) ;
  • deux modes : FICHIER (TS extrait, seek libre) et REJEU : un moteur unique
    (pcap_replay.do_routed_replay) émet les flux cochés en UDP/TCP vers les cibles
    (fan-out) ET alimente l'IHM via WebSocket — /ws/video (TS binaire → mpegts.js,
    « ce que voit le client ») et /ws/events (JSON : progression, journal) ;
  • fond de carte configurable depuis l'IHM : ArcGIS Online (internet, défaut) ou
    MapServer local via proxy (basemap.json).

Usage :
  python pcap_web.py [capture.pcap] [--port 8765] [--limit N] [--no-browser]

API :
  GET /                         page
  GET /api/streams?pcap=&limit= inventaire des flux TS (PID, codecs, KLV, durée)
  GET /api/klv?pcap=&dport=     trace KLV complète (t relatif vidéo, position, empreinte)
  GET /video.ts?pcap=&dport=    TS réassemblé (Range supporté)
  GET /live.ts?pcap=&dport=&speed=&loop=  TS cadencé temps réel (chunked, sans UDP)
  GET /api/flows?pcap=&limit=   flux applicatifs (pcap_analyze) pour le routage
  POST /api/replay/start        {pcap, routes:[{proto,dport,targets:[ip[:port]]}], speed, loop, rebase,
                                 taps:[dport], watch:[...], track:{profile, overrides}} → démarre le
                                 moteur de rejeu (track = pistage GMTI temps réel, pistes dans les lots gmti)
  POST /api/replay/stop         arrêt propre
  POST /api/replay/pause {paused} · /api/replay/speed {speed} · /api/replay/seek {t}  transport
                                (pause/reprise, vitesse à chaud, saut = redémarrage avec rembobinage à blanc)
  GET /api/replay/status        état courant
  WS  /ws/events                événements JSON (replay/log/end)
  WS  /ws/video?dport=          TS binaire du flux tapé (mpegts.js WebSocket loader)
  GET/POST /api/basemap         config fond de carte (basemap.json)
  GET/POST /api/settings        réglages (dernier pcap, récents, IHM) — pcap_web_settings.json
  GET /api/browse?dir=          explorateur de fichiers côté serveur (dossiers + captures)
  GET /basemap?bbox=&w=&h=&sr=  PNG fond de carte (proxy ArcGIS MapServer export dynamique)
  GET /api/gmti/decode?pcap=    décodage GMTI (extracteur complet | streaming) + inventaire 4607
  GET /api/gmti/track?pcap=&profile=&overrides={json}  tracker (profil + surcharges, noms Java) → pistes,
                                plots bruts, zone job, porteur, contacts (fusion), métriques, config effective
  GET/POST /api/gmti/profiles   profils du tracker (source unique gmti_profiles.json, partagée avec le Java)
  GET /api/gmti/track/detail?pcap=&profile=&overrides=&id=  inspection d'une piste (historique, plots
                                associés + d², gates 2σ, vitesses)
  GET /api/timeline?pcap=&watch=&profile=&overrides=  ligne de temps préchargée (mode Lecture IHM seule) :
                                CoT datés, dwells/plots GMTI datés, offsets vidéo, pistes du run hors ligne datées
  GET /api/gmti/parity.zip?pcap=&profile=&overrides=&name=  oracle de parité pour TrackerParityTest (Java) :
                                <nom>.input.csv + <nom>.expected.csv + <nom>.profile.json
  GET /api/cot/scan?pcap=&filter=     analyse CoT statique (objets, traces, inventaire des types)
  GET /api/cot/event?pcap=&uid=       dernier event XML d'un uid
  GET /api/fused/export.geojson?pcap=&profile=  fusion GMTI + CoT + capteur vidéo (WGS84)
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
import queue
import socket
import struct
import sys
import tempfile
import threading
import time
import types
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pcap_replay import iter_frames, parse                       # noqa: E402
import pcap_replay                                                # noqa: E402
import pcap_analyze                                               # noqa: E402
import video4609 as v9                                            # noqa: E402
import xml.etree.ElementTree as ET                                # noqa: E402
try:
    import gmti_pcap_to_csv                                       # noqa: E402
except Exception:
    gmti_pcap_to_csv = None
try:
    import cot_extract                                            # noqa: E402
except Exception:
    cot_extract = None
try:
    import arcgis_basemap                                         # noqa: E402
except Exception:
    arcgis_basemap = None

STATIC_DIR = os.path.join(HERE, "pcap_web", "static")
TS_PKT = 188
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
        ".css": "text/css", ".png": "image/png", ".txt": "text/plain; charset=utf-8",
        ".json": "application/json"}


# ── Scan pcap → flux TS + horodatages par datagramme ─────────────────────────
class TsStream:
    __slots__ = ("dst", "dport", "buf", "pkts", "t0", "t1", "info")

    def __init__(self, dst, dport):
        self.dst, self.dport = dst, dport
        self.buf = bytearray()
        self.pkts = []          # (ts_pcap, offset, longueur) pour le cadencement live
        self.t0 = self.t1 = None
        self.info = None


_CACHE = {}
_LOCK = threading.Lock()


def scan(path, limit=0):
    """{dport: TsStream} — mis en cache par (path, mtime, limit)."""
    key = (os.path.abspath(path), os.path.getmtime(path), int(limit or 0))
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
    streams = {}
    n = 0
    for ts, lt, frame in iter_frames(path):
        n += 1
        if limit and n > limit:
            break
        r = parse(lt, frame)
        if not r:
            continue
        proto, src, sport, dst, dport, pl = r
        if proto != "UDP":
            continue
        tsdata = v9._ts_from_udp(pl)
        if not tsdata:
            continue
        st = streams.get(dport)
        if st is None:
            st = streams[dport] = TsStream(dst, dport)
            st.t0 = ts
        st.pkts.append((ts, len(st.buf), len(tsdata)))
        st.buf.extend(tsdata)
        st.t1 = ts
    for st in streams.values():
        st.info = v9.analyze_stream(st.buf)
    with _LOCK:
        _CACHE[key] = streams
    return streams


# ── PES / KLV avec PTS ───────────────────────────────────────────────────────
def _pts(b):
    return (((b[0] >> 1) & 0x07) << 30) | (b[1] << 22) | ((b[2] >> 1) << 15) | (b[3] << 7) | (b[4] >> 1)


def pes_units(buf, pid):
    """Itère (pts_90k ou None, payload) des unités PES d'un PID."""
    cur, cur_pts = None, None
    for pkt in v9._iter_ts(buf):
        if v9._pid(pkt) != pid:
            continue
        pl = v9._payload(pkt)
        if pkt[1] & 0x40:                                   # PUSI
            if cur is not None:
                yield cur_pts, bytes(cur)
            cur, cur_pts = bytearray(), None
            if len(pl) >= 9 and pl[0] == 0 and pl[1] == 0 and pl[2] == 1:
                flags2, hlen = pl[7], pl[8]
                if flags2 & 0x80 and len(pl) >= 14:
                    cur_pts = _pts(pl[9:14])
                pl = pl[9 + hlen:]
        if cur is not None:
            cur.extend(pl)
    if cur is not None:
        yield cur_pts, bytes(cur)


def first_pts(buf, pid):
    for pts, _ in pes_units(buf, pid):
        if pts is not None:
            return pts
    return None


def parse_ls(payload):
    """Local set MISB 0601 → {tag: bytes} (None si clé absente / tronqué)."""
    i = payload.find(v9.MISB_0601_KEY)
    if i < 0:
        return None
    i += len(v9.MISB_0601_KEY)
    total, i = v9._ber_len(payload, i)
    if total is None or i + total > len(payload):
        return None
    end, out = i + total, {}
    while i < end:
        tag = payload[i]; i += 1
        if tag & 0x80:                                     # BER-OID 2 octets
            tag = ((tag & 0x7F) << 7) | payload[i]; i += 1
        ln, i = v9._ber_len(payload, i)
        if ln is None or i + ln > end:
            break
        out[tag] = payload[i:i + ln]; i += ln
    return out


def _f(d, tag, fn):
    v = d.get(tag)
    try:
        return round(fn(v), 7) if v is not None else None
    except Exception:
        return None


def klv_numeric(d):
    """Valeurs numériques utiles pour la carte à partir d'un LS {tag: bytes}."""
    s, u = v9._s, v9._u
    o = {
        "ts_us": _f(d, 2, u),
        "hdg": _f(d, 5, lambda b: v9._lin_u(u(b), 16, 360.0)),
        "pitch": _f(d, 6, lambda b: v9._lin_s(s(b), 16, 20.0)),
        "roll": _f(d, 7, lambda b: v9._lin_s(s(b), 16, 50.0)),
        "lat": _f(d, 13, lambda b: v9._lin_s(s(b), 32, 90.0)),
        "lon": _f(d, 14, lambda b: v9._lin_s(s(b), 32, 180.0)),
        "alt": _f(d, 15, lambda b: v9._lin_u(u(b), 16, 19900.0, -900.0)),
        "hfov": _f(d, 16, lambda b: v9._lin_u(u(b), 16, 180.0)),
        "vfov": _f(d, 17, lambda b: v9._lin_u(u(b), 16, 180.0)),
        "rel_az": _f(d, 18, lambda b: v9._lin_u(u(b), 32, 360.0)),
        "rel_el": _f(d, 19, lambda b: v9._lin_s(s(b), 32, 180.0)),
        "slant": _f(d, 21, lambda b: v9._lin_u(u(b), 32, 5000000.0)),
        "fc_lat": _f(d, 23, lambda b: v9._lin_s(s(b), 32, 90.0)),
        "fc_lon": _f(d, 24, lambda b: v9._lin_s(s(b), 32, 180.0)),
        "fc_alt": _f(d, 25, lambda b: v9._lin_u(u(b), 16, 19900.0, -900.0)),
    }
    corners = []
    if all(t in d for t in range(82, 90)):                 # coins absolus (tags 82-89)
        for k in range(4):
            corners.append([_f(d, 82 + 2 * k, lambda b: v9._lin_s(s(b), 32, 90.0)),
                            _f(d, 83 + 2 * k, lambda b: v9._lin_s(s(b), 32, 180.0))])
    elif o["fc_lat"] is not None and all(t in d for t in range(26, 34)):
        for k in range(4):                                # offsets ±0.075° (tags 26-33)
            dla = v9._lin_s(s(d[26 + 2 * k]), 16, 0.075)
            dlo = v9._lin_s(s(d[27 + 2 * k]), 16, 0.075)
            corners.append([round(o["fc_lat"] + dla, 7), round(o["fc_lon"] + dlo, 7)])
    o["corners"] = corners or None
    return o


def klv_track(st):
    """Trace KLV complète d'un flux : t (s) relatif au 1er PTS vidéo + valeurs."""
    info = st.info
    kpid = info["klv_pid"]
    vpid = next((p for p, t in info["elements"].items() if t in (0x1B, 0x24, 0x02)), None)
    v0 = first_pts(st.buf, vpid) if vpid is not None else None
    sets = []
    if kpid is not None:
        for pts, payload in pes_units(st.buf, kpid):
            d = parse_ls(payload)
            if not d or pts is None:
                continue
            o = klv_numeric(d)
            if o["lat"] is None:
                continue
            base = v0 if v0 is not None else pts
            o["t"] = round((pts - base) / 90000.0, 3)
            o["pts_ms"] = pts // 90
            sets.append(o)
    return {"video_pid": vpid, "klv_pid": kpid, "video_first_pts_ms": (v0 // 90) if v0 else None,
            "n": len(sets), "sets": sets}


def stream_summary(st):
    info = st.info
    els = [{"pid": p, "type": t, "name": v9.STREAM_TYPES.get(t, "type 0x%02X" % t)}
           for p, t in sorted(info["elements"].items())]
    first_klv = None
    if info["klv_pid"] is not None:
        rec = v9.klv_from_stream(st.buf, info["klv_pid"])
        if rec:
            first_klv = [{"tag": t, "name": n, "value": str(v)} for t, n, v in rec]
    return {"dst": st.dst, "dport": st.dport, "bytes": len(st.buf), "datagrams": len(st.pkts),
            "duration_s": round((st.t1 or 0) - (st.t0 or 0), 3), "cc_errors": info["cc_errors"],
            "pids": {str(k): v for k, v in sorted(info["pids"].items())},
            "elements": els, "klv_pid": info["klv_pid"], "pmt_pids": info["pmt_pids"],
            "first_klv": first_klv}


# ── Analyse statique : tracker GMTI (lazy, numpy/scipy), extracteur 4607, CoT ─
TRACKER_PREFIX = "prototype_tracker_gmti_v"
EXTRACT_MAX_BYTES = 700 * 1024 * 1024
MAX_DISPLAY_PLOTS = 50000


def _tracker_dir():
    """Version `prototype_tracker_gmti_v<N[.M]>` la plus élevée contenant track_run.py."""
    best, best_ver = None, ()
    for name in os.listdir(HERE):
        if not name.startswith(TRACKER_PREFIX):
            continue
        parts = name[len(TRACKER_PREFIX):].split(".")
        if not all(x.isdigit() for x in parts):
            continue
        ver = tuple(int(x) for x in parts)
        if os.path.isfile(os.path.join(HERE, name, "track_run.py")) and ver > best_ver:
            best_ver, best = ver, name
    return os.path.join(HERE, best) if best else None


def _load_module_from(path, modname):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


_TRACK_RUN = [None]
_EXTRACT = [None]


def load_track_run():
    if _TRACK_RUN[0] is None:
        d = _tracker_dir()
        if not d:
            raise RuntimeError("aucun dossier %s* avec track_run.py" % TRACKER_PREFIX)
        for q in [x for x in sys.path if os.path.basename(x).startswith(TRACKER_PREFIX)]:
            sys.path.remove(q)
        _load_module_from(os.path.join(d, "tracker.py"), "tracker")
        _TRACK_RUN[0] = _load_module_from(os.path.join(d, "track_run.py"), "track_run")
    return _TRACK_RUN[0]


def load_extract():
    if _EXTRACT[0] is None:
        d = _tracker_dir()
        if not d:
            raise RuntimeError("extracteur 4607 introuvable")
        _EXTRACT[0] = _load_module_from(os.path.join(d, "stanag4607_extract.py"), "stanag4607_extract")
    return _EXTRACT[0]


def tracker_version():
    d = _tracker_dir()
    return os.path.basename(d)[len("prototype_tracker_gmti_"):] if d else None


_GMTI = {}          # pcap → {"csv", "sink", "mode", "n_plots", "dwells", "rapport", "zone", "porteur", "tracks":{profile: res}}
_COT = {}           # pcap → scan_cot result
_ALOCK = threading.Lock()


def gmti_decode(path, limit=0):
    """Décode le GMTI d'un pcap → CSV plots (extracteur complet si taille raisonnable,
    sinon streaming gmti_pcap_to_csv). Mis en cache. Renvoie le résumé JSON-able."""
    key = (os.path.abspath(path), int(limit or 0))
    with _ALOCK:
        if key in _GMTI:
            return _GMTI[key]
    out = os.path.join(tempfile.gettempdir(), "pcap_web_gmti_%s.csv" % hashlib.md5(repr(key).encode()).hexdigest()[:10])
    entry = {"csv": None, "sink": None, "mode": None, "n_plots": 0, "dwells": 0, "rapport": None,
             "zone": [], "porteur": [], "tracks": {}, "error": None}
    if os.path.getsize(path) <= EXTRACT_MAX_BYTES:
        try:
            ex = load_extract()
            sink = ex.extract(path)
            if sink.plots:
                ex.write_csv(sink, out)
                entry.update({"csv": out, "sink": sink, "mode": "extracteur complet", "n_plots": len(sink.plots),
                              "dwells": sink.dwell_count, "rapport": ex.rapport(sink)})
                for j in sink.jobdefs:
                    ba = j.get("bounding_area") or []
                    if len(ba) >= 3 and any(abs(a) + abs(b) > 1e-6 for a, b in ba):
                        entry["zone"] = [[la, lo] for la, lo in ba]
                        break
                entry["porteur"] = [[la, lo] for la, lo in sink.platlocs]
        except Exception as e:
            entry["error"] = "extracteur : %s" % e
    if entry["csv"] is None and gmti_pcap_to_csv is not None:
        try:
            rc = gmti_pcap_to_csv.export(path, out, None, limit)
            if rc == 0:
                with open(out, encoding="utf-8") as f:
                    n = max(0, sum(1 for _ in f) - 1)
                entry.update({"csv": out, "mode": "streaming (sans overlays)", "n_plots": n})
            else:
                entry["error"] = "aucun flux GMTI détecté"
        except Exception as e:
            entry["error"] = "streaming : %s" % e
    with _ALOCK:
        _GMTI[key] = entry
    return entry


def gmti_summary(entry):
    return {k: entry[k] for k in ("mode", "n_plots", "dwells", "rapport", "zone", "porteur", "error")} | \
        {"decoded": entry["csv"] is not None, "tracker": tracker_version(),
         "profiles": list(load_track_run().PROFILES.keys()) if _tracker_dir() else []}


def gmti_profiles():
    """Profils (source unique gmti_profiles.json) : defaults, profiles, params (doc), config effective."""
    tr = load_track_run()
    data = tr.load_profiles()
    names = list((data.get("profiles") or {}).keys()) or list(tr.PROFILES.keys())
    return {"path": tr.PROFILES_JSON, "defaults": data.get("defaults") or {}, "profiles": data.get("profiles") or {},
            "params": data.get("params") or {}, "names": names,
            "effective": {n: tr.java_config(n) for n in names}}


def gmti_profile_save(name, params):
    """Enregistre/écrase un profil dans gmti_profiles.json (écarts par rapport aux defaults)."""
    tr = load_track_run()
    data = tr.load_profiles()
    name = (name or "").strip()
    if not name or not all(c.isalnum() or c in "_-" for c in name):
        raise ValueError("nom de profil invalide (lettres, chiffres, _ -)")
    if params is None:                                  # suppression
        if name in ("defaut",):
            raise ValueError("le profil « defaut » ne peut pas être supprimé")
        (data.get("profiles") or {}).pop(name, None)
        with open(tr.PROFILES_JSON, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tr.load_profiles()
        return gmti_profiles()
    defaults = data.get("defaults") or {}
    prof = {}
    for k, v in (params or {}).items():
        if k not in defaults and k != "deleteSec":
            continue
        if v != defaults.get(k):
            prof[k] = v
    data.setdefault("profiles", {})[name] = prof
    with open(tr.PROFILES_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tr.load_profiles()
    with _ALOCK:                                        # les runs en cache dépendent des profils
        for e in _GMTI.values():
            e["tracks"].clear(); e.get("res", {}).clear()
    return gmti_profiles()


def gmti_track(entry, profile, overrides=None):
    """Déroule le tracker (profil + surcharges, noms Java) sur le CSV décodé → pistes/plots en lat/lon."""
    if entry["csv"] is None:
        raise ValueError(entry["error"] or "GMTI non décodé")
    key = profile + "|" + json.dumps(overrides or {}, sort_keys=True)
    if key in entry["tracks"]:
        return entry["tracks"][key]
    tr = load_track_run()
    with TRACK_LOCK:                                    # Params globaux : pas en même temps que le pistage live
        res = tr.run_tracking(entry["csv"], profile, overrides or None)
    fr = res.get("frame")
    if fr is None:
        raise ValueError("tracker : aucun plot exploitable")
    ll = lambda pts: [[round(a, 6), round(b, 6)] for a, b in (fr.to_ll(x, y) for x, y in pts)]
    tracks = [{"id": t["id"], "hits": t["hits"], "etat": t.get("etat", ""), "is_air": t["is_air"],
               "is_rotator": t["is_rotator"], "pts": ll(t["pts"]), "smooth": ll(t["smooth"])} for t in res["tracks"]]
    if entry["sink"] is not None:                       # plots bruts + classification (extracteur)
        raw = [[round(la, 6), round(lo, 6), int(t["classification"]) if t.get("classification") is not None else None]
               for d, t, (la, lo) in entry["sink"].plots]
    else:
        raw = [[a, b, None] for a, b in ll(res["raw"])]
    if len(raw) > MAX_DISPLAY_PLOTS:
        raw = raw[::len(raw) // MAX_DISPLAY_PLOTS + 1]
    contacts = None
    if res.get("contacts") is not None:
        # Affichage : contacts issus d'une vraie fusion (n_max > 1) ou persistants (≥ 3 dwells), plafonnés.
        sel = sorted((c for c in res["contacts"] if c["n_max"] > 1 or len(c["pts"]) >= 3), key=lambda c: -len(c["pts"]))[:2000]
        contacts = [{"id": c["id"], "pts": ll(c["pts"]), "n_max": c["n_max"], "hits": c["hits"], "members": c["members"]} for c in sel]
    out = {"profile": profile, "overrides": overrides or {}, "config": res.get("config"), "metrics": res.get("metrics"),
           "n_kept": res["n_kept"], "n_rejected": res["n_rejected"], "tracks": tracks,
           "raw": raw, "n_raw": len(raw), "zone": entry["zone"], "porteur": entry["porteur"], "contacts": contacts}
    entry["tracks"][key] = out
    entry.setdefault("res", {})[key] = res                # objets Python (inspection d'une piste)
    return out


def gmti_parity_zip(entry, profile, overrides, name=None, seconds=300.0):
    """Oracle de parité pour le test Java TrackerParityTest (cas personnalisé) : zip contenant
    <nom>.input.csv (plots décodés, schéma gmti_pcap_to_csv), <nom>.expected.csv (pistes affichables
    par dwell, tracker Python de référence avec profil + surcharges) et <nom>.profile.json (config
    effective, noms TrackerConfig). À déposer dans src/test/resources/parity/custom/ du receiver."""
    import io, zipfile
    if entry["csv"] is None:
        raise ValueError(entry["error"] or "GMTI non décodé")
    tr = load_track_run()
    d = _tracker_dir()
    pe = _load_module_from(os.path.join(d, "parity_export.py"), "parity_export")
    name = "".join(c if (c.isalnum() or c in "_-") else "_" for c in (name or profile))
    if overrides:
        name = name if name != profile else name + "_custom"
    tag = hashlib.md5((name + entry["csv"] + str(seconds)).encode()).hexdigest()[:8]
    tmp = os.path.join(tempfile.gettempdir(), "pcap_web_parity_%s.csv" % tag)
    # Fenêtre temporelle (le test JUnit compare dwell par dwell en O(n²) : on borne le cas à
    # `seconds` de dwell_time à partir du premier plot ; 0 = toute la capture).
    src = entry["csv"]
    if seconds and seconds > 0:
        src = os.path.join(tempfile.gettempdir(), "pcap_web_parity_in_%s.csv" % tag)
        t0 = None
        with open(entry["csv"], encoding="utf-8") as f:            # 1re passe : plus ancien dwell_time
            f.readline()
            for line in f:
                try:
                    tms = int(line.split(";", 1)[0])
                except ValueError:
                    continue
                t0 = tms if t0 is None else min(t0, tms)
        with open(entry["csv"], encoding="utf-8") as f, open(src, "w", encoding="utf-8") as g:
            hdr = f.readline(); g.write(hdr)
            for line in f:
                try:
                    tms = int(line.split(";", 1)[0])
                except ValueError:
                    continue
                if t0 is not None and tms - t0 <= seconds * 1000.0:
                    g.write(line)
    with TRACK_LOCK:
        pe.export(src, profile, tmp, overrides or None)
        cfg = tr.java_config(profile, overrides or None)
    with open(src, "rb") as f:
        inp = f.read()
    with open(tmp, "rb") as f:
        exp = f.read()
    n_exp = max(0, exp.count(b"\n") - 1)
    if n_exp == 0:
        raise ValueError("aucune piste affichable dans la fenêtre (%s s) avec ce profil : élargir la fenêtre "
                         "(0 = capture entière) ou changer de profil" % seconds)
    prof = {"profile": profile, "overrides": overrides or {}, "config": cfg,
            "_doc": "Config effective (noms TrackerConfig.java) utilisée pour produire <nom>.expected.csv "
                    "avec le tracker Python v8.1 de référence. TrackerParityTest.parite_cas_personnalises() "
                    "l'applique telle quelle (ProfilesJson.apply)."}
    readme = ("Oracle de parité tracker Python v8.1 -> Java (Receiver4607-geoevent-adapter)\n"
              "cas : %s | profil : %s%s | %d lignes attendues | fenetre : %s\n\n"
              "1. Copier %s.input.csv, %s.expected.csv, %s.profile.json dans\n"
              "   Receiver4607-geoevent-adapter/src/test/resources/parity/custom/\n"
              "2. mvn test  (TrackerParityTest.parite_cas_personnalises)\n"
              "   -> parité OK = le processor Java reproduit ce réglage sur cette capture (<= 1 m, flags identiques).\n"
              "3. Pour la prod : déposer gmti_profiles.json sur le serveur GeoEvent et renseigner la propriété\n"
              "   « profilesFile » du processeur (chemin absolu), profil = %s.\n"
              % (name, profile, " + surcharges" if overrides else "", n_exp,
                 ("%g s de dwell_time depuis le premier plot" % seconds) if seconds and seconds > 0 else "capture entiere",
                 name, name, name, profile))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("%s.input.csv" % name, inp)
        z.writestr("%s.expected.csv" % name, exp)
        z.writestr("%s.profile.json" % name, json.dumps(prof, indent=2, ensure_ascii=False))
        z.writestr("README-parite.txt", readme)
    return name, buf.getvalue(), n_exp


# ── Ligne de temps préchargée (mode « Lecture IHM seule », sans moteur) ─────────
_TL_CACHE = {}


def timeline_data(path, limit=0, watch=None):
    """Événements datés de toute la capture (temps relatif au 1er paquet) : CoT (un par
    datagramme), dwells GMTI (zone, plots), offsets des flux vidéo. Mis en cache par pcap."""
    key = (os.path.abspath(path), os.path.getmtime(path), int(limit or 0), tuple(sorted(watch or [])))
    with _ALOCK:
        if key in _TL_CACHE:
            return _TL_CACHE[key]
    t0 = None
    cot, dwells, gmti_dt = [], [], []
    n = 0
    wset = set(w.lower() for w in watch) if watch else None
    for ts, lt, frame in iter_frames(path):
        n += 1
        if limit and n > limit:
            break
        r = parse(lt, frame)
        if not r:
            continue
        proto, src, sport, dst, dport, pl = r
        if not pl:
            continue
        if t0 is None:
            t0 = ts
        key2 = "%s/%s" % (proto.lower(), dport)
        if wset is not None and key2 not in wset:
            continue
        if pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
            ev = decode_cot(pl)
            if ev:
                cot.append([round(ts - t0, 3), ev["uid"], ev["type"], ev["aff"], ev.get("callsign"), ev["lat"], ev["lon"],
                            ev.get("speed"), ev.get("course"), key2])
        elif len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
            g = decode_gmti(pl)
            if g is not None:
                plots, sensor, dw = g
                for d in dw:
                    dwells.append([round(ts - t0, 3), sensor, d["center"], d["poly"], d["n"], d.get("t_ms")])
                    if d.get("t_ms") is not None:
                        gmti_dt.append(ts - d["t_ms"] / 1000.0)
                if plots and not dw:
                    dwells.append([round(ts - t0, 3), sensor, None, None, len(plots), None])
                if plots:
                    dwells[-1].append(plots)
    gmti_dt.sort()
    dwell_offset = gmti_dt[len(gmti_dt) // 2] if gmti_dt else None      # pcap_ts ≈ dwell_time + offset
    streams = scan(path, limit)
    video = [{"dport": st.dport, "dst": st.dst, "t_offset": round((st.t0 or t0 or 0) - (t0 or 0), 3), "duration": round((st.t1 or 0) - (st.t0 or 0), 3)}
             for st in streams.values()]
    out = {"t0": t0, "duration": round((ts - t0) if t0 is not None else 0.0, 3), "n_packets": n,
           "cot": cot, "dwells": dwells, "dwell_offset": dwell_offset, "video": video}
    with _ALOCK:
        _TL_CACHE[key] = out
    return out


def timeline_tracks(entry, profile, overrides, tl):
    """Pistes du run hors ligne (même algorithme que le live) datées en temps de capture :
    [{id, air, rot, hist:[[t_rel, lat, lon, state, hit, ever]]}] via dwell_offset."""
    key = profile + "|" + json.dumps(overrides or {}, sort_keys=True)
    res = (entry.get("res") or {}).get(key)
    if res is None:
        gmti_track(entry, profile, overrides)
        res = entry["res"][key]
    fr = res.get("frame")
    off = tl.get("dwell_offset")
    t0 = tl.get("t0")
    if fr is None or off is None or t0 is None:
        return []
    T_ = sys.modules["tracker"]
    names = {T_.TENTATIVE: "T", T_.CONFIRMED: "C", T_.SOLID: "S", T_.COASTING: "K", T_.DEAD: "D"}
    out = []
    MAX_PER_TRACK = 240                                  # sous-échantillonnage du coasting (les hits et
    for tid, tr in (res.get("_objs") or {}).items():     # changements d'état sont toujours conservés)
        h = tr.history
        n = len(h)
        step = max(1, n // MAX_PER_TRACK)
        hist, ever, last_nm = [], False, None
        for i, (t, x, y, st, hit) in enumerate(h):
            nm = names.get(st, "T")
            if nm in ("C", "S"):
                ever = True
            keep = hit or nm != last_nm or i == n - 1 or i == 0 or (i % step == 0)
            last_nm = nm
            if not keep:
                continue
            la, lo = fr.to_ll(float(x), float(y))
            hist.append([round(float(t) + off - t0, 3), round(la, 6), round(lo, 6), nm, 1 if hit else 0, 1 if ever else 0])
        if hist:
            out.append({"id": tid, "air": bool(tr.is_air), "rot": bool(tr.is_rotator), "hits": tr.hits, "hist": hist})
    return out


def gmti_track_detail(entry, profile, overrides, track_id):
    key = profile + "|" + json.dumps(overrides or {}, sort_keys=True)
    res = (entry.get("res") or {}).get(key)
    if res is None:
        gmti_track(entry, profile, overrides)
        res = entry["res"][key]
    tr = load_track_run()
    with TRACK_LOCK:
        tr.apply_profile(profile, overrides or None)      # GATE_CHI2 du profil pour les ellipses
        d = tr.track_detail(res, track_id)
    if d is None:
        raise ValueError("piste %s inconnue pour ce run" % track_id)
    return d


def cot_scan(path, flt=None):
    key = (os.path.abspath(path), flt or "")
    with _ALOCK:
        if key in _COT:
            return _COT[key]
    if cot_extract is None:
        raise ValueError("cot_extract indisponible")
    r = cot_extract.scan_cot(path, flt or None)
    with _ALOCK:
        _COT[key] = r
    return r


def cot_summary(r):
    rows = []
    for uid, row in sorted(r["rows"].items()):
        rows.append({k: row.get(k) for k in ("uid", "type", "affiliation", "dimension", "callsign", "track_number",
                                              "how", "lat", "lon", "hae", "course", "speed", "time", "src")})
    tracks = {uid: [[la, lo] for (_t, la, lo) in tr] for uid, tr in r["tracks"].items() if len(tr) >= 2}
    types = [{"type": t, "n": n, "affiliation": cot_extract.affiliation(t), "dimension": cot_extract.dimension(t)}
             for t, n in r["types"].most_common()]
    return {"total": r["total"], "kept": r["kept"], "malformed": r["malformed"], "tcp_recovered": r.get("tcp_recovered", 0),
            "empty_uid": r.get("empty_uid", 0), "rows": rows, "tracks": tracks, "types": types}


def fused_geojson(path, profile, limit=0):
    """GeoJSON WGS84 : pistes GMTI (LineString) + objets CoT (Point) + trace capteur vidéo."""
    feats = []
    try:
        entry = gmti_decode(path, limit)
        if entry["csv"]:
            res = gmti_track(entry, profile)
            for t in res["tracks"]:
                if len(t["pts"]) >= 2:
                    feats.append({"type": "Feature", "geometry": {"type": "LineString",
                                  "coordinates": [[lo, la] for la, lo in t["pts"]]},
                                  "properties": {"source": "gmti", "track_id": t["id"], "etat": t["etat"],
                                                 "aerien": t["is_air"], "rotateur": t["is_rotator"], "hits": t["hits"]}})
    except Exception:
        pass
    try:
        r = cot_scan(path)
        for uid, row in r["rows"].items():
            la, lo = _num(row["lat"]), _num(row["lon"])
            if la is not None and lo is not None and not (la == 0 and lo == 0):
                feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [round(lo, 7), round(la, 7)]},
                              "properties": {"source": "cot", "uid": uid, "type": row["type"], "affiliation": row["affiliation"],
                                             "callsign": row.get("callsign")}})
        for uid, tr in r["tracks"].items():
            if len(tr) >= 2:
                feats.append({"type": "Feature", "geometry": {"type": "LineString",
                              "coordinates": [[round(lo, 7), round(la, 7)] for (_t, la, lo) in tr]},
                              "properties": {"source": "cot-track", "uid": uid}})
    except Exception:
        pass
    try:
        streams = scan(path, limit)
        for st in streams.values():
            tk = klv_track(st)
            pts = [[round(s_["lon"], 7), round(s_["lat"], 7)] for s_ in tk["sets"][::10]]
            if len(pts) >= 2:
                feats.append({"type": "Feature", "geometry": {"type": "LineString", "coordinates": pts},
                              "properties": {"source": "video-sensor", "dport": st.dport}})
    except Exception:
        pass
    return {"type": "FeatureCollection",
            "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:OGC:1.3:CRS84"}}, "features": feats}


# ── Réglages persistants (dernier pcap, récents, IHM) + explorateur de fichiers ─
SETTINGS_PATH = os.path.join(HERE, "pcap_web_settings.json")
PCAP_EXT = (".pcap", ".pcapng", ".cap")


def settings_load():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def settings_save(patch):
    cur = settings_load()
    cur.update({k: v for k, v in patch.items() if v is not None})
    if "last_pcap" in patch and patch["last_pcap"]:
        rec = [patch["last_pcap"]] + [r for r in cur.get("recent", []) if r != patch["last_pcap"]]
        cur["recent"] = [r for r in rec if os.path.isfile(r)][:12]
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=2, ensure_ascii=False)
    return cur


def browse(d=None):
    """Liste un dossier (sous-dossiers + captures). Défaut : dossier du dernier pcap,
    sinon ../Captures, sinon le dossier des outils. Windows : `d=""` liste les lecteurs."""
    if d is None or d == "":
        st = settings_load()
        last = st.get("last_pcap")
        cand = [os.path.dirname(last) if last else None, os.path.join(os.path.dirname(HERE), "Captures"), HERE]
        d = next((c for c in cand if c and os.path.isdir(c)), HERE)
    if d == "::drives" or (d == "/" and os.name == "nt"):
        drives = ["%s:\\" % c for c in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.isdir("%s:\\" % c)]
        return {"dir": "::drives", "parent": None, "dirs": drives, "files": []}
    d = os.path.abspath(d)
    if not os.path.isdir(d):
        raise FileNotFoundError("dossier introuvable : %r" % d)
    dirs, files = [], []
    try:
        for name in sorted(os.listdir(d), key=str.lower):
            full = os.path.join(d, name)
            try:
                if os.path.isdir(full):
                    if not name.startswith((".", "$")):
                        dirs.append(name)
                elif name.lower().endswith(PCAP_EXT):
                    stt = os.stat(full)
                    files.append({"name": name, "size": stt.st_size, "mtime": int(stt.st_mtime)})
            except OSError:
                continue
    except PermissionError:
        raise FileNotFoundError("accès refusé : %s" % d)
    parent = os.path.dirname(d)
    if parent == d:
        parent = "::drives" if os.name == "nt" else None
    return {"dir": d, "parent": parent, "dirs": dirs, "files": files}


# ── WebSocket serveur minimal (RFC 6455, stdlib) ─────────────────────────────
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def ws_frame(data, opcode):
    """Trame serveur→client (non masquée). opcode 1 = texte, 2 = binaire, 8 = close, 10 = pong."""
    n = len(data)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return hdr + data


def ws_reader(sock, on_close):
    """Lit les trames client (ping/close) ; toute autre trame est ignorée."""
    try:
        sock.settimeout(None)
        while True:
            h = sock.recv(2, socket.MSG_WAITALL)
            if len(h) < 2:
                break
            op, ln = h[0] & 0x0F, h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", sock.recv(2, socket.MSG_WAITALL))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", sock.recv(8, socket.MSG_WAITALL))[0]
            mask = sock.recv(4, socket.MSG_WAITALL) if h[1] & 0x80 else None
            data = sock.recv(ln, socket.MSG_WAITALL) if ln else b""
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 8:
                break
            if op == 9:
                try:
                    sock.sendall(ws_frame(data, 10))
                except OSError:
                    break
    except (OSError, ValueError):
        pass
    on_close()


class Bus:
    """Diffusion 1→N par files bornées (les abonnés lents perdent des messages, pas le moteur)."""

    def __init__(self):
        self.subs = set()
        self.lock = threading.Lock()

    def subscribe(self, maxsize=2000):
        q = queue.Queue(maxsize=maxsize)
        with self.lock:
            self.subs.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subs.discard(q)

    def publish(self, item):
        with self.lock:
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(item)
            except queue.Full:
                pass


EVENTS = Bus()                       # JSON (dict) → /ws/events
VIDEO_TAPS = {}                      # dport → Bus (bytes TS) → /ws/video
VIDEO_LOCK = threading.Lock()


def video_bus(dport):
    with VIDEO_LOCK:
        b = VIDEO_TAPS.get(dport)
        if b is None:
            b = VIDEO_TAPS[dport] = Bus()
        return b


# ── Décodage par paquet (CoT XML, GMTI 4607) pour l'IHM ─────────────────────
def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def decode_cot(pl):
    """Un event CoT XML (un datagramme UDP) → dict léger pour la carte, ou None."""
    try:
        el = ET.fromstring(pl)
    except ET.ParseError:
        return None
    if el.tag != "event":
        return None
    typ = el.get("type", "") or ""
    pt = el.find("point"); det = el.find("detail")
    contact = det.find("contact") if det is not None else None
    track = det.find("track") if det is not None else None
    lat = _num(pt.get("lat")) if pt is not None else None
    lon = _num(pt.get("lon")) if pt is not None else None
    return {"uid": el.get("uid", "") or "", "type": typ,
            "aff": cot_extract.affiliation(typ) if cot_extract else "",
            "callsign": contact.get("callsign") if contact is not None else None,
            "lat": lat, "lon": lon, "hae": _num(pt.get("hae")) if pt is not None else None,
            "course": _num(track.get("course")) if track is not None else None,
            "speed": _num(track.get("speed")) if track is not None else None,
            "time": el.get("time"), "stale": el.get("stale"), "how": el.get("how")}


def _dest(lat, lon, bearing_deg, dist_m):
    """Point à `dist_m` mètres dans la direction `bearing_deg` (sphère, R = 6371 km)."""
    R = 6371000.0
    la1, lo1, br = math.radians(lat), math.radians(lon), math.radians(bearing_deg)
    dr = dist_m / R
    la2 = math.asin(math.sin(la1) * math.cos(dr) + math.cos(la1) * math.sin(dr) * math.cos(br))
    lo2 = lo1 + math.atan2(math.sin(br) * math.sin(dr) * math.cos(la1), math.cos(dr) - math.sin(la1) * math.sin(la2))
    return [round(math.degrees(la2), 6), round(math.degrees(lo2), 6)]


def _dist_bearing(lat1, lon1, lat2, lon2):
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    d = 2 * R * math.asin(math.sqrt(a))
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return d, (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def dwell_area(sensor, center, range_he_km, angle_he_deg):
    """Polygone (secteur annulaire) de la zone de dwell : centre C vu du capteur S à
    distance R et gisement θ ; coins à R ± ΔR et θ ± Δθ (D24/D25). None si incomplet."""
    if not sensor or not center or sensor[0] is None or center[0] is None:
        return None
    if range_he_km is None or angle_he_deg is None or range_he_km <= 0:
        return None
    R, th = _dist_bearing(sensor[0], sensor[1], center[0], center[1])
    dr = range_he_km * 1000.0
    r1, r2 = max(0.0, R - dr), R + dr
    a1, a2 = th - angle_he_deg, th + angle_he_deg
    poly = [_dest(sensor[0], sensor[1], a1, r1)]
    for k in range(9):                                       # arc extérieur
        poly.append(_dest(sensor[0], sensor[1], a1 + (a2 - a1) * k / 8, r2))
    poly.append(_dest(sensor[0], sensor[1], a2, r1))
    for k in range(9):                                       # arc intérieur (retour)
        poly.append(_dest(sensor[0], sensor[1], a2 - (a2 - a1) * k / 8, r1))
    return poly


def decode_gmti(pl):
    """Paquet(s) 4607 → (plots [[lat, lon, vel_los_cms, snr, cls]…], sensor [lat, lon] | None,
    dwells [{"center":[lat,lon], "poly":[[lat,lon]…]|None, "n":n_targets, "range_he_km", "angle_he_deg"}])."""
    if gmti_pcap_to_csv is None or not gmti_pcap_to_csv.looks_like_4607(pl):
        return None
    dwells = gmti_pcap_to_csv.decode_packet_dwells(pl)
    plots, sensor, dw = [], None, []
    for d in dwells:
        for r in d["rows"]:
            plots.append([round(r["lat"], 6), round(r["lon"], 6), r["vel_los_cms"], r["snr_db"], r["classification"]])
        sl = d["sensor"]
        if sl and sl[0] is not None and sl[1] is not None:
            sensor = [round(sl[0], 6), round(sl[1], 6)]
        c = d["center"]
        if c and c[0] is not None:
            dw.append({"center": [round(c[0], 6), round(c[1], 6)], "n": len(d["rows"]),
                       "range_he_km": d["range_he_km"], "angle_he_deg": d["angle_he_deg"],
                       "poly": dwell_area(sensor, c, d["range_he_km"], d["angle_he_deg"]),
                       "t_ms": d["time"], "revisit": d["revisit"], "dwell": d["dwell"]})
    return plots, sensor, dw


TRACK_LOCK = threading.RLock()     # Params du tracker = classe globale : un seul utilisateur à la fois


class LiveTracker:
    """Pistage TEMPS RÉEL pendant le rejeu : Tracker.step() dwell par dwell (comme le
    processor GeoEvent), profil + surcharges (noms Java), déclutter, fusion TrackMerger.
    Le lock global sérialise l'accès à tracker.Params avec l'analyse statique."""

    def __init__(self, profile="defaut", overrides=None):
        import itertools
        self.tr = load_track_run()
        self.T = sys.modules["tracker"]
        self.profile, self.overrides = profile or "defaut", overrides or {}
        self.tk = None; self.frame = None; self.last_t = None; self.merger = None
        self.n_dwells = 0; self.n_plots = 0; self.n_resets = 0; self.n_filtered = 0
        self.itertools = itertools
        self.cfg = None

    def _apply(self):
        self.cfg = self.tr.apply_profile(self.profile, self.overrides)
        return self.cfg

    def _reset(self):
        self.tk = self.T.Tracker(); self.T.Track._ids = self.itertools.count(1)
        self.merger = self.tr.TrackMerger(self.cfg or self._apply()); self.last_t = None

    def step_dwells(self, dwells):
        """dwells : sortie de gmti_pcap_to_csv.decode_packet_dwells (rows déjà validés)."""
        T = self.T
        with TRACK_LOCK:
            cfg = self._apply()
            if self.tk is None:
                self._reset()
            min_snr = float(cfg.get("minSnrDb") or 0); cls_f = set(int(c) for c in (cfg.get("classFilter") or []))
            for d in dwells:
                if d["time"] is None:
                    continue
                t = d["time"] / 1000.0
                rows = d["rows"]
                if self.frame is None:
                    if not rows:
                        continue
                    self.frame = T.LocalFrame(rows[0]["lat"], rows[0]["lon"])
                if self.last_t is not None:
                    if t < self.last_t - 5.0:                       # rejeu bouclé / retour franc → nouvelle session
                        self.n_resets += 1; self._reset()
                    elif t < self.last_t:                            # léger désordre : on ne recule pas le temps
                        t = self.last_t
                sl = d["sensor"]
                sxy = self.frame.to_xy(sl[0], sl[1]) if sl and sl[0] is not None and sl[1] is not None else None
                plots = []
                for r in rows:
                    if min_snr > 0 and (r["snr_db"] is None or r["snr_db"] < min_snr):
                        self.n_filtered += 1; continue
                    if cls_f and (r["classification"] is None or int(r["classification"]) not in cls_f):
                        self.n_filtered += 1; continue
                    x, y = self.frame.to_xy(r["lat"], r["lon"])
                    sig_r = (r["sig_range_cm"] / 100.0) if r["sig_range_cm"] else T.Params.R_POS_DEFAULT
                    sig_x = (r["sig_xrange_dm"] / 10.0) if r["sig_xrange_dm"] else T.Params.R_POS_DEFAULT
                    R = T.covariance_from_4607(sxy, (x, y), self.tr._clamp_std(sig_r), self.tr._clamp_std(sig_x)) if sxy else None
                    plots.append(T.Plot(x, y, r_pos=max(sig_r, sig_x), R=R,
                                        vel_los=(r["vel_los_cms"] or 0) / 100.0, snr=r["snr_db"], classification=r["classification"]))
                self.tk.step(t, plots)
                self.last_t = t; self.n_dwells += 1; self.n_plots += len(plots)

    def snapshot(self, tail=30):
        """Pistes vivantes (état, position, vitesse, cap, traîne) + contacts fusionnés."""
        T = self.T
        if self.tk is None or self.frame is None:
            return {"tracks": [], "stats": self._stats(0, 0, 0, 0)}
        with TRACK_LOCK:
            self._apply()
            names = {T.TENTATIVE: "TENTATIVE", T.CONFIRMED: "CONFIRMED", T.SOLID: "SOLID", T.COASTING: "COASTING"}
            out, outs = [], []
            counts = {"TENTATIVE": 0, "CONFIRMED": 0, "SOLID": 0, "COASTING": 0, "EVER": 0}
            min_speed = float((self.cfg or {}).get("minTrackSpeedMps") or 0.0)
            for tr in self.tk.tracks:
                st = tr.state
                if st == T.DEAD:
                    continue
                name = names.get(st, str(st)); counts[name] = counts.get(name, 0) + 1
                if tr.confirmed_ever:
                    counts["EVER"] += 1
                sp = float(tr.speed())
                la, lo = self.frame.to_ll(float(tr.x[0]), float(tr.x[1]))
                hist = tr.history[-tail:]
                o = {"id": tr.id, "lat": round(la, 6), "lon": round(lo, 6), "speed": round(sp, 1),
                     "heading": round((math.degrees(math.atan2(tr.x[2], tr.x[3])) + 360.0) % 360.0, 1),
                     "state": name, "hits": tr.hits, "misses": tr.misses, "ever": bool(tr.confirmed_ever),
                     "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator),
                     "age_s": round(max(0.0, (self.last_t or 0) - tr.t_last_update), 1),
                     "tail": [[round(a, 6), round(b, 6)] for a, b in (self.frame.to_ll(float(x), float(y)) for (_t, x, y, _s, _h) in hist)]}
                out.append(o)
                if tr.confirmed_ever and name != "TENTATIVE" and (min_speed <= 0 or sp >= min_speed):   # affichables (comme le processor)
                    outs.append({"track_id": tr.id, "x": float(tr.x[0]), "y": float(tr.x[1]), "speed": sp, "heading": o["heading"],
                                 "state": name, "hits": tr.hits, "is_air": o["is_air"], "is_rotator": o["is_rotator"]})
            contacts = None
            if self.merger and self.merger.enabled():
                by_track = {}
                cs = self.merger.merge(outs)
                for c in cs:
                    for m in c["members"]:
                        by_track[m] = c["id"]
                for o in out:
                    o["contact"] = by_track.get(o["id"])
                contacts = [{"id": c["id"], "n": c["n"], "lat": round(self.frame.to_ll(c["x"], c["y"])[0], 6),
                             "lon": round(self.frame.to_ll(c["x"], c["y"])[1], 6), "members": c["members"]} for c in cs if c["n"] > 1]
            st_ = self._stats(counts["TENTATIVE"], counts["CONFIRMED"], counts["SOLID"], counts["COASTING"]); st_["displayable"] = counts["EVER"]
            return {"tracks": out, "contacts": contacts, "stats": st_}

    def _stats(self, tent, conf, solid, coast):
        return {"profile": self.profile, "overrides": self.overrides, "n_dwells": self.n_dwells, "n_plots": self.n_plots,
                "n_filtered": self.n_filtered, "n_resets": self.n_resets, "t": self.last_t,
                "tentative": tent, "confirmed": conf, "solid": solid, "coasting": coast,
                "archived": len(self.tk.archive) if self.tk else 0}


class ReplayEngine:
    """Un rejeu à la fois : pcap_replay.do_routed_replay dans un thread + hook on_packet."""

    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.state = {"running": False}
        self.paused = False; self.args = None; self.params = None

    def status(self):
        with self.lock:
            return dict(self.state)

    def start(self, pcap, routes, speed=1.0, loop=False, rebase=False, taps=(), watch=None, track=None, start_at=0.0):
        """`routes` : flux émis (targets non vides) ; `taps` : ports vidéo poussés vers l'IHM ;
        `watch` : liste "udp/1237" des flux dont CoT/GMTI sont décodés pour l'IHM
        (None = tous, [] = aucun). Un flux non coché n'est ni émis ni affiché."""
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError("un rejeu est déjà en cours")
            specs = ["%s/%s=%s" % (r["proto"].lower(), r["dport"], ",".join(r["targets"]))
                     for r in routes if r.get("targets")]
            table = pcap_replay.parse_routes(specs) if specs else {}
            args = types.SimpleNamespace(speed=float(speed), loop=bool(loop), precise=True,
                                         rebase_time=bool(rebase), drop_unmatched=True,
                                         target=None, target_port=None)
            self.stop_event.clear(); self.paused = False; self.args = args
            self.params = {"pcap": pcap, "routes": routes, "speed": speed, "loop": loop, "rebase": rebase,
                           "taps": list(taps), "watch": watch, "track": track}
            self.state = {"running": True, "pcap": pcap, "routes": specs, "speed": speed, "paused": False,
                          "loop": loop, "taps": list(taps), "watch": watch, "track": track, "sent": 0, "passes": 0, "t": 0.0,
                          "start_at": float(start_at or 0.0), "started": time.time()}
            wset = None if watch is None else set(str(w).lower() for w in watch)
            live = None
            if track:
                try:
                    live = LiveTracker(track.get("profile") or "defaut", track.get("overrides") or {})
                except Exception as e:
                    raise ValueError("pistage temps réel indisponible : %s" % e)
            self.thread = threading.Thread(target=self._run, args=(pcap, args, table, set(int(t) for t in taps), wset, live,
                                                                   float(start_at or 0.0)), daemon=True)
            self.thread.start()

    def stop(self):
        self.stop_event.set()

    # ── Transport ────────────────────────────────────────────────────────
    def pause(self, on=True):
        with self.lock:
            self.paused = bool(on); self.state["paused"] = self.paused
        EVENTS.publish({"type": "replay", **self.status()})

    def set_speed(self, speed):
        with self.lock:
            if getattr(self, "args", None) is not None:
                self.args.speed = float(speed)
            if getattr(self, "params", None):
                self.params["speed"] = float(speed)          # un saut ultérieur garde la vitesse courante
            self.state["speed"] = float(speed)
        EVENTS.publish({"type": "replay", **self.status()})

    def seek(self, t):
        """Saut à t (s depuis le 1er paquet) : arrêt du run courant puis redémarrage avec
        rembobinage à blanc jusqu'à t (état trackers/CoT reconstitué). Bloquant (< 1 s + relecture)."""
        params = getattr(self, "params", None)
        if not params:
            raise ValueError("aucun rejeu à repositionner")
        self.stop_event.set()
        th = self.thread
        if th is not None:
            th.join(timeout=10)
        self.start(params["pcap"], params["routes"], params["speed"], params["loop"], params["rebase"],
                   params["taps"], params["watch"], params["track"], start_at=max(0.0, float(t)))
        return self.status()

    def _run(self, pcap, args, table, taps, watch=None, live=None, start_at=0.0):
        counters = {}
        t_cap0 = [None]
        last_pub = [0.0]
        wall0 = time.perf_counter()
        bytes_out = [0]

        def publish(force=False):
            now = time.perf_counter()
            if not force and now - last_pub[0] < 0.25:
                return
            last_pub[0] = now
            with self.lock:
                st = self.state
                st.update({"t": round(t_rel[0], 3), "flows": dict(counters), "bytes": bytes_out[0],
                           "wall": round(now - wall0, 2)})
                snap = dict(st)
            EVENTS.publish({"type": "replay", **snap})

        t_rel = [0.0]

        cot_batch, gmti_batch = {}, {"plots": [], "sensor": None, "pkts": 0, "dwells": []}
        app_batch_at = [time.perf_counter()]
        totals = {"cot": 0, "gmti_plots": 0, "gmti_pkts": 0, "gmti_dwells": 0}

        def flush_app(force=False):
            now = time.perf_counter()
            if not force and now - app_batch_at[0] < 0.2:
                return
            app_batch_at[0] = now
            if cot_batch:
                EVENTS.publish({"type": "cot", "t": round(t_rel[0], 3), "events": list(cot_batch.values()),
                                "total": totals["cot"]})
                cot_batch.clear()
            if gmti_batch["pkts"]:
                plots = gmti_batch["plots"]
                if len(plots) > 4000:                          # décimation d'affichage
                    plots = plots[::len(plots) // 4000 + 1]
                ev = {"type": "gmti", "t": round(t_rel[0], 3), "plots": plots, "sensor": gmti_batch["sensor"],
                      "dwells": gmti_batch["dwells"][-40:], "pkts": gmti_batch["pkts"],
                      "total_plots": totals["gmti_plots"], "total_pkts": totals["gmti_pkts"],
                      "total_dwells": totals["gmti_dwells"]}
                if live is not None:
                    try:
                        ev["live"] = live.snapshot()
                    except Exception as e:
                        ev["live"] = {"tracks": [], "stats": {"error": str(e)}}
                EVENTS.publish(ev)
                gmti_batch.update({"plots": [], "sensor": None, "pkts": 0, "dwells": []})

        skip_state = {"cot": {}, "n": 0, "first": None}

        def on_skip(ts, proto, dport, pl):
            """Rembobinage à blanc (avant start_at) : état des trackers et du CoT sans affichage."""
            if skip_state["first"] is None:
                skip_state["first"] = ts
                t_cap0[0] = ts                                        # l'horloge relative garde l'origine du pcap
            skip_state["n"] += 1
            key = "%s/%s" % (proto.lower(), dport)
            if watch is not None and key not in watch:
                return
            if pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
                ev = decode_cot(pl)
                if ev:
                    ev["src"] = key; skip_state["cot"][ev["uid"] or ("#%d" % skip_state["n"])] = ev
            elif live is not None and gmti_pcap_to_csv is not None and len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
                if gmti_pcap_to_csv.looks_like_4607(pl):
                    try:
                        live.step_dwells(gmti_pcap_to_csv.decode_packet_dwells(pl))
                    except Exception:
                        pass

        def on_packet(ts, proto, dport, pl, tgts):
            if t_cap0[0] is None:
                t_cap0[0] = ts
            if skip_state["cot"]:                                     # état CoT reconstitué au point de reprise
                EVENTS.publish({"type": "cot", "t": round(ts - t_cap0[0], 3), "events": list(skip_state["cot"].values()),
                                "total": len(skip_state["cot"]), "resumed": True})
                skip_state["cot"] = {}
            t_rel[0] = ts - t_cap0[0]
            key = "%s/%s" % (proto.lower(), dport)
            if tgts:
                counters[key] = counters.get(key, 0) + 1
                bytes_out[0] += len(pl) * len(tgts)
            if proto == "UDP" and dport in taps:
                tsdata = v9._ts_from_udp(pl)
                if tsdata:
                    video_bus(dport).publish(bytes(tsdata))
            elif watch is not None and key not in watch:
                pass                                              # flux non coché : ni émis, ni affiché
            elif pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
                ev = decode_cot(pl)
                if ev:
                    ev["src"] = key; totals["cot"] += 1
                    cot_batch[ev["uid"] or ("#%d" % totals["cot"])] = ev
            elif len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
                g = decode_gmti(pl)
                if g is not None:
                    plots, sensor, dw = g
                    gmti_batch["plots"].extend(plots); gmti_batch["pkts"] += 1
                    gmti_batch["dwells"].extend(dw)
                    if live is not None and gmti_pcap_to_csv is not None:
                        try:
                            live.step_dwells(gmti_pcap_to_csv.decode_packet_dwells(pl))
                        except Exception as e:
                            EVENTS.publish({"type": "log", "msg": "pistage temps réel : %s" % e})
                    if sensor:
                        gmti_batch["sensor"] = sensor
                    totals["gmti_plots"] += len(plots); totals["gmti_pkts"] += 1; totals["gmti_dwells"] += len(dw)
            flush_app()
            publish()

        def on_progress(sent, passes):
            with self.lock:
                self.state["sent"], self.state["passes"] = sent, passes
                if passes > 1 and self.state.get("_pass") != passes:
                    self.state["_pass"] = passes
                    t_cap0[0] = None

        def log(msg):
            EVENTS.publish({"type": "log", "msg": str(msg)})

        try:
            if start_at:
                EVENTS.publish({"type": "log", "msg": "saut à t=%.1f s : rembobinage à blanc (état pistes/CoT reconstitué)…" % start_at})
            pcap_replay.do_routed_replay(pcap, args, table, should_stop=self.stop_event.is_set,
                                         on_progress=on_progress, log=log, on_packet=on_packet,
                                         start_at=start_at, on_skip=on_skip if start_at else None,
                                         is_paused=lambda: self.paused)
        except Exception as e:
            EVENTS.publish({"type": "log", "msg": "ERREUR rejeu : %s" % e})
        finally:
            flush_app(force=True)
            with self.lock:
                self.state["running"] = False
                self.state["stopped"] = self.stop_event.is_set()
            publish(force=True)
            EVENTS.publish({"type": "end", "stopped": self.stop_event.is_set()})


ENGINE = ReplayEngine()


def flows_summary(path, limit=0):
    """Flux applicatifs (pcap_analyze.scan) → lignes pour le routage."""
    res = pcap_analyze.scan(path, limit)
    rows = []
    for proto, dport, dominant, pkts, nbytes, dsts in pcap_analyze.port_rows(res["ports"]):
        rows.append({"proto": proto, "dport": dport, "dominant": dominant, "pkts": pkts,
                     "bytes": nbytes, "dsts": dsts})
    return {"npkt": res["npkt"], "duration_s": round((res["tmax"] or 0) - (res["tmin"] or 0), 3),
            "truncated": res["truncated"], "flows": rows}


BASEMAP_DEFAULT = {"provider": "arcgis_online", "layer": "World_Imagery",
                   "url": "", "token": None, "insecure": True}


def basemap_load():
    cfg = dict(BASEMAP_DEFAULT)
    if arcgis_basemap:
        raw = arcgis_basemap.load_config(HERE)
        cfg["url"], cfg["token"], cfg["insecure"] = raw.get("url", ""), raw.get("token"), raw.get("insecure", True)
        for k in ("provider", "layer"):
            if k in raw:
                cfg[k] = raw[k]
    return cfg


def basemap_save(cfg):
    path = os.path.join(HERE, "basemap.json")
    cur = {}
    try:
        with open(path, encoding="utf-8") as f:
            cur = json.load(f)
    except (OSError, ValueError):
        pass
    cur.update({k: cfg[k] for k in ("provider", "layer", "url", "token", "insecure") if k in cfg})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=2, ensure_ascii=False)
    return cur


# ── Serveur HTTP ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "pcap-web/0.2"
    protocol_version = "HTTP/1.1"          # requis pour le chunked (live) ; toutes les
                                           # autres réponses posent Content-Length.
    default_pcap = None
    default_limit = 0
    basemap_cfg = None

    def log_message(self, fmt, *args):            # log compact
        sys.stderr.write("[web] %s\n" % (fmt % args))

    # helpers
    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _err(self, code, msg):
        self._json({"error": msg}, code)

    def _pcap(self, q):
        p = q.get("pcap", [self.default_pcap or ""])[0]
        if not p or not os.path.isfile(p):
            raise FileNotFoundError("pcap introuvable : %r" % p)
        return p

    def _stream(self, q):
        path = self._pcap(q)
        limit = int(q.get("limit", ["0"])[0] or 0)
        streams = scan(path, limit)
        if not streams:
            raise ValueError("aucun flux MPEG-TS dans le pcap")
        dport = q.get("dport", [None])[0]
        if dport:
            st = streams.get(int(dport))
            if st is None:
                raise ValueError("pas de flux TS sur le port %s" % dport)
            return st
        return max(streams.values(), key=lambda s: len(s.buf))

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                return self._static("index.html")
            if u.path.startswith("/static/"):
                return self._static(u.path[len("/static/"):])
            if u.path == "/api/config":
                st = settings_load()
                default = self.default_pcap or (st.get("last_pcap") if st.get("last_pcap") and os.path.isfile(st["last_pcap"]) else None)
                return self._json({"default_pcap": default, "default_limit": self.default_limit,
                                   "basemap": basemap_load(), "replay": ENGINE.status(), "settings": st})
            if u.path == "/api/settings":
                return self._json(settings_load())
            if u.path == "/api/browse":
                return self._json(browse(q.get("dir", [None])[0]))
            if u.path == "/api/basemap":
                return self._json(basemap_load())
            if u.path == "/api/flows":
                path = self._pcap(q)
                return self._json(flows_summary(path, int(q.get("limit", ["0"])[0] or 0)))
            if u.path == "/api/gmti/decode":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                return self._json(gmti_summary(gmti_decode(path, limit)))
            if u.path == "/api/gmti/track":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                profile = q.get("profile", ["defaut"])[0]
                ov = json.loads(q.get("overrides", ["{}"])[0] or "{}")
                return self._json(gmti_track(gmti_decode(path, limit), profile, ov))
            if u.path == "/api/gmti/profiles":
                return self._json(gmti_profiles())
            if u.path == "/api/gmti/parity.zip":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                profile = q.get("profile", ["defaut"])[0]
                ov = json.loads(q.get("overrides", ["{}"])[0] or "{}")
                name, data, n = gmti_parity_zip(gmti_decode(path, limit), profile, ov, q.get("name", [None])[0],
                                                float(q.get("seconds", ["300"])[0] or 0))
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", "attachment; filename=\"parity_%s.zip\"" % name)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers(); self.wfile.write(data); return
            if u.path == "/api/timeline":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                watch = [w for w in q.get("watch", [""])[0].split(",") if w]
                tl = timeline_data(path, limit, watch or None)
                out = dict(tl)
                if q.get("profile", [""])[0]:
                    ov = json.loads(q.get("overrides", ["{}"])[0] or "{}")
                    try:
                        out["tracks"] = timeline_tracks(gmti_decode(path, limit), q["profile"][0], ov, tl)
                    except Exception as e:
                        out["tracks"] = []; out["tracks_error"] = str(e)
                return self._json(out)
            if u.path == "/api/gmti/track/detail":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                profile = q.get("profile", ["defaut"])[0]
                ov = json.loads(q.get("overrides", ["{}"])[0] or "{}")
                return self._json(gmti_track_detail(gmti_decode(path, limit), profile, ov, int(q.get("id", ["0"])[0])))
            if u.path == "/api/cot/scan":
                path = self._pcap(q)
                return self._json(cot_summary(cot_scan(path, q.get("filter", [""])[0])))
            if u.path == "/api/cot/event":
                path = self._pcap(q); r = cot_scan(path, q.get("filter", [""])[0])
                raw = r["by_uid"].get(q.get("uid", [""])[0])
                return self._json({"uid": q.get("uid", [""])[0], "xml": (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw) if raw else None})
            if u.path == "/api/fused/export.geojson":
                path = self._pcap(q); limit = int(q.get("limit", ["0"])[0] or 0)
                fc = fused_geojson(path, q.get("profile", ["defaut"])[0], limit)
                data = json.dumps(fc, ensure_ascii=False, indent=1).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/geo+json; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=\"fusion.geojson\"")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers(); self.wfile.write(data); return
            if u.path == "/api/replay/status":
                return self._json(ENGINE.status())
            if u.path == "/ws/events":
                return self._ws_events()
            if u.path == "/ws/video":
                return self._ws_video(int(q.get("dport", ["0"])[0] or 0))
            if u.path == "/api/streams":
                path = self._pcap(q)
                limit = int(q.get("limit", ["0"])[0] or 0)
                settings_save({"last_pcap": os.path.abspath(path)})
                streams = scan(path, limit)
                return self._json({"pcap": path, "streams": sorted(
                    (stream_summary(s) for s in streams.values()), key=lambda d: -d["bytes"])})
            if u.path == "/api/klv":
                return self._json(klv_track(self._stream(q)))
            if u.path == "/video.ts":
                return self._video(self._stream(q))
            if u.path == "/live.ts":
                return self._live(self._stream(q), q)
            if u.path == "/basemap":
                return self._basemap(q)
            self._err(404, "route inconnue")
        except (FileNotFoundError, ValueError) as e:
            self._err(400, str(e))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}") if n else {}
        except ValueError:
            return self._err(400, "JSON invalide")
        try:
            if u.path == "/api/replay/start":
                pcap = body.get("pcap") or self.default_pcap
                if not pcap or not os.path.isfile(pcap):
                    raise FileNotFoundError("pcap introuvable : %r" % pcap)
                ENGINE.start(pcap, body.get("routes", []), body.get("speed", 1.0), body.get("loop", False),
                             body.get("rebase", False), body.get("taps", []), body.get("watch"), body.get("track"),
                             float(body.get("start_at", 0.0) or 0.0))
                return self._json(ENGINE.status())
            if u.path == "/api/replay/stop":
                ENGINE.stop()
                return self._json({"ok": True})
            if u.path == "/api/replay/pause":
                ENGINE.pause(bool(body.get("paused", True)))
                return self._json(ENGINE.status())
            if u.path == "/api/replay/speed":
                ENGINE.set_speed(float(body.get("speed", 1.0)))
                return self._json(ENGINE.status())
            if u.path == "/api/replay/seek":
                return self._json(ENGINE.seek(float(body.get("t", 0.0))))
            if u.path == "/api/settings":
                return self._json(settings_save(body))
            if u.path == "/api/gmti/profiles":
                return self._json(gmti_profile_save(body.get("name"), body.get("params")))
            if u.path == "/api/basemap":
                cfg = basemap_save(body)
                self.__class__.basemap_cfg = cfg
                return self._json(basemap_load())
            self._err(404, "route inconnue")
        except (FileNotFoundError, ValueError) as e:
            self._err(400, str(e))

    # ── WebSocket ─────────────────────────────────────────────────────────
    def _ws_handshake(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
            self._err(400, "WebSocket attendu"); return False
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self.close_connection = True
        return True

    def _ws_pump(self, q, opcode, encode):
        """Boucle d'envoi : file → trames. Termine sur fermeture client ou erreur socket."""
        sock = self.connection
        alive = threading.Event(); alive.set()
        threading.Thread(target=ws_reader, args=(sock, alive.clear), daemon=True).start()
        try:
            while alive.is_set():
                try:
                    item = q.get(timeout=1.0)
                except queue.Empty:
                    sock.sendall(ws_frame(b"", 9))          # ping (keep-alive)
                    continue
                if item is None:
                    break
                sock.sendall(ws_frame(encode(item), opcode))
        except OSError:
            pass
        finally:
            alive.clear()

    def _ws_events(self):
        if not self._ws_handshake():
            return
        q = EVENTS.subscribe()
        q.put({"type": "hello", "replay": ENGINE.status()})
        try:
            self._ws_pump(q, 1, lambda d: json.dumps(d, ensure_ascii=False).encode("utf-8"))
        finally:
            EVENTS.unsubscribe(q)

    def _ws_video(self, dport):
        if not dport:
            return self._err(400, "dport requis")
        if not self._ws_handshake():
            return
        bus = video_bus(dport)
        q = bus.subscribe(maxsize=4000)
        try:
            self._ws_pump(q, 2, lambda b: b)
        finally:
            bus.unsubscribe(q)

    def _static(self, rel):
        rel = rel.replace("\\", "/")
        if ".." in rel:
            return self._err(403, "chemin refusé")
        path = os.path.join(STATIC_DIR, rel)
        if not os.path.isfile(path):
            return self._err(404, "fichier statique absent : %s" % rel)
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(os.path.splitext(path)[1], "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _video(self, st):
        data = st.buf
        total = len(data)
        rng = self.headers.get("Range")
        start, end = 0, total - 1
        code = 200
        if rng and rng.startswith("bytes="):
            a, _, b = rng[6:].partition("-")
            start = int(a) if a else max(0, total - int(b))
            end = int(b) if (a and b) else end
            end = min(end, total - 1)
            code = 206
        self.send_response(code)
        self.send_header("Content-Type", "video/mp2t")
        if self.headers.get("X-Download") or "download" in urllib.parse.urlsplit(self.path).query:
            self.send_header("Content-Disposition", "attachment; filename=\"flux_%d.ts\"" % st.dport)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(end - start + 1))
        if code == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, total))
        self.end_headers()
        mv = memoryview(data)[start:end + 1]
        for i in range(0, len(mv), 1 << 20):
            self.wfile.write(mv[i:i + (1 << 20)])

    def _live(self, st, q):
        """Pousse le TS cadencé aux horodatages pcap (× speed). speed=0 → max."""
        speed = float(q.get("speed", ["1"])[0] or 1)
        loop = q.get("loop", ["0"])[0] in ("1", "true")
        self.send_response(200)
        self.send_header("Content-Type", "video/mp2t")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        buf = memoryview(st.buf)

        def chunk(b):
            self.wfile.write(b"%x\r\n" % len(b)); self.wfile.write(b); self.wfile.write(b"\r\n")

        while True:
            wall0, ts0 = time.perf_counter(), st.pkts[0][0]
            pending, plen, last_flush = [], 0, time.perf_counter()
            for ts, off, ln in st.pkts:
                if speed > 0:
                    target = wall0 + (ts - ts0) / speed
                    delay = target - time.perf_counter()
                    if delay > 0.002:
                        if pending:
                            chunk(b"".join(pending)); self.wfile.flush(); pending, plen = [], 0
                        time.sleep(delay)
                pending.append(buf[off:off + ln].tobytes()); plen += ln
                now = time.perf_counter()
                if plen >= 64 * 1024 or now - last_flush > 0.05:
                    chunk(b"".join(pending)); self.wfile.flush()
                    pending, plen, last_flush = [], 0, now
            if pending:
                chunk(b"".join(pending)); self.wfile.flush()
            if not loop:
                break
        self.wfile.write(b"0\r\n\r\n")

    def _basemap(self, q):
        cfg = basemap_load()
        if not (arcgis_basemap and cfg.get("url")):
            return self._err(503, "MapServer non configuré")
        bbox = [float(x) for x in q["bbox"][0].split(",")]
        w, h = int(q.get("w", ["1024"])[0]), int(q.get("h", ["768"])[0])
        sr = int(q.get("sr", ["4326"])[0])
        url = arcgis_basemap.export_url(arcgis_basemap.mapserver_root(cfg["url"]),
                                        bbox[0], bbox[1], bbox[2], bbox[3], w, h, cfg.get("token"), sr=sr)
        try:
            png = arcgis_basemap.fetch_png(url, insecure=cfg.get("insecure", True))
        except Exception as e:
            return self._err(502, "fond de carte injoignable : %s" % e)
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(png)))
        self.end_headers()
        self.wfile.write(png)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pcap", nargs="?", help="capture par défaut")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--limit", type=int, default=0, help="nb max de trames lues (0 = tout)")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    Handler.default_pcap = os.path.abspath(a.pcap) if a.pcap else None
    Handler.basemap_cfg = basemap_load()
    Handler.default_limit = a.limit
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    url = "http://127.0.0.1:%d/" % a.port
    print("Console web : %s   (Ctrl+C pour arrêter)" % url)
    if a.pcap:
        print("Pré-analyse de %s…" % a.pcap)
        t = time.time(); streams = scan(a.pcap, a.limit)
        for st in streams.values():
            print("  flux %s:%d  %.1f Mo  %d datagrammes  %.1f s  klv_pid=%s" % (
                st.dst, st.dport, len(st.buf) / 1e6, len(st.pkts), (st.t1 - st.t0), st.info["klv_pid"]))
        print("  (%.1f s)" % (time.time() - t))
    if not a.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
