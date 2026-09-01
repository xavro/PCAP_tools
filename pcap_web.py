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
import collections
import queue
import re
import socket
import shutil
import struct
import subprocess
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
try:
    import net_capture                                            # noqa: E402  (écoute réseau live)
except Exception:                                                 # pragma: no cover
    net_capture = None
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
    t_start = time.time(); last_log = t_start
    size_mb = os.path.getsize(path) / 1e6
    print("[scan] %s (%.0f Mo) : analyse des flux TS…" % (os.path.basename(path), size_mb), flush=True)
    for ts, lt, frame in iter_frames(path):
        n += 1
        if limit and n > limit:
            break
        if n % 200000 == 0 and time.time() - last_log > 5:          # progression visible dans le journal (conteneur)
            last_log = time.time()
            print("[scan] %s : %d trames, %d flux TS, %.0f Mo en mémoire, %.0f s" % (
                os.path.basename(path), n, len(streams), sum(len(st.buf) for st in streams.values()) / 1e6, time.time() - t_start), flush=True)
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
    print("[scan] %s : terminé — %d trames, %d flux TS, %.0f Mo en mémoire, %.1f s" % (
        os.path.basename(path), n, len(streams), sum(len(st.buf) for st in streams.values()) / 1e6, time.time() - t_start), flush=True)
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


def klv_from_ts(tsdata):
    """Local set 0601 (éventuellement PARTIEL : les premiers tags, dont position / centre / coins) trouvé dans les
    paquets TS d'un datagramme — payloads regroupés par PID, clé UL cherchée, tags lus jusqu'à la fin des données.
    Renvoie {tag: bytes} ou None. Suffisant pour la trace plateforme (tags 2..25, en tête du LS)."""
    by_pid = {}
    n = len(tsdata) - (len(tsdata) % TS_PKT)
    for i in range(0, n, TS_PKT):
        p = tsdata[i:i + TS_PKT]
        if p[0] != 0x47:
            continue
        pid = ((p[1] & 0x1F) << 8) | p[2]; afc = (p[3] >> 4) & 3
        off = 4
        if afc & 2:
            off += 1 + p[4]
        if afc & 1 and off < TS_PKT:
            by_pid.setdefault(pid, bytearray()).extend(p[off:])
    for buf in by_pid.values():
        k = buf.find(v9.MISB_0601_KEY)
        if k < 0:
            continue
        i = k + len(v9.MISB_0601_KEY)
        total, i = v9._ber_len(buf, i)
        if total is None:
            continue
        end = min(len(buf), i + total); out = {}
        while i < end:
            tag = buf[i]; i += 1
            if tag & 0x80:
                if i >= end:
                    break
                tag = ((tag & 0x7F) << 7) | buf[i]; i += 1
            ln, i = v9._ber_len(buf, i)
            if ln is None or i + ln > end:
                break
            out[tag] = bytes(buf[i:i + ln]); i += ln
        return out or None
    return None


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
    if is_csv_source(path):                                   # détections déjà décodées (StratusServer / banc)
        src = csv_source(path)
        entry.update({"csv": path, "mode": "CSV de détections (StratusServer / banc)", "n_plots": src["n_plots"],
                      "dwells": len(src["dwells"]), "porteur": list(src["sensors"]),
                      "rapport": "Source CSV : %d détections, %d dwells, %.0f s (%s → %s)" % (
                          src["n_plots"], len(src["dwells"]), (src["t1"] or 0) - (src["t0"] or 0), src["t0"], src["t1"])})
        with _ALOCK:
            _GMTI[key] = entry
        return entry
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


def gmti_publish(url, insecure=True):
    """Publie gmti_profiles.json (source unique) vers StratusServer : PUT {url}/api/gmti/profiles →
    dépôt + rechargement à chaud côté service (les pistes en cours sont conservées)."""
    import ssl
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ValueError("URL StratusServer manquante (⚙ Paramètres → StratusServer)")
    tr = load_track_run()
    data = tr.load_profiles()
    if not data.get("profiles"):
        raise ValueError("gmti_profiles.json introuvable ou vide")
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url + "/api/gmti/profiles", data=body, method="PUT", headers={"Content-Type": "application/json"})
    ctx = ssl._create_unverified_context() if (insecure and url.startswith("https")) else None
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            res = json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        raise ValueError("StratusServer %s : %s" % (e.code, e.read().decode("utf-8", "replace")[:300]))
    except (urllib.error.URLError, OSError) as e:
        raise ValueError("StratusServer injoignable : %s" % e)
    settings_save({"stratus_url": url})
    return {"ok": True, "url": url, "remote": res, "profiles": list(data.get("profiles", {}).keys())}


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
               "is_rotator": t["is_rotator"], "pts": ll(t["pts"]), "smooth": ll(t["smooth"]),
               "speed": round(math.hypot(*t["vel"]), 1) if t.get("vel") else None,
               "heading": round((math.degrees(math.atan2(t["vel"][0], t["vel"][1])) + 360.0) % 360.0, 1) if t.get("vel") else None}
              for t in res["tracks"]]
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


def _mission_pcaps(d):
    """Fichiers pcap d'un dossier mission : Capture/{mission}_NNN.pcap (maître v2) sinon *.pcap à la racine."""
    cap = os.path.join(d, "Capture")
    out = []
    for base in (cap, d):
        if os.path.isdir(base):
            out = sorted(f for f in os.listdir(base) if f.lower().endswith(".pcap"))
            if out:
                return [os.path.join(base, f) for f in out]
    return []


def _capture_sets():
    """CAPTURE_SETS (même variable que stratus2-capture : CR1:6789+5454,CR2:9876) → {port: CR}."""
    out = {}
    for item in (os.getenv("CAPTURE_SETS", "") or "").split(","):
        name, _, ports = item.strip().partition(":")
        for p in ports.replace("+", " ").split():
            if p.isdigit():
                out[int(p)] = name.strip().upper()
    return out


_META_DERIVED = {}


def _mission_meta(pcap0, pcaps=None):
    """mission.json écrit par stratus2-capture (CR, début/fin UTC, indicatif / tail / Mission ID KLV).
    Sans fichier (capture ancienne ou manuelle) : métadonnées DÉRIVÉES du pcap — ports et début lus dans les
    2000 premières trames, fin = dernière écriture, CR = nom du dossier ou mapping CAPTURE_SETS (mis en cache)."""
    d = os.path.dirname(pcap0)
    p = os.path.join(d, "mission.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        pass
    key = (pcap0, os.path.getmtime(pcap0))
    if key in _META_DERIVED:
        return _META_DERIVED[key]
    meta = {"derived": True, "flows": {}, "start_utc": None, "end_utc": None, "cr": None}
    try:
        n = 0
        for ts, lt, fr in iter_frames(pcap0):
            r = parse(lt, fr)
            if r and r[0] == "UDP" and r[5]:
                if meta["start_utc"] is None:
                    meta["start_utc"] = ts
                meta["flows"][str(r[4])] = meta["flows"].get(str(r[4]), 0) + 1
            n += 1
            if n >= 2000:
                break
        last = pcaps[-1] if pcaps else pcap0
        meta["end_utc"] = os.path.getmtime(last)
        sets = _capture_sets()
        crs = {sets[int(pt)] for pt in meta["flows"] if int(pt) in sets}
        if len(crs) == 1:
            meta["cr"] = crs.pop()
    except (OSError, ValueError):
        pass
    _META_DERIVED[key] = meta
    return meta


_CR_RE = re.compile(r"(?:^|_)(CR\d+)(?:_|$)", re.I)


def missions_list(cr=None, callsign=None, t_from=None, t_to=None, day=None):
    """Missions du dossier des enregistrements (page opérateur / ExB) : nom, 1er pcap, taille, dates, métadonnées
    KLV (mission.json), suivi possible. Filtres : cr (CR1…), callsign (indicatif KLV, insensible à la casse),
    fenêtre temporelle [t_from, t_to] (epoch s, chevauchement) ou day (YYYYMMDD, sur le début de capture)."""
    root = CAPTURES_DIR
    out = []
    if not root or not os.path.isdir(root):
        return out
    now = time.time()
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if not os.path.isdir(d):
            continue
        pcaps = _mission_pcaps(d)
        if not pcaps:
            continue
        meta = _mission_meta(pcaps[0], pcaps)
        size = sum(os.path.getsize(p) for p in pcaps)
        mtime = max(os.path.getmtime(p) for p in pcaps)
        m_cr = (meta.get("cr") or "").upper() or ((_CR_RE.search(name) or [None, ""])[1] or "").upper()
        start = meta.get("start_utc"); end = meta.get("end_utc")
        recent = (now - mtime) < 30 and not meta.get("closed")
        if cr and m_cr != cr.upper():
            continue
        if callsign and (meta.get("callsign") or "").strip().upper() != callsign.strip().upper():
            continue
        if day and (not start or time.strftime("%Y%m%d", time.gmtime(start)) != day):
            continue
        if (t_from is not None or t_to is not None):
            a = start if start is not None else mtime; b = (now if recent else (end if end is not None else mtime))
            if t_to is not None and a > t_to:
                continue
            if t_from is not None and b < t_from:
                continue
        out.append({"name": name, "pcap": pcaps[0], "segments": len(pcaps), "bytes": size, "mtime": mtime, "recent": recent,
                    "indexed": os.path.isfile(os.path.join(os.path.dirname(pcaps[0]), name + ".idx")),
                    "cr": m_cr or None, "callsign": meta.get("callsign"), "tail": meta.get("tail"), "mission_id": meta.get("mission_id"),
                    "start_utc": start, "end_utc": end, "closed": bool(meta.get("closed")), "flows": meta.get("flows") or {},
                    "platform": meta.get("platform"), "sensor": meta.get("sensor"), "derived": bool(meta.get("derived"))})
    out.sort(key=lambda m: -(m["start_utc"] or m["mtime"]))
    return out


def mission_resolve(name):
    if not name or "/" in name or "\\" in name or ".." in name:
        raise ValueError("nom de mission invalide")
    d = os.path.join(CAPTURES_DIR or "", name)
    pcaps = _mission_pcaps(d) if os.path.isdir(d) else []
    if not pcaps:
        raise FileNotFoundError("mission introuvable : %s" % name)
    return {"name": name, "pcap": pcaps[0], "segments": len(pcaps), "recent": (time.time() - max(os.path.getmtime(p) for p in pcaps)) < 30}


def _journal_klv(pcap0):
    """Positions KLV [t_rel, lat, lon, alt, hdg, fc_lat, fc_lon, dport] et t0 depuis le journal .tl.jsonl (lignes k)."""
    seg = follow_segments(pcap0)
    base = seg[0] if seg else pcap0
    p = base + ".tl.jsonl"
    if not os.path.isfile(p):
        return None, None
    t0 = None; rows = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            try:
                it = json.loads(line)
            except ValueError:
                continue
            if it[0] == "h":
                t0 = it[1].get("t0")
            elif it[0] == "k":
                rows.append(it[1])
    return t0, rows


def mission_klv(name, wait_s=120.0):
    """(t0, positions KLV, pcap) d'une mission : suivi en cours s'il existe, sinon journal, sinon suivi temporaire
    (rattrapage borné) — permet le GPX / les détails d'une capture jamais ouverte."""
    d = os.path.join(CAPTURES_DIR or "", name)
    pcaps = _mission_pcaps(d) if (CAPTURES_DIR and os.path.isdir(d)) else []
    if not pcaps:
        raise FileNotFoundError("mission introuvable : %s" % name)
    fid = follow_id(pcaps[0])
    eng = FOLLOWS.get(fid)
    if eng is not None and eng.state.get("running") and not eng.catching_up:
        return eng.t0, list(eng.klv), pcaps[0]
    t0, rows = _journal_klv(pcaps[0])
    if rows:
        return t0, rows, pcaps[0]
    st = follow_start(pcaps[0], None, None, [])
    eng = FOLLOWS.get(st["id"]); t_end = time.time() + wait_s
    while eng is not None and eng.catching_up and time.time() < t_end:
        time.sleep(0.25)
    if eng is None:
        raise ValueError("suivi impossible")
    return eng.t0, list(eng.klv), pcaps[0]


def mission_gpx(name):
    """GPX 1.1 : une <trk> par flux vidéo (positions KLV, 1 pt / 0,5 s, ele = altitude MSL, time UTC)."""
    t0, rows, pcap0 = mission_klv(name)
    by = {}
    for r in rows:
        by.setdefault(r[7], []).append(r)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<gpx version="1.1" creator="StratusServer v2" xmlns="http://www.topografix.com/GPX/1/1">',
           '  <metadata><name>%s</name><time>%s</time></metadata>' % (name, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 or 0)))]
    for dp, rs in by.items():
        out.append('  <trk><name>%s udp/%d</name><trkseg>' % (name, dp))
        for r in rs:
            ele = ('<ele>%.1f</ele>' % r[3]) if r[3] is not None else ''
            out.append('    <trkpt lat="%.6f" lon="%.6f">%s<time>%s</time></trkpt>' % (
                r[1], r[2], ele, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime((t0 or 0) + r[0])) + ("%.3fZ" % (((t0 or 0) + r[0]) % 1))[1:]))
        out.append('  </trkseg></trk>')
    out.append('</gpx>')
    return "\n".join(out)


def mission_details(name):
    """Compat mission-launcher (/api/missions/{name}/details) depuis mission.json + positions KLV."""
    d = os.path.join(CAPTURES_DIR or "", name)
    pcaps = _mission_pcaps(d) if (CAPTURES_DIR and os.path.isdir(d)) else []
    if not pcaps:
        raise FileNotFoundError("mission introuvable : %s" % name)
    meta = _mission_meta(pcaps[0], pcaps)
    try:
        t0, rows, _ = mission_klv(name, wait_s=30.0)              # suivi en cours > journal > suivi temporaire
    except Exception:
        t0, rows = _journal_klv(pcaps[0]); rows = rows or []
    st = meta.get("start_utc"); en = meta.get("end_utc")
    if meta.get("derived") and rows and t0:                       # capture sans mission.json : fin = dernière position KLV (pas la date du fichier)
        st = st or t0; en = t0 + rows[-1][0]
    lats = [r[1] for r in rows]; lons = [r[2] for r in rows]
    return {"mission_name": name, "total_points": len(rows), "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st)) if st else None,
            "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(en)) if en else None,
            "duration_seconds": round(en - st, 1) if (st and en) else None, "unique_streams": len({r[7] for r in rows}), "unique_segments": len(pcaps),
            "center_lat": round(sum(lats) / len(lats), 6) if lats else None, "center_lon": round(sum(lons) / len(lons), 6) if lons else None,
            "bounds": ([min(lons), min(lats), max(lons), max(lats)] if lats else None),
            "cr": meta.get("cr"), "callsign": meta.get("callsign"), "sensor": meta.get("sensor"), "closed": bool(meta.get("closed")),
            "flows": meta.get("flows") or {}, "total_size_mb": round(sum(os.path.getsize(p) for p in pcaps) / 1e6, 1)}


# ── Snaps (passerelle fichiers MASTER MISSION, contrat du v1 : widget ExB snaps-import) ─────────
MISSIONS_PATH = os.getenv("MISSIONS_PATH", "").strip()
SNAPS_SUBDIR = os.getenv("SNAPS_SUBDIR", "3-Production/1-Snaps").strip().strip("/")
SNAPS_PROCESSED_SUBDIR = os.getenv("SNAPS_PROCESSED_SUBDIR", "3-Production/1-Snaps/snaps_traités").strip().strip("/")
SNAPS_EXT = (".jpg", ".jpeg", ".png")
_SNAPS_DIR_CACHE = {}


def snaps_mission_dir(label):
    """Dossier MASTER d'une mission : <racine>/<label> ou <racine>/*/*/<label> (année/mois), sous la racine."""
    import glob
    if not MISSIONS_PATH:
        raise ValueError("MISSIONS_PATH non configuré")
    if not label or "/" in label or "\\" in label or ".." in label:
        raise ValueError("label mission invalide")
    c = _SNAPS_DIR_CACHE.get(label)
    if c and os.path.isdir(c):
        return c
    root = os.path.realpath(MISSIONS_PATH)
    direct = os.path.join(root, label)
    cands = [direct] if os.path.isdir(direct) else [p for p in glob.glob(os.path.join(glob.escape(root), "*", "*", glob.escape(label))) if os.path.isdir(p)]
    if not cands:
        raise FileNotFoundError("dossier mission introuvable sous la racine missions : %s" % label)
    d = os.path.realpath(sorted(cands)[0])
    if not d.startswith(root + os.sep):
        raise ValueError("accès refusé")
    _SNAPS_DIR_CACHE[label] = d
    return d


def snaps_file(label, filename, processed=False):
    if not filename or "/" in filename or "\\" in filename or ".." in filename or not filename.lower().endswith(SNAPS_EXT):
        raise ValueError("nom de fichier invalide")
    d = os.path.join(snaps_mission_dir(label), SNAPS_PROCESSED_SUBDIR if processed else SNAPS_SUBDIR)
    return os.path.join(d, filename)


def snaps_list(label):
    d = os.path.join(snaps_mission_dir(label), SNAPS_SUBDIR)
    if not os.path.isdir(d):
        return {"mission_name": label, "folder_exists": False, "files": []}
    files = []
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if n.lower().endswith(SNAPS_EXT) and os.path.isfile(p):
            st = os.stat(p)
            files.append({"filename": n, "size": st.st_size, "modified": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(st.st_mtime))})
    return {"mission_name": label, "folder_exists": True, "files": files}


def snaps_archive(label, filename):
    """Déplace 1-Snaps/<f> vers snaps_traités/<f> (suffixe _vN en cas de collision)."""
    import shutil
    src = snaps_file(label, filename)
    if not os.path.isfile(src):
        raise FileNotFoundError("snap introuvable : %s" % filename)
    dst_dir = os.path.join(snaps_mission_dir(label), SNAPS_PROCESSED_SUBDIR)
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, filename); base, ext = os.path.splitext(filename); v = 1
    while os.path.exists(dst):
        dst = os.path.join(dst_dir, "%s_v%d%s" % (base, v, ext)); v += 1
    shutil.move(src, dst)
    return {"mission_name": label, "filename": filename, "archived_as": os.path.basename(dst)}


# ── Préparation mission (passerelle fichiers MASTER MISSION : widget ExB data-loader) ───────────
# L'opérateur Pro dépose ses couches dans <mission>/<préparation>/ ; l'opérateur web les charge
# depuis son widget. Le serveur ne fait que lister / servir / déposer : parsing, symbologie et
# affichage restent côté navigateur. Les imports venus du web atterrissent dans le sous-dossier
# `web/` pour que la provenance reste lisible des deux côtés.
PREPA_SUBDIR = os.getenv("PREPA_SUBDIR", "2-Preparation").strip().strip("/")
PREPA_WEB_SUBDIR = os.getenv("PREPA_WEB_SUBDIR", "web").strip().strip("/")
PREPA_EXT = (".shp", ".kml", ".kmz", ".gpx", ".csv", ".xlsx", ".xls", ".geojson", ".json", ".zip")
PREPA_SIDECARS = (".dbf", ".shx", ".prj", ".cpg")      # annexes shapefile : jamais listées seules
PREPA_MAX_DEPTH = 2                                    # profondeur de parcours sous la préparation
_PREPA_DIR_CACHE = {}


def prepa_dir(label):
    """
    Dossier de préparation d'une mission. Chemin configuré (PREPA_SUBDIR) d'abord ; à défaut,
    premier sous-dossier de premier niveau dont le nom évoque la préparation — la numérotation du
    dossier MASTER a bougé au fil des versions, un renommage ne doit pas casser l'import.
    """
    c = _PREPA_DIR_CACHE.get(label)
    if c and os.path.isdir(c):
        return c
    mdir = snaps_mission_dir(label)                     # résolution + garde racine partagées avec les snaps
    d = os.path.realpath(os.path.join(mdir, PREPA_SUBDIR))
    if not (d.startswith(mdir + os.sep) and os.path.isdir(d)):
        d = None
        for n in sorted(os.listdir(mdir)):
            p = os.path.join(mdir, n)
            if os.path.isdir(p) and "prepa" in n.lower().replace("é", "e").replace("è", "e"):
                d = os.path.realpath(p)
                break
    if not d:
        raise FileNotFoundError("dossier de préparation introuvable pour %s (attendu : %s)" % (label, PREPA_SUBDIR))
    _PREPA_DIR_CACHE[label] = d
    return d


def prepa_path(label, rel, must_exist=True):
    """Fichier sous le dossier de préparation, avec garde anti-traversée."""
    root = prepa_dir(label)
    r = (rel or "").replace("\\", "/").strip("/")
    if not r or ".." in r.split("/"):
        raise ValueError("chemin invalide")
    p = os.path.realpath(os.path.join(root, r))
    if not p.startswith(root + os.sep):
        raise ValueError("accès refusé")
    if must_exist and not os.path.isfile(p):
        raise FileNotFoundError("fichier introuvable : %s" % rel)
    return p


def prepa_list(label):
    """
    Fichiers vecteur importables. Un shapefile est UNE entrée, avec l'état de ses annexes : le
    widget prévient qu'il manque le .prj avant que l'opérateur ne clique (sans projection, un
    fichier Lambert 93 se poserait à des milliers de kilomètres).
    """
    root = prepa_dir(label)
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        if depth >= PREPA_MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for n in sorted(filenames):
            ext = os.path.splitext(n)[1].lower()
            if ext not in PREPA_EXT:
                continue
            full = os.path.join(dirpath, n)
            try:
                st = os.stat(full)
            except OSError:
                continue
            e = {"path": os.path.relpath(full, root).replace(os.sep, "/"),
                 "name": os.path.splitext(n)[0], "ext": ext,
                 "kind": "shapeset" if ext == ".shp" else "file",
                 "size_bytes": st.st_size,
                 "modified": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(st.st_mtime))}
            if ext == ".shp":
                base = os.path.splitext(full)[0]
                present = {s: os.path.exists(base + s) for s in PREPA_SIDECARS}
                e["sidecars"] = present
                e["missing"] = [s for s in (".dbf", ".prj") if not present[s]]   # .shx = simple index
                e["complete"] = not e["missing"]
                e["size_bytes"] = st.st_size + sum(os.path.getsize(base + s) for s, ok in present.items() if ok)
            files.append(e)
    files.sort(key=lambda f: f["path"].lower())
    return {"mission_name": label, "dir": os.path.basename(root), "count": len(files), "files": files}


def prepa_shapeset(label, rel):
    """Shapefile complet zippé (.shp + annexes présentes) : le seul format qui garantit que
    géométries, attributs et projection arrivent ensemble dans un navigateur."""
    import io, zipfile
    shp = prepa_path(label, rel)
    if not shp.lower().endswith(".shp"):
        raise ValueError("le chemin doit désigner un .shp")
    base = os.path.splitext(shp)[0]
    name = os.path.basename(base)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(shp, name + ".shp")
        for s in PREPA_SIDECARS:
            if os.path.exists(base + s):
                z.write(base + s, name + s)
    return name + ".zip", buf.getvalue()


def prepa_upload(label, filename, data):
    """Dépose un fichier dans <préparation>/<PREPA_WEB_SUBDIR> (suffixe _vN en cas de collision,
    même convention que l'archivage des snaps)."""
    n = os.path.basename(filename or "")
    if not n or "/" in n or "\\" in n or ".." in n:
        raise ValueError("nom de fichier invalide")
    if os.path.splitext(n)[1].lower() not in (PREPA_EXT + PREPA_SIDECARS):
        raise ValueError("extension non acceptée : %s" % n)
    root = prepa_dir(label)
    dst_dir = os.path.realpath(os.path.join(root, PREPA_WEB_SUBDIR))
    if not dst_dir.startswith(root + os.sep):
        raise ValueError("accès refusé")
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, n)
    base, ext = os.path.splitext(n)
    v = 1
    while os.path.exists(dst):
        dst = os.path.join(dst_dir, "%s_v%d%s" % (base, v, ext))
        v += 1
    with open(dst, "wb") as f:
        f.write(data)
    return {"mission_name": label, "count": 1,
            "files": [{"path": os.path.relpath(dst, root).replace(os.sep, "/"), "size_bytes": len(data)}]}


def coverage_bands(times, max_gap, t0=0.0):
    """Plages [[début, fin] relatifs à t0] de présence d'un flux : instants triés, une coupure dès
    qu'un trou dépasse max_gap s (réception vidéo 4609 ≈ continue ; dwells radar 4607 par passes)."""
    out = []; a = b = None
    for t in times:
        if a is None:
            a = b = t
        elif t - b > max_gap:
            out.append([round(a - t0, 3), round(b - t0, 3)]); a = b = t
        else:
            b = t
    if a is not None:
        out.append([round(a - t0, 3), round(b - t0, 3)])
    return out


def timeline_data(path, limit=0, watch=None):
    """Événements datés de toute la capture (temps relatif au 1er paquet) : CoT (un par
    datagramme), dwells GMTI (zone, plots), offsets des flux vidéo. Mis en cache par pcap."""
    key = (os.path.abspath(path), os.path.getmtime(path), int(limit or 0), tuple(sorted(watch or [])))
    with _ALOCK:
        if key in _TL_CACHE:
            return _TL_CACHE[key]
    if is_csv_source(path):
        src = csv_source(path)
        t0 = src["t0"]
        dwells = [[round(d["t"] - t0, 3), d["sensor"], None, None, len(d["plots"]), int(round(d["t"] * 1000)), d["plots"]] for d in src["dwells"]]
        out = {"t0": t0, "duration": round((src["t1"] or 0) - (t0 or 0), 3), "n_packets": len(src["dwells"]),
               "cot": [], "dwells": dwells, "dwell_offset": 0.0, "video": [], "source": "csv"}
        with _ALOCK:
            _TL_CACHE[key] = out
        return out
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
    coverage = {"video": {str(st.dport): coverage_bands([p[0] for p in st.pkts], 2.0, t0 or 0) for st in streams.values()},
                "gmti": coverage_bands([d[0] for d in dwells], 6.0, 0.0)}
    out = {"t0": t0, "duration": round((ts - t0) if t0 is not None else 0.0, 3), "n_packets": n,
           "cot": cot, "dwells": dwells, "dwell_offset": dwell_offset, "video": video, "coverage": coverage}
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
        sts = tr.states
        for i, (t, x, y, st, hit) in enumerate(h):
            nm = names.get(st, "T")
            if nm in ("C", "S"):
                ever = True
            keep = hit or nm != last_nm or i == n - 1 or i == 0 or (i % step == 0)
            last_nm = nm
            if not keep:
                continue
            la, lo = fr.to_ll(float(x), float(y))
            sp = hd = None
            if i < len(sts):
                xs = sts[i][1]; sp = round(float(math.hypot(xs[2], xs[3])), 1); hd = round((math.degrees(math.atan2(float(xs[2]), float(xs[3]))) + 360.0) % 360.0, 1)
            hist.append([round(float(t) + off - t0, 3), round(la, 6), round(lo, 6), nm, 1 if hit else 0, 1 if ever else 0, sp, hd])
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
PCAP_EXT = (".pcap", ".pcapng", ".cap", ".csv")          # .csv = détections GMTI (enregistrement StratusServer / banc)
BASE_PATH = ""                                             # préfixe d'URL (derrière un reverse proxy : /console)
CAPTURES_DIR = None                                        # dossier proposé par défaut dans « Parcourir »


# ── Source CSV GMTI (schéma gmti_pcap_to_csv : enregistrement StratusServer par mission) ──
_CSV_CACHE = {}


def is_csv_source(path):
    return bool(path) and path.lower().endswith(".csv")


def csv_source(path):
    """Lit un CSV de détections GMTI (schéma du banc) → dwells triés [(t_s, sensor|None, plots[[lat,lon,vel,snr,cls]])],
    bornes, nb de plots, positions capteur. Mis en cache (chemin, mtime)."""
    import csv as _csv
    key = (os.path.abspath(path), os.path.getmtime(path))
    with _ALOCK:
        if key in _CSV_CACHE:
            return _CSV_CACHE[key]
    by = {}
    sensors = []
    n = 0
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in _csv.DictReader(f, delimiter=";"):
            try:
                t = int(float(r["dwell_time_ms"]))
                lat, lon = float(r["lat"]), float(r["lon"])
            except (KeyError, ValueError):
                continue
            k = (t, r.get("revisit_idx", ""), r.get("dwell_idx", ""))
            d = by.get(k)
            if d is None:
                sl = r.get("sensor_lat"), r.get("sensor_lon")
                sensor = [round(float(sl[0]), 6), round(float(sl[1]), 6)] if sl[0] and sl[1] else None
                d = by[k] = {"t": t / 1000.0, "sensor": sensor, "plots": []}
                if sensor and (not sensors or sensors[-1] != sensor):
                    sensors.append(sensor)
            def _num(v, scale=1.0):
                try:
                    return float(v) * scale if v not in (None, "") else None
                except ValueError:
                    return None
            cls = r.get("classification")
            d["plots"].append([round(lat, 6), round(lon, 6), _num(r.get("vel_los_cms")), _num(r.get("snr_db")),
                               int(float(cls)) if cls not in (None, "") else None])
            n += 1
    dwells = sorted(by.values(), key=lambda d: d["t"])
    out = {"dwells": dwells, "n_plots": n, "sensors": sensors,
           "t0": dwells[0]["t"] if dwells else None, "t1": dwells[-1]["t"] if dwells else None}
    with _ALOCK:
        _CSV_CACHE[key] = out
    return out



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
        last = st.get("last_pcap") or (os.path.join(CAPTURES_DIR, "x") if CAPTURES_DIR and os.path.isdir(CAPTURES_DIR) else None)
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


import gmti_live                                                  # noqa: E402  (partagé avec StratusServer)
TRACK_LOCK = gmti_live.TRACK_LOCK
_dest, _dist_bearing, dwell_area = gmti_live.dest_point, gmti_live.dist_bearing, gmti_live.dwell_area


def decode_gmti(pl):
    """Paquet(s) 4607 → (plots, sensor, dwells) prêts à dessiner ; None sinon (cf. gmti_live)."""
    r = gmti_live.decode_gmti(gmti_pcap_to_csv, pl)
    return None if r is None else r[:3]


def LiveTracker(profile="defaut", overrides=None):
    """Pistage temps réel (gmti_live.LiveTracker) sur le tracker versionné chargé par la console."""
    tr = load_track_run()
    return gmti_live.LiveTracker(tr, sys.modules["tracker"], profile, overrides)


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
        sink = PacketSink(self, taps, watch, live)

        def on_progress(sent, passes):
            with self.lock:
                self.state["sent"], self.state["passes"] = sent, passes
                if passes > 1 and self.state.get("_pass") != passes:
                    self.state["_pass"] = passes
                    sink.t_cap0 = None

        def log(msg):
            EVENTS.publish({"type": "log", "msg": str(msg)})

        try:
            if start_at:
                EVENTS.publish({"type": "log", "msg": "saut à t=%.1f s : rembobinage à blanc (état pistes/CoT reconstitué)…" % start_at})
            pcap_replay.do_routed_replay(pcap, args, table, should_stop=self.stop_event.is_set,
                                         on_progress=on_progress, log=log, on_packet=sink.on_packet,
                                         start_at=start_at, on_skip=sink.on_skip if start_at else None,
                                         is_paused=lambda: self.paused)
        except Exception as e:
            EVENTS.publish({"type": "log", "msg": "ERREUR rejeu : %s" % e})
        finally:
            sink.flush_app(force=True)
            with self.lock:
                self.state["running"] = False
                self.state["stopped"] = self.stop_event.is_set()
            sink.publish(force=True)
            EVENTS.publish({"type": "end", "stopped": self.stop_event.is_set()})


class PacketSink:
    """Consommateurs applicatifs d'un flux de paquets — COMMUNS au rejeu de pcap et à l'écoute
    réseau live : taps vidéo (→ /ws/video), CoT, plots/dwells GMTI + pistage temps réel
    (LiveTracker), compteurs, publication des événements sur /ws/events. `engine` fournit
    lock/state (le statut publié sous type "replay")."""

    def __init__(self, engine, taps, watch, live):
        self.engine = engine
        self.taps = set(int(t) for t in taps)
        self.watch = watch                       # set de clés "udp/1237" | None = tout
        self.live = live                         # LiveTracker | None
        self.counters = {}; self.t_cap0 = None; self.last_pub = 0.0
        self.wall0 = time.perf_counter(); self.bytes_out = 0; self.t_rel = 0.0
        self.cot_batch = {}; self.gmti_batch = {"plots": [], "sensor": None, "pkts": 0, "dwells": []}
        self.app_batch_at = time.perf_counter()
        self.totals = {"cot": 0, "gmti_plots": 0, "gmti_pkts": 0, "gmti_dwells": 0}
        self.skip_state = {"cot": {}, "n": 0, "first": None}

    # -- réglages à chaud (écoute live : cocher/décocher un flux sans redémarrer) --
    def follow(self, taps=None, watch=None, track=None):
        """taps/watch : None = inchangé ; track : None = inchangé, False = arrêt, dict = (re)démarrage."""
        if taps is not None:
            self.taps = set(int(t) for t in taps)
        if watch is not None:
            self.watch = set(str(w).lower() for w in watch)
        if track is not None:
            if track is False:
                self.live = None
            else:
                try:
                    if self.live is None or self.live.profile != (track.get("profile") or "defaut") or self.live.overrides != (track.get("overrides") or {}):
                        self.live = LiveTracker(track.get("profile") or "defaut", track.get("overrides") or {})
                except Exception as e:
                    EVENTS.publish({"type": "log", "msg": "pistage temps réel indisponible : %s (numpy/scipy manquants pour cet interpréteur ?)" % e})

    def publish(self, force=False):
        now = time.perf_counter()
        if not force and now - self.last_pub < 0.25:
            return
        self.last_pub = now
        with self.engine.lock:
            self.engine.state.update({"t": round(self.t_rel, 3), "flows": dict(self.counters), "bytes": self.bytes_out,
                                      "wall": round(now - self.wall0, 2)})
        EVENTS.publish({"type": "replay", **self.engine.status()})     # status() : + champs propres au live

    def flush_app(self, force=False):
        now = time.perf_counter()
        if not force and now - self.app_batch_at < 0.2:
            return
        self.app_batch_at = now
        if self.cot_batch:
            EVENTS.publish({"type": "cot", "t": round(self.t_rel, 3), "events": list(self.cot_batch.values()),
                            "total": self.totals["cot"]})
            self.cot_batch.clear()
        gb = self.gmti_batch
        if gb["pkts"]:
            plots = gb["plots"]
            if len(plots) > 4000:                          # décimation d'affichage
                plots = plots[::len(plots) // 4000 + 1]
            ev = {"type": "gmti", "t": round(self.t_rel, 3), "plots": plots, "sensor": gb["sensor"],
                  "dwells": gb["dwells"][-40:], "pkts": gb["pkts"],
                  "total_plots": self.totals["gmti_plots"], "total_pkts": self.totals["gmti_pkts"],
                  "total_dwells": self.totals["gmti_dwells"]}
            if self.live is not None:
                try:
                    ev["live"] = self.live.snapshot()
                except Exception as e:
                    ev["live"] = {"tracks": [], "stats": {"error": str(e)}}
            EVENTS.publish(ev)
            self.gmti_batch = {"plots": [], "sensor": None, "pkts": 0, "dwells": []}

    def on_skip(self, ts, proto, dport, pl):
        """Rembobinage à blanc (avant start_at) : état des trackers et du CoT sans affichage."""
        ss = self.skip_state
        if ss["first"] is None:
            ss["first"] = ts
            self.t_cap0 = ts                                      # l'horloge relative garde l'origine du pcap
        ss["n"] += 1
        key = "%s/%s" % (proto.lower(), dport)
        if self.watch is not None and key not in self.watch:
            return
        if pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
            ev = decode_cot(pl)
            if ev:
                ev["src"] = key; ss["cot"][ev["uid"] or ("#%d" % ss["n"])] = ev
        elif self.live is not None and gmti_pcap_to_csv is not None and len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
            if gmti_pcap_to_csv.looks_like_4607(pl):
                try:
                    self.live.step_dwells(gmti_pcap_to_csv.decode_packet_dwells(pl))
                except Exception:
                    pass

    def on_packet(self, ts, proto, dport, pl, tgts):
        if self.t_cap0 is None:
            self.t_cap0 = ts
        if self.skip_state["cot"]:                                # état CoT reconstitué au point de reprise
            EVENTS.publish({"type": "cot", "t": round(ts - self.t_cap0, 3), "events": list(self.skip_state["cot"].values()),
                            "total": len(self.skip_state["cot"]), "resumed": True})
            self.skip_state["cot"] = {}
        self.t_rel = ts - self.t_cap0
        key = "%s/%s" % (proto.lower(), dport)
        if tgts:
            self.counters[key] = self.counters.get(key, 0) + 1
            self.bytes_out += len(pl) * len(tgts)
        if proto == "UDP" and dport in self.taps:
            tsdata = v9._ts_from_udp(pl)
            if tsdata:
                video_bus(dport).publish(bytes(tsdata))
        elif self.watch is not None and key not in self.watch:
            pass                                                  # flux non coché : ni émis, ni affiché
        elif pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
            ev = decode_cot(pl)
            if ev:
                ev["src"] = key; self.totals["cot"] += 1
                self.cot_batch[ev["uid"] or ("#%d" % self.totals["cot"])] = ev
        elif len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
            g = decode_gmti(pl)
            if g is not None:
                plots, sensor, dw = g
                gb = self.gmti_batch
                gb["plots"].extend(plots); gb["pkts"] += 1
                gb["dwells"].extend(dw)
                if self.live is not None and gmti_pcap_to_csv is not None:
                    try:
                        self.live.step_dwells(gmti_pcap_to_csv.decode_packet_dwells(pl))
                    except Exception as e:
                        EVENTS.publish({"type": "log", "msg": "pistage temps réel : %s" % e})
                if sensor:
                    gb["sensor"] = sensor
                self.totals["gmti_plots"] += len(plots); self.totals["gmti_pkts"] += 1; self.totals["gmti_dwells"] += len(dw)
        self.flush_app()
        self.publish()


class LiveEngine:
    """Écoute réseau LIVE (net_capture) : mêmes consommateurs que le rejeu (PacketSink), plus une
    table de flux découverts au fil de l'eau (comme l'analyse d'un pcap, en continu) et un
    enregistrement pcap glissant optionnel. Un seul à la fois ; exclusif avec le rejeu."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"running": False}
        self.cap = None; self.sink = None; self.writer = None
        self.flows = {}                     # (proto, dport) -> {pkts, bytes, cls Counter, dsts set, srcs set, first, last}
        self.flow_lock = threading.Lock()
        self.stop_event = threading.Event(); self.thread = None

    def status(self):
        with self.lock:
            st = dict(self.state)
        st["live"] = True
        if self.cap is not None:
            st["captured"] = self.cap.n_frames; st["captured_bytes"] = self.cap.n_bytes; st["mode"] = self.cap.mode
        if self.writer is not None:
            st["recording"] = self.writer.current(); st["rec_files"] = list(self.writer.files)
        return st

    def flows_summary(self):
        with self.flow_lock:
            items = sorted(self.flows.items(), key=lambda kv: -kv[1]["bytes"])
            rows = []
            for (proto, dport), st in items:
                rows.append({"proto": proto, "dport": dport, "dominant": st["cls"].most_common(1)[0][0],
                             "pkts": st["pkts"], "bytes": st["bytes"], "dsts": sorted(st["dsts"]), "srcs": sorted(st["srcs"]),
                             "first": st["first"], "last": st["last"], "rate": st.get("rate", 0.0)})
            return rows

    def start(self, iface=None, ip=None, groups=(), ports=(), backend="auto", record=None,
              taps=(), watch=None, track=None):
        if net_capture is None:
            raise ValueError("module net_capture indisponible")
        with self.lock:
            if self.state.get("running"):
                raise ValueError("une écoute est déjà en cours")
            if ENGINE.status().get("running"):
                raise ValueError("un rejeu est en cours : l'arrêter d'abord")
            live = None
            warn = None
            if track:
                try:
                    live = LiveTracker(track.get("profile") or "defaut", track.get("overrides") or {})
                except Exception as e:                        # non bloquant : l'écoute continue sans pistage
                    warn = ("pistage temps réel indisponible : %s — l'écoute continue sans pistes (installer numpy/scipy "
                            "pour l'interpréteur qui lance la console : sous sudo → `sudo pip3 install numpy scipy`)" % e)
                    track = None
            wset = None if watch is None else set(str(w).lower() for w in watch)
            self.stop_event.clear()
            self.flows = {}
            self.state = {"running": True, "live": True, "iface": iface, "ip": ip, "groups": list(groups or []),
                          "ports": list(ports or []), "taps": list(taps), "watch": watch, "track": track,
                          "sent": 0, "passes": 1, "t": 0.0, "started": time.time(), "speed": 1, "paused": False, "loop": False,
                          "record": bool(record)}
            self.sink = PacketSink(self, taps, wset, live)
            self.writer = None
            if record:
                d = record.get("dir") or os.path.join(tempfile.gettempdir(), "pcap_web_live")
                self.writer = net_capture.PcapWriter(d, record.get("prefix") or "live", record.get("max_mb") or 200, record.get("keep") or 5)
            self.cap = net_capture.Capture(self._on_frame, iface=iface, ip=ip, groups=groups, ports=ports, backend=backend,
                                           log=lambda m: EVENTS.publish({"type": "log", "msg": "écoute : %s" % m}))
            try:
                mode = self.cap.start()
            except OSError as e:
                self.state = {"running": False, "live": True, "error": str(e)}
                self.cap = None
                raise ValueError("écoute impossible : %s" % e)
            self.state["mode"] = mode
        EVENTS.publish({"type": "log", "msg": "écoute réseau démarrée (%s)%s" % (mode, (" — enregistrement " + self.writer.dir) if self.writer else "")})
        if warn:
            EVENTS.publish({"type": "log", "msg": warn})
        self.thread = threading.Thread(target=self._ticker, daemon=True); self.thread.start()
        EVENTS.publish({"type": "replay", **self.status()})

    def _on_frame(self, ts, frame):
        if self.writer is not None:
            try:
                self.writer.write(ts, frame)
            except Exception as e:
                EVENTS.publish({"type": "log", "msg": "enregistrement : %s" % e}); self.writer = None
        r = pcap_analyze.parse(1, frame)
        if not r:
            return
        proto, src, sport, dst, dport, pl = r
        cls = pcap_analyze.classify(pl)
        with self.flow_lock:
            st = self.flows.get((proto, dport))
            if st is None:
                import collections
                st = self.flows[(proto, dport)] = {"pkts": 0, "bytes": 0, "cls": collections.Counter(), "dsts": set(), "srcs": set(),
                                                   "first": ts, "last": ts, "_win": []}
                new = True
            else:
                new = False
            st["pkts"] += 1; st["bytes"] += len(pl); st["cls"][cls] += 1
            st["dsts"].add(dst); st["srcs"].add(src); st["last"] = ts
        if new:
            EVENTS.publish({"type": "log", "msg": "nouveau flux : %s/%s %s (%s → %s)" % (proto.lower(), dport, cls, src, dst)})
        if proto == "UDP" and self.sink is not None:
            self.sink.on_packet(ts, proto, dport, pl, ())

    def _ticker(self):
        """Publication périodique du statut + table des flux (débits), même sans paquet."""
        last = {}
        while not self.stop_event.is_set():
            time.sleep(1.0)
            with self.flow_lock:
                for k, st in self.flows.items():
                    prev = last.get(k, (st["bytes"], time.time()))
                    dt = max(1e-3, time.time() - prev[1])
                    st["rate"] = round((st["bytes"] - prev[0]) * 8 / dt / 1000.0, 1)      # kbit/s
                    last[k] = (st["bytes"], time.time())
            if self.sink is not None:
                self.sink.flush_app(force=True)
            with self.lock:
                self.state["t"] = round(time.time() - self.state.get("started", time.time()), 1)
                if self.cap is not None and self.cap.err:
                    self.state["error"] = self.cap.err
            EVENTS.publish({"type": "replay", **self.status(), "flows_live": self.flows_summary()})

    def follow(self, taps=None, watch=None, track=None):
        if self.sink is None:
            raise ValueError("aucune écoute en cours")
        self.sink.follow(taps, watch, track)
        with self.lock:
            if taps is not None: self.state["taps"] = list(taps)
            if watch is not None: self.state["watch"] = list(watch)
            if track is not None: self.state["track"] = None if track is False else track
        return self.status()

    def stop(self):
        self.stop_event.set()
        cap, self.cap = self.cap, None
        if cap is not None:
            cap.stop()
        if self.writer is not None:
            self.writer.close()
        if self.sink is not None:
            self.sink.flush_app(force=True)
        with self.lock:
            self.state["running"] = False; self.state["stopped"] = True
        EVENTS.publish({"type": "replay", **self.status(), "flows_live": self.flows_summary()})
        EVENTS.publish({"type": "end", "stopped": True, "live": True})
        return self.status()


ENGINE = ReplayEngine()
LIVE = LiveEngine()


# ── Suivi d'un pcap EN COURS D'ÉCRITURE (DVR pendant le live) ───────────────
class PcapTail:
    """Lecteur incrémental d'un pcap classique (pas pcapng) : `read()` rend les trames complètes
    ajoutées depuis le dernier appel et mémorise l'offset ; un enregistrement partiel (écriture en
    cours) est relu au tour suivant. `incl` aberrant (en-tête déchiré) → arrêt propre."""
    MAX_INCL = 1 << 20

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        hdr = self.f.read(24)
        if len(hdr) < 24:
            self.f.close(); raise ValueError("en-tête pcap incomplet")
        magic = hdr[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            self.f.close(); raise ValueError("format non suivi (pcap classique attendu, magic %s)" % magic.hex())
        le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        self.nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        end = "<" if le else ">"
        self.linktype = struct.unpack(end + "I", hdr[20:24])[0]
        self.hdr = struct.Struct(end + "IIII")
        self.tsdiv = 1e9 if self.nano else 1e6
        self.offset = 24
        self.corrupt = False

    def read(self, max_bytes=64 << 20):
        """Liste de (ts, linktype, data, offset_enregistrement) des trames complètes disponibles (≤ max_bytes lus)."""
        out = []
        if self.corrupt:
            return out
        avail = self.size() - self.offset                      # ne demander QUE ce qui existe : read(64 Mo)
        if avail < 16:                                         # allouerait 64 Mo à chaque tour au bord du direct
            return out
        self.f.seek(self.offset)
        data = self.f.read(min(max_bytes, avail))
        pos, n = 0, len(data)
        while n - pos >= 16:
            ts_s, ts_frac, incl, _orig = self.hdr.unpack_from(data, pos)
            if incl > self.MAX_INCL:
                self.corrupt = True
                break
            if n - pos - 16 < incl:
                break                                          # enregistrement partiel : au tour suivant
            out.append((ts_s + ts_frac / self.tsdiv, self.linktype, data[pos + 16:pos + 16 + incl], self.offset + pos))
            pos += 16 + incl
        self.offset += pos
        return out

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


_SEG_RE = re.compile(r"^(.*)_(\d{3})\.pcap$", re.I)


def follow_segments(path):
    """Série de segments {base}_NNN.pcap (capture maître StratusServer v2) : (base, n) ou None."""
    m = _SEG_RE.match(os.path.basename(path))
    if not m:
        return None
    return os.path.join(os.path.dirname(path), m.group(1)), int(m.group(2))


class FollowStream:
    """Flux TS d'un pcap suivi : AUCUNE copie du TS en mémoire (le pcap sur disque est le maître) —
    seulement des compteurs et un index clairsemé (1 point / 0,5 s de capture) :
    ts → (segment, offset de l'enregistrement, octets TS cumulés avant lui). Le DVR relit le disque
    à partir du point d'index ; la RAM reste bornée quelle que soit la durée de la mission."""
    __slots__ = ("dst", "dport", "t0", "t1", "nbytes", "npkts", "idx_ts", "idx_seg", "idx_off", "idx_cum", "last_idx", "lock", "resume_pos", "fid")
    IDX_STEP_S = 0.5

    def __init__(self, dst, dport):
        import array
        self.dst, self.dport = dst, dport
        self.t0 = self.t1 = None; self.nbytes = 0; self.npkts = 0
        self.idx_ts = array.array("d"); self.idx_seg = array.array("H"); self.idx_off = array.array("Q"); self.idx_cum = array.array("Q")
        self.last_idx = None; self.resume_pos = None; self.fid = None
        self.lock = threading.Lock()

    def note(self, ts, seg_no, rec_off, n):
        """Comptabilise un datagramme TS ; renvoie le cumul d'octets si un point d'index a été ajouté, sinon None."""
        with self.lock:
            added = None
            if self.last_idx is None or ts - self.last_idx >= self.IDX_STEP_S:
                self.idx_ts.append(ts); self.idx_seg.append(seg_no); self.idx_off.append(rec_off); self.idx_cum.append(self.nbytes)
                self.last_idx = ts; added = self.nbytes
            self.nbytes += n; self.npkts += 1; self.t1 = ts
            return added

    def locate_time(self, t_abs):
        """Point d'index ≤ t_abs : (seg_no, offset, cumul) — ou le début du flux."""
        import bisect
        with self.lock:
            i = bisect.bisect_right(self.idx_ts, t_abs) - 1
            if i < 0:
                return (1, 24, 0) if not len(self.idx_seg) else (self.idx_seg[0], self.idx_off[0], 0)
            return (self.idx_seg[i], self.idx_off[i], self.idx_cum[i])

    def locate_bytes(self, cum):
        """Point d'index dont le cumul d'octets est ≤ cum : (seg_no, offset, cumul)."""
        import bisect
        with self.lock:
            i = bisect.bisect_right(self.idx_cum, cum) - 1
            if i < 0:
                return (1, 24, 0) if not len(self.idx_seg) else (self.idx_seg[0], self.idx_off[0], 0)
            return (self.idx_seg[i], self.idx_off[i], self.idx_cum[i])


class FollowEngine:
    """Lecture d'un pcap en cours d'écriture : rattrapage (tout ce qui existe déjà), puis suivi de la
    croissance du fichier et passage au segment suivant. Construit en continu la même ligne de temps
    que timeline_data (CoT, dwells GMTI, offsets vidéo) + l'historique des pistes du LiveTracker daté
    en temps de capture ; le client la précharge puis reçoit les ajouts (delta). Le TS vidéo est servi
    en HTTP Range (DVR : retour arrière) et poussé sur /ws/video au bord (direct)."""

    IDLE_STOP_S = 90.0                                   # arrêt automatique sans client (delta/status) depuis ce délai

    def __init__(self, fid=""):
        self.fid = fid
        self.lock = threading.Lock()
        self.state = {"running": False}
        self.stop_event = threading.Event(); self.thread = None
        self.last_touch = time.time()
        self._clear()

    def touch(self):
        self.last_touch = time.time()

    def _clear(self):
        self.t0 = None; self.last_ts = None; self.n_packets = 0
        self.cot = []; self.dwells = []; self.gmti_dt = []; self.dwell_offset = None
        self.klv = []; self._klv_last = {}                   # trace plateforme : [t_rel, lat, lon, alt, hdg, fc_lat, fc_lon] par dport, 1 pt / 0,5 s
        # GMTI live (C.3) : bus par moteur → /ws/gmti/{CR}, contrat du service v1 (gmti-live-isr, sensor-tracker)
        self.cr = None; self.system = False; self.gmti_bus = Bus()
        self.gmti_batch = {"plots": [], "sensor": None, "pkts": 0, "dwells": []}
        self.recent_plots = collections.deque(maxlen=2000); self.recent_dwells = collections.deque(maxlen=40)
        self.gmti_sensor = None; self.gmti_totals = {"gmti_plots": 0, "gmti_pkts": 0, "gmti_dwells": 0}; self.gmti_last_rx = None
        self.gmti_profile = "defaut"; self.gmti_overrides = {}
        self.tracks = {}; self.track_rows = []          # rows : (id, row) dans l'ordre d'ajout (delta)
        self.streams = {}; self.watch = None; self.taps = set(); self.live = None
        self.segments = []; self.cur_seg = None; self.catching_up = True; self.bytes_read = 0
        self.edge_wall = 0.0
        self._seg_base = None; self._single = None; self.seg_first = 1; self.idx_path = None; self._idx_last_a = None; self.indexed = False
        self.tl_path = None; self._tl_f = None; self._tl_pos = None; self._tl_flush = 0.0; self._tl_loaded = 0; self._id_offset = 0
        self.flows = {}                                 # (proto, dport) → inventaire (classe dominante, compteurs) — journalisé ("f")
        self.thumbs = None                              # générateur de vignettes (ThumbWorker) du suivi

    # -- statut --
    def status(self):
        with self.lock:
            st = dict(self.state)
        st.update({"follow": True, "id": self.fid, "duration": self.duration(), "t0": self.t0, "n_packets": self.n_packets,
                   "streams": self.video_info(), "flows": self.flows_info(),
                   "catching_up": self.catching_up, "segment": self.cur_seg, "segments": list(self.segments),
                   "bytes_read": self.bytes_read, "indexed": self.indexed, "journal": bool(self._tl_f is not None), "journal_loaded": self._tl_loaded, "edge_age_s": round(time.time() - self.edge_wall, 1) if self.edge_wall else None,
                   "seq": {"cot": len(self.cot), "dw": len(self.dwells), "tr": len(self.track_rows)}})
        return st

    def duration(self):
        return round((self.last_ts - self.t0), 3) if (self.t0 is not None and self.last_ts is not None) else 0.0

    # -- démarrage / arrêt --
    def start(self, path, watch=None, track=None, taps=()):
        with self.lock:
            if self.state.get("running"):
                raise ValueError("ce suivi est déjà en cours")
            # NB : un rejeu-émission (ENGINE) ou une écoute réseau (LIVE) peuvent tourner en même temps que des
            # suivis — ils n'ont aucune ressource commune (le verrou historique de la console mono-vue empêchait
            # le suivi système de démarrer quand la console du serveur servait à émettre un flux de test).
            if self.thread is not None and self.thread.is_alive():   # ancien suivi arrêté : attendre la fin de sa boucle
                self.stop_event.set(); self.thread.join(5.0)
            self._clear()
            self.watch = None if watch is None else set(str(w).lower() for w in watch)
            self.taps = set(int(t) for t in (taps or []))
            warn = None
            if track:
                try:
                    self.live = LiveTracker(track.get("profile") or "defaut", track.get("overrides") or {})
                except Exception as e:
                    warn = "pistage indisponible : %s" % e; track = None
            seg = follow_segments(path)
            if seg:
                base, n = seg                                   # base = dossier/mission (sans _NNN.pcap)
                self._seg_base = base; self._single = None
                self.seg_first = 1 if os.path.isfile("%s_001.pcap" % base) else n     # toute la série, même si l'utilisateur a ouvert _003
                self.idx_path = base + ".idx"                   # index persistant écrit par stratus2-capture (s'il existe)
                self.tl_path = base + ".tl.jsonl"               # journal de la ligne de temps décodée (écrit par la console)
            else:
                self._seg_base = None; self._single = path; self.seg_first = 1; self.idx_path = None
            self.segments = [self.seg_path(self.seg_first)]
            self.stop_event.clear()
            self.state = {"running": True, "pcap": path, "watch": watch, "track": track, "taps": list(self.taps),
                          "started": time.time(), "speed": 1, "paused": False, "loop": False, "t": 0.0}
        EVENTS.publish({"type": "log", "msg": "suivi du fichier : %s%s%s" % (path, " (série de segments)" if seg else "",
                                                                        " + index persistant" if (self.idx_path and os.path.isfile(self.idx_path)) else "")})
        if warn:
            EVENTS.publish({"type": "log", "msg": warn})
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()
        self.thumbs = ThumbWorker(self) if THUMBS_ON and self.mission_name() else None
        if self.thumbs:
            self.thumbs.start()

    def stop(self):
        self.stop_event.set()
        with self.lock:
            self.state["running"] = False; self.state["stopped"] = True
        self._tl_close()
        EVENTS.publish({"type": "log", "msg": "suivi du fichier arrêté (%d paquets, %.1f s)" % (self.n_packets, self.duration())})
        return self.status()

    # -- segments (numéro du fichier _NNN ; 1 pour un fichier isolé) --
    def seg_path(self, n):
        if self._seg_base:
            return "%s_%03d.pcap" % (self._seg_base, n)
        return self._single if n == 1 else None

    def _seg_exists(self, n):
        p = self.seg_path(n)
        return bool(p) and os.path.isfile(p)

    # -- journal de la ligne de temps décodée ({mission}.tl.jsonl) --
    # Une ligne JSON par élément : ["h", {t0}] en-tête · ["c", row] CoT · ["d", row] dwell (avec plots) ·
    # ["m", {id, air, rot}] nouvelle piste · ["t", id, row] état de piste · ["p", seg, off] point de reprise
    # (tous les paquets applicatifs ≤ (seg, off) sont journalisés). Au redémarrage, les lignes jusqu'au
    # dernier "p" sont rechargées telles quelles : plus rien à redécoder, quelle que soit la durée.
    def _tl_open(self):
        if not self.tl_path or self._tl_f is not None:
            return
        try:
            new = not os.path.isfile(self.tl_path) or os.path.getsize(self.tl_path) == 0
            self._tl_f = open(self.tl_path, "a", encoding="utf-8")
            if new:
                self._tl_f.write(json.dumps(["h", {"v": 1, "t0": self.t0}]) + "\n")
        except OSError as e:
            EVENTS.publish({"type": "log", "msg": "journal de ligne de temps indisponible : %s" % e}); self._tl_f = None; self.tl_path = None

    def _tl_write(self, *item):
        if self._tl_f is not None:
            try:
                self._tl_f.write(json.dumps(list(item), ensure_ascii=False, separators=(",", ":")) + "\n")
            except (OSError, ValueError):
                pass

    def _tl_checkpoint(self, seg_no, rec_off, force=False):
        """Point de reprise après le paquet applicatif (seg_no, rec_off) ; flush toutes les 2 s."""
        self._tl_pos = (seg_no, rec_off)
        now = time.time()
        if self._tl_f is not None and (force or now - self._tl_flush >= 2.0):
            self._tl_write("p", seg_no, rec_off)
            try:
                self._tl_f.flush()
            except OSError:
                pass
            self._tl_flush = now

    def _tl_close(self):
        if self._tl_f is not None:
            if self._tl_pos:
                self._tl_write("p", *self._tl_pos)
            try:
                self._tl_f.close()
            except OSError:
                pass
            self._tl_f = None

    def _tl_load(self):
        """Recharge le journal (lignes jusqu'au dernier point de reprise). Renvoie (seg, off) couvert, ou None."""
        if not self.tl_path or not os.path.isfile(self.tl_path):
            return None
        cot, dwells, tracks, rows, pos, t0 = [], [], {}, [], None, None
        klv = []
        vstreams = {}                                              # dport -> FollowStream reconstruit (points "v")
        pend = []                                                  # lignes depuis le dernier "p" (non validées)
        with open(self.tl_path, encoding="utf-8") as f:
            for line in f:
                try:
                    it = json.loads(line)
                except ValueError:
                    continue
                k = it[0]
                if k == "h":
                    t0 = it[1].get("t0")
                elif k == "f":                                     # flux (inventaire) — idempotent
                    _k, proto, dport, cls, dst = it
                    if (proto, dport) not in self.flows:
                        self.flows[(proto, dport)] = {"proto": proto, "dport": dport, "dominant": cls, "pkts": 0, "bytes": 0, "dsts": {dst} if dst else set()}
                elif k == "v":                                     # point d'index vidéo (validé immédiatement : idempotent)
                    _k, dport, dst, vts, seg, off, cum = it
                    st = vstreams.get(dport)
                    if st is None:
                        st = vstreams[dport] = FollowStream(dst, dport); st.t0 = vts; st.fid = self.fid
                    st.idx_ts.append(vts); st.idx_seg.append(seg); st.idx_off.append(off); st.idx_cum.append(cum)
                    st.last_idx = vts; st.nbytes = cum; st.t1 = vts; st.resume_pos = (seg, off)
                elif k == "p":
                    for pk in pend:
                        if pk[0] == "c":
                            cot.append(pk[1])
                        elif pk[0] == "d":
                            dwells.append(pk[1])
                        elif pk[0] == "k":
                            klv.append(pk[1])
                        elif pk[0] == "m":
                            m = pk[1]; tracks.setdefault(m["id"], {"id": m["id"], "air": m.get("air", False), "rot": m.get("rot", False), "hits": m.get("hits", 0), "hist": []})
                        elif pk[0] == "t":
                            r = tracks.get(pk[1])
                            if r is None:
                                r = tracks[pk[1]] = {"id": pk[1], "air": False, "rot": False, "hits": 0, "hist": []}
                            r["hist"].append(pk[2]); rows.append((pk[1], pk[2]))
                    pend = []; pos = (int(it[1]), int(it[2]))
                else:
                    pend.append(it)
        if pos is None or t0 is None:
            try:
                os.remove(self.tl_path)                            # journal sans point de reprise : repart de zéro
            except OSError:
                pass
            return None
        self.streams.update(vstreams)
        resume = pos
        for st in vstreams.values():                               # reprise séquentielle au plus ancien des points
            if st.resume_pos and st.resume_pos < resume:
                resume = st.resume_pos
        self.t0 = t0; self.cot = cot; self.dwells = dwells; self.tracks = tracks; self.track_rows = rows; self.klv = klv
        for r in klv:
            self._klv_last[r[7] if len(r) > 7 else 0] = t0 + r[0]
        self._id_offset = max(tracks) if tracks else 0
        gd = sorted(t0 + d[0] - d[5] / 1000.0 for d in dwells[:200] if d[5] is not None)
        self.dwell_offset = gd[len(gd) // 2] if gd else None; self.gmti_dt = gd
        if dwells or cot:
            self.last_ts = t0 + max((cot[-1][0] if cot else 0), (dwells[-1][0] if dwells else 0))
        self._tl_loaded = len(cot) + len(dwells) + len(rows) + len(klv)
        return resume, pos                                         # (reprise séquentielle, dernier paquet applicatif journalisé)

    # -- index persistant (STRIDX01, écrit par stratus2-capture) --
    IDX_REC = struct.Struct("<cdHQQH")

    def _load_index(self):
        """Rattrapage instantané : points vidéo → index des flux ; paquets applicatifs → relus un à un
        (seek direct) pour CoT / dwells / pistes. Renvoie la position (segment, offset) où la lecture
        séquentielle reprend (≤ 0,5 s avant le bord)."""
        with open(self.idx_path, "rb") as f:
            if f.read(8) != b"STRIDX01":
                raise ValueError("format d'index inconnu")
            data = f.read()
        R = self.IDX_REC; n = len(data) // R.size
        handles = {}; last_v = {}; last_a = self._idx_last_a; last_pos = None; n_a = 0
        skip_a = self._idx_last_a                                  # paquets applicatifs déjà dans le journal
        try:
            for i in range(n):
                kind, ts, seg, off, val, dport = R.unpack_from(data, i * R.size)
                if self.t0 is None:
                    self.t0 = ts
                if kind == b"V":
                    st = self.streams.get(dport)
                    if st is None:
                        st = self.streams[dport] = FollowStream("?", dport); st.t0 = ts; st.fid = self.fid
                    st.idx_ts.append(ts); st.idx_seg.append(seg); st.idx_off.append(off); st.idx_cum.append(val)
                    st.last_idx = ts; st.nbytes = val; st.t1 = ts; last_v[dport] = (seg, off)
                else:
                    if skip_a is not None and (seg, off) <= skip_a:
                        last_pos = (seg, off) if last_pos is None or (seg, off) > last_pos else last_pos
                        continue
                    f = handles.get(seg)
                    if f is None:
                        p = self.seg_path(seg)
                        if not p or not os.path.isfile(p):
                            continue
                        f = handles[seg] = open(p, "rb")
                    f.seek(off); h = f.read(16)
                    if len(h) < 16:
                        continue
                    ts_s, ts_us, incl, _o = struct.unpack("<IIII", h)
                    if incl > PcapTail.MAX_INCL:
                        continue
                    frame = f.read(incl)
                    if len(frame) < incl:
                        continue
                    self._idx_last_a = None                    # (le filtre du journal est déjà appliqué ici)
                    self._on_frame(ts_s + ts_us / 1e6, 1, frame, seg, off); n_a += 1
                    last_a = (seg, off)
                last_pos = (seg, off) if last_pos is None or (seg, off) > last_pos else last_pos
                self.last_ts = max(self.last_ts or ts, ts)
        finally:
            for f in handles.values():
                f.close()
        self._idx_last_a = last_a
        for dport, pos in last_v.items():
            self.streams[dport].resume_pos = pos
        resume = min(last_v.values()) if last_v else last_pos
        self.indexed = True
        EVENTS.publish({"type": "log", "msg": "suivi : index chargé — %d flux vidéo, %d paquets applicatifs relus, %.1f s" % (len(last_v), n_a, self.duration())})
        return resume

    def _run(self):
        n = self.seg_first
        tail = None; idle_polls = 0; resume = None
        _t0 = time.perf_counter(); tl_resume = None
        try:
            tlr = self._tl_load()
            if tlr:
                tl_resume, self._idx_last_a = tlr
                print("[follow] journal chargé en %.2fs : %d éléments, reprise %s, applicatif après %s" % (time.perf_counter() - _t0, self._tl_loaded, tl_resume, self._idx_last_a), flush=True)
                EVENTS.publish({"type": "log", "msg": "suivi : ligne de temps rechargée (%d CoT, %d dwells, %d pistes)" % (len(self.cot), len(self.dwells), len(self.tracks))})
        except Exception as e:
            EVENTS.publish({"type": "log", "msg": "suivi : journal inutilisable (%s) — redécodage" % e})
            self.cot = []; self.dwells = []; self.tracks = {}; self.track_rows = []; self._idx_last_a = None; self.t0 = None; self._id_offset = 0
        if self.idx_path and os.path.isfile(self.idx_path):
            try:
                resume = self._load_index()
                print("[follow %s] index chargé en %.2fs → reprise %s" % (self.fid, time.perf_counter() - _t0, resume), flush=True)
            except Exception as e:
                EVENTS.publish({"type": "log", "msg": "suivi : index inutilisable (%s) — rattrapage complet" % e})
                self.streams = {}; self.cot = []; self.dwells = []; self.tracks = {}; self.track_rows = []; self._idx_last_a = None
                self.t0 = self.last_ts = None; self.n_packets = 0; resume = None
            if resume:
                n = resume[0]
        elif self._idx_last_a and not resume:
            resume = tl_resume                                     # pas d'index : reprise séquentielle après le journal
            n = resume[0]
        try:
            while not self.stop_event.is_set():
                if tail is None:
                    path = self.seg_path(n)
                    try:
                        tail = PcapTail(path)
                    except (OSError, ValueError, TypeError) as e:
                        EVENTS.publish({"type": "log", "msg": "suivi : %s" % e}); time.sleep(1.0); continue
                    if resume and resume[0] == n:
                        tail.offset = max(24, resume[1]); resume = None
                    self.cur_seg = path
                    if path not in self.segments:
                        self.segments.append(path)
                    print("[follow] %.2fs segment %s offset %d / %d" % (time.perf_counter() - _t0, os.path.basename(path), tail.offset, tail.size()), flush=True)
                    EVENTS.publish({"type": "log", "msg": "suivi : segment %s" % os.path.basename(path)})
                frames = tail.read()
                if frames:
                    idle_polls = 0
                    for ts, lt, data, rec_off in frames:
                        self._on_frame(ts, lt, data, n, rec_off)
                    self.bytes_read = tail.offset
                    self.edge_wall = time.time()
                    if self.catching_up and tail.offset >= tail.size() and not self._seg_exists(n + 1):
                        self.catching_up = False
                        print("[follow] %.2fs rattrapage terminé (%d paquets)" % (time.perf_counter() - _t0, self.n_packets), flush=True)
                        EVENTS.publish({"type": "log", "msg": "suivi : rattrapage terminé (%d paquets, %.1f s) — au bord du direct" % (self.n_packets, self.duration())})
                    continue
                # pas de nouvelle trame : segment suivant disponible ?
                if self._seg_exists(n + 1) and tail.offset >= tail.size():
                    idle_polls += 1
                    if idle_polls >= 3 or self.catching_up:       # 3 tours sans croissance → l'écrivain est passé au suivant
                        tail.close(); tail = None; n += 1; idle_polls = 0
                        continue
                if self.catching_up and tail.offset >= tail.size():
                    self.catching_up = False
                    EVENTS.publish({"type": "log", "msg": "suivi : rattrapage terminé (%d paquets, %.1f s) — au bord du direct" % (self.n_packets, self.duration())})
                time.sleep(0.3)
        finally:
            if tail is not None:
                tail.close()

    def _on_frame(self, ts, lt, frame, seg_no=0, rec_off=0):
        r = parse(lt, frame)
        if not r:
            return
        proto, src, sport, dst, dport, pl = r
        if not pl:
            return
        if self.t0 is None:
            self.t0 = ts
        if self._tl_f is None and self.tl_path:
            self._tl_open()
        self.last_ts = ts; self.n_packets += 1
        t_rel = round(ts - self.t0, 3)
        if proto == "UDP":
            st = self.streams.get(dport)
            tsdata = v9._ts_from_udp(pl) if (st is not None or len(pl) >= TS_PKT) else None
            if tsdata:
                if st is None:
                    st = self.streams[dport] = FollowStream(dst, dport); st.fid = self.fid
                    st.t0 = ts
                elif st.dst == "?":
                    st.dst = dst
                if st.resume_pos is not None:
                    if (seg_no, rec_off) < st.resume_pos:
                        return                                     # déjà compté par l'index
                    st.resume_pos = None
                cum = st.note(ts, seg_no, rec_off, len(tsdata))
                self._flow("UDP", dport, dst, len(pl), cls="MPEG-TS/4609(video)")
                if cum is not None:
                    self._tl_write("v", dport, dst, round(ts, 6), seg_no, rec_off, cum)
                if ts - self._klv_last.get(dport, -1e9) >= 0.5 and (self._idx_last_a is None or (seg_no, rec_off) > self._idx_last_a):
                    d = klv_from_ts(tsdata)
                    if d and 13 in d and 14 in d:
                        n = klv_numeric(d)
                        if n["lat"] is not None and n["lon"] is not None:
                            row = [t_rel, n["lat"], n["lon"], n["alt"], n["hdg"], n["fc_lat"], n["fc_lon"], dport]
                            self.klv.append(row); self._tl_write("k", row); self._klv_last[dport] = ts
                if not self.catching_up and dport in self.taps:
                    video_bus("%s:%d" % (self.fid, dport)).publish(bytes(tsdata))
                return
        key = "%s/%s" % (proto.lower(), dport)
        if self._idx_last_a is not None and (seg_no, rec_off) <= self._idx_last_a:
            return                                                 # déjà relu via l'index / le journal
        self._flow(proto, dport, dst, len(pl), pl=pl)
        if self.watch is not None and key not in self.watch:
            return
        if pl[:1] == b"<" or pl[:6].lstrip()[:1] == b"<":
            ev = decode_cot(pl)
            if ev:
                row = [t_rel, ev["uid"], ev["type"], ev["aff"], ev.get("callsign"), ev["lat"], ev["lon"], ev.get("speed"), ev.get("course"), key]
                self.cot.append(row); self._tl_write("c", row)
            self._tl_checkpoint(seg_no, rec_off)
        elif len(pl) > 37 and 32 <= pl[0] < 127 and 32 <= pl[1] < 127:
            g = decode_gmti(pl)
            if g is None:
                return
            plots, sensor, dw = g
            n_dw0 = len(self.dwells)
            for d in dw:
                self.dwells.append([t_rel, sensor, d["center"], d["poly"], d["n"], d.get("t_ms")])
                if d.get("t_ms") is not None and len(self.gmti_dt) < 200:
                    self.gmti_dt.append(ts - d["t_ms"] / 1000.0)
                    if len(self.gmti_dt) >= 20 or self.dwell_offset is None:
                        s_ = sorted(self.gmti_dt); self.dwell_offset = s_[len(s_) // 2]     # figé après 200 dwells
            if plots and not dw:
                self.dwells.append([t_rel, sensor, None, None, len(plots), None])
            if plots:
                self.dwells[-1].append(plots)
            for row in self.dwells[n_dw0:]:
                self._tl_write("d", row)
            if self.live is not None and gmti_pcap_to_csv is not None:
                try:
                    self.live.step_dwells(gmti_pcap_to_csv.decode_packet_dwells(pl))
                    self._track_rows(t_rel)
                except Exception as e:
                    EVENTS.publish({"type": "log", "msg": "suivi : pistage : %s" % e})
            self.gmti_totals["gmti_plots"] += len(plots); self.gmti_totals["gmti_pkts"] += 1; self.gmti_totals["gmti_dwells"] += len(dw)
            self.gmti_last_rx = time.time()
            if sensor:
                self.gmti_sensor = sensor
            if not self.catching_up:                               # live : batch pour les abonnés /ws/gmti
                gb = self.gmti_batch
                gb["plots"].extend(plots); gb["pkts"] += 1; gb["dwells"].extend(dw)
                if sensor:
                    gb["sensor"] = sensor
                self.recent_plots.extend(plots); self.recent_dwells.extend(dw)
            self._tl_checkpoint(seg_no, rec_off)

    def _track_rows(self, t_rel):
        """Historique des pistes (même forme que timeline_tracks) : une ligne par piste vivante et par
        dwell traité, datée en temps de capture (pas de dwell_offset : le paquet fait foi)."""
        lv = self.live
        T = lv.T
        if lv.tk is None or lv.frame is None:
            return
        names = {T.TENTATIVE: "T", T.CONFIRMED: "C", T.SOLID: "S", T.COASTING: "K", T.DEAD: "D"}
        with TRACK_LOCK:
            last_t = lv.last_t
            for tr in lv.tk.tracks:
                st = tr.state
                if st == T.DEAD:
                    continue
                la, lo = lv.frame.to_ll(float(tr.x[0]), float(tr.x[1]))
                nm = names.get(st, "T")
                hit = 1 if (last_t is not None and abs(float(tr.t_last_update) - last_t) < 1e-6) else 0
                sp = round(float(tr.speed()), 1)
                hd = round((math.degrees(math.atan2(float(tr.x[2]), float(tr.x[3]))) + 360.0) % 360.0, 1)
                tid = tr.id + self._id_offset                     # pistes rechargées du journal : pas de collision d'id
                rec = self.tracks.get(tid)
                if rec is None:
                    rec = self.tracks[tid] = {"id": tid, "air": bool(tr.is_air), "rot": bool(tr.is_rotator), "hits": 0, "hist": []}
                    self._tl_write("m", {"id": tid, "air": rec["air"], "rot": rec["rot"]})
                rec["hits"] = tr.hits; rec["air"] = bool(tr.is_air); rec["rot"] = bool(tr.is_rotator)
                row = [t_rel, round(la, 6), round(lo, 6), nm, hit, 1 if tr.confirmed_ever else 0, sp, hd]
                rec["hist"].append(row); self.track_rows.append((tid, row)); self._tl_write("t", tid, row)

    def _flow(self, proto, dport, dst, n, cls=None, pl=None):
        k = (proto, dport); f = self.flows.get(k)
        if f is None:
            f = self.flows[k] = {"proto": proto, "dport": dport, "dominant": cls or pcap_analyze.classify(pl or b""), "pkts": 0, "bytes": 0, "dsts": set()}
            self._tl_write("f", proto, dport, f["dominant"], dst)
        f["pkts"] += 1; f["bytes"] += n
        if len(f["dsts"]) < 8:
            f["dsts"].add(dst)

    def flows_info(self):
        return [{"proto": f["proto"], "dport": f["dport"], "dominant": f["dominant"], "pkts": f["pkts"], "bytes": f["bytes"], "dsts": sorted(f["dsts"])}
                for f in sorted(self.flows.values(), key=lambda f: -f["bytes"])]

    # -- vues client --
    def video_info(self):
        return [{"dport": st.dport, "dst": st.dst, "t_offset": round((st.t0 or self.t0 or 0) - (self.t0 or 0), 3),
                 "duration": round((st.t1 or 0) - (st.t0 or 0), 3), "bytes": st.nbytes} for st in self.streams.values()]

    def coverage(self):
        """Présence des flux depuis l'index : points vidéo (0,5 s → trou si > 2 s), dwells radar (trou > 6 s)."""
        vid = {}
        for st in self.streams.values():
            with st.lock:
                pts = list(st.idx_ts)
            if st.t1 is not None and (not pts or st.t1 > pts[-1]):
                pts.append(st.t1)
            vid[str(st.dport)] = coverage_bands(pts, 2.0, self.t0 or 0)
        return {"video": vid, "gmti": coverage_bands([d[0] for d in self.dwells], 6.0, 0.0)}

    def timeline(self):
        return {"t0": self.t0, "duration": self.duration(), "n_packets": self.n_packets, "cot": list(self.cot), "coverage": self.coverage(),
                "dwells": list(self.dwells), "dwell_offset": self.dwell_offset, "video": self.video_info(),
                "tracks": [{"id": r["id"], "air": r["air"], "rot": r["rot"], "hits": r["hits"], "hist": list(r["hist"])} for r in self.tracks.values()],
                "klv": list(self.klv), "mission": self.mission_name(), "clips": clips_list(self.mission_name()) if self.mission_name() else [],
                "captures": captures_list(self.mission_name()) if self.mission_name() else [],
                "follow": True, "catching_up": self.catching_up, "seq": {"cot": len(self.cot), "dw": len(self.dwells), "tr": len(self.track_rows), "k": len(self.klv)}}

    def mission_name(self):
        """Nom de la mission suivie (dossier {recordings}/{mission}/Capture/{mission}_NNN.pcap) — None hors dossier des enregistrements."""
        base = self._seg_base or self._single
        if not base or not CAPTURES_DIR:
            return None
        d = os.path.dirname(os.path.abspath(base))
        if os.path.basename(d).lower() == "capture":
            d = os.path.dirname(d)
        if os.path.dirname(d) != os.path.abspath(CAPTURES_DIR):
            return None
        return os.path.basename(d)

    def track_geojson(self, dport=None):
        """Trace plateforme (LineString par flux vidéo, WGS84) — équivalent v2 de /api/streams/{CR}/track.geojson."""
        by = {}
        t0 = self.t0 or 0
        for r in self.klv:
            if dport is not None and r[7] != dport:
                continue
            e = by.setdefault(r[7], {"pts": [], "times": []})
            e["pts"].append([r[2], r[1], r[3] if r[3] is not None else 0]); e["times"].append(int(round((t0 + r[0]) * 1000)))
        mission = os.path.basename(self._seg_base or self.state.get("pcap", ""))
        feats = [{"type": "Feature", "properties": {"dport": dp, "n": len(e["pts"]), "mission": mission, "mode": "full", "times": e["times"]},
                  "geometry": {"type": "LineString", "coordinates": e["pts"]}} for dp, e in by.items() if len(e["pts"]) > 1]
        return {"type": "FeatureCollection", "features": feats, "t0": self.t0, "duration": self.duration(), "mission_name": mission}

    def mission_closed(self):
        """mission.json (stratus2-capture) : closed = la capture est terminée (silence > SILENCE_S)."""
        if not self._seg_base:
            return False
        p = os.path.join(os.path.dirname(self._seg_base), "mission.json")
        try:
            mt = os.path.getmtime(p)
            c = getattr(self, "_closed_cache", None)
            if c and c[0] == mt:
                return c[1]
            with open(p, encoding="utf-8") as f:
                v = bool(json.load(f).get("closed"))
            self._closed_cache = (mt, v)
            return v
        except (OSError, ValueError):
            return False

    def delta(self, cot_i, dw_i, tr_i, k_i=0):
        rows = self.track_rows[tr_i:]
        meta = {}
        for tid, _r in rows:
            if tid not in meta:
                r = self.tracks[tid]; meta[tid] = {"id": tid, "air": r["air"], "rot": r["rot"], "hits": r["hits"]}
        return {"duration": self.duration(), "n_packets": self.n_packets, "cot": self.cot[cot_i:], "dwells": self.dwells[dw_i:],
                "track_rows": [[tid, row] for tid, row in rows], "track_meta": list(meta.values()), "video": self.video_info(), "coverage": self.coverage(),
                "catching_up": self.catching_up, "segment": os.path.basename(self.cur_seg) if self.cur_seg else None,
                "edge_age_s": round(time.time() - self.edge_wall, 1) if self.edge_wall else None, "closed": self.mission_closed(),
                "klv": self.klv[k_i:],
                "seq": {"cot": len(self.cot), "dw": len(self.dwells), "tr": len(self.track_rows), "k": len(self.klv)}}

    def stream(self, dport=None):
        if not self.streams:
            raise ValueError("aucun flux TS dans le fichier suivi (pour l'instant)")
        if dport:
            st = self.streams.get(int(dport))
            if st is None:
                raise ValueError("pas de flux TS sur le port %s" % dport)
            return st
        return max(self.streams.values(), key=lambda s: s.nbytes)

    # -- lecture disque (DVR) --
    def iter_ts(self, st, seg_no, rec_off, skip=0, t_min=None, t_max=None):
        """TS du flux `st` relu depuis le disque à partir de (segment, offset) : saute `skip` octets
        (reprise Range) et/ou les datagrammes datés < t_min ; s'arrête au premier datagramme > t_max
        (extraction de clip) ; enchaîne les segments suivants existants et s'arrête au bord (fin des
        données écrites)."""
        n = seg_no
        while self._seg_exists(n):
            try:
                tail = PcapTail(self.seg_path(n))
            except (OSError, ValueError):
                return
            if n == seg_no:
                tail.offset = max(24, rec_off)
            try:
                while True:
                    frames = tail.read(4 << 20)
                    if not frames:
                        if self._seg_exists(n + 1) and tail.offset >= tail.size():
                            break                                  # segment suivant
                        return                                     # bord du direct : fin de la ressource
                    for ts, lt, data, _off in frames:
                        r = parse(lt, data)
                        if not r or r[0] != "UDP" or r[4] != st.dport or not r[5]:
                            continue
                        if t_min is not None and ts < t_min:
                            continue
                        if t_max is not None and ts > t_max:
                            return
                        tsdata = v9._ts_from_udp(r[5])
                        if not tsdata:
                            continue
                        if skip:
                            if skip >= len(tsdata):
                                skip -= len(tsdata); continue
                            tsdata = tsdata[skip:]; skip = 0
                        yield bytes(tsdata)
            finally:
                tail.close()
            n += 1

    def follow(self, taps=None, track=None):
        if taps is not None:
            self.taps = set(int(t) for t in taps)
            with self.lock:
                self.state["taps"] = list(self.taps)
        return self.status()

    # -- GMTI live (contrat du service v1) --
    def gmti_status(self):
        now = time.time()
        st = self.live._stats(0, 0, 0, 0) if self.live else {}
        return {"port": self.cr, "udp_port": next((int(p) for p in _capture_sets_by_cr().get(self.cr or "", [])[1:2]), None),
                "profile": self.gmti_profile, "overrides": self.gmti_overrides,
                "receiving": bool(self.gmti_last_rx and now - self.gmti_last_rx < 10.0),
                "last_rx_age_s": round(now - self.gmti_last_rx, 1) if self.gmti_last_rx else None,
                "totals": dict(self.gmti_totals), "n_dwells": st.get("n_dwells", 0), "n_ghosts": st.get("n_ghosts", 0),
                "n_clustered": st.get("n_clustered", 0), "n_absorbed": st.get("n_absorbed", 0), "n_resets": st.get("n_resets", 0),
                "tracks_alive": len(self.live.tk.tracks) if (self.live and self.live.tk) else 0,
                "subscribers": len(self.gmti_bus.subs), "recording": self.state.get("pcap"), "errors": 0,
                "mission_name": os.path.basename(self._seg_base or ""), "catching_up": self.catching_up}

    def gmti_snapshot_event(self):
        try:
            snap = self.live.snapshot() if self.live else {"tracks": [], "contacts": None, "stats": {}}
        except Exception as e:
            snap = {"tracks": [], "contacts": None, "stats": {"error": str(e)}}
        return {"type": "snapshot", "port": self.cr, "t": round(time.time(), 3), "plots": list(self.recent_plots), "sensor": self.gmti_sensor,
                "dwells": list(self.recent_dwells), "total_plots": self.gmti_totals["gmti_plots"], "total_pkts": self.gmti_totals["gmti_pkts"],
                "total_dwells": self.gmti_totals["gmti_dwells"], "live": snap, "status": self.gmti_status()}

    def gmti_flush(self):
        """Batch 4607 → abonnés (appelé par gmti_ticker à ~4 Hz)."""
        gb = self.gmti_batch
        if not gb["pkts"]:
            return
        plots = gb["plots"]
        if len(plots) > 4000:
            plots = plots[::len(plots) // 4000 + 1]
        ev = {"type": "gmti", "port": self.cr, "t": round(time.time(), 3), "plots": plots, "sensor": gb["sensor"], "dwells": gb["dwells"][-40:],
              "pkts": gb["pkts"], "total_plots": self.gmti_totals["gmti_plots"], "total_pkts": self.gmti_totals["gmti_pkts"], "total_dwells": self.gmti_totals["gmti_dwells"]}
        try:
            ev["live"] = self.live.snapshot() if self.live else {"tracks": [], "contacts": None, "stats": {}}
        except Exception as e:
            ev["live"] = {"tracks": [], "contacts": None, "stats": {"error": str(e)}}
        self.gmti_batch = {"plots": [], "sensor": None, "pkts": 0, "dwells": []}
        self.gmti_bus.publish(ev)

    def set_gmti_profile(self, profile=None, overrides=None, reset=False):
        if self.live is None:
            raise ValueError("pistage indisponible sur ce suivi")
        self.live.set_profile(profile, overrides, reset)
        if profile:
            self.gmti_profile = profile
        if overrides is not None:
            self.gmti_overrides = dict(overrides)
        if reset:
            self.recent_plots.clear(); self.recent_dwells.clear()
        self.gmti_bus.publish({"type": "status", **self.gmti_status()})


FOLLOWS = {}                                          # id → FollowEngine (un par mission suivie, partagé)
FOLLOWS_LOCK = threading.Lock()


def follow_id(path):
    seg = follow_segments(path)
    base = seg[0] if seg else path
    return hashlib.md5(os.path.abspath(base).encode("utf-8")).hexdigest()[:10]


# ── Clips : extraits MPEG-TS d'une mission, découpés dans le pcap maître (sans FFmpeg) ─────────────
CLIP_MAX_S = float(os.getenv("CLIP_MAX_S", "3600"))
CLIP_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


def clips_dir(mission):
    if not mission or "/" in mission or "\\" in mission or ".." in mission:
        raise ValueError("nom de mission invalide")
    if not CAPTURES_DIR or not os.path.isdir(os.path.join(CAPTURES_DIR, mission)):
        raise FileNotFoundError("mission introuvable : %s" % mission)
    return os.path.join(CAPTURES_DIR, mission, "clips")


def clips_list(mission):
    """Clips extraits d'une mission (sidecars {name}.json de {mission}/clips/), triés par début."""
    try:
        d = clips_dir(mission)
    except (ValueError, FileNotFoundError):
        return []
    out = []
    if os.path.isdir(d):
        for f in os.listdir(d):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(d, f), encoding="utf-8") as fh:
                        c = json.load(fh)
                    ts = os.path.join(d, c.get("file") or (c["name"] + ".ts"))
                    c["bytes"] = os.path.getsize(ts) if os.path.isfile(ts) else c.get("bytes")
                    c["csv"] = os.path.isfile(os.path.join(d, c["name"] + "_klv.csv"))
                    out.append(c)
                except Exception:
                    continue
    out.sort(key=lambda c: c.get("start_utc") or 0)
    return out


_CRC32_MPEG = None


def _crc32_mpeg(data):
    """CRC-32/MPEG-2 (polynôme 0x04C11DB7, init 0xFFFFFFFF, sans réflexion) des sections PSI."""
    global _CRC32_MPEG
    if _CRC32_MPEG is None:
        tbl = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                c = ((c << 1) ^ 0x04C11DB7) if (c & 0x80000000) else (c << 1)
            tbl.append(c & 0xFFFFFFFF)
        _CRC32_MPEG = tbl
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC32_MPEG[((crc >> 24) ^ b) & 0xFF]
    return crc


def _pmt_without_pid(pkt, drop_pid):
    """Paquet PMT (section unique) réécrit sans l'entrée d'élément `drop_pid` ; None si non modifiable."""
    if not (pkt[1] & 0x40) or not (pkt[3] & 0x10):            # payload_unit_start requis, payload présent
        return None
    off = 4
    if pkt[3] & 0x20:
        off += 1 + pkt[4]
    ptr = pkt[off]; sec = off + 1 + ptr
    if sec + 12 > 188 or pkt[sec] != 0x02:
        return None
    slen = ((pkt[sec + 1] & 0x0F) << 8) | pkt[sec + 2]
    end = sec + 3 + slen
    if end > 188:
        return None                                            # section sur plusieurs paquets : non gérée
    hdr = bytearray(pkt[sec:sec + 12])
    pil = ((pkt[sec + 10] & 0x0F) << 8) | pkt[sec + 11]
    body = bytearray(pkt[sec + 12:sec + 12 + pil])             # descripteurs programme
    i = sec + 12 + pil; changed = False; loop = bytearray()
    while i + 5 <= end - 4:
        st, epid = pkt[i], ((pkt[i + 1] & 0x1F) << 8) | pkt[i + 2]
        el = ((pkt[i + 3] & 0x0F) << 8) | pkt[i + 4]
        n = 5 + el
        if epid == drop_pid:
            changed = True
        else:
            loop += pkt[i:i + n]
        i += n
    if not changed:
        return None
    new_len = 9 + len(body) + len(loop) + 4                    # après section_length : 9 octets fixes … + CRC
    hdr[1] = (hdr[1] & 0xF0) | ((new_len >> 8) & 0x0F); hdr[2] = new_len & 0xFF
    section = bytes(hdr) + bytes(body) + bytes(loop)
    section += struct.pack(">I", _crc32_mpeg(section))
    out = bytearray(pkt[:sec]) + section
    if len(out) > 188:
        return None
    return bytes(out + b"\xff" * (188 - len(out)))


def _strip_pid(chunk, pid, pmt_pids=()):
    """Retire d'un bloc TS (paquets de 188 octets alignés) les paquets du PID donné et son entrée dans la PMT."""
    keep = []
    for i in range(0, len(chunk) - 187, 188):
        pkt = chunk[i:i + 188]
        if pkt[0] != 0x47:
            keep.append(pkt); continue
        p = ((pkt[1] & 0x1F) << 8) | pkt[2]
        if p == pid:
            continue
        if p in pmt_pids:
            pkt = _pmt_without_pid(pkt, pid) or pkt
        keep.append(pkt)
    return b"".join(keep)


def clip_extract(mission, start_utc, end_utc, name=None, include_metadata=True, dport=None):
    """Extrait [start_utc, end_utc] du flux vidéo de la mission dans {mission}/clips/{name}.ts — copie
    octet à octet du TS capturé (aucun ré-encodage) ; sans métadonnées, les paquets du PID KLV sont
    retirés. Avec métadonnées : {name}_klv.csv (positions KLV, 1 pt / 0,5 s) en plus. Sidecar {name}.json."""
    start_utc, end_utc = float(start_utc), float(end_utc)
    if not (end_utc > start_utc):
        raise ValueError("la fin doit être postérieure au début")
    if end_utc - start_utc > CLIP_MAX_S:
        raise ValueError("durée maximale d'un clip : %d s" % CLIP_MAX_S)
    d = clips_dir(mission)
    pcap0 = mission_resolve(mission)["pcap"]
    eng = FOLLOWS.get(follow_id(pcap0))
    if eng is None or not eng.state.get("running"):
        follow_start(pcap0, None, None, [])                    # ouvre le suivi (index) le temps de l'extraction
        eng = follow_get(follow_id(pcap0))
        for _ in range(600):                                   # rattrapage de l'index (≤ 60 s)
            if not eng.catching_up:
                break
            time.sleep(0.1)
    st = eng.stream(dport)
    if not name:
        name = "clip_%s-%s" % (time.strftime("%H%M%SZ", time.gmtime(start_utc)), time.strftime("%H%M%SZ", time.gmtime(end_utc)))
    if not CLIP_NAME_RE.match(name):
        raise ValueError("nom de clip invalide (lettres, chiffres, _ et - ; 100 caractères max)")
    os.makedirs(d, exist_ok=True)
    out = os.path.join(d, name + ".ts")
    if os.path.exists(out):
        raise ValueError("un clip nommé %s existe déjà" % name)
    seg_no, off, _cum = st.locate_time(start_utc)
    klv_pid = None; pmt_pids = (); probe = bytearray(); n = 0
    tmp = out + ".part"
    try:
        with open(tmp, "wb") as fh:
            for chunk in eng.iter_ts(st, seg_no, off, 0, t_min=start_utc, t_max=end_utc):
                if not include_metadata:
                    if klv_pid is None:                        # PID KLV déterminé sur les premiers Mo (PMT)
                        probe += chunk
                        if len(probe) >= 2 << 20:
                            info = v9.analyze_stream(bytes(probe)); klv_pid = info.get("klv_pid") or -1; pmt_pids = tuple(info.get("pmt_pids") or ())
                            data = _strip_pid(bytes(probe), klv_pid, pmt_pids); probe = bytearray()
                            fh.write(data); n += len(data)
                        continue
                    chunk = _strip_pid(chunk, klv_pid, pmt_pids)
                fh.write(chunk); n += len(chunk)
            if probe:
                info = v9.analyze_stream(bytes(probe)); klv_pid = info.get("klv_pid") or -1; pmt_pids = tuple(info.get("pmt_pids") or ())
                data = _strip_pid(bytes(probe), klv_pid, pmt_pids); fh.write(data); n += len(data)
        if n == 0:
            raise ValueError("aucune donnée vidéo dans ce créneau")
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    meta = {"name": name, "file": name + ".ts", "mission": mission, "dport": st.dport, "start_utc": start_utc, "end_utc": end_utc,
            "duration": round(end_utc - start_utc, 3), "bytes": n, "metadata": bool(include_metadata), "created_at": time.time(),
            "klv_pid": klv_pid if klv_pid not in (None, -1) else None}
    if include_metadata:
        t0 = eng.t0 or 0
        rows = [k for k in eng.klv if start_utc <= t0 + k[0] <= end_utc and (dport is None or (len(k) > 7 and k[7] == st.dport))]
        if rows:
            with open(os.path.join(d, name + "_klv.csv"), "w", encoding="utf-8", newline="") as fh:
                fh.write("utc,timestamp,lat,lon,alt_m,heading,frame_center_lat,frame_center_lon\n")
                for k in rows:
                    t = t0 + k[0]
                    utc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % (int(round((t % 1) * 1000)) % 1000)
                    fh.write("%s,%.3f,%s\n" % (utc, t, ",".join("" if v is None else str(v) for v in k[1:7])))
            meta["csv"] = True
    with open(os.path.join(d, name + ".json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)
    print("[clips] %s : %s  %.1f s  %.1f Mo  métadonnées=%s" % (mission, name, meta["duration"], n / 1e6, include_metadata))
    return meta


def clip_delete(mission, name):
    if not CLIP_NAME_RE.match(name or ""):
        raise ValueError("nom de clip invalide")
    d = clips_dir(mission); gone = 0
    for suf in (".ts", ".json", "_klv.csv"):
        f = os.path.join(d, name + suf)
        if os.path.isfile(f):
            os.remove(f); gone += 1
    if not gone:
        raise FileNotFoundError("clip introuvable : %s" % name)
    return {"ok": True, "deleted": name}


# ── Vignettes : sprites JPEG générés depuis le pcap maître par ffmpeg (prévisualisation au survol de la barre) ──
def _find_ffmpeg():
    p = os.getenv("FFMPEG") or shutil.which("ffmpeg")
    if not p:
        try:
            import imageio_ffmpeg                        # poste Windows (banc) : binaire embarqué
            p = imageio_ffmpeg.get_ffmpeg_exe()
        except Exception:
            p = None
    return p


FFMPEG = _find_ffmpeg()
THUMBS_ON = os.getenv("THUMBS", "1") not in ("0", "false", "no") and bool(FFMPEG)
THUMB_INTERVAL_S = float(os.getenv("THUMB_INTERVAL_S", "10"))
THUMB_W, THUMB_H = int(os.getenv("THUMB_W", "160")), int(os.getenv("THUMB_H", "90"))
THUMB_COLS, THUMB_ROWS = 10, 10
THUMB_WINDOW_S = THUMB_INTERVAL_S * THUMB_COLS * THUMB_ROWS        # 1000 s par sprite


def thumbs_dir(mission):
    if not mission or "/" in mission or "\\" in mission or ".." in mission:
        raise ValueError("nom de mission invalide")
    if not CAPTURES_DIR or not os.path.isdir(os.path.join(CAPTURES_DIR, mission)):
        raise FileNotFoundError("mission introuvable : %s" % mission)
    return os.path.join(CAPTURES_DIR, mission, "thumbnails")


def thumbs_index(mission):
    """Index des sprites d'une mission : {available, interval, w, h, cols, rows, window_s, t0, sprites:{k:{file, n, partial, ver}}}."""
    base = {"available": False, "enabled": THUMBS_ON, "interval": THUMB_INTERVAL_S, "w": THUMB_W, "h": THUMB_H, "cols": THUMB_COLS, "rows": THUMB_ROWS,
            "window_s": THUMB_WINDOW_S, "t0": None, "sprites": {}}
    try:
        p = os.path.join(thumbs_dir(mission), "index.json")
    except (ValueError, FileNotFoundError):
        return base
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as fh:
                idx = json.load(fh)
            base.update(idx); base["available"] = bool(idx.get("sprites"))
        except Exception:
            pass
    return base


class ThumbWorker:
    """Sprites d'un suivi : fenêtre k = [k·1000 s, (k+1)·1000 s[ du flux vidéo principal → sprite_{k:03d}.jpg (10×10 vignettes
    de 160×90, une toutes les 10 s, images clés seulement). Fenêtres révolues générées une fois ; fenêtre courante (direct)
    régénérée toutes les 60 s de données nouvelles. Décodage H.264 par ffmpeg (TS relu depuis le pcap, aucune écriture
    intermédiaire) ; index.json réécrit après chaque sprite."""
    def __init__(self, eng):
        self.eng = eng; self.mission = eng.mission_name(); self.dir = os.path.join(CAPTURES_DIR, self.mission, "thumbnails")
        self.index = {"interval": THUMB_INTERVAL_S, "w": THUMB_W, "h": THUMB_H, "cols": THUMB_COLS, "rows": THUMB_ROWS, "window_s": THUMB_WINDOW_S, "t0": None, "sprites": {}}
        self.partial_edge = -1e9; self.partial_k = None; self.thread = None; self.busy = False; self.error = None

    def start(self):
        p = os.path.join(self.dir, "index.json")
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as fh:
                    self.index = json.load(fh)
            except Exception:
                pass
        self.thread = threading.Thread(target=self._run, daemon=True, name="thumbs-" + self.mission); self.thread.start()

    def _save(self):
        os.makedirs(self.dir, exist_ok=True)
        tmp = os.path.join(self.dir, "index.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.index, fh)
        os.replace(tmp, os.path.join(self.dir, "index.json"))

    def _run(self):
        eng = self.eng
        while not eng.stop_event.is_set():
            try:
                if not eng.catching_up and eng.streams:
                    self._step()
            except Exception as e:
                self.error = str(e); print("[thumbs] %s : %s" % (self.mission, e))
            eng.stop_event.wait(5.0)

    def _step(self):
        eng = self.eng
        st = max(eng.streams.values(), key=lambda s: s.nbytes)
        if st.t0 is None or st.t1 is None or eng.t0 is None:
            return
        t0 = eng.t0; edge = st.t1 - t0
        if self.index.get("t0") is None:
            self.index["t0"] = t0
        sprites = self.index["sprites"]
        n_full = int(edge // THUMB_WINDOW_S)
        for k in range(n_full):                                           # fenêtres révolues manquantes
            if str(k) not in sprites or sprites[str(k)].get("partial"):
                self._gen(st, k, t0, (k + 1) * THUMB_WINDOW_S)
                if eng.stop_event.is_set():
                    return
        k = n_full                                                        # fenêtre courante (partielle)
        if edge - k * THUMB_WINDOW_S >= THUMB_INTERVAL_S:
            fresh = edge - self.partial_edge
            if self.partial_k != k or fresh >= 60 or (fresh >= THUMB_INTERVAL_S and eng.edge_wall and time.time() - eng.edge_wall > 20):
                self._gen(st, k, t0, edge); self.partial_edge = edge; self.partial_k = k

    def _gen(self, st, k, t0, t_end_rel):
        eng = self.eng
        t_a = t0 + k * THUMB_WINDOW_S; t_b = min(t0 + t_end_rel, t_a + THUMB_WINDOW_S)
        n = max(1, int(math.ceil((t_b - t_a) / THUMB_INTERVAL_S)))
        partial = (t_b - t_a) < THUMB_WINDOW_S - 1e-6
        os.makedirs(self.dir, exist_ok=True)
        fname = "sprite_%03d.jpg" % k; out = os.path.join(self.dir, fname); tmp = out + ".part.jpg"
        vf = "fps=1/%g,scale=%d:%d,tile=%dx%d" % (THUMB_INTERVAL_S, THUMB_W, THUMB_H, THUMB_COLS, THUMB_ROWS)
        cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-skip_frame", "nokey", "-fflags", "+genpts+discardcorrupt",
               "-f", "mpegts", "-i", "pipe:0", "-an", "-sn", "-dn", "-map", "0:v:0", "-vf", vf, "-frames:v", "1", "-q:v", "4", "-y", tmp]
        t_start = time.time()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.busy = True
        try:
            seg_no, off, _cum = st.locate_time(t_a)
            fed = 0; feed_err = None
            try:
                for chunk in eng.iter_ts(st, seg_no, off, 0, t_min=t_a, t_max=t_b):
                    proc.stdin.write(chunk); fed += len(chunk)
                    if eng.stop_event.is_set():
                        break
            except (OSError, ValueError) as e:                 # ffmpeg terminé avant la fin du flux (erreur) : on lit sa sortie
                feed_err = e
            try:                                               # communicate() vide et ferme stdin lui-même (ne pas le fermer avant :
                _o, err = proc.communicate(timeout=300)        # sous Linux il fait stdin.flush() → ValueError « flush of closed file »)
            except subprocess.TimeoutExpired:
                proc.kill(); err = b"timeout"
            if feed_err is not None and proc.returncode == 0 and not os.path.isfile(tmp):
                err = (err or b"") + (" | écriture : %s (%d octets envoyés)" % (feed_err, fed)).encode()
            if proc.returncode != 0 or not os.path.isfile(tmp) or os.path.getsize(tmp) < 1000:
                self.error = "ffmpeg (code %s, %d octets envoyés) : %s" % (proc.returncode, fed, (err or b"").decode("utf-8", "replace").strip()[-400:] or "(aucun message)")
                print("[thumbs] %s sprite %d : %s" % (self.mission, k, self.error))
                if os.path.isfile(tmp):
                    os.remove(tmp)
                return
            os.replace(tmp, out)
            self.index["sprites"][str(k)] = {"file": fname, "n": n, "partial": partial, "t_start": k * THUMB_WINDOW_S, "ver": int(time.time())}
            self._save()
            print("[thumbs] %s : %s (%d vignettes%s) en %.1fs" % (self.mission, fname, n, ", partiel" if partial else "", time.time() - t_start))
        finally:
            self.busy = False


# ── Captures SNAP : image de la vidéo à l'instant t + métadonnées KLV → PNG/JSON + slide PowerPoint (template) ──
SNAP_TEMPLATE = os.getenv("SNAP_TEMPLATE", "/data/templates/Template.pptx")
SNAPS_EXPORT = os.getenv("SNAPS_EXPORT", "1") not in ("0", "false", "no")     # copie du PNG dans le partage MASTER MISSION
CAPTURES_LOCK = threading.Lock()
FT_PER_M = 3.280839895


def captures_dir(mission):
    if not mission or "/" in mission or "\\" in mission or ".." in mission:
        raise ValueError("nom de mission invalide")
    if not CAPTURES_DIR or not os.path.isdir(os.path.join(CAPTURES_DIR, mission)):
        raise FileNotFoundError("mission introuvable : %s" % mission)
    return os.path.join(CAPTURES_DIR, mission, "captures")


def captures_list(mission):
    try:
        d = captures_dir(mission)
    except (ValueError, FileNotFoundError):
        return []
    out = []
    if os.path.isdir(d):
        for f in os.listdir(d):
            if f.endswith(".json") and f != "deck.json":
                try:
                    with open(os.path.join(d, f), encoding="utf-8") as fh:
                        out.append(json.load(fh))
                except Exception:
                    continue
    out.sort(key=lambda c: c.get("t_utc") or 0)
    return out


def _klv_strings(d):
    """Chaînes utiles d'un LS 0601 {tag: bytes} : indicatif (10), capteur (11), Mission ID (3), tail (4), plateforme (59)."""
    def txt(t):
        b = d.get(t)
        return b.decode("utf-8", "replace").strip("\x00 ") if b else None
    return {"callsign": txt(10), "sensor": txt(11), "mission_id": txt(3), "tail": txt(4), "platform": txt(59)}


def _snap_frame_and_klv(eng, st, t_utc, png_path):
    """Frame décodée la plus proche de t_utc (≤ t_utc) écrite en PNG (résolution native) + dernier LS KLV avant t_utc.
    Le TS de [t_utc − 4 s, t_utc + 0,15 s] est envoyé à ffmpeg (-update 1 : la dernière image écrite reste)."""
    if not FFMPEG:
        raise RuntimeError("ffmpeg indisponible : capture d'image impossible")
    t_a = max((st.t0 or t_utc) - 0.001, t_utc - 3.0); t_b = t_utc + 0.15
    seg_no, off, _cum = st.locate_time(t_a)
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-fflags", "+genpts+discardcorrupt", "-f", "mpegts", "-i", "pipe:0",
           "-an", "-sn", "-dn", "-map", "0:v:0", "-vsync", "0", "-update", "1", "-frames:v", "100000", "-y", png_path]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    merged = {}; last_ts = None; fed = 0
    try:
        for chunk in eng.iter_ts(st, seg_no, off, 0, t_min=t_a, t_max=t_b):
            try:
                proc.stdin.write(chunk); fed += len(chunk)
            except (OSError, ValueError):
                pass
            d = klv_from_ts(chunk)
            if d:
                merged.update(d)                                   # LS partiels : les derniers tags vus l'emportent
                if 2 in d:
                    last_ts = d
    finally:
        try:
            _o, err = proc.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill(); err = b"timeout"
    if not os.path.isfile(png_path) or os.path.getsize(png_path) < 1000:
        raise RuntimeError("aucune image décodée à cet instant (ffmpeg %s : %s ; %d octets)" % (proc.returncode, (err or b"").decode("utf-8", "replace").strip()[-300:], fed))
    return merged


def snap_capture(mission, t_utc, description=None, dport=None, snaps_label=None):
    """Capture SNAP à t_utc : PNG + JSON dans {mission}/captures/, slide ajoutée au deck {mission}/captures/{mission}_SNAPS.pptx
    (template SNAP_TEMPLATE), copie du PNG nommé selon la convention dans le partage MASTER MISSION si `snaps_label` résolu."""
    t_utc = float(t_utc)
    d = captures_dir(mission)
    pcap0 = mission_resolve(mission)["pcap"]
    eng = FOLLOWS.get(follow_id(pcap0))
    if eng is None or not eng.state.get("running"):
        follow_start(pcap0, None, None, [])
        eng = follow_get(follow_id(pcap0))
        for _ in range(600):
            if not eng.catching_up:
                break
            time.sleep(0.1)
    st = eng.stream(dport)
    if st.t0 is None or t_utc < st.t0 - 1 or (st.t1 is not None and t_utc > st.t1 + 1):
        raise ValueError("instant hors du flux vidéo")
    os.makedirs(d, exist_ok=True)
    description = re.sub(r"[\r\n\t]+", " ", (description or "")).strip()[:120]
    with CAPTURES_LOCK:
        base = time.strftime("%y%m%d_%H%M%S", time.gmtime(t_utc)); cid = base; k = 1
        while os.path.exists(os.path.join(d, cid + ".json")):
            k += 1; cid = "%s_%d" % (base, k)
        png = os.path.join(d, cid + ".png")
        ls = _snap_frame_and_klv(eng, st, t_utc, png)
        n = klv_numeric(ls) if ls else {}
        strs = _klv_strings(ls) if ls else {}
        fc_lat, fc_lon = n.get("fc_lat"), n.get("fc_lon")
        if fc_lat is None and n.get("lat") is not None:
            fc_lat, fc_lon = n["lat"], n["lon"]                 # sans centre image : position capteur
        mgrs = None
        if fc_lat is not None:
            try:
                import mgrs_lite
                mgrs = mgrs_lite.latlon_to_mgrs(fc_lat, fc_lon, 5)
            except Exception:
                mgrs = None
        ts_klv = (n.get("ts_us") / 1e6) if n.get("ts_us") else None
        meta = {"id": cid, "mission": mission, "t_utc": t_utc, "t_klv": ts_klv, "png": cid + ".png", "description": description, "dport": st.dport,
                "lat": n.get("lat"), "lon": n.get("lon"), "alt_m": n.get("alt"), "alt_ft": (n["alt"] * FT_PER_M) if n.get("alt") is not None else None,
                "hdg": n.get("hdg"), "fc_lat": fc_lat, "fc_lon": fc_lon, "fc_elev_m": n.get("fc_alt"),
                "fc_elev_ft": (n["fc_alt"] * FT_PER_M) if n.get("fc_alt") is not None else None,
                "hfov": n.get("hfov"), "vfov": n.get("vfov"), "slant_m": n.get("slant"), "mgrs": mgrs, "mgrs_fmt": None,
                "callsign": strs.get("callsign"), "sensor": strs.get("sensor"), "mission_id": strs.get("mission_id"), "platform": strs.get("platform"),
                "created_at": time.time(), "deck": None, "slide": None, "share_png": None}
        try:
            import snap_pptx
            meta["mgrs_fmt"] = snap_pptx.fmt_mgrs(mgrs)
        except Exception:
            pass
        meta["deck"] = "%s_SNAPS.pptx" % mission; meta["pending"] = True
        with open(os.path.join(d, cid + ".json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=1)
    print("[captures] %s : %s  %s  MGRS %s" % (mission, cid, time.strftime("%H:%M:%SZ", time.gmtime(t_utc)), mgrs))
    # Deck PowerPoint serveur et copie dans le partage : en arrière-plan (la réponse — et l'agent poste — n'attendent
    # que le PNG et la fiche) ; la fiche est réécrite à la fin (slide, share_png, erreurs éventuelles).
    threading.Thread(target=_snap_finish, args=(d, cid, dict(meta), png, ts_klv or t_utc, snaps_label), daemon=True, name="snap-" + cid).start()
    return meta


def _snap_finish(d, cid, meta, png, ts, snaps_label):
    mission, mgrs, description, t_utc = meta["mission"], meta.get("mgrs"), meta.get("description") or "", meta["t_utc"]
    try:
        import snap_pptx
        deck = os.path.join(d, "%s_SNAPS.pptx" % mission)
        meta["slide"] = snap_pptx.append_capture(deck, SNAP_TEMPLATE, png, dict(meta, ts=ts))
    except Exception as e:
        meta["deck_error"] = str(e); print("[captures] %s : deck PPTX : %s" % (mission, e))
    if SNAPS_EXPORT and snaps_label:
        try:
            sd = os.path.join(snaps_mission_dir(snaps_label), SNAPS_SUBDIR)
            os.makedirs(sd, exist_ok=True)
            name = "%s_DR_%sZ_SNAP_%s%s.png" % (time.strftime("%y%m%d", time.gmtime(t_utc)), time.strftime("%H%M", time.gmtime(t_utc)), mgrs or "NOFIX",
                                                ("_" + re.sub(r"[^\w\-]+", "_", description).strip("_")) if description else "")
            shutil.copyfile(png, os.path.join(sd, name)); meta["share_png"] = name
        except Exception as e:
            meta["share_error"] = str(e); print("[captures] %s : partage snaps : %s" % (mission, e))
    meta["pending"] = False
    try:
        with CAPTURES_LOCK:
            with open(os.path.join(d, cid + ".json"), "w", encoding="utf-8") as fh:
                json.dump(meta, fh, ensure_ascii=False, indent=1)
    except Exception as e:
        print("[captures] %s : fiche %s : %s" % (mission, cid, e))
    print("[captures] %s : %s  slide %s%s" % (mission, cid, meta.get("slide"), (" · partage " + meta["share_png"]) if meta.get("share_png") else ""))


def mission_delete(name):
    """Supprime le dossier d'une mission (pcap maître, index, journal, clips, captures, vignettes). Refusé si la mission
    est en cours (démon de capture) ; les suivis de relecture ouverts dessus sont arrêtés d'abord."""
    if not name or "/" in name or "\\" in name or ".." in name:
        raise ValueError("nom de mission invalide")
    d = os.path.join(CAPTURES_DIR or "", name)
    if not CAPTURES_DIR or not os.path.isdir(d) or os.path.realpath(os.path.dirname(d)) != os.path.realpath(CAPTURES_DIR):
        raise FileNotFoundError("mission introuvable : %s" % name)
    try:
        with urllib.request.urlopen(CAPTURE_STATUS_URL + "/api/capture/status", timeout=3) as r:
            st = json.load(r)
        for cr, s_ in (st.get("sets") or {}).items():
            if s_.get("mission") == name:
                raise ValueError("mission en cours d'enregistrement sur %s : arrêter la capture d'abord" % cr)
    except (urllib.error.URLError, OSError, ValueError) as e:
        if isinstance(e, ValueError) and "en cours" in str(e):
            raise
    with FOLLOWS_LOCK:
        engs = [e for e in FOLLOWS.values() if e.state.get("running") and e.mission_name() == name]
    for e in engs:
        if e.system:
            raise ValueError("mission suivie en direct (suivi système) : impossible de la supprimer")
        e.stop()
    time.sleep(0.3)
    shutil.rmtree(d)
    print("[missions] supprimée : %s" % name)
    return {"ok": True, "deleted": name}


def capture_delete(mission, cid):
    if not re.match(r"^\d{6}_\d{6}(_\d+)?$", cid or ""):
        raise ValueError("identifiant invalide")
    d = captures_dir(mission); gone = 0
    for suf in (".png", ".json"):
        f = os.path.join(d, cid + suf)
        if os.path.isfile(f):
            os.remove(f); gone += 1
    if not gone:
        raise FileNotFoundError("capture introuvable : %s" % cid)
    return {"ok": True, "deleted": cid}                    # la slide déjà ajoutée au deck est conservée


def follow_get(fid):
    with FOLLOWS_LOCK:
        eng = FOLLOWS.get(fid or "")
        if eng is None and fid in ("1", "", None) and len(FOLLOWS) == 1:   # compatibilité : un seul suivi → implicite
            eng = next(iter(FOLLOWS.values()))
    if eng is None:
        raise ValueError("suivi inconnu (id %s)" % fid)
    eng.touch()
    return eng


def follow_start(path, watch=None, track=None, taps=()):
    """Démarre — ou REJOINT — le suivi de cette mission : un moteur par mission, partagé par tous les
    visionneurs (taps cumulés) ; la configuration (flux suivis, profil) est celle du premier arrivé."""
    fid = follow_id(path)
    with FOLLOWS_LOCK:
        eng = FOLLOWS.get(fid)
        if eng is not None and eng.state.get("running"):
            eng.touch()
            if taps:
                eng.follow(taps=set(eng.taps) | set(int(t) for t in taps))
            st = eng.status(); st["joined"] = True
            return st
        eng = FOLLOWS[fid] = FollowEngine(fid)
    try:
        eng.start(path, watch, track, taps)
    except Exception as e:
        import traceback
        print("[follow] démarrage impossible (%s) : %s" % (os.path.basename(path), e), flush=True); traceback.print_exc()
        with FOLLOWS_LOCK:
            FOLLOWS.pop(fid, None)
        raise
    return eng.status()


CR_FOLLOW = {}                                        # CR → id du suivi « système » de sa mission en cours
CAPTURE_STATUS_URL = os.getenv("CAPTURE_STATUS_URL", "http://127.0.0.1:8768").strip().rstrip("/")


def _capture_sets_by_cr():
    out = {}
    for item in (os.getenv("CAPTURE_SETS", "") or "").split(","):
        name, _, ports = item.strip().partition(":")
        if name:
            out[name.strip().upper()] = [int(p) for p in ports.replace("+", " ").split() if p.isdigit()]
    return out


def health_status():
    """État des services v2 pour la page Health : démon de capture, suivis, MediaMTX, disque, télémétrie."""
    out = {"ts": time.time(), "capture": {"ok": False}, "replay": {"ok": True}, "mediamtx": {"ok": False}, "disk": None, "klv": {}}
    try:
        with urllib.request.urlopen(CAPTURE_STATUS_URL + "/api/capture/status", timeout=3) as r:
            st = json.load(r)
        out["capture"] = {"ok": True, **st}
        for cr in (st.get("sets") or {}):
            try:
                with urllib.request.urlopen("%s/api/streams/%s/klv" % (CAPTURE_STATUS_URL, cr), timeout=2) as r:
                    k = json.load(r); out["klv"][cr] = {"age_s": k.get("age_s"), "callsign": k.get("PlatformCallSign"), "fl": k.get("FlightLevel")}
            except Exception:
                pass
    except Exception as e:
        out["capture"] = {"ok": False, "error": str(e)}
    try:
        out["replay"] = {"ok": True, "missions": len(missions_list()),
                         "follows": [{"id": e.fid, "mission": os.path.basename(e._seg_base or e.state.get("pcap", "")), "cr": e.cr, "duration": e.duration(),
                                      "n_packets": e.n_packets, "tracks": len(e.tracks), "gmti_subscribers": len(e.gmti_bus.subs), "system": e.system,
                                      "catching_up": e.catching_up} for e in list(FOLLOWS.values()) if e.state.get("running")]}
    except Exception as e:
        out["replay"] = {"ok": False, "error": str(e)}
    try:
        with urllib.request.urlopen(os.getenv("MEDIAMTX_API_URL", "http://127.0.0.1:9998") + "/v3/paths/list", timeout=2) as r:
            pl = json.load(r)
        items = pl.get("items") or []
        out["mediamtx"] = {"ok": True, "paths": len(items), "ready": sum(1 for p in items if p.get("ready")), "items": [{"name": p.get("name"), "ready": p.get("ready"), "readers": len(p.get("readers") or [])} for p in items]}
    except Exception as e:
        out["mediamtx"] = {"ok": False, "error": str(e)}
    out["thumbnails"] = {"enabled": THUMBS_ON, "ffmpeg": FFMPEG}
    out["captures"] = {"template": os.path.isfile(SNAP_TEMPLATE), "template_path": SNAP_TEMPLATE, "snaps_export": SNAPS_EXPORT}
    try:
        if CAPTURES_DIR:
            du = shutil.disk_usage(CAPTURES_DIR); out["disk"] = {"path": CAPTURES_DIR, "total": du.total, "used": du.used, "free": du.free}
    except Exception:
        pass
    return out


def gmti_status_idle(cr):
    """Statut GMTI d'un CR sans mission en cours (mêmes clés que FollowEngine.gmti_status)."""
    ports = _capture_sets_by_cr().get((cr or "").upper(), [])
    return {"port": (cr or "").upper(), "udp_port": (ports[1] if len(ports) > 1 else None),
            "profile": os.getenv("GMTI_PROFILE_%s" % (cr or "").upper()) or os.getenv("GMTI_PROFILE") or "defaut", "overrides": {},
            "receiving": False, "last_rx_age_s": None, "totals": {"gmti_plots": 0, "gmti_pkts": 0, "gmti_dwells": 0},
            "n_dwells": 0, "n_ghosts": 0, "n_clustered": 0, "n_absorbed": 0, "n_resets": 0, "tracks_alive": 0,
            "subscribers": 0, "recording": None, "errors": 0, "mission_name": None, "catching_up": False}


def cr_engine(cr):
    fid = CR_FOLLOW.get((cr or "").upper())
    return FOLLOWS.get(fid) if fid else None


def auto_follow_loop():
    """Suit automatiquement (suivi « système », jamais détaché) la mission EN COURS de chaque CR annoncée par
    stratus2-capture : c'est ce suivi qui porte le tracker GMTI live (/ws/gmti/{CR}), la trace KLV et le
    journal — une mission ouverte plus tard par un opérateur est immédiatement prête."""
    if not CAPTURES_DIR:
        return
    while True:
        try:
            with urllib.request.urlopen(CAPTURE_STATUS_URL + "/api/capture/status", timeout=4) as r:
                st = json.load(r)
            for cr, info in (st.get("sets") or {}).items():
                mission = info.get("mission")
                cur = cr_engine(cr)
                if mission:
                    d = os.path.join(CAPTURES_DIR, mission)
                    pcaps = _mission_pcaps(d) if os.path.isdir(d) else []
                    if not pcaps:
                        continue
                    if cur is None or cur.state.get("pcap") != pcaps[0] or not cur.state.get("running"):
                        if cur is not None:
                            cur.system = False
                        prof = os.getenv("GMTI_PROFILE_%s" % cr.upper()) or os.getenv("GMTI_PROFILE") or "defaut"
                        stt = follow_start(pcaps[0], None, {"profile": prof, "overrides": {}}, [])
                        eng = FOLLOWS.get(stt["id"])
                        if eng is not None:
                            eng.cr = cr.upper(); eng.system = True; eng.gmti_profile = prof
                            CR_FOLLOW[cr.upper()] = stt["id"]
                            EVENTS.publish({"type": "log", "msg": "suivi système %s : %s" % (cr, mission)})
                elif cur is not None and cur.system:
                    cur.system = False                        # mission close : le reaper l'arrêtera sans client
                    EVENTS.publish({"type": "log", "msg": "suivi système %s : mission terminée" % cr})
        except Exception as e:
            import traceback
            print("[follow] suivi automatique : %s" % e, flush=True); traceback.print_exc()
        time.sleep(5.0)


def gmti_ticker():
    """Batches GMTI (~4 Hz) + status (1 Hz) vers les abonnés /ws/gmti de chaque suivi."""
    n = 0
    while True:
        time.sleep(0.25); n += 1
        for eng in list(FOLLOWS.values()):
            if not eng.state.get("running"):
                continue
            try:
                eng.gmti_flush()
                if n % 4 == 0 and eng.gmti_bus.subs:
                    eng.gmti_bus.publish({"type": "status", **eng.gmti_status()})
            except Exception:
                pass


threading.Thread(target=gmti_ticker, name="gmti_ticker", daemon=True).start()


def follow_reaper():
    """Arrête les suivis sans client depuis IDLE_STOP_S (les visionneurs signalent leur présence à chaque delta)."""
    while True:
        time.sleep(15.0)
        now = time.time()
        with FOLLOWS_LOCK:
            for e in FOLLOWS.values():
                if e.system:
                    e.last_touch = now                        # suivi système : jamais arrêté tant que la mission est en cours
            idle = [f for f, e in FOLLOWS.items() if e.state.get("running") and now - e.last_touch > FollowEngine.IDLE_STOP_S]
            dead = [f for f, e in FOLLOWS.items() if not e.state.get("running") and now - e.last_touch > 600]
            for f in dead:
                FOLLOWS.pop(f, None)
        for f in idle:
            try:
                eng = FOLLOWS.get(f)
                if eng is not None:
                    eng.stop(); EVENTS.publish({"type": "log", "msg": "suivi %s arrêté (plus de visionneur)" % f})
            except Exception:
                pass


threading.Thread(target=follow_reaper, name="follow_reaper", daemon=True).start()


def flows_summary(path, limit=0):
    """Flux applicatifs (pcap_analyze.scan) → lignes pour le routage."""
    if is_csv_source(path):
        src = csv_source(path)
        return {"npkt": len(src["dwells"]), "duration_s": round((src["t1"] or 0) - (src["t0"] or 0), 3), "truncated": False,
                "flows": [{"proto": "UDP", "dport": 4607, "dominant": "GMTI/4607 (CSV)", "pkts": len(src["dwells"]),
                           "bytes": os.path.getsize(path), "dsts": []}], "source": "csv"}
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
        self._json({"error": msg, "detail": msg}, code)

    def _cors_if_direct(self):
        """
        En-têtes CORS pour les réponses binaires, **uniquement en accès direct**
        (:8767 sans reverse proxy).

        Derrière nginx, c'est lui l'autorité : il pose déjà
        `Access-Control-Allow-Origin: $http_origin` (`add_header … always`). Un
        second en-tête fait **rejeter la réponse par le navigateur**
        (« Failed to fetch »), alors que curl, qui ignore CORS, la reçoit sans
        problème — d'où un symptôme déroutant. On détecte le passage par le
        proxy aux en-têtes `X-Forwarded-*` qu'il ajoute.
        """
        if self.headers.get("X-Forwarded-For") or self.headers.get("X-Forwarded-Proto"):
            return
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Expose-Headers", "*")

    def _pcap(self, q):
        p = q.get("pcap", [self.default_pcap or ""])[0]
        if not p or not os.path.isfile(p):
            raise FileNotFoundError("pcap introuvable : %r" % p)
        return p

    def _stream(self, q):
        if q.get("follow", [""])[0]:
            return follow_get(q["follow"][0]).stream(q.get("dport", [None])[0])
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

    def handle(self):
        """Le navigateur coupe les requêtes Range vidéo à chaque seek : pas de trace pour ces resets."""
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def _strip_base(self):
        """--base-path : accepte les URL préfixées (/console/api/…) en plus des URL nues."""
        if BASE_PATH and self.path.startswith(BASE_PATH):
            rest = self.path[len(BASE_PATH):]
            if rest == "" or rest.startswith("/") or rest.startswith("?"):
                self.path = rest or "/"

    def do_GET(self):
        self._strip_base()
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                return self._static("index.html")
            if u.path in ("/replay", "/replay.html"):             # page opérateur (carte + vidéo + barre de temps)
                return self._static("replay.html")
            if u.path in ("/missions", "/missions.html"):         # pages StratusServer v2
                return self._static("missions.html")
            if u.path in ("/health", "/health.html"):
                return self._static("health.html")
            if u.path in ("/api/docs", "/docs", "/apidocs.html"):
                return self._static("apidocs.html")
            if u.path == "/api/health":
                return self._json(health_status())
            if u.path == "/api/capture/status":                   # proxy vers le démon (accès direct :8767 sans nginx)
                try:
                    with urllib.request.urlopen(CAPTURE_STATUS_URL + "/api/capture/status", timeout=3) as r:
                        return self._json(json.load(r))
                except Exception as e:
                    return self._err(502, "capture injoignable : %s" % e)
            m_ = re.match(r"^/api/snaps/([^/]+)/(list|file/([^/]+))$", u.path)
            if m_:
                label = urllib.parse.unquote(m_.group(1))
                if m_.group(2) == "list":
                    return self._json(snaps_list(label))
                p = snaps_file(label, urllib.parse.unquote(m_.group(3)))
                if not os.path.isfile(p):
                    raise FileNotFoundError("snap introuvable")
                with open(p, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png" if p.lower().endswith(".png") else "image/jpeg")
                self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-cache")
                self._cors_if_direct()
                self.end_headers(); self.wfile.write(data); return
            m_ = re.match(r"^/api/missions/([^/]+)/prepa/(list|file|shapeset)$", u.path)
            if m_:
                label = urllib.parse.unquote(m_.group(1))
                if m_.group(2) == "list":
                    return self._json(prepa_list(label))
                rel = q.get("path", [""])[0]
                if m_.group(2) == "shapeset":
                    fname, data = prepa_shapeset(label, rel)
                else:
                    fp = prepa_path(label, rel)
                    fname = os.path.basename(fp)
                    with open(fp, "rb") as f:
                        data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip" if fname.lower().endswith(".zip") else "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="%s"' % fname)
                self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-cache")
                self._cors_if_direct()
                self.end_headers(); self.wfile.write(data); return
            if u.path == "/api/missions":
                fl = lambda k: (float(q[k][0]) if q.get(k, [""])[0] else None)
                return self._json({"missions": missions_list(q.get("cr", [None])[0], q.get("callsign", [None])[0], fl("from"), fl("to"), q.get("day", [None])[0])})
            if u.path == "/api/mission/resolve":
                return self._json(mission_resolve(q.get("name", [""])[0]))
            if u.path.startswith("/static/"):
                return self._static(u.path[len("/static/"):])
            if u.path == "/api/config":
                st = settings_load()
                default = self.default_pcap or (st.get("last_pcap") if st.get("last_pcap") and os.path.isfile(st["last_pcap"]) else None)
                return self._json({"default_pcap": default, "default_limit": self.default_limit,
                                   "basemap": basemap_load(), "replay": ENGINE.status(), "live": LIVE.status(), "follows": [e.status() for e in list(FOLLOWS.values())], "settings": st})
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
            if u.path == "/api/follow/list":
                return self._json({"follows": [e.status() for e in list(FOLLOWS.values())]})
            if u.path.startswith("/ws/gmti/"):
                return self._ws_gmti(u.path[len("/ws/gmti/"):])
            m_ = re.match(r"^/api/streams/([^/]+)/track\.geojson$", u.path)
            if m_:                                                     # trackline (amorçage) du CR : contrat v1
                eng = cr_engine(m_.group(1))
                if eng is None:
                    return self._err(404, "pas de mission en cours sur %s" % m_.group(1))
                return self._json(eng.track_geojson())
            if u.path == "/api/captures/template.pptx":
                if not os.path.isfile(SNAP_TEMPLATE):
                    return self._err(404, "template introuvable : %s" % SNAP_TEMPLATE)
                data = open(SNAP_TEMPLATE, "rb").read()
                self.send_response(200); self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
                self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-cache"); self.end_headers(); self.wfile.write(data)
                return
            m_ = re.match(r"^/api/captures/([^/]+)/(list|deck\.pptx|[^/]+\.(?:png|json|pptx))$", u.path)
            if m_:
                mission = urllib.parse.unquote(m_.group(1)); what = urllib.parse.unquote(m_.group(2))
                if what == "list":
                    return self._json({"mission": mission, "template": os.path.isfile(SNAP_TEMPLATE), "captures": captures_list(mission)})
                d = captures_dir(mission)
                if what == "deck.pptx":
                    what = "%s_SNAPS.pptx" % mission
                path = os.path.realpath(os.path.join(d, what))
                if not path.startswith(os.path.realpath(d) + os.sep) or not os.path.isfile(path):
                    return self._err(404, "capture introuvable : %s" % what)
                data = open(path, "rb").read(); ext = os.path.splitext(path)[1].lower()
                self.send_response(200)
                self.send_header("Content-Type", {".png": "image/png", ".json": "application/json", ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"}.get(ext, "application/octet-stream"))
                if ext == ".pptx" or q.get("download"):
                    self.send_header("Content-Disposition", "attachment; filename=\"%s\"" % os.path.basename(path))
                self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-cache")
                self.end_headers(); self.wfile.write(data)
                return
            m_ = re.match(r"^/api/thumbnails/([^/]+)/(index|sprite_\d{3}\.jpg)$", u.path)
            if m_:
                mission = urllib.parse.unquote(m_.group(1)); what = m_.group(2)
                if what == "index":
                    idx = thumbs_index(mission)
                    eng = FOLLOWS.get(follow_id(mission_resolve(mission)["pcap"])) if os.path.isdir(os.path.join(CAPTURES_DIR or "", mission)) else None
                    idx["generating"] = bool(eng and eng.thumbs and eng.thumbs.busy)
                    idx["worker"] = bool(eng and eng.thumbs); idx["error"] = eng.thumbs.error if eng and eng.thumbs else None
                    idx["ffmpeg"] = FFMPEG
                    return self._json(idx)
                path = os.path.join(thumbs_dir(mission), what)
                if not os.path.isfile(path):
                    return self._err(404, "sprite introuvable : %s" % what)
                data = open(path, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg"); self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=%d" % (86400 if not q.get("v") else 31536000))
                self.end_headers(); self.wfile.write(data)
                return
            m_ = re.match(r"^/api/clips/([^/]+)/(list|[^/]+)$", u.path)
            if m_:
                mission = urllib.parse.unquote(m_.group(1)); what = urllib.parse.unquote(m_.group(2))
                if what == "list":
                    return self._json({"mission": mission, "clips": clips_list(mission)})
                d = clips_dir(mission); path = os.path.realpath(os.path.join(d, what))
                if not path.startswith(os.path.realpath(d) + os.sep) or not os.path.isfile(path):
                    return self._err(404, "clip introuvable : %s" % what)
                size = os.path.getsize(path); ext = os.path.splitext(path)[1].lower()
                self.send_response(200)
                self.send_header("Content-Type", {".ts": "video/mp2t", ".csv": "text/csv; charset=utf-8", ".json": "application/json"}.get(ext, "application/octet-stream"))
                if not q.get("inline"):
                    self.send_header("Content-Disposition", "attachment; filename=\"%s\"" % os.path.basename(path))
                self.send_header("Content-Length", str(size)); self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                with open(path, "rb") as fh:
                    try:
                        while True:
                            b = fh.read(1 << 20)
                            if not b:
                                break
                            self.wfile.write(b)
                    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                        self.close_connection = True
                return
            m_ = re.match(r"^/api/missions/([^/]+)/(gpx/merged|details|track\.geojson)$", u.path) or re.match(r"^/download/([^/]+)/(gpx)$", u.path)
            if m_:
                name = urllib.parse.unquote(m_.group(1)); what = m_.group(2)
                if "/" in name or "\\" in name or ".." in name:
                    raise ValueError("nom de mission invalide")
                if what == "details":
                    return self._json(mission_details(name))
                if what == "track.geojson":
                    t0, rows, _p = mission_klv(name)
                    eng = FollowEngine(); eng.t0 = t0; eng.klv = rows; eng._seg_base = os.path.join(CAPTURES_DIR, name, "Capture", name)
                    return self._json(eng.track_geojson())
                data = mission_gpx(name).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/gpx+xml; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=\"%s.gpx\"" % name)
                self.send_header("Content-Length", str(len(data)))
                self._cors_if_direct()
                self.end_headers(); self.wfile.write(data); return
            if u.path == "/api/gmti/ports":
                sets = _capture_sets_by_cr()
                return self._json({"ports": [{"port": cr, "udp_port": (ports[1] if len(ports) > 1 else None),
                                              "profile": (cr_engine(cr).gmti_profile if cr_engine(cr) else (os.getenv("GMTI_PROFILE_%s" % cr) or os.getenv("GMTI_PROFILE") or "defaut"))}
                                             for cr, ports in sets.items()]})
            if u.path == "/api/gmti/status":
                return self._json({"ports": {cr: (cr_engine(cr).gmti_status() if cr_engine(cr) else gmti_status_idle(cr)) for cr in _capture_sets_by_cr()},
                                   "profiles_path": getattr(load_track_run(), "PROFILES_JSON", None)})
            m_ = re.match(r"^/api/gmti/([^/]+)/(state|profile)$", u.path)
            if m_:
                eng = cr_engine(m_.group(1))
                if eng is None:
                    return self._err(404, "pas de mission en cours sur %s" % m_.group(1))
                if m_.group(2) == "state":
                    return self._json(eng.gmti_snapshot_event())
                return self._json({"port": eng.cr, "profile": eng.gmti_profile, "overrides": eng.gmti_overrides, "effective": load_track_run().java_config(eng.gmti_profile, eng.gmti_overrides)})
            if u.path == "/api/follow/status":
                return self._json(follow_get(q.get("id", [""])[0]).status())
            if u.path == "/api/follow/timeline":
                return self._json(follow_get(q.get("id", [""])[0]).timeline())
            if u.path == "/api/follow/delta":
                return self._json(follow_get(q.get("id", [""])[0]).delta(int(q.get("cot", ["0"])[0] or 0), int(q.get("dw", ["0"])[0] or 0), int(q.get("tr", ["0"])[0] or 0), int(q.get("k", ["0"])[0] or 0)))
            if u.path == "/api/follow/track.geojson":
                dp = q.get("dport", [""])[0]
                return self._json(follow_get(q.get("id", [""])[0]).track_geojson(int(dp) if dp else None))
            if u.path == "/api/live/status":
                st = LIVE.status(); st["flows_live"] = LIVE.flows_summary(); return self._json(st)
            if u.path == "/api/live/ifaces":
                return self._json({"ifaces": net_capture.list_interfaces() if net_capture else [],
                                   "platform": sys.platform, "raw_hint": ("administrateur requis (SIO_RCVALL)" if sys.platform.startswith("win") else "CAP_NET_RAW ou root requis (AF_PACKET)")})
            if u.path == "/ws/events":
                return self._ws_events()
            if u.path == "/ws/video":
                return self._ws_video(int(q.get("dport", ["0"])[0] or 0), q.get("follow", [None])[0] or None)
            if u.path == "/api/streams":
                path = self._pcap(q)
                limit = int(q.get("limit", ["0"])[0] or 0)
                settings_save({"last_pcap": os.path.abspath(path)})
                if is_csv_source(path):
                    return self._json({"pcap": path, "streams": [], "source": "csv"})
                streams = scan(path, limit)
                return self._json({"pcap": path, "streams": sorted(
                    (stream_summary(s) for s in streams.values()), key=lambda d: -d["bytes"])})
            if u.path == "/api/klv":
                return self._json(klv_track(self._stream(q)))
            if u.path == "/video.ts":
                return self._video(self._stream(q), q)
            if u.path == "/live.ts":
                return self._live(self._stream(q), q)
            if u.path == "/basemap":
                return self._basemap(q)
            self._err(404, "route inconnue")
        except (FileNotFoundError, ValueError) as e:
            self._err(400, str(e))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True
        except Exception as e:                                     # erreur interne : réponse JSON (sinon nginx renvoie 502)
            import traceback; traceback.print_exc()
            try:
                self._err(500, "%s : %s" % (type(e).__name__, e))
            except Exception:
                self.close_connection = True
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def do_PUT(self):
        return self.do_POST()

    def do_POST(self):
        self._strip_base()
        u = urllib.parse.urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        # Dépôt d'un fichier de préparation : corps = octets bruts, nom en query string.
        # Traité AVANT le parsing JSON du corps, qui échouerait sur du binaire.
        m_ = re.match(r"^/api/missions/([^/]+)/prepa/upload$", u.path)
        if m_:
            try:
                q_ = urllib.parse.parse_qs(u.query)
                data = self.rfile.read(n) if n else b""
                if not data:
                    raise ValueError("corps vide")
                return self._json(prepa_upload(urllib.parse.unquote(m_.group(1)), q_.get("name", [""])[0], data))
            except (FileNotFoundError, ValueError) as e:
                return self._err(400, str(e))
            except Exception as e:
                import traceback; traceback.print_exc()
                return self._err(500, "%s : %s" % (type(e).__name__, e))
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}") if n else {}
        except ValueError:
            return self._err(400, "JSON invalide")
        try:
            if u.path == "/api/replay/start":
                pcap = body.get("pcap") or self.default_pcap
                if not pcap or not os.path.isfile(pcap):
                    raise FileNotFoundError("pcap introuvable : %r" % pcap)
                if is_csv_source(pcap):
                    raise ValueError("un CSV de détections ne se rejoue pas en UDP : utiliser « Lecture IHM seule » (préchargé)")
                ENGINE.start(pcap, body.get("routes", []), body.get("speed", 1.0), body.get("loop", False),
                             body.get("rebase", False), body.get("taps", []), body.get("watch"), body.get("track"),
                             float(body.get("start_at", 0.0) or 0.0))
                return self._json(ENGINE.status())
            if u.path == "/api/replay/stop":
                ENGINE.stop()
                return self._json({"ok": True})
            if u.path == "/api/live/start":
                LIVE.start(body.get("iface") or None, body.get("ip") or None, body.get("groups") or [], body.get("ports") or [],
                           body.get("backend") or "auto", body.get("record") or None, body.get("taps", []), body.get("watch"), body.get("track"))
                return self._json(LIVE.status())
            if u.path == "/api/live/stop":
                return self._json(LIVE.stop())
            m_ = re.match(r"^/api/missions/([^/]+)/delete$", u.path)
            if m_:
                return self._json(mission_delete(urllib.parse.unquote(m_.group(1))))
            if u.path == "/api/captures/snap":
                return self._json(snap_capture(body.get("mission"), body.get("t_utc"), body.get("description"), body.get("dport"), body.get("snaps_label")))
            m_ = re.match(r"^/api/captures/([^/]+)/([^/]+)/delete$", u.path)
            if m_:
                return self._json(capture_delete(urllib.parse.unquote(m_.group(1)), urllib.parse.unquote(m_.group(2))))
            if u.path == "/api/clips/extract":
                return self._json(clip_extract(body.get("mission"), body.get("start_utc"), body.get("end_utc"), body.get("name") or None,
                                               bool(body.get("include_metadata", True)), body.get("dport")))
            m_ = re.match(r"^/api/clips/([^/]+)/([^/]+)/delete$", u.path)
            if m_:
                return self._json(clip_delete(urllib.parse.unquote(m_.group(1)), urllib.parse.unquote(m_.group(2))))
            if u.path == "/api/follow/start":
                pcap = body.get("pcap") or self.default_pcap
                if not pcap or not os.path.isfile(pcap):
                    raise FileNotFoundError("pcap introuvable : %r" % pcap)
                if is_csv_source(pcap):
                    raise ValueError("un CSV ne se suit pas : ouvrir le pcap de la capture")
                return self._json(follow_start(pcap, body.get("watch"), body.get("track"), body.get("taps") or []))
            m_ = re.match(r"^/api/gmti/([^/]+)/(profile|reset)$", u.path)
            if m_:
                eng = cr_engine(m_.group(1))
                if eng is None:
                    raise ValueError("pas de mission en cours sur %s" % m_.group(1))
                if m_.group(2) == "reset":
                    eng.set_gmti_profile(None, None, True)
                else:
                    eng.set_gmti_profile(body.get("profile"), body.get("overrides"), bool(body.get("reset")))
                return self._json({"port": eng.cr, "profile": eng.gmti_profile, "overrides": eng.gmti_overrides})
            m_ = re.match(r"^/api/snaps/([^/]+)/processed/([^/]+)$", u.path)
            if m_:
                return self._json(snaps_archive(urllib.parse.unquote(m_.group(1)), urllib.parse.unquote(m_.group(2))))
            if u.path == "/api/follow/stop":
                # Un visionneur qui part ne coupe pas les autres : le moteur s'arrête seul sans client (reaper) ;
                # force=true = arrêt immédiat (console d'analyse).
                eng = follow_get(body.get("id"))
                if body.get("force"):
                    return self._json(eng.stop())
                eng.last_touch = time.time() - FollowEngine.IDLE_STOP_S + 20.0     # arrêt dans ~20 s si personne d'autre
                st = eng.status(); st["detached"] = True
                return self._json(st)
            if u.path == "/api/follow/follow":
                return self._json(follow_get(body.get("id")).follow(body.get("taps"), body.get("track")))
            if u.path == "/api/live/follow":
                return self._json(LIVE.follow(body.get("taps"), body.get("watch"), body.get("track")))
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
            if u.path == "/api/gmti/publish":
                return self._json(gmti_publish(body.get("url") or (settings_load().get("stratus_url") or ""), bool(body.get("insecure", True))))
            if u.path == "/api/basemap":
                cfg = basemap_save(body)
                self.__class__.basemap_cfg = cfg
                return self._json(basemap_load())
            self._err(404, "route inconnue")
        except (FileNotFoundError, ValueError) as e:
            self._err(400, str(e))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True
        except Exception as e:                                     # erreur interne : réponse JSON (sinon nginx renvoie 502)
            import traceback; traceback.print_exc()
            try:
                self._err(500, "%s : %s" % (type(e).__name__, e))
            except Exception:
                self.close_connection = True

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

    def _ws_gmti(self, cr):
        """Contrat du service GMTI v1 : snapshot à la connexion, puis événements gmti (~4 Hz) et status (1 Hz).
        Sans mission en cours sur le CR : status receiving=false, puis attente (l'abonné n'a pas à se reconnecter)."""
        if not self._ws_handshake():
            return
        sock = self.connection; alive = threading.Event(); alive.set()
        threading.Thread(target=ws_reader, args=(sock, alive.clear), daemon=True).start()
        cur = None; q = None
        try:
            while alive.is_set():
                eng = cr_engine(cr)
                if eng is not cur:
                    if cur is not None and q is not None:
                        cur.gmti_bus.unsubscribe(q)
                    cur = eng; q = None
                    if eng is not None:
                        q = eng.gmti_bus.subscribe(maxsize=200)
                        sock.sendall(ws_frame(json.dumps(eng.gmti_snapshot_event(), ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 1))
                    else:
                        sock.sendall(ws_frame(json.dumps({"type": "status", **gmti_status_idle(cr)}).encode("utf-8"), 1))
                if q is None:
                    time.sleep(1.0); sock.sendall(ws_frame(b"", 9)); continue
                try:
                    item = q.get(timeout=1.0)
                except queue.Empty:
                    sock.sendall(ws_frame(b"", 9)); continue
                sock.sendall(ws_frame(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 1))
        except OSError:
            pass
        finally:
            alive.clear()
            if cur is not None and q is not None:
                cur.gmti_bus.unsubscribe(q)

    def _ws_events(self):
        if not self._ws_handshake():
            return
        q = EVENTS.subscribe()
        q.put({"type": "hello", "replay": ENGINE.status()})
        try:
            self._ws_pump(q, 1, lambda d: json.dumps(d, ensure_ascii=False).encode("utf-8"))
        finally:
            EVENTS.unsubscribe(q)

    def _ws_video(self, dport, fid=None):
        if not dport:
            return self._err(400, "dport requis")
        if not self._ws_handshake():
            return
        bus = video_bus(("%s:%d" % (fid, dport)) if fid else dport)
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

    def _video_follow(self, st, q):
        """DVR sur fichier suivi : ressource = TS du flux à partir de l'instant `from` (temps capture),
        relu depuis le pcap sur disque ; `Range: bytes=X-` = reprise à X octets de la ressource (index
        des octets cumulés → point ≤ X, puis saut) — c'est ce que fait mpegts.js en lazyLoad."""
        t_from = (st.t0 or 0) + float(q.get("from", ["0"])[0] or 0)
        seg_no, off, cum = st.locate_time(t_from)
        # cumul exact au 1er datagramme daté >= t_from : on compte depuis le point d'index
        base = cum
        for chunk in self.__class__._count_until(self, st, seg_no, off, t_from):
            base += chunk
        rng = self.headers.get("Range")
        x = 0
        if rng and rng.startswith("bytes="):
            a = rng[6:].partition("-")[0]
            x = int(a) if a else 0
        seg_no, off, cum = st.locate_bytes(base + x)
        skip = base + x - cum
        self.send_response(206 if x else 200)
        self.send_header("Content-Type", "video/mp2t")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        pending, plen = [], 0
        try:
            for b in FOLLOWS[st.fid].iter_ts(st, seg_no, off, skip):
                pending.append(b); plen += len(b)
                if plen >= 256 * 1024:
                    data = b"".join(pending); self.wfile.write(b"%x\r\n" % len(data)); self.wfile.write(data); self.wfile.write(b"\r\n"); self.wfile.flush()
                    pending, plen = [], 0
            if pending:
                data = b"".join(pending); self.wfile.write(b"%x\r\n" % len(data)); self.wfile.write(data); self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    @staticmethod
    def _count_until(handler, st, seg_no, off, t_abs):
        """Octets TS entre le point d'index et le 1er datagramme daté >= t_abs (≤ 0,5 s de flux)."""
        try:
            tail = PcapTail(FOLLOWS[st.fid].seg_path(seg_no))
        except (OSError, ValueError, TypeError):
            return
        tail.offset = max(24, off)
        try:
            frames = tail.read(8 << 20)
            for ts, lt, data, _o in frames:
                if ts >= t_abs:
                    return
                r = parse(lt, data)
                if r and r[0] == "UDP" and r[4] == st.dport and r[5]:
                    tsd = v9._ts_from_udp(r[5])
                    if tsd:
                        yield len(tsd)
        finally:
            tail.close()

    def _video(self, st, q=None):
        if isinstance(st, FollowStream):
            return self._video_follow(st, q or {})
        data = st.buf
        base = 0
        if q and q.get("from", [""])[0]:
            # Suivi (DVR) : ressource servie À PARTIR du 1er datagramme daté >= t0 + from (index (ts, offset)
            # du tampon) — saut exact au paquet, au lieu de l'estimation par débit du lecteur (Range).
            t_from = (st.t0 or 0) + float(q["from"][0])
            lock = getattr(st, "lock", None)
            with (lock if lock is not None else threading.Lock()):
                tss = [p[0] for p in st.pkts]
                import bisect
                i = bisect.bisect_left(tss, t_from)
                base = st.pkts[i][1] if i < len(st.pkts) else len(data)
        total = len(data) - base
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
        lock = getattr(st, "lock", None)
        for i in range(start, end + 1, 1 << 20):            # tranches copiées : le tampon peut grossir (suivi)
            j = min(i + (1 << 20), end + 1)
            if lock is not None:
                with lock:
                    chunk = bytes(data[base + i:base + j])
            else:
                chunk = bytes(data[base + i:base + j])
            self.wfile.write(chunk)

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
    ap.add_argument("--host", default="127.0.0.1", help="adresse d'écoute (0.0.0.0 en conteneur)")
    ap.add_argument("--base-path", default="", help="préfixe d'URL derrière un reverse proxy (ex. /console) ; les URL nues restent acceptées")
    ap.add_argument("--captures-dir", default=None, help="dossier proposé par défaut dans « Parcourir » (ex. /data/recordings)")
    ap.add_argument("--limit", type=int, default=0, help="nb max de trames lues (0 = tout)")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    Handler.default_pcap = os.path.abspath(a.pcap) if a.pcap else None
    Handler.basemap_cfg = basemap_load()
    Handler.default_limit = a.limit
    global BASE_PATH, CAPTURES_DIR
    BASE_PATH = ("/" + a.base_path.strip("/")) if a.base_path and a.base_path.strip("/") else ""
    CAPTURES_DIR = os.path.abspath(a.captures_dir) if a.captures_dir else None
    if CAPTURES_DIR and os.getenv("AUTO_FOLLOW", "1").strip().lower() not in ("0", "false", "no", "off"):
        threading.Thread(target=auto_follow_loop, name="auto_follow", daemon=True).start()
        print("[follow] suivi automatique des missions en cours (%s, GMTI live sur /ws/gmti/{CR})" % CAPTURE_STATUS_URL, flush=True)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    url = "http://%s:%d%s/" % ("127.0.0.1" if a.host in ("0.0.0.0", "") else a.host, a.port, BASE_PATH)
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
