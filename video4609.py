# -*- coding: utf-8 -*-
"""video4609.py — inspection d'un flux vidéo STANAG 4609 (MPEG-TS + KLV MISB 0601).

Parse une capture pcap/pcapng : réassemble le MPEG-TS transporté en UDP (TS brut
ou RTP/MP2T), inventorie les PID (PAT/PMT), identifie codecs et **métadonnées KLV**
(MISB ST 0601) qu'il décode en champ=valeur (position capteur, attitude porteur,
centre image, portée…). Peut extraire le flux TS pour un lecteur externe.

Pur Python (réutilise le lecteur pcap de pcap_replay). Aucun décodage d'image
(air-gap) : la lecture vidéo passe par le lecteur système sur le .ts extrait.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_replay import iter_frames, parse   # noqa: E402

TS_PKT = 188
STREAM_TYPES = {
    0x01: "MPEG-1 vidéo", 0x02: "MPEG-2 vidéo", 0x1B: "H.264/AVC",
    0x24: "H.265/HEVC", 0x03: "MPEG-1 audio", 0x04: "MPEG-2 audio",
    0x0F: "AAC", 0x06: "PES privé (souvent KLV async)",
    0x15: "Métadonnées (KLV synchro)",
}
# Clé universelle MISB ST 0601 (UAS Datalink Local Set).
MISB_0601_KEY = bytes.fromhex("060e2b34020b01010e01030101000000")


# ── Réassemblage TS depuis l'UDP (TS brut ou RTP) ───────────────────────────
def _ts_from_udp(pl):
    """Extrait le TS d'un payload UDP : TS brut (0x47…) ou RTP/MP2T (saute l'en-tête)."""
    if not pl:
        return b""
    if pl[0] == 0x47 and len(pl) % TS_PKT == 0:
        return pl
    if len(pl) > 12 and (pl[0] >> 6) == 2:            # RTP v2
        hdr = 12 + (pl[0] & 0x0F) * 4                 # + CSRC
        if len(pl) > hdr and pl[hdr] == 0x47:
            return pl[hdr:]
    return b""


def udp_ts_streams(path, port=None, limit=0):
    """{(dst,dport): bytearray(TS)} pour les flux UDP transportant du MPEG-TS."""
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
        if proto != "UDP" or (port and dport != port):
            continue
        tsdata = _ts_from_udp(pl)
        if tsdata:
            streams.setdefault((dst, dport), bytearray()).extend(tsdata)
    return streams


# ── Parsing MPEG-TS : PID, PAT, PMT ─────────────────────────────────────────
def _iter_ts(buf):
    off = 0
    n = len(buf)
    # resync sur 0x47
    while off + TS_PKT <= n and buf[off] != 0x47:
        off += 1
    while off + TS_PKT <= n:
        pkt = buf[off:off + TS_PKT]
        off += TS_PKT
        if pkt[0] != 0x47:
            # resync
            while off + TS_PKT <= n and buf[off] != 0x47:
                off += 1
            continue
        yield pkt


def _pid(pkt):
    return ((pkt[1] & 0x1F) << 8) | pkt[2]


def _payload(pkt):
    afc = (pkt[3] >> 4) & 0x3
    idx = 4
    if afc & 0x2:                       # champ d'adaptation
        idx += 1 + pkt[4]
    if not (afc & 0x1) or idx >= TS_PKT:
        return b""
    return pkt[idx:]


def _section_payload(pkt):
    """Payload de section (PSI) : saute le pointer_field si PUSI."""
    pl = _payload(pkt)
    if not pl:
        return b""
    if pkt[1] & 0x40:                   # PUSI
        return pl[1 + pl[0]:]
    return pl


def analyze_stream(buf):
    """Inventaire d'un flux TS : PID, PAT/PMT, codecs, PID KLV, continuité."""
    pids = {}
    cc = {}
    cc_err = 0
    pmt_pids = set()
    pmt_seen = {}
    for pkt in _iter_ts(buf):
        pid = _pid(pkt)
        pids[pid] = pids.get(pid, 0) + 1
        c = pkt[3] & 0x0F
        if pid in cc and (cc[pid] + 1) & 0x0F != c and (pkt[3] & 0x10):
            cc_err += 1
        cc[pid] = c
        if pid == 0:                    # PAT
            sec = _section_payload(pkt)
            if len(sec) >= 8 and sec[0] == 0x00:
                sl = ((sec[1] & 0x0F) << 8) | sec[2]
                body = sec[8:3 + sl - 4]
                for i in range(0, len(body) - 3, 4):
                    prog = (body[i] << 8) | body[i + 1]
                    pmt_pid = ((body[i + 2] & 0x1F) << 8) | body[i + 3]
                    if prog != 0:
                        pmt_pids.add(pmt_pid)
        elif pid in pmt_pids and pid not in pmt_seen:
            sec = _section_payload(pkt)
            es = _parse_pmt(sec)
            if es:
                pmt_seen[pid] = es
    elems = {}
    for es in pmt_seen.values():
        elems.update(es)
    klv_pid = None
    for epid, stype in elems.items():
        if stype in (0x06, 0x15):
            klv_pid = epid
            break
    return {"pids": pids, "elements": elems, "klv_pid": klv_pid,
            "cc_errors": cc_err, "pmt_pids": sorted(pmt_pids)}


def _parse_pmt(sec):
    if len(sec) < 12 or sec[0] != 0x02:
        return {}
    sl = ((sec[1] & 0x0F) << 8) | sec[2]
    pi_len = ((sec[10] & 0x0F) << 8) | sec[11]
    off = 12 + pi_len
    end = 3 + sl - 4
    es = {}
    while off + 5 <= end and off + 5 <= len(sec):
        stype = sec[off]
        epid = ((sec[off + 1] & 0x1F) << 8) | sec[off + 2]
        es_len = ((sec[off + 3] & 0x0F) << 8) | sec[off + 4]
        es[epid] = stype
        off += 5 + es_len
    return es


# ── KLV MISB ST 0601 : décodage champ=valeur (sous-ensemble utile) ──────────
def _u(b): return int.from_bytes(b, "big", signed=False)
def _s(b): return int.from_bytes(b, "big", signed=True)


def _lin_s(raw, bits, rng):
    return raw * (rng / (2 ** (bits - 1) - 1))


def _lin_u(raw, bits, rng, off=0.0):
    return raw * (rng / (2 ** bits - 1)) + off


# tag -> (nom, fonction(bytes)->valeur formatée)
KLV_TAGS = {
    2:  ("Horodatage (UTC)", lambda b: "%d µs" % _u(b)),
    3:  ("Mission ID", lambda b: b.decode("ascii", "replace")),
    4:  ("Plateforme (tail)", lambda b: b.decode("ascii", "replace")),
    5:  ("Cap plateforme (°)", lambda b: "%.2f" % _lin_u(_u(b), 16, 360.0)),
    6:  ("Tangage plateforme (°)", lambda b: "%.2f" % _lin_s(_s(b), 16, 20.0)),
    7:  ("Roulis plateforme (°)", lambda b: "%.2f" % _lin_s(_s(b), 16, 50.0)),
    10: ("Désignation plateforme", lambda b: b.decode("ascii", "replace")),
    11: ("Capteur (source image)", lambda b: b.decode("ascii", "replace")),
    12: ("Système de coord. image", lambda b: b.decode("ascii", "replace")),
    13: ("Latitude capteur (°)", lambda b: "%.7f" % _lin_s(_s(b), 32, 90.0)),
    14: ("Longitude capteur (°)", lambda b: "%.7f" % _lin_s(_s(b), 32, 180.0)),
    15: ("Altitude capteur (m)", lambda b: "%.1f" % _lin_u(_u(b), 16, 19900.0, -900.0)),
    16: ("HFOV capteur (°)", lambda b: "%.2f" % _lin_u(_u(b), 16, 180.0)),
    17: ("VFOV capteur (°)", lambda b: "%.2f" % _lin_u(_u(b), 16, 180.0)),
    18: ("Azimut relatif capteur (°)", lambda b: "%.3f" % _lin_u(_u(b), 32, 360.0)),
    19: ("Élévation relative capteur (°)", lambda b: "%.3f" % _lin_s(_s(b), 32, 180.0)),
    21: ("Portée oblique (m)", lambda b: "%.1f" % _lin_u(_u(b), 32, 5000000.0)),
    23: ("Latitude centre image (°)", lambda b: "%.7f" % _lin_s(_s(b), 32, 90.0)),
    24: ("Longitude centre image (°)", lambda b: "%.7f" % _lin_s(_s(b), 32, 180.0)),
    25: ("Altitude centre image (m)", lambda b: "%.1f" % _lin_u(_u(b), 16, 19900.0, -900.0)),
    65: ("Version LS MISB 0601", lambda b: str(_u(b))),
}


def _ber_len(buf, i):
    """Longueur BER : renvoie (longueur, index suivant), ou (None, i) si tronqué."""
    if i >= len(buf):
        return None, i
    b0 = buf[i]
    if b0 < 0x80:
        return b0, i + 1
    n = b0 & 0x7F
    if i + 1 + n > len(buf):
        return None, i + 1 + n
    return int.from_bytes(buf[i + 1:i + 1 + n], "big"), i + 1 + n


def decode_klv_0601(buf):
    """Décode le PREMIER local set MISB 0601 COMPLET de `buf` -> [(tag,nom,valeur)].
    Renvoie None si la clé est absente OU si le set n'est pas encore entier."""
    idx = buf.find(MISB_0601_KEY)
    if idx < 0:
        return None
    i = idx + len(MISB_0601_KEY)
    total, i = _ber_len(buf, i)
    if total is None or i + total > len(buf):
        return None                       # set incomplet : attendre plus d'octets
    end = i + total
    out = []
    while i < end:
        tag = buf[i]; i += 1
        ln, i = _ber_len(buf, i)
        if ln is None or i + ln > end:
            break
        val = buf[i:i + ln]; i += ln
        if tag in KLV_TAGS:
            name, fn = KLV_TAGS[tag]
            try:
                out.append((tag, name, fn(val)))
            except Exception:
                out.append((tag, name, val.hex()))
        else:
            out.append((tag, "tag %d" % tag, val.hex()[:32]))
    return out


def _fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def klv_samples(buf, klv_pid, max_sets=400):
    """Décode les sets KLV 0601 successifs -> échantillons position capteur +
    centre image : [(sensor_lat, sensor_lon, fc_lat, fc_lon)] (fc = None si absent)."""
    if klv_pid is None:
        return []
    acc = bytearray()
    for pkt in _iter_ts(buf):
        if _pid(pkt) == klv_pid:
            acc.extend(_payload(pkt))
    data = bytes(acc)
    out, start = [], 0
    while len(out) < max_sets:
        idx = data.find(MISB_0601_KEY, start)
        if idx < 0:
            break
        start = idx + len(MISB_0601_KEY)
        rec = decode_klv_0601(data[idx:])
        if not rec:
            continue
        d = {tag: val for tag, _n, val in rec}
        slat, slon = _fnum(d.get(13)), _fnum(d.get(14))
        if slat is None or slon is None:
            continue
        out.append((slat, slon, _fnum(d.get(23)), _fnum(d.get(24))))
    return out


def klv_from_stream(buf, klv_pid):
    """Concatène le payload du PID KLV et décode le 1er set 0601."""
    if klv_pid is None:
        return None
    acc = bytearray()
    for pkt in _iter_ts(buf):
        if _pid(pkt) == klv_pid:
            acc.extend(_payload(pkt))
            if MISB_0601_KEY in acc:
                r = decode_klv_0601(bytes(acc))
                if r:
                    return r
            if len(acc) > 4_000_000:      # garde-fou mémoire (échantillon)
                break
    return None


# ── API haut niveau ─────────────────────────────────────────────────────────
def inspect(path, port=None, limit=0):
    """Inventaire complet des flux vidéo 4609 d'un pcap."""
    streams = udp_ts_streams(path, port, limit)
    result = []
    for (dst, dport), buf in streams.items():
        info = analyze_stream(buf)
        info["dst"], info["dport"], info["bytes"] = dst, dport, len(buf)
        info["klv"] = klv_from_stream(buf, info["klv_pid"])
        result.append(info)
    result.sort(key=lambda d: -d["bytes"])
    return result


def sensor_samples(path, port=None, limit=0, max_sets=400):
    """Position capteur + centre image dans le temps, pour le flux KLV principal."""
    streams = udp_ts_streams(path, port, limit)
    for (dst, dport), buf in sorted(streams.items(), key=lambda kv: -len(kv[1])):
        info = analyze_stream(buf)
        if info["klv_pid"] is not None:
            return klv_samples(buf, info["klv_pid"], max_sets)
    return []


def extract_ts(path, dport, out_path, port=None, limit=0):
    """Écrit le TS réassemblé du flux sur `dport` dans `out_path` (pour lecteur externe)."""
    streams = udp_ts_streams(path, port or dport, limit)
    buf = streams.get((None, None))
    for (dst, dp), b in streams.items():
        if dp == dport:
            buf = b; break
    if not buf:
        raise ValueError("aucun flux TS sur le port %s" % dport)
    with open(out_path, "wb") as f:
        f.write(bytes(buf))
    return len(buf)


def _report(infos):
    L = []
    A = L.append
    A("=" * 60); A("INVENTAIRE VIDÉO STANAG 4609"); A("=" * 60)
    if not infos:
        A("Aucun flux MPEG-TS détecté."); return "\n".join(L)
    for info in infos:
        A("")
        A("Flux %s:%d — %.1f Mo, %d PID, erreurs continuité %d"
          % (info["dst"], info["dport"], info["bytes"] / 1e6, len(info["pids"]), info["cc_errors"]))
        for epid, stype in info["elements"].items():
            A("  PID %d : %s (type 0x%02X)" % (epid, STREAM_TYPES.get(stype, "?"), stype))
        if info["klv_pid"] is not None:
            A("  -> KLV MISB 0601 sur PID %d" % info["klv_pid"])
        if info["klv"]:
            A("  Métadonnées KLV (1er set) :")
            for tag, name, val in info["klv"]:
                A("     %-30s = %s" % (name, val))
        elif info["klv_pid"] is not None:
            A("  (KLV présent, set non décodé sur l'échantillon)")
    return "\n".join(L)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__); sys.exit(0)

    def opt(name):
        for i, a in enumerate(sys.argv):
            if a == "--" + name:
                return sys.argv[i + 1]
        return None

    port = opt("port")
    limit = opt("limit")
    infos = inspect(args[0], int(port) if port else None, int(limit) if limit else 0)
    print(_report(infos))
