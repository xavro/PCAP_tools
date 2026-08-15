#!/usr/bin/env python3
"""Analyse de captures pcap / pcapng — inventaire des flux et protocoles détectés.

POC ISRBOX / 33e ESRA. Script dédié à l'ANALYSE (le rejeu est assuré par
`pcap_replay.py`). Répond à « quels ports, quels protocoles » dans une capture :
pour chaque flux (proto / IP:port), compte les paquets/octets et DÉTECTE le
protocole applicatif par signature — CoT XML, bus SITAC, Link16/JREAP, vidéo
MPEG-TS (STANAG 4609), métadonnées KLV, GMTI STANAG 4607 (validation
structurelle), JSON, gzip, sinon binaire.

Formats lus : pcap classique (LE/BE, µs et ns) et pcapng. Lecture en STREAMING
(gros fichiers). Bibliothèque standard uniquement.

Usage :
  python pcap_analyze.py capture.pcap                # synthèse par port
  python pcap_analyze.py capture.pcap --flows        # + détail par flux src→dst
  python pcap_analyze.py capture.pcap --proto gmti   # ne lister que les ports GMTI
"""
from __future__ import annotations

import argparse
import collections
import struct
import sys

# Sortie accentuée fiable quelle que soit la page de code console (Windows cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# --------------------------------------------------------------------------
# Lecture pcap classique + pcapng (streaming) — aligné sur pcap_replay.py
# --------------------------------------------------------------------------

def iter_frames(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _iter_pcap(f, magic)
        elif magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f)
        else:
            raise ValueError("format inconnu (magic %s)" % magic.hex())


def _iter_pcap(f, magic):
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    end = "<" if le else ">"
    rest = f.read(20)
    linktype = struct.unpack(end + "I", rest[16:20])[0]
    tsdiv = 1e9 if nano else 1e6
    hdr = struct.Struct(end + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        ts_s, ts_frac, incl, orig = hdr.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield (ts_s + ts_frac / tsdiv, linktype, data)


def _iter_pcapng(f):
    f.seek(0)
    linktype = 1
    tsresol = 1e-6
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        btype, blen = struct.unpack("<II", head)
        body = f.read(blen - 12)
        f.read(4)
        if len(body) < blen - 12:
            return
        if btype == 0x00000001:
            linktype = struct.unpack("<H", body[0:2])[0]
            tsresol = _ng_tsresol(body[8:]) or tsresol
        elif btype == 0x00000006:
            ts_hi, ts_lo, caplen = struct.unpack("<III", body[4:16])
            ts = ((ts_hi << 32) | ts_lo) * tsresol
            yield (ts, linktype, body[20:20 + caplen])
        elif btype == 0x00000003:
            yield (0.0, linktype, body[4:])


def _ng_tsresol(opts):
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack("<HH", opts[i:i + 4])
        val = opts[i + 4:i + 4 + ln]
        if code == 0:
            return None
        if code == 9 and ln >= 1:
            r = val[0]
            return (1.0 / (2 ** (r & 0x7f))) if (r & 0x80) else (10.0 ** -r)
        i += 4 + ln + ((-ln) % 4)
    return None


# --------------------------------------------------------------------------
# Ethernet / IPv4 / UDP / TCP -> (proto, src, sport, dst, dport, payload)
# --------------------------------------------------------------------------

def parse(linktype, frame):
    if linktype != 1 or len(frame) < 34:
        return None
    p = 14
    eth = frame[12:14]
    if eth == b"\x81\x00":
        eth = frame[16:18]
        p = 18
    if eth != b"\x08\x00":
        return None
    ihl = (frame[p] & 0x0f) * 4
    proto = frame[p + 9]
    src = ".".join(map(str, frame[p + 12:p + 16]))
    dst = ".".join(map(str, frame[p + 16:p + 20]))
    t = p + ihl
    if proto == 17 and len(frame) >= t + 8:      # UDP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        ulen = struct.unpack(">H", frame[t + 4:t + 6])[0]
        pl = frame[t + 8: t + ulen] if 8 <= ulen <= len(frame) - t else frame[t + 8:]
        return ("UDP", src, sport, dst, dport, pl)
    if proto == 6 and len(frame) >= t + 20:      # TCP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        thl = ((frame[t + 12] >> 4) & 0xf) * 4
        return ("TCP", src, sport, dst, dport, frame[t + thl:])
    return None


# --------------------------------------------------------------------------
# Détection de protocole applicatif par signature
# --------------------------------------------------------------------------

# Types de segments STANAG 4607 (pour la validation structurelle).
_4607_SEG_TYPES = {1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 100, 101, 102, 103, 110, 111, 120, 121}
_4607_PKT_HDR = 32


def looks_like_4607(pl: bytes) -> bool:
    """Validation STRUCTURELLE d'un paquet STANAG 4607 (GMTI) — pas juste le port.

    En-tête paquet (taille auto-délimitante == datagramme, version/nationalité
    ASCII) + 1er segment cohérent (type connu, taille plausible).
    """
    if len(pl) < _4607_PKT_HDR + 5:
        return False
    try:
        pkt_size = struct.unpack(">I", pl[2:6])[0]
        if not (_4607_PKT_HDR <= pkt_size <= len(pl) and abs(pkt_size - len(pl)) <= 4):
            return False
        if not (all(32 <= c < 127 for c in pl[0:2]) and all(32 <= c < 127 for c in pl[6:8])):
            return False
        typ = pl[32]
        size = struct.unpack(">I", pl[33:37])[0]
        return typ in _4607_SEG_TYPES and 5 <= size <= (min(pkt_size, len(pl)) - _4607_PKT_HDR)
    except Exception:
        return False


def classify(pl: bytes) -> str:
    if not pl:
        return "vide"
    if pl[:4] == b"\x98\x15\x1c\xaa":
        return "SITAC-bus"
    if pl[:2] == b"\x49\x36":
        return "Link16/JREAP(I6)"
    if pl[0] == 0x47 and len(pl) % 188 == 0:
        return "MPEG-TS/4609(video)"
    if pl[:4] == b"\x06\x0e\x2b\x34":                       # clé universelle SMPTE 336
        return "KLV/4609(meta)"
    if looks_like_4607(pl):
        return "GMTI/4607"
    s = pl.lstrip()
    if s[:6] == b"<event" or s[:5] == b"<?xml":
        return "CoT-XML"
    if s[:1] in (b"{", b"["):
        return "JSON"
    if pl[:2] == b"\x1f\x8b":
        return "gzip"
    return "binaire"


# Filtres --proto (nom convivial -> étiquette classify).
_PROTO_ALIASES = {
    "gmti": "GMTI/4607", "4607": "GMTI/4607",
    "cot": "CoT-XML", "sitac": "SITAC-bus", "link16": "Link16/JREAP(I6)",
    "video": "MPEG-TS/4609(video)", "klv": "KLV/4609(meta)",
    "json": "JSON", "gzip": "gzip",
}


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------

def analyze(path, show_flows, proto_filter, limit=0, top_n=25, show_all=False):
    flows = collections.OrderedDict()      # (proto,src,sport,dst,dport) -> stats
    ports = collections.OrderedDict()      # (proto,dport) -> stats agrégées
    npkt = 0
    tmin = tmax = None
    truncated = False
    for ts, lt, frame in iter_frames(path):
        npkt += 1
        if limit and npkt > limit:
            truncated = True
            npkt -= 1
            break
        r = parse(lt, frame)
        if not r:
            continue
        proto, src, sport, dst, dport, pl = r
        if ts:
            tmin = ts if tmin is None else min(tmin, ts)
            tmax = ts if tmax is None else max(tmax, ts)
        cls = classify(pl)
        for table, key in ((flows, (proto, src, sport, dst, dport)), (ports, (proto, dport))):
            st = table.get(key)
            if st is None:
                st = table[key] = {"pkts": 0, "bytes": 0, "cls": collections.Counter(), "dsts": set()}
            st["pkts"] += 1
            st["bytes"] += len(pl)
            st["cls"][cls] += 1
            st["dsts"].add(dst)

    span = ("%.1f s" % (tmax - tmin)) if (tmin is not None and tmax and tmax > tmin) else "n/a"
    print("=== %s ===" % path)
    lim = (" (analyse limitée aux %d premiers paquets)" % limit) if truncated else ""
    print("%d paquets%s, %d flux, %d port(s) destination, durée %s\n"
          % (npkt, lim, len(flows), len(ports), span))

    want = _PROTO_ALIASES.get(proto_filter.lower()) if proto_filter else None
    APP = ("GMTI", "CoT", "SITAC", "Link16", "MPEG", "KLV", "JSON")

    # ── Protocoles applicatifs identifiés (réponse principale, en tête) ────
    hits = []
    for key in sorted(ports, key=lambda k: -ports[k]["bytes"]):
        proto, dport = key
        dominant = ports[key]["cls"].most_common(1)[0][0]
        if dominant.startswith(APP) and not (want and dominant != want):
            hits.append((proto, dport, dominant, ports[key]))
    if hits:
        print("PROTOCOLES APPLICATIFS IDENTIFIÉS :")
        for proto, dport, d, st in hits:
            print("  %-5s port %-6d %-22s %d paquets -> %s"
                  % (proto, dport, d, st["pkts"], ",".join(sorted(st["dsts"]))))
    else:
        print("Aucun protocole applicatif connu identifié (que du binaire/vide).")

    # ── Table complète par PORT destination (triée, tronquée sauf --all) ──
    rows = [k for k in sorted(ports, key=lambda k: -ports[k]["bytes"])
            if not (want and ports[k]["cls"].most_common(1)[0][0] != want)]
    shown = rows if show_all else rows[:top_n]
    print("\nPorts destination (par volume) :")
    print("  %-5s %-7s %-9s %-12s  %-15s %s"
          % ("proto", "port", "paquets", "octets", "dst", "protocole détecté"))
    for key in shown:
        proto, dport = key
        st = ports[key]
        top = st["cls"].most_common(2)
        dominant = top[0][0]
        detected = ", ".join("%s:%d" % (c, n) for c, n in top)
        dsts = ",".join(sorted(st["dsts"]))
        mark = "  <<<" if dominant.startswith(APP) else ""
        print("  %-5s %-7d %-9d %-12d  %-15s %s%s"
              % (proto, dport, st["pkts"], st["bytes"], dsts[:15], detected, mark))
    if not show_all and len(rows) > top_n:
        print("  … %d autres port(s) mineur(s) (--all pour tout voir)" % (len(rows) - top_n))

    # ── Détail par flux (optionnel) ───────────────────────────────────────
    if show_flows:
        print("\nDétail par flux :")
        print("  %-5s %-21s -> %-21s %-9s %-11s  %s"
              % ("proto", "source", "destination", "paquets", "octets", "protocole"))
        for key in sorted(flows, key=lambda k: -flows[k]["bytes"]):
            proto, src, sport, dst, dport = key
            st = flows[key]
            dominant = st["cls"].most_common(1)[0][0]
            if want and dominant != want:
                continue
            print("  %-5s %-21s -> %-21s %-9d %-11d  %s"
                  % (proto, "%s:%d" % (src, sport), "%s:%d" % (dst, dport),
                     st["pkts"], st["bytes"], dominant))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyse pcap/pcapng — ports & protocoles détectés")
    ap.add_argument("files", nargs="+", help="fichier(s) .pcap ou .pcapng")
    ap.add_argument("--flows", action="store_true", help="détailler chaque flux src→dst")
    ap.add_argument("--proto", default=None,
                    help="ne lister que ce protocole (gmti, cot, sitac, link16, video, klv, json)")
    ap.add_argument("--limit", type=int, default=0,
                    help="n'analyser que les N premiers paquets (empreinte rapide des gros .pcap)")
    ap.add_argument("--top", type=int, default=25,
                    help="nb de ports affichés dans la table (défaut 25 ; --all pour tout)")
    ap.add_argument("--all", action="store_true", help="afficher tous les ports (pas de troncature)")
    args = ap.parse_args(argv)
    for path in args.files:
        analyze(path, args.flows, args.proto, args.limit, args.top, args.all)


if __name__ == "__main__":
    sys.exit(main())
