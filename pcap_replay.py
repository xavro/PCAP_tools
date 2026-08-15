#!/usr/bin/env python3
"""Rejeu de captures pcap / pcapng — simulateur de flux pour banc de test.

POC ISRBOX / 33e ESRA. Ré-émet sur le réseau les charges applicatives (UDP/TCP)
enregistrées dans une capture, pour alimenter GeoEvent (ou tout consommateur)
depuis des enregistrements réels, sans les sources live (CSI/Link16, Delta Suite,
vidéo 4609, GMTI, SAR, CoT...).

Agnostique au contenu : on rejoue les OCTETS applicatifs tels quels — peu importe
le format du flux. Le rejeu régénère les en-têtes L2/L3 (nouveaux datagrammes /
nouvelle connexion TCP vers la cible) : suffisant pour un consommateur applicatif.

Formats lus : pcap classique (LE/BE, µs et ns) et pcapng (blocs SHB/IDB/EPB/SPB).
Gros fichiers : lecture en STREAMING (pas de chargement intégral en mémoire).

Usage :
  # 1) inventorier les flux de la capture
  python pcap_replay.py capture.pcap --list

  # 2) rejouer un flux UDP (ex. le CSI) vers GeoEvent, à vitesse réelle
  python pcap_replay.py capture.pcap --udp --dst-port 17003 \\
      --target 192.168.1.50 --speed 1.0

  # 3) rejouer en boucle, aussi vite que possible, port cible différent
  python pcap_replay.py capture.pcap --udp --dst-port 9876 \\
      --target 192.168.1.50 --target-port 9876 --speed 0 --loop

  # 4) rejouer un flux TCP (ex. bus SITAC) vers un serveur cible
  python pcap_replay.py capture.pcap --tcp --dst-port 4072 --target 192.168.1.50

  # 5) rejouer un flux CoT d'hier comme s'il était émis maintenant
  #    (time/start/stale décalés vers le présent, écarts relatifs préservés ;
  #     indispensable depuis que `stale` est TIME_END du Stream Service)
  python pcap_replay.py capture.pcap --udp --dst-port 8087 \\
      --target 192.168.1.50 --rebase-time

Bibliothèque standard uniquement.
"""

from __future__ import annotations

import argparse
import collections
import re
import socket
import struct
import sys
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Lecture pcap classique + pcapng (streaming) -> (timestamp, linktype, frame)
# --------------------------------------------------------------------------

def iter_frames(path):
    """Yield (ts_float, linktype, frame_bytes) pour chaque paquet capturé."""
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
    rest = f.read(20)  # reste de l'en-tête global (24 - 4 déjà lus)
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
        f.read(4)  # trailing block length
        if len(body) < blen - 12:
            return
        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack("<H", body[0:2])[0]
            # option if_tsresol (code 9) : resolution des timestamps
            tsresol = _ng_tsresol(body[8:]) or tsresol
        elif btype == 0x00000006:  # Enhanced Packet Block
            ts_hi, ts_lo, caplen = struct.unpack("<III", body[4:16])
            ts = ((ts_hi << 32) | ts_lo) * tsresol
            yield (ts, linktype, body[20:20 + caplen])
        elif btype == 0x00000003:  # Simple Packet Block
            yield (0.0, linktype, body[4:])
        # autres blocs ignorés


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
    if linktype != 1 or len(frame) < 34:      # 1 = Ethernet
        return None
    p = 14
    eth = frame[12:14]
    if eth == b"\x81\x00":                     # VLAN
        eth = frame[16:18]
        p = 18
    if eth != b"\x08\x00":                     # IPv4 seulement
        return None
    ihl = (frame[p] & 0x0f) * 4
    proto = frame[p + 9]
    src = ".".join(map(str, frame[p + 12:p + 16]))
    dst = ".".join(map(str, frame[p + 16:p + 20]))
    t = p + ihl
    if proto == 17 and len(frame) >= t + 8:    # UDP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        return ("UDP", src, sport, dst, dport, frame[t + 8:])
    if proto == 6 and len(frame) >= t + 20:    # TCP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        thl = ((frame[t + 12] >> 4) & 0xf) * 4
        return ("TCP", src, sport, dst, dport, frame[t + thl:])
    return None


def classify(pl: bytes) -> str:
    if not pl:
        return "vide"
    if pl[:4] == b"\x98\x15\x1c\xaa":
        return "SITAC-bus"
    if pl[:2] == b"\x49\x36":
        return "Link16/JREAP(I6)"
    if pl[0] == 0x47 and len(pl) % 188 == 0:
        return "MPEG-TS(video)"
    s = pl.lstrip()
    if s[:6] == b"<event" or s[:5] == b"<?xml":
        return "CoT-XML"
    if s[:1] in (b"{", b"["):
        return "JSON"
    if pl[:2] == b"\x1f\x8b":
        return "gzip"
    return "binaire"


# --------------------------------------------------------------------------
# Rebasage temporel des payloads CoT XML (--rebase-time)
# --------------------------------------------------------------------------

# Attributs horodatés d'un event CoT (event@time/start/stale + remarks@time).
_TS_ATTR_RE = re.compile(rb'\b(time|start|stale)="([^"]+)"')
_TIME_ATTR_RE = re.compile(rb'\btime="([^"]+)"')


def _parse_iso(raw: bytes):
    try:
        return datetime.fromisoformat(raw.decode("ascii").replace("Z", "+00:00"))
    except (ValueError, UnicodeDecodeError):
        return None


class TimeRebaser:
    """Décale les horodatages CoT vers le présent, à écarts relatifs constants.

    Le décalage est ancré sur le PREMIER attribut `time` rencontré (l'instant de
    production du premier event devient "maintenant") puis appliqué tel quel à
    tous les time/start/stale suivants : inter-arrivées et durées de validité
    (stale - time) sont préservées. Seuls les payloads CoT XML sont touchés ;
    tout le reste (SITAC binaire, vidéo...) passe inchangé. Un horodatage
    illisible est laissé tel quel plutôt que de corrompre le message.
    """

    def __init__(self):
        self.delta = None
        self.rebased = 0

    def rebase(self, pl: bytes) -> bytes:
        if classify(pl) != "CoT-XML":
            return pl
        if self.delta is None:
            m = _TIME_ATTR_RE.search(pl)
            anchor = _parse_iso(m.group(1)) if m else None
            if anchor is None:
                return pl
            self.delta = datetime.now(timezone.utc) - anchor

        def shift(m):
            dt = _parse_iso(m.group(2))
            if dt is None:
                return m.group(0)
            nv = (dt + self.delta).astimezone(timezone.utc)
            iso = nv.strftime("%Y-%m-%dT%H:%M:%S.") + f"{nv.microsecond // 1000:03d}Z"
            return m.group(1) + b'="' + iso.encode("ascii") + b'"'

        out = _TS_ATTR_RE.sub(shift, pl)
        self.rebased += 1
        return out


# --------------------------------------------------------------------------
# Inventaire
# --------------------------------------------------------------------------

def do_list(path):
    flows = collections.OrderedDict()
    npkt = 0
    for ts, lt, frame in iter_frames(path):
        npkt += 1
        r = parse(lt, frame)
        if not r:
            continue
        proto, src, sport, dst, dport, pl = r
        key = (proto, src, sport, dst, dport)
        fl = flows.get(key)
        if fl is None:
            fl = flows[key] = {"pkts": 0, "bytes": 0, "cls": collections.Counter()}
        fl["pkts"] += 1
        fl["bytes"] += len(pl)
        if pl:
            fl["cls"][classify(pl)] += 1
    print(f"{npkt} paquets, {len(flows)} flux :\n")
    print(f"  {'#':>3}  {'proto':5} {'source':>21} -> {'destination':<21} "
          f"{'paquets':>9} {'octets':>11}  contenu")
    for i, (k, fl) in enumerate(sorted(flows.items(), key=lambda kv: -kv[1]["bytes"])):
        proto, src, sport, dst, dport = k
        cls = ", ".join(f"{c}:{n}" for c, n in fl["cls"].most_common(2)) or "-"
        print(f"  {i:>3}  {proto:5} {src+':'+str(sport):>21} -> "
              f"{dst+':'+str(dport):<21} {fl['pkts']:>9} {fl['bytes']:>11}  {cls}")
    print("\nPour rejouer : --udp/--tcp --dst-port <p> [--src-port <p>] "
          "--target <IP> [--target-port <p>]")


# --------------------------------------------------------------------------
# Rejeu
# --------------------------------------------------------------------------

def wait_until(target: float, precise: bool):
    """Attend jusqu'a l'instant `target` (horloge perf_counter).
    precise=False : time.sleep (precision ~ms sous Windows).
    precise=True  : sommeil grossier + attente active (spin) -> precision ~us,
                    au prix d'un coeur CPU occupe pendant l'attente."""
    if not precise:
        dl = target - time.perf_counter()
        if dl > 0:
            time.sleep(dl)
        return
    while True:
        dl = target - time.perf_counter()
        if dl <= 0:
            return
        if dl > 0.0015:
            time.sleep(dl - 0.001)   # dort jusqu'a ~1 ms avant la cible
        # sinon : spin serre jusqu'a l'echeance (dizaines de us)


def matches(r, args):
    proto, src, sport, dst, dport, pl = r
    if args.udp and proto != "UDP":
        return False
    if args.tcp and proto != "TCP":
        return False
    if args.dst_port is not None and dport != args.dst_port:
        return False
    if args.src_port is not None and sport != args.src_port:
        return False
    if args.src and src != args.src:
        return False
    return bool(pl)


def do_replay(path, args):
    proto = "TCP" if args.tcp else "UDP"
    port_desc = str(args.target_port) if args.target_port else "port d'origine"
    speed_desc = "max" if args.speed == 0 else f"{args.speed}x"
    loop_desc = ", boucle" if args.loop else ""
    prec_desc = ", pacing precis" if args.precise else ""
    rebase_desc = ", horodatages CoT rebasés sur maintenant" if args.rebase_time else ""
    print(f"Rejeu {proto} vers {args.target}:{port_desc} "
          f"(vitesse {speed_desc}{loop_desc}{prec_desc}{rebase_desc}).")

    # Pré-collecte des messages du flux sélectionné (payload + timestamp).
    # Pour un gros fichier mono-flux, on streame directement au rejeu.
    passes = 0
    try:
        while True:
            passes += 1
            _replay_once(path, args, proto)
            if not args.loop:
                break
            print(f"  -- boucle {passes} terminée, on recommence --")
    except KeyboardInterrupt:
        print("\n  (arrêt manuel)")


def _replay_once(path, args, proto):
    tcp_sock = None
    udp_sock = None
    if proto == "UDP":
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Nouveau rebaser à chaque passe : en --loop, chaque tour est ré-ancré sur
    # l'heure courante (sinon la 2e boucle rejouerait des events déjà périmés).
    rebaser = TimeRebaser() if args.rebase_time else None
    sent = 0
    t0_wall = None
    t0_cap = None
    try:
        for ts, lt, frame in iter_frames(path):
            r = parse(lt, frame)
            if not r or not matches(r, args):
                continue
            _proto, src, sport, dst, dport, pl = r
            tgt_port = args.target_port or dport
            if rebaser is not None:
                pl = rebaser.rebase(pl)
            # Cadence : respecter les inter-arrivées si speed>0.
            if args.speed and args.speed > 0:
                if t0_cap is None:
                    t0_cap, t0_wall = ts, time.perf_counter()
                target_wall = t0_wall + (ts - t0_cap) / args.speed
                wait_until(target_wall, args.precise)
            if proto == "UDP":
                udp_sock.sendto(pl, (args.target, tgt_port))
            else:
                if tcp_sock is None:
                    tcp_sock = socket.create_connection((args.target, tgt_port), timeout=5)
                    print(f"  connecté TCP {args.target}:{tgt_port}")
                tcp_sock.sendall(pl)
            sent += 1
            if sent % 5000 == 0:
                print(f"  {sent} messages émis...")
    finally:
        if udp_sock:
            udp_sock.close()
        if tcp_sock:
            tcp_sock.close()
    if rebaser is not None:
        print(f"  {sent} messages rejoués ({rebaser.rebased} CoT rebasés).")
    else:
        print(f"  {sent} messages rejoués.")


# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Rejeu de captures pcap/pcapng (banc de test)")
    ap.add_argument("file", help="fichier .pcap ou .pcapng")
    ap.add_argument("--list", action="store_true", help="inventorier les flux et sortir")
    ap.add_argument("--udp", action="store_true", help="rejouer les flux UDP")
    ap.add_argument("--tcp", action="store_true", help="rejouer un flux TCP")
    ap.add_argument("--dst-port", type=int, help="filtrer sur le port destination")
    ap.add_argument("--src-port", type=int, help="filtrer sur le port source")
    ap.add_argument("--src", help="filtrer sur l'IP source")
    ap.add_argument("--target", help="IP cible du rejeu")
    ap.add_argument("--target-port", type=int, help="port cible (defaut : port d'origine)")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="1.0 = temps reel, >1 accelere, 0 = aussi vite que possible")
    ap.add_argument("--precise", action="store_true",
                    help="pacing haute precision (spin ; ~us mais occupe un coeur CPU)")
    ap.add_argument("--loop", action="store_true", help="rejouer en boucle")
    ap.add_argument("--rebase-time", action="store_true",
                    help="décaler les horodatages CoT (time/start/stale) vers le "
                         "présent, écarts relatifs préservés (payloads CoT XML "
                         "uniquement, le binaire passe inchangé)")
    args = ap.parse_args(argv)

    if args.list:
        return do_list(args.file)
    if not (args.udp or args.tcp):
        ap.error("precisez --list, ou --udp / --tcp pour rejouer")
    if not args.target:
        ap.error("--target <IP> requis pour le rejeu")
    if args.udp and args.tcp:
        ap.error("choisir --udp OU --tcp")
    return do_replay(args.file, args)


if __name__ == "__main__":
    sys.exit(main())
