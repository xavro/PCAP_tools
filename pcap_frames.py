# -*- coding: utf-8 -*-
"""pcap_frames.py — lecteur de trames pcap/pcapng COMMUN (streaming, stdlib).

Lecteur unique partagé par les outils de la suite (gmti_pcap_to_csv,
stanag4607_extract, …) pour éviter les copies divergentes. Lit en STREAMING
(jamais tout le fichier en mémoire) :
  - pcap classique : little/big-endian, timestamps µs et ns ;
  - pcapng : blocs SHB/IDB, Enhanced/Simple Packet Block (EPB/SPB).

Décapsulation L2/L3/L4 : Ethernet (+ VLAN 802.1Q) / IPv4 / UDP / TCP.

Limite connue : la FRAGMENTATION IP n'est pas réassemblée (un datagramme UDP
fragmenté sur plusieurs paquets IP n'est pas reconstitué). Les flux GMTI/CoT/
vidéo observés tiennent dans un seul paquet IP ; à revoir si un vecteur fragmente.
"""
import struct

__all__ = ["iter_frames", "parse", "udp_payload"]


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
    rest = f.read(20)                       # reste de l'en-tête global (24 - 4 lus)
    linktype = struct.unpack(end + "I", rest[16:20])[0]
    tsdiv = 1e9 if nano else 1e6
    hdr = struct.Struct(end + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        ts_s, ts_frac, incl, _orig = hdr.unpack(h)
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
        if blen < 12:
            return
        body = f.read(blen - 12)
        f.read(4)                           # longueur de bloc en fin (redondante)
        if len(body) < blen - 12:
            return
        if btype == 0x00000001:             # Interface Description Block
            linktype = struct.unpack("<H", body[0:2])[0]
            tsresol = _ng_tsresol(body[8:]) or tsresol
        elif btype == 0x00000006:           # Enhanced Packet Block
            ts_hi, ts_lo, caplen = struct.unpack("<III", body[4:16])
            ts = ((ts_hi << 32) | ts_lo) * tsresol
            yield (ts, linktype, body[20:20 + caplen])
        elif btype == 0x00000003:           # Simple Packet Block
            yield (0.0, linktype, body[4:])


def _ng_tsresol(opts):
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack("<HH", opts[i:i + 4])
        val = opts[i + 4:i + 4 + ln]
        if code == 0:
            return None
        if code == 9 and ln >= 1:           # if_tsresol
            r = val[0]
            return (1.0 / (2 ** (r & 0x7f))) if (r & 0x80) else (10.0 ** -r)
        i += 4 + ln + ((-ln) % 4)
    return None


def parse(linktype, frame):
    """(proto, src, sport, dst, dport, payload) pour UDP/TCP IPv4, sinon None.
    Pas de réassemblage de fragments IP (cf. limite en tête de module)."""
    if linktype != 1 or len(frame) < 34:     # 1 = Ethernet
        return None
    p = 14
    eth = frame[12:14]
    if eth == b"\x81\x00":                    # VLAN 802.1Q
        eth = frame[16:18]
        p = 18
    if eth != b"\x08\x00":                    # IPv4 uniquement
        return None
    ihl = (frame[p] & 0x0f) * 4
    proto = frame[p + 9]
    src = ".".join(map(str, frame[p + 12:p + 16]))
    dst = ".".join(map(str, frame[p + 16:p + 20]))
    t = p + ihl
    if proto == 17 and len(frame) >= t + 8:   # UDP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        ulen = struct.unpack(">H", frame[t + 4:t + 6])[0]
        pl = frame[t + 8: t + ulen] if 8 <= ulen <= len(frame) - t else frame[t + 8:]
        return ("UDP", src, sport, dst, dport, pl)
    if proto == 6 and len(frame) >= t + 20:   # TCP
        sport, dport = struct.unpack(">HH", frame[t:t + 4])
        thl = ((frame[t + 12] >> 4) & 0xf) * 4
        return ("TCP", src, sport, dst, dport, frame[t + thl:])
    return None


def udp_payload(linktype, frame):
    """(dport, payload) pour un datagramme UDP IPv4, sinon None (raccourci)."""
    r = parse(linktype, frame)
    if r and r[0] == "UDP":
        return (r[4], r[5])
    return None
