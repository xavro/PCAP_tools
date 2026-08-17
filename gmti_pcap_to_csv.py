#!/usr/bin/env python3
"""Décodage GMTI STANAG 4607 depuis un pcap/pcapng -> CSV de plots MTI.

Ferme la boucle d'évaluation d'algorithme SANS passer par GeoEvent :

    pcap  --(ce script)-->  plots.csv  --(prototype_tracker_gmti_v8.1/demo.py)-->  pistes

Émet exactement le CSV attendu par `tools/prototype_tracker_gmti_v8.1/demo.py`
(délimiteur ';', une ligne par target report) :

  dwell_time_ms;revisit_idx;dwell_idx;lat;lon;vel_los_cms;snr_db;classification;
  sig_range_cm;sig_xrange_dm;sig_rvel_cms;sensor_lat;sensor_lon

Décodage PILOTÉ PAR LE MASQUE d'existence (offsets dynamiques), aligné sur le
parser Java Gmti4607Parser (mêmes tailles de champ). Lit pcap classique (LE/BE,
µs/ns) et pcapng, en streaming (lecteur commun `pcap_frames`). Bibliothèque
standard uniquement.

Hypothèses / limites :
  - Un datagramme UDP peut porter UN ou PLUSIEURS paquets 4607 concaténés
    (decode_packet_rows les enchaîne). looks_like_4607 valide le 1er paquet.
  - Les payloads du port GMTI non reconnus 4607 sont COMPTÉS et signalés en fin
    d'export (rend visible une fragmentation/format inattendu d'un futur vecteur).
  - La FRAGMENTATION IP n'est pas réassemblée (cf. pcap_frames) : un paquet 4607
    éclaté sur plusieurs paquets IP ne serait pas reconstitué.

Usage :
  # auto-détection du port GMTI, écrit plots.csv
  python gmti_pcap_to_csv.py ../DATA/Captures/20260812_CaptureALL_CR2.pcap -o plots.csv

  # port explicite (ex. 5454 pré-prod, 27551 labo volCAE)
  python gmti_pcap_to_csv.py capture.pcap --port 5454 -o plots.csv

  # puis :
  python prototype_tracker_gmti_v8.1/demo.py plots.csv
"""
from __future__ import annotations

import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_frames import iter_frames, udp_payload  # noqa: E402  (lecteur commun pcap/pcapng)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Lecture pcap/pcapng : lecteur commun `pcap_frames` (importé en tête).
# --------------------------------------------------------------------------
# Décodage STANAG 4607 — tailles de champ alignées sur Gmti4607Parser (bits 0..47)
# --------------------------------------------------------------------------

FIELD_SIZE = [
    2, 2, 1, 2, 4, 4, 4, 4,   # 0 Revisit,1 DwellIdx,2 Last,3 TRC,4 DwellTime,5 SLat,6 SLon,7 SAlt
    4, 4, 4, 4, 2, 2, 4, 1,   # 8 ScaleLat,9 ScaleLon,10 SPUAlong,11 SPUCross,12 SPUAlt,13 Track,14 Speed,15 VVel
    1, 2, 2, 2, 2, 2, 4, 4,   # 16 TrkUnc,17 SpdUnc,18 VVelUnc,19 PlatHdg,20 PlatPitch,21 PlatRoll,22 CenterLat,23 CenterLon
    2, 2, 2, 2, 2, 1,         # 24 RangeHE,25 AngleHE,26 SensHdg,27 SensPitch,28 SensRoll,29 MDV
    2, 4, 4, 2, 2, 2, 2, 2,   # 30 MTIidx,31 LatHi,32 LonHi,33 DeltaLat,34 DeltaLon,35 Height,36 VelLOS,37 WrapVel
    1, 1, 1, 2, 2, 1, 2, 1,   # 38 SNR,39 Class,40 ClassProb,41 SlantUnc,42 CrossUnc,43 HeightUnc,44 RadVelUnc,45 TruthApp
    4, 1                      # 46 TruthEntity,47 RCS
]
PKT_HDR = 32
SEG_DWELL = 2
_2_31 = float(1 << 31)
_2_32 = float(1 << 32)
_2_15 = float(1 << 15)


def _u8(b, p): return b[p]
def _u16(b, p): return struct.unpack(">H", b[p:p + 2])[0]
def _u32(b, p): return struct.unpack(">I", b[p:p + 4])[0]
def _s8(b, p): return struct.unpack(">b", b[p:p + 1])[0]
def _s16(b, p): return struct.unpack(">h", b[p:p + 2])[0]
def _s32(b, p): return struct.unpack(">i", b[p:p + 4])[0]
def _sa32(b, p): return _s32(b, p) * (90.0 / _2_31)     # angle signé 32 bits (lat)
def _ba32(b, p): return _u32(b, p) * (360.0 / _2_32)    # angle binaire 32 bits (lon 0..360)
def _sa16(b, p): return _s16(b, p) * (90.0 / _2_15)


def _norm_lon(lon):
    """0..360 -> -180..180 (WGS84 standard)."""
    if lon is None:
        return None
    return lon - 360.0 if lon > 180.0 else lon


def _mask_bit(mask8, bit):
    """Bit du masque d'existence 8 octets, bit 0 = MSB du 1er octet."""
    return (mask8[bit // 8] >> (7 - (bit % 8))) & 1


def looks_like_4607(b):
    """Valide qu'un payload COMMENCE par un paquet 4607 plausible (en-tête ASCII +
    1er segment cohérent). N'exige plus `pkt_size == len(payload)` : un datagramme
    peut porter PLUSIEURS paquets 4607 concaténés (cf. decode_packet_rows)."""
    if len(b) < PKT_HDR + 5:
        return False
    try:
        pkt = _u32(b, 2)
        if not (PKT_HDR <= pkt <= len(b)):        # le 1er paquet tient dans le payload
            return False
        if not (all(32 <= c < 127 for c in b[0:2]) and all(32 <= c < 127 for c in b[6:8])):
            return False
        size = _u32(b, 33)
        return 5 <= size <= (pkt - PKT_HDR)
    except Exception:
        return False


def decode_packet_rows(b):
    """Décode le(s) paquet(s) 4607 d'un payload -> liste de dicts (un par target
    report). Enchaîne PLUSIEURS paquets 4607 concaténés dans le même datagramme
    (tant qu'un en-tête plausible suit : 2 caractères ASCII + taille cohérente)."""
    rows = []
    n = len(b)
    off = 0
    while off + PKT_HDR + 5 <= n:
        # En-tête plausible du paquet à `off` (version = 2 caractères ASCII).
        if not (32 <= b[off] < 127 and 32 <= b[off + 1] < 127):
            break
        try:
            pkt_size = _u32(b, off + 2)
        except Exception:
            break
        if pkt_size < PKT_HDR:
            break
        limit = min(off + pkt_size, n)
        idx = off + PKT_HDR
        try:
            while idx + 5 <= limit:
                seg_type = _u8(b, idx)
                seg_size = _u32(b, idx + 1)
                if seg_size < 5 or idx + seg_size > limit:
                    break
                if seg_type == SEG_DWELL:
                    rows.extend(_decode_dwell(b, idx))
                idx += seg_size
        except Exception:
            break
        off += pkt_size                          # paquet 4607 suivant éventuel
    return rows


def _decode_dwell(b, seg):
    return _decode_dwell_full(b, seg)[1]


def decode_packet_dwells(b):
    """Comme decode_packet_rows mais renvoie la liste des DWELLS :
    [{"time","revisit","dwell","sensor":(lat,lon,alt_m|None),"center":(lat,lon)|None,
      "range_he_km","angle_he_deg","rows":[…]}] — pour dessiner la zone balayée."""
    out = []
    n = len(b)
    off = 0
    while off + PKT_HDR + 5 <= n:
        if not (32 <= b[off] < 127 and 32 <= b[off + 1] < 127):
            break
        try:
            pkt_size = _u32(b, off + 2)
        except Exception:
            break
        if pkt_size < PKT_HDR:
            break
        limit = min(off + pkt_size, n)
        idx = off + PKT_HDR
        try:
            while idx + 5 <= limit:
                seg_type = _u8(b, idx)
                seg_size = _u32(b, idx + 1)
                if seg_size < 5 or idx + seg_size > limit:
                    break
                if seg_type == SEG_DWELL:
                    d, rows = _decode_dwell_full(b, idx)
                    out.append({"time": d["time"], "revisit": d["revisit"], "dwell": d["dwell"],
                                "sensor": (d["slat"], _norm_lon(d["slon"]) if d["slon"] is not None else None, d["salt"]),
                                "center": (d["clat"], _norm_lon(d["clon"])) if d["clat"] is not None and d["clon"] is not None else None,
                                "range_he_km": d["range_he"], "angle_he_deg": d["angle_he"], "rows": rows})
                idx += seg_size
        except Exception:
            break
        off += pkt_size
    return out


def _decode_dwell_full(b, seg):
    mask = b[seg + 5:seg + 13]
    p = seg + 13
    d = {"revisit": None, "dwell": None, "trc": 0, "time": None,
         "slat": None, "slon": None, "salt": None, "clat": None, "clon": None,
         "scale_lat": None, "scale_lon": None, "range_he": None, "angle_he": None}
    for bit in range(0, 30):
        if not _mask_bit(mask, bit):
            continue
        if bit == 0: d["revisit"] = _u16(b, p)
        elif bit == 1: d["dwell"] = _u16(b, p)
        elif bit == 3: d["trc"] = _u16(b, p)
        elif bit == 4: d["time"] = _u32(b, p)
        elif bit == 5: d["slat"] = _sa32(b, p)
        elif bit == 6: d["slon"] = _ba32(b, p)
        elif bit == 7: d["salt"] = _s32(b, p) / 100.0                 # cm -> m
        elif bit == 8: d["scale_lat"] = _sa32(b, p)
        elif bit == 9: d["scale_lon"] = _ba32(b, p)
        elif bit == 22: d["clat"] = _sa32(b, p)
        elif bit == 23: d["clon"] = _ba32(b, p)
        elif bit == 24: d["range_he"] = _u16(b, p) / 256.0             # B16 : km, 8 bits fractionnaires
        elif bit == 25: d["angle_he"] = _u16(b, p) * (360.0 / 65536.0)  # BA16 : degrés
        p += FIELD_SIZE[bit]

    rows = []
    for _ in range(d["trc"]):
        tr = {"lat": None, "lon": None, "dlat": None, "dlon": None,
              "vel_los": None, "snr": None, "cls": None,
              "sig_r": None, "sig_x": None, "sig_rv": None}
        for bit in range(30, 48):
            if not _mask_bit(mask, bit):
                continue
            if bit == 31: tr["lat"] = _sa32(b, p)
            elif bit == 32: tr["lon"] = _ba32(b, p)
            # D32.4/D32.5 : ENTIERS SIGNÉS 16 bits BRUTS (pas un angle) — le
            # standard les multiplie ensuite par les scale factors D10/D11.
            # (Correctif : _sa16 appliquait à tort ×90/2^15, faussant les
            # positions en mode delta. Vérifier le MÊME bug dans le parser Java
            # Gmti4607Parser du receiver GeoEvent, hors de ce dépôt.)
            elif bit == 33: tr["dlat"] = _s16(b, p)
            elif bit == 34: tr["dlon"] = _s16(b, p)
            elif bit == 36: tr["vel_los"] = _s16(b, p)     # cm/s (brut)
            elif bit == 38: tr["snr"] = _s8(b, p)
            elif bit == 39: tr["cls"] = _u8(b, p)
            elif bit == 41: tr["sig_r"] = _u16(b, p)       # cm
            elif bit == 42: tr["sig_x"] = _u16(b, p)       # dm
            elif bit == 44: tr["sig_rv"] = _u16(b, p)      # cm/s
            p += FIELD_SIZE[bit]
        # Position : hi-res prioritaire, sinon repli delta * scale + centre.
        lat, lon = tr["lat"], tr["lon"]
        if lat is None and tr["dlat"] is not None and d["scale_lat"] is not None and d["clat"] is not None:
            lat = tr["dlat"] * d["scale_lat"] + d["clat"]
            lon = tr["dlon"] * d["scale_lon"] + d["clon"]
        if lat is None or lon is None:
            continue
        rows.append({
            "dwell_time_ms": d["time"] if d["time"] is not None else 0,
            "revisit_idx": d["revisit"] if d["revisit"] is not None else 0,
            "dwell_idx": d["dwell"] if d["dwell"] is not None else 0,
            "lat": lat,
            "lon": _norm_lon(lon),
            "vel_los_cms": tr["vel_los"],
            "snr_db": tr["snr"],
            "classification": tr["cls"],
            "sig_range_cm": tr["sig_r"],
            "sig_xrange_dm": tr["sig_x"],
            "sig_rvel_cms": tr["sig_rv"],
            "sensor_lat": d["slat"],
            "sensor_lon": _norm_lon(d["slon"]),
        })
    return d, rows


# --------------------------------------------------------------------------
# Auto-détection du port GMTI
# --------------------------------------------------------------------------

def detect_gmti_port(path, sample=200000):
    """Port UDP dst où les payloads valident 4607 en majorité (ou None)."""
    ok = collections.Counter()
    tot = collections.Counter()
    n = 0
    for _ts, lt, frame in iter_frames(path):
        n += 1
        if n > sample:
            break
        r = udp_payload(lt, frame)
        if not r:
            continue
        dport, pl = r
        tot[dport] += 1
        if looks_like_4607(pl):
            ok[dport] += 1
    best, best_ratio = None, 0.0
    for port, c in ok.items():
        ratio = c / max(1, tot[port])
        if c >= 5 and ratio >= 0.8 and c > (ok[best] if best else 0):
            best, best_ratio = port, ratio
    return best


# --------------------------------------------------------------------------

CSV_COLS = ["dwell_time_ms", "revisit_idx", "dwell_idx", "lat", "lon",
            "vel_los_cms", "snr_db", "classification", "sig_range_cm",
            "sig_xrange_dm", "sig_rvel_cms", "sensor_lat", "sensor_lon"]


def _fmt(v):
    if v is None:
        return ""
    if isinstance(v, float):
        return "%.7f" % v
    return str(v)


def export(path, out_path, port, limit=0):
    if port is None:
        print("Auto-détection du port GMTI…")
        port = detect_gmti_port(path)
        if port is None:
            print("Aucun flux GMTI 4607 détecté dans la capture.", file=sys.stderr)
            return 1
        print("Port GMTI détecté : UDP %d" % port)

    n_pkt = n_rows = n_rejected = 0
    dwells = set()
    n = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        f.write(";".join(CSV_COLS) + "\n")
        for _ts, lt, frame in iter_frames(path):
            n += 1
            if limit and n > limit:
                break
            r = udp_payload(lt, frame)
            if not r:
                continue
            dport, pl = r
            if dport != port:
                continue
            if not looks_like_4607(pl):
                n_rejected += 1          # payload du port GMTI non reconnu 4607
                continue
            n_pkt += 1
            for row in decode_packet_rows(pl):
                dwells.add((row["revisit_idx"], row["dwell_idx"]))
                f.write(";".join(_fmt(row[c]) for c in CSV_COLS) + "\n")
                n_rows += 1

    print("%d paquets GMTI décodés (port %d) -> %d plots MTI, %d dwells distincts"
          % (n_pkt, port, n_rows, len(dwells)))
    if n_rejected:
        # Rend visible une éventuelle fragmentation/format inattendu du vecteur.
        print("ATTENTION : %d payload(s) du port %d rejeté(s) (non reconnus 4607)"
              % (n_rejected, port))
    print("-> %s" % out_path)
    print("Évaluer l'algo : python prototype_tracker_gmti_v8.1/demo.py %s" % out_path)
    return 0


def selftest():
    """Vérifie le décodage en MODE DELTA (bits 33/34 = entiers signés bruts
    multipliés par les scale factors, PAS un angle). Sans ce correctif, _sa16
    faussait la position."""
    def e_sa32(deg): return int(round(deg / (90.0 / _2_31)))
    def e_ba32(deg): return int(round((deg % 360) / (360.0 / _2_32)))
    present = [0, 1, 3, 4, 5, 6, 8, 9, 22, 23, 33, 34]   # header + delta (pas 31/32)
    mask = 0
    for bit in present:
        mask |= 1 << (63 - bit)
    scale_lat, scale_lon, clat, clon = 0.0001, 0.0002, 46.5, 3.4
    dlat_raw, dlon_raw = 1000, 500                        # entiers bruts
    seg_body = mask.to_bytes(8, "big")
    seg_body += struct.pack(">H", 7) + struct.pack(">H", 2) + struct.pack(">H", 1)  # revisit,dwell,trc
    seg_body += struct.pack(">I", 123456)                 # dwell_time_ms
    seg_body += struct.pack(">i", e_sa32(46.6)) + struct.pack(">I", e_ba32(3.5))    # slat/slon
    seg_body += struct.pack(">i", e_sa32(scale_lat)) + struct.pack(">I", e_ba32(scale_lon))
    seg_body += struct.pack(">i", e_sa32(clat)) + struct.pack(">I", e_ba32(clon))
    seg_body += struct.pack(">h", dlat_raw) + struct.pack(">h", dlon_raw)           # delta bruts
    seg = struct.pack(">B", SEG_DWELL) + struct.pack(">I", len(seg_body) + 5) + seg_body
    rows = _decode_dwell(seg, 0)
    assert len(rows) == 1, rows
    lat, lon = rows[0]["lat"], rows[0]["lon"]
    exp_lat = clat + dlat_raw * (e_sa32(scale_lat) * (90.0 / _2_31))
    exp_lon = clon + dlon_raw * (e_ba32(scale_lon) * (360.0 / _2_32))
    assert abs(lat - exp_lat) < 1e-5 and abs(lon - exp_lon) < 1e-5, (lat, lon, exp_lat, exp_lon)
    assert abs(lat - 46.6) < 1e-4 and abs(lon - 3.5) < 1e-4, (lat, lon)
    # Contrôle anti-régression : l'ancien bug (_sa16) donnerait lat ≈ 46.5003.
    assert abs(lat - 46.5003) > 1e-2
    print("selftest OK — mode delta décodé correctement : lat=%.6f lon=%.6f" % (lat, lon))
    return 0


def main(argv=None):
    if "--selftest" in (argv if argv is not None else sys.argv[1:]):
        return selftest()
    ap = argparse.ArgumentParser(description="Décodage GMTI 4607 pcap -> CSV de plots (pour le tracker)")
    ap.add_argument("pcap", help="fichier .pcap ou .pcapng")
    ap.add_argument("-o", "--out", default="plots.csv", help="CSV de sortie (défaut plots.csv)")
    ap.add_argument("--port", type=int, default=None,
                    help="port UDP GMTI (défaut : auto-détection ; 27551 labo, 5454 pré-prod)")
    ap.add_argument("--limit", type=int, default=0, help="n'analyser que les N premiers paquets")
    ap.add_argument("--selftest", action="store_true", help="test unitaire (mode delta) et sortir")
    args = ap.parse_args(argv)
    return export(args.pcap, args.out, args.port, args.limit)


if __name__ == "__main__":
    sys.exit(main())
