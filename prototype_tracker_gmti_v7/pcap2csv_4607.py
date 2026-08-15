# -*- coding: utf-8 -*-
"""
pcap2csv_4607.py — extrait les plots MTI d'une capture pcap contenant du
STANAG 4607 et produit le CSV du prototype tracker, enrichi des champs hauteur
(D32.6 Target Geodetic Height, D32.14 Height Uncertainty).

  python3 pcap2csv_4607.py capture.pcap plots.csv [--port 1234]
  python3 pcap2csv_4607.py --selftest

Pur Python, aucune dependance. Format pcap classique uniquement (un .pcapng
Wireshark se convertit avec :  editcap -F pcap in.pcapng out.pcap).
Le flux 4609 (MPEG-TS, octets 0x47) present dans la meme capture est ignore.

VALIDATION OBLIGATOIRE avant confiance : lancer sur un pcap deja passe dans
votre receiver GeoEvent et comparer lat/lon/vel de quelques plots avec le CSV
du receiver — cela detecte immediatement toute erreur de facteur de conversion.
"""
import csv
import struct
import sys

# ----------------------------------------------------------------------
# Conversions AEDP-7 (schema coherent pleine echelle ; cf. VALIDATION ci-dessus)
# ----------------------------------------------------------------------
def sa32(raw):  return raw * (90.0 / 2**31)      # angle signe ±90
def ba32(raw):  return raw * (360.0 / 2**32)     # angle 0..360
def sa16(raw):  return raw * (90.0 / 2**15)
def ba16(raw):  return raw * (360.0 / 2**16)
def lon_pm180(v): return v - 360.0 if v > 180.0 else v

# ----------------------------------------------------------------------
# Dwell Segment (type 2) : champs dans l'ordre du standard.
# (nom, format struct big-endian, conversion) — l'existence mask (8 octets en
# tete, bit de poids fort = D2) dit lesquels sont presents.
# ----------------------------------------------------------------------
DWELL_FIELDS = [
    ("revisit_idx",   ">H", None),          # D2
    ("dwell_idx",     ">H", None),          # D3
    ("last_dwell",    ">B", None),          # D4
    ("target_count",  ">H", None),          # D5
    ("dwell_time_ms", ">I", None),          # D6
    ("sensor_lat",    ">i", sa32),          # D7
    ("sensor_lon",    ">I", ba32),          # D8
    ("sensor_alt_cm", ">i", None),          # D9
    ("lat_scale",     ">i", sa32),          # D10
    ("lon_scale",     ">I", ba32),          # D11
    ("spu_along_cm",  ">I", None),          # D12
    ("spu_cross_cm",  ">I", None),          # D13
    ("spu_alt_cm",    ">H", None),          # D14
    ("sensor_track",  ">H", ba16),          # D15
    ("sensor_speed",  ">I", None),          # D16
    ("sensor_vvel",   ">b", None),          # D17
    ("track_unc",     ">B", None),          # D18
    ("speed_unc",     ">H", None),          # D19
    ("vvel_unc",      ">H", None),          # D20
    ("plat_heading",  ">H", ba16),          # D21
    ("plat_pitch",    ">h", sa16),          # D22
    ("plat_roll",     ">h", sa16),          # D23
    ("center_lat",    ">i", sa32),          # D24
    ("center_lon",    ">I", ba32),          # D25
    ("range_he",      ">H", None),          # D26 (B16, km — /128 si besoin)
    ("angle_he",      ">H", ba16),          # D27
    ("sensor_head",   ">H", ba16),          # D28
    ("sensor_pitch",  ">h", sa16),          # D29
    ("sensor_roll",   ">h", sa16),          # D30
    ("mdv",           ">B", None),          # D31
]
TGT_FIELDS = [
    ("report_idx",    ">H", None),          # D32.1
    ("hr_lat",        ">i", sa32),          # D32.2
    ("hr_lon",        ">I", ba32),          # D32.3
    ("delta_lat",     ">h", None),          # D32.4
    ("delta_lon",     ">h", None),          # D32.5
    ("height_m",      ">h", None),          # D32.6  <- HAUTEUR (WGS-84)
    ("vel_los_cms",   ">h", None),          # D32.7
    ("wrap_vel",      ">H", None),          # D32.8
    ("snr_db",        ">b", None),          # D32.9
    ("classification",">B", None),          # D32.10
    ("class_prob",    ">B", None),          # D32.11
    ("sig_range_cm",  ">H", None),          # D32.12
    ("sig_xrange_dm", ">H", None),          # D32.13
    ("sig_height_m",  ">B", None),          # D32.14 <- INCERTITUDE HAUTEUR
    ("sig_rvel_cms",  ">H", None),          # D32.15
    ("truth_app",     ">B", None),          # D32.16
    ("truth_ent",     ">I", None),          # D32.17
    ("rcs",           ">b", None),          # D32.18
]

def parse_dwell(payload):
    """Retourne (dwell_dict, [target_dicts]) ou None si segment inexploitable."""
    if len(payload) < 8:
        return None
    mask = int.from_bytes(payload[0:8], "big")
    off = 8
    bit = 0
    def present(b): return (mask >> (63 - b)) & 1

    dwell = {}
    for name, fmt, conv in DWELL_FIELDS:
        if present(bit):
            size = struct.calcsize(fmt)
            (raw,) = struct.unpack_from(fmt, payload, off)
            dwell[name] = conv(raw) if conv else raw
            off += size
        bit += 1

    targets = []
    for _ in range(dwell.get("target_count", 0)):
        tgt, b = {}, bit
        for name, fmt, conv in TGT_FIELDS:
            if present(b):
                size = struct.calcsize(fmt)
                (raw,) = struct.unpack_from(fmt, payload, off)
                tgt[name] = conv(raw) if conv else raw
                off += size
            b += 1
        targets.append(tgt)
    return dwell, targets

def target_latlon(dwell, tgt):
    if "hr_lat" in tgt and "hr_lon" in tgt:
        return tgt["hr_lat"], lon_pm180(tgt["hr_lon"])
    if "delta_lat" in tgt and "delta_lon" in tgt and "center_lat" in dwell and "center_lon" in dwell:
        lat = dwell["center_lat"] + tgt["delta_lat"] * dwell.get("lat_scale", 0)
        lon = dwell["center_lon"] + tgt["delta_lon"] * dwell.get("lon_scale", 0)
        return lat, lon_pm180(lon)
    return None

# ----------------------------------------------------------------------
# Flux 4607 : paquets (en-tete 32 octets) -> segments (en-tete 5 octets)
# ----------------------------------------------------------------------
def parse_4607_stream(buf, rows):
    off, stats = 0, {"packets": 0, "dwells": 0, "resync": 0}
    n = len(buf)
    while off + 32 <= n:
        v0, v1 = buf[off], buf[off + 1]
        size = int.from_bytes(buf[off + 2:off + 6], "big")
        plausible = (0x30 <= v0 <= 0x39 and 0x30 <= v1 <= 0x39 and 32 <= size <= 1_000_000)
        if not plausible:
            off += 1
            stats["resync"] += 1
            continue
        if off + size > n:
            break                                # paquet incomplet en fin de capture
        stats["packets"] += 1
        seg_off = off + 32
        end = off + size
        while seg_off + 5 <= end:
            seg_type = buf[seg_off]
            seg_size = int.from_bytes(buf[seg_off + 1:seg_off + 5], "big")
            if seg_size < 5 or seg_off + seg_size > end:
                break
            if seg_type == 2:                    # Dwell Segment
                out = parse_dwell(buf[seg_off + 5:seg_off + seg_size])
                if out:
                    dwell, targets = out
                    stats["dwells"] += 1
                    for tgt in targets:
                        ll = target_latlon(dwell, tgt)
                        if ll is None:
                            continue
                        rows.append({
                            "dwell_time_ms": dwell.get("dwell_time_ms", ""),
                            "revisit_idx":   dwell.get("revisit_idx", ""),
                            "dwell_idx":     dwell.get("dwell_idx", ""),
                            "lat": f"{ll[0]:.7f}", "lon": f"{ll[1]:.7f}",
                            "vel_los_cms":   tgt.get("vel_los_cms", ""),
                            "snr_db":        tgt.get("snr_db", ""),
                            "classification": tgt.get("classification", ""),
                            "sig_range_cm":  tgt.get("sig_range_cm", ""),
                            "sig_xrange_dm": tgt.get("sig_xrange_dm", ""),
                            "sig_rvel_cms":  tgt.get("sig_rvel_cms", ""),
                            "sensor_lat": f"{dwell.get('sensor_lat', ''):.7f}"
                                          if "sensor_lat" in dwell else "",
                            "sensor_lon": f"{lon_pm180(dwell['sensor_lon']):.7f}"
                                          if "sensor_lon" in dwell else "",
                            "target_height_m": tgt.get("height_m", ""),
                            "sig_height_m":    tgt.get("sig_height_m", ""),
                        })
            seg_off += seg_size
        off += size
    return stats

# ----------------------------------------------------------------------
# Lecture pcap classique + extraction des payloads UDP par flux
# ----------------------------------------------------------------------
def udp_streams(path, port=None):
    data = open(path, "rb").read()
    magic = data[0:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        sys.exit("Fichier pcapng : convertir d'abord avec  editcap -F pcap in.pcapng out.pcap")
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        sys.exit("Format pcap non reconnu")
    off, n = 24, len(data)
    streams = {}
    while off + 16 <= n:
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < 34:
            continue
        eth = 12
        etype = int.from_bytes(pkt[eth:eth + 2], "big")
        if etype == 0x8100:                       # VLAN
            eth += 4
            etype = int.from_bytes(pkt[eth:eth + 2], "big")
        if etype != 0x0800:                       # IPv4 uniquement
            continue
        ip = eth + 2
        ihl = (pkt[ip] & 0x0F) * 4
        if pkt[ip + 9] != 17:                     # UDP
            continue
        udp = ip + ihl
        sport, dport, ulen = struct.unpack(">HHH", pkt[udp:udp + 6])
        if port and port not in (sport, dport):
            continue
        payload = pkt[udp + 8: udp + ulen]
        key = (pkt[ip + 12:ip + 16], pkt[ip + 16:ip + 20], sport, dport)
        streams.setdefault(key, bytearray()).extend(payload)
    return streams

def looks_4607(buf):
    return len(buf) >= 6 and 0x30 <= buf[0] <= 0x39 and 0x30 <= buf[1] <= 0x39

def looks_4609(buf):
    return len(buf) >= 1 and buf[0] == 0x47      # sync MPEG-TS

COLS = ["dwell_time_ms", "revisit_idx", "dwell_idx", "lat", "lon", "vel_los_cms",
        "snr_db", "classification", "sig_range_cm", "sig_xrange_dm", "sig_rvel_cms",
        "sensor_lat", "sensor_lon", "target_height_m", "sig_height_m"]

def main(pcap_path, csv_path, port=None):
    rows = []
    for key, buf in udp_streams(pcap_path, port).items():
        tag = f"{'.'.join(map(str, key[0]))}:{key[2]} -> {'.'.join(map(str, key[1]))}:{key[3]}"
        if looks_4609(buf):
            print(f"  flux {tag} : MPEG-TS/4609 ({len(buf)} o) — ignore")
            continue
        if not looks_4607(buf):
            print(f"  flux {tag} : non reconnu ({len(buf)} o) — ignore")
            continue
        stats = parse_4607_stream(bytes(buf), rows)
        print(f"  flux {tag} : 4607 — {stats['packets']} paquets, "
              f"{stats['dwells']} dwells, resync {stats['resync']} o")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, delimiter=";")
        w.writeheader()
        w.writerows(rows)
    n_h = sum(1 for r in rows if r["target_height_m"] != "")
    print(f"\n{len(rows)} plots -> {csv_path}")
    print(f"hauteur renseignee : {n_h}/{len(rows)} plots"
          + ("" if not n_h else " — champ D32.6 actif !"))
    if n_h:
        hs = sorted(float(r["target_height_m"]) for r in rows if r["target_height_m"] != "")
        print(f"hauteurs (m, WGS-84) : min {hs[0]:.0f} / med {hs[len(hs)//2]:.0f} / max {hs[-1]:.0f}")

# ----------------------------------------------------------------------
# Autotest : construit un paquet 4607 synthetique, le parse, verifie.
# ----------------------------------------------------------------------
def selftest():
    def enc_sa32(deg): return int(round(deg / (90.0 / 2**31)))
    def enc_ba32(deg): return int(round((deg % 360) / (360.0 / 2**32)))
    # existence mask : D2,D3,D5,D6,D7,D8,D24,D25 + D32.2,3,6,7,9,10,12,13,14,15
    bits_dwell = [0, 1, 3, 4, 5, 6, 22, 23]
    bits_tgt = [29 + i for i in (2, 3, 6, 7, 9, 10, 12, 13, 14, 15)]
    mask = 0
    for b in bits_dwell + bits_tgt:
        mask |= 1 << (63 - b)
    body = mask.to_bytes(8, "big")
    body += struct.pack(">H", 424) + struct.pack(">H", 2)          # D2, D3
    body += struct.pack(">H", 1) + struct.pack(">I", 42739324)     # D5, D6
    body += struct.pack(">i", enc_sa32(35.7070767))                # D7
    body += struct.pack(">I", enc_ba32(16.9375327))                # D8
    body += struct.pack(">i", enc_sa32(35.62)) + struct.pack(">I", enc_ba32(16.90))  # D24, D25
    body += struct.pack(">i", enc_sa32(35.6245687))                # D32.2
    body += struct.pack(">I", enc_ba32(16.8998668))                # D32.3
    body += struct.pack(">h", 123)                                 # D32.6 hauteur
    body += struct.pack(">h", -599)                                # D32.7
    body += struct.pack(">b", 27) + struct.pack(">B", 6)           # D32.9, .10
    body += struct.pack(">H", 10105) + struct.pack(">H", 788)      # D32.12, .13
    body += struct.pack(">B", 15) + struct.pack(">H", 45)          # D32.14, .15
    seg = bytes([2]) + struct.pack(">I", len(body) + 5) + body
    pkt = b"31" + struct.pack(">I", 32 + len(seg)) + b"\x00" * 26 + seg
    rows = []
    parse_4607_stream(pkt, rows)
    r = rows[0]
    assert abs(float(r["lat"]) - 35.6245687) < 1e-5, r["lat"]
    assert abs(float(r["lon"]) - 16.8998668) < 1e-5, r["lon"]
    assert r["vel_los_cms"] == -599 and r["classification"] == 6
    assert r["target_height_m"] == 123 and r["sig_height_m"] == 15
    assert r["sig_range_cm"] == 10105 and r["sig_xrange_dm"] == 788
    assert abs(float(r["sensor_lat"]) - 35.7070767) < 1e-5
    print("selftest OK — encode/decode coherent (lat, lon, vel, hauteur, incertitudes)")

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--selftest" in sys.argv:
        selftest()
    elif len(args) >= 2:
        port = None
        for a in sys.argv[1:]:
            if a.startswith("--port"):
                port = int(a.split("=")[1] if "=" in a else sys.argv[sys.argv.index(a) + 1])
        main(args[0], args[1], port)
    else:
        print(__doc__)
