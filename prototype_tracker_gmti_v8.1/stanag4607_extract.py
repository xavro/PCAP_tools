# -*- coding: utf-8 -*-
"""
stanag4607_extract.py — extracteur STANAG 4607 complet depuis une capture pcap.

Objectif : INVENTORIER tout ce que votre vecteur emet reellement — segments
presents, champs renseignes (via existence mask), plages de valeurs — pour
decider quelles metadonnees exploiter dans ISRBOX.

  python3 stanag4607_extract.py capture.pcap [--port N]
      [--csv plots.csv]          CSV plots pour le prototype tracker (+ hauteur)
      [--jsonl segments.jsonl]   dump JSON de chaque segment parse (exploration)
      [--rapport rapport.txt]    rapport d'inventaire (aussi affiche console)
  python3 stanag4607_extract.py --selftest

Pur Python, aucune dependance. pcap classique (pcapng : editcap -F pcap ...).
Segments entierement decodes : en-tete paquet, Mission (1), Dwell (2) complet
avec targets, Job Definition (5), Free Text (6), Test & Status (10),
Platform Location (13). Les autres (HRR 3, LRI 7, Group 8, Attached Target 9,
System-Specific 11, Processing History 12, Job Request/Ack 101/102) sont
comptes et dumpes en hexadecimal (structure a decoder si votre vecteur les emet).

VALIDATION : comparer quelques plots (lat/lon/vel) avec le CSV de votre
receiver GeoEvent sur le meme pcap avant d'exploiter les valeurs converties.
"""
import csv
import json
import os
import struct
import sys
from collections import Counter, defaultdict

# Lecteur pcap/pcapng COMMUN (au niveau racine de la suite d'outils).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pcap_frames import iter_frames, parse  # noqa: E402

# ---------------------------------------------------------------- conversions
def sa32(r): return r * (90.0 / 2**31)
def ba32(r): return r * (360.0 / 2**32)
def sa16(r): return r * (90.0 / 2**15)
def ba16(r): return r * (360.0 / 2**16)
def b16(r):  return r / 128.0                      # binaire 16 bits, 7 bits fractionnaires
def lon180(v): return v - 360.0 if v > 180.0 else v
def astr(b): return b.decode("ascii", "replace").strip("\x00 ")

CLASSIF_SECU = {1: "TOP SECRET", 2: "SECRET", 3: "CONFIDENTIAL",
                4: "RESTRICTED", 5: "UNCLASSIFIED"}
RADAR_MODE_GEN = {0: "Unspecified", 1: "MTI", 2: "HRR", 3: "UHRR",
                  4: "HUR", 5: "FTI"}
TGT_CLASSIF = {0: "No Info (Live)", 1: "Tracked Vehicle", 2: "Wheeled Vehicle",
               3: "Rotary Wing", 4: "Fixed Wing", 5: "Stationary Rotator",
               6: "Maritime", 7: "Beacon", 8: "Amphibious", 9: "Person",
               10: "Vehicle", 11: "Animal", 12: "Large Multi-Return Land",
               13: "Large Multi-Return Maritime", 126: "Other", 127: "Unknown"}

# ---------------------------------------------------------------- en-tete paquet
def parse_packet_header(b):
    return {
        "version": astr(b[0:2]),
        "packet_size": int.from_bytes(b[2:6], "big"),
        "nationality": astr(b[6:8]),
        "classification": CLASSIF_SECU.get(b[8], b[8]),
        "class_system": astr(b[9:11]),
        "class_code": int.from_bytes(b[11:13], "big"),
        "exercise_indicator": b[13],
        "platform_id": astr(b[14:24]),
        "mission_id": int.from_bytes(b[24:28], "big"),
        "job_id": int.from_bytes(b[28:32], "big"),
    }

# ---------------------------------------------------------------- Mission (1)
def parse_mission(p):
    return {
        "mission_plan": astr(p[0:12]), "flight_plan": astr(p[12:24]),
        "platform_type": p[24], "platform_config": astr(p[25:35]),
        "ref_year": int.from_bytes(p[35:37], "big"),
        "ref_month": p[37], "ref_day": p[38],
    }

# ---------------------------------------------------------------- Dwell (2)
DWELL_FIELDS = [
    ("revisit_idx", ">H", None), ("dwell_idx", ">H", None),
    ("last_dwell_of_revisit", ">B", None), ("target_count", ">H", None),
    ("dwell_time_ms", ">I", None),
    ("sensor_lat", ">i", sa32), ("sensor_lon", ">I", ba32),
    ("sensor_alt_cm", ">i", None),
    ("lat_scale", ">i", sa32), ("lon_scale", ">I", ba32),
    ("spu_along_cm", ">I", None), ("spu_cross_cm", ">I", None),
    ("spu_alt_cm", ">H", None),
    ("sensor_track_deg", ">H", ba16), ("sensor_speed_mms", ">I", None),
    ("sensor_vvel_dms", ">b", None),
    ("sensor_track_unc_deg", ">B", None), ("sensor_speed_unc_mms", ">H", None),
    ("sensor_vvel_unc_cms", ">H", None),
    ("plat_heading_deg", ">H", ba16), ("plat_pitch_deg", ">h", sa16),
    ("plat_roll_deg", ">h", sa16),
    ("dwell_center_lat", ">i", sa32), ("dwell_center_lon", ">I", ba32),
    ("dwell_range_he_km", ">H", b16), ("dwell_angle_he_deg", ">H", ba16),
    ("sensor_heading_deg", ">H", ba16), ("sensor_pitch_deg", ">h", sa16),
    ("sensor_roll_deg", ">h", sa16),
    ("mdv_dms", ">B", None),
]
TGT_FIELDS = [
    ("report_idx", ">H", None),
    ("hr_lat", ">i", sa32), ("hr_lon", ">I", ba32),
    ("delta_lat", ">h", None), ("delta_lon", ">h", None),
    ("height_m", ">h", None),
    ("vel_los_cms", ">h", None), ("wrap_vel_cms", ">H", None),
    ("snr_db", ">b", None),
    ("classification", ">B", None), ("class_prob_pct", ">B", None),
    ("sig_range_cm", ">H", None), ("sig_xrange_dm", ">H", None),
    ("sig_height_m", ">B", None), ("sig_rvel_cms", ">H", None),
    ("truth_tag_app", ">B", None), ("truth_tag_entity", ">I", None),
    ("rcs_half_db", ">b", None),
]

def parse_dwell(p, presence=None):
    if len(p) < 8:
        return None
    mask = int.from_bytes(p[0:8], "big")
    off, bit = 8, 0
    def has(b): return (mask >> (63 - b)) & 1
    dwell = {}
    for name, fmt, conv in DWELL_FIELDS:
        if has(bit):
            (raw,) = struct.unpack_from(fmt, p, off)
            dwell[name] = conv(raw) if conv else raw
            off += struct.calcsize(fmt)
            if presence is not None:
                presence["dwell"][name] += 1
        bit += 1
    targets = []
    for _ in range(dwell.get("target_count", 0)):
        tgt, b = {}, bit
        for name, fmt, conv in TGT_FIELDS:
            if has(b):
                (raw,) = struct.unpack_from(fmt, p, off)
                tgt[name] = conv(raw) if conv else raw
                off += struct.calcsize(fmt)
                if presence is not None:
                    presence["target"][name] += 1
            b += 1
        targets.append(tgt)
    dwell["targets"] = targets
    return dwell

# ---------------------------------------------------------------- Job Def (5)
def parse_jobdef(p):
    o = {}
    o["job_id"] = int.from_bytes(p[0:4], "big")
    o["sensor_id_type"] = p[4]
    o["sensor_id_model"] = astr(p[5:11])
    o["target_filtering_flag"] = p[11]
    o["priority"] = p[12]
    pts = []
    off = 13
    for _ in range(4):
        la = sa32(struct.unpack_from(">i", p, off)[0])
        lo = lon180(ba32(struct.unpack_from(">I", p, off + 4)[0]))
        pts.append([round(la, 7), round(lo, 7)])
        off += 8
    o["bounding_area"] = pts
    (mode, revisit, unc_along, unc_cross, unc_alt) = struct.unpack_from(">BHHHH", p, off)
    off += 9
    (unc_head, unc_speed, sr_std, xr_std, vlos_std) = struct.unpack_from(">BHHHH", p, off)
    off += 9
    (mdv, det_prob, fa_density, terrain_model, geoid_model) = struct.unpack_from(">BBBBB", p, off)
    o.update(radar_mode=mode, radar_mode_lib=RADAR_MODE_GEN.get(mode, f"mode {mode} (table AEDP-7)"),
             revisit_interval_ds=revisit,
             nom_unc_along_dm=unc_along, nom_unc_cross_dm=unc_cross, nom_unc_alt_dm=unc_alt,
             nom_unc_heading_deg=unc_head, nom_unc_speed_mms=unc_speed,
             nom_slant_range_std_cm=sr_std, nom_xrange_std_dm=xr_std,
             nom_vlos_std_cms=vlos_std, nom_mdv_dms=mdv,
             nom_detection_prob_pct=det_prob, nom_false_alarm_density=fa_density,
             terrain_model=terrain_model, geoid_model=geoid_model)
    return o

# ---------------------------------------------------------------- autres
def parse_freetext(p):
    return {"originator": astr(p[0:10]), "recipient": astr(p[10:20]),
            "text": astr(p[20:])}

def parse_test_status(p):
    jid, rev, dwl, t = struct.unpack_from(">IHHI", p, 0)
    hw, mode = p[12], p[13]
    return {"job_id": jid, "revisit_idx": rev, "dwell_idx": dwl,
            "dwell_time_ms": t,
            "hardware_status_bits": f"{hw:08b}", "mode_status_bits": f"{mode:08b}"}

def parse_platform_loc(p):
    t, la, lo, alt = struct.unpack_from(">IiIi", p, 0)
    trk, spd, vv = struct.unpack_from(">HIb", p, 16)
    return {"location_time_ms": t, "lat": sa32(la), "lon": lon180(ba32(lo)),
            "alt_cm": alt, "track_deg": ba16(trk), "speed_mms": spd,
            "vvel_dms": vv}

SEGMENTS = {
    1: ("Mission", parse_mission),
    2: ("Dwell", None),                    # traite a part (presence + plots)
    3: ("HRR", None),
    5: ("Job Definition", parse_jobdef),
    6: ("Free Text", parse_freetext),
    7: ("Low Reflectivity Index", None),
    8: ("Group", None),
    9: ("Attached Target", None),
    10: ("Test and Status", parse_test_status),
    11: ("System-Specific", None),
    12: ("Processing History", None),
    13: ("Platform Location", parse_platform_loc),
    101: ("Job Request", None),
    102: ("Job Acknowledge", None),
}

# ---------------------------------------------------------------- flux 4607
def parse_stream(buf, sink):
    off, n = 0, len(buf)
    while off + 32 <= n:
        if not (0x30 <= buf[off] <= 0x39 and 0x30 <= buf[off + 1] <= 0x39):
            off += 1
            sink.resync += 1
            continue
        size = int.from_bytes(buf[off + 2:off + 6], "big")
        if not (32 <= size <= 1_000_000) or off + size > n:
            off += 1
            sink.resync += 1
            continue
        hdr = parse_packet_header(buf[off:off + 32])
        sink.packet(hdr)
        so, end = off + 32, off + size
        while so + 5 <= end:
            st = buf[so]
            ss = int.from_bytes(buf[so + 1:so + 5], "big")
            if ss < 5 or so + ss > end:
                break
            sink.segment(st, buf[so + 5:so + ss], hdr)
            so += ss
        off += size

# ---------------------------------------------------------------- collecte
class Sink:
    def __init__(self, jsonl_path=None):
        self.resync = 0
        self.pkt_count = 0
        self.pkt_meta = defaultdict(Counter)
        self.seg_count = Counter()
        self.presence = {"dwell": Counter(), "target": Counter()}
        self.dwell_count = 0
        self.plots = []
        self.num_stats = defaultdict(list)
        self.jobdefs, self.missions, self.freetexts = [], [], []
        self.platloc_count = 0
        self.platlocs = []          # positions porteur (lat, lon) — overlay/tracé
        self.unknown_samples = {}
        self.jsonl = open(jsonl_path, "w") if jsonl_path else None

    def packet(self, hdr):
        self.pkt_count += 1
        for k in ("version", "nationality", "classification", "platform_id",
                  "mission_id", "job_id", "exercise_indicator"):
            self.pkt_meta[k][hdr[k]] += 1

    def _emit(self, kind, data, hdr):
        if self.jsonl:
            self.jsonl.write(json.dumps(
                {"segment": kind, "job_id": hdr["job_id"], "data": data},
                ensure_ascii=False, default=str) + "\n")

    def segment(self, st, payload, hdr):
        name = SEGMENTS.get(st, (f"type {st}", None))[0]
        self.seg_count[name] += 1
        if st == 2:
            d = parse_dwell(payload, self.presence)
            if not d:
                return
            self.dwell_count += 1
            for tgt in d["targets"]:
                for k in ("height_m", "sig_height_m", "snr_db", "wrap_vel_cms",
                          "class_prob_pct", "rcs_half_db", "vel_los_cms",
                          "sig_range_cm", "sig_xrange_dm", "sig_rvel_cms"):
                    if k in tgt:
                        self.num_stats[k].append(tgt[k])
                ll = self._latlon(d, tgt)
                if ll:
                    self.plots.append((d, tgt, ll))
            for k in ("mdv_dms", "dwell_range_he_km", "dwell_angle_he_deg"):
                if k in d:
                    self.num_stats[k].append(d[k])
            self._emit("Dwell", {k: v for k, v in d.items() if k != "targets"}
                       | {"n_targets": len(d["targets"])}, hdr)
        elif SEGMENTS.get(st, (None, None))[1]:
            data = SEGMENTS[st][1](payload)
            self._emit(name, data, hdr)
            if st == 5 and data not in self.jobdefs:
                self.jobdefs.append(data)
            elif st == 1 and data not in self.missions:
                self.missions.append(data)
            elif st == 6:
                self.freetexts.append(data)
            elif st == 13:
                self.platloc_count += 1
                if "lat" in data and "lon" in data:
                    self.platlocs.append((data["lat"], data["lon"]))
        else:
            self.unknown_samples.setdefault(name, payload[:64].hex())
            self._emit(name, {"taille": len(payload),
                              "hex_debut": payload[:64].hex()}, hdr)

    @staticmethod
    def _latlon(d, tgt):
        if "hr_lat" in tgt and "hr_lon" in tgt:
            return tgt["hr_lat"], lon180(tgt["hr_lon"])
        if all(k in tgt for k in ("delta_lat", "delta_lon")) and \
           all(k in d for k in ("dwell_center_lat", "dwell_center_lon")):
            return (d["dwell_center_lat"] + tgt["delta_lat"] * d.get("lat_scale", 0),
                    lon180(d["dwell_center_lon"] + tgt["delta_lon"] * d.get("lon_scale", 0)))
        return None

# ---------------------------------------------------------------- rapport
def med(v): s = sorted(v); return s[len(s) // 2]

def rapport(s):
    L = []
    A = L.append
    A("=" * 68)
    A("INVENTAIRE STANAG 4607")
    A("=" * 68)
    A(f"paquets : {s.pkt_count} | octets resynchronises : {s.resync}")
    A("")
    A("-- En-tete paquet --")
    for k, c in s.pkt_meta.items():
        vals = ", ".join(f"{v} (x{n})" for v, n in c.most_common(6))
        A(f"  {k:22s}: {vals}")
    A("")
    A("-- Segments recus --")
    for name, n in s.seg_count.most_common():
        A(f"  {name:28s}: {n}")
    for name, hx in s.unknown_samples.items():
        A(f"    > {name} non decode, debut hex : {hx[:48]}...")
    A("")
    A(f"-- Dwell Segment ({s.dwell_count}) : presence des champs --")
    for name, _, _ in DWELL_FIELDS:
        n = s.presence['dwell'][name]
        if n:
            A(f"  {name:26s}: {100 * n // max(s.dwell_count, 1):3d} %")
    absents = [f for f, _, _ in DWELL_FIELDS if not s.presence['dwell'][f]]
    if absents:
        A(f"  ABSENTS : {', '.join(absents)}")
    A("")
    n_tgt = len(s.plots) or 1
    A(f"-- Target reports ({len(s.plots)} plots) : presence des champs --")
    for name, _, _ in TGT_FIELDS:
        n = s.presence['target'][name]
        if n:
            A(f"  {name:26s}: {100 * n // n_tgt:3d} %")
    absents = [f for f, _, _ in TGT_FIELDS if not s.presence['target'][f]]
    if absents:
        A(f"  ABSENTS : {', '.join(absents)}")
    A("")
    A("-- Plages de valeurs (min / mediane / max) --")
    for k, v in sorted(s.num_stats.items()):
        A(f"  {k:26s}: {min(v):>9.7g} / {med(v):>9.7g} / {max(v):>9.7g}   (n={len(v)})")
    cls = Counter(t.get("classification") for _, t, _ in s.plots)
    A("")
    A("-- Classifications cibles --")
    for c, n in cls.most_common():
        A(f"  {c} = {TGT_CLASSIF.get(c if (c or 0) < 128 else c - 128, '?')}"
          f"{' [SIMULE]' if (c or 0) >= 128 else ''} : {n}")
    if s.jobdefs:
        A("")
        A(f"-- Job Definition ({len(s.jobdefs)} unique(s)) --")
        for j in s.jobdefs:
            A("  " + json.dumps(j, ensure_ascii=False))
    if s.missions:
        A("")
        A(f"-- Mission ({len(s.missions)} unique(s)) --")
        for m in s.missions:
            A("  " + json.dumps(m, ensure_ascii=False))
    if s.freetexts:
        A("")
        A(f"-- Free Text ({len(s.freetexts)}) --")
        for t in s.freetexts[:10]:
            A("  " + json.dumps(t, ensure_ascii=False))
    if s.platloc_count:
        A("")
        A(f"-- Platform Location : {s.platloc_count} positions porteur --")
    return "\n".join(L)

# ---------------------------------------------------------------- CSV plots
CSV_COLS = ["dwell_time_ms", "revisit_idx", "dwell_idx", "lat", "lon",
            "vel_los_cms", "snr_db", "classification", "sig_range_cm",
            "sig_xrange_dm", "sig_rvel_cms", "sensor_lat", "sensor_lon",
            "target_height_m", "sig_height_m"]

def write_csv(s, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(CSV_COLS)
        for d, t, (la, lo) in s.plots:
            w.writerow([d.get("dwell_time_ms", ""), d.get("revisit_idx", ""),
                        d.get("dwell_idx", ""), f"{la:.7f}", f"{lo:.7f}",
                        t.get("vel_los_cms", ""), t.get("snr_db", ""),
                        t.get("classification", ""), t.get("sig_range_cm", ""),
                        t.get("sig_xrange_dm", ""), t.get("sig_rvel_cms", ""),
                        f"{d['sensor_lat']:.7f}" if "sensor_lat" in d else "",
                        f"{lon180(d['sensor_lon']):.7f}" if "sensor_lon" in d else "",
                        t.get("height_m", ""), t.get("sig_height_m", "")])

# ---------------------------------------------------------------- pcap
# Conservée pour compat (l'API extract() catch ValueError) ; plus levée depuis
# que le lecteur commun `pcap_frames` gère nativement le pcapng.
class PcapngError(ValueError):
    """(obsolète) pcapng désormais supporté nativement."""


def udp_streams(path, port=None):
    """Réassemble les payloads UDP par flux (src,sport,dst,dport). Lecture via le
    lecteur commun `pcap_frames` (pcap ET pcapng, streaming ; conserve le
    réassemblage par flux, propre à l'extracteur 4607)."""
    streams = {}
    for _ts, lt, frame in iter_frames(path):
        r = parse(lt, frame)
        if not r or r[0] != "UDP":
            continue
        _proto, src, sport, dst, dport, pl = r
        if port and port not in (sport, dport):
            continue
        streams.setdefault((src, sport, dst, dport), bytearray()).extend(pl)
    return streams

# ---------------------------------------------------------------- API importable
def extract(path, port=None, jsonl_path=None):
    """Parse un pcap 4607 -> Sink peuplé (plots, inventaire, job defs, porteur…).
    Réutilisable (GUI/tests). Lève PcapngError sur pcapng. Ignore les flux non-4607."""
    sink = Sink(jsonl_path=jsonl_path)
    for key, buf in udp_streams(path, port).items():
        if buf[:1] == b"\x47":                       # MPEG-TS/4609 : ignoré
            continue
        if not (len(buf) > 6 and 0x30 <= buf[0] <= 0x39 and 0x30 <= buf[1] <= 0x39):
            continue
        parse_stream(bytes(buf), sink)
    if sink.jsonl:
        sink.jsonl.close()
        sink.jsonl = None
    return sink


# ---------------------------------------------------------------- selftest
def selftest():
    def e_sa32(d): return int(round(d / (90.0 / 2**31)))
    def e_ba32(d): return int(round((d % 360) / (360.0 / 2**32)))
    segs = b""
    # Mission
    m = b"PLAN-ALPHA  " + b"VOL-01      " + bytes([9]) + b"CONFIG-A  " + struct.pack(">HBB", 2026, 8, 15)
    segs += bytes([1]) + struct.pack(">I", len(m) + 5) + m
    # Job Definition
    j = struct.pack(">I", 77) + bytes([12]) + b"RADAR1" + bytes([0, 1])
    for la, lo in [(35.7, 16.8), (35.7, 17.0), (35.5, 17.0), (35.5, 16.8)]:
        j += struct.pack(">i", e_sa32(la)) + struct.pack(">I", e_ba32(lo))
    j += struct.pack(">BHHHH", 1, 20, 10, 10, 10) + struct.pack(">BHHHH", 5, 100, 100, 50, 25)
    j += struct.pack(">BBBBB", 20, 90, 2, 1, 1)
    segs += bytes([5]) + struct.pack(">I", len(j) + 5) + j
    # Dwell (1 target avec hauteur)
    bits = [0, 1, 3, 4, 5, 6, 22, 23] + [29 + i for i in (2, 3, 6, 7, 9, 10, 12, 13, 14, 15)]
    mask = 0
    for b in bits:
        mask |= 1 << (63 - b)
    d = mask.to_bytes(8, "big")
    d += struct.pack(">HH", 424, 2) + struct.pack(">HI", 1, 42739324)
    d += struct.pack(">i", e_sa32(35.7070767)) + struct.pack(">I", e_ba32(16.9375327))
    d += struct.pack(">i", e_sa32(35.62)) + struct.pack(">I", e_ba32(16.90))
    d += struct.pack(">i", e_sa32(35.6245687)) + struct.pack(">I", e_ba32(16.8998668))
    d += struct.pack(">hh", 123, -599) + struct.pack(">bB", 27, 6)
    d += struct.pack(">HH", 10105, 788) + struct.pack(">BH", 15, 45)
    segs += bytes([2]) + struct.pack(">I", len(d) + 5) + d
    # Platform Location
    pl = struct.pack(">IiIi", 42739000, e_sa32(35.71), e_ba32(16.94), 850000)
    pl += struct.pack(">HIb", int(120 / (360 / 2**16)), 120000, -2)
    segs += bytes([13]) + struct.pack(">I", len(pl) + 5) + pl
    # Free Text
    ft = b"OPERATEUR " + b"ISRBOX    " + b"TEST INVENTAIRE"
    segs += bytes([6]) + struct.pack(">I", len(ft) + 5) + ft

    pkt = b"31" + struct.pack(">I", 32 + len(segs)) + b"FR" + bytes([5]) + b"  " \
          + struct.pack(">H", 0) + bytes([0]) + b"VECTEUR-01" + struct.pack(">II", 1, 77) + segs
    s = Sink()
    parse_stream(pkt, s)
    assert s.seg_count["Mission"] == 1 and s.seg_count["Job Definition"] == 1
    assert s.seg_count["Dwell"] == 1 and s.seg_count["Platform Location"] == 1
    assert s.seg_count["Free Text"] == 1
    d0, t0, (la, lo) = s.plots[0]
    assert abs(la - 35.6245687) < 1e-5 and abs(lo - 16.8998668) < 1e-5
    assert t0["height_m"] == 123 and t0["sig_height_m"] == 15
    assert s.jobdefs[0]["radar_mode_lib"] == "MTI"
    assert abs(s.jobdefs[0]["bounding_area"][0][0] - 35.7) < 1e-5
    assert s.missions[0]["mission_plan"] == "PLAN-ALPHA"
    print(rapport(s))
    print("\nselftest OK — Mission, Job Definition, Dwell+target, "
          "Platform Location, Free Text decodes et verifies")

# ---------------------------------------------------------------- main
if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(0)

    def opt(name, default=None):
        for i, a in enumerate(sys.argv):
            if a == f"--{name}":
                return sys.argv[i + 1]
            if a.startswith(f"--{name}="):
                return a.split("=", 1)[1]
        return default

    port = opt("port")
    sink = Sink(jsonl_path=opt("jsonl"))
    try:
        streams = udp_streams(args[0], int(port) if port else None)
    except ValueError as ex:            # inclut PcapngError
        sys.exit(str(ex))
    for key, buf in streams.items():
        tag = f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}"
        if buf[:1] == b"\x47":
            print(f"flux {tag} : MPEG-TS/4609 — ignore")
            continue
        if not (len(buf) > 6 and 0x30 <= buf[0] <= 0x39 and 0x30 <= buf[1] <= 0x39):
            print(f"flux {tag} : non reconnu — ignore")
            continue
        print(f"flux {tag} : 4607 ({len(buf)} octets)")
        parse_stream(bytes(buf), sink)
    if sink.jsonl:
        sink.jsonl.close()

    txt = rapport(sink)
    print("\n" + txt)
    rp = opt("rapport")
    if rp:
        open(rp, "w").write(txt + "\n")
        print(f"\nrapport -> {rp}")
    cp = opt("csv")
    if cp:
        write_csv(sink, cp)
        print(f"plots  -> {cp} ({len(sink.plots)} lignes)")
