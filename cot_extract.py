#!/usr/bin/env python3
"""Extraction des messages CoT d'une capture pcap/pcapng vers des fichiers
exploitables (XML indenté + CSV) pour recherche et vérification.

POC ISRBOX / 33e ESRA. Sert notamment à VÉRIFIER l'affiliation dérivée par le
receiver GeoEvent : l'affiliation = 2e caractère du `type` CoT (identique à
`CotSidc.identity` du receiver), reproduite ici à l'identique. Le tableau par
type permet de contrôler d'un coup d'œil que chaque type reçu (ex. défense
sol-air `a-*-G-U-C-D`) porte la bonne affiliation.

Trois sorties (préfixe = nom de la capture) :
  <cap>.events.xml   tous les <event> (ou dédupliqués / filtrés), indentés, sous
                     une racine <cot_capture> — ouvrable et cherchable.
  <cap>.tracks.csv   une ligne par piste (uid), dernière valeur vue.
  <cap>.types.csv    une ligne par `type` distinct : compte + affiliation +
                     dimension + SIDC + description (CoTtypes.xml). ← vérif affiliation

Bibliothèque standard uniquement.

  python cot_extract.py CaptureCoT_CSI.pcap
  python cot_extract.py capture.pcap --filter-type G-U-C-D   # seulement la défense sol-air
  python cot_extract.py capture.pcap --dedup                 # un event par uid dans le XML
"""

from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import sys
import xml.etree.ElementTree as ET

# Réutilise le lecteur pcap/pcapng + le découpage L2/L3/L4 déjà éprouvé.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_replay import iter_frames, parse, classify  # noqa: E402

EVENT_RE = re.compile(r"<event\b.*?</event>", re.S)

# --- Dérivation affiliation / dimension / SIDC : PORT EXACT de CotSidc.java ---

_IDENTITY = {"f": "F", "h": "H", "n": "N", "u": "U", "p": "P",
             "a": "A", "s": "S", "j": "J", "k": "K"}
_AFFIL = {"F": "FRIEND", "H": "HOSTILE", "N": "NEUTRAL", "U": "UNKNOWN",
          "P": "PENDING", "A": "ASSUMED_FRIEND", "S": "SUSPECT",
          "J": "JOKER", "K": "FAKER"}
_DIM = {"A": "A", "G": "G", "S": "S", "U": "U", "P": "P", "F": "F"}


def identity(cot_type: str) -> str:
    p = (cot_type or "").split("-")
    if len(p) < 2 or p[0] != "a":
        return "U"
    return _IDENTITY.get(p[1].lower(), "U")


def affiliation(cot_type: str) -> str:
    return _AFFIL.get(identity(cot_type), "")


def dimension(cot_type: str) -> str:
    p = (cot_type or "").split("-")
    if len(p) < 3 or p[0] != "a":
        return "-"
    return _DIM.get(p[2].upper(), "-")


def sidc_algo(cot_type: str) -> str:
    """SIDC algorithmique de CotSidc.sidc (le receiver applique EN PLUS l'APP-6
    pour Delta Suite ; pour le CoT CSI il retombe en général sur celui-ci)."""
    p = (cot_type or "").split("-")
    if len(p) < 3 or p[0] != "a":
        return ""
    fid = ("".join(p[3:]).upper() + "------")[:6]
    return "S" + identity(cot_type) + dimension(cot_type) + "P" + fid + "-----"


def load_cot_descriptions(path: str | None) -> dict[str, str]:
    """Charge type normalisé (a-.-…) -> description depuis CoTtypes.xml."""
    if not path or not os.path.exists(path):
        return {}
    out: dict[str, str] = {}
    text = open(path, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'<cot\s+cot="([^"]+)"[^>]*?desc="([^"]*)"', text):
        out[m.group(1)] = m.group(2)
    return out


def type_key(cot_type: str) -> str:
    """Normalise l'affiliation en '.' pour la recherche dans CoTtypes."""
    p = (cot_type or "").split("-")
    if len(p) >= 2 and p[0] == "a":
        p[1] = "."
    return "-".join(p)


def describe(cot_type: str, table: dict[str, str]) -> str:
    """Description la plus spécifique (préfixes décroissants), '' si absente."""
    p = type_key(cot_type).split("-")
    while p:
        hit = table.get("-".join(p))
        if hit:
            return hit
        p.pop()
    return ""


def default_cot_types() -> str | None:
    """CoTtypes.xml du receiver, s'il est là (extract lancé depuis tools/)."""
    guess = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "src", "main", "resources", "CoTtypes.xml")
    return guess if os.path.exists(guess) else None


def attr(el, name):
    v = el.get(name)
    return v if v not in (None, "") else None


def _fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_TCP_MAX_BUF = 1_000_000        # borne du tampon de réassemblage par flux TCP (1 Mo)
_TCP_DECIDE_BYTES = 4096        # au-delà, si aucun <event vu, le flux TCP est non-CoT


def scan_cot(pcap, filter_type=None, descriptions=None):
    """Parse un pcap et renvoie les CoT EN MÉMOIRE (réutilisable GUI/tests).

    UDP : un event par datagramme (inchangé). TCP : RÉASSEMBLAGE simple par flux
    (src,sport,dst,dport) — concaténation dans l'ordre de capture, SANS gestion
    des retransmissions ni du désordre — pour récupérer les <event> coupés entre
    segments (sinon perdus silencieusement). Tampon incrémental borné à 1 Mo.

    Retour : {total, kept, malformed, types, type_example, rows, tracks, events,
              by_uid, tcp_recovered (events à cheval sur ≥2 segments),
              residual_bytes (tampons TCP non parsés en fin), empty_uid}.
    """
    descriptions = descriptions or {}
    events, by_uid, rows = [], {}, {}
    tracks = collections.defaultdict(list)
    types = collections.Counter()
    type_example = {}
    counters = {"total": 0, "kept": 0, "malformed": 0, "tcp_recovered": 0, "empty_uid": 0}

    def process(raw, src):
        counters["total"] += 1
        try:
            el = ET.fromstring(raw)
        except ET.ParseError:
            counters["malformed"] += 1
            return
        cot_type = el.get("type", "") or ""
        if filter_type and filter_type not in cot_type:
            return
        counters["kept"] += 1
        uid = el.get("uid", "") or ""
        if uid == "":
            counters["empty_uid"] += 1
        events.append(raw)
        by_uid[uid] = raw
        types[cot_type] += 1
        type_example.setdefault(cot_type, uid)
        point = el.find("point")
        det = el.find("detail")
        duid = det.find("uid") if det is not None else None
        contact = det.find("contact") if det is not None else None
        track = det.find("track") if det is not None else None
        lat = attr(point, "lat") if point is not None else None
        lon = attr(point, "lon") if point is not None else None
        rows[uid] = {
            "uid": uid, "type": cot_type,
            "affiliation": affiliation(cot_type), "dimension": dimension(cot_type),
            "sidc_algo": sidc_algo(cot_type),
            "type_description": describe(cot_type, descriptions),
            "track_number": (attr(duid, "tadilj") or attr(duid, "tadila")) if duid is not None else None,
            "callsign": attr(contact, "callsign") if contact is not None else None,
            "how": attr(el, "how"), "src": src,
            "lat": lat, "lon": lon,
            "hae": attr(point, "hae") if point is not None else None,
            "ce": attr(point, "ce") if point is not None else None,
            "le": attr(point, "le") if point is not None else None,
            "course": attr(track, "course") if track is not None else None,
            "speed": attr(track, "speed") if track is not None else None,
            "time": attr(el, "time"),
        }
        fla, flo = _fnum(lat), _fnum(lon)
        if fla is not None and flo is not None and not (fla == 0.0 and flo == 0.0):
            tracks[uid].append((attr(el, "time"), fla, flo))

    tcp = {}   # (src,sport,dst,dport) -> {"s": str tampon, "cot": bool|None}

    for ts, lt, frame in iter_frames(pcap):
        r = parse(lt, frame)
        if not r:
            continue
        proto, src, sport, dst, dport, pl = r
        if proto == "UDP":
            if classify(pl) != "CoT-XML":
                continue
            for raw in EVENT_RE.findall(pl.decode("utf-8", "replace")):
                process(raw, src)
            continue
        # ── TCP : réassemblage par flux ──────────────────────────────────
        key = (src, sport, dst, dport)
        st = tcp.get(key)
        if st is None:
            st = tcp[key] = {"s": "", "cot": None}
        if st["cot"] is False:
            continue
        seg_start = len(st["s"])
        st["s"] += pl.decode("utf-8", "replace")
        if st["cot"] is None:
            if "<event" in st["s"] or "<?xml" in st["s"]:
                st["cot"] = True
            elif len(st["s"]) > _TCP_DECIDE_BYTES:
                st["cot"] = False; st["s"] = ""; continue
            else:
                continue
        last_end = 0
        for m in EVENT_RE.finditer(st["s"]):
            if m.start() < seg_start:          # event commencé dans un segment antérieur
                counters["tcp_recovered"] += 1
            process(m.group(0), src)
            last_end = m.end()
        tail = st["s"].rfind("<event", last_end)   # garder une éventuelle queue non fermée
        st["s"] = st["s"][tail:] if tail >= 0 else ""
        if len(st["s"]) > _TCP_MAX_BUF:
            st["s"] = st["s"][-_TCP_MAX_BUF:]

    residual = sum(len(v["s"]) for v in tcp.values() if v["cot"])
    return {"total": counters["total"], "kept": counters["kept"],
            "malformed": counters["malformed"], "tcp_recovered": counters["tcp_recovered"],
            "residual_bytes": residual, "empty_uid": counters["empty_uid"],
            "types": types, "type_example": type_example, "rows": rows,
            "tracks": dict(tracks), "events": events, "by_uid": by_uid}


def main() -> int:
    ap = argparse.ArgumentParser(description="Extraction CoT d'un pcap -> XML + CSV exploitables")
    ap.add_argument("pcap", help="fichier .pcap ou .pcapng")
    ap.add_argument("--out-prefix", default=None,
                    help="préfixe des fichiers de sortie (défaut : nom de la capture)")
    ap.add_argument("--filter-type", default=None,
                    help="ne garder que les types CONTENANT cette sous-chaîne (ex. G-U-C-D)")
    ap.add_argument("--dedup", action="store_true",
                    help="un seul event par uid (dernier vu) dans le XML")
    ap.add_argument("--cot-types", default=default_cot_types(),
                    help="CoTtypes.xml pour la colonne description")
    args = ap.parse_args()

    prefix = args.out_prefix or os.path.splitext(args.pcap)[0]
    descriptions = load_cot_descriptions(args.cot_types)

    res = scan_cot(args.pcap, args.filter_type, descriptions)
    total, kept, malformed = res["total"], res["kept"], res["malformed"]
    events, by_uid, rows = res["events"], res["by_uid"], res["rows"]
    types, type_example = res["types"], res["type_example"]

    if kept == 0:
        print("Aucun message CoT retenu (filtre trop restrictif ?).", file=sys.stderr)
        return 1

    # --- 1) XML indenté, tous les events (ou dédupliqués) sous une racine ---
    xml_events = list(by_uid.values()) if args.dedup else events
    root = ET.Element("cot_capture")
    root.set("source", os.path.basename(args.pcap))
    root.set("events", str(len(xml_events)))
    if args.filter_type:
        root.set("filter_type", args.filter_type)
    for raw in xml_events:
        try:
            root.append(ET.fromstring(raw))
        except ET.ParseError:
            continue
    ET.indent(root, space="  ")
    xml_path = f"{prefix}.events.xml"
    ET.ElementTree(root).write(xml_path, encoding="utf-8", xml_declaration=True)

    # --- 2) tracks.csv : une ligne par piste ---
    cols = ["uid", "type", "affiliation", "dimension", "sidc_algo", "type_description",
            "track_number", "callsign", "how", "src", "lat", "lon", "hae", "ce", "le",
            "course", "speed", "time"]
    tracks_path = f"{prefix}.tracks.csv"
    with open(tracks_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for uid in sorted(rows):
            w.writerow(rows[uid])

    # --- 3) types.csv : une ligne par type distinct (vérif affiliation) ---
    types_path = f"{prefix}.types.csv"
    with open(types_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["type", "count", "affiliation", "dimension", "sidc_algo",
                    "type_description", "uid_exemple"])
        for cot_type, n in types.most_common():
            w.writerow([cot_type, n, affiliation(cot_type), dimension(cot_type),
                        sidc_algo(cot_type), describe(cot_type, descriptions),
                        type_example.get(cot_type, "")])

    print(f"Messages CoT lus     : {total} (malformés : {malformed})")
    print(f"Retenus              : {kept}"
          + (f"  [filtre type contient '{args.filter_type}']" if args.filter_type else ""))
    print(f"Reassembles TCP      : {res['tcp_recovered']} event(s) a cheval sur >=2 segments")
    print(f"Tampon TCP résiduel  : {res['residual_bytes']} octet(s) non parsés en fin de capture")
    print(f"Events à uid vide    : {res['empty_uid']} (écrasés sous la clé '')")
    print(f"Pistes distinctes    : {len(rows)}")
    print(f"Types distincts      : {len(types)}")
    print(f"CoTtypes.xml         : {'chargé' if descriptions else 'absent (colonne description vide)'}")
    print()
    print("Écrit :")
    print(f"  {xml_path}     ({len(xml_events)} events{', dédupliqués' if args.dedup else ''})")
    print(f"  {tracks_path}")
    print(f"  {types_path}   <- vérification affiliation par type")
    return 0


if __name__ == "__main__":
    sys.exit(main())
