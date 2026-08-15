#!/usr/bin/env python3
"""Relais CoT -> texte delimite, pour ingestion par GeoEvent Server.

POURQUOI CE RELAIS
------------------
L'adaptateur XML de GeoEvent Server ne delimite pas les datagrammes UDP : il
accumule le flux recu dans un cache et tente de le parser comme un document XML
unique. Un flux de messages CoT independants produit donc un document
multi-racines, que Xerces rejette systematiquement — quel que soit le
parametrage (constate en integration le 20/07/2026, GeoEvent 11.4, voir
docs/geoevent-config.md).

Ce relais deporte le parsing CoT en Python, ou nous le maitrisons, et alimente
GeoEvent avec du texte delimite — format pour lequel l'adaptateur Texte dispose
d'un vrai `Message Separator`.

Il traite indifferemment le flux du generateur et celui d'un ATAK reel : le
prologue XML, present chez ATAK et absent avec --no-xml-decl, est accepte dans
les deux cas. C'est donc aussi la reponse au probleme de la phase 2.

Etant un processus externe a la plateforme Esri, il est conforme a la note de
portabilite du §9 du cadrage (aucun OSGi) et reutilisable tel quel avec
ArcGIS Velocity.

Bibliotheque standard uniquement.

    python cot_relay.py --in-group 239.2.3.1 --in-port 6969 \
                        --out-host 192.168.26.145 --out-port 6970
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Iterator

AFFILIATIONS = {
    "f": "FRIEND", "h": "HOSTILE", "n": "NEUTRAL", "u": "UNKNOWN",
    "p": "PENDING", "a": "ASSUMED_FRIEND", "s": "SUSPECT",
}
DIMENSIONS = {"A": "AIR", "G": "GROUND", "S": "SURFACE", "U": "SUBSURFACE", "P": "SPACE"}

# Ordre des colonnes emises. C'EST LE CONTRAT avec la GeoEvent Definition :
# toute modification impose de mettre a jour CoT_Event_Definition.
FIELDS = [
    "uid",                 # TRACK_ID
    "cot_type",
    "event_time",          # TIME_START
    "start_time",
    "stale_time",
    "how",
    "point_lat",           # GEOMETRY (Y)
    "point_lon",           # GEOMETRY (X)
    "point_hae",
    "point_ce",
    "point_le",
    "callsign",
    "course",
    "speed",
    "affiliation",
    "battle_dimension",
    "remarks",
]


PROLOG_RE = re.compile(rb"<\?xml[^>]*\?>")
UID_RE = re.compile(rb'uid="([^"]*)"')
TYPE_RE = re.compile(rb'type="([^"]*)"')


def strip_prolog(datagram: bytes) -> bytes:
    """Retourne le message CoT debarrasse de son prologue XML.

    L'adaptateur CoT de GeoEvent accumule les octets recus avant de parser, sur
    UDP comme sur TCP. Un prologue en milieu de buffer fait echouer le parse —
    et declenche un mecanisme de reprise qui REEMET des evenements deja emis.
    ATAK emet le prologue et n'est pas modifiable : c'est la raison d'etre de ce
    mode passe-plat.
    """
    start = datagram.find(b"<event")
    if start == -1:
        raise ValueError("aucun element <event> dans le datagramme")
    end = datagram.rfind(b"</event>")
    body = datagram[start:end + len(b"</event>")] if end != -1 else datagram[start:]
    # Un prologue peut aussi se cacher dans un <detail> imbrique.
    return PROLOG_RE.sub(b"", body)


def parse_cot(datagram: bytes) -> dict[str, str]:
    """Decode un datagramme CoT en dictionnaire de champs plats.

    Tolere la presence ou l'absence du prologue XML : ATAK l'emet, le
    generateur peut l'omettre.
    """
    text = datagram.decode("utf-8", errors="replace").strip()
    # Un datagramme peut theoriquement porter du remplissage ; on isole l'event.
    start = text.find("<event")
    end = text.rfind("</event>")
    if start == -1:
        raise ValueError("aucun element <event> dans le datagramme")
    text = text[start:end + len("</event>")] if end != -1 else text[start:]

    root = ET.fromstring(text)
    out = {name: "" for name in FIELDS}

    out["uid"] = root.get("uid", "")
    out["cot_type"] = root.get("type", "")
    out["event_time"] = root.get("time", "")
    out["start_time"] = root.get("start", "")
    out["stale_time"] = root.get("stale", "")
    out["how"] = root.get("how", "")

    point = root.find("point")
    if point is None:
        raise ValueError(f"element <point> absent (uid={out['uid']})")
    out["point_lat"] = point.get("lat", "")
    out["point_lon"] = point.get("lon", "")
    out["point_hae"] = point.get("hae", "")
    out["point_ce"] = point.get("ce", "")
    out["point_le"] = point.get("le", "")

    detail = root.find("detail")
    if detail is not None:
        contact = detail.find("contact")
        if contact is not None:
            out["callsign"] = contact.get("callsign", "")
        trk = detail.find("track")
        if trk is not None:
            out["course"] = trk.get("course", "")
            out["speed"] = trk.get("speed", "")
        remarks = detail.find("remarks")
        if remarks is not None and remarks.text:
            out["remarks"] = remarks.text

    # Fallback d'etiquette : une piste sans callsign reste identifiable.
    if not out["callsign"]:
        out["callsign"] = out["uid"]

    # Affiliation et dimension derivees du type CoT. Les calculer ici plutot que
    # dans un Field Calculator evite des expressions fragiles cote GeoEvent, et
    # `cot_type` reste emis pour qui voudrait le refaire en aval.
    parts = out["cot_type"].split("-")
    if len(parts) >= 3 and parts[0] == "a":
        out["affiliation"] = AFFILIATIONS.get(parts[1].lower(), "UNKNOWN")
        out["battle_dimension"] = DIMENSIONS.get(parts[2].upper(), "")
    else:
        out["affiliation"] = "UNKNOWN"

    return out


# --------------------------------------------------------------------------
# Entites non ponctuelles : reconstruction de la geometrie
# --------------------------------------------------------------------------

# Champs emis vers l'input geometrique. C'est le contrat avec la GeoEvent
# Definition `CoT_Shape` (cot-server-files/geoevent/CoT_Shape.xml).
SHAPE_FIELDS = ["uid", "cot_type", "callsign", "event_time", "start_time",
                "stale_time", "how", "shape_type", "vertex_count"]


def extract_vertices(detail: ET.Element) -> tuple[list[tuple[float, float]], bool | None]:
    """Recupere les sommets d'une entite non ponctuelle.

    Deux conventions coexistent et l'adaptateur CoT d'Esri ne sait lire ni l'une
    ni l'autre — d'ou cette reconstruction hors de GeoEvent :

    `<link point="lat,lon,hae"/>` repete  : convention ATAK, emise par les
        outils de dessin. La definition livree declare `link` en cardinalite
        One, donc un seul sommet remonterait.
    `<shape><polyline><vertex lat lon/>`  : schema MITRE. L'adaptateur force
        tout element nomme `shape` au type Geometry, ce qui supprime `polyline`
        et `vertex` de la definition.

    Retourne les sommets et, si la source le precise, le caractere ferme.
    """
    vertices: list[tuple[float, float]] = []
    closed: bool | None = None

    polyline = detail.find("shape/polyline")
    if polyline is not None:
        for vertex in polyline.findall("vertex"):
            try:
                vertices.append((float(vertex.get("lat")), float(vertex.get("lon"))))
            except (TypeError, ValueError):
                continue
        attribute = polyline.get("closed")
        if attribute is not None:
            closed = attribute.strip().lower() == "true"

    if not vertices:
        for link in detail.findall("link"):
            raw = link.get("point")
            if not raw:
                continue
            parts = raw.split(",")
            if len(parts) < 2:
                continue
            try:
                vertices.append((float(parts[0]), float(parts[1])))
            except ValueError:
                continue

    return vertices, closed


def build_shape_json(datagram: bytes) -> dict | None:
    """Construit un enregistrement a geometrie Esri, ou None si l'entite est ponctuelle.

    Le JSON produit est celui qu'attend l'adaptateur Generic-JSON de GeoEvent
    quand la definition declare un champ de type Geometry : l'objet geometrique
    est repris tel quel, sans `Construct Geometry from Fields`.
    """
    text = datagram.decode("utf-8", errors="replace")
    start, end = text.find("<event"), text.rfind("</event>")
    if start == -1:
        raise ValueError("aucun element <event> dans le datagramme")
    root = ET.fromstring(text[start:end + len("</event>")] if end != -1 else text[start:])

    detail = root.find("detail")
    if detail is None:
        return None
    vertices, closed = extract_vertices(detail)
    if len(vertices) < 2:
        return None   # entite ponctuelle : elle passe par la chaine CoT normale

    cot_type = root.get("type", "")
    if closed is None:
        # A defaut d'indication explicite : un remplissage ou un contour boucle
        # signent un polygone. Les routes `b-m-r` sont toujours ouvertes.
        closed = (detail.find("fillColor") is not None
                  or vertices[0] == vertices[-1]) and not cot_type.startswith("b-m-r")

    ring = [[lon, lat] for lat, lon in vertices]
    if closed and ring[0] != ring[-1]:
        ring.append(ring[0])   # une bague Esri doit etre fermee explicitement

    spatial = {"wkid": 4326}
    geometry = {"rings": [ring], "spatialReference": spatial} if closed \
        else {"paths": [ring], "spatialReference": spatial}

    contact = detail.find("contact")
    return {
        "uid": root.get("uid", ""),
        "cot_type": cot_type,
        "callsign": (contact.get("callsign", "") if contact is not None else "")
                    or root.get("uid", ""),
        "event_time": root.get("time", ""),
        "start_time": root.get("start", ""),
        "stale_time": root.get("stale", ""),
        "how": root.get("how", ""),
        "shape_type": "polygon" if closed else "polyline",
        "vertex_count": len(vertices),
        "geometry": geometry,
    }


def to_line(fields: dict[str, str], separator: str) -> str:
    """Serialise en ligne delimitee, en neutralisant le separateur.

    `remarks` est du texte libre : s'il contenait le separateur, il decalerait
    toutes les colonnes suivantes et corromprait silencieusement les evenements.
    """
    values = []
    for name in FIELDS:
        value = fields.get(name, "").replace(separator, " ")
        values.append(" ".join(value.split()))  # aplatir tout retour ligne
    return separator.join(values)


def open_input(args: argparse.Namespace) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    except OSError as exc:
        print(f"[relay] SO_RCVBUF non applique : {exc}", file=sys.stderr)
    try:
        sock.bind(("", args.in_port))
    except OSError as exc:
        sock.close()
        raise SystemExit(
            f"[relay] impossible d'ecouter sur le port UDP {args.in_port} : {exc}\n"
            f"Le port est-il deja detenu ? netstat -ano -p UDP | findstr {args.in_port}"
        ) from None

    first_octet = int(args.in_group.split(".")[0]) if args.in_group[0].isdigit() else 0
    if 224 <= first_octet <= 239:
        mreq = struct.pack("4s4s", socket.inet_aton(args.in_group),
                           socket.inet_aton(args.in_iface or "0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print(f"[relay] entree : groupe {args.in_group}:{args.in_port}", file=sys.stderr)
    else:
        print(f"[relay] entree : unicast :{args.in_port}", file=sys.stderr)
    sock.settimeout(1.0)
    return sock


def iter_replay(args: argparse.Namespace) -> Iterator[tuple[bytes, tuple[str, int]]]:
    """Rejoue une capture `--save` du listener, vers le reseau cette fois.

    Le `--replay` de cot_listener.py analyse une capture hors ligne ; celui-ci
    la REEMET, ce qui permet de valider la chaine GeoEvent complete avec les
    octets reels d'un client TAK — prologue compris, et surtout `detail`
    complet, ce que le generateur ne sait pas reproduire.

    La cadence d'origine est respectee : WinTAK emet par rafales de 2 a 4
    messages espaces de quelques millisecondes, et c'est precisement ce profil
    qui met en defaut le framing de l'adaptateur. Un rejeu lisse ne testerait
    pas la meme chose.
    """
    with open(args.replay, encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    if not records:
        raise SystemExit(f"[relay] capture vide : {args.replay}")

    span = records[-1].get("t", 0.0) - records[0].get("t", 0.0)
    pace = "au plus vite" if args.replay_speed <= 0 else f"x{args.replay_speed:g}"
    print(f"[relay] rejeu de {args.replay} : {len(records)} datagrammes, "
          f"{span:.1f} s de capture, {pace}", file=sys.stderr)

    origin = records[0].get("t", 0.0)
    started = time.monotonic()
    for record in records:
        if args.replay_speed > 0:
            due = (record.get("t", 0.0) - origin) / args.replay_speed
            delay = due - (time.monotonic() - started)
            if delay > 0:
                time.sleep(delay)
        yield record["raw"].encode("utf-8"), (record.get("src", "replay"), 0)


def run(args: argparse.Namespace) -> int:
    separator = args.separator.replace("\\t", "\t")
    terminator = args.terminator.replace("\\r", "\r").replace("\\n", "\n")

    if args.header:
        print(separator.join(FIELDS))
        return 0

    src = None if args.replay else open_input(args)
    dst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    target = (args.out_host, args.out_port)
    mode = "passe-plat CoT, prologue retire" if args.passthrough \
        else f"texte delimite {separator!r}"
    print(f"[relay] sortie : {args.out_host}:{args.out_port} ({mode})",
          file=sys.stderr)
    print("[relay] Ctrl+C pour arreter.", file=sys.stderr)

    started = time.monotonic()
    received = relayed = rejected = failed = 0

    last_send = 0.0

    def pace() -> None:
        """Impose un ecart minimal entre deux emissions.

        L'adaptateur CoT accumule les octets recus avant de parser. Deux
        messages arrivant a quelques millisecondes d'intervalle se retrouvent
        dans le meme buffer, qui devient un document multi-racines : le parse
        echoue ('markup ... must be well-formed'), et le fragment remis a
        traverseBranch peut porter plusieurs <point> ('multiple points'). Dans
        les deux cas l'evenement est PERDU.

        TAK emet precisement par rafales — mesure sur la capture WinTAK : 22
        ecarts inferieurs a 50 ms, dont plusieurs a 1-4 ms. C'est le pendant du
        --spread du generateur, applique a une source non modifiable.
        """
        nonlocal last_send
        if args.min_gap <= 0:
            return
        due = last_send + args.min_gap / 1000.0
        delay = due - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        last_send = time.monotonic()

    def send(sock: socket.socket, payload: bytes, dest) -> bool:
        """Emet vers GeoEvent sans jamais laisser une erreur tuer le relais."""
        nonlocal failed
        pace()
        try:
            sock.sendto(payload, dest)
            return True
        except OSError as exc:
            failed += 1
            if failed <= args.max_errors:
                print(f"[relay] emission vers {dest[0]}:{dest[1]} : {exc}",
                      file=sys.stderr)
                if failed == args.max_errors:
                    print("[relay] (erreurs d'emission suivantes silencieuses)",
                          file=sys.stderr)
            return False

    affiliations: Counter[str] = Counter()
    seen_uids: set[str] = set()
    shapes_sent = 0
    shape_kinds: Counter[str] = Counter()
    shape_target = (args.out_host, args.shapes_out) if args.shapes_out else None
    if shape_target:
        print(f"[relay] geometries : {shape_target[0]}:{shape_target[1]} "
              "(JSON Esri, entites non ponctuelles)", file=sys.stderr)

    def forward_shape(datagram: bytes) -> None:
        """Derive les entites non ponctuelles vers l'input geometrique.

        Le CoT d'origine continue de partir vers la chaine normale : le
        centroide et les attributs restent disponibles cote `CoT`. Seule la
        geometrie, que l'adaptateur ne sait pas restituer, emprunte ce chemin.
        """
        nonlocal shapes_sent
        if not shape_target:
            return
        try:
            record = build_shape_json(datagram)
        except Exception as exc:
            if rejected <= args.max_errors:
                print(f"[relay] geometrie ignoree : {exc}", file=sys.stderr)
            return
        if record is None:
            return
        if send(dst, (json.dumps(record) + "\n").encode("utf-8"), shape_target):
            shapes_sent += 1
            shape_kinds[record["shape_type"]] += 1

    def iter_live() -> Iterator[tuple[bytes, tuple[str, int]]]:
        nonlocal failed
        while True:
            try:
                yield src.recvfrom(65535)
            except socket.timeout:
                yield b"", ("", 0)  # laisse la boucle reevaluer --duration
            except OSError as exc:
                # Sous Windows, un ICMP port unreachable en retour d'un envoi
                # precedent remonte ici (WSAECONNRESET). Ne doit pas arreter un
                # relais destine a tourner en continu.
                failed += 1
                if failed <= args.max_errors:
                    print(f"[relay] reception : {exc}", file=sys.stderr)
                yield b"", ("", 0)

    source = iter_replay(args) if args.replay else iter_live()

    try:
        for datagram, sender in source:
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                break
            if not datagram:
                continue

            received += 1

            if args.passthrough:
                # Passe-plat : on ne reformate rien, on retire le prologue et on
                # reemet le CoT tel quel vers le connecteur CoT d'Esri.
                try:
                    body = strip_prolog(datagram)
                except ValueError as exc:
                    rejected += 1
                    if rejected <= args.max_errors:
                        print(f"[relay] rejet depuis {sender[0]} : {exc}",
                              file=sys.stderr)
                    continue
                if not send(dst, body, target):
                    continue
                relayed += 1
                forward_shape(body)
                match = UID_RE.search(body)
                if match:
                    seen_uids.add(match.group(1).decode("utf-8", "replace"))
                match = TYPE_RE.search(body)
                if match:
                    affiliations[match.group(1).decode("utf-8", "replace")] += 1
                if args.echo:
                    sys.stdout.buffer.write(body + b"\n")
                elif args.verbose and relayed % 50 == 0:
                    print(f"[relay] {relayed} relaye(s), {len(seen_uids)} piste(s)",
                          file=sys.stderr)
                continue

            try:
                fields = parse_cot(datagram)
            except Exception as exc:
                rejected += 1
                if rejected <= args.max_errors:
                    print(f"[relay] rejet depuis {sender[0]} : {exc}", file=sys.stderr)
                    if rejected == args.max_errors:
                        print("[relay] (erreurs suivantes silencieuses)", file=sys.stderr)
                continue

            line = to_line(fields, separator)
            if not send(dst, (line + terminator).encode("utf-8"), target):
                continue
            relayed += 1
            seen_uids.add(fields["uid"])
            affiliations[fields["affiliation"]] += 1

            if args.echo:
                print(line)
            elif args.verbose and relayed % 50 == 0:
                print(f"[relay] {relayed} relaye(s), {len(seen_uids)} piste(s)",
                      file=sys.stderr)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        if src is not None:
            src.close()
        dst.close()

    elapsed = max(1e-6, time.monotonic() - started)
    print("", file=sys.stderr)
    print("=== BILAN RELAIS ==================================", file=sys.stderr)
    print(f"duree              : {elapsed:.1f} s", file=sys.stderr)
    print(f"CoT recus          : {received} ({received / elapsed:.1f}/s)", file=sys.stderr)
    print(f"relayes            : {relayed}", file=sys.stderr)
    print(f"rejetes (parsing)  : {rejected}", file=sys.stderr)
    print(f"echecs reseau      : {failed}", file=sys.stderr)
    print(f"uid distincts      : {len(seen_uids)}", file=sys.stderr)
    if shape_target:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(shape_kinds.items()))
        print(f"geometries emises  : {shapes_sent}"
              + (f" ({detail})" if detail else ""), file=sys.stderr)
    if affiliations:
        print("affiliations       : "
              + ", ".join(f"{k}={v}" for k, v in sorted(affiliations.items())),
              file=sys.stderr)
    print("===================================================", file=sys.stderr)
    return 0 if rejected == 0 and failed == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Relais CoT XML -> texte delimite pour GeoEvent Server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    src = parser.add_argument_group("entree (CoT)")
    src.add_argument("--in-group", default="239.2.3.1",
                     help="groupe multicast a rejoindre (0.0.0.0 pour unicast)")
    src.add_argument("--in-port", type=int, default=6969, help="port UDP d'ecoute")
    src.add_argument("--in-iface", default=None,
                     help="IP de l'interface locale d'abonnement")
    src.add_argument("--rcvbuf", type=int, default=16 * 1024 * 1024,
                     help="buffer de reception UDP, en octets")
    src.add_argument("--replay", default=None, metavar="FICHIER",
                     help="rejouer une capture JSON Lines vers GeoEvent au lieu "
                          "d'ecouter le reseau (fichier produit par "
                          "cot_listener.py --save)")
    src.add_argument("--replay-speed", type=float, default=1.0, metavar="F",
                     help="facteur d'acceleration du rejeu ; 1 = cadence reelle, "
                          "0 = au plus vite")

    dst = parser.add_argument_group("sortie (GeoEvent)")
    dst.add_argument("--out-host", default="127.0.0.1",
                     help="IP du serveur GeoEvent")
    dst.add_argument("--out-port", type=int, default=6970,
                     help="port UDP du receiver GeoEvent")
    dst.add_argument("--separator", default=",",
                     help="separateur d'attributs (doit correspondre a l'input GeoEvent)")
    dst.add_argument("--terminator", default="\\n",
                     help="separateur de messages (Message Separator cote GeoEvent)")

    dst.add_argument("--shapes-out", type=int, default=0, metavar="PORT",
                     help="port UDP d'un second input GeoEvent recevant les "
                          "ENTITES NON PONCTUELLES en JSON Esri (rings/paths). "
                          "L'adaptateur CoT ne restitue que le centroide : "
                          "c'est le seul moyen d'obtenir lignes et polygones. "
                          "Definition a importer : CoT_Shape.xml. 0 = desactive")

    dst.add_argument("--min-gap", type=float, default=0.0, metavar="MS",
                     help="ecart minimal entre deux emissions, en millisecondes. "
                          "Evite que l'adaptateur CoT recoive deux messages dans "
                          "le meme buffer (defaut 0 = desactive, 50 recommande "
                          "avec une source TAK qui emet par rafales)")

    dst.add_argument("--passthrough", action="store_true",
                     help="MODE PHASE 2 : reemettre le CoT XML tel quel en retirant "
                          "seulement le prologue, vers le connecteur CoT d'Esri. "
                          "Ignore --separator et --terminator")

    run_grp = parser.add_argument_group("execution")
    run_grp.add_argument("--duration", type=float, default=0.0,
                         help="duree en secondes (0 = illimite)")
    run_grp.add_argument("--echo", action="store_true",
                         help="afficher chaque ligne relayee")
    run_grp.add_argument("--verbose", action="store_true",
                         help="statistiques periodiques")
    run_grp.add_argument("--max-errors", type=int, default=5,
                         help="nombre de rejets detailles avant silence")
    run_grp.add_argument("--header", action="store_true",
                         help="afficher l'ordre des colonnes et quitter "
                              "(pour construire la GeoEvent Definition)")
    return parser


if __name__ == "__main__":
    sys.exit(run(build_parser().parse_args()))
