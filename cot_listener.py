#!/usr/bin/env python3
"""Ecoute et controle du flux CoT, independamment de GeoEvent.

Outil de verification de la phase 1 : rejoint le groupe multicast TAK (ou ecoute
en unicast), decode chaque datagramme comme un message CoT et affiche ce que
GeoEvent devrait voir — y compris les champs aplatis facon Velocity
(point_lat, point_lon, point_hae, point_ce, point_le).

Bibliotheque standard uniquement.

Usage minimal :
    python cot_listener.py
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

DEFAULT_GROUP = "239.2.3.1"
DEFAULT_PORT = 6969

AFFILIATIONS = {
    "f": "FRIEND", "h": "HOSTILE", "n": "NEUTRAL", "u": "UNKNOWN",
    "p": "PENDING", "a": "ASSUMED_FRIEND", "s": "SUSPECT",
}
DIMENSIONS = {"A": "AIR", "G": "GROUND", "S": "SURFACE", "U": "SUBSURFACE", "P": "SPACE"}


def flatten(datagram: bytes) -> dict[str, str]:
    """Decode un datagramme CoT et retourne les champs aplatis.

    Les noms suivent la convention du feed TAK Client d'ArcGIS Velocity, celle
    retenue pour la GeoEvent Definition (cf. section 5.1 du prompt).
    """
    root = ET.fromstring(datagram.decode("utf-8"))
    if root.tag != "event":
        raise ValueError(f"racine XML inattendue : <{root.tag}> (attendu <event>)")

    out: dict[str, str] = {f"{k}": v for k, v in root.attrib.items()}

    point = root.find("point")
    if point is not None:
        for key, value in point.attrib.items():
            out[f"point_{key}"] = value

    detail = root.find("detail")
    if detail is not None:
        contact = detail.find("contact")
        if contact is not None and "callsign" in contact.attrib:
            out["detail_contact_callsign"] = contact.attrib["callsign"]
        trk = detail.find("track")
        if trk is not None:
            for key, value in trk.attrib.items():
                out[f"detail_track_{key}"] = value
        remarks = detail.find("remarks")
        if remarks is not None and remarks.text:
            out["detail_remarks"] = remarks.text

    cot_type = out.get("type", "")
    parts = cot_type.split("-")
    if len(parts) >= 3 and parts[0] == "a":
        out["affiliation"] = AFFILIATIONS.get(parts[1].lower(), "UNKNOWN")
        out["battle_dimension"] = DIMENSIONS.get(parts[2].upper(), "")
    return out


def load_cot_types(path: str) -> set[str]:
    """Charge les cles de type declarees dans CoTtypes.xml.

    Les entrees utilisent le point comme joker d'affiliation (`a-.-A-M-F`).
    """
    keys: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as handle:
        for match in re.finditer(r'<cot\s+cot="([^"]+)"', handle.read()):
            keys.add(match.group(1))
    return keys


def type_key(cot_type: str) -> str:
    """Normalise un type CoT vers la cle de la table : affiliation -> `.`."""
    parts = cot_type.split("-")
    if len(parts) >= 2 and parts[0] == "a":
        parts[1] = "."
    return "-".join(parts)


def lookup_type(cot_type: str, table: set[str]) -> str | None:
    """Cherche la correspondance la plus specifique, par prefixes decroissants."""
    parts = type_key(cot_type).split("-")
    while parts:
        candidate = "-".join(parts)
        if candidate in table:
            return candidate
        parts.pop()
    return None


class SchemaInventory:
    """Releve tout ce qu'un receiver CoT devra savoir traiter.

    C'est le livrable d'une session de capture : la description exacte du flux
    d'un emetteur donne, etablie sur des octets reels et non sur la
    documentation. Elle sert deux fois — DeltaSuite, puis le flux CSI — et
    chaque emetteur a ses propres libertes vis-a-vis de la norme.

    Trois familles d'observations, dans l'ordre ou elles conditionnent
    l'ecriture d'un receiver :

    1. CADRAGE  — un message par datagramme ? prologue ? rafales ? XML ou
       protobuf ? C'est ce qui decide de la strategie de decoupage, et c'est la
       ou l'adaptateur d'Esri echoue.
    2. GEOMETRIE — quelle convention porte lignes et polygones. La norme dit
       `detail/shape` (MITRE), TAK dit `detail/link@point`. Un receiver doit
       savoir laquelle il recoit avant de pouvoir construire la geometrie.
    3. DETAIL   — l'inventaire des sous-elements et de leurs attributs, qui
       devient la GeoEvent Definition de sortie.
    """

    def __init__(self) -> None:
        self.messages = 0
        self.with_prolog = 0
        self.multi_event = 0
        self.not_xml = 0
        self.encodings: Counter[str] = Counter()
        self.sizes: list[int] = []
        self.timestamps_without_ms = 0
        self.detail_attrs: dict[str, Counter[str]] = {}
        self.detail_counts: Counter[str] = Counter()
        self.detail_text: Counter[str] = Counter()
        self.geometry: Counter[str] = Counter()
        self.point_counts: Counter[int] = Counter()

    def observe(self, datagram: bytes) -> None:
        self.messages += 1
        self.sizes.append(len(datagram))
        self.encodings[self.classify(datagram)] += 1

        text = datagram.decode("utf-8", errors="replace")
        if "<?xml" in text:
            self.with_prolog += 1
        if text.count("<event") > 1:
            self.multi_event += 1
        start = text.find("<event")
        if start == -1:
            # Ni prologue ni element racine : signature d'un payload protobuf,
            # variante du protocole TAK qu'un receiver XML ne verra jamais.
            self.not_xml += 1
            return

        end = text.rfind("</event>")
        try:
            root = ET.fromstring(text[start:end + len("</event>")] if end != -1
                                 else text[start:])
        except ET.ParseError:
            self.not_xml += 1
            return

        self.point_counts[len(root.findall("point"))] += 1
        for attribute in ("time", "start", "stale"):
            value = root.get(attribute, "")
            # Sans millisecondes, le format primaire de plusieurs parseurs
            # echoue et bascule sur un repli. A savoir avant d'ecrire le notre.
            if value.endswith("Z") and "." not in value:
                self.timestamps_without_ms += 1
                break

        detail = root.find("detail")
        if detail is None:
            self.geometry["point seul (pas de detail)"] += 1
            return

        for child in detail:
            self.detail_counts[child.tag] += 1
            # Les noms d'attributs, pas leurs valeurs : c'est la liste des
            # champs a prevoir, le contenu importe peu ici.
            self.detail_attrs.setdefault(child.tag, Counter()).update(child.attrib.keys())
            if (child.text or "").strip():
                self.detail_text[child.tag] += 1

        # Conventions geometriques, dans l'ordre de specificite.
        polyline = detail.find("shape/polyline")
        ellipse = detail.find("shape/ellipse")
        vertex_links = [l for l in detail.findall("link") if l.get("point")]
        if polyline is not None:
            kind = "polygone" if (polyline.get("closed") or "").lower() == "true" else "ligne"
            self.geometry[f"shape/polyline MITRE ({kind}, "
                          f"{len(polyline.findall('vertex'))} sommets)"] += 1
        elif ellipse is not None:
            shape = "cercle" if ellipse.get("major") == ellipse.get("minor") else "ellipse"
            self.geometry[f"shape/ellipse MITRE ({shape})"] += 1
        elif len(vertex_links) >= 2:
            self.geometry[f"link@point TAK ({len(vertex_links)} sommets)"] += 1
        else:
            self.geometry["point seul"] += 1

    @staticmethod
    def classify(datagram: bytes) -> str:
        """Identifie l'encodage sur les premiers octets.

        L'ecosysteme TAK transporte trois encodages sur les MEMES sockets, et
        rien ne l'annonce hors bande — il faut le lire dans le flux :

        `<`              -> TAK Protocol v0, CoT en XML clair
        `bf 01 bf`       -> TAK Protocol v1 « Mesh » : un message par
                            datagramme, encadre par deux octets magiques
        `bf` + varint    -> TAK Protocol v1 « Stream » : longueur variable,
                            pour un flux TCP continu

        La distinction compte : un receiver XML ne verra jamais passer du
        protobuf, et le symptome — zero evenement, aucune erreur — est le meme
        qu'une panne reseau. A noter pour la cible : le feed TAK Client
        d'ArcGIS Velocity n'ingere que du XML, pas le protobuf.
        """
        if not datagram:
            return "datagramme vide"
        if datagram[0] == 0xBF:
            if len(datagram) >= 3 and datagram[1] == 0x01 and datagram[2] == 0xBF:
                return "TAK Protocol v1 Mesh (protobuf)"
            return "TAK Protocol v1 Stream (protobuf)"
        head = datagram.lstrip()[:1]
        if head == b"<":
            return "XML (TAK Protocol v0)"
        return "inconnu — ni XML ni protobuf TAK"

    def report(self, out) -> None:
        if not self.messages:
            return
        say = lambda line="": print(line, file=out)
        say()
        say("=== INVENTAIRE POUR LE RECEIVER ===================")

        say("--- cadrage ---")
        say(f"  messages analyses      : {self.messages}")
        for encoding, count in self.encodings.most_common():
            alert = "   -> UN RECEIVER XML NE VERRA RIEN" if "protobuf" in encoding else ""
            say(f"  encodage               : {encoding} = {count}{alert}")
        say(f"  avec prologue <?xml    : {self.with_prolog}"
            + ("   -> le decoupage doit l'accepter en tete de datagramme"
               if self.with_prolog else ""))
        say(f"  plusieurs <event>      : {self.multi_event}"
            + ("   -> DECOUPAGE PAR MESSAGE OBLIGATOIRE" if self.multi_event else ""))
        say(f"  non decodables en XML  : {self.not_xml}"
            + ("   -> protobuf probable, forcer le XML cote emetteur"
               if self.not_xml else ""))
        if self.sizes:
            say(f"  taille des datagrammes : {min(self.sizes)} a {max(self.sizes)} octets"
                f" (buffer a dimensionner en consequence)")
        say(f"  horodatages sans ms    : {self.timestamps_without_ms}"
            + ("   -> le parseur de dates doit accepter les deux formes"
               if self.timestamps_without_ms else ""))
        counts = ", ".join(f"{n} point={c}" for n, c in sorted(self.point_counts.items()))
        say(f"  <point> par event      : {counts}")

        say()
        say("--- geometries rencontrees ---")
        for convention, count in self.geometry.most_common():
            say(f"  {convention:<48} {count}")

        say()
        say("--- elements de detail et attributs ---")
        say("  (chaque ligne est un champ a prevoir dans la definition de sortie)")
        for element, count in sorted(self.detail_counts.items()):
            text = "  [#text]" if self.detail_text[element] else ""
            attributes = ", ".join(sorted(self.detail_attrs[element])) or "-"
            say(f"  {element:<22} {count:>5}  {attributes}{text}")
        say("===================================================")


def diagnose_bind_failure(exc: OSError, port: int) -> str:
    """Transforme un echec de bind en diagnostic actionnable.

    Cas rencontre en integration : WinError 10013 sur le serveur GeoEvent, le
    port etant deja detenu (exclusivement) par l'input GeoEvent lui-meme.
    """
    lines = [f"[listen] impossible d'ecouter sur le port UDP {port} : {exc}", ""]
    if getattr(exc, "winerror", None) in (10013, 10048) or exc.errno in (13, 98):
        lines += [
            "Le port est deja detenu par un autre processus, ou reserve par le systeme.",
            "Sur le serveur GeoEvent, c'est normalement l'input GeoEvent lui-meme :",
            "deux sockets UDP ne peuvent pas partager un port sous Windows.",
            "",
            "Identifier le detenteur :",
            f"    netstat -ano -p UDP | findstr {port}",
            "    Get-Process -Id <PID>",
            "",
            "Verifier que le port n'est pas dans une plage reservee (Hyper-V / WinNAT) :",
            "    netsh interface ipv4 show excludedportrange protocol=udp",
            "",
            "Contournements, par ordre de preference :",
            f"    1. ecouter sur un autre port : --port {port + 1}",
            "       (et emettre vers ce port : cot_generator.py --port ...)",
            "    2. arreter temporairement l'input GeoEvent, puis relancer ce listener",
            "    3. capturer avec Wireshark, qui n'a pas besoin de detenir le port",
        ]
    else:
        lines.append("Verifier les droits et la disponibilite du port.")
    return "\n".join(lines)


def open_socket(args: argparse.Namespace) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Buffer de reception genereux : le defaut de l'OS (~64 ko) sature des
    # quelques centaines de messages/s et provoque des pertes silencieuses.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    except OSError as exc:
        print(f"[listen] SO_RCVBUF non applique : {exc}", file=sys.stderr)
    try:
        sock.bind(("", args.port))
    except OSError as exc:
        sock.close()
        raise SystemExit(diagnose_bind_failure(exc, args.port)) from None

    first_octet = int(args.group.split(".")[0]) if args.group[0].isdigit() else 0
    if 224 <= first_octet <= 239:
        mreq = struct.pack(
            "4s4s",
            socket.inet_aton(args.group),
            socket.inet_aton(args.iface or "0.0.0.0"),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print(f"[listen] abonne au groupe {args.group}:{args.port}"
              + (f" via {args.iface}" if args.iface else ""), file=sys.stderr)
    else:
        print(f"[listen] ecoute unicast sur :{args.port}", file=sys.stderr)
    sock.settimeout(1.0)
    return sock


def source_live(args: argparse.Namespace):
    """Datagrammes issus du reseau, avec ecriture optionnelle d'une capture."""
    sock = open_socket(args)
    capture = None
    if args.save:
        capture = open(args.save, "w", encoding="utf-8")
        print(f"[listen] capture ecrite dans {args.save}", file=sys.stderr)
    started = time.monotonic()
    try:
        while True:
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                return
            try:
                datagram, sender = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if capture is not None:
                capture.write(json.dumps({
                    "t": round(time.monotonic() - started, 3),
                    "src": sender[0],
                    "raw": datagram.decode("utf-8", errors="replace"),
                }) + "\n")
                capture.flush()   # une session ATAK ne se rejoue pas
            yield datagram, sender
    finally:
        sock.close()
        if capture is not None:
            capture.close()


def source_replay(args: argparse.Namespace):
    """Datagrammes relus depuis une capture — analyse hors ligne, repetable."""
    print(f"[listen] relecture de {args.replay}", file=sys.stderr)
    with open(args.replay, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"[listen] ligne {number} illisible, ignoree", file=sys.stderr)
                continue
            yield record["raw"].encode("utf-8"), (record.get("src", "?"), 0)


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    received = 0
    errors = 0
    uids: Counter[str] = Counter()
    affiliations: Counter[str] = Counter()
    cot_types: Counter[str] = Counter()
    seqs: set[int] = set()
    last_seen: dict[str, float] = {}

    table: set[str] = set()
    if args.cot_types:
        try:
            table = load_cot_types(args.cot_types)
            print(f"[listen] CoTtypes.xml : {len(table)} type(s) connu(s)", file=sys.stderr)
        except OSError as exc:
            print(f"[listen] CoTtypes.xml illisible : {exc}", file=sys.stderr)

    inventory = SchemaInventory() if args.schema else None

    source = source_replay(args) if args.replay else source_live(args)
    if not args.replay:
        print("[listen] Ctrl+C pour arreter et afficher le bilan.", file=sys.stderr)
    try:
        for datagram, sender in source:
            received += 1
            if inventory is not None:
                # Avant tout decodage : l'inventaire doit voir le datagramme
                # tel qu'il arrive, y compris s'il est illisible.
                inventory.observe(datagram)
            if args.raw:
                print(datagram.decode("utf-8", errors="replace"))
                continue

            try:
                fields = flatten(datagram)
            except Exception as exc:  # datagramme non conforme (protobuf ? tronque ?)
                errors += 1
                print(f"[listen] ERREUR de decodage depuis {sender[0]} : {exc}",
                      file=sys.stderr)
                if args.show_bad:
                    print(datagram[:400], file=sys.stderr)
                continue

            uid = fields.get("uid", "<sans-uid>")
            uids[uid] += 1
            affiliations[fields.get("affiliation", "?")] += 1
            cot_types[fields.get("type", "?")] += 1
            last_seen[uid] = time.monotonic()

            match = re.search(r"SEQ=(\d+)", fields.get("detail_remarks", ""))
            if match:
                seqs.add(int(match.group(1)))

            if args.quiet:
                continue
            print(
                f"{fields.get('time','?'):<26} {uid:<18} "
                f"{fields.get('type','?'):<12} "
                f"{fields.get('affiliation','?'):<14} "
                f"{fields.get('detail_contact_callsign','-'):<12} "
                f"lat={fields.get('point_lat','?'):>11} "
                f"lon={fields.get('point_lon','?'):>11} "
                f"hae={fields.get('point_hae','?'):>8} "
                f"stale={fields.get('stale','?')}"
            )
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        source.close()

    elapsed = max(1e-6, time.monotonic() - started)
    print("", file=sys.stderr)
    print("=== BILAN =========================================", file=sys.stderr)
    if not args.replay:
        print(f"duree                : {elapsed:.1f} s", file=sys.stderr)
    print(f"datagrammes recus    : {received}"
          + (f" ({received / elapsed:.1f}/s)" if not args.replay else ""),
          file=sys.stderr)
    print(f"erreurs de decodage  : {errors}", file=sys.stderr)
    print(f"uid distincts        : {len(uids)}", file=sys.stderr)
    if affiliations:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(affiliations.items()))
        print(f"affiliations         : {detail}", file=sys.stderr)
    if uids and args.per_track:
        print("--- messages par uid ---", file=sys.stderr)
        for uid, count in sorted(uids.items()):
            print(f"  {uid:<20} {count}", file=sys.stderr)

    if seqs:
        lo, hi = min(seqs), max(seqs)
        expected = hi - lo + 1
        missing = sorted(set(range(lo, hi + 1)) - seqs)
        print("--- continuite des sequences ---", file=sys.stderr)
        print(f"  plage recue       : {lo} -> {hi} ({expected} attendus)",
              file=sys.stderr)
        print(f"  recus distincts   : {len(seqs)}", file=sys.stderr)
        print(f"  manquants         : {len(missing)}"
              + (f"  {missing[:20]}{' ...' if len(missing) > 20 else ''}"
                 if missing else ""), file=sys.stderr)
        if received > len(seqs):
            print(f"  DOUBLONS          : {received - len(seqs)} message(s) recus "
                  f"plus d'une fois", file=sys.stderr)
        if lo > 1:
            print(f"  NOTE : la sequence demarre a {lo}, pas a 1 — l'ecoute a "
                  f"commence apres l'emetteur ({lo - 1} message(s) hors mesure)",
                  file=sys.stderr)

    if cot_types:
        print("--- types CoT observes ---", file=sys.stderr)
        missing: list[str] = []
        for cot_type, count in sorted(cot_types.items()):
            if not table:
                print(f"  {cot_type:<24} {count}", file=sys.stderr)
                continue
            hit = lookup_type(cot_type, table)
            if hit == type_key(cot_type):
                verdict = f"exact : {hit}"
            elif hit:
                # Repli sur un ancetre : la description sera vague.
                verdict = f"PARTIEL, retombe sur '{hit}'"
                missing.append(cot_type)
            else:
                verdict = "ABSENT de la table"
                missing.append(cot_type)
            print(f"  {cot_type:<24} {count:>6}   {verdict}", file=sys.stderr)

        if missing:
            print("", file=sys.stderr)
            print("--- types imprecis : a ajouter dans CoTtypes.xml ---",
                  file=sys.stderr)
            for cot_type in missing:
                print(f'  <cot cot="{type_key(cot_type)}" desc="A DOCUMENTER" />',
                      file=sys.stderr)
            print("", file=sys.stderr)
            print("Rappel : la table ne fournit que `typeDescription`. Le champ",
                  file=sys.stderr)
            print("`2525b` est construit par l'adaptateur depuis la structure",
                  file=sys.stderr)
            print("`a-<affiliation>-<dimension>-...` et restera vide pour les",
                  file=sys.stderr)
            print("types non-atom (b-, u-, t-).", file=sys.stderr)

    print("===================================================", file=sys.stderr)
    if inventory is not None:
        inventory.report(sys.stderr)
    return 0 if errors == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ecoute de controle du flux CoT (verification hors GeoEvent).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--group", default=DEFAULT_GROUP,
                        help="groupe multicast a rejoindre (ou 0.0.0.0 pour unicast)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port UDP d'ecoute")
    parser.add_argument("--iface", default=None,
                        help="IP de l'interface locale sur laquelle s'abonner")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="duree d'ecoute en secondes (0 = illimite)")
    parser.add_argument("--raw", action="store_true",
                        help="afficher le XML brut sans le decoder")
    parser.add_argument("--quiet", action="store_true",
                        help="ne rien afficher par message, seulement le bilan final")
    parser.add_argument("--per-track", action="store_true",
                        help="detailler le compte de messages par uid dans le bilan")
    parser.add_argument("--save", default=None, metavar="FICHIER",
                        help="enregistrer les datagrammes bruts (JSON Lines) — "
                             "une session ATAK ne se rejoue pas, la capture si")
    parser.add_argument("--replay", default=None, metavar="FICHIER",
                        help="analyser une capture au lieu du reseau : autant de "
                             "relectures que voulu, sans le terrain")
    parser.add_argument("--cot-types", default=None,
                        help="chemin de CoTtypes.xml — signale les types observes "
                             "absents de la table (inventaire ATAK en phase 2)")
    parser.add_argument("--rcvbuf", type=int, default=16 * 1024 * 1024,
                        help="taille du buffer de reception UDP, en octets")
    parser.add_argument("--schema", action="store_true",
                        help="inventorier ce qu'un receiver devra traiter : "
                             "cadrage (prologue, messages par datagramme, XML ou "
                             "protobuf), conventions geometriques, et elements de "
                             "`detail` avec leurs attributs")
    parser.add_argument("--show-bad", action="store_true",
                        help="afficher les octets des datagrammes non decodables")
    return parser


if __name__ == "__main__":
    sys.exit(run(build_parser().parse_args()))
