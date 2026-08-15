#!/usr/bin/env python3
"""Generateur de pistes CoT (Cursor on Target) vers un groupe multicast TAK.

POC ISRBOX / 33e ESRA — phase 1 : banc de test CoT non classifie.

Contraintes de conception :
  - bibliotheque standard Python uniquement (environnement cloisonne) ;
  - un datagramme UDP = un et un seul message CoT XML (convention TAK) ;
  - horodatages UTC ISO 8601 avec suffixe Z ;
  - identifiants de piste (uid) stables dans le temps.

Usage minimal :
    python cot_generator.py

Voir README.md pour les exemples de ligne de commande.
"""

from __future__ import annotations

import argparse
import math
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape, quoteattr

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------

DEFAULT_GROUP = "239.2.3.1"          # groupe SA mesh par defaut de TAK
DEFAULT_PORT = 6969
DEFAULT_TTL = 1                      # 1 = ne sort pas du sous-reseau local
DEFAULT_CENTER_LAT = 45.658          # region de Cognac
DEFAULT_CENTER_LON = -0.317

# Ellipsoide WGS-84
WGS84_A = 6378137.0
WGS84_F = 1.0 / 298.257223563
WGS84_B = WGS84_A * (1.0 - WGS84_F)

# Affiliation : 2e caractere du type CoT (cf. section 3 du prompt)
AFFILIATION_CODES = {
    "f": "FRIEND",
    "h": "HOSTILE",
    "n": "NEUTRAL",
    "u": "UNKNOWN",
    "p": "PENDING",
    "a": "ASSUMED_FRIEND",
    "s": "SUSPECT",
}

# Dimension de bataille : 3e caractere du type CoT
BATTLE_DIMENSIONS = {
    "A": "AIR",
    "G": "GROUND",
    "S": "SURFACE",
    "U": "SUBSURFACE",
    "P": "SPACE",
}

# Profils de piste : (suffixe de type apres a-<aff>-, vitesse m/s, altitude m)
# Le suffixe complete le type CoT : "a" + "-" + affiliation + "-" + suffixe.
TRACK_PROFILES = {
    "AIR": {
        "suffix": "A-M-F",          # air / militaire / fixed wing
        "speed_ms": (120.0, 260.0),
        "hae_m": (900.0, 10000.0),
    },
    "GROUND": {
        "suffix": "G-U-C",          # sol / unite / combat
        "speed_ms": (2.0, 22.0),
        "hae_m": (20.0, 200.0),
    },
    "SURFACE": {
        "suffix": "S-C-L",          # surface / combattant / ligne
        "speed_ms": (3.0, 15.0),
        "hae_m": (0.0, 0.0),
    },
}

CALLSIGN_ALPHABET = [
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL",
    "INDIA", "JULIETT", "KILO", "LIMA", "MIKE", "NOVEMBER", "OSCAR", "PAPA",
    "QUEBEC", "ROMEO", "SIERRA", "TANGO", "UNIFORM", "VICTOR", "WHISKEY",
    "XRAY", "YANKEE", "ZULU",
]


# --------------------------------------------------------------------------
# Navigation geodesique — probleme direct de Vincenty sur WGS-84
# --------------------------------------------------------------------------

def vincenty_direct(lat_deg: float, lon_deg: float, bearing_deg: float,
                    distance_m: float) -> tuple[float, float]:
    """Projette un point de `distance_m` metres au cap `bearing_deg`.

    Resout le probleme geodesique direct sur l'ellipsoide WGS-84 (Vincenty).
    Retourne (latitude, longitude) en degres decimaux signes.
    """
    if distance_m == 0.0:
        return lat_deg, lon_deg

    phi1 = math.radians(lat_deg)
    lambda1 = math.radians(lon_deg)
    alpha1 = math.radians(bearing_deg)

    sin_alpha1 = math.sin(alpha1)
    cos_alpha1 = math.cos(alpha1)

    tan_u1 = (1.0 - WGS84_F) * math.tan(phi1)
    cos_u1 = 1.0 / math.sqrt(1.0 + tan_u1 * tan_u1)
    sin_u1 = tan_u1 * cos_u1

    sigma1 = math.atan2(tan_u1, cos_alpha1)
    sin_alpha = cos_u1 * sin_alpha1
    cos_sq_alpha = 1.0 - sin_alpha * sin_alpha
    u_sq = cos_sq_alpha * (WGS84_A ** 2 - WGS84_B ** 2) / (WGS84_B ** 2)

    big_a = 1.0 + u_sq / 16384.0 * (4096.0 + u_sq * (-768.0 + u_sq * (320.0 - 175.0 * u_sq)))
    big_b = u_sq / 1024.0 * (256.0 + u_sq * (-128.0 + u_sq * (74.0 - 47.0 * u_sq)))

    sigma = distance_m / (WGS84_B * big_a)
    sigma_prev = 0.0
    cos2_sigma_m = 0.0
    sin_sigma = 0.0
    cos_sigma = 0.0

    for _ in range(200):
        cos2_sigma_m = math.cos(2.0 * sigma1 + sigma)
        sin_sigma = math.sin(sigma)
        cos_sigma = math.cos(sigma)
        delta_sigma = big_b * sin_sigma * (
            cos2_sigma_m + big_b / 4.0 * (
                cos_sigma * (-1.0 + 2.0 * cos2_sigma_m ** 2)
                - big_b / 6.0 * cos2_sigma_m * (-3.0 + 4.0 * sin_sigma ** 2)
                * (-3.0 + 4.0 * cos2_sigma_m ** 2)
            )
        )
        sigma_prev = sigma
        sigma = distance_m / (WGS84_B * big_a) + delta_sigma
        if abs(sigma - sigma_prev) < 1e-12:
            break

    tmp = sin_u1 * sin_sigma - cos_u1 * cos_sigma * cos_alpha1
    phi2 = math.atan2(
        sin_u1 * cos_sigma + cos_u1 * sin_sigma * cos_alpha1,
        (1.0 - WGS84_F) * math.sqrt(sin_alpha ** 2 + tmp ** 2),
    )
    lambda_ = math.atan2(
        sin_sigma * sin_alpha1,
        cos_u1 * cos_sigma - sin_u1 * sin_sigma * cos_alpha1,
    )
    big_c = WGS84_F / 16.0 * cos_sq_alpha * (4.0 + WGS84_F * (4.0 - 3.0 * cos_sq_alpha))
    big_l = lambda_ - (1.0 - big_c) * WGS84_F * sin_alpha * (
        sigma + big_c * sin_sigma * (
            cos2_sigma_m + big_c * cos_sigma * (-1.0 + 2.0 * cos2_sigma_m ** 2)
        )
    )

    lambda2 = lambda1 + big_l
    lat2 = math.degrees(phi2)
    lon2 = (math.degrees(lambda2) + 540.0) % 360.0 - 180.0
    return lat2, lon2


# --------------------------------------------------------------------------
# Modele de piste
# --------------------------------------------------------------------------

@dataclass
class Track:
    """Une piste simulee : uid stable, cap et vitesse constants."""

    uid: str
    callsign: str
    cot_type: str
    affiliation: str
    dimension: str
    lat: float
    lon: float
    hae_m: float
    course_deg: float
    speed_ms: float
    ce_m: float
    le_m: float
    remarks: str
    dies_after_tick: int | None = None   # None = piste permanente
    ticks: int = field(default=0)

    @property
    def alive(self) -> bool:
        return self.dies_after_tick is None or self.ticks < self.dies_after_tick

    def advance(self, dt_s: float) -> None:
        """Recalcule la position apres `dt_s` secondes de vol au cap courant."""
        self.ticks += 1
        if self.speed_ms <= 0.0:
            return
        self.lat, self.lon = vincenty_direct(
            self.lat, self.lon, self.course_deg, self.speed_ms * dt_s
        )


# --------------------------------------------------------------------------
# Construction du XML CoT
# --------------------------------------------------------------------------

def iso_utc(moment: datetime) -> str:
    """Horodatage ISO 8601 UTC avec suffixe Z et millisecondes."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{moment.microsecond // 1000:03d}Z"


def build_cot(track: Track, now: datetime, stale_s: int,
              include_remarks: bool = True,
              xml_declaration: bool = True,
              opex: str = "", qos: str = "",
              seq: int | None = None) -> str:
    """Serialise une piste en message CoT XML (une seule ligne, un datagramme).

    `xml_declaration` : emettre ou non le prologue `<?xml ... ?>`.
    ATAK et la convention CoT l'incluent, mais l'adaptateur XML de GeoEvent
    Server concatene les datagrammes recus avant de parser : un prologue en
    milieu de flux est alors illegal et fait rejeter tout le bloc. Voir
    docs/geoevent-config.md.
    """
    time_s = iso_utc(now)
    stale_str = iso_utc(now + timedelta(seconds=stale_s))

    detail = [
        f'<contact callsign={quoteattr(track.callsign)}/>',
        f'<track course="{track.course_deg:.1f}" speed="{track.speed_ms:.1f}"/>',
    ]
    # Le numero de sequence voyage dans <remarks> : c'est le seul champ de texte
    # libre que toute la chaine conserve. Il permet de reperer exactement quels
    # messages manquent en bout de chaine, au lieu de comparer deux compteurs.
    remarks = track.remarks if include_remarks else ""
    if seq is not None:
        remarks = f"SEQ={seq:06d} {remarks}".strip()
    if remarks:
        detail.append(f'<remarks>{escape(remarks)}</remarks>')

    # Le prologue est suivi d'un retour ligne : c'est la convention TAK (§7 du
    # cadrage), et c'est exactement ce qu'emet WinTAK 5.7 — verifie sur capture
    # reelle le 21/07/2026. Notre version collait le prologue au <event>.
    prolog = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              if xml_declaration else '')

    # `opex` et `qos` sont optionnels dans le schema CoT. L'adaptateur CoT de
    # GeoEvent leve toutefois une NullPointerException quand ils sont absents ;
    # les renseigner supprime ce bruit dans les logs.
    optional = ""
    if opex:
        optional += f' opex={quoteattr(opex)}'
    if qos:
        optional += f' qos={quoteattr(qos)}'

    return (
        f'{prolog}'
        f'<event version="2.0"'
        f' uid={quoteattr(track.uid)}'
        f' type={quoteattr(track.cot_type)}'
        f' time="{time_s}" start="{time_s}" stale="{stale_str}" how="m-g"'
        f'{optional}>'
        f'<point lat="{track.lat:.6f}" lon="{track.lon:.6f}"'
        f' hae="{track.hae_m:.1f}" ce="{track.ce_m:.1f}" le="{track.le_m:.1f}"/>'
        f'<detail>{"".join(detail)}</detail>'
        '</event>'
    )


# --------------------------------------------------------------------------
# Entites non ponctuelles : polygones et routes
# --------------------------------------------------------------------------

# Duree de vie des objets dessines. WinTAK place `stale` a +1 an sur les
# marqueurs et les formes : un point d'interet n'est pas une piste, il ne doit
# pas s'effacer tout seul. Reproduire ce comportement est necessaire pour tester
# la purge, qui ne doit PAS les faire disparaitre.
SHAPE_STALE_S = 365 * 24 * 3600


@dataclass
class Shape:
    """Une entite non ponctuelle : polygone ferme ou route ouverte.

    Contrairement a Track, elle ne se deplace pas — un objet dessine est
    rediffuse a l'identique. Son `point` CoT est son centroide : c'est une
    position de reference, pas sa geometrie.
    """

    uid: str
    callsign: str
    cot_type: str
    vertices: list[tuple[float, float]]
    closed: bool
    ticks: int = field(default=0)

    @property
    def alive(self) -> bool:
        return True

    def advance(self, dt_s: float) -> None:
        self.ticks += 1

    @property
    def centroid(self) -> tuple[float, float]:
        return (sum(v[0] for v in self.vertices) / len(self.vertices),
                sum(v[1] for v in self.vertices) / len(self.vertices))


def build_shape_cot(shape: Shape, now: datetime, encoding: str,
                    xml_declaration: bool = True,
                    opex: str = "", qos: str = "") -> str:
    """Serialise un polygone ou une route en CoT.

    La geometrie d'une entite non ponctuelle ne tient pas dans `<point>`. Deux
    conventions coexistent, et savoir laquelle l'adaptateur sait lire est
    precisement l'objet du test — d'ou `encoding` :

    `link`  — convention ATAK : un `<link point="lat,lon,hae"/>` par sommet.
              C'est ce qu'emettent les outils de dessin du client.
    `shape` — convention du schema MITRE `CoT_shape.xsd` :
              `<shape><polyline closed="..."><vertex lat lon hae/></polyline></shape>`.
    `both`  — les deux dans le meme message, pour comparer sur un seul tir.

    Reserve connue avant meme le test : l'adaptateur force tout element nomme
    `shape` au type Geometry, ce qui ecrase le groupe et supprime `polyline` et
    `vertex` de la definition. Cote `link`, la definition livree declare une
    cardinalite One : un seul lien serait lu. Voir docs/cot-connector-esri.md.
    """
    time_s = iso_utc(now)
    stale_str = iso_utc(now + timedelta(seconds=SHAPE_STALE_S))
    lat, lon = shape.centroid

    detail = [f'<contact callsign={quoteattr(shape.callsign)}/>']

    if encoding in ("link", "both"):
        for index, (v_lat, v_lon) in enumerate(shape.vertices):
            # Les routes referencent des waypoints ; un dessin libre n'a que
            # des sommets anonymes. On reproduit les deux formes.
            if shape.cot_type.startswith("b-m-r"):
                detail.append(
                    f'<link uid={quoteattr(f"{shape.uid}.{index}")}'
                    f' type="b-m-p-w" relation="c"'
                    f' point="{v_lat:.6f},{v_lon:.6f},0.0"/>')
            else:
                detail.append(f'<link point="{v_lat:.6f},{v_lon:.6f},0.0"/>')

    if encoding in ("shape", "both"):
        vertices = "".join(f'<vertex lat="{v_lat:.6f}" lon="{v_lon:.6f}" hae="0.0"/>'
                           for v_lat, v_lon in shape.vertices)
        detail.append(f'<shape><polyline closed="{str(shape.closed).lower()}">'
                      f'{vertices}</polyline></shape>')

    # Attributs de rendu emis par ATAK. Sans interet fonctionnel ici, mais ils
    # font partie du message reel et testent la tolerance de l'adaptateur aux
    # elements qu'aucun XSD ne decrit.
    detail.append('<strokeColor value="-65536"/><strokeWeight value="4.0"/>')
    if shape.closed:
        detail.append('<fillColor value="-1877995776"/>')
    detail.append('<archive/>')

    prolog = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              if xml_declaration else '')
    optional = ""
    if opex:
        optional += f' opex={quoteattr(opex)}'
    if qos:
        optional += f' qos={quoteattr(qos)}'

    return (
        f'{prolog}'
        f'<event version="2.0"'
        f' uid={quoteattr(shape.uid)}'
        f' type={quoteattr(shape.cot_type)}'
        f' time="{time_s}" start="{time_s}" stale="{stale_str}" how="h-e"'
        f'{optional}>'
        f'<point lat="{lat:.6f}" lon="{lon:.6f}"'
        f' hae="0.0" ce="9999999.0" le="9999999.0"/>'
        f'<detail>{"".join(detail)}</detail>'
        '</event>'
    )


def make_shapes(args: argparse.Namespace, rng: random.Random) -> list[Shape]:
    """Construit les polygones et les routes demandes, autour du meme centre."""
    shapes: list[Shape] = []

    for index in range(args.polygons):
        # Centre tire dans la zone, puis quatre coins geodesiques : le rectangle
        # reste correct meme loin de l'equateur, contrairement a un +/- degres.
        bearing = rng.uniform(0.0, 360.0)
        offset_km = rng.uniform(0.0, args.radius_km)
        lat, lon = vincenty_direct(args.center_lat, args.center_lon,
                                   bearing, offset_km * 1000.0)
        half_diag = args.shape_size_km * 1000.0 * math.sqrt(2.0) / 2.0
        corners = [vincenty_direct(lat, lon, angle, half_diag)
                   for angle in (315.0, 45.0, 135.0, 225.0)]
        shapes.append(Shape(
            uid=f"{args.uid_prefix}-POLY-{index + 1:04d}",
            callsign=f"ZONE-{index + 1}",
            # `u-d-f` : dessin libre. Absent de CoTtypes.xml — le test porte
            # donc aussi sur le comportement face a un type inconnu.
            cot_type="u-d-f",
            vertices=corners,
            closed=True,
        ))

    for index in range(args.routes):
        bearing = rng.uniform(0.0, 360.0)
        offset_km = rng.uniform(0.0, args.radius_km)
        lat, lon = vincenty_direct(args.center_lat, args.center_lon,
                                   bearing, offset_km * 1000.0)
        heading = rng.uniform(0.0, 360.0)
        vertices = [(lat, lon)]
        for _ in range(args.route_legs):
            heading += rng.uniform(-45.0, 45.0)
            lat, lon = vincenty_direct(lat, lon, heading,
                                       args.shape_size_km * 1000.0)
            vertices.append((lat, lon))
        shapes.append(Shape(
            uid=f"{args.uid_prefix}-ROUTE-{index + 1:04d}",
            callsign=f"ROUTE-{index + 1}",
            cot_type="b-m-r",   # present dans CoTtypes.xml
            vertices=vertices,
            closed=False,
        ))

    return shapes


# --------------------------------------------------------------------------
# Generation du jeu de pistes
# --------------------------------------------------------------------------

def parse_affiliation_mix(spec: str) -> list[str]:
    """Convertit "f=4,h=2,n=1,u=1" en liste ponderee de codes d'affiliation."""
    weighted: list[str] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            code, _, weight_s = item.partition("=")
        else:
            code, weight_s = item, "1"
        code = code.strip().lower()
        if code not in AFFILIATION_CODES:
            raise argparse.ArgumentTypeError(
                f"code d'affiliation inconnu : {code!r} "
                f"(attendus : {', '.join(sorted(AFFILIATION_CODES))})"
            )
        try:
            weight = int(weight_s)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"poids non entier pour {code!r} : {weight_s!r}"
            ) from None
        weighted.extend([code] * max(0, weight))
    if not weighted:
        raise argparse.ArgumentTypeError("repartition d'affiliations vide")
    return weighted


def make_tracks(args: argparse.Namespace, rng: random.Random) -> list[Track]:
    """Cree les N pistes initiales, reparties autour du point central."""
    mix = parse_affiliation_mix(args.affiliations)
    dimensions = [d.strip().upper() for d in args.dimensions.split(",") if d.strip()]
    for dim in dimensions:
        if dim not in TRACK_PROFILES:
            raise SystemExit(
                f"dimension non supportee : {dim} "
                f"(attendues : {', '.join(TRACK_PROFILES)})"
            )

    tracks: list[Track] = []
    for index in range(args.tracks):
        aff_code = mix[index % len(mix)]
        dim = dimensions[index % len(dimensions)]
        profile = TRACK_PROFILES[dim]

        # Dispersion initiale dans un disque de rayon `--radius-km`.
        bearing = rng.uniform(0.0, 360.0)
        distance = args.radius_km * 1000.0 * math.sqrt(rng.random())
        lat, lon = vincenty_direct(args.center_lat, args.center_lon, bearing, distance)

        speed_lo, speed_hi = profile["speed_ms"]
        hae_lo, hae_hi = profile["hae_m"]

        word = CALLSIGN_ALPHABET[index % len(CALLSIGN_ALPHABET)]
        callsign = f"{word}-{index // len(CALLSIGN_ALPHABET) + 1:02d}"

        dies = None
        if args.dead_after > 0 and index < args.dead_tracks:
            dies = args.dead_after

        tracks.append(Track(
            uid=f"{args.uid_prefix}-{index + 1:04d}",
            callsign=callsign,
            cot_type=f"a-{aff_code}-{profile['suffix']}",
            affiliation=AFFILIATION_CODES[aff_code],
            dimension=dim,
            lat=lat,
            lon=lon,
            hae_m=rng.uniform(hae_lo, hae_hi),
            course_deg=rng.uniform(0.0, 360.0),
            speed_ms=rng.uniform(speed_lo, speed_hi),
            ce_m=rng.uniform(5.0, 40.0),
            le_m=rng.uniform(5.0, 20.0),
            remarks=f"Piste de test {AFFILIATION_CODES[aff_code]} / {dim}",
            dies_after_tick=dies,
        ))
    return tracks


# --------------------------------------------------------------------------
# Emission
# --------------------------------------------------------------------------

class UdpSender:
    """Emission UDP — multicast ou unicast selon l'adresse cible."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.target = (args.group, args.port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        first_octet = int(args.group.split(".")[0]) if args.group[0].isdigit() else 0
        if 224 <= first_octet <= 239:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                                 struct.pack("b", args.ttl))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP,
                                 struct.pack("b", 1 if args.loopback else 0))
            if args.iface:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                     socket.inet_aton(args.iface))

    def send(self, payload: bytes) -> bool:
        self.sock.sendto(payload, self.target)
        return True

    def close(self) -> None:
        self.sock.close()


class TcpSender:
    """Emission TCP vers le connecteur `Receive Cursor on Target Over TCP Socket`.

    GeoEvent est en mode SERVER : c'est lui qui ecoute, le generateur se
    connecte en client.

    Deux modes, la description du connecteur Esri mentionnant une socket « qui
    s'ouvre et se ferme avant et apres reception du message » :
      - `persistent` (defaut) : une seule connexion, tous les messages dessus.
        L'adaptateur CoT sait decouper le flux, c'est le mode le plus efficace.
      - `per-message` : connexion, envoi, fermeture pour chaque message. Plus
        conforme a la description, mais tres couteux en montee en charge.

    La connexion est retablie automatiquement si le serveur la coupe : un
    redemarrage de l'input GeoEvent ne doit pas tuer le generateur.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self.target = (args.group, args.port)
        self.per_message = args.tcp_per_message
        self.sock: socket.socket | None = None
        self.retry_after = 0.0
        self.failures = 0

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(self.target)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def send(self, payload: bytes) -> bool:
        if self.per_message:
            try:
                sock = self._connect()
            except OSError as exc:
                self._note_failure(exc)
                return False
            try:
                sock.sendall(payload)
                return True
            except OSError as exc:
                self._note_failure(exc)
                return False
            finally:
                sock.close()

        if self.sock is None:
            # Ne pas marteler un serveur absent : une tentative par seconde.
            if time.monotonic() < self.retry_after:
                return False
            try:
                self.sock = self._connect()
                print(f"[cot] connecte a {self.target[0]}:{self.target[1]} (TCP)",
                      file=sys.stderr)
                self.failures = 0
            except OSError as exc:
                self._note_failure(exc)
                self.retry_after = time.monotonic() + 1.0
                return False

        try:
            self.sock.sendall(payload)
            return True
        except OSError as exc:
            self._note_failure(exc)
            self.sock.close()
            self.sock = None
            self.retry_after = time.monotonic() + 1.0
            return False

    def _note_failure(self, exc: OSError) -> None:
        self.failures += 1
        if self.failures <= 3:
            print(f"[cot] TCP {self.target[0]}:{self.target[1]} : {exc}", file=sys.stderr)
            if self.failures == 3:
                print("[cot] (erreurs TCP suivantes silencieuses)", file=sys.stderr)

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()


def open_sender(args: argparse.Namespace):
    return TcpSender(args) if args.transport == "tcp" else UdpSender(args)


def run(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    tracks = make_tracks(args, rng)
    shapes = make_shapes(args, rng)
    period = 1.0 / args.rate
    sender = None if args.dry_run else open_sender(args)

    if args.dry_run:
        mode = "DRY-RUN, aucune emission"
    elif args.transport == "tcp":
        mode = "TCP " + ("per-message" if args.tcp_per_message else "persistant")
    else:
        mode = f"UDP, TTL {args.ttl}"
    inventory = f"{len(tracks)} piste(s)"
    if shapes:
        polygons = sum(1 for s in shapes if s.closed)
        inventory += f", {polygons} polygone(s), {len(shapes) - polygons} route(s)" \
                     f" [encodage {args.shape_encoding}]"
    print(f"[cot] {inventory} -> {args.group}:{args.port} ({mode})",
          file=sys.stderr)
    print(f"[cot] cadence {args.rate} Hz/piste, stale +{args.stale}s, "
          f"centre {args.center_lat}/{args.center_lon} rayon {args.radius_km} km",
          file=sys.stderr)
    if args.dead_after > 0:
        print(f"[cot] {args.dead_tracks} piste(s) morte(s) apres {args.dead_after} ticks",
              file=sys.stderr)
    print("[cot] Ctrl+C pour arreter.", file=sys.stderr)

    started = time.monotonic()
    sent = 0
    dropped = 0
    tick = 0
    try:
        while True:
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                break

            tick_start = started + tick * period
            now = datetime.now(timezone.utc)
            # Les formes sont rediffusees a chaque tick, comme les pistes : un
            # objet dessine est reemis tel quel par TAK. Elles entrent dans le
            # lissage, sans quoi elles formeraient a elles seules une rafale.
            active = [t for t in tracks if t.alive] + shapes
            # Lissage : repartir les messages sur l'intervalle du tick plutot que
            # de les emettre en rafale. Evite que l'adaptateur CoT de GeoEvent
            # recoive deux messages dans un meme buffer (echec de parse
            # multi-racines), et supprime les pics mesures au test de charge.
            slice_s = period / len(active) if (args.spread and active) else 0.0

            for index, track in enumerate(active):
                if slice_s:
                    delay = tick_start + index * slice_s - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    now = datetime.now(timezone.utc)
                if isinstance(track, Shape):
                    message = build_shape_cot(track, now, args.shape_encoding,
                                              xml_declaration=not args.no_xml_decl,
                                              opex=args.opex, qos=args.qos)
                else:
                    message = build_cot(track, now, args.stale,
                                        include_remarks=not args.no_remarks,
                                        xml_declaration=not args.no_xml_decl,
                                        opex=args.opex, qos=args.qos,
                                        seq=sent + dropped + 1 if args.seq else None)
                payload = (message + args.terminator).encode("utf-8")
                if args.dry_run:
                    # Ecrire la charge utile exacte : le dry-run doit montrer ce
                    # qui partirait reellement, terminateur compris.
                    sys.stdout.buffer.write(payload + b"\n")
                    sent += 1
                elif sender.send(payload):
                    sent += 1
                else:
                    # En TCP, une coupure ne doit pas arreter la simulation :
                    # les pistes continuent d'avancer, l'envoi reprendra seul.
                    dropped += 1
                track.advance(period)

            tick += 1
            alive = sum(1 for t in tracks if t.alive)
            if args.verbose and tick % max(1, int(args.rate * 10)) == 0:
                print(f"[cot] tick {tick} | {sent} message(s) emis | "
                      f"{alive} piste(s) active(s)", file=sys.stderr)
            if alive == 0 and not shapes:
                print("[cot] plus aucune piste active, arret.", file=sys.stderr)
                break

            # Cadencement sans derive : on vise l'instant theorique du prochain tick.
            next_at = started + tick * period
            delay = next_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        if sender is not None:
            sender.close()

    elapsed = time.monotonic() - started
    rate = sent / elapsed if elapsed > 0 else 0.0
    print(f"[cot] termine : {sent} message(s) en {elapsed:.1f}s "
          f"({rate:.1f} msg/s)", file=sys.stderr)
    if dropped:
        print(f"[cot] {dropped} message(s) NON emis (destination injoignable)",
              file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generateur de pistes CoT vers un groupe multicast TAK.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    net = parser.add_argument_group("reseau")
    net.add_argument("--transport", choices=("udp", "tcp"), default="udp",
                     help="udp = mesh TAK ; tcp = connecteur CoT Esri "
                          "'Receive Cursor on Target Over TCP Socket'")
    net.add_argument("--tcp-per-message", action="store_true",
                     help="TCP : une connexion par message (defaut : connexion persistante)")
    net.add_argument("--group", default=DEFAULT_GROUP,
                     help="adresse de destination (multicast TAK, ou IP du serveur)")
    net.add_argument("--port", type=int, default=DEFAULT_PORT,
                     help="port de destination (5570 pour le connecteur CoT TCP)")
    net.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                     help="TTL multicast (augmenter si routage inter-VLAN)")
    net.add_argument("--iface", default=None,
                     help="IP de l'interface locale d'emission multicast")
    net.add_argument("--loopback", action="store_true",
                     help="activer le retour local du multicast (test sur une seule machine)")

    sim = parser.add_argument_group("simulation")
    sim.add_argument("--tracks", type=int, default=10, help="nombre de pistes simulees")
    sim.add_argument("--rate", type=float, default=1.0,
                     help="cadence d'emission en Hz par piste")
    sim.add_argument("--center-lat", type=float, default=DEFAULT_CENTER_LAT,
                     help="latitude du centre de la zone de depart")
    sim.add_argument("--center-lon", type=float, default=DEFAULT_CENTER_LON,
                     help="longitude du centre de la zone de depart")
    sim.add_argument("--radius-km", type=float, default=25.0,
                     help="rayon de dispersion initiale des pistes, en km")
    sim.add_argument("--affiliations", default="f=4,h=2,n=1,u=1",
                     help="repartition ponderee des affiliations (f,h,n,u,p,a,s)")
    sim.add_argument("--dimensions", default="AIR",
                     help="dimensions de bataille utilisees : AIR,GROUND,SURFACE")
    sim.add_argument("--uid-prefix", default="SIM-TRACK",
                     help="prefixe des uid generes (doit rester stable entre runs)")
    sim.add_argument("--seed", type=int, default=1337,
                     help="graine aleatoire (reproductibilite du scenario)")

    shp = parser.add_argument_group("entites non ponctuelles")
    shp.add_argument("--polygons", type=int, default=0,
                     help="nombre de polygones fermes (rectangles, type u-d-f)")
    shp.add_argument("--routes", type=int, default=0,
                     help="nombre de routes ouvertes (type b-m-r)")
    shp.add_argument("--shape-size-km", type=float, default=2.0,
                     help="cote du rectangle, ou longueur d'un troncon de route, en km")
    shp.add_argument("--route-legs", type=int, default=4,
                     help="nombre de troncons par route (sommets = troncons + 1)")
    shp.add_argument("--shape-encoding", choices=("link", "shape", "both"),
                     default="link",
                     help="portage de la geometrie : `link` = convention ATAK "
                          "(un <link point> par sommet), `shape` = schema MITRE "
                          "(<shape><polyline><vertex>), `both` = les deux, pour "
                          "comparer ce que l'adaptateur sait lire")

    cot = parser.add_argument_group("message CoT")
    cot.add_argument("--stale", type=int, default=60,
                     help="delai avant expiration, en secondes (stale = time + delai)")
    cot.add_argument("--no-remarks", action="store_true",
                     help="ne pas emettre l'element <remarks>")
    cot.add_argument("--seq", action="store_true",
                     help="inserer un numero de sequence dans <remarks> "
                          "(SEQ=000001) — permet d'identifier precisement les "
                          "messages perdus en bout de chaine")
    cot.add_argument("--opex", default="",
                     help="attribut opex (o|e|s[-nom]) — ex. 's-POC' pour simulation. "
                          "Vide = non emis ; le renseigner supprime une NPE de "
                          "l'adaptateur CoT de GeoEvent")
    cot.add_argument("--qos", default="",
                     help="attribut qos (priorite-overtaking-securite) — ex. '1-r-c'. "
                          "Meme remarque que --opex")
    cot.add_argument("--terminator", default="",
                     help=r"caracteres ajoutes apres chaque message (ex. '\n') — "
                          r"certains adaptateurs ont besoin d'un delimiteur pour "
                          r"decouper un flux concatene")
    cot.add_argument("--no-xml-decl", action="store_true",
                     help="omettre le prologue <?xml ...?> — REQUIS pour l'adaptateur "
                          "XML de GeoEvent Server, qui concatene les datagrammes")

    run_grp = parser.add_argument_group("execution")
    run_grp.add_argument("--spread", action="store_true",
                         help="repartir les messages sur l'intervalle du tick au lieu "
                              "d'emettre en rafale — recommande vers GeoEvent, dont "
                              "l'adaptateur CoT echoue si deux messages arrivent dans "
                              "le meme buffer")
    run_grp.add_argument("--duration", type=float, default=0.0,
                         help="duree d'emission en secondes (0 = illimite)")
    run_grp.add_argument("--dead-after", type=int, default=0,
                         help="nombre de ticks apres lequel les pistes 'mortes' cessent d'emettre (0 = desactive)")
    run_grp.add_argument("--dead-tracks", type=int, default=1,
                         help="nombre de pistes concernees par --dead-after")
    run_grp.add_argument("--dry-run", action="store_true",
                         help="afficher les messages sur stdout sans rien emettre")
    run_grp.add_argument("--verbose", action="store_true",
                         help="statistiques periodiques sur stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Rendre les echappements utilisables depuis la ligne de commande : le shell
    # transmet "\n" en deux caracteres, pas en saut de ligne.
    args.terminator = args.terminator.replace("\\r", "\r").replace("\\n", "\n")
    if args.tracks < 0:
        raise SystemExit("--tracks ne peut pas etre negatif")
    if args.tracks < 1 and args.polygons < 1 and args.routes < 1:
        raise SystemExit("rien a emettre : indiquer --tracks, --polygons ou --routes")
    if args.rate <= 0:
        raise SystemExit("--rate doit etre strictement positif")
    if args.stale < 1:
        raise SystemExit("--stale doit valoir au moins 1 seconde")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
