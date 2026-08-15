#!/usr/bin/env python3
"""Passerelle HTTP -> CoT UDP : émission de messages CoT depuis l'appli web ExB.

POC ISRBOX / 33e ESRA. Un navigateur ne sait pas émettre d'UDP : cette passerelle
reçoit un JSON simple en HTTP POST (widget ExB « cot-send ») et émet le message
CoT XML correspondant en UDP vers un ou plusieurs destinataires (GeoEvent,
DeltaSuite, TAK/ATAK...). Maquette de l'option B avant l'adaptateur GeoEvent
sortant (option A, industrialisation).

Le format émis reproduit le profil observé dans la capture de l'addin ArcGIS Pro
(Capture_CoT_ArcGIS_send.pcap) : un event par datagramme, prologue XML, UTF-8
strict, temps UTC suffixés Z, un `\\n` final. Règles appliquées :
  - uid auto `EXB.<user>.<millis>.<seq>` (traçabilité de l'émetteur web) ;
  - `stale = time + staleSeconds` (défaut 300 s) en émission normale ;
  - suppression explicite : `"delete": true` -> `stale = time` (le receiver
    GeoEvent pose alors `deleted = true` — pratique documentée par le guide
    MITRE p.14, également convention DeltaSuite) ;
  - `ce`/`le` optionnels (mètres) ; absents -> `9999999.0` = borne d'erreur
    INCONNUE de la norme (guide MITRE p.11) — on n'affirme jamais une
    précision non mesurée ;
  - caractères de contrôle XML 1.0 interdits supprimés de tous les textes.

API :
  POST /cot          un event (objet JSON) ou un lot ({"events": [...]})
  GET  /health       état + compteurs

Champs JSON d'un event : type (requis), lat (requis), lon (requis), hae,
callsign, remarks, uid, user, how (défaut "h-e"), staleSeconds, delete,
course, speed.

Usage :
  # vers le receiver GeoEvent du banc + une DeltaSuite
  python cot_web_gateway.py --target 192.168.150.148:8087 \\
      --target 192.168.150.60:6969 --http-port 8088

  # test local (répond CORS pour un ExB en dev sur un autre origin)
  python cot_web_gateway.py --target 127.0.0.1:18087

Bibliothèque standard uniquement.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape, quoteattr

# --------------------------------------------------------------------------
# Construction du message CoT (profil ArcGIS/receiver, cf. docstring)
# --------------------------------------------------------------------------

_ATOM_PREFIX = ("a-", "b-", "t-")   # familles CoT tolérées (atomes, bits, tasking)

# Borne d'erreur « inconnue » de la norme CoT (guide MITRE p.11) : émise quand
# ce/le ne sont pas fournis — on n'affirme jamais une précision non mesurée.
UNKNOWN_ERROR_M = 9999999.0

# Caractères de contrôle interdits en XML 1.0 (TAB/LF/CR autorisés) : un seul
# rendrait le message entier non parsable chez tous les consommateurs.
_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _clean(s: str) -> str:
    return _CTRL_RE.sub("", s)


# Plafond de sommets d'une forme : un event = UN datagramme UDP (~65 507 o).
MAX_SHAPE_VERTICES = 800


def _parse_vertices(encoded: str) -> list[tuple[float, float, float]]:
    """Décode l'encodage PLAT des sommets : `"lat,lon[,hae];..."` (le format
    qui traverse l'input REST GeoEvent sans structure imbriquée)."""
    out = []
    for part in (encoded or "").split(";"):
        v = part.strip()
        if not v:
            continue
        c = [x.strip() for x in v.split(",")]
        if len(c) not in (2, 3):
            raise ValueError(f"sommet invalide (attendu lat,lon[,hae]) : {v!r}")
        lat, lon = float(c[0]), float(c[1])
        hae = float(c[2]) if len(c) == 3 else 0.0
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            raise ValueError(f"sommet hors bornes WGS-84 : {v!r}")
        out.append((lat, lon, hae))
    return out


def _iso(dt: datetime) -> str:
    """UTC millisecondes suffixé Z — format accepté par Instant.parse (receiver)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_cot(ev: dict, seq: int) -> tuple[bytes, str]:
    """Construit un datagramme CoT depuis un event JSON. Retourne (payload, uid).
    Lève ValueError si un champ requis manque ou est invalide."""
    cot_type = _clean(str(ev.get("type") or "").strip())
    if not any(cot_type.startswith(p) for p in _ATOM_PREFIX):
        raise ValueError(f"type CoT invalide ou absent : {cot_type!r}")

    # Forme (polyligne/polygone) — contrat plat shapeVertices/shapeClosed.
    vertices = _parse_vertices(str(ev.get("shapeVertices") or ""))
    closed = bool(ev.get("shapeClosed"))
    if vertices:
        if len(vertices) < 2:
            raise ValueError("forme : au moins 2 sommets requis")
        if len(vertices) > MAX_SHAPE_VERTICES:
            raise ValueError(f"forme : {len(vertices)} sommets > plafond {MAX_SHAPE_VERTICES}")
        # Point = CENTROIDE des sommets (convention MITRE/DeltaSuite : le point
        # est toujours présent ; les consommateurs « points seulement », comme
        # l'addin ArcGIS Pro, affichent au moins le centroïde).
        lat = sum(v[0] for v in vertices) / len(vertices)
        lon = sum(v[1] for v in vertices) / len(vertices)
    else:
        try:
            lat, lon = float(ev["lat"]), float(ev["lon"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("lat/lon requis et numériques")
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            raise ValueError(f"lat/lon hors bornes : {lat}, {lon}")

    now = datetime.now(timezone.utc)
    user = _clean(str(ev.get("user") or "anon").strip()) or "anon"
    uid = _clean(str(ev.get("uid") or "").strip()) or f"EXB.{user}.{int(now.timestamp() * 1000)}.{seq}"
    how = _clean(str(ev.get("how") or "h-e").strip())
    stale_s = float(ev.get("staleSeconds") or 300)
    if stale_s <= 0:
        raise ValueError(f"staleSeconds doit être > 0 : {stale_s}")
    # Suppression explicite : stale == time -> deleted=true côté receiver.
    stale = now if ev.get("delete") else now + timedelta(seconds=stale_s)

    hae = float(ev.get("hae") or 0.0)
    # ce/le : rayon / demi-hauteur du cylindre englobant (m) — 9999999 = inconnu.
    ce = UNKNOWN_ERROR_M if ev.get("ce") is None else float(ev["ce"])
    le = UNKNOWN_ERROR_M if ev.get("le") is None else float(ev["le"])
    if ce < 0 or le < 0:
        raise ValueError(f"ce/le doivent être >= 0 : {ce}, {le}")
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<event version="2.0" uid={quoteattr(uid)} type={quoteattr(cot_type)} '
        f'how={quoteattr(how)} time="{_iso(now)}" start="{_iso(now)}" stale="{_iso(stale)}">',
        f'<point lat="{lat:.6f}" lon="{lon:.6f}" hae="{hae:.1f}" ce="{ce:.1f}" le="{le:.1f}"/>',
        "<detail>",
    ]
    callsign = _clean(str(ev.get("callsign") or "").strip())
    if callsign:
        parts.append(f"<contact callsign={quoteattr(callsign)}/>")
    if ev.get("course") is not None or ev.get("speed") is not None:
        course = float(ev.get("course") or 0.0)
        speed = float(ev.get("speed") or 0.0)
        parts.append(f'<track course="{course:.1f}" speed="{speed:.1f}"/>')
    remarks = _clean(str(ev.get("remarks") or "").strip())
    if remarks:
        parts.append(f'<remarks time="{_iso(now)}">{escape(remarks)}</remarks>')
    if vertices:
        # Convention MITRE/DeltaSuite (celle que le receiver ingère nativement) :
        # closed=true -> polygone, false -> ligne ouverte.
        parts.append(f'<shape><polyline closed="{"true" if closed else "false"}">')
        parts.extend(f'<vertex lat="{v[0]:.6f}" lon="{v[1]:.6f}" hae="{v[2]:.1f}"/>' for v in vertices)
        parts.append("</polyline></shape>")
    parts.append("</detail></event>")
    return ("".join(parts) + "\n").encode("utf-8"), uid


# --------------------------------------------------------------------------
# Serveur HTTP
# --------------------------------------------------------------------------

class Gateway:
    def __init__(self, targets: list[tuple[str, int]]):
        self.targets = targets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.lock = threading.Lock()
        self.seq = 0
        self.sent = 0
        self.errors = 0
        self.started = time.time()

    def emit(self, ev: dict) -> str:
        with self.lock:
            self.seq += 1
            seq = self.seq
        payload, uid = build_cot(ev, seq)
        for host, port in self.targets:
            self.sock.sendto(payload, (host, port))
        with self.lock:
            self.sent += 1
        return uid


class Handler(BaseHTTPRequestHandler):
    gateway: Gateway = None  # injecté au démarrage
    server_version = "cot-web-gateway/1.0"

    # -- CORS : l'ExB (autre origin en dev, voire en prod) doit pouvoir POSTer.
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _reply(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):  # preflight CORS
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/health"):
            g = self.gateway
            self._reply(200, {
                "status": "ok",
                "targets": [f"{h}:{p}" for h, p in g.targets],
                "sent": g.sent, "errors": g.errors,
                "uptimeSeconds": round(time.time() - g.started, 1),
            })
        else:
            self._reply(404, {"error": "inconnu — utiliser POST /cot ou GET /health"})

    def do_POST(self):
        if self.path.rstrip("/") != "/cot":
            self._reply(404, {"error": "inconnu — utiliser POST /cot"})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            self._reply(400, {"error": f"JSON illisible : {e}"})
            return
        # Trois formes acceptées : un event (objet), {"events": [...]}, ou un
        # tableau nu [...] — cette dernière = le format de l'input REST GeoEvent,
        # pour garder un contrat identique banc/cible.
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict) and "events" in data:
            events = data.get("events")
        else:
            events = [data]
        if not isinstance(events, list) or not events:
            self._reply(400, {"error": "corps attendu : un event JSON, {\"events\": [...]} ou [...]"})
            return
        uids, rejected = [], []
        for i, ev in enumerate(events):
            try:
                uids.append(self.gateway.emit(ev))
            except (ValueError, TypeError) as e:
                self.gateway.errors += 1
                rejected.append({"index": i, "error": str(e)})
        code = 200 if uids and not rejected else (207 if uids else 400)
        self._reply(code, {"sent": len(uids), "uids": uids, "rejected": rejected})

    def log_message(self, fmt, *args):  # journal une ligne, sans reverse DNS
        print(f"  {self.address_string()} {fmt % args}")


# --------------------------------------------------------------------------

def parse_target(s: str) -> tuple[str, int]:
    host, sep, port = s.rpartition(":")
    if not sep:
        raise argparse.ArgumentTypeError(f"cible attendue au format IP:port : {s!r}")
    return host, int(port)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Passerelle HTTP -> CoT UDP (widget ExB cot-send)")
    ap.add_argument("--target", type=parse_target, action="append", required=True,
                    metavar="IP:PORT", help="destinataire UDP CoT (répétable)")
    ap.add_argument("--http-host", default="0.0.0.0", help="interface d'écoute HTTP")
    ap.add_argument("--http-port", type=int, default=8088, help="port d'écoute HTTP (défaut 8088)")
    args = ap.parse_args(argv)

    Handler.gateway = Gateway(args.target)
    srv = ThreadingHTTPServer((args.http_host, args.http_port), Handler)
    tgts = ", ".join(f"{h}:{p}" for h, p in args.target)
    print(f"Passerelle CoT : http://{args.http_host}:{args.http_port}/cot -> UDP {tgts}")
    print("(Ctrl+C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  (arrêt manuel)")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
