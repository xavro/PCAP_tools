#!/usr/bin/env python3
"""Injecteur d'entites vers Delta Suite via le canal SITAC/AUTOIMPORT (bus 4072).

POC ISRBOX / 33e ESRA — carte web (ExB) -> Delta Suite.

Format reconstruit a partir d'une capture reelle (ds_sync.tcp), trame par trame :

  98 15 1c aa                        magic
  03 00 01                           en-tete (03 = donnees)
  <uint16 BE>                        longueur = taille_trame - 9  (= len du reste)
  "SITAC/AUTOIMPORT\\0"              canal d'auto-import (null-termine)
  {enveloppe paquet} {enveloppe routage} ||   2 JSON + separateur
  base64( gzip( FeatureCollection GeoJSON ) )  charge

  - enveloppe routage : {"LayerName": <calque>, "sendToId": "", "UserName": <user>}
  - symbole : properties.style.bodyStyle.Icon = "APP6B://<SIDC 2525>/--"
    -> alimente par notre catalogue type<->SIDC.

Usage :
  # auto-test (construit + re-decode, n'envoie rien) :
  python deltasuite_inject.py --self-test
  # injecter un point hostile EW dans le calque "ISRBOX" :
  python deltasuite_inject.py --connect <IP_DS> --lat 45.70 --lon -1.10 \\
      --name CIBLE1 --sidc SHG-EWOL-------/-- --layer ISRBOX --repeat 6

Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import socket
import struct
import sys
import threading
import time

try:
    from deltasuite_bus_probe import build_beacon, analyse as _bus_analyse
except Exception:                     # sonde absente : mode --reply degrade
    build_beacon = None
    _bus_analyse = None

MAGIC = b"\x98\x15\x1c\xaa"
HEADER_PREFIX = b"\x03\x00\x01"
CHANNEL = b"SITAC/AUTOIMPORT\x00"
DEFAULT_PORT = 4072


def style_json(sidc: str) -> str:
    """Style Delta Suite (chaine JSON imbriquee). Icon = APP6B://<SIDC> pour le symbole."""
    icon = f"APP6B://{sidc}" if sidc else ""
    body = {
        "bodyStyle": {
            "type": "com.impact.deltasuite.spatial.view.layer.style.entities.body.PointStyle",
            "Icon": icon, "Icon3D": icon, "IconOriented": True,
            "SpeedVector": {"Speed": 0.0, "VectorColor": -1, "VectorPattern": 0},
            "Size": 1.0, "Orientation": 0.0,
            "ExpandingCircle": {"CircleActivated": False, "CircleDate": 0,
                                "CircleSpeed": 0.0, "CircleRadius": 0.0},
            "Color": -1,
        },
        "labelStyle": {
            "type": "com.impact.deltasuite.spatial.view.layer.style.entities.LabelStyle",
            "font": "Arial", "borderColor": -1, "textColor": -1, "haloColor": 255,
            "backgroundColor": 127, "distanceText": 5, "borderSize": 0, "textSize": 12,
            "haloSize": 2, "EnableBackground": False, "EnablePinouille": False,
            "isBold": False, "isItalic": False, "isUnderline": False, "hideTooltip": False,
        },
    }
    return json.dumps(body, ensure_ascii=False)


def feature(lat, lon, name, sidc, oid, ds_id, user, user_id, now_ms, fid) -> dict:
    suivi = json.dumps([{"modificationDate": now_ms, "userName": user,
                         "userId": str(user_id)}], ensure_ascii=False)
    return {
        "type": "Feature", "id": fid,
        "geometry": {"type": "Point", "coordinates": [lon, lat, 0.0]},
        "properties": {
            "name": name, "description": "", "style": style_json(sidc),
            "date": now_ms, "expediteur": None, "gdh_reception": None, "commentaires": "",
            "oid": str(oid), "ds_id": ds_id, "isvisible": None, "pieces_jointes": None,
            "date_observation": now_ms, "observateur": user, "createur": user,
            "suivi": suivi, "__9line": None, "__vmf": None,
            "__entity_id_serial_number": None, "__observation_report": None,
        },
    }


def feature_collection(features: list[dict]) -> dict:
    return {
        "type": "FeatureCollection",
        "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:EPSG::4326"}},
        "features": features,
    }


def build_frame(fc: dict, layer: str, user: str, user_id: int, message_id: int,
                send_to: str = "", group_id: int = 0) -> bytes:
    payload = json.dumps(fc, ensure_ascii=False).encode("utf-8")
    b64 = base64.b64encode(gzip.compress(payload))
    env1 = json.dumps({"userId": user_id, "userName": user, "dynamic": False,
                       "messageId": message_id, "groupId": group_id or user_id,
                       "packetNumber": 1, "packetCount": 1, "ackWanted": False,
                       "encrypt": False}, ensure_ascii=False).encode("utf-8")
    env2 = json.dumps({"LayerName": layer, "sendToId": send_to, "UserName": user},
                      ensure_ascii=False).encode("utf-8")
    content = CHANNEL + env1 + b" " + env2 + b"||" + b64
    if len(content) > 0xFFFF:
        raise ValueError("charge > 65535 o : necessiterait le multi-paquet (non gere)")
    return MAGIC + HEADER_PREFIX + struct.pack(">H", len(content)) + content


def decode_frame(frame: bytes) -> dict:
    """Re-decode une trame construite (auto-test)."""
    assert frame[:4] == MAGIC, "magic absent"
    lenfield = struct.unpack(">H", frame[7:9])[0]
    assert lenfield == len(frame) - 9, f"longueur {lenfield} != {len(frame)-9}"
    nul = frame.index(0, 9)
    channel = frame[9:nul].decode()
    sep = frame.find(b"||")
    b64 = frame[sep + 2:]
    fc = json.loads(gzip.decompress(base64.b64decode(b64)))
    return {"channel": channel, "features": fc.get("features", [])}


def build_fc_from_args(args) -> dict:
    now = int(time.time() * 1000)
    uid = args.user_id if args.user_id else now * 1000 + 71719
    oid = str(now) + "1"
    ft = feature(args.lat, args.lon, args.name, args.sidc, oid, args.ds_id,
                 args.user, uid, now, 3)
    return feature_collection([ft])


def build_from_args(args):
    now = int(time.time() * 1000)
    uid = args.user_id if args.user_id else now * 1000 + 71719
    mid = now * 100 + 1
    fc = build_fc_from_args(args)
    return build_frame(fc, args.layer, args.user, uid, mid,
                       send_to=args.send_to, group_id=args.group_id)


def run_gateway(args):
    """Envoie la FeatureCollection RICHE (format DeltaSuite exact) a la passerelle
    GeoJSON (50850), en essayant plusieurs cadrages/enveloppes."""
    fc = build_fc_from_args(args)
    fc_bytes = json.dumps(fc, ensure_ascii=False).encode("utf-8")
    wrapper = json.dumps({"layerName": args.layer, "data": fc},
                         ensure_ascii=False).encode("utf-8")
    candidates = [
        ("FeatureCollection brute + \\n", fc_bytes + b"\n"),
        ("FeatureCollection brute", fc_bytes),
        ("{layerName,data:FC} + \\n", wrapper + b"\n"),
        ("frame bus (magic+SITAC/AUTOIMPORT)", build_from_args(args)),
    ]
    host, port = args.gateway, args.gateway_port
    for label, data in candidates:
        print(f"\n== essai : {label} ({len(data)} o) vers {host}:{port} ==")
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(data)
                s.settimeout(3.0)
                resp = b""
                try:
                    while len(resp) < 65535:
                        c = s.recv(65535)
                        if not c:
                            break
                        resp += c
                except socket.timeout:
                    pass
            print("  reponse :", (resp[:120].hex(" ") if resp else "(aucune)"))
            print("  -> regarde DeltaSuite (calque", args.layer + ").")
        except OSError as e:
            print("  ECHEC :", e)
        time.sleep(2.0)
    print("\nSi l'un des cadrages fait apparaitre le point, on le fige. Sinon -> Impact.")
    return 0


def run_self_test(args):
    frame = build_from_args(args)
    print(f"Trame construite : {len(frame)} octets")
    print("  entete :", frame[:9].hex(" "))
    dec = decode_frame(frame)
    print("  canal  :", dec["channel"])
    print("  features:", [(f["properties"]["name"],
                           json.loads(f["properties"]["style"])["bodyStyle"]["Icon"])
                          for f in dec["features"]])
    print("  aller-retour OK — la trame se re-decode a l'identique.")
    return 0


def run_inject(args):
    if args.beacon_first and build_beacon is not None:
        b = build_beacon(args.user[:3])
        bs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            bs.sendto(b, (args.broadcast, args.port)); time.sleep(0.3)
        bs.close()
        print(f"  balises '{args.user[:3]}' diffusees (pair reconnu).")
    print(f"Connexion a Delta Suite {args.connect}:{args.port} (TCP)...")
    for i in range(args.repeat):
        frame = build_from_args(args)      # nouvel oid/messageId a chaque envoi
        try:
            s = socket.create_connection((args.connect, args.port), timeout=5)
        except OSError as e:
            print(f"  [{i+1}/{args.repeat}] ECHEC connexion : {e}")
            time.sleep(args.interval)
            continue
        try:
            s.sendall(frame)
            print(f"  [{i+1}/{args.repeat}] envoye ({len(frame)} o) — calque '{args.layer}', "
                  f"point '{args.name}'. Lecture de la reaction 3s...")
            s.settimeout(3.0)
            resp = b""
            try:
                while len(resp) < 65535:
                    chunk = s.recv(65535)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            if resp:
                print(f"    Delta Suite a repondu {len(resp)} o (entete {resp[:9].hex(' ')}) "
                      f"-> il LIT la connexion.")
            else:
                print("    (aucune reponse sur cette connexion)")
        finally:
            s.close()
        if i + 1 < args.repeat:
            time.sleep(args.interval)
    print("Termine. Si rien n'apparait, essaie le mode --reply (repond sur la connexion "
          "que Delta Suite ouvre vers nous apres la balise).")
    return 0


def run_reply(args):
    """Se fait passer pour un pair (balise) et, quand Delta Suite se connecte a nous
    pour synchroniser, lui RENVOIE notre trame sur CETTE connexion (sync bidirectionnel)."""
    if build_beacon is None:
        print("deltasuite_bus_probe.py requis pour --reply (place-le a cote).")
        return 1
    stop = threading.Event()
    state = {"connected": False}

    def tcp_server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", args.port)); srv.listen(5); srv.settimeout(1.0)
        except OSError as e:
            print(f"  [TCP {args.port}] ecoute impossible : {e}"); return
        print(f"  [TCP {args.port}] pret — j'attends que Delta Suite se connecte.")
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            state["connected"] = True
            print(f"\n  *** Delta Suite {addr[0]} connecte — j'INJECTE sur sa connexion ***")
            conn.settimeout(2.0)
            try:
                conn.sendall(build_from_args(args))
                print(f"  trame injectee ({args.name}/{args.layer}). Lecture des echanges...")
                while not stop.is_set():
                    try:
                        chunk = conn.recv(65535)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    if _bus_analyse:
                        _bus_analyse(chunk, f"DS {addr[0]}")
            except OSError:
                pass
            finally:
                conn.close()
        srv.close()

    t = threading.Thread(target=tcp_server, daemon=True); t.start()
    time.sleep(0.3)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.bind(("0.0.0.0", args.port)); udp.settimeout(1.0)
    beacon = build_beacon(args.name[:3])
    print(f"Balise '{args.name[:3]}' diffusee sur {args.broadcast}:{args.port}. "
          f"Cree un objet dans Delta Suite pour declencher sa connexion. Ctrl-C pour arreter.")
    end = time.monotonic() + args.wait
    nxt = 0.0
    try:
        while time.monotonic() < end:
            if time.monotonic() >= nxt:
                udp.sendto(beacon, (args.broadcast, args.port)); nxt = time.monotonic() + 2.0
            try:
                udp.recvfrom(65535)
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        print("\n  (arret)")
    finally:
        stop.set(); udp.close(); t.join(timeout=2.0)
    print(f"  connexion Delta Suite : {'OUI' if state['connected'] else 'NON'}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Injecteur SITAC/AUTOIMPORT vers Delta Suite")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--connect", metavar="HOST", help="hote Delta Suite (on se connecte a lui)")
    mode.add_argument("--reply", action="store_true",
                      help="balise + injecte sur la connexion que Delta Suite ouvre vers nous")
    mode.add_argument("--gateway", metavar="HOST",
                      help="envoie la FeatureCollection riche a la passerelle GeoJSON (50850)")
    mode.add_argument("--to-file", metavar="FICHIER.geojson",
                      help="ecrit la FeatureCollection riche dans un .geojson (import manuel / dossier auto)")
    mode.add_argument("--self-test", action="store_true", help="construit + re-decode, sans reseau")
    ap.add_argument("--gateway-port", type=int, default=50850)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--broadcast", default="255.255.255.255", help="broadcast (mode --reply)")
    ap.add_argument("--wait", type=float, default=120.0, help="duree (mode --reply)")
    ap.add_argument("--lat", type=float, default=45.70)
    ap.add_argument("--lon", type=float, default=-1.10)
    ap.add_argument("--name", default="CIBLE ISRBOX")
    ap.add_argument("--sidc", default="SHG-EWOL-------/--",
                    help="SIDC 2525 pour Icon APP6B (ex SHG-EWOL-------/-- ; '' = sans symbole)")
    ap.add_argument("--layer", default="ISRBOX", help="calque de destination dans Delta Suite")
    ap.add_argument("--user", default="ISRBOX")
    ap.add_argument("--user-id", type=int, default=0, help="userId (0 = genere)")
    ap.add_argument("--ds-id", default="A1-15-B0-30-C2-D3",
                    help="ds_id source — DOIT differer de celui de Delta Suite (anti-echo)")
    ap.add_argument("--beacon-first", action="store_true",
                    help="diffuser quelques balises avant de se connecter (etre reconnu comme pair)")
    ap.add_argument("--send-to", default="664444781480071719",
                    help="sendToId = destinataire (defaut : l'ID XAV vu dans la capture)")
    ap.add_argument("--group-id", type=int, default=664444781480071719,
                    help="groupId (defaut : le groupe vu dans la capture)")
    ap.add_argument("--repeat", type=int, default=1, help="nombre d'envois (Delta Suite rafraichit)")
    ap.add_argument("--interval", type=float, default=3.0, help="delai entre envois (s)")
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test(args)
    if args.reply:
        return run_reply(args)
    if args.gateway:
        return run_gateway(args)
    if args.to_file:
        fc = build_fc_from_args(args)
        with open(args.to_file, "w", encoding="utf-8") as f:
            json.dump(fc, f, ensure_ascii=False)
        print(f"FeatureCollection ecrite : {args.to_file}")
        print(f"  1 feature '{args.name}' calque '{args.layer}' Icon APP6B://{args.sidc}")
        print("  -> glisse-depose ce fichier dans Delta Suite (ou depose-le dans son "
              "dossier de chargement automatique).")
        return 0
    return run_inject(args)


if __name__ == "__main__":
    sys.exit(main())
