#!/usr/bin/env python3
"""Sonde + injecteur de la passerelle GeoJSON de Delta Suite (TCP 50850).

POC ISRBOX / 33e ESRA — etude du chemin d'INJECTION carte web (ExB) -> Delta Suite.

Contexte (schema de communication Delta Suite, doc constructeur) :
  Delta Suite expose une passerelle GeoJSON externe sur TCP 50850. C'est le chemin
  SUPPORTE pour echanger des entites en GeoJSON — a l'inverse du bus proprietaire
  (4072/4073, framing 98 15 1c aa, handshake gRPC "Woody") qu'on evite ainsi.

  L'analyse statique montre que Delta Suite DECODE des FeatureCollection en entree
  (GeoJsonIncomingMarshaller) et attend, dans les `properties` : name, LayerName,
  symbolIndex, et des blocs de style optionnels.

Ce que l'outil sert a TRANCHER (empiriquement, DS lance) :
  1. SENS   : DS ecoute-t-il sur 50850 (serveur) ou s'y connecte-t-il (client) ?
  2. FRAMING: GeoJSON brut ? delimite par newline ? prefixe en longueur ?
  3. SCHEMA : quelles `properties` minimales suffisent pour qu'un objet s'affiche ?

Deux modes symetriques :
  # Si Delta Suite ECOUTE sur 50850 : on s'y connecte et on observe / injecte
  python deltasuite_geojson_gateway.py --connect <IP_DS>
  python deltasuite_geojson_gateway.py --connect <IP_DS> --send --lat 45.7 --lon -1.1

  # Si Delta Suite se CONNECTE a un gateway externe : on ecoute a sa place
  python deltasuite_geojson_gateway.py --serve
  python deltasuite_geojson_gateway.py --serve --send   # pousse le test des connexion

Options de framing pour l'injection (--send) :
  --framing raw       (defaut) FeatureCollection brute
  --framing newline   FeatureCollection + '\\n'
  --framing length    prefixe entier 4 octets big-endian + FeatureCollection

Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
import datetime

DEFAULT_PORT = 50850


# --------------------------------------------------------------------------
# FeatureCollection de test (schema deduit des jars Delta Suite)
# --------------------------------------------------------------------------

def test_feature_collection(lat: float, lon: float, name: str,
                            layer: str, symbol_index) -> dict:
    """Une FeatureCollection minimale, un point, avec les `properties` que
    Delta Suite semble attendre. `symbol_index` reste a caler empiriquement :
    on l'expose en parametre pour tester plusieurs valeurs (index interne ou SIDC)."""
    props = {"name": name, "LayerName": layer}
    if symbol_index is not None:
        props["symbolIndex"] = symbol_index
    return {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": props,
            }
        ],
    }


def build_payload(fc: dict, fmt: str, layer: str) -> bytes:
    """Construit le message applicatif selon l'enveloppe supposee du gateway.
    Les champs @SerializedName observes dans les jars sont `layerName` et `data`."""
    if fmt == "plain":
        obj = fc                                              # FeatureCollection seule
    elif fmt == "wrapper":
        obj = {"layerName": layer, "data": fc}                # data = objet GeoJSON
    elif fmt == "wrapper-str":
        obj = {"layerName": layer,
               "data": json.dumps(fc, ensure_ascii=False)}    # data = GeoJSON en chaine
    else:
        obj = fc
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def frame(payload: bytes, framing: str) -> bytes:
    if framing == "newline":
        return payload + b"\n"
    if framing == "length":
        return struct.pack(">I", len(payload)) + payload
    return payload  # raw


# --------------------------------------------------------------------------
# Analyse de ce que Delta Suite emet (pour deduire sens + framing)
# --------------------------------------------------------------------------

def hexdump(data: bytes, limit: int = 256) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexa = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {i:04x}  {hexa:<48}  {text}")
    if len(data) > limit:
        out.append(f"  ... (+{len(data) - limit} octets)")
    return "\n".join(out)


def classify(data: bytes) -> str:
    head = data[:4]
    if head == b"\x98\x15\x1c\xaa":
        return "BUS PROPRIETAIRE (98 15 1c aa) — pas la passerelle GeoJSON"
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        hint = "FeatureCollection" if b"FeatureCollection" in data[:200] else "JSON"
        return f"GeoJSON/{hint} brut (commence par '{stripped[:1].decode()}')"
    if len(data) >= 4:
        n = struct.unpack(">I", data[:4])[0]
        if 0 < n < 10_000_000 and data[4:5].lstrip()[:1] in (b"{", b"["):
            return f"JSON prefixe en longueur (len={n})"
    return "format indetermine — voir hexdump"


def analyse(data: bytes, label: str) -> None:
    print(f"\n[{label}] {len(data)} octets recus")
    print("  classification :", classify(data))
    print(hexdump(data))


def pump(sock, seconds: float, save_path: str | None, label: str) -> bool:
    """Affiche EN DIRECT chaque bloc recu (avec analyse), pendant `seconds` au
    total. Sauvegarde le brut si save_path. Ctrl-C pour arreter. -> True si recu."""
    sock.settimeout(1.0)
    deadline = time.monotonic() + seconds
    fh = open(save_path, "ab") if save_path else None
    got = False
    print(f"  observation en direct pendant {int(seconds)}s "
          f"(cree/deplace un objet dans DeltaSuite maintenant ; Ctrl-C pour arreter)...")
    try:
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65535)
            except socket.timeout:
                continue
            if not chunk:
                print("  (connexion fermee par DeltaSuite)")
                break
            got = True
            if fh:
                fh.write(chunk)
                fh.flush()
            stamp = datetime.datetime.now().strftime("%H:%M:%S")
            analyse(chunk, f"{label} {stamp}")
    except KeyboardInterrupt:
        print("\n  (arret manuel)")
    finally:
        if fh:
            fh.close()
            print(f"  brut sauvegarde dans {save_path}")
    if not got:
        print(f"  (rien recu pendant {int(seconds)}s)")
    return got


# --------------------------------------------------------------------------
# Modes client / serveur
# --------------------------------------------------------------------------

def run_connect(host: str, port: int, send: bool, payload: bytes,
                framing: str, wait: float, save_path: str | None) -> int:
    print(f"Connexion a Delta Suite {host}:{port} (TCP)...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"  ECHEC connexion : {e}")
        print("  -> Delta Suite n'ecoute peut-etre PAS sur ce port (il s'y connecte "
              "peut-etre en client). Essayez --serve.")
        return 1
    print("  connecte.")
    try:
        if send:
            data = frame(payload, framing)
            print(f"  envoi FeatureCollection ({len(payload)} o, framing={framing})...")
            sock.sendall(data)
            print("  -> REGARDEZ Delta Suite : un point doit apparaitre.")
        pump(sock, wait, save_path, "DS -> nous")
    finally:
        sock.close()
    return 0


def run_serve(port: int, send: bool, payload: bytes, framing: str, wait: float,
              save_path: str | None) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"En ecoute sur 0.0.0.0:{port} (TCP) — en attente que Delta Suite se connecte...")
    print("  (configurez Delta Suite pour viser <cette machine>:%d comme gateway GeoJSON)" % port)
    srv.settimeout(120)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print("  aucune connexion en 120s — DS ne se connecte pas ici (il ecoute "
              "peut-etre lui-meme : essayez --connect).")
        return 1
    print(f"  connexion de {addr[0]}:{addr[1]} !")
    try:
        if send:
            data = frame(payload, framing)
            print(f"  envoi FeatureCollection ({len(payload)} o, framing={framing})...")
            conn.sendall(data)
            print("  -> REGARDEZ Delta Suite : un point doit apparaitre.")
        pump(conn, wait, save_path, "DS -> nous")
    finally:
        conn.close()
        srv.close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sonde/injecteur passerelle GeoJSON Delta Suite (50850)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--connect", metavar="HOST", help="se connecter a Delta Suite (DS serveur)")
    mode.add_argument("--serve", action="store_true", help="ecouter (DS client se connecte a nous)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="port TCP (defaut 50850)")
    ap.add_argument("--send", action="store_true", help="injecter une FeatureCollection de test")
    ap.add_argument("--framing", choices=["raw", "newline", "length"], default="newline",
                    help="cadrage de l'injection (defaut newline — le serveur fait readLine)")
    ap.add_argument("--format", dest="fmt",
                    choices=["plain", "wrapper", "wrapper-str"], default="wrapper",
                    help="enveloppe applicative : plain=FeatureCollection seule ; "
                         "wrapper={layerName,data:<FC>} ; wrapper-str={layerName,data:'<FC>'}")
    ap.add_argument("--lat", type=float, default=45.70, help="latitude du point de test")
    ap.add_argument("--lon", type=float, default=-1.10, help="longitude du point de test")
    ap.add_argument("--name", default="TEST ISRBOX", help="nom de l'objet de test")
    ap.add_argument("--layer", default="ISRBOX_IMPORT", help="LayerName cible")
    ap.add_argument("--symbol-index", default=None,
                    help="valeur symbolIndex a tester (index interne ou SIDC ; defaut : absent)")
    ap.add_argument("--wait", type=float, default=30.0,
                    help="duree d'observation en direct (s ; defaut 30, Ctrl-C pour arreter)")
    ap.add_argument("--save", metavar="FICHIER", default=None,
                    help="sauvegarder le brut recu de DeltaSuite (pour analyse hors-ligne)")
    args = ap.parse_args(argv)

    fc = test_feature_collection(args.lat, args.lon, args.name, args.layer, args.symbol_index)
    payload = build_payload(fc, args.fmt, args.layer)
    if args.send:
        print(f"Message de test (format={args.fmt}, framing={args.framing}) :")
        print("  " + payload.decode("utf-8"))

    if args.connect:
        return run_connect(args.connect, args.port, args.send, payload,
                           args.framing, args.wait, args.save)
    return run_serve(args.port, args.send, payload, args.framing, args.wait, args.save)


if __name__ == "__main__":
    sys.exit(main())
