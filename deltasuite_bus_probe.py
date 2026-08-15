#!/usr/bin/env python3
"""Sonde + decodeur du bus proprietaire Delta Suite (TCP 4072 / UDP 4073).

POC ISRBOX / 33e ESRA — etude de l'INJECTION carte web -> Delta Suite, voie bus.

Contexte : la passerelle GeoJSON (50850) n'a pas abouti. Le bus inter-DS (4072
TCP / 4073 UDP, canal MOYEN IP) est, lui, BIDIRECTIONNEL et OBSERVABLE : Delta
Suite y emet sa propre situation. On apprend donc le format PAR L'EXEMPLE.

Ce que l'analyse statique a etabli sur le framing (jar `bridge`) :
  - trame prefixee par le magic 98 15 1c aa ;
  - un BridgeFrameSlicer (decoupage) + BridgeFrameCodec (encode/decode) ;
  - une partie "metadata" bornee a 65535 octets (=> longueur sur 2 octets) ;
  - charge utile SITAC/MANUALIMPORT : enveloppe JSON + payload gzip/base64.

STRATEGIE :
  1. CAPTURER ce que Delta Suite pousse (ci-dessous) et le SAUVEGARDER ;
  2. DECODER (magic -> longueurs -> gunzip/base64 -> JSON) ;
  3. plus tard, REJOUER une trame (modifiee) pour tester l'ingestion.

Usage :
  # Se connecter au bus TCP et capturer/decoder en direct (Delta Suite lance) :
  python deltasuite_bus_probe.py --connect <IP_DS> --save bus_4072.bin
  # Ecouter le canal UDP 4073 :
  python deltasuite_bus_probe.py --udp --port 4073 --save bus_4073.bin
  # Re-decoder une capture hors-ligne :
  python deltasuite_bus_probe.py --decode-file bus_4072.bin

Pendant la capture TCP : cree/deplace un objet dans Delta Suite pour provoquer
l'emission. Envoie-moi le .bin : je reconstruis le decodage exact et l'injecteur.

Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import re
import socket
import struct
import sys
import threading
import time
import zlib

MAGIC = b"\x98\x15\x1c\xaa"
DEFAULT_TCP_PORT = 4072
DEFAULT_UDP_PORT = 4073

# Balise de presence observee (pcap Envoi_sitac_tcp_4072) : DeltaSuite diffuse
# ceci en boucle sur UDP 4072 -> x.x.x.255. Structure (36 o) :
#   magic(4) | type=01 | peerId(9) | nom(3) | 02 | couleur1(3) | couleur2(3) | zeros(12)
BEACON_REF = bytes.fromhex(
    "98151caa"            # magic
    "01"                  # type = balise
    "0938950224fb522703"  # peerId (9 o)
    "584156"              # nom "XAV"
    "02"                  # separateur/flag
    "ff0000" "ff0000"     # deux couleurs
    + "00" * 12           # padding
)


def build_beacon(name: str = "GEV") -> bytes:
    """Reforge une balise de presence a partir de la reference observee, avec un
    nom (3 car.) et un peerId legerement distinct (pour ne pas entrer en conflit
    avec le pair XAV existant)."""
    b = bytearray(BEACON_REF)
    b[13] = (b[13] + 0x11) & 0xFF                 # dernier octet du peerId, distinct
    nm = name.encode("latin1")[:3].ljust(3, b" ")
    b[14:17] = nm
    return bytes(b[:36].ljust(36, b"\x00"))


# --------------------------------------------------------------------------
# Affichage
# --------------------------------------------------------------------------

def hexdump(data: bytes, limit: int = 512) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexa = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {i:04x}  {hexa:<48}  {text}")
    if len(data) > limit:
        out.append(f"  ... (+{len(data) - limit} octets)")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Tentatives de decompression / extraction de texte
# --------------------------------------------------------------------------

def try_inflate(blob: bytes):
    """Essaie gzip, puis zlib/deflate brut. Renvoie (methode, texte) ou None."""
    if blob[:2] == b"\x1f\x8b":
        try:
            return "gzip", gzip.decompress(blob).decode("utf-8", "replace")
        except Exception:
            pass
    for wbits, label in ((zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "deflate")):
        try:
            txt = zlib.decompress(blob, wbits).decode("utf-8", "replace")
            if txt.strip():
                return label, txt
        except Exception:
            continue
    return None


B64_RUN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")


def scan_payload(data: bytes) -> list[str]:
    """Cherche du contenu exploitable dans une trame :
       gzip inline (1f 8b), blobs base64 (-> gunzip), et JSON en clair."""
    findings = []
    # 1. gzip/zlib inline
    for magic in (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        pos = data.find(magic)
        if pos >= 0:
            res = try_inflate(data[pos:])
            if res:
                findings.append(f"[{res[0]} inline @octet {pos}]\n{res[1][:2000]}")
    # 2. blobs base64 -> (gunzip ou texte)
    for m in B64_RUN.finditer(data):
        raw = m.group()
        try:
            dec = base64.b64decode(raw + b"=" * (-len(raw) % 4), validate=False)
        except Exception:
            continue
        res = try_inflate(dec)
        if res:
            findings.append(f"[base64 -> {res[0]} @octet {m.start()}]\n{res[1][:2000]}")
        elif dec[:1] in (b"{", b"[") or b"FeatureCollection" in dec[:200]:
            findings.append(f"[base64 -> JSON @octet {m.start()}]\n"
                            f"{dec[:2000].decode('utf-8', 'replace')}")
    # 3. JSON en clair
    for m in re.finditer(rb"\{.{20,}", data, re.S):
        seg = m.group()[:2000]
        if b'"' in seg:
            findings.append(f"[JSON clair @octet {m.start()}]\n"
                            f"{seg.decode('utf-8', 'replace')}")
            break
    return findings


def parse_frames(data: bytes) -> None:
    """Localise les trames au magic 98 15 1c aa et tente d'en lire la structure."""
    positions = [m.start() for m in re.finditer(re.escape(MAGIC), data)]
    if not positions:
        print("  (aucun magic 98 15 1c aa — voir hexdump/extraction ci-dessus)")
        return
    print(f"  {len(positions)} trame(s) reperee(s) au magic 98 15 1c aa :")
    positions.append(len(data))
    for i in range(len(positions) - 1):
        start, end = positions[i], positions[i + 1]
        frame = data[start:end]
        hdr = frame[4:16]
        # Hypothese : apres le magic, des octets de version/type, puis des longueurs.
        u16 = [struct.unpack(">H", frame[j:j + 2])[0] for j in range(4, 12, 2) if j + 2 <= len(frame)]
        u32 = [struct.unpack(">I", frame[j:j + 4])[0] for j in range(4, 16, 4) if j + 4 <= len(frame)]
        print(f"\n  -- trame @octet {start} ({len(frame)} o) --")
        print(f"     en-tete apres magic : {hdr.hex(' ')}")
        print(f"     u16(BE) candidats longueur : {u16}   u32(BE) : {u32}")


# --------------------------------------------------------------------------
# Analyse d'un bloc recu
# --------------------------------------------------------------------------

def analyse(data: bytes, label: str) -> None:
    print(f"\n[{label}] {len(data)} octets")
    print(hexdump(data))
    parse_frames(data)
    for f in scan_payload(data):
        print("  " + f.replace("\n", "\n  "))


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------

def pump(sock, seconds: float, save_path, label, is_udp=False):
    sock.settimeout(1.0)
    deadline = time.monotonic() + seconds
    fh = open(save_path, "ab") if save_path else None
    got = False
    print(f"  capture en direct {int(seconds)}s "
          f"(provoque une emission : cree/deplace un objet dans Delta Suite ; Ctrl-C pour arreter)...")
    try:
        while time.monotonic() < deadline:
            try:
                chunk, _ = sock.recvfrom(65535) if is_udp else (sock.recv(65535), None)
            except socket.timeout:
                continue
            if not chunk:
                print("  (connexion fermee)")
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
            print(f"\n  brut sauvegarde dans {save_path} — envoie-le pour decodage precis.")
    if not got:
        print(f"  (rien recu en {int(seconds)}s — Delta Suite pousse peut-etre seulement "
              "sur changement, ou il faut un hello prealable)")


def run_tcp(host, port, save_path, wait):
    print(f"Connexion au bus Delta Suite {host}:{port} (TCP)...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"  ECHEC : {e}")
        return 1
    print("  connecte — ecoute de ce que Delta Suite emet.")
    try:
        pump(sock, wait, save_path, "DS bus")
    finally:
        sock.close()
    return 0


def run_udp(port, save_path, wait):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    print(f"Ecoute UDP sur 0.0.0.0:{port} ...")
    try:
        pump(sock, wait, save_path, "DS udp", is_udp=True)
    finally:
        sock.close()
    return 0


def _tcp_peer_server(port, save_path, stop_evt, state):
    """Serveur TCP 4072 : accepte la connexion que DeltaSuite ouvre vers nous
    (client) quand il nous reconnait comme pair, et capture/decode ce qu'il pousse."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(5)
        srv.settimeout(1.0)
    except OSError as e:
        print(f"  [TCP {port}] impossible d'ecouter : {e} "
              f"(port deja pris ? firewall ?)")
        return
    print(f"  [TCP {port}] serveur pret — en attente de la connexion DeltaSuite.")
    fh = open(save_path + ".tcp", "ab") if save_path else None
    try:
        while not stop_evt.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            print(f"\n  *** DeltaSuite ({addr[0]}:{addr[1]}) NOUS A CONNECTES en TCP {port} ! ***")
            state["connected"] = True
            conn.settimeout(1.0)
            try:
                while not stop_evt.is_set():
                    try:
                        chunk = conn.recv(65535)
                    except socket.timeout:
                        continue
                    if not chunk:
                        print(f"  [TCP {port}] connexion fermee par DeltaSuite.")
                        break
                    state["got"] = True
                    if fh:
                        fh.write(chunk)
                        fh.flush()
                    analyse(chunk, f"OBJET TCP {addr[0]} "
                            + datetime.datetime.now().strftime("%H:%M:%S"))
            finally:
                conn.close()
    finally:
        if fh:
            fh.close()
        srv.close()


def run_beacon(broadcast_addr, port, name, interval, wait, save_path):
    """Se fait passer pour un pair : diffuse une balise UDP + ecoute UDP, ET ouvre
    un SERVEUR TCP sur le meme port pour accepter la connexion de synchronisation
    que DeltaSuite (client) etablit vers nous."""
    stop_evt = threading.Event()
    state = {"connected": False, "got": False}
    tcp_thread = threading.Thread(target=_tcp_peer_server,
                                  args=(port, save_path, stop_evt, state), daemon=True)
    tcp_thread.start()
    time.sleep(0.3)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    beacon = build_beacon(name)
    print(f"Balise '{name}' diffusee sur {broadcast_addr}:{port} toutes les {interval}s.")
    print(f"  balise : {beacon.hex(' ')}")
    print("  -> cree/deplace un objet dans DeltaSuite. S'il nous reconnait, il se "
          "connectera en TCP pour pousser sa situation. Ctrl-C pour arreter.")
    deadline = time.monotonic() + wait
    next_send = 0.0
    udp_beacons = 0
    try:
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                sock.sendto(beacon, (broadcast_addr, port))
                next_send = time.monotonic() + interval
            try:
                chunk, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if chunk == beacon:
                continue
            if len(chunk) == 36 and chunk[:4] == MAGIC:
                udp_beacons += 1                      # balise d'un autre pair : on compte
                continue
            analyse(chunk, f"UDP {addr[0]}:{addr[1]} "
                    + datetime.datetime.now().strftime("%H:%M:%S"))
    except KeyboardInterrupt:
        print("\n  (arret manuel)")
    finally:
        stop_evt.set()
        sock.close()
        tcp_thread.join(timeout=2.0)
    print(f"\n  bilan : {udp_beacons} balise(s) UDP d'autres pairs vues ; "
          f"connexion TCP DeltaSuite : {'OUI' if state['connected'] else 'NON'} ; "
          f"objets recus : {'OUI -> ' + save_path + '.tcp' if state['got'] else 'NON'}")
    if not state["connected"]:
        print("  (DeltaSuite ne s'est pas connecte : ouvre le firewall Windows sur "
              "TCP 4072 entrant, et verifie que la balise le fait bien nous reconnaitre)")
    return 0


def run_decode_file(path):
    with open(path, "rb") as f:
        data = f.read()
    print(f"Decodage hors-ligne de {path} ({len(data)} octets)")
    analyse(data, "fichier")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sonde/decodeur du bus proprietaire Delta Suite (4072/4073)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--connect", metavar="HOST", help="se connecter au bus TCP de Delta Suite")
    mode.add_argument("--udp", action="store_true", help="ecouter le canal UDP")
    mode.add_argument("--decode-file", metavar="FICHIER", help="re-decoder une capture .bin")
    mode.add_argument("--beacon", action="store_true",
                      help="se faire passer pour un pair (diffuse une balise + ecoute)")
    ap.add_argument("--port", type=int, default=None, help="port (defaut 4072 TCP/UDP)")
    ap.add_argument("--save", metavar="FICHIER", default=None, help="sauvegarder le brut capture")
    ap.add_argument("--wait", type=float, default=45.0, help="duree de capture (s)")
    ap.add_argument("--name", default="GEV", help="nom du pair simule (3 car., mode --beacon)")
    ap.add_argument("--broadcast", default="255.255.255.255",
                    help="adresse de broadcast (ex 192.168.150.255)")
    ap.add_argument("--interval", type=float, default=2.0, help="periode des balises (s)")
    args = ap.parse_args(argv)

    if args.decode_file:
        return run_decode_file(args.decode_file)
    if args.beacon:
        return run_beacon(args.broadcast, args.port or DEFAULT_TCP_PORT,
                          args.name, args.interval, args.wait, args.save)
    if args.udp:
        return run_udp(args.port or DEFAULT_UDP_PORT, args.save, args.wait)
    return run_tcp(args.connect, args.port or DEFAULT_TCP_PORT, args.save, args.wait)


if __name__ == "__main__":
    sys.exit(main())
