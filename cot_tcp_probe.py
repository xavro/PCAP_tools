#!/usr/bin/env python3
"""Sonde TCP : capture et diagnostique un flux CoT emis en TCP.

POURQUOI CET OUTIL
------------------
`cot_listener.py` ecoute l'UDP. Les clients de type TAK — et Delta Suite dans sa
configuration par defaut — emettent en TCP, en se CONNECTANT a un serveur. Le
connecteur CoT d'Esri « Receive Cursor on Target Over TCP Socket » est ce
serveur. Pour voir ce qui arrive REELLEMENT sur le fil, cette sonde prend la
place du serveur : elle ecoute le meme port, accepte la connexion du client, et
dump les octets bruts.

Elle repond a la question que le message d'erreur de GeoEvent laisse ouverte :

    Failed to parse byte buffer using sax parser:
      Invalid byte 1 of 1-byte UTF-8 sequence

Deux causes possibles, que seuls les octets tranchent :

  A. Le flux n'est PAS du XML — premier octet 0xBF = TAK Protocol v1 (protobuf).
     Un receiver XML ne le lira jamais.
  B. C'est du XML, mais des octets Windows-1252 / Latin-1 (guillemets « », degre
     °, accentuees) apparaissent alors que le prologue ne declare pas
     d'encodage : le parseur, en UTF-8 par defaut, echoue sur le premier octet
     >= 0x80.

USAGE
-----
Liberer d'abord le port cote GeoEvent (arreter l'input TCP), puis :

    python cot_tcp_probe.py --port 4072

Emettre un objet depuis Delta Suite. La sonde dump les octets et rend son
verdict. Ctrl+C pour le bilan.

Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
import time


def hexdump(data: bytes, limit: int = 96) -> str:
    """Rend un dump hex + ASCII des premiers octets, facon `hexdump -C`."""
    out = []
    chunk = data[:limit]
    for offset in range(0, len(chunk), 16):
        row = chunk[offset:offset + 16]
        hexa = " ".join(f"{b:02x}" for b in row)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        out.append(f"  {offset:04x}  {hexa:<47}  {text}")
    if len(data) > limit:
        out.append(f"  … {len(data) - limit} octet(s) de plus")
    return "\n".join(out)


def classify(data: bytes) -> str:
    """Identifie l'encodage sur les premiers octets — meme logique que le
    listener, adaptee au flux TCP."""
    if not data:
        return "flux vide"
    if data[0] == 0xBF:
        if len(data) >= 3 and data[1] == 0x01 and data[2] == 0xBF:
            return "TAK Protocol v1 Mesh (protobuf) — un receiver XML ne lira RIEN"
        return "TAK Protocol v1 Stream (protobuf) — un receiver XML ne lira RIEN"
    head = data.lstrip()[:1]
    if head == b"<":
        return "XML (TAK Protocol v0)"
    return f"inconnu — 1er octet 0x{data[0]:02x}, ni '<' ni magic TAK"


# Octets 0x80-0xBF : illegaux comme premier octet d'un caractere UTF-8. C'est la
# famille qui declenche « Invalid byte 1 of 1-byte UTF-8 sequence ». On documente
# les plus probables sur des donnees francaises encodees Windows-1252.
WIN1252_HINTS = {
    0xAB: "« (guillemet ouvrant)", 0xBB: "» (guillemet fermant)",
    0xB0: "° (degre — coordonnees ?)", 0xA0: "espace insecable",
    0xE9: None, 0xE8: None,  # e-aigu / e-grave : leaders 3-octets, autre erreur
}


def analyse_utf8(data: bytes) -> list[str]:
    """Repere les octets qui feraient echouer un parseur UTF-8, et devine la
    cause probable cote Windows-1252."""
    notes = []
    for index, byte in enumerate(data):
        if 0x80 <= byte <= 0xBF:
            hint = WIN1252_HINTS.get(byte)
            label = f" — {hint}" if hint else ""
            around = data[max(0, index - 12):index + 12]
            context = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in around)
            notes.append(f"  offset {index}: octet 0x{byte:02x}{label}  …{context}…")
            if len(notes) >= 8:
                notes.append("  (autres occurrences masquees)")
                break
    return notes


def verdict(data: bytes) -> None:
    say = lambda line="": print(line, file=sys.stderr)
    say()
    say("=== VERDICT =======================================")
    kind = classify(data)
    say(f"encodage             : {kind}")

    if data[:1] == b"\xbf" or (data and data[0] == 0xBF):
        say()
        say("→ HYPOTHESE A confirmee : flux binaire TAK Protocol, pas du XML.")
        say("  Le connecteur CoT d'Esri attend du XML : il ne pourra pas le lire.")
        say("  Piste : forcer le mode XML / TAK Protocol v0 cote Delta Suite,")
        say("  ou basculer sur un client qui emet du CoT XML.")
        say("===================================================")
        return

    # Cas XML : chercher le prologue et les octets fautifs.
    text_head = data[:200].decode("latin-1", errors="replace")
    prolog = re.match(r"\s*<\?xml[^>]*\?>", text_head)
    if prolog:
        p = prolog.group(0).strip()
        say(f"prologue             : {p}")
        if "encoding" not in p.lower():
            say("  ⚠ pas de declaration d'encodage — UTF-8 impose par defaut")

    bad = analyse_utf8(data)
    if bad:
        say()
        say("→ HYPOTHESE B confirmee : XML avec octets NON-UTF-8.")
        say("  Ces octets cassent le parse « Invalid byte 1 of 1-byte UTF-8 » :")
        for note in bad:
            say(note)
        say()
        say("  Cause : donnees encodees Windows-1252 / Latin-1, prologue sans")
        say("  encoding. Cote Delta Suite : forcer l'UTF-8 en sortie, ou eviter")
        say("  les caracteres accentues/guillemets/degre dans les libelles SITAC.")
        say("  Un relais Python peut aussi transcoder Latin-1 → UTF-8 avant")
        say("  GeoEvent, si la source n'est pas modifiable.")
    else:
        say()
        say("→ XML sans octet non-UTF-8 dans l'echantillon. Si GeoEvent echoue")
        say("  quand meme, capturer plus de messages : le fautif est peut-etre")
        say("  plus loin dans le flux.")
    say("===================================================")


def run(args: argparse.Namespace) -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((args.bind, args.port))
    except OSError as exc:
        sys.exit(
            f"[probe] impossible d'ecouter sur {args.bind}:{args.port} : {exc}\n"
            f"Le port est-il encore detenu par l'input GeoEvent ? "
            f"L'arreter d'abord, ou choisir un autre port et y pointer Delta Suite."
        )
    server.listen(4)
    server.settimeout(1.0)
    print(f"[probe] serveur TCP sur {args.bind}:{args.port} — en attente d'un client",
          file=sys.stderr)
    print("[probe] emettre un objet depuis Delta Suite. Ctrl+C pour le bilan.",
          file=sys.stderr)

    capture = open(args.save, "wb") if args.save else None
    connections = 0
    total = 0
    first_payload = b""

    try:
        while True:
            try:
                conn, peer = server.accept()
            except socket.timeout:
                continue
            connections += 1
            print(f"\n[probe] connexion #{connections} depuis {peer[0]}:{peer[1]}",
                  file=sys.stderr)
            conn.settimeout(args.idle)
            payload = b""
            try:
                while True:
                    try:
                        block = conn.recv(65535)
                    except socket.timeout:
                        break
                    if not block:
                        break
                    payload += block
                    if capture:
                        capture.write(block)
                        capture.flush()
                    if len(payload) >= args.max_bytes:
                        break
            finally:
                conn.close()

            total += len(payload)
            print(f"[probe] {len(payload)} octet(s) recu(s) sur cette connexion",
                  file=sys.stderr)
            if payload:
                print(hexdump(payload, args.head), file=sys.stderr)
                if not first_payload:
                    first_payload = payload
                    verdict(payload)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        server.close()
        if capture:
            capture.close()
            print(f"[probe] flux brut enregistre dans {args.save}", file=sys.stderr)

    print("", file=sys.stderr)
    print("=== BILAN =========================================", file=sys.stderr)
    print(f"connexions          : {connections}", file=sys.stderr)
    print(f"octets totaux       : {total}", file=sys.stderr)
    if not first_payload:
        print("aucune donnee recue — le client s'est-il bien connecte ?",
              file=sys.stderr)
    print("===================================================", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sonde TCP pour diagnostiquer un flux CoT (Delta Suite, TAK…).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=4072,
                        help="port TCP d'ecoute (celui configure cote client)")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="interface d'ecoute")
    parser.add_argument("--save", default=None, metavar="FICHIER",
                        help="enregistrer le flux brut (binaire) pour analyse")
    parser.add_argument("--idle", type=float, default=3.0,
                        help="silence (s) apres lequel on considere l'envoi fini")
    parser.add_argument("--max-bytes", type=int, default=1 << 20,
                        help="plafond d'octets lus par connexion")
    parser.add_argument("--head", type=int, default=96,
                        help="nombre d'octets affiches en hexdump")
    return parser


if __name__ == "__main__":
    sys.exit(run(build_parser().parse_args()))
