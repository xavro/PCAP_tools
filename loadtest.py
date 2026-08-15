#!/usr/bin/env python3
"""Test de charge de la chaine d'emission CoT — critere d'acceptation phase 1.

Fait monter en charge le generateur par paliers et mesure, pour chacun :
  - le debit reellement emis (le generateur tient-il la cadence demandee ?) ;
  - le debit recu et le taux de perte ;
  - la regularite (jitter inter-tick) ;
  - la couverture des pistes (toutes les pistes sont-elles vues ?).

Le recepteur est integre au script, avec un gros buffer UDP et un decodage
minimal (extraction du `uid` par recherche d'octets, pas de parsing XML), afin
que le goulot mesure le reseau et non l'outil de mesure.

PERIMETRE : mesure la chaine emission -> reseau -> reception UDP. L'ingestion
GeoEvent doit etre mesuree separement, sur la plateforme.

Bibliotheque standard uniquement.

    python loadtest.py                 # palier par defaut
    python loadtest.py --steps 100x1,500x1,1000x2 --duration 30
"""

from __future__ import annotations

import argparse
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GENERATOR = HERE / "cot_generator.py"

# Paliers par defaut : (pistes, Hz). Debit = pistes x Hz messages/s.
DEFAULT_STEPS = "100x1,250x1,500x1,1000x1,1000x2,2000x2"

SENT_RE = re.compile(r"termine\s*:\s*(\d+)\s+message")
UID_RE = re.compile(rb'uid="([^"]*)"')


class Receiver(threading.Thread):
    """Recepteur multicast a decodage minimal, pour ne pas fausser la mesure."""

    def __init__(self, group: str, port: int, rcvbuf: int) -> None:
        super().__init__(daemon=True)
        self.group = group
        self.port = port
        self.rcvbuf = rcvbuf
        self.stop_event = threading.Event()
        self.ready = threading.Event()

        self.count = 0
        self.bytes = 0
        self.malformed = 0
        self.uids: set[bytes] = set()
        self.per_second: list[int] = []
        self.first_at: float | None = None
        self.last_at: float | None = None
        self.error: str | None = None

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
            sock.bind(("", self.port))
            first_octet = int(self.group.split(".")[0])
            if 224 <= first_octet <= 239:
                mreq = struct.pack("4s4s", socket.inet_aton(self.group),
                                   socket.inet_aton("0.0.0.0"))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(0.25)
        except OSError as exc:
            self.error = str(exc)
            self.ready.set()
            sock.close()
            return

        self.ready.set()
        bucket_start = time.monotonic()
        bucket = 0
        try:
            while not self.stop_event.is_set():
                try:
                    datagram = sock.recv(65535)
                except socket.timeout:
                    now = time.monotonic()
                    while now - bucket_start >= 1.0:
                        self.per_second.append(bucket)
                        bucket = 0
                        bucket_start += 1.0
                    continue

                now = time.monotonic()
                if self.first_at is None:
                    self.first_at = now
                    bucket_start = now
                self.last_at = now
                self.count += 1
                self.bytes += len(datagram)
                bucket += 1
                while now - bucket_start >= 1.0:
                    self.per_second.append(bucket)
                    bucket = 0
                    bucket_start += 1.0

                match = UID_RE.search(datagram)
                if match:
                    self.uids.add(match.group(1))
                else:
                    self.malformed += 1
        finally:
            if bucket:
                self.per_second.append(bucket)
            sock.close()


def parse_steps(spec: str) -> list[tuple[int, float]]:
    steps: list[tuple[int, float]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        tracks_s, _, rate_s = item.partition("x")
        try:
            steps.append((int(tracks_s), float(rate_s or "1")))
        except ValueError:
            raise SystemExit(f"palier invalide : {item!r} (format attendu : 500x2)")
    if not steps:
        raise SystemExit("aucun palier a executer")
    return steps


def run_step(tracks: int, rate: float, args: argparse.Namespace) -> dict:
    """Execute un palier et retourne ses metriques."""
    target = tracks * rate

    receiver = Receiver(args.group, args.port, args.rcvbuf)
    receiver.start()
    receiver.ready.wait(timeout=5.0)
    if receiver.error:
        raise SystemExit(f"recepteur indisponible : {receiver.error}")

    cmd = [
        sys.executable, str(GENERATOR),
        "--tracks", str(tracks),
        "--rate", str(rate),
        "--duration", str(args.duration),
        "--group", args.group,
        "--port", str(args.port),
        "--seed", str(args.seed),
    ]
    if args.loopback:
        cmd.append("--loopback")

    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    gen_elapsed = time.monotonic() - started

    # Laisser le temps aux derniers datagrammes en vol d'arriver.
    time.sleep(args.drain)
    receiver.stop_event.set()
    receiver.join(timeout=5.0)

    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"le generateur a echoue (code {proc.returncode})")

    match = SENT_RE.search(proc.stderr)
    sent = int(match.group(1)) if match else 0
    expected = tracks * rate * args.duration

    recv_window = 0.0
    if receiver.first_at is not None and receiver.last_at is not None:
        recv_window = receiver.last_at - receiver.first_at

    # Jitter : ecart des debits par seconde autour de la cible, hors premiere
    # et derniere seconde (partielles par construction).
    stable = receiver.per_second[1:-1] if len(receiver.per_second) > 2 else receiver.per_second
    if stable:
        worst_second = min(stable)
        best_second = max(stable)
        mean_second = sum(stable) / len(stable)
    else:
        worst_second = best_second = mean_second = 0

    # Les deux debits sont rapportes a la MEME fenetre — la duree d'emission
    # demandee — sinon "recus/s" et "emis/s" ne sont pas comparables.
    window = args.duration

    return {
        "tracks": tracks,
        "rate": rate,
        "target_mps": target,
        "expected": expected,
        "sent": sent,
        "sent_mps": sent / window if window else 0.0,
        "received": receiver.count,
        "recv_mps": receiver.count / window if window else 0.0,
        "recv_window": recv_window,
        "loss": sent - receiver.count,
        "loss_pct": (sent - receiver.count) / sent * 100.0 if sent else 0.0,
        "emit_deficit_pct": (expected - sent) / expected * 100.0 if expected else 0.0,
        "uids": len(receiver.uids),
        "malformed": receiver.malformed,
        "bytes": receiver.bytes,
        "mbps": receiver.bytes * 8 / window / 1e6 if window else 0.0,
        "worst_second": worst_second,
        "best_second": best_second,
        "mean_second": mean_second,
        "elapsed": gen_elapsed,
    }


def verdict(row: dict) -> str:
    if row["uids"] != row["tracks"]:
        return "ECHEC"
    if row["malformed"] > 0:
        return "ECHEC"
    if row["loss_pct"] > 1.0 or row["emit_deficit_pct"] > 1.0:
        return "ECHEC"
    if row["loss_pct"] > 0.0 or row["emit_deficit_pct"] > 0.1:
        return "LIMITE"
    return "OK"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test de charge de la chaine d'emission CoT.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--steps", default=DEFAULT_STEPS,
                        help="paliers 'pistes x Hz' separes par des virgules")
    parser.add_argument("--duration", type=float, default=20.0,
                        help="duree de chaque palier, en secondes")
    parser.add_argument("--group", default="239.2.3.1", help="adresse de destination")
    parser.add_argument("--port", type=int, default=6969, help="port UDP")
    parser.add_argument("--loopback", action="store_true", default=True,
                        help="multicast en retour local (test sur une seule machine)")
    parser.add_argument("--no-loopback", dest="loopback", action="store_false",
                        help="desactiver le retour local (emetteur et recepteur distincts)")
    parser.add_argument("--rcvbuf", type=int, default=32 * 1024 * 1024,
                        help="buffer de reception UDP, en octets")
    parser.add_argument("--drain", type=float, default=1.0,
                        help="attente apres l'arret du generateur, en secondes")
    parser.add_argument("--seed", type=int, default=1337, help="graine du generateur")
    args = parser.parse_args()

    steps = parse_steps(args.steps)
    print(f"Test de charge CoT — {len(steps)} palier(s) de {args.duration:.0f}s "
          f"vers {args.group}:{args.port}")
    print(f"Duree totale estimee : {len(steps) * (args.duration + args.drain + 1):.0f}s\n")

    rows: list[dict] = []
    for index, (tracks, rate) in enumerate(steps, start=1):
        print(f"[{index}/{len(steps)}] {tracks} pistes @ {rate} Hz "
              f"= {tracks * rate:.0f} msg/s cible ... ", end="", flush=True)
        row = run_step(tracks, rate, args)
        row["verdict"] = verdict(row)
        rows.append(row)
        print(f"{row['verdict']} "
              f"(emis {row['sent']}, recus {row['received']}, "
              f"perte {row['loss_pct']:.2f}%)")

    print("\n=== RESULTATS ==============================================================")
    header = (f"{'palier':>12} {'cible':>8} {'emis/s':>9} {'recus/s':>9} "
              f"{'perte':>8} {'pistes':>8} {'Mbit/s':>8} {'min/s':>7} {'verdict':>8}")
    print(header)
    print("-" * len(header))
    for row in rows:
        print(f"{row['tracks']:>5}x{row['rate']:<6g} "
              f"{row['target_mps']:>8.0f} "
              f"{row['sent_mps']:>9.0f} "
              f"{row['recv_mps']:>9.0f} "
              f"{row['loss_pct']:>7.2f}% "
              f"{row['uids']:>4}/{row['tracks']:<3} "
              f"{row['mbps']:>8.1f} "
              f"{row['worst_second']:>7} "
              f"{row['verdict']:>8}")
    print("=" * len(header))

    ok = [r for r in rows if r["verdict"] == "OK"]
    if ok:
        best = max(ok, key=lambda r: r["target_mps"])
        print(f"\nDebit soutenu sans perte : {best['target_mps']:.0f} msg/s "
              f"({best['tracks']} pistes @ {best['rate']:g} Hz, "
              f"{best['mbps']:.1f} Mbit/s)")
    failed = [r for r in rows if r["verdict"] == "ECHEC"]
    if failed:
        first = min(failed, key=lambda r: r["target_mps"])
        print(f"Premier palier en echec : {first['target_mps']:.0f} msg/s "
              f"(perte {first['loss_pct']:.2f}%, "
              f"deficit d'emission {first['emit_deficit_pct']:.2f}%)")
    else:
        print("Aucun palier en echec : la limite n'a pas ete atteinte, "
              "relancer avec des paliers superieurs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
