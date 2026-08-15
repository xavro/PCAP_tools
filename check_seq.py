#!/usr/bin/env python3
"""Analyse la continuite des numeros de sequence dans une capture de sortie.

Repond a la question « ou sont passes les messages manquants ? » sans comparer
deux compteurs releves a des instants differents — methode qui confond une
perte reelle avec un simple decalage de mesure.

Emettre avec `cot_generator.py --seq`, capturer la sortie du service GeoEvent
dans un fichier, puis :

    python check_seq.py sortie_geoevent.json

Fonctionne sur n'importe quel format texte (JSON, XML, log) : le script cherche
les motifs `SEQ=nnnnnn` ou qu'ils se trouvent.

Bibliotheque standard uniquement.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter

SEQ_RE = re.compile(r"SEQ=(\d+)")


def analyse(text: str, expected_total: int | None) -> int:
    found = [int(m.group(1)) for m in SEQ_RE.finditer(text)]
    if not found:
        print("Aucun motif SEQ= trouve.", file=sys.stderr)
        print("Le generateur a-t-il ete lance avec --seq, et <remarks> "
              "est-il conserve par la chaine ?", file=sys.stderr)
        return 2

    counts = Counter(found)
    unique = sorted(counts)
    lo, hi = unique[0], unique[-1]
    span = hi - lo + 1
    missing = [n for n in range(lo, hi + 1) if n not in counts]
    duplicates = {n: c for n, c in counts.items() if c > 1}

    print("=== CONTINUITE DES SEQUENCES ======================")
    print(f"occurrences lues     : {len(found)}")
    print(f"sequences distinctes : {len(unique)}")
    print(f"plage                : {lo} -> {hi} ({span} attendus sur la plage)")
    print(f"manquants dans plage : {len(missing)}")
    print(f"doublons             : {len(duplicates)}")

    if expected_total:
        print(f"attendus au total    : {expected_total}")
        before = lo - 1
        after = expected_total - hi
        if before > 0:
            print(f"  -> {before} message(s) AVANT le premier recu "
                  f"(emetteur demarre avant la mesure)")
        if after > 0:
            print(f"  -> {after} message(s) APRES le dernier recu "
                  f"(mesure arretee avant l'emetteur)")

    if missing:
        print()
        print("--- messages manquants ---")
        print(f"  {missing[:40]}{' ...' if len(missing) > 40 else ''}")
        # La repartition des trous designe la cause.
        gaps = []
        run_start = missing[0]
        previous = missing[0]
        for value in missing[1:]:
            if value != previous + 1:
                gaps.append((run_start, previous))
                run_start = value
            previous = value
        gaps.append((run_start, previous))
        longest = max(end - start + 1 for start, end in gaps)
        print(f"  {len(gaps)} trou(s), le plus long de {longest} message(s)")
        print()
        print("--- lecture ---")
        if len(gaps) == 1 and gaps[0][0] == lo:
            print("  Trou unique en debut : decalage de mesure, pas une perte.")
        elif longest == 1:
            print("  Trous isoles et disperses : echecs de parsing unitaires.")
            print("  Verifier les erreurs SAX dans les logs GeoEvent.")
        else:
            print("  Trous groupes : saturation de buffer ou coupure de flux.")
            print("  Verifier la taille du buffer et le lissage (--spread).")

    if duplicates:
        print()
        print("--- doublons ---")
        for seq, count in sorted(duplicates.items())[:20]:
            print(f"  SEQ={seq:06d} recu {count} fois")
        print("  Cause probable : reprise de l'adaptateur CoT apres un echec de")
        print("  parsing, qui reemet un message deja emis.")

    print("===================================================")
    return 0 if not missing and not duplicates else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verifie la continuite des SEQ dans une capture de sortie.")
    parser.add_argument("file", nargs="?",
                        help="fichier a analyser (defaut : entree standard)")
    parser.add_argument("--expected", type=int, default=None,
                        help="nombre total de messages emis, tel qu'annonce par "
                             "le generateur — situe les pertes hors plage")
    args = parser.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    return analyse(text, args.expected)


if __name__ == "__main__":
    sys.exit(main())
