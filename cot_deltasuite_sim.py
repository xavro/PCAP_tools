#!/usr/bin/env python3
"""Simulateur de points CoT au format Delta Suite (societe Impact).

POC ISRBOX / 33e ESRA — banc de test symbologie MIL-STD-2525 / dictionnaire APP-6.

But : emettre en masse des points de TYPES varies, exactement comme Delta Suite les
formaterait, pour eprouver d'un seul tir la reconstruction SIDC du receiver et le
dictionnaire 2525 de la carte web — sans creer les points un a un dans Delta Suite.

Principe (etabli par capture reelle du 23/07/2026) :
  - Delta Suite n'emet AUCUN code symbole ; son `<detail>` est vide.
  - le `type` CoT EST le SIDC dont on a retire les tirets
    (SFGPIBN---HK---  ->  a-f-G-P-I-B-N-H-K).
On INVERSE donc la marshalling APP-6 de Delta Suite (tables app6/marshalling/*.csv,
extraites de son module delta-suite-app6) : on choisit des symboles reels, on
superpose leurs gabarits pour obtenir le SIDC, puis on le compacte en type CoT.
Le receiver, lui, refera le chemin inverse et doit retomber sur le meme SIDC.

Contraintes de conception (identiques au reste du POC) :
  - bibliotheque standard uniquement ;
  - un datagramme UDP = un seul message CoT XML, prologue <?xml ...?> compris ;
  - format de trame calque sur la capture Delta Suite (ordre des attributs,
    version 2.0, how m-r, opex o-, qos 1-r-c, <detail/> vide, horodatage ms + Z).

Usage minimal (echantillon representatif vers le port UDP du receiver) :
    python cot_deltasuite_sim.py --host 192.168.1.50 --port 6969

Autres exemples :
    python cot_deltasuite_sim.py --dry-run              # n'emet rien, verifie tout
    python cot_deltasuite_sim.py --all --host X --port Y # catalogue complet
    python cot_deltasuite_sim.py --count 120 --seed 7    # echantillon reproductible
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import quoteattr

# --------------------------------------------------------------------------
# Constantes — format Delta Suite (calque sur capture)
# --------------------------------------------------------------------------

PROLOG = "<?xml version='1.0' standalone='yes'?>\n"
HOW = "m-r"
OPEX = "o-"
QOS = "1-r-c"
VERSION = "2.0"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6969
DEFAULT_CENTER_LAT = 45.70          # secteur Charente-Maritime (cf. PORT KIRIKOU)
DEFAULT_CENTER_LON = -0.90
DEFAULT_SPACING = 0.045             # ~5 km entre points de la grille
DEFAULT_GAP_MS = 15                 # anti-coalescence, tenable par le receiver

# Quatre affiliations principales = quatre cadres 2525 (rectangle / losange /
# carre / quadrilobe). Les codes correspondent a la 1re lettre de app6 identity.
MAIN_IDENTITIES = ["f", "h", "n", "u"]

DASH = "-" * 15


# --------------------------------------------------------------------------
# Marshalling APP-6 (miroir Python de CotApp6Sidc.java)
# --------------------------------------------------------------------------

class App6Tables:
    """Charge les 7 tables APP-6 et sait superposer / compacter / reconstruire."""

    def __init__(self, tables_dir: str):
        self.identity: dict[str, str] = {}      # lettre affiliation -> gabarit
        self.status: list[str] = []
        self.size: list[str] = []
        self.mobility: list[str] = []
        self.cores: list[tuple[str, str, str]] = []  # (gabarit, name, battleDimension)
        bd_by_name: dict[str, str] = {}

        self.identity_name: dict[str, str] = {}   # lettre affiliation -> libelle
        for row in self._load(tables_dir, "identity.csv"):
            e = self._tpl(row.get("encode"))
            if e:
                self.identity[e[1].lower()] = e
                self.identity_name[e[1].lower()] = row.get("name", "")
        self.status = [self._tpl(r.get("encode")) for r in self._load(tables_dir, "status.csv")]
        self.size = [self._tpl(r.get("encode")) for r in self._load(tables_dir, "size.csv")]
        self.mobility = [self._tpl(r.get("encode")) for r in self._load(tables_dir, "mobility.csv")]
        self.status = [x for x in self.status if x]
        self.size = [x for x in self.size if x]
        self.mobility = [x for x in self.mobility if x]

        for r in self._load(tables_dir, "battleDimension.csv"):
            e = self._tpl(r.get("encode"))
            if not e:
                continue
            self.cores.append((e, r.get("name", ""), r.get("name", "")))
            if r.get("name"):
                bd_by_name[r["name"]] = e
        for fname in ("type.csv", "subtype.csv"):
            for r in self._load(tables_dir, fname):
                e = self._tpl(r.get("encode"))
                if not e:
                    continue
                bd = bd_by_name.get(r.get("battleDimension", ""))
                if bd:
                    e = self.overlay(bd, e)         # complete les deltas ----EVS----
                self.cores.append((e, r.get("name", ""), r.get("battleDimension", "")))

    # -- E/S -------------------------------------------------------------
    @staticmethod
    def _load(tables_dir: str, fname: str) -> list[dict]:
        path = os.path.join(tables_dir, fname)
        with open(path, encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))

    @staticmethod
    def _tpl(encode: str | None) -> str | None:
        if not encode:
            return None
        s = encode.split("/", 1)[0]
        return s if len(s) == 15 else None

    # -- superposition / compaction -------------------------------------
    @staticmethod
    def overlay(*tpls: str) -> str:
        out = list(DASH)
        for t in tpls:
            for i, c in enumerate(t):
                if c != "-":
                    out[i] = c
        return "".join(out)

    @staticmethod
    def compact(sidc: str) -> str:
        chars = [c for c in sidc if c != "-"]
        if len(chars) <= 1:
            return "a" if chars else ""
        tail = "-".join([chars[1].lower()] + chars[2:])
        return "a-" + tail

    @staticmethod
    def present(sidc: str) -> str:
        """Statut position 4 -> P si vide (defaut 2525, aligne le receiver)."""
        if len(sidc) >= 4 and sidc[3] == "-":
            sidc = sidc[:3] + "P" + sidc[4:]
        return sidc

    def build_index(self, identities: list[str]) -> dict[str, tuple[str, str, str]]:
        """Rejoue la recherche du receiver en UNE passe, MEME ordre imbrique
        (premier gagnant = setdefault), et renvoie {type CoT -> (SIDC, nom, dimension)}.

        L'ordre reproduit exactement CotApp6Sidc.search : par core, d'abord sans
        statut, puis chaque statut, puis tailles, puis mobilites. Le SIDC, le nom et
        la dimension stockes sont donc CEUX que le receiver produira — aucun ecart.
        La cle contient l'affiliation, donc pas de collision inter-identite."""
        m: dict[str, tuple[str, str, str]] = {}
        for ident in identities:
            idt = self.identity.get(ident)
            if not idt:
                continue
            for core, name, bd in self.cores:
                base0 = self.overlay(idt, core)
                m.setdefault(self.compact(base0), (self.present(base0), name, bd))
                for st in self.status:
                    base = self.overlay(idt, core, st)
                    m.setdefault(self.compact(base), (self.present(base), name, bd))
                    for sz in self.size:
                        w = self.overlay(base, sz)
                        m.setdefault(self.compact(w), (self.present(w), name, bd))
                    for mb in self.mobility:
                        w = self.overlay(base, mb)
                        m.setdefault(self.compact(w), (self.present(w), name, bd))
        return m


# --------------------------------------------------------------------------
# Selection des symboles a emettre
# --------------------------------------------------------------------------

class Symbol:
    __slots__ = ("cot_type", "sidc", "name", "identity")

    def __init__(self, cot_type, sidc, name, identity):
        self.cot_type = cot_type
        self.sidc = sidc
        self.name = name
        self.identity = identity


def catalogue_from_index(index: dict[str, tuple[str, str]]) -> list[Symbol]:
    """Transforme l'index {type -> (SIDC, nom)} en catalogue de symboles.
    Chaque entree est un type DISTINCT que le receiver sait produire, avec le SIDC
    et le nom EXACTS qu'il en tirera : nom, icone et code restent coherents."""
    out: list[Symbol] = []
    for cot_type, (sidc, name, _bd) in index.items():
        if not sidc:
            continue
        parts = cot_type.split("-")
        ident = parts[1] if len(parts) > 1 else "?"
        out.append(Symbol(cot_type, sidc, name or "(marqueur)", ident))
    return out


def dedupe_by_icon(symbols: list[Symbol]) -> list[Symbol]:
    """Une entree par ICONE de base : schema + affiliation + dimension + fonction
    (positions 1-3 et 5-10). On EXCLUT de la cle le statut (pos 4 : Present /
    Damaged / Destroyed...) et la taille/mobilite (pos 11-12), qui ne sont que des
    decorations. On garde le type le plus court (le symbole nominal)."""
    best: dict[str, Symbol] = {}
    for s in symbols:
        key = s.sidc[:3] + s.sidc[4:10]
        cur = best.get(key)
        if cur is None or s.cot_type.count("-") < cur.cot_type.count("-"):
            best[key] = s
    return list(best.values())


def stratified_sample(symbols: list[Symbol], count: int, seed) -> list[Symbol]:
    """Echantillonne en garantissant la presence de chaque affiliation (cadres)."""
    rnd = random.Random(seed)
    by_ident: dict[str, list[Symbol]] = {}
    for s in symbols:
        by_ident.setdefault(s.identity, []).append(s)
    per = max(1, count // max(1, len(by_ident)))
    chosen: list[Symbol] = []
    for group in by_ident.values():
        chosen.extend(rnd.sample(group, min(per, len(group))))
    # Complete au besoin avec le reste, sans doublon.
    if len(chosen) < count:
        rest = [s for s in symbols if s not in chosen]
        rnd.shuffle(rest)
        chosen.extend(rest[: count - len(chosen)])
    return chosen[:count]


# --------------------------------------------------------------------------
# Fabrication et emission des messages CoT
# --------------------------------------------------------------------------

def iso(dt: datetime) -> str:
    """ISO 8601 UTC avec millisecondes et suffixe Z (format Delta Suite)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_event(sym: Symbol, seq: int, lat: float, lon: float,
                now: datetime, stale_s: int) -> str:
    uid = f"DeltaSuite-SIM-{seq:04d}.{sym.name}"
    time_s = iso(now)
    start_s = iso(now - timedelta(minutes=30))
    stale_s_iso = iso(now + timedelta(seconds=stale_s))
    return (
        f"<event uid={quoteattr(uid)} time={quoteattr(time_s)} "
        f"start={quoteattr(start_s)} stale={quoteattr(stale_s_iso)} "
        f"type={quoteattr(sym.cot_type)} how={quoteattr(HOW)} "
        f"version={quoteattr(VERSION)} opex={quoteattr(OPEX)} qos={quoteattr(QOS)}>"
        f"<point lat=\"{lat:.8f}\" lon=\"{lon:.8f}\" hae=\"0.0\" le=\"0.0\" ce=\"0.0\"/>"
        f"<detail/></event>"
    )


def grid_positions(n: int, center_lat: float, center_lon: float,
                   spacing: float) -> list[tuple[float, float]]:
    cols = max(1, int(round(n ** 0.5)))
    positions = []
    for i in range(n):
        r, c = divmod(i, cols)
        lat = center_lat - r * spacing
        lon = center_lon + (c - cols / 2) * spacing
        positions.append((lat, lon))
    return positions


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simulateur de points CoT format Delta Suite")
    ap.add_argument("--host", default=DEFAULT_HOST, help="hote UDP du receiver GeoEvent")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="port UDP (defaut 6969)")
    ap.add_argument("--tables", default=None,
                    help="dossier des CSV APP-6 (defaut : app6/marshalling a cote du script)")
    ap.add_argument("--count", type=int, default=60,
                    help="nombre de symboles a tirer au hasard (defaut 60)")
    ap.add_argument("--all", action="store_true", help="emettre TOUT le catalogue (apres filtrage icones)")
    ap.add_argument("--modifiers", action="store_true",
                    help="garder les variantes taille/mobilite (echelons) au lieu d'une icone unique")
    ap.add_argument("--identities", default="f,h,n,u",
                    help="affiliations a couvrir, ex : f,h,n,u")
    ap.add_argument("--center-lat", type=float, default=DEFAULT_CENTER_LAT)
    ap.add_argument("--center-lon", type=float, default=DEFAULT_CENTER_LON)
    ap.add_argument("--spacing", type=float, default=DEFAULT_SPACING,
                    help="pas de la grille en degres (defaut 0.045 ~5 km)")
    ap.add_argument("--gap-ms", type=int, default=DEFAULT_GAP_MS,
                    help="pause entre datagrammes en ms (anti-coalescence)")
    ap.add_argument("--stale-s", type=int, default=3600,
                    help="duree de vie des points en secondes (defaut 1h)")
    ap.add_argument("--seed", type=int, default=None, help="graine aleatoire (reproductibilite)")
    ap.add_argument("--dry-run", action="store_true",
                    help="n'emet rien : verifie la reconstruction et affiche un apercu")
    args = ap.parse_args(argv)

    tables_dir = args.tables or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "app6", "marshalling")
    if not os.path.isdir(tables_dir):
        ap.error(f"dossier de tables introuvable : {tables_dir}")
    tables = App6Tables(tables_dir)

    identities = [x.strip() for x in args.identities.split(",") if x.strip()]
    print("Construction du catalogue (rejeu de la marshalling APP-6)...", flush=True)
    index = tables.build_index(identities)          # {type -> (SIDC, nom) du receiver}
    catalogue = catalogue_from_index(index)         # zero drift : SIDC = sortie receiver
    pool = catalogue if args.modifiers else dedupe_by_icon(catalogue)

    usable = pool
    if not args.all and args.count < len(pool):
        usable = stratified_sample(pool, args.count, args.seed)
    usable.sort(key=lambda s: (s.identity, s.cot_type))

    counts: dict[str, int] = {}
    for s in usable:
        counts[s.identity] = counts.get(s.identity, 0) + 1
    repartition = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
    scope = "avec echelons" if args.modifiers else "icones distinctes"
    print(f"Tables   : {tables_dir}")
    print(f"Catalogue: {len(index)} types reconstructibles -> {len(pool)} {scope}")
    print(f"A emettre: {len(usable)} points ({repartition})")

    positions = grid_positions(len(usable), args.center_lat, args.center_lon, args.spacing)
    now = datetime.now(timezone.utc)

    if args.dry_run:
        print("\n--- apercu (5 premiers datagrammes) ---")
        for i, s in enumerate(usable[:5]):
            lat, lon = positions[i]
            print(PROLOG + build_event(s, i, lat, lon, now, args.stale_s))
        print(f"\n[dry-run] rien envoye. {len(usable)} points prets pour {args.host}:{args.port}")
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for i, s in enumerate(usable):
            lat, lon = positions[i]
            datagram = (PROLOG + build_event(s, i, lat, lon, now, args.stale_s)).encode("utf-8")
            sock.sendto(datagram, (args.host, args.port))
            sent += 1
            if args.gap_ms > 0:
                time.sleep(args.gap_ms / 1000.0)
    finally:
        sock.close()
    print(f"\n{sent} points CoT format Delta Suite envoyes vers {args.host}:{args.port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
