#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aesd.py — décodeur des métadonnées ASCII « AESD » du système REAPER.

Flux UDP de texte pur, sans en-tête, sans séparateur d'enregistrement, sans somme de contrôle : une suite
continue de couples `<tag de 2 lettres><valeur>`. Les enregistrements ne sont PAS alignés sur les datagrammes
(un datagramme commence au milieu d'un champ) — le décodage se fait donc sur un tampon glissant, la coupure
d'un enregistrement étant le retour du premier tag du cycle (`Ta`).

Cycle nominal, 20 Hz :

    Ta+4540422 Te0 To-00019056 Tw0 Sr0.90 Sp6.33 Se-1.23 Sl-68 Sa+4539486 So-00019133
    Fv44.13 Ir-0.09 Ip-3.08 Ih218.15

auquel s'ajoutent, **une fois par seconde chacun et dans des enregistrements différents**, les champs
`Cd` (date), `Ct` (heure UTC), `Sn` (n° de capteur) et `Ic`. Tout champ est donc optionnel.

Sémantique établie en confrontant une capture AESD au flux 4609 du MÊME porteur pris deux minutes plus tôt
(`Capture9.pcapng` / `Capture8.pcap`, 2026-09-04) :

  - `Sa`/`So`/`Ta`/`To` sont en **degrés-minutes-secondes collés** (±[DDD]MMSSs, secondes au dixième) :
    la position ainsi décodée tombe à **5 m** de la position capteur du KLV ;
  - `Fv` = champ de vision horizontal : **44.13 exactement**, comme le tag 16 du KLV ;
  - `Ih`/`Ip`/`Ir` = cap / tangage / roulis plateforme (KLV 5, 6, 7 à 0,07° près) ;
  - `Sp` = **azimut vrai** de la ligne de visée : le KLV donne cap 218,15 + azimut relatif 147,545 = 5,7°,
    valeur de `Sp` ; recalculé depuis les positions, l'écart est de +0,65° ± 0,06° ;
  - `Se` = **angle de site** (négatif vers le bas) : distance × tan|Se| = 34,5 ± 1,1 m sur 3 600
    enregistrements alors que la distance varie de 1 654 à 960 m — donc bien un angle ;
  - `Sr` = **portée oblique en milles nautiques** : distance/`Sr` = 1 838 ± 11 m par unité (1 NM = 1 852 m,
    le pas de 0,01 NM valant 18 m) ;
  - `Sl` reste **indéterminé** (-68, parfois -70, sans corrélation avec la géométrie) : niveau de signal ?
  - `Te`, `Tw` et `Ic` étaient à 0 dans toute la capture de référence — non renseignés par la source.

Le flux ne porte NI altitude plateforme, NI champ vertical, NI coins d'empreinte, NI horodatage
sous-seconde : `Cd`+`Ct` ne datent qu'à la seconde. Sans somme de contrôle ni numéro de séquence, un
datagramme perdu corrompt silencieusement un enregistrement — d'où la validation de plage sur chaque champ.

Usage :
    python aesd.py capture.pcapng [--port 8001] [--csv sortie.csv] [--limit 0]
"""
import argparse
import calendar
import re
import statistics
import sys
import time

# tag -> (clé canonique, libellé, unité, conversion)
#   dms  : ±[DDD]MMSSs collés            num : décimal signé            int : entier            str : brut
FIELDS = {
    "Sa": ("lat", "Latitude plateforme", "°", "dms"),
    "So": ("lon", "Longitude plateforme", "°", "dms"),
    "Ta": ("tgt_lat", "Latitude point visé", "°", "dms"),
    "To": ("tgt_lon", "Longitude point visé", "°", "dms"),
    "Te": ("tgt_elev", "Élévation point visé", "m", "num"),
    "Tw": ("tgt_width", "Largeur cible", "m", "num"),
    "Sr": ("slant_nm", "Portée oblique", "NM", "num"),
    "Sp": ("los_az", "Azimut vrai de visée", "°", "num"),
    "Se": ("los_el", "Angle de site de visée", "°", "num"),
    "Sl": ("sl", "Sl (indéterminé — niveau ?)", "", "num"),
    "Fv": ("hfov", "Champ de vision horizontal", "°", "num"),
    "Ih": ("hdg", "Cap plateforme", "°", "num"),
    "Ip": ("pitch", "Tangage plateforme", "°", "num"),
    "Ir": ("roll", "Roulis plateforme", "°", "num"),
    "Sn": ("sensor", "Numéro de capteur", "", "int"),
    "Ic": ("ic", "Ic (indéterminé)", "", "int"),
    "Cd": ("date", "Date UTC (AAAAMMJJ)", "", "str"),
    "Ct": ("time", "Heure UTC (HHMMSS)", "", "str"),
}
CYCLE_START = "Ta"                       # premier champ du cycle : sert de coupure entre enregistrements
TOKEN = re.compile(r"([A-Z][a-z])([+-]?[0-9][0-9.]*)")
NM_M = 1852.0


def dms_to_deg(v):
    """±[DDD]MMSSs (minutes et secondes collées, secondes au dixième) -> degrés décimaux, None si invalide."""
    sign = -1.0 if v[:1] == "-" else 1.0
    d = v.lstrip("+-")
    if not d.isdigit() or len(d) < 6:
        return None
    deg, mn, sec = int(d[:-5]), int(d[-5:-3]), int(d[-3:]) / 10.0
    if mn > 59 or sec >= 60.0 or deg > 180:
        return None
    return round(sign * (deg + mn / 60.0 + sec / 3600.0), 7)      # 0,1" ≈ 3 m : 7 décimales suffisent


def _convert(tag, val):
    kind = FIELDS[tag][3]
    try:
        if kind == "dms":
            return dms_to_deg(val)
        if kind == "num":
            return float(val)
        if kind == "int":
            return int(float(val))
    except ValueError:
        return None
    return val


def looks_like_aesd(pl):
    """Signature STRUCTURELLE d'un datagramme AESD — pas seulement le port.

    Exigences : ASCII imprimable, entièrement couvert par des couples <tag><valeur>, et une majorité de tags
    connus. Un datagramme commençant au milieu d'un champ reste reconnu (le premier fragment est ignoré)."""
    if not pl or len(pl) < 24:
        return False
    try:
        txt = pl.decode("ascii")
    except UnicodeDecodeError:
        return False
    if any(not (32 <= ord(c) < 127) for c in txt):
        return False
    toks = TOKEN.findall(txt)
    if len(toks) < 4:
        return False
    covered = sum(len(a) + len(b) for a, b in toks)
    known = sum(1 for t, _ in toks if t in FIELDS)
    return covered >= 0.85 * len(txt) and known >= 0.8 * len(toks)


class Decoder:
    """Décodeur incrémental : `feed(octets)` -> liste d'enregistrements complets.

    Le tampon garde la fin du flux tant que le cycle n'est pas refermé, ce qui absorbe la coupure des
    enregistrements par les datagrammes. Il est borné : un flux qui ne serait pas de l'AESD ne le fait pas
    croître indéfiniment."""

    MAX_BUF = 65536

    def __init__(self):
        self.buf = ""
        self.pending = {}
        self.started = False

    def feed(self, data, t=None):
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("ascii", "replace")
        self.buf += data
        if len(self.buf) > self.MAX_BUF:
            self.buf = self.buf[-self.MAX_BUF:]
            self.pending = {}
        out = []
        pos = 0
        for m in TOKEN.finditer(self.buf):
            tag, val = m.group(1), m.group(2)
            if m.end() == len(self.buf):
                break                                   # valeur peut-être tronquée : on attend la suite
            pos = m.end()
            if tag == CYCLE_START:
                if self.started and self.pending:
                    out.append(self._emit(t))
                self.started = True
            if tag in FIELDS:
                self.pending[tag] = val
        self.buf = self.buf[pos:]
        return out

    def _emit(self, t):
        # Toutes les clés canoniques sont présentes, à None si le champ manque : les champs à 1 Hz (`Sn`,
        # `Cd`, `Ct`, `Ic`) n'apparaissent que dans un enregistrement sur vingt, et un consommateur ne
        # devrait pas avoir à distinguer « absent » de « pas dans ce cycle ».
        rec = {"t": t, "raw": dict(self.pending)}
        rec.update({f[0]: None for f in FIELDS.values()})
        for tag, val in self.pending.items():
            key = FIELDS[tag][0]
            rec[key] = _convert(tag, val)
        self.pending = {}
        rec["slant_m"] = round(rec["slant_nm"] * NM_M, 1) if isinstance(rec.get("slant_nm"), float) else None
        return rec


def decode_bytes(blob):
    """Décode un flux AESD complet (octets concaténés) -> liste d'enregistrements."""
    d = Decoder()
    return d.feed(blob)


def _mark_epoch(date, tm):
    """`Cd`+`Ct` (AAAAMMJJ, HHMMSS) -> epoch UTC, None si l'un manque ou est malformé."""
    if not date or not tm or len(date) != 8 or len(tm) != 6 or not (date + tm).isdigit():
        return None
    try:
        return calendar.timegm((int(date[:4]), int(date[4:6]), int(date[6:]),
                                int(tm[:2]), int(tm[2:4]), int(tm[4:]), 0, 0, 0))
    except ValueError:
        return None


def _stamp(recs):
    """Date chaque enregistrement en UTC.

    Le flux ne porte l'heure qu'UNE FOIS PAR SECONDE (`Cd`+`Ct`), alors qu'il produit 20 enregistrements par
    seconde : dater uniquement les enregistrements marqués laisserait 19 lignes sur 20 sans heure. On cale
    donc l'horloge de capture sur les marques — décalage médian, robuste aux datagrammes retardés — et on
    date tout le reste par cet écart. La précision RELATIVE vaut celle de la capture (~ms) ; le biais ABSOLU
    peut atteindre 1 s, la marque n'indiquant pas à quel instant de la seconde elle a été émise."""
    # `Cd` et `Ct` ne tombent PAS dans le même enregistrement (chaque champ à 1 Hz arrive dans un cycle
    # différent) : on garde la dernière date vue, avec repli sur la première de la capture pour les marques
    # d'heure qui la précèdent.
    first_date = next((r["date"] for r in recs if r.get("date")), None)
    date = first_date
    offs = []
    for r in recs:
        if r.get("date"):
            date = r["date"]
        if r.get("time") and r.get("t") is not None:
            e = _mark_epoch(date, r["time"])
            if e is not None:
                offs.append(e - r["t"])
    if not offs:
        return
    off = statistics.median(offs)
    for r in recs:
        if r.get("t") is not None:
            r["utc"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(r["t"] + off)) + ".%02dZ" % (((r["t"] + off) % 1) * 100)
            r["utc_epoch"] = round(r["t"] + off, 3)


def aesd_ports(path, limit=0):
    """Ports UDP portant de l'AESD dans un pcap : {dport: {pkts, bytes, src, dst}}."""
    import pcap_analyze
    seen = {}
    n = 0
    for ts, linktype, frame in pcap_analyze.iter_frames(path):
        n += 1
        if limit and n > limit:
            break
        r = pcap_analyze.parse(linktype, frame)
        if not r or r[0] != "UDP":
            continue
        _, src, _, dst, dport, pl = r
        e = seen.get(dport)
        if e is None:
            if not looks_like_aesd(pl):
                continue
            e = seen[dport] = {"pkts": 0, "bytes": 0, "src": src, "dst": dst, "t0": ts, "t1": ts}
        e["pkts"] += 1
        e["bytes"] += len(pl)
        e["t1"] = ts
    return seen


def records_from_pcap(path, dport=None, limit=0):
    """Décode l'AESD d'un pcap. `dport` None = port AESD le plus bavard. -> dict prêt pour l'API/console."""
    import pcap_analyze
    ports = aesd_ports(path, limit)
    if not ports:
        return {"port": None, "n": 0, "records": [], "ports": {}}
    if dport is None:
        dport = max(ports, key=lambda p: ports[p]["pkts"])
    dport = int(dport)
    if dport not in ports:
        raise ValueError("aucun flux AESD sur le port %d" % dport)
    dec = Decoder()
    recs = []
    n = 0
    cap_t0 = None
    for ts, linktype, frame in pcap_analyze.iter_frames(path):
        n += 1
        if cap_t0 is None:
            cap_t0 = ts                          # origine de la barre de temps de la console
        if limit and n > limit:
            break
        r = pcap_analyze.parse(linktype, frame)
        if not r or r[0] != "UDP" or r[4] != dport:
            continue
        recs.extend(dec.feed(r[5], ts))
    _stamp(recs)
    for r in recs:
        r["dt"] = round(r["t"] - cap_t0, 3) if (cap_t0 is not None and r.get("t") is not None) else None
    info = ports[dport]
    dur = (recs[-1]["t"] - recs[0]["t"]) if len(recs) > 1 else 0.0
    return {"port": dport, "src": info["src"], "dst": info["dst"], "pkts": info["pkts"], "bytes": info["bytes"],
            "capture_t0": cap_t0,
            "duration_s": round(dur, 3), "hz": round(len(recs) / dur, 2) if dur > 0 else None,
            "n": len(recs), "utc_first": next((r["utc"] for r in recs if r.get("utc")), None),
            "utc_last": next((r["utc"] for r in reversed(recs) if r.get("utc")), None),
            "fields": [{"tag": t, "key": FIELDS[t][0], "name": FIELDS[t][1], "unit": FIELDS[t][2]} for t in FIELDS],
            "ports": {str(p): {"pkts": v["pkts"], "bytes": v["bytes"], "src": v["src"], "dst": v["dst"]} for p, v in ports.items()},
            "records": recs}


CSV_COLS = ["t", "dt", "utc", "utc_epoch", "lat", "lon", "tgt_lat", "tgt_lon", "tgt_elev", "tgt_width",
            "slant_nm", "slant_m", "los_az", "los_el", "hfov", "hdg", "pitch", "roll", "sensor", "sl", "ic"]


def to_csv(recs):
    out = [";".join(CSV_COLS)]
    for r in recs:
        out.append(";".join("" if r.get(c) is None else str(r.get(c)) for c in CSV_COLS))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Décodeur AESD (métadonnées ASCII REAPER) d'un pcap/pcapng.")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=None, help="port UDP (défaut : le flux AESD le plus bavard)")
    ap.add_argument("--limit", type=int, default=0, help="nombre de paquets à lire (0 = tout)")
    ap.add_argument("--csv", help="écrire les enregistrements décodés dans ce fichier")
    a = ap.parse_args(argv)
    d = records_from_pcap(a.pcap, a.port, a.limit)
    if not d["n"]:
        print("aucun flux AESD détecté dans %s" % a.pcap)
        return 1
    print("port %s : %s → %s · %d datagrammes · %d enregistrements · %.1f s · %s Hz"
          % (d["port"], d["src"], d["dst"], d["pkts"], d["n"], d["duration_s"], d["hz"]))
    print("UTC : %s → %s" % (d["utc_first"], d["utc_last"]))
    r = d["records"][0]
    for tag, (key, name, unit, _k) in FIELDS.items():
        if r.get(key) is not None:
            print("   %s  %-28s %s %s" % (tag, name, r[key], unit))
    if a.csv:
        with open(a.csv, "w", encoding="utf-8") as f:
            f.write(to_csv(d["records"]))
        print("CSV : %s (%d lignes)" % (a.csv, d["n"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
