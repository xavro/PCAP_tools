#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_amorcage_profils.py — l'amorcage du depot de profils : ce qui se passe au premier demarrage du conteneur.

En V2, GMTI_PROFILES pointe /data/gmti/gmti_profiles.json, un volume vide au premier lancement. Sans
amorcage, l'editeur de la console n'a AUCUN parametre a proposer — leur description vit dans ce fichier.
Et un depot existant ne doit jamais etre ecrase : il porte les reglages de l'exploitant.

    python test_amorcage_profils.py
"""
import io, json, os, shutil, sys, tempfile
TOOLS = r"C:\Users\xavco\Documents\Mes Projets\DATA\Tools"
tmp = tempfile.mkdtemp(prefix="stx-amorce-")
cible = os.path.join(tmp, "gmti", "gmti_profiles.json")
os.environ["GMTI_PROFILES"] = cible
sys.path.insert(0, TOOLS)
import pcap_web as W

ok = fail = 0
def chk(l, c, d=""):
    global ok, fail
    if c: ok += 1; print("  OK    %s" % l)
    else: fail += 1; print("  ECHEC %s  %s" % (l, d))

print("premier demarrage : volume vide")
chk("le depot n'existe pas encore", not os.path.isfile(cible))
tr = W.load_track_run()
chk("le depot a ete cree", os.path.isfile(cible), cible)
v = W.gmti_profiles()
chk("l'editeur a des parametres", len(v["params"]) >= 56, len(v["params"]))
chk("generation annoncee", v.get("generation") == "v9", v.get("generation"))

print("\ndemarrage suivant : le depot porte des reglages de l'exploitant")
d = json.load(io.open(cible, encoding="utf-8"))
d.setdefault("v9", {})["maritime"] = {"gate_max_m": 333.0}
io.open(cible, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False, indent=2))
W._TRACK_RUN[0] = None                                   # on rejoue un demarrage
tr = W.load_track_run()
tr.load_profiles(cible)
d2 = json.load(io.open(cible, encoding="utf-8"))
chk("le depot existant n'est pas ecrase", d2.get("v9", {}).get("maritime", {}).get("gate_max_m") == 333.0,
    json.dumps(d2.get("v9", {}))[:100])
chk("le reglage de l'exploitant est applique", tr.PROFILES["maritime"].gate_max_m == 333.0,
    tr.PROFILES["maritime"].gate_max_m)

shutil.rmtree(tmp, ignore_errors=True)
print("\n%d controles OK, %d echecs" % (ok, fail))
sys.exit(1 if fail else 0)
