#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_profils_console.py — l'edition de profils de la console agit-elle sur le tracker charge ?

C'etait le defaut a corriger : la console ecrivait les noms Java du v8 dans une section que le v9 ne
relit pas. Une modification restait donc sans effet, sans le moindre message. On rejoue ici le parcours
complet de la console — lecture, modification, enregistrement, relecture — puis on verifie que le
PISTAGE change vraiment, ce qui est la seule preuve qui compte.

    python test_profils_console.py
"""
import io
import json
import os
import shutil
import sys
import tempfile

TOOLS = r"C:\Users\xavco\Documents\Mes Projets\DATA\Tools"
sys.path.insert(0, TOOLS)

tmp = tempfile.mkdtemp(prefix="stx-prof-")
profils = os.path.join(tmp, "gmti_profiles.json")
shutil.copy(os.path.join(TOOLS, "gmti_profiles.json"), profils)
os.environ["GMTI_PROFILES_V9"] = profils

import pcap_web as W  # noqa: E402

ok = fail = 0


def chk(label, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1; print("  OK    %s" % label)
    else:
        fail += 1; print("  ECHEC %s  %s" % (label, detail))


tr = W.load_track_run()
tr.PROFILES_JSON = profils
tr.load_profiles(profils)

print("vue servie a la console")
v = W.gmti_profiles()
chk("generation annoncee", v.get("generation") == "v9", v.get("generation"))
chk("parametres decrits", len(v["params"]) >= 56, len(v["params"]))
chk("noms de champs v9", "gate_max_m" in v["defaults"], sorted(v["defaults"])[:5])
chk("aucun nom Java residuel", "gateMaxM" not in v["defaults"])
chk("reglage d'affichage conserve", "projectSec" in v["params"] and v["defaults"].get("projectSec") == 60.0)
chk("tous les groupes ont un titre cote console",
    set(m["group"] for m in v["params"].values()) <= {
        "briques", "gate", "dynamique", "mesure", "mdv", "vie", "aerien", "cluster", "fusion",
        "contact", "filtre", "affichage"},
    sorted({m["group"] for m in v["params"].values()}))
chk("profil maritime present", "maritime" in v["names"])

print("\nenregistrement d'une modification, comme le bouton « enregistrer »")
eff = dict(v["effective"]["maritime"])
avant = tr.PROFILES["maritime"].gate_max_m
eff["gate_max_m"] = 777.0
eff["doppler_enabled"] = False
W.gmti_profile_save("maritime", eff)
tr.load_profiles(profils)
chk("le reglage numerique agit sur le tracker", tr.PROFILES["maritime"].gate_max_m == 777.0,
    "%s -> %s" % (avant, tr.PROFILES["maritime"].gate_max_m))
chk("le reglage booleen agit sur le tracker", tr.PROFILES["maritime"].doppler_enabled is False)

d = json.load(io.open(profils, encoding="utf-8"))
chk("ecrit dans la section v9", d.get("v9", {}).get("maritime", {}).get("gate_max_m") == 777.0,
    json.dumps(d.get("v9", {}).get("maritime", {}))[:120])
chk("section v8 intacte (processor Java et v8.1)", d["profiles"]["maritime"].get("gateMaxM") == 500)
chk("seuls les ECARTS sont enregistres", "sigma_min_m" not in d["v9"]["maritime"],
    sorted(d["v9"]["maritime"]))

print("\neffet reel sur le pistage")
csv = os.environ.get("GMTI_TEST_CSV") or os.path.join(TOOLS, "plots.csv")
if os.path.isfile(csv):
    tr.load_profiles(profils)
    r1 = tr.run_tracking(csv, "maritime", {})
    d["v9"]["maritime"]["gate_max_m"] = 60.0                 # porte tres serree : le resultat DOIT changer
    io.open(profils, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False, indent=2))
    tr.load_profiles(profils)
    r2 = tr.run_tracking(csv, "maritime", {})
    chk("changer la porte change le resultat du pistage",
        len(r1["tracks"]) != len(r2["tracks"]) or r1["metrics"]["hits_total"] != r2["metrics"]["hits_total"],
        "%d pistes / %d hits contre %d / %d" % (len(r1["tracks"]), r1["metrics"]["hits_total"],
                                                len(r2["tracks"]), r2["metrics"]["hits_total"]))
else:
    print("  (capture cargo.csv absente : controle de pistage saute)")

print("\nsuppression d'un profil")
W.gmti_profile_save("maritime", None)
d = json.load(io.open(profils, encoding="utf-8"))
chk("profil retire de la section v9", "maritime" not in d.get("v9", {}))
try:
    W.gmti_profile_save("defaut", None)
    chk("le profil « defaut » est protege", False, "suppression acceptee a tort")
except ValueError:
    chk("le profil « defaut » est protege", True)

shutil.rmtree(tmp, ignore_errors=True)
print("\n%d controles OK, %d echecs" % (ok, fail))
sys.exit(1 if fail else 0)
