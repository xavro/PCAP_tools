#!/usr/bin/env python3
"""Reconditionne `cot-adapter-10.6.0.jar` avec une definition CoT completee.

Contexte
--------
La propriete `XSD_Path` du connecteur CoT d'Esri n'est jamais lue par le code
(cf. `docs/defect-report-cot-adapter.md`). La GeoEvent Definition `CoT` est
figee dans la ressource `input-adapter-definition.xml` embarquee dans le jar :
la remplacer est le seul moyen d'ajouter des champs `detail/*`.

Ce script ne touche QUE cette entree. Toutes les autres — classes, MANIFEST,
blueprint OSGi, `CoTtypes.xml` — sont recopiees octet pour octet, dans leur
ordre d'origine, pour que le bundle reste resoluble par le conteneur.

Aucune recompilation, aucun code Java modifie.

Chaine complete
---------------
    python gen_cot_definition.py --patch <extrait du jar> -o definition.xml
    python patch_cot_jar.py cot-adapter-10.6.0.jar definition.xml -o cot-adapter-10.6.0-isrbox.jar

Le jar produit se depose dans le repertoire de deploiement de GeoEvent Server,
apres retrait de l'original. **Supprimer ensuite la GeoEvent Definition `CoT`
dans GeoEvent Manager** : l'adaptateur ne l'enregistre que si aucune definition
de ce nom n'existe deja, et ne la met jamais a jour.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys
import zipfile

ENTRY = "input-adapter-definition.xml"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("jar", help="cot-adapter-10.6.0.jar d'origine")
    ap.add_argument("definition", help="input-adapter-definition.xml de remplacement")
    ap.add_argument("-o", "--output", help="jar produit (defaut : <jar>-isrbox.jar)")
    ap.add_argument("--extract", action="store_true",
                    help="extraire la ressource d'origine au lieu de patcher")
    args = ap.parse_args()

    source = pathlib.Path(args.jar)
    if not source.is_file():
        sys.exit(f"jar introuvable : {source}")

    if args.extract:
        with zipfile.ZipFile(source) as zf:
            pathlib.Path(args.definition).write_bytes(zf.read(ENTRY))
        print(f"{ENTRY} extrait vers {args.definition}")
        return 0

    replacement = pathlib.Path(args.definition)
    if not replacement.is_file():
        sys.exit(f"definition introuvable : {replacement}")

    payload = replacement.read_bytes()
    # Garde-fou : une definition tronquee produirait un bundle qui demarre mais
    # ne sort aucun evenement, panne bien plus couteuse a diagnostiquer.
    for marker in (b'<geoEventDefinition name="CoT">', b'name="detail" type="Group"',
                   b'propertyName="CoT_Types_Path"'):
        if marker not in payload:
            sys.exit(f"la definition ne contient pas {marker.decode()!r} — refus de patcher")

    destination = pathlib.Path(args.output) if args.output else \
        source.with_name(source.stem + "-isrbox" + source.suffix)
    if destination.resolve() == source.resolve():
        sys.exit("refus d'ecraser le jar d'origine : indiquer -o")

    with zipfile.ZipFile(source) as src:
        if ENTRY not in src.namelist():
            sys.exit(f"{ENTRY} absent du jar — mauvais fichier ?")
        original = src.read(ENTRY)
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                data = payload if item.filename == ENTRY else src.read(item.filename)
                # On conserve l'ordre et les metadonnees d'origine : le MANIFEST
                # doit rester la premiere entree utile du jar.
                info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                info.compress_type = item.compress_type
                info.external_attr = item.external_attr
                info.create_system = item.create_system
                dst.writestr(info, data)

    backup = source.with_suffix(source.suffix + ".orig")
    if not backup.exists():
        shutil.copy2(source, backup)
        print(f"original sauvegarde : {backup}")

    print(f"{destination}")
    print(f"  {ENTRY} : {len(original)} -> {len(payload)} octets")
    print("\nDeploiement :")
    print("  1. arreter ArcGIS GeoEvent Server")
    print("  2. retirer le jar d'origine du repertoire de deploiement")
    print("  3. y deposer le jar produit, redemarrer le service")
    print("  4. verifier dans les logs que le bundle se resout et demarre")
    print("  5. SUPPRIMER la GeoEvent Definition `CoT` dans GeoEvent Manager")
    print("  6. redemarrer l'input, emettre un message : la definition est recreee")
    return 0


if __name__ == "__main__":
    sys.exit(main())
