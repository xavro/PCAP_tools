#!/usr/bin/env python3
"""Ajoute des groupes `detail/*` a la GeoEvent Definition CoT d'Esri.

Pourquoi cet outil existe
-------------------------
La propriete `XSD_Path` du connecteur CoT d'Esri est **inoperante**. Elle est
declaree dans l'IHM et meme marquee obligatoire, mais aucune ligne du jar ne la
lit : le constructeur de `CoTAdapterServiceInbound` se borne a charger trois
ressources embarquees, et le parseur de XSD (`CoTDetailsDeff`) n'est appele par
personne. Verifie sur `cot-adapter-10.6.0.jar` (release 202104).

Consequence : deposer un XSD dans un repertoire n'a aucun effet, et tout
element de `detail` absent de la definition figee est perdu silencieusement a la
reception. Le seul moyen d'ajouter des champs est de **regenerer la ressource
`input-adapter-definition.xml` et de la replacer dans le jar**.

Ce que fait ce script
---------------------
Il lit la ressource livree par Esri, y **ajoute** les groupes decrits par les
XSD qui ne sont pas d'origine, et reecrit le fichier. Le bloc livre n'est pas
regenere : ses champs, leurs types et leur ordre sont conserves tels quels. Deux
raisons a ce choix conservateur :

  - `CoTAdapterInbound` alimente les champs racine par **indice positionnel** ;
    toute reorganisation les decale silencieusement ;
  - la definition livree contient des anomalies non reproductibles par une
    regle (cf. `--audit`) qu'il vaut mieux ne pas toucher a l'aveugle.

Si un groupe genere porte le nom d'un groupe existant, ses attributs manquants
sont **fusionnes** dans le groupe existant plutot que de le dupliquer. C'est
ainsi que `detail/uid/@Droid` est ajoute au groupe `uid` livre.

Les regles de generation rejouent celles du parseur mort `CoTDetailsDeff` :

  - `xs:element`   -> champ Group, precede d'un enfant `#text`
  - `xs:attribute` -> champ scalaire type d'apres l'attribut `type`
  - `xs:any` / `xs:anyAttribute` -> ignores
  - attribut type par un `xs:simpleType` anonyme -> type perdu, donc String
  - `maxOccurs="unbounded"` -> cardinalite Many

Usage
-----
    python gen_cot_definition.py --audit                 # ecarts regle / livre
    python gen_cot_definition.py                         # apercu des ajouts
    python gen_cot_definition.py --patch input-adapter-definition.xml \
                                 -o input-adapter-definition.xml
"""

from __future__ import annotations

import argparse
import copy
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

XS = "{http://www.w3.org/2001/XMLSchema}"

# Table de `CoTDetailsDeff.lookupType`. Volontairement aussi courte que
# l'originale : xs:double, xs:float, xs:long, xs:int, xs:date n'y figurent pas
# cote Esri et retombent sur String.
TYPE_MAP = {
    "": "String",
    "xs:string": "String",
    "xs:dateTime": "Date",
    "xs:integer": "Integer",
    "xs:nonNegativeInteger": "Integer",
    "xs:decimal": "Double",
    "xs:boolean": "Boolean",
}

# Ordre de chargement code en dur dans `getBuiltInSchemas`. Sert a distinguer
# les XSD d'origine de nos ajouts, et a l'audit.
BUILTIN = [
    "CoT__flow-tags_.xsd",
    "CoT_remarks.xsd",
    "CoT_request.xsd",
    "CoT_sensor.xsd",
    "CoT_shape.xsd",
    "CoT_spatial.xsd",
    "CoT_track.xsd",
    "CoT_uid.xsd",
]


class Field:
    """Un `fieldDefinition` de la GeoEvent Definition."""

    def __init__(self, name: str, ftype: str, many: bool = False):
        self.name = name
        self.type = ftype
        self.many = many
        self.children: list[Field] = []

    def child(self, name: str) -> "Field | None":
        return next((c for c in self.children if c.name == name), None)

    def lines(self, indent: str) -> list[str]:
        card = ' cardinality="Many"' if self.many else ""
        head = f'{indent}<fieldDefinition name="{self.name}" type="{self.type}"{card}'
        if not self.children:
            return [head + " />"]
        out = [head + ">", f"{indent}  <fieldDefinitions>"]
        for c in self.children:
            out += c.lines(indent + "    ")
        return out + [f"{indent}  </fieldDefinitions>", f"{indent}</fieldDefinition>"]


# --------------------------------------------------------------------------
# Lecture des XSD — transcription de CoTDetailsDeff.nodeDrillDown
# --------------------------------------------------------------------------

def _lookup(raw: str, alias: dict[str, str], warn: bool) -> str:
    resolved = alias.get(raw, raw)
    if warn and resolved not in TYPE_MAP:
        print(f"  ! type inconnu de l'adaptateur : {resolved!r} -> String", file=sys.stderr)
    return TYPE_MAP.get(resolved, "String")


def _drill(node: ET.Element, parent: Field, alias: dict[str, str], warn: bool) -> None:
    for child in node:
        target = parent

        if child.tag == f"{XS}simpleType":
            key = child.get("name")
            if key is None:
                # Le parseur Esri abandonne ici : un simpleType anonyme fait
                # perdre le type de l'attribut porteur. Reproduit tel quel.
                continue
            restriction = child.find(f"{XS}restriction")
            if restriction is not None and restriction.get("base"):
                alias[key] = restriction.get("base")
            continue

        if child.tag == f"{XS}element":
            name = child.get("name")
            if name is None:
                continue
            field = Field(name, "Group", many=child.get("maxOccurs") == "unbounded")
            parent.children.append(field)
            field.children.append(Field("#text", "String"))
            if name == "shape":
                # L'adaptateur force `shape` en Geometry et n'expose aucun
                # enfant : on s'arrete la, comme la definition livree.
                field.type, field.children = "Geometry", []
                continue
            target = field

        elif child.tag == f"{XS}attribute":
            name = child.get("name")
            if name is not None:
                parent.children.append(Field(name, _lookup(child.get("type", ""), alias, warn)))
            continue

        _drill(child, target, alias, warn)


def parse_xsd(path: pathlib.Path, warn: bool = True) -> list[Field]:
    holder = Field("detail", "Group")
    _drill(ET.parse(path).getroot(), holder, {}, warn)
    return holder.children


# --------------------------------------------------------------------------
# Lecture du bloc `detail` livre
# --------------------------------------------------------------------------

BLOCK_RE = re.compile(
    r'^([ \t]*)<fieldDefinition name="detail" type="Group">.*?^\1</fieldDefinition>',
    re.S | re.M)


def extract_block(text: str) -> tuple[str, str]:
    match = BLOCK_RE.search(text)
    if not match:
        sys.exit("bloc `detail` introuvable — le fichier n'est pas "
                 "l'input-adapter-definition.xml attendu")
    return match.group(0), match.group(1)


def block_to_field(block: str) -> Field:
    def convert(node: ET.Element) -> Field:
        field = Field(node.get("name"), node.get("type"),
                      many=node.get("cardinality") == "Many")
        holder = node.find("fieldDefinitions")
        if holder is not None:
            field.children = [convert(c) for c in holder.findall("fieldDefinition")]
        return field
    return convert(ET.fromstring(block))


# --------------------------------------------------------------------------
# Fusion
# --------------------------------------------------------------------------

def merge(detail: Field, groups: list[Field]) -> tuple[list[str], list[str]]:
    added, merged = [], []
    for group in groups:
        existing = detail.child(group.name)
        if existing is None:
            detail.children.append(copy.deepcopy(group))
            added.append(group.name)
            continue
        for field in group.children:
            if existing.child(field.name) is None:
                existing.children.append(copy.deepcopy(field))
                merged.append(f"{group.name}/{field.name}")
    return added, merged


# --------------------------------------------------------------------------
# Commandes
# --------------------------------------------------------------------------

def cmd_audit(xsd_dir: pathlib.Path, reference: pathlib.Path) -> int:
    """Regenere les 8 groupes d'origine et compare : mesure ce que la regle
    explique, et isole ce qui releve d'une anomalie cote Esri."""
    generated = Field("detail", "Group")
    for name in BUILTIN:
        path = xsd_dir / name
        if path.exists():
            generated.children.extend(parse_xsd(path, warn=False))
        else:
            print(f"  ! XSD d'origine absent : {name}", file=sys.stderr)

    livre = block_to_field(extract_block(reference.read_text(encoding="utf-8"))[0])

    def flatten(field: Field, prefix: str = "") -> dict[str, str]:
        out = {}
        for c in field.children:
            path = f"{prefix}{c.name}"
            out[path] = c.type + (" [Many]" if c.many else "")
            out.update(flatten(c, path + "/"))
        return out

    want, got = flatten(livre), flatten(generated)
    ecarts = 0
    for path in sorted(set(want) | set(got)):
        a, b = want.get(path), got.get(path)
        if a == b:
            continue
        ecarts += 1
        print(f"  {path:32} livre={a or '(absent)':12} regle={b or '(absent)'}")
    total = len(set(want) | set(got))
    print(f"\n{total - ecarts}/{total} champs expliques par la regle, {ecarts} ecarts.")
    if ecarts:
        print("Les ecarts sont des anomalies de la definition livree, pas de la regle :\n"
              "  - `_flow-tags` : underscore final perdu, le groupe ne peut jamais matcher\n"
              "    l'element `_flow-tags_` reellement emis ;\n"
              "  - types `sensor` incoherents entre attributs de structure identique\n"
              "    (`elevation` en Date, `fov` en Double, les autres en String).\n"
              "C'est pourquoi le bloc livre n'est PAS regenere par --patch.")
    return 0


def collect_extras(xsd_dir: pathlib.Path) -> list[Field]:
    groups: list[Field] = []
    for path in sorted(p for p in xsd_dir.glob("*.xsd") if p.name not in BUILTIN):
        print(f"  + {path.name}", file=sys.stderr)
        groups.extend(parse_xsd(path))
    return groups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xsd-dir", default="cot-server-files/xsd",
                    help="repertoire des XSD (defaut : cot-server-files/xsd)")
    ap.add_argument("--patch", metavar="FICHIER",
                    help="input-adapter-definition.xml a completer")
    ap.add_argument("-o", "--output", help="fichier de sortie (defaut : celui de --patch)")
    ap.add_argument("--audit", metavar="FICHIER", nargs="?", const="",
                    help="compare la definition livree a ce que la regle produirait")
    args = ap.parse_args()

    xsd_dir = pathlib.Path(args.xsd_dir)
    if not xsd_dir.is_dir():
        sys.exit(f"repertoire XSD introuvable : {xsd_dir}")

    if args.audit is not None:
        reference = args.audit or args.patch
        if not reference:
            sys.exit("--audit exige le chemin de l'input-adapter-definition.xml")
        return cmd_audit(xsd_dir, pathlib.Path(reference))

    extras = collect_extras(xsd_dir)
    if not extras:
        sys.exit(f"aucun XSD additionnel dans {xsd_dir}")

    if not args.patch:
        print("\n".join(l for g in extras for l in g.lines("            ")))
        return 0

    source = pathlib.Path(args.patch)
    text = source.read_text(encoding="utf-8")
    block, indent = extract_block(text)
    detail = block_to_field(block)

    added, merged = merge(detail, extras)

    destination = pathlib.Path(args.output) if args.output else source
    destination.write_text(text.replace(block, "\n".join(detail.lines(indent)), 1),
                           encoding="utf-8")

    print(f"\n{destination}", file=sys.stderr)
    print(f"  groupes ajoutes  ({len(added)}) : {', '.join(added) or '-'}", file=sys.stderr)
    print(f"  champs fusionnes ({len(merged)}) : {', '.join(merged) or '-'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
