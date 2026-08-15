# PCAP_tools — boîte à outils captures & flux (ISRBOX / 33e ESRA)

Outils Python 3 (bibliothèque standard) pour **analyser, rejouer et exploiter**
des captures réseau et des flux tactiques sur banc de test : CoT, bus SITAC /
Delta Suite, Link16/JREAP, vidéo STANAG 4609, GMTI STANAG 4607.

> ⚠️ Les **captures** (`.pcap`, `.pcapng`, médias) et les **sorties générées**
> (CSV/PNG) sont hors dépôt (cf. `.gitignore`) — certaines pèsent plusieurs Go.

## Chaîne pcap : analyser → rejouer → exploiter

| Outil | Rôle |
|-------|------|
| `pcap_analyze.py` | **Analyse** d'une capture : liste des ports + **protocole détecté** par signature (GMTI 4607, CoT, SITAC, Link16, vidéo 4609/KLV, JSON…). pcap **et** pcapng, streaming, `--limit` pour les gros fichiers. |
| `pcap_replay.py` | **Rejeu** générique (agnostique au contenu) vers un consommateur (GeoEvent…), vitesse réelle/accélérée, boucle, rebasage temporel CoT. |
| `gmti_pcap_to_csv.py` | **Décodage GMTI 4607** d'un pcap → CSV de plots MTI (auto-détection du port) pour `prototype_tracker_gmti/`. |
| `prototype_tracker_gmti/` | Prototype de **tracker** GMTI (Kalman + GNN + M-sur-N) : plots MTI → pistes à ID persistant. `demo.py` consomme le CSV ci-dessus. |

```bash
# 1) Quel(s) protocole(s) et sur quel port dans une capture ?
python pcap_analyze.py capture.pcap

# 2) Rejouer le flux GMTI (port trouvé à l'étape 1) vers GeoEvent
python pcap_replay.py capture.pcap --udp --dst-port 5454 --target <IP> --speed 1.0

# 3) Évaluer l'algorithme de pistage directement depuis le pcap
python gmti_pcap_to_csv.py capture.pcap -o plots.csv
python prototype_tracker_gmti/demo.py plots.csv   # requiert numpy + scipy + matplotlib
```

> **Port GMTI** selon la capture : `27551` (captures labo volCAE), `5454`
> (captures pré-prod). `pcap_analyze.py` et l'auto-détection de
> `gmti_pcap_to_csv.py` le retrouvent par validation de structure 4607.

## Autres outils

`cot_*` (génération/écoute/relais/catalogue CoT), `deltasuite_*` (bus Delta
Suite : sonde, injection, passerelle GeoJSON), `loadtest.py`, `check_seq.py`,
`patch_cot_jar.py`, `gen_cot_definition.py` — utilitaires du POC CoT/SITAC.
