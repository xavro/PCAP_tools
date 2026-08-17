# PCAP_tools — boîte à outils captures & flux (ISRBOX / 33e ESRA)

Outils Python 3 pour **analyser, rejouer et exploiter** des captures réseau et
des flux tactiques sur banc de test : CoT, bus SITAC / Delta Suite, Link16/JREAP,
vidéo STANAG 4609, GMTI STANAG 4607.

> ⚠️ Les **captures** (`.pcap`, `.pcapng`, médias) et les **sorties générées**
> (CSV/PNG) sont hors dépôt (cf. `.gitignore`) — certaines pèsent plusieurs Go.

## Vue d'ensemble

| Besoin | Outil | Dépendances |
|---|---|---|
| Savoir ce qu'il y a dans une capture (ports, protocoles, flux) | `pcap_analyze.py` | stdlib |
| Rejouer une capture vers un banc (routage, fan-out, vitesse, boucle, recalage CoT) | `pcap_replay.py` | stdlib |
| **Tout piloter en cliquant** : analyse, routage/rejeu, GMTI → pistes, inventaire 4607, CoT, vidéo 4609, carte fusionnée | **`pcap_console.py`** (Tkinter) | stdlib ; tracker en lazy (numpy + scipy) ; thème sombre optionnel `sv-ttk` |
| La même console **dans le navigateur**, avec vidéo H.264 + KLV synchronisés et rejeu « live » | **`pcap_web.py`** — branche [`web-console`](https://github.com/xavro/PCAP_tools/tree/web-console) | stdlib (libs JS vendorées) |
| Décoder le GMTI STANAG 4607 en plots CSV | `gmti_pcap_to_csv.py`, `prototype_tracker_gmti_v8.1/stanag4607_extract.py` | stdlib |
| Pister les plots (ID persistant, profils de tuning) | `prototype_tracker_gmti_v8.1/tracker.py`, `track_run.py`, `demo.py` | numpy, scipy (matplotlib pour demo) |
| Analyser le CoT XML (objets, types, traces) | `cot_extract.py` | stdlib |
| Inspecter la vidéo STANAG 4609 (TS, PID, KLV MISB 0601, extraction .ts) | `video4609.py` | stdlib |
| Fond de carte ArcGIS pour les consoles | `arcgis_basemap.py` + `basemap.json` (local) | stdlib |
| POC CoT / SITAC / Delta Suite (génération, écoute, relais, passerelles) | `cot_*`, `deltasuite_*`, `loadtest.py`… | stdlib |

## Chaîne GMTI en un coup d'œil

```
capture.pcap ──pcap_analyze.py──► quel port ? quel protocole ?
             ──pcap_replay.py───► rejeu vers GeoEvent (temps réel/accéléré)
             ──gmti_pcap_to_csv.py──► plots.csv ──demo.py/tracker.py──► pistes

pcap_console.py ──► interface graphique (analyse + routage + rejeu + pistes + CoT + vidéo)
pcap_web.py     ──► idem dans le navigateur (+ vidéo synchronisée KLV, rejeu live) — branche web-console
```

## `pcap_console.py` — console graphique (Tkinter, zéro install)

Application desktop à **six onglets**. Tkinter est fourni avec Python : l'onglet
*Rejeu* ne dépend de rien. L'onglet *GMTI → Pistes* charge le tracker
(numpy + scipy) **en lazy** — s'ils manquent, seul cet onglet est indisponible.

```bash
python pcap_console.py
```

**Interface sombre** (optionnel) : `pip install sv-ttk` active le thème *Sun Valley*
(look Windows 11, fond anthracite) ; sans lui, un thème sombre `ttk` intégré prend le
relais — la console reste « zéro install ». **F2** (ou le bouton ☾/☀ du bandeau)
bascule sombre ↔ clair. Dans l'onglet CoT, les lignes sont colorées par affiliation
comme les symboles de la carte (ami cyan, hostile rouge, inconnu jaune).

**Onglet « Vue d'ensemble »** — un clic *Analyser le pcap* liste les
**protocoles présents et leur port** (GMTI / CoT / vidéo…) ; **double-clic** sur
une ligne ouvre l'onglet dédié (et pré-remplit le port vidéo). Point d'entrée
pour savoir ce que contient une capture.

**Onglet « Rejeu »** — piloter le rejeu **sans taper les lignes `--route`** :
analyse automatique → **cocher les flux**, saisir la cible `IP[:port]`,
**« + client »** (fan-out) → **Start / Stop**, vitesse, boucle, statut live. La
GUI ne fait qu'appeler `pcap_analyze` et `pcap_replay`.

**Onglet « GMTI → Pistes »** — **écran partagé** (comme l'onglet CoT) : à gauche
l'**inventaire 4607** du flux, à droite la **carte du tracker** (plots + pistes).
La chaîne d'exploitation, tout en cliquant :

1. **Décoder GMTI** → plots MTI. Décodeur **complet** (`stanag4607_extract`,
   hauteur + zone job + porteur + classification) sur pcap classique de taille
   raisonnable ; **repli streaming** (`gmti_pcap_to_csv`, pcapng / gros fichiers,
   auto-détection du port) sinon.
2. Choisir un **profil** (maritime / routier / **routier_zone** / convoi /
   personnel / aérien) et **Lancer le tracker**
   (`track_run.py` de la dernière version `prototype_tracker_gmti_v*`).
3. **Plots et pistes** sur un **canvas natif** (repère local ENU, mètres) :
   glisser = pan, molette = zoom, échelle en bas. Overlays quand le décodeur
   complet est utilisé : **zone de job** (bounding area, pointillés), **trajet
   porteur** (Platform Location), **plots colorés par classification**. Cases
   *plots bruts* / *lissage RTS*.

C'est une **boucle de tuning** : on décode **une fois**, puis on relance le
tracker par profil en un clic (~0,03 s) pour comparer nombre de pistes et
fragmentation. `routier_zone` (vie de piste en secondes, gate croissant) est le
profil des scans grande zone où une cible n'est pas vue à chaque dwell.

Les canvas GMTI et CoT portent un **graticule lat/lon** et une **lecture de
position (lat/lon + MGRS) sous le curseur** (`mgrs_lite.py`, conversion pure
Python), et un **fond de carte raster ArcGIS Server** optionnel (case
« Fond ArcGIS ») : `arcgis_basemap.py` appelle `MapServer/export` en **EPSG:4326**
(alignement exact avec le canvas ENU), rafraîchi au relâchement du pan/zoom, avec
**repli graticule** si le serveur est absent. Configuration dans **`basemap.json`**
(à côté du script) :

```json
{"url": "https://asus-xav/arcgis/rest/services/WorldTopoMap/MapServer",
 "token": null, "insecure": true}
```

`insecure: true` accepte le certificat auto-signé d'un serveur DEV local.
*(Un VectorTileServer ne convient pas : tuiles vectorielles à rendre côté client
— il faut un MapServer raster / ImageServer.)*

**Volet « Inventaire 4607 »** (gauche de l'onglet GMTI) — *ce que le vecteur émet
réellement* : lance
`stanag4607_extract` et affiche segments reçus, **présence de chaque champ (%)**,
plages min/méd/max, **classifications**, **Job Definition** (radar mode,
incertitudes nominales, bounding area), positions porteur. Outil de validation
pré-prod. Lit le **pcap classique** (pcapng → `editcap -F pcap`).

**Onglet « CoT »** — parse tout le CoT XML du pcap (`cot_extract`) et affiche :
un **tableau des objets** (uid / type / affiliation / callsign), l'**inventaire
par type** (compte + affiliation + dimension), le **field=value** d'un objet
sélectionné, et un **canvas de points** (repère ENU) colorés par **affiliation**
(ami=bleu, hostile=rouge, neutre=vert, inconnu=jaune — MIL-STD-2525) avec une
**trace par uid**. Filtre par sous-chaîne de type ; affiliation dérivée du 2ᵉ
caractère du type (port exact de `CotSidc.java`).

**Onglet « Carte fusionnée »** — superpose sur **une seule carte** (repère ENU
commun + graticule + fond ArcGIS) : les **pistes GMTI** (tracker), les **points
CoT** (par affiliation), et la **position capteur vidéo + empreinte au sol**
(KLV MISB 0601, capteur → centre image). Cases par couche (GMTI / CoT / Vidéo) ;
« Ajuster la vue » cadre sur les couches **visibles** (les flux peuvent être dans
des zones différentes). Vue tactique fusionnée d'un pcap, sans GeoEvent.

**Onglet « Vidéo 4609 »** — inspecte le flux vidéo STANAG 4609 (`video4609.py`) :
réassemble le **MPEG-TS** (TS brut ou RTP), inventorie les **PID** (PAT/PMT),
identifie **codecs** (H.264/HEVC/MPEG-2) et **erreurs de continuité**, et surtout
**décode les métadonnées KLV MISB ST 0601 en champ=valeur** (horodatage, position
et attitude porteur, cap/FOV/az-el capteur, portée oblique, centre image…).
Bouton **« Extraire .ts + ouvrir »** : écrit le flux réassemblé et l'ouvre dans le
**lecteur système** (VLC/ffplay) — pas de décodeur embarqué (contrainte air-gap).

## `video4609.py` / `stanag4607_extract.py` / `cot_extract.py` en CLI

Les trois décodeurs marchent aussi en ligne de commande :

```bash
python video4609.py capture.pcap --limit 200000        # inventaire TS + KLV
python cot_extract.py capture.pcap                      # events.xml + tracks.csv + types.csv
python prototype_tracker_gmti_v8.1/stanag4607_extract.py capture.pcap --rapport r.txt --csv plots.csv
# (adapter le numéro de version au dernier prototype_tracker_gmti_v*)
```

> Le tracker et l'extracteur `stanag4607_extract` vivent dans le dossier
> `prototype_tracker_gmti_v<N>` : la console prend **automatiquement la version
> la plus élevée** contenant `track_run.py` (déposer une v8 à côté suffit).
> numpy/scipy sont chargés **en lazy** → l'onglet Rejeu marche sans eux. Rejeu,
> décodage, tracker et inventaire tournent dans un thread (UI réactive via file).

## Dépendances

| Pour lancer… | Il faut |
|---|---|
| `pcap_analyze.py`, `pcap_replay.py`, `gmti_pcap_to_csv.py` | **rien** — bibliothèque standard Python 3 (≥ 3.7) |
| `prototype_tracker_gmti_v8.1/demo.py` + `tracker.py` | `numpy`, `scipy` (≥ 1.13), `matplotlib` (≥ 3.8) — versions compatibles numpy 2.x |
| `pcap_console.py` | **rien** (Tkinter livré avec Python) ; onglet GMTI → `numpy`, `scipy` ; thème sombre Windows 11 → `sv-ttk` (optionnel) |
| `pcap_web.py` (branche `web-console`) | **rien** côté serveur ; navigateur moderne (MSE) ; tracker → `numpy`, `scipy` |

```bash
pip install scipy matplotlib          # numpy est tiré en dépendance
# air-gap : pip download ... -d wheels/ sur un poste connecté, puis
#           pip install --no-index --find-links wheels/ scipy matplotlib
```

---

## `pcap_analyze.py` — analyse (ports & protocoles détectés)

Inventorie une capture et **détecte le protocole applicatif de chaque flux par
signature** (pas seulement par numéro de port). Lit pcap classique (LE/BE, µs/ns)
**et** pcapng, en streaming (gros fichiers OK).

Protocoles reconnus : **GMTI/4607** (validation structurelle de l'en-tête + 1er
segment), **CoT-XML**, **SITAC-bus**, **Link16/JREAP**, **MPEG-TS/4609** (vidéo),
**KLV/4609** (métadonnées), **JSON**, **gzip** ; sinon `binaire`.

```bash
python pcap_analyze.py capture.pcap                 # synthèse par port
python pcap_analyze.py gros.pcap --limit 400000     # empreinte rapide (N 1ers paquets)
python pcap_analyze.py capture.pcap --proto gmti    # ne garder que le GMTI
python pcap_analyze.py capture.pcap --flows --all   # détail par flux, tous les ports
```

| Option | Effet |
|---|---|
| `--limit N` | n'analyser que les N premiers paquets (gros `.pcap`) |
| `--proto <p>` | filtrer : `gmti`, `cot`, `sitac`, `link16`, `video`, `klv`, `json` |
| `--top N` | nb de ports affichés dans la table (défaut 25) |
| `--all` | afficher tous les ports (pas de troncature) |
| `--flows` | détailler chaque flux `src:port → dst:port` |

**Sortie** : en-tête (paquets, flux, ports, durée) → bloc *« PROTOCOLES
APPLICATIFS IDENTIFIÉS »* (la réponse « GMTI sur quel port ? ») → table des ports
triée par volume.

---

## `pcap_replay.py` — rejeu générique

Ré-émet les **charges applicatives** (UDP/TCP) d'une capture vers une cible, pour
alimenter GeoEvent (ou tout consommateur) sans les sources live. **Agnostique au
contenu** : rejoue les octets tels quels (GMTI, CoT, vidéo, SITAC…). Régénère les
en-têtes L2/L3. pcap + pcapng, streaming.

```bash
# 1) inventorier les flux (avec protocole détecté)
python pcap_replay.py capture.pcap --list

# 2) rejouer un flux UDP (ex. GMTI port 5454) vers GeoEvent, en temps réel
python pcap_replay.py capture.pcap --udp --dst-port 5454 --target 192.168.1.50 --speed 1.0

# 3) rejouer en boucle, aussi vite que possible
python pcap_replay.py capture.pcap --udp --dst-port 5454 --target 192.168.1.50 --speed 0 --loop

# 4) rejouer un flux TCP (ex. bus SITAC)
python pcap_replay.py capture.pcap --tcp --dst-port 4072 --target 192.168.1.50

# 5) rejouer du CoT d'hier « comme maintenant » (horodatages décalés vers le présent)
python pcap_replay.py capture.pcap --udp --dst-port 8087 --target 192.168.1.50 --rebase-time
```

| Option | Effet |
|---|---|
| `--list` | inventorier les flux et sortir |
| `--udp` / `--tcp` | protocole à rejouer |
| `--dst-port` / `--src-port` / `--src` | filtres de sélection du flux |
| `--target <IP>` | cible du rejeu (requis) |
| `--target-port <p>` | port cible (défaut : port d'origine) |
| `--speed` | `1.0` temps réel, `>1` accéléré, `0` aussi vite que possible |
| `--precise` | pacing haute précision (spin ; ~µs, occupe un cœur) |
| `--loop` | rejeu en boucle |
| `--rebase-time` | décaler les horodatages **CoT** (time/start/stale) vers le présent |
| `--route SEL=CIBLES` | **routage multi-flux** (voir ci-dessous) — répétable |
| `--drop-unmatched` | en mode routage : ignorer les flux non routés |

### Routage multi-flux (`--route`)

Rejoue **tout le pcap d'un coup** (vidéo + CoT + GMTI…), avec son **timing global
préservé** (multiplex réaliste), en envoyant **chaque flux à sa/ses propre(s)
destination(s)**. Syntaxe répétable :

```
--route PROTO/PORT = IP[:PORT][,IP[:PORT]...]
```

- `PROTO` = `udp` ou `tcp` ; `PORT` = numéro ou `*` (tout ce protocole) ;
- chaque cible `IP[:PORT]` : **`:PORT` absent = port d'origine conservé**, présent = port réécrit ;
- plusieurs cibles séparées par `,` = **fan-out** (le flux part vers chacune → « ajouter un client ») ;
- les flux non routés vont vers `--target` (destination par défaut) ou sont ignorés (`--drop-unmatched`).

```bash
# Rejeu de toute la capture DEV : vidéo vers 2 clients (dont un sur un autre port),
# GMTI et CoT vers GeoEvent, tout le reste ignoré.
python pcap_replay.py 20260812_CaptureALL_CR2.pcap \
  --route udp/9876=192.168.1.60,192.168.1.61:6000 \
  --route udp/6789=192.168.1.60 \
  --route udp/5454=192.168.1.50 \
  --route udp/1237=192.168.1.50 \
  --drop-unmatched --speed 1.0
```

---

## `gmti_pcap_to_csv.py` — décodage GMTI 4607 → CSV de plots

Ferme la boucle d'évaluation d'algorithme **sans passer par GeoEvent** :
`pcap → plots.csv → prototype_tracker_gmti`. Décodage **piloté par le masque
d'existence** (offsets dynamiques), aligné sur le parser Java `Gmti4607Parser`.
**Auto-détecte le port GMTI** (ou `--port`). Bibliothèque standard uniquement.

```bash
python gmti_pcap_to_csv.py capture.pcap -o plots.csv        # port auto-détecté
python gmti_pcap_to_csv.py capture.pcap --port 5454 -o plots.csv
python gmti_pcap_to_csv.py gros.pcap --limit 400000 -o plots.csv
```

| Option | Effet |
|---|---|
| `-o, --out` | CSV de sortie (défaut `plots.csv`) |
| `--port` | port UDP GMTI (défaut : auto ; `27551` labo volCAE, `5454` pré-prod) |
| `--limit N` | n'analyser que les N premiers paquets |

**CSV produit** (délimiteur `;`, une ligne par target report), directement lu par
`demo.py` :

```
dwell_time_ms;revisit_idx;dwell_idx;lat;lon;vel_los_cms;snr_db;classification;sig_range_cm;sig_xrange_dm;sig_rvel_cms;sensor_lat;sensor_lon
```

Position en hi-res (bits 31/32) sinon repli delta×échelle+centre ; longitudes
normalisées en −180..180 ; incertitudes portée/travers/vitesse radiale en brut
4607 (cm, dm, cm/s) pour orienter l'ellipse d'erreur côté tracker.

---

## `prototype_tracker_gmti_v8.1/` — tracker MTI → pistes à ID persistant

Corrèle les plots MTI en **pistes à `track_id` unique** :
**prédiction Kalman (vitesse constante) → gating Mahalanobis (khi²) → association
globale GNN (hongrois) → confirmation M-sur-N → coasting → suppression**.

### `tracker.py` — cœur autonome (aucune I/O, portable en processor Java)

| Élément | Rôle |
|---|---|
| `Params` | réglages de tuning (voir table ci-dessous) |
| `Plot` | un plot MTI en repère local métrique + covariance de mesure `R` |
| `Track` | état cinématique `[x, y, vx, vy]` + covariance `P`, cycle de vie, historique |
| `Tracker.step(t, plots)` | traite un dwell/revisite complet (predict → gate → GNN → update → ménage) |
| `LocalFrame` | conversion lat/lon ↔ plan local ENU (équirectangulaire, ~dizaines de km) |
| `covariance_from_4607(...)` | ellipse d'erreur du plot orientée axe capteur→cible depuis les incertitudes 4607 |

**États de piste** (alignés sur l'expression Arcade de symbologie) :
`Faible` (tentative) → `Confirmee` (M-sur-N) → `Solide` (≥ `SOLID_HITS` hits) ;
`Coasting` (revisites manquées, position extrapolée) → `Supprimee`.

| Paramètre | Défaut | Rôle |
|---|---|---|
| `GATE_CHI2` | 9,21 | porte d'association (khi² 99 %, 2 ddl) — baisser = plus strict |
| `Q_ACCEL` | 1,0 | agilité supposée des cibles (m/s²) — monter si fragmentation en virage |
| `R_POS_DEFAULT` | 40 m | écart-type position si incertitudes 4607 absentes |
| `CONFIRM_M / N` | 3 / 5 | confirmation M-sur-N — monter M si fausses pistes |
| `DELETE_MISSES` | 4 | revisites sans plot avant suppression (tolérance MDV) |
| `SOLID_HITS` | 10 | seuil « Solide » |

### `demo.py` — banc d'essai + lecteur CSV

```bash
python demo.py                 # scénario synthétique (3 cibles manœuvrantes + clutter)
python demo.py plots.csv       # vos plots réels (issus de gmti_pcap_to_csv.py)
```

Groupe les plots par `(revisit_idx, dwell_idx)`, projette en repère local ENU,
construit chaque `Plot` avec sa covariance 4607 (si la position capteur est
présente), déroule le tracker, puis écrit :

- **`tracker_result.png`** — plots bruts (gris) vs pistes corrélées (couleurs, ID) ;
- **`tracks_out.csv`** — trajets : `track_id;t_s;x_m;y_m;etat`.

*(Nécessite `numpy`, `scipy`, `matplotlib`.)*

---

## Console web (`pcap_web.py`, branche `web-console`)

Portage de la console dans le navigateur — même backend Python (stdlib) et mêmes modules
métier, plus : **vidéo H.264 lue dans le navigateur** (mpegts.js, sans ffmpeg) avec les
**KLV MISB 0601 synchronisés** (< 10 ms), **rejeu UDP live** vu depuis l'IHM (moteur
unique + WebSocket), tracker par profil, CoT vivant/statique, export GeoJSON, fond de
carte ArcGIS Online ou MapServer local configurable. Voir le README de la branche
[`web-console`](https://github.com/xavro/PCAP_tools/tree/web-console) :

```bash
git checkout web-console
python pcap_web.py ../Captures/capture.pcap      # ouvre http://127.0.0.1:8765/
```

## Autres outils

`cot_*` (génération / écoute / relais / catalogue CoT), `deltasuite_*` (bus Delta
Suite : sonde, injection, passerelle GeoJSON), `loadtest.py`, `check_seq.py`,
`patch_cot_jar.py`, `gen_cot_definition.py` — utilitaires du POC CoT/SITAC.
`pcap_frames.py` : lecteur pcap/pcapng commun ; `mgrs_lite.py` : conversion MGRS légère.
