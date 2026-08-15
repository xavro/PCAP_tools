# PCAP_tools — boîte à outils captures & flux (ISRBOX / 33e ESRA)

Outils Python 3 pour **analyser, rejouer et exploiter** des captures réseau et
des flux tactiques sur banc de test : CoT, bus SITAC / Delta Suite, Link16/JREAP,
vidéo STANAG 4609, GMTI STANAG 4607.

> ⚠️ Les **captures** (`.pcap`, `.pcapng`, médias) et les **sorties générées**
> (CSV/PNG) sont hors dépôt (cf. `.gitignore`) — certaines pèsent plusieurs Go.

## Chaîne GMTI en un coup d'œil

```
capture.pcap ──pcap_analyze.py──► quel port ? quel protocole ?
             ──pcap_replay.py───► rejeu vers GeoEvent (temps réel/accéléré)
             ──gmti_pcap_to_csv.py──► plots.csv ──demo.py/tracker.py──► pistes

pcap_console.py ──► interface graphique (analyse + routage + rejeu, en cliquant)
```

## `pcap_console.py` — console graphique (Tkinter, zéro install)

Application desktop à **deux onglets**. Tkinter est fourni avec Python : l'onglet
*Rejeu* ne dépend de rien. L'onglet *GMTI → Pistes* charge le tracker
(numpy + scipy) **en lazy** — s'ils manquent, seul cet onglet est indisponible.

```bash
python pcap_console.py
```

**Onglet « Rejeu »** — piloter le rejeu **sans taper les lignes `--route`** :
analyse automatique → **cocher les flux**, saisir la cible `IP[:port]`,
**« + client »** (fan-out) → **Start / Stop**, vitesse, boucle, statut live. La
GUI ne fait qu'appeler `pcap_analyze` et `pcap_replay`.

**Onglet « GMTI → Pistes »** — la chaîne d'exploitation, tout en cliquant :

1. **Décoder GMTI** (auto-détection du port) → plots MTI (via `gmti_pcap_to_csv`).
2. Choisir un **profil** (maritime / routier / convoi / personnel / aérien) et
   **Lancer le tracker** (`prototype_tracker_gmti_v5/track_run.py`).
3. Les **plots et pistes** s'affichent sur un **canvas natif** (repère local ENU,
   mètres) : glisser = pan, molette = zoom, échelle en bas. Cases *plots bruts* /
   *lissage RTS*.

C'est une **boucle de tuning** : on décode **une fois**, puis on relance le
tracker par profil en un clic (~0,03 s) pour comparer le nombre de pistes et la
fragmentation — la « méthode de tuning sur données réelles » du tracker, en
interactif. Pour les captures très denses (dizaines de milliers de plots), le
run est plus long ; borner avec le champ *limit*.

> `track_run.py` (noyau sans matplotlib) est la source unique des profils —
> `demo.py` s'en sert aussi. Le rejeu comme le tracker tournent dans un thread
> (UI réactive, mise à jour via une file thread-safe).

## Dépendances

| Pour lancer… | Il faut |
|---|---|
| `pcap_analyze.py`, `pcap_replay.py`, `gmti_pcap_to_csv.py` | **rien** — bibliothèque standard Python 3 (≥ 3.7) |
| `prototype_tracker_gmti/demo.py` + `tracker.py` | `numpy`, `scipy` (≥ 1.13), `matplotlib` (≥ 3.8) — versions compatibles numpy 2.x |

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

## `prototype_tracker_gmti/` — tracker MTI → pistes à ID persistant

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

## Autres outils

`cot_*` (génération / écoute / relais / catalogue CoT), `deltasuite_*` (bus Delta
Suite : sonde, injection, passerelle GeoJSON), `loadtest.py`, `check_seq.py`,
`patch_cot_jar.py`, `gen_cot_definition.py` — utilitaires du POC CoT/SITAC.
