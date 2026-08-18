# Cahier de tests — réglage du tracker GMTI 4607 (banc `pcap_web.py`)

Objectif : régler les profils du tracker (`gmti_profiles.json`, source unique avec le processor
GeoEvent) sur des captures réelles, prouver la parité Java, puis déployer sans recompilation.
Chaque campagne = une capture + un profil de départ + des réglages à essayer + des critères.

## 0. Préparation (une fois)

| Étape | Action |
|---|---|
| Lancer | `git checkout web-console` puis `python pcap_web.py` (ouvre http://127.0.0.1:8765/) |
| Capture | Parcourir… → le pcap → Analyser (flux, inventaire TS, KLV) |
| Onglet GMTI | 1. Décoder GMTI (inventaire 4607 : vérifier `target reports rejetés` et `octets resynchronisés`) |
| Mode | en-tête : **Lecture IHM seule (préchargé)** ; cocher le flux GMTI et, s'il existe, le flux vidéo qui filme la cible (clic sur le flux dans l'onglet FMV pour l'afficher) |
| Suivi | carte : « suivre → le centre image » quand une vidéo cadre la cible |

Boucle de réglage : **⚙ paramètres → modifier → ▶ Relancer** (run hors ligne, métriques, A/B, inspection d'une piste)
→ **▶ Lire** (lecture préchargée : pistes qui se forment, écart piste↔centre image en direct) → 💾 Enregistrer
sous un nom quand c'est bon → ⤓ oracle de parité → `mvn clean test` côté receiver → déployer.

## 1. Données à fournir (par cas)

| Cas | Capture souhaitée | Ce qu'elle doit contenir | Vérité terrain utile |
|---|---|---|---|
| **M1 gros navire** (pétrolier, > 250 m) | déjà disponible : `20260812_CaptureALL_CR2.pcap` (GMTI 5454 + vidéo 6789) | ≥ 3 min de GMTI sur le navire, revisites régulières | vidéo 4609 cadrant le navire (centre image = position de référence) ; si possible AIS/position réelle du navire |
| **M2 petits navires** (chalutier, voilier, semi-rigide) | **à fournir** : sortie côtière / port | plusieurs navires proches (< 500 m) et lents, échos faibles | vidéo si possible, sinon relevé visuel (nombre de navires réels) |
| **M3 trafic dense maritime** | **à fournir** : rade, chenal | ≥ 5 navires simultanés, croisements | idem |
| **R1 routier** (déjà : `volCAE2-MTI.pcap`, simulateur CAE, scan grande zone) | 48 min, revisites espacées | plots avec sentinelles (filtrés) | aucune ; on juge fragmentation/durée |
| **R2 routier réel** | **à fournir** : capture terrain sur axe routier, revisite ~1 s | véhicules à 20–30 m/s, virages, échangeurs | comptage réel si possible |
| **A1 aérien / rotateur** | synthétique existant (`parity_input_air.csv`) ; réel **à fournir** si disponible | cible > 40 m/s ; éolienne/radar tournant | — |

Format : `.pcap`/`.pcapng` bruts (UDP 4607, + 4609/CoT s'ils existent). Indiquer date, capteur, zone,
et ce que l'opérateur voyait (nombre de cibles, comportement) — c'est la vérité terrain minimale.

## 2. Critères de succès (métriques du banc)

Panneau métriques (Relancer / A/B) et texte « pistage temps réel » (Lecture) :

| Critère | Où | Cible |
|---|---|---|
| **1 cible = 1 piste** | pistes vivantes en Lecture, `contacts_multi` | gros navire : 1 piste (ou 1 contact) stable ; pas de piste parallèle |
| **Écart piste ↔ centre image** | ligne « écart piste↔centre image » (Lecture, vidéo cadrant la cible) | moy < 100 m, max < 300 m sur un navire de 350 m (le centre image n'est pas forcément le centre du navire) |
| **Fragmentation** | `pistes confirmées` vs cibles réelles ; `pistes < 5 hits` ; `durée moyenne` | peu de pistes courtes ; durée ≈ durée de visibilité |
| **Continuité** | `part de coasting` ; inspection : chronologie hit/miss | pas de trous longs sans reprise ; d² moyen 1–3 (gate ni trop serré ni trop lâche) |
| **Fausses pistes** | `pistes rejetées` (tentatives) doit rester majoritaire pour le clutter, `pistes confirmées` ne doit pas exploser | pas de piste confirmée sur du bruit statique (rotateurs → flag `rotateur`) |
| **Parité Java** | ⤓ oracle → `mvn clean test` | 100 % ≤ 1 m, 0 flag divergent |

## 3. Plans de réglage par cas

Toujours **une variable à la fois**, A/B contre le profil de départ, noter la valeur retenue.

### M1 — gros navire (profil de départ `maritime`)

| # | Paramètre | Essais | Ce qu'on regarde |
|---|---|---|---|
| 1 | `clusterDistM` (pré-clustering) | 0 / 60 / **80** / 120 / 200 | nombre de pistes sur le navire (→ 1), `échos regroupés`, écart↔centre image |
| 2 | `clusterDvMps` | 1.5 / 2.5 / 4 | échos de la coque tous fusionnés (Δ Doppler faible) sans avaler un autre mobile |
| 3 | `clusterMaxSpanM` | 300 / 400 / 600 | groupe non éclaté sur un 350 m ; pas de fusion de deux navires |
| 4 | `accelStd` | 0.02 / **0.05** / 0.2 | lissage de la piste (navire = faible dynamique) vs suivi des changements de cap |
| 5 | `gateChi2` / `gateMaxM` | 5.99–9.21 / 150–400 | inspection : plots au bord du gate (rouge) → élargir ; associations aberrantes → resserrer |
| 6 | `deleteMisses` (ou `deleteSec`) | 8 / 12 / 20 (ou 30–60 s) | la piste survit aux dwells sans écho (le faisceau balaie ailleurs) |
| 7 | `mergeMaxDistM` (fusion post-pistage) | 0 / 300 | filet : si des pistes parallèles subsistent, `contacts_multi` doit les recoller ; sinon 0 |
| 8 | `projectSec` (affichage) | 60 / 120 | projection cohérente avec la position réelle 1–2 min plus tard (rejouer/sauter) |
| 9 | `ghostSnrDb` / `ghostDistM` (fantômes) | 0 / 15 / **20** / 30 · 300 / 400 | `échos fantômes rejetés` ; les échos 20–39 dB à ±250 m du navire (Doppler ±6–9 m/s) disparaissent, les pistes « satellites » à 6 m/s aussi ; vérifier qu'aucune cible réelle faible ne disparaît |
| 10 | `measPosStdMin` (plancher σ mesure) | 5 / 60 / **100** / 150 | cible étendue : les échos proue/poupe (~300 m) doivent rester dans une même piste ; trop haut = piste molle |
| 11 | `snrRefDb` (pondération SNR) | 0 / 60 | écho faible cru moins précisément (à comparer avec 9 : redondant si les fantômes sont déjà rejetés) |

Résultat de référence pétrolier (2026-08-18, `maritime` = cluster 150 · fantômes 20 dB/400 m · σ_min 100 m · fusion 450 m) :
63 échos fantômes rejetés, **2 pistes** (proue/poupe, ~300 m, même cap) fusionnées en **1 contact**, écart↔centre image ~30–120 m.
Sans fantômes ni plancher σ : 8 pistes dont 4 « satellites » à 6 m/s. Constat : SNR bimodal (20–39 dB = artefacts, 60–89 dB = coque).

Attendu M1 : 1 piste (ou 1 contact) sur le pétrolier, écart↔centre image moyen < 100 m, pas de piste
courte fantôme, projection à 60 s dans le sillage.

### M2 / M3 — petits navires, trafic dense (profil de départ `maritime`, à décliner en `maritime_cotier`)

| # | Paramètre | Essais | Ce qu'on regarde |
|---|---|---|---|
| 1 | `clusterDistM` | **0** / 30 / 60 | deux navires proches doivent rester deux pistes ; le clustering ne doit rien fusionner d'incompatible |
| 2 | `gateMaxM` | 100 / 150 / 250 | croisements : pas d'échange de pistes (inspection : d² et sauts) |
| 3 | `confirmM/N` | 3/5 / 4/6 | échos faibles/intermittents : confirmation ni trop lente ni sur du bruit |
| 4 | `minSnrDb` | 0 / 5 / 10 | supprime le clutter de mer sans perdre le voilier |
| 6 | `ghostSnrDb` | 0 / 20 / 30 | **piège** : un petit navire à < 400 m d'un gros (SNR −20 dB) serait rejeté comme fantôme → à valider avec la vérité terrain ; sinon 0 |
| 7 | `measPosStdMin` | 5 / 30 | petits navires = cibles ponctuelles : garder bas (sinon deux navires proches fusionnent) |
| 5 | `mergeMaxDistM` | 0 / 100 | fusion post-pistage limitée à la taille des cibles |

Attendu : nombre de pistes = nombre de navires réels (vérité terrain), pas d'échange d'identité aux croisements.

### R1 / R2 — routier (profil de départ `routier`, `routier_zone` en scan grande zone)

| # | Paramètre | Essais | Ce qu'on regarde |
|---|---|---|---|
| 0 | `clusterDistM` | **0** (ne pas activer) | contrôle de non-régression : métriques identiques au run de référence (volCAE2 : 77 pistes, R1) |
| 1 | `accelStd` | 1 / 2 / 3 | virages / échangeurs : fragmentation en virage → monter |
| 2 | `gateChi2` | 5.99 / 7 / 9.21 | trafic dense : associations croisées → baisser ; pertes → monter |
| 3 | `deleteMisses` ou `deleteSec` | 4–8 / 30–60 s | R2 revisite ~1 s : `deleteMisses` ; scan grande zone : `deleteSec` |
| 4 | `confirmByHits` + `confirmM` | off / 5 | cibles vues par intermittence (grande zone) |
| 5 | `gateGrowMps` | 0 / 25 | grande zone : reprise après longue absence |

Attendu : durée moyenne des pistes ≈ durée de visibilité, `pistes < 5 hits` faible, pas de piste multiple sur un même véhicule.

### A1 — aérien / rotateur (profil `aerien`)

| # | Paramètre | Essais |
|---|---|---|
| 1 | `airSpeedMps`, `airVlosMps`, `airConfirm` | 35–50 / 40–60 / 2–4 : latch aérien ni trop tôt ni jamais |
| 2 | `rotMaxGround` | 2–5 : rotateur fixe reconnu (v_LOS forte, sol immobile) |

## 4. Consigner un résultat

Pour chaque profil retenu : nom du profil (`💾 Enregistrer`), capture, valeurs (⤓ JSON), métriques clés
(pistes, hits moyens, part de coasting, écart↔centre image), capture d'écran de la carte, et le
`parity_<nom>.zip` déposé dans `Receiver4607-geoevent-adapter/src/test/resources/parity/custom/`
(`mvn clean test` vert). Le fichier `gmti_profiles.json` versionné dans PCAP_tools est la référence ;
le même fichier est déposé sur le serveur GeoEvent (propriété `profilesFile`).

## 5. Points de vigilance connus

- Le pré-clustering (`clusterDistM`), la suppression des fantômes (`ghostSnrDb`) et la pondération SNR
  (`snrRefDb`) n'existent pas encore côté Java : un profil qui les active ne passera pas la parité tant
  que l'étage `prepare_plots` (déclutter → fantômes → SNR → clustering) n'est pas porté dans
  `Tracker.process` — à faire une fois les valeurs validées sur le banc. `measPosStdMin` est déjà porté.
- Le décodage rejette les target reports hors zone de dwell (sentinelles) — compteur dans l'inventaire ;
  à porter dans `Gmti4607Parser` sinon le processor voit des pistes fantômes.
- Le profil `routier_zone` sur une longue capture peut prendre plusieurs minutes de tracker Python au
  premier run (cache ensuite).
- Le centre image KLV n'est une vérité que quand l'opérateur cadre la cible : filtrer visuellement.
