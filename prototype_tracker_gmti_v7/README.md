# Prototype tracker GMTI — plots MTI 4607 → pistes à ID unique

Boucle complète : **prédiction Kalman (vitesse constante) → gating Mahalanobis →
association globale GNN (hongrois) → confirmation M-sur-N → coasting → suppression**.
Chaque piste porte un `track_id` persistant et son trajet complet.

## Circuit de test avec votre pcap

1. Rejeu du pcap vers le GeoEvent pré-prod : `tcpreplay -i <iface> --mbps=X capture.pcap`
2. Sur le GeoEvent Service 4607, ajouter un output **Write to File (CSV, délimiteur ;)**
   avec les champs ci-dessous.
3. `python3 demo.py plots_geoevent.csv` → figure PNG + trajets CSV.

Sans CSV, `python3 demo.py` exécute un scénario synthétique
(3 cibles manœuvrantes, Pd 0,9, ~6 fausses alarmes/dwell) pour valider l'installation.

## Format CSV attendu (une ligne par plot MTI)

    dwell_time_ms;revisit_idx;dwell_idx;lat;lon;vel_los_cms;snr_db;classification;
    sig_range_cm;sig_xrange_dm;sig_rvel_cms;sensor_lat;sensor_lon

Incertitudes et position capteur optionnelles (défauts appliqués, mais fortement
recommandées : elles orientent l'ellipse d'erreur de chaque plot via
`covariance_from_4607`).

## Paramètres à tuner (classe `Params`, tracker.py)

| Paramètre       | Défaut | Rôle |
|-----------------|--------|------|
| `GATE_CHI2`     | 9,21   | Porte d'association (khi² 99 %, 2 ddl). Baisser → plus strict. |
| `Q_ACCEL`       | 1,0    | Agilité supposée des cibles (m/s²). Monter si fragmentation en virage. |
| `R_POS_DEFAULT` | 40 m   | Écart-type position si incertitudes 4607 absentes. |
| `CONFIRM_M / N` | 3 / 5  | Confirmation M-sur-N. Monter M si fausses pistes résiduelles. |
| `DELETE_MISSES` | 4      | Revisites sans plot avant suppression (tolérance MDV). |
| `SOLID_HITS`    | 10     | Aligné sur votre classe « Solide » Arcade. |

Les états de piste (`Faible`, `Confirmee`, `Solide`, `Coasting`) sont alignés sur
votre expression Arcade de symbologie — le stream de sortie peut les porter tels quels.

## Méthode de tuning sur données réelles

1. Rejouer le même CSV avec deux réglages, comparer `tracks_out.csv`
   (nb pistes, longueur moyenne, fragmentation d'une cible connue).
2. Fausses pistes résiduelles → monter `CONFIRM_M` (4/5) ou baisser `GATE_CHI2` (7).
3. Cible perdue en virage → monter `Q_ACCEL` (2–3 m/s²).
4. Pistes coupées par les trous MDV → monter `DELETE_MISSES`.

## Plan de portage GeoEvent (phase 2)

La classe `Tracker` est autonome (aucune I/O) : c'est elle qu'on transpose en
processor Java. Correspondances : `numpy.linalg` → Apache Commons Math
(`RealMatrix`, `LUDecomposition`) ; `linear_sum_assignment` → implémentation
hongroise (~100 lignes) ; état des pistes → map en mémoire du processor,
traitement déclenché par dwell complet (grouper sur revisit/dwell index).
Le champ `track_id` en sortie doit être tagué **TRACK_ID** dans la GeoEvent
Definition pour activer les trails côté stream layer / ExB.

## Pistes d'amélioration (v2)

- Vitesse radiale LOS comme 3e dimension de mesure (projection sur l'axe
  capteur→cible, déjà disponible dans le CSV).
- Score de piste log-vraisemblance à la place du M-sur-N binaire.
- Contrainte réseau routier (road-aided tracking) pour les véhicules.

## Profil maritime (validé sur export réel)

Scène de cibles lentes (classification 6) avec bruit de mesure ~100 m ≫ déplacement
inter-dwell (~6 m) : les défauts « véhicules terrestres » provoquent zigzags et échanges
de plots entre pistes voisines. Réglage validé :

    Q_ACCEL=0.05  V_INIT_STD=4.0  GATE_CHI2=7.0  CONFIRM_M=4  CONFIRM_N=6  DELETE_MISSES=12

Résultat sur l'export test : 14 pistes enchevêtrées → 6 pistes lisses et cohérentes
(la plus longue : 48 hits). DELETE_MISSES est en nombre de revisites : à ~1,5 s de
cadence, 12 ≈ 18 s de tolérance — à convertir en secondes si la cadence varie.

## Correctifs fin de piste (v3)

1. **Queue de coasting tronquée** : le trajet exporté (`Track.trajectory()`) s'arrête
   à la dernière détection réelle ; le coasting reste interne pour la ré-association.
2. **`GATE_MAX_M` (250 m)** : plafond du gate en mètres — en coasting la covariance
   gonfle et le gate khi² finissait par capturer des plots parasites qui tordaient
   la fin de piste.
3. **Lisseur RTS** (`rts_smooth(track)`) : passe arrière sur piste terminée →
   trajectoire lissée quasi rectiligne pour les produits trajet/débriefing.
   Non causal : à réserver au différé, le flux temps réel garde l'état filtré.
   Export automatique dans `tracks_out_lisse.csv`.

## Profils par environnement (v5)

| Profil | Cibles types | Physique dominante | Points durs |
|---|---|---|---|
| `maritime` | navires (classif 6) | lents, rectilignes, bruit ≫ déplacement | validé sur données réelles |
| `routier` | véhicules sur axes | 20–120 km/h, freinages, virages | arrêts sous MDV, intersections |
| `convoi` | colonnes rapprochées | espacement < 2× bruit mesure | échanges de plots entre pistes |
| `personnel` | piétons (classif 9) | 1–2 m/s, proche MDV | détections très intermittentes |
| `aerien` | voilures tournantes (3/4) | 30–80 m/s, très manœuvrant | gate large obligatoire |

Limites connues (visibles sur validation_routier.png) et remèdes v2 :
- **Virage brutal** → fragmentation (2 IDs) : modèle IMM (CV + virage coordonné).
- **Arrêt > tolérance coasting** → 2 IDs : « hypothèse d'arrêt » (geler la vitesse
  en coasting au lieu d'extrapoler) + ré-association spatiale à la reprise.
- **Convoi serré** → tresses/échanges : JPDA ou group tracking (le 4607 prévoit
  d'ailleurs un Group Segment, type 8).

Portage processor : convertir DELETE_MISSES en secondes (la tolérance doit être
indépendante de la cadence de revisite) ; profil sélectionnable par paramètre du
processor — un GeoEvent Service par type de mission, ou aiguillage par zone de job.

## Surveillance grande zone (v6) — profil `routier_zone`

Validé sur capture réelle 48 min / 11 219 plots / réseau routier ~66×70 km.
En scan sectoriel, une cible n'est observée qu'à certains dwells : compter les
« miss » par dwell tue les pistes en quelques secondes (symptôme : milliers de
fragments 5–20 hits). Trois mécanismes v6 :
- `DELETE_SEC` : vie de piste en **secondes d'ancienneté de dernière MAJ**
  (prioritaire sur DELETE_MISSES).
- `CONFIRM_BY_HITS=True` : confirmation dès `CONFIRM_M` hits cumulés (la fenêtre
  M-sur-N n'a pas de sens quand la cadence d'observation d'une cible varie).
- `GATE_GROW_MPS` : le plafond de gate grandit avec l'ancienneté (une cible non vue
  depuis 30 s peut s'être déplacée de plusieurs centaines de mètres).
Résultat : ~820 pistes cohérentes (durée médiane 39 s, max 14 min), vitesses
lissées médianes 76 km/h. Limite connue : sur longue interruption, l'association
en ligne droite « coupe » les courbes de la route (remède : road-aided tracking).
