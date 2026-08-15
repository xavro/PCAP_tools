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
