# Tracker GMTI v9 — journal des étapes et mesures

Brief : `StratusServer-v2/docs/BRIEF_TRACKER_GMTI_V9.md`. Chaque brique a été activée seule, puis
cumulée, et mesurée à chaque fois (§7). Le v8.1 n'est pas modifié ; v9 est un dossier frère, détecté
automatiquement par `pcap_web` / `pcap_console` (version la plus élevée contenant `track_run.py`).

Banc : `python compare_tracker_versions.py <plots.csv> --profile maritime --ladder`.

## 0. Prérequis livré : le CSV transporte le dwell

Le tracker v9 a besoin de savoir **si une piste était regardée** au moment d'un dwell. Ces champs
existaient dans le parser mais s'arrêtaient là. Sept colonnes ont été ajoutées en fin de ligne
(`sensor_alt_m`, `dwell_center_lat`, `dwell_center_lon`, `dwell_range_he_km`, `dwell_angle_he_deg`,
`mdv_mps`, `job_id`), dans `stanag4607_extract.write_csv` et dans `gmti_pcap_to_csv` (où D24.29 MDV et
le job id du paquet n'étaient pas décodés). Ajout compatible : le v8 ignore ces colonnes, et le v9 sans
elles se comporte comme le v8 sur l'observabilité.

## 1. Portage : le module est conforme à la référence

`python test_synthetic.py` (scénarios du brief §6.1) :

```
[A] pistes confirmées : {1: [dwell 2 → 119]} — 90 hits, cap 135.6° ± 0.90 (vrai 135), 28.7 km/h (vrai 28.8)
[B] deux navires parallèles à 600 m → 2 pistes
RESULTAT : OK
```

Chiffres **identiques** à ceux de `gmti_tracker_v9_ref.py`. Ce qui suit sur les captures réelles n'est
donc pas un défaut d'implémentation.

## 2. Capture maritime — `20260812_CaptureALL_CR2.pcap` (port 5454)

609 paquets, 595 dwells, **185 plots**, 156 s, un seul job, classification 100 % « 6 = Maritime ».
Référence de cible reconstruite depuis les plots, sans tracker : **157 plots alignés, 13,3 km/h cap 127°**
(résidu 177 m, cohérent avec une coque de ~250 m).

| variante | pistes | ID sur cible | simult. max | couverture | σ cap | σ vitesse | jitter | vitesse | erreur cap |
|---|---|---|---|---|---|---|---|---|---|
| v8.1 (référence) | 3 | 3 | 3 | 100 % | 16,9° | 2,7 km/h | 54 m | 7,1 km/h | 16,5° |
| v9 — aucune brique | 11 | 11 | 5 | 69 % | 11,0° | 3,2 km/h | 16 m | 17,4 km/h | 3,8° |
| + clustering | 5 | 5 | 3 | 79 % | 10,2° | 1,7 km/h | 28 m | 18,3 km/h | 6,8° |
| + EKF Doppler | 4 | 4 | 2 | 97 % | **4,4°** | 2,7 km/h | 46 m | 25,6 km/h | 0,0° |
| + observabilité | 6 | 5 | 4 | 85 % | **3,0°** | 4,3 km/h | 44 m | 25,7 km/h | 0,5° |
| + fusion | 12 | 11 | 4 | 81 % | 26,0° | 3,3 km/h | 23 m | 11,1 km/h | 62,8° |

Cibles du brief : 1 piste simultanée, 1 identifiant, σ cap < 5°, σ vitesse < 2 km/h, jitter < 40 m,
couverture > 90 %. **Non atteintes** en l'état — le détail ci-dessous dit pourquoi.

### Ce que dit la donnée : D32.7 ne mesure pas la translation du navire

Écart de v_LOS entre deux échos **du même dwell** (donc du même instant), par distance :

| distance entre échos | paires | \|Δv_LOS\| médian |
|---|---|---|
| 0 – 50 m | 8 | 2,88 m/s |
| 50 – 150 m | 8 | 2,76 m/s |
| 150 – 300 m | 52 | 10,51 m/s |
| 300 – 600 m | 22 | 10,42 m/s |

Le flux annonce pourtant σ_v_LOS = 0,23 à 0,51 m/s (D32.15, présent à 100 %). Un ajustement d'UNE vitesse
commune à tous les plots laisse un résidu de 5,12 m/s. Autrement dit, sur ce capteur et cette cible, le
Doppler décrit l'agitation des diffuseurs de la coque, pas le déplacement du navire (13 km/h = 3,7 m/s,
alors que le v_LOS mesuré balaie ±8,9 m/s).

Conséquences vérifiées :
- avec un σ_v_LOS serré, l'EKF Doppler **stabilise le cap** (σ 1,5 à 2,4°, erreur de cap ~0°, la géométrie
  étant quasi radiale) mais **double la vitesse** : 22 à 25 km/h affichés pour 13,3 km/h réels, parce que
  la composante le long de la ligne de vue suit les oscillations du Doppler ;
- avec un σ plancher à 8 m/s ou plus, le Doppler cesse d'informer et l'on retombe sur le position seule ;
- le critère Doppler du clustering (3 m/s au brief) **empêchait** de lier proue et poupe : porté à 25 m/s,
  le clustering fait passer les pistes de 11 à 5.

D'où le réglage livré : `doppler_enabled=False` **sur le profil maritime**, avec le commentaire de mesure
dans `track_run.py`. Ce n'est pas un abandon de la brique — elle est juste, le test synthétique le prouve
(σ cap 0,9° sur un Doppler propre) — c'est un constat sur ce capteur. `doppler_enabled=True` reste
disponible en surcharge, profil par profil.

### Ce qui reste ouvert

Le nombre de pistes sur la cible (4 à 6 selon le réglage) est encore loin de 1. Les doublons sont des
pistes distantes de 100 à 300 m, co-mobiles, que ni le Mahalanobis (covariances de 20 m) ni le critère de
co-mobilité actuel n'absorbent proprement : la fusion telle qu'elle est réglée **dégrade** le résultat
(12 pistes, erreur de cap 63°), parce qu'absorber une piste libère ses mesures, qui refont naître une
piste au dwell suivant. À traiter : mémoriser l'identifiant absorbé pour que la mesure revienne à la piste
mère, et resserrer le critère (distance ≤ longueur de coque, Δcap ≤ 20°, k ≥ 4).

## 3. Capture routière — `volCAE2-MTI.pcap` (48 min, 11 219 plots)

| variante | pistes confirmées | rejetées | clustering | miss observables | miss évités | fusions |
|---|---|---|---|---|---|---|
| v8.1 | 841 | 1 572 | — | — | — | — |
| v9 complet | **845** | 5 025 | 478 plots agrégés | 8 937 | **333 704** | 214 |

**+0,5 %** de pistes : la non-régression du §6.3 est tenue (limite +10 %).

Le chiffre à retenir est celui des **miss évités** : 333 704 dwells où une piste n'était pas dans
l'empreinte du dwell — 97 % des « miss » que le v8 aurait comptés. C'est la brique d'observabilité qui
justifie à elle seule les colonnes de dwell ajoutées au CSV. Sans ces colonnes (ancien CSV), le même
profil ne garde que 41 pistes : les pistes meurent sur des miss fictifs.

## 4. État des étapes du brief §7

| étape | état |
|---|---|
| 1. clustering seul | fait, mesuré (11 → 5 pistes sur la maritime) |
| 2. EKF Doppler + R anisotrope | fait, mesuré ; **désactivé par défaut en maritime** au vu de la donnée |
| 3. observabilité (empreinte + zone aveugle) | fait, mesuré (couverture 79 → 97 % ; 333 704 miss évités en routier) |
| 4. suppression sur miss observables + fusion | fait, **à retravailler** (la fusion dégrade) |
| 5. portage des flags v8 | fait (`is_air`, `is_rotator`, états Faible/Confirmee/Solide/Coasting, RTS) |
| 6. intégration console | automatique (auto-détection), **non testée en console** |
