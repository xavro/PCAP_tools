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

| variante | pistes | ID sur cible | contacts | couv. contact | σ cap | σ vitesse | jitter | vitesse |
|---|---|---|---|---|---|---|---|---|
| v8.1 (référence) | 3 | 3 | — | — | 16,9° | 2,7 km/h | 54 m | 7,1 km/h |
| v9 — aucune brique | 12 | 12 | 5 | 80 % | 4,9° | 1,7 km/h | 16 m | 19,9 km/h |
| + clustering | 3 | 3 | 2 | 98 % | 7,3° | 1,5 km/h | 21 m | 13,2 km/h |
| + EKF Doppler | 2 | 2 | 2 | 98 % | 5,7° | 1,2 km/h | 15 m | 14,4 km/h |
| + observabilité | 3 | 2 | 2 | 96 % | 9,9° | 1,5 km/h | 18 m | 13,2 km/h |
| **v9 livré** (réglages ci-dessous) | **3** | **2** | **2** | **98 %** | **3,9°** | **1,0 km/h** | **15 m** | **14,6 km/h** |

Cibles du brief : σ cap < 5° **tenu**, σ vitesse < 2 km/h **tenu**, jitter < 40 m **tenu**, couverture > 90 %
**tenue** (100 %), vitesse à +10 % de la référence. **Reste 2 identifiants et 2 contacts au lieu d'un.**

Pour mémoire, le v8 sur la même capture : cap trois fois moins stable (16,9°) et surtout une vitesse de
7,1 km/h pour une cible à 13,3 — il sous-estime de moitié.

### Ce que dit la donnée : D32.7 est en partie du micro-Doppler

Écart de v_LOS entre deux échos **du même dwell** (même instant), par distance :

| distance entre échos | paires | \|Δv_LOS\| médian |
|---|---|---|
| 0 – 50 m | 8 | 2,88 m/s |
| 50 – 150 m | 8 | 2,76 m/s |
| 150 – 300 m | 52 | 10,51 m/s |
| 300 – 600 m | 22 | 10,42 m/s |

Le flux annonce pourtant σ_v_LOS = 0,23 à 0,51 m/s (D32.15, présent à 100 %), et un ajustement d'UNE
vitesse commune à tous les plots laisse 5,12 m/s de résidu. Conséquences mesurées :

- pris au mot **avec une porte large (400 m)**, le Doppler double la vitesse affichée (25 km/h pour 13
  réels) : la composante le long de la ligne de vue suit ses oscillations ;
- avec la porte resserrée à **200 m** et un **plancher σ_v_LOS de 2 m/s**, il stabilise le cap sans imposer
  sa dispersion : σ cap 3,9° et 14,6 km/h, contre 7,3° et 13,2 km/h sans Doppler du tout. C'est le réglage
  livré ;
- le critère Doppler du clustering (3 m/s au brief) **empêchait** de lier proue et poupe ; porté à 25 m/s,
  le clustering fait tomber les pistes de 12 à 3.

### Réglages retenus pour le profil maritime, et pourquoi

| réglage | valeur | mesure qui le justifie |
|---|---|---|
| `gate_max_m` | 200 | à 300-400 m la piste attrape des échos de mer : vitesse 19-25 km/h au lieu de 13-15 |
| `cluster_eps_vr_mps` | 25 | l'écart Doppler intra-coque atteint 10,5 m/s |
| `sigma_vr_floor_mps` | 2,0 | compromis mesuré entre stabilité du cap et justesse de la vitesse |
| `target_extent_m` + étendue déduite | 300 m / clusters | 18 naissances de pistes concurrentes bloquées dans l'emprise de la coque |
| `merge_enabled` | **False** | la fusion de pistes AJOUTE une piste (absorber libère les mesures, qui refont naître) |
| `contact_dist_m` / `contact_memory_sec` | 450 m / 30 s | étage d'affichage : un contact couvre 98 % de la fenêtre |

### Pourquoi une fusion purement géométrique ne suffit pas

Essai serveur : deux pistes sur le cargo (5 m/s et 2 m/s), plus une piste indépendante à 2 km. Mesuré sur
les deux estimations du cargo : distance médiane **103 m** (10e centile 48 m, 90e 365 m), |Δv| médian
3,8 m/s. Elles se croisent — c'est la signature d'une cible étendue.

Mais la seconde piste **naît à 650 m** de la première : aucun rayon d'interdiction de naissance ne peut la
bloquer sans bloquer aussi un second navire légitime, et le scénario synthétique du brief contient
précisément deux navires parallèles à 600 m qu'il ne faut PAS fusionner. Vérifié aussi : le nuage de plots
du cargo est unimodal autour de la trajectoire (157 plots sur 185 entre −279 et +171 m en travers, médianes
par index de dwell à ±77 m) — il n'y a donc pas de biais de géoréférencement entre faisceaux, piste
pourtant suggérée par le §8 du brief.

Un critère de **croisement** a été ajouté (`merge_cross_m` : deux pistes co-mobiles qui se rapprochent à
moins de N mètres sont la même cible ; deux navires parallèles gardent leur écart) — il déclenche bien,
mais ne réduit pas le compte final : la piste absorbée renaît au dwell suivant sur des échos que la piste
survivante ne peut pas atteindre (porte 200 m, nuage ±300 m). Il est donc livré **désactivé**, documenté.

### La réponse opérationnelle : un contact = un navire

Le regroupement se fait à l'affichage, et il est juste : les deux pistes du cargo appartiennent au
**contact 1**, la piste indépendante au contact 2. La console n'affiche désormais qu'un symbole par contact
multi-pistes — celui de la piste qui le représente — étiqueté `C1 (2 pistes) S60 4m/s` ; les membres
masqués restent listés dans l'infobulle et accessibles en cochant « tentatives ». L'opérateur voit un
navire, le filtre garde ses deux estimations.

### Ce qui reste ouvert

Deux estimations subsistent dans le filtre pour un navire unique. C'est acceptable à l'écran depuis que le
contact fait foi, mais pas satisfaisant dans l'état interne — les deux pistes portent des vitesses
différentes (4,5 et 2,0 m/s), et c'est celle du représentant qui est affichée.

Aller jusqu'à UNE piste demande de modéliser l'étendue DANS l'état (filtre à matrice aléatoire / cible
étendue elliptique) : la taille et l'orientation de la coque deviennent des paramètres estimés, et toutes
les mesures d'un dwell tombant dans l'ellipse alimentent la même piste. C'est ce que fait le CLAW du radar,
qui travaille en plus sur le signal brut. Chantier d'un autre ordre que le brief, à décider.

## 3. Capture routière — `volCAE2-MTI.pcap` (48 min, 11 219 plots)

| variante | pistes confirmées | rejetées | clustering | miss observables | miss évités | fusions |
|---|---|---|---|---|---|---|
| v8.1 | 841 | 1 572 | — | — | — | — |
| v9 livré | **821** | 5 025 | 478 plots agrégés | 8 937 | **333 704** | 0 |

**−2,4 %** de pistes : la non-régression du §6.3 est tenue (limite ±10 %). Le profil routier n'active ni
l'étage contact ni l'étendue de cible — deux véhicules d'un convoi ne doivent jamais être regroupés.

Le chiffre à retenir est celui des **miss évités** : 333 704 dwells où une piste n'était pas dans
l'empreinte du dwell — 97 % des « miss » que le v8 aurait comptés. C'est la brique d'observabilité qui
justifie à elle seule les colonnes de dwell ajoutées au CSV. Sans ces colonnes (ancien CSV), le même
profil ne garde que 41 pistes : les pistes meurent sur des miss fictifs.

## 4. État des étapes du brief §7

| étape | état |
|---|---|
| 1. clustering seul | fait, mesuré (12 → 3 pistes sur la maritime) |
| 2. EKF Doppler + R anisotrope | fait, mesuré ; **actif** avec un plancher σ_v_LOS de 2 m/s — sans plancher, ou avec une porte large, il fausse la vitesse |
| 3. observabilité (empreinte + zone aveugle) | fait, mesuré (333 704 miss évités en routier, couverture 100 % en maritime) |
| 4. suppression sur miss observables + fusion | fait ; fusion de pistes mesurée nuisible → remplacée par l'étage contact (port du TrackMerger v8) |
| 4 bis. étendue de cible (naissances bloquées, échos absorbés) | ajouté hors brief : c'est ce qui fait tomber 12 pistes à 3 |
| 5. portage des flags v8 | fait (`is_air`, `is_rotator`, états Faible/Confirmee/Solide/Coasting, RTS) |
| 6. intégration console | faite : pistage direct (`gmti_live`), analyse de pcap, détail de piste, profils, extracteur et parité vérifiés avec le v9 sélectionné ; `GMTI_TRACKER_VERSION` épingle une version |

## 5. Interchangeabilité v8 / v9 (corrigé après essai serveur)

Le premier essai sur serveur n'a produit **aucune piste** alors que les plots s'affichaient : le dossier du
tracker ne porte pas que le tracker, et `gmti_live.LiveTracker` — le pistage TEMPS RÉEL, celui de la console
en écoute réseau comme du service GMTI — était écrit pour l'API v8 (`Tracker()`, `step(t, plots)`,
`prepare_plots`, `TrackMerger`). Corrections :

- `gmti_live` détecte la génération et parle l'API native du v9 (`step(Dwell)`), en lui passant les champs
  d'empreinte du dwell **et les dwells sans plot** — sans eux, l'observabilité ne sert à rien en direct.
  Mesuré sur la capture cargo rejouée : 585 dwells traités contre 113 au v8, 3 pistes regroupées en
  1 contact pour le navire ;
- l'extracteur 4607 et l'oracle de parité sont désormais cherchés dans le dossier le plus récent QUI LES
  FOURNIT, et non dans celui du tracker retenu (ce sont des outils, pas des versions de tracker) ;
- le v9 expose ce qu'attend la console : `PROFILES_JSON`, `java_config`, `load_profiles` au format du
  fichier partagé, `rts_tail` pour la traîne lissée, la constante d'état `DEAD` (codes de la barre de temps
  et du journal de pistage), `misses`, et un `track_detail` de même forme que le v8 (historique, plots
  associés avec leur d², ellipses de porte) — l'inspecteur de piste fonctionne.

`test_console_api.py` parcourt ce contrat de bout en bout sur une vraie capture — sélection de version,
attributs du module, analyse de pcap, inspection d'une piste, barre de temps, pistage direct. **41 contrôles,
0 échec, avec le v9 comme avec le v8** (`GMTI_TRACKER_VERSION=8.1`). Trois essais serveur avaient échoué
faute de ce test : une constante manquante suffisait à ne plus produire aucune piste, sans autre signal.
