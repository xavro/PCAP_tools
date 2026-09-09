# Estimateur de cible étendue — lot A (prototype hors ligne)

Prototype d'un tracker où une piste n'est plus un point mais **un point plus une ellipse**, l'ellipse
étant estimée en ligne avec l'état (modèle de matrice aléatoire, inverse-Wishart : Koch 2008,
Feldmann–Franken–Koch 2011).

**Ce module ne touche pas la chaîne temps réel.** Il importe le tracker v9 et en sous-classe `Track` et
`Tracker` ; `gmti_live`, StratusServer et les widgets restent sur le v9 sans modification. Aucun portage
Java n'est prévu (parité Java abandonnée).

## Architecture — deux étages volontairement découplés

Le modèle FFK d'origine corrige la cinématique et la forme d'un seul coup, en supposant n échos
indépendants tirés autour du centre de la cible. C'est faux ici : ce sont des diffuseurs précis dont
l'ensemble détecté change d'un dwell à l'autre — leur centroïde n'est pas √n fois plus juste, il est
simplement ailleurs. D'où la séparation, dictée par les mesures :

| étage | entrée | rôle |
|---|---|---|
| cinématique | centroïde du groupe d'échos simultanés (mesure du v9, covariance déjà élargie) | position et vitesse |
| forme | échos **bruts**, un par un | longueur, largeur, axe de la coque |

Regrouper sans conserver les membres fait tomber la coque estimée de 224 m à 64 m sur le scénario
synthétique (l'information de forme est dans la dispersion des échos) ; ne pas regrouper du tout dégrade
le cap d'un facteur trois sur la capture réelle. Les deux étages sont nécessaires.

L'ellipse sert alors à trois choses : élargir la fenêtre d'association (`S = P + z·X + R`), interdire une
naissance à l'intérieur, et fournir un cap de coque quand elle est franchement allongée.

## Usage

    python track_run.py cargo.csv --profile maritime
    python test_extended.py                                   # validation sur vérité connue
    python ../compare_tracker_versions.py cargo.csv --profile maritime --ext

## Validation sur vérité connue (scénario synthétique du v9) — CONCLUANTE

| attendu | v9 | v9ext |
|---|---|---|
| une seule identité sur la cible | 1 | **1** |
| longueur de coque (vraie : 220 m) | non estimée | **224 m** (× 57 m, allongement 3,9) |
| cap de coque (vrai : 135°) | non estimé | **129,1°** |
| cinématique (vrai 135° / 28,8 km/h) | 135,5° ± 0,87 / 28,5 km/h | 135,4° ± 0,84 / 28,6 km/h |
| deux navires à 600 m restent deux | 2 | **2** (coques 265 m et 219 m) |

L'estimateur mesure donc bien une coque quand il y en a une, sans avaler le navire voisin, et sans rien
coûter à la cinématique.

## Mesure sur la capture réelle (cargo, 185 plots, 156 s, référence 13,3 km/h cap 127,3°)

| variante | ID sur cible | simult. | σ cap | σ vitesse | jitter | écart réf. | vitesse | erreur cap |
|---|---|---|---|---|---|---|---|---|
| v8.1 | 3 | 3 | 16,9° | 2,7 km/h | 54 m | 63 m | 7,1 km/h | 16,5° |
| v9 | 2 | 2 | **3,9°** | **1,0 km/h** | **15 m** | 80 m | 14,6 km/h | **7,0°** |
| v9ext | **1** | **1** | 7,5° | 5,7 km/h | 27 m | **68 m** | 11,9 km/h | 24,4° |

**Le critère de décision est atteint** : une seule identité, une seule piste simultanée, couverture
100 %, et la piste principale porte 101 détections contre 60 au v9. La position est meilleure (68 m
contre 80). **Le cap, lui, se dégrade nettement** : σ 3,9° → 7,5° et erreur 7° → 24°.

## Mesure sur une mission complète (2 septembre, CR1, 7 h 42, 84 000 plots, 8 navires isolés)

Cette mission change la conclusion tirée du seul cargo, pour une raison simple : **le radar y revisite
toutes les 6 à 10 s**, contre 1,35 s sur le cargo. Or le profil maritime avait été réglé sur le cargo.

Les navires sont pourtant bien détectés (écart médian entre détections 6 à 10 s, 90e centile 14 à 27 s,
presque aucun trou de plus d'une minute). Ce n'est donc pas un problème de détection : c'est la **porte
d'association**, fixée à 200 m, qui rejette une cible ayant légitimement parcouru 225 m pendant un trou
de 27 s. La piste se dédouble alors à chaque trou.

Indicateur : part de la fenêtre tenue par **une seule et même identité** (médiane sur les 8 navires).

| | porte fixe 200 m | porte + 40 m/s écoulés |
|---|---|---|
| cible ponctuelle (≈ v9) | 17 % | 43 % |
| **avec l'ellipse** | 24 % | **82 %** |

Les deux mécanismes se multiplient : ni l'un ni l'autre seul ne suffit. C'est le résultat principal du
lot A, et il n'était pas visible sur la capture cargo.

**La porte doit être proportionnelle au temps écoulé, pas fixe.** Ouvrir la porte fixe à 800 m donne
bien 47 % sur cette mission, mais ruine le cargo (erreur de cap 7° → 51°, 2 identités → 4). La grandeur
physique n'est pas une distance mais une vitesse : `porte = fixe + 40 m/s × Δt depuis la dernière mise à
jour`. Ce réglage unique sert les deux cadences — sur le cargo à 1,35 s il n'ouvre que de 54 m, et les
indicateurs y sont **inchangés au chiffre près**.

Contrôle de nuisance en trafic dense (capture routière, 1 500 plots) : 119 → 115 pistes, durée moyenne
26,8 → 27,2 s. La porte large ne vole pas les détections des voisins.

## Les limites mesurées, à connaître avant de décider du lot B


1. **L'estimateur ne distingue pas une grande cible d'une mesure bruitée.** Sur la capture routière
   (extrait de 1 500 plots, profil `routier`), il attribue à des véhicules de 5 m une coque médiane de
   **148 m**, et dépasse 200 m sur 10 pistes. Ce qu'il mesure alors, c'est l'erreur du radar, pas un
   objet. Sur le cargo, la coque sort à 259 × **209 m** : la longueur est crédible, la largeur n'est que
   du bruit — et l'allongement (1,24) reste sous le seuil de publication du cap de coque, qui n'est donc
   jamais fourni sur cette capture. Sur la mission complète, même constat : l'allongement médian de
   l'ellipse est de **1,00**, il dépasse 1,6 sur un seul cas sur cinq, et la longueur est collée à une
   borne (60 ou 400 m) dans 3 cas sur 5. **La plus-value « cap de coque » et « longueur de navire »
   n'est démontrée sur aucune capture réelle** — seulement sur le scénario synthétique.
   L'ellipse est donc utile comme *amortisseur d'association*, pas comme *mesure de la cible*.
2. **La signature de coque est faible dans cette géométrie.** Le nuage d'échos autour de la route de
   référence n'a un allongement que de **1,27** (σ 139 m le long, 110 m en travers). La ligne de vue du
   capteur est à **72°** de la route : l'erreur en distance annoncée par le radar (101 m, la plus grande)
   tombe en travers de la coque et masque sa forme, tandis que l'erreur transverse (50 m) tombe le long.
   Sur les paires d'échos simultanés, **36 % seulement** sont alignées à moins de 30° de la route.
3. **Sur le cargo seul, l'ellipse n'était pas nécessaire ; sur la mission, elle l'est.** Décomposition
   mesurée : sur le cargo, l'ellipse dégonflée jusqu'à la cible ponctuelle atteint déjà 1 identité —
   c'est la boucle d'association qui fait tout. Sur les 8 navires de la mission au contraire, la cible
   ponctuelle plafonne à 43 % de couverture quand l'ellipse en donne 82 %. Une seule capture ne pouvait
   pas trancher, et aurait conduit à la mauvaise décision.
4. **Le cap reste le point faible.** Sur le cargo, erreur de cap 7° (v9) contre 24° (v9ext) : absorber
   tous les échos de la coque stabilise l'identité mais fait errer le centroïde le long du navire. C'est
   le prix à payer, et il n'a pas été réduit.

Contrôle complémentaire : l'étendue **scalaire** que le v9 possède déjà (`target_extent_m`), essayée de
200 à 500 m, ne change strictement rien — parce que la seconde identité naît alors que les deux pistes
sont à **384 m** l'une de l'autre (elles se rapprochent ensuite à 103 m). Activer la fusion
piste-à-piste du v9 (`merge_enabled`, désactivée dans le profil maritime) fait *empirer* le compte
d'identités (2 → 3). Aucun levier existant du v9 n'atteint le critère.

Enfin, au niveau de l'opérateur, l'étage « contact » du v9 regroupait déjà ces deux identités (1 contact,
98 % de couverture) : le doublon corrigé était interne au filtre.

## Défaut du v9 découvert au passage (indépendant de l'étendue)

Le v9 confirme sur « m détections parmi les n derniers dwells **facturés** ». Un dwell où la piste n'est
pas observable n'est pas facturé — à juste titre. Mais une piste **jamais** observable (écho de fouillis
à Doppler constant sous la MDV) ne se voit alors jamais opposer de manqué : sa fenêtre ne contient que
des détections, et elle se confirme sur trois échos étalés sur 21 s.

Le v9 n'y échappe que par accident : sur ce type d'écho son estimation de vitesse s'emballe (3,1 → 4,2 →
5,2 m/s) et repasse au-dessus de la MDV, ce qui le rend observable et lui vaut des manqués. Dès qu'on
estime mieux la vitesse — ce que fait ce prototype — la piste reste sous la MDV et se confirme à tort.

Correctif retenu ici : `ext_confirm_window_s` (15 s) — les m détections doivent tomber dans une fenêtre
de **temps**, pas seulement de dwells. Sans lui, le scénario synthétique produit 3 identités au lieu
d'une. **Ce correctif vaut pour le v9 lui-même** et peut y être porté à faible risque.

## Le facteur `ext_z`

`z` traduit où se tiennent les diffuseurs sur la cible : 1/3 s'ils sont répartis uniformément sur la
longueur, 1 s'ils ne sont qu'aux deux extrémités, **2/3** (valeur retenue) pour extrémités + centre. Le
produit `z·X` — la dispersion réellement observée — est invariant : `z` ne change donc pas le pistage,
seulement la longueur **publiée**. C'est une hypothèse assumée sur la répartition des échos, pas une
mesure ; elle restitue les 220 m du scénario synthétique.

## Suite — ce que disent les mesures

**Ce qui est acquis et déjà porté au v9** (2026-09-09) : la **porte d'association proportionnelle au
temps écoulé**, `porte = gate_max_m + (|v| estimé + 40 m/s) × Δt`. Sans elle, le profil maritime ne tient
pas une mission à 6-10 s de revisite. Mesuré sur le v9 lui-même, sans aucune ellipse : couverture par une
seule identité **20 % → 59 %**, écart à la référence inchangé (130 m), aucun effet en trafic routier
dense, contact principal du cargo inchangé. Détail et contre-mesures dans `../prototype_tracker_gmti_v9/
CHANGELOG_v9.md`.

**Ce qui a été mesuré puis REFUSÉ au v9** : la fenêtre de confirmation bornée. Aucune de ses trois
formulations ne tient sur les trois jeux de données — en secondes elle dépend de la cadence, en dwells
reçus elle anéantit le trafic routier (128 → 20 pistes confirmées), en fenêtre M/N pleine elle dégrade
tout. Elle reste dans ce prototype, qui en a besoin parce qu'il estime trop bien la vitesse des échos de
fouillis à Doppler constant.

**Ce qui reste à décider (lot B).** L'ellipse elle-même double encore la couverture (43 % → 82 %) mais
touche le cœur du filtre, coûte 30 % de temps de calcul, et n'apporte **aucune mesure de forme
exploitable** sur du réel — sa valeur est celle d'un amortisseur d'association, pas d'un capteur de
dimensions. Le cap reste dégradé d'un facteur trois.

**Pour ajouter des captures :** déposer les pcap, extraire avec
`python gmti_pcap_to_csv.py <pcap> --port 5454 -o <csv>`, puis
`python compare_tracker_versions.py <csv> --profile maritime --ext`. Pour une mission longue, isoler
d'abord les navires : la référence de trajectoire du banc est quadratique et n'a de sens que sur une
cible unique.

Ce qu'il faut regarder sur chaque nouvelle capture : la **revisite réelle** (elle conditionne tout), la
couverture par une seule identité, l'erreur de cap, et l'allongement de l'ellipse.
