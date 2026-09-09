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

## Les trois limites mesurées, à connaître avant de décider du lot B

1. **L'estimateur ne distingue pas une grande cible d'une mesure bruitée.** Sur la capture routière
   (extrait de 1 500 plots, profil `routier`), il attribue à des véhicules de 5 m une coque médiane de
   **148 m**, et dépasse 200 m sur 10 pistes. Ce qu'il mesure alors, c'est l'erreur du radar, pas un
   objet. Sur le cargo, la coque sort à 259 × **209 m** : la longueur est crédible, la largeur n'est que
   du bruit — et l'allongement (1,24) reste sous le seuil de publication du cap de coque, qui n'est donc
   jamais fourni sur cette capture. **La plus-value « cap de coque » n'est pas démontrée sur du réel.**
2. **La signature de coque est faible dans cette géométrie.** Le nuage d'échos autour de la route de
   référence n'a un allongement que de **1,27** (σ 139 m le long, 110 m en travers). La ligne de vue du
   capteur est à **72°** de la route : l'erreur en distance annoncée par le radar (101 m, la plus grande)
   tombe en travers de la coque et masque sa forme, tandis que l'erreur transverse (50 m) tombe le long.
   Sur les paires d'échos simultanés, **36 % seulement** sont alignées à moins de 30° de la route.
3. **Le gain sur les identités ne vient pas entièrement de la forme.** Décomposition mesurée : avec
   l'ellipse dégonflée jusqu'à la cible ponctuelle, le prototype atteint déjà 1 identité — c'est la
   boucle d'association (« une piste peut prendre plusieurs groupes d'échos », au lieu du un-pour-un du
   v9) qui fait l'essentiel. L'ellipse ajoute la précision de position (86 → 68 m) et la forme.
   Il existe donc une option intermédiaire, bien moins coûteuse que le lot B complet.

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

## Suite

Une seule capture de navire ne décide pas d'un lot B. Pour en ajouter : déposer les pcap dans
`StratusServer-v2/docker/data/captures`, extraire avec
`python gmti_pcap_to_csv.py <pcap> -o <csv>`, puis
`python compare_tracker_versions.py <csv> --profile maritime --ext`.

Ce qu'il faudra regarder sur chaque nouvelle capture : le nombre d'identités sur la cible (le critère),
l'erreur de cap (le coût), et l'allongement de l'ellipse (si elle reste sous 1,6 comme ici, la forme
n'apporte rien d'exploitable).
