#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tracker_ext.py — estimateur de CIBLE ÉTENDUE (lot A, prototype hors ligne).

Ce que ça change, en une phrase : une piste cesse d'être un point pour devenir un point PLUS une
ellipse, et les échos qui tombent dans l'ellipse alimentent cette piste au lieu d'en ouvrir une autre.

Sur la capture cargo, un navire de ~250 m rend 1 à 3 échos par dwell (médiane 1), espacés de 259 m en
médiane quand il y en a plusieurs : le v9 les traite en mesures concurrentes, la coque finit portée par
deux identifiants, et la fusion a posteriori répare imparfaitement. Ici l'étendue est estimée EN LIGNE
avec l'état, par le modèle « matrice aléatoire » (Koch 2008, Feldmann-Franken-Koch 2011) : l'ellipse est
une inverse-Wishart de ν degrés de liberté, mise à jour par l'étalement des échos ET par la dispersion
des innovations — indispensable ici, car avec un seul écho par dwell l'étalement instantané est nul et
seule la seconde source informe.

TROIS EMPLOIS de l'ellipse, et c'est là que se joue la valeur :
  1. fenêtre d'association — S = P + z·X + R : un écho à 100 m du centre est DANS la piste ;
  2. interdiction de naissance — un écho dans l'ellipse ne fonde pas de piste concurrente ;
  3. cap de coque — l'axe majeur donne une orientation que le Doppler d'un navire ne donne pas
     (il mesure l'agitation des diffuseurs, cf. le plancher σ_v_LOS du v9).

CE MODULE NE TOUCHE PAS LE V9 : il en importe le tracker et sous-classe `Track`/`Tracker`. La chaîne
temps réel (gmti_live, StratusServer, widgets) reste sur le v9 tant qu'aucune décision n'est prise.
"""
from __future__ import annotations

import importlib.util
import math
import os
import sys
from dataclasses import dataclass

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
V9_DIR = os.path.join(os.path.dirname(HERE), "prototype_tracker_gmti_v9")


def _load_v9():
    """Charge `tracker.py` et `track_run.py` du v9 SANS les modifier ni polluer durablement sys.modules.

    Le v9 fait `import tracker as T` : le module doit donc être enregistré sous ce nom le temps du
    chargement. On restaure ensuite l'état d'origine — le banc de comparaison charge plusieurs versions
    dans le même processus, et deux modules nommés `tracker` ne doivent pas se marcher dessus.
    """
    if not os.path.isdir(V9_DIR):
        raise SystemExit("tracker v9 introuvable : %s" % V9_DIR)
    saved_path = list(sys.path)
    saved_mods = {n: sys.modules.get(n) for n in ("tracker", "track_run")}
    sys.path.insert(0, V9_DIR)
    try:
        mods = {}
        for name in ("tracker", "track_run"):
            spec = importlib.util.spec_from_file_location(name, os.path.join(V9_DIR, name + ".py"))
            m = importlib.util.module_from_spec(spec)
            sys.modules[name] = m
            spec.loader.exec_module(m)
            mods[name] = m
        return mods["tracker"], mods["track_run"]
    finally:
        sys.path[:] = saved_path
        for n, m in saved_mods.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


T, R9 = _load_v9()


# ----------------------------------------------------------------------
# Réglages propres à l'estimateur d'étendue
# ----------------------------------------------------------------------
@dataclass
class ExtProfile(T.Profile):
    """Profil v9 + les réglages de l'étendue. Tout le reste du v9 continue de s'appliquer tel quel."""
    ext_enabled: bool = True
    # Ellipse initiale : isotrope, de diamètre `ext_init_m`. On ne prétend PAS connaître l'orientation à
    # la naissance — un seul écho ne la donne pas ; l'estimateur la trouve en quelques dwells.
    ext_init_m: float = 150.0
    ext_dof0: float = 6.0                 # ν initial : faible = l'ellipse se laisse corriger vite
    ext_tau_s: float = 60.0               # oubli de ν : au-delà, l'ellipse ne suivrait plus une évolution
    # Facteur d'échelle des sources de mesure (z du modèle FFK) : les échos se répartissent selon
    # N(centre, z·X). Ce n'est PAS une constante universelle — il traduit où les diffuseurs se tiennent
    # sur la cible : z = 1/3 s'ils sont répartis uniformément sur la longueur, z = 1 s'ils ne sont qu'aux
    # deux extrémités, z = 2/3 pour extrémités + centre. Le produit z·X (la dispersion réellement
    # observée) est invariant : z ne change donc PAS le pistage, seulement la longueur PUBLIÉE. 2/3
    # restitue les 220 m du scénario synthétique et les ~250 m de la coque du cargo ; c'est la valeur
    # retenue, et elle est une hypothèse assumée sur la répartition des échos, pas une mesure.
    ext_z: float = 2.0 / 3.0
    ext_min_m: float = 40.0               # garde-fous sur les axes (longueurs, pas demi-axes), en mètres
    ext_max_m: float = 500.0
    ext_gate_chi2: float = 9.21           # 99 % à 2 ddl sur S = P + z·X + R
    ext_gate_margin_m: float = 150.0      # marge dure au-delà du demi-grand axe (borne le coût)
    ext_birth_k: float = 1.0              # un écho à d²_X ≤ k² dans l'ellipse ne fonde pas de piste
    # FENÊTRE DE CONFIRMATION EN TEMPS. Le v9 confirme sur « m détections parmi les n derniers dwells
    # FACTURÉS » ; or un dwell où la piste n'est pas observable n'est pas facturé, à juste titre. Une
    # piste jamais observable — un écho de fouillis à Doppler constant sous la MDV — ne se voit donc
    # jamais opposer de manqué et finit confirmée sur trois détections étalées sur une demi-minute. Le
    # v9 n'y échappe que par accident (son estimation de vitesse s'emballe sur ce type d'écho et le rend
    # observable) ; on l'interdit ici explicitement : les m détections doivent tomber dans cette durée.
    # 0 = comportement v9.
    ext_confirm_window_s: float = 15.0
    ext_rotate_with_course: bool = True   # l'ellipse tourne avec le cap (une coque suit sa route)
    # Regrouper les échos SIMULTANÉS avant l'association (clustering v9). Laisser l'étendue tout faire
    # paraissait plus pur ; c'est mesuré comme moins bon (sur le cargo : 2 identités et σ cap 22,8° sans
    # regroupement, 1 identité et 6,1° avec). Les deux étages ne traitent pas la même chose : le
    # regroupement réunit les échos d'un MÊME dwell en un centroïde à covariance élargie, l'étendue
    # assure la cohérence d'un dwell à l'autre. Le second ne remplace pas le premier.
    ext_cluster_first: bool = True
    # Cap de coque : publié toujours, substitué au cap cinématique seulement si demandé, et seulement
    # quand l'ellipse est franchement allongée (sinon l'axe majeur n'est que du bruit).
    heading_from_extent: bool = False
    ext_hdg_min_ratio: float = 1.6        # allongement minimal (grand axe / petit axe)
    ext_hdg_min_speed_mps: float = 1.0


def ext_profile(prof, **kw) -> ExtProfile:
    """Profil v9 existant → profil étendu, réglages d'étendue par défaut sauf indication."""
    base = dict(prof.__dict__)
    base.update(kw)
    return ExtProfile(**base)


# ----------------------------------------------------------------------
# Algèbre des matrices d'étendue
# ----------------------------------------------------------------------
def _sym(M):
    return 0.5 * (M + M.T)


def _eig(M):
    """Décomposition symétrique avec valeurs propres strictement positives (X doit rester inversible)."""
    w, V = np.linalg.eigh(_sym(M))
    return np.clip(w, 1e-6, None), V


def _sqrt(M):
    w, V = _eig(M)
    return V @ np.diag(np.sqrt(w)) @ V.T


def _inv_sqrt(M):
    w, V = _eig(M)
    return V @ np.diag(1.0 / np.sqrt(w)) @ V.T


def _clip_extent(X, min_m, max_m):
    """Borne les axes. Les valeurs propres de X sont les carrés des DEMI-axes : une ellipse longue de
    250 m a λ_max = 125²."""
    w, V = _eig(X)
    lo, hi = (min_m / 2.0) ** 2, (max_m / 2.0) ** 2
    return _sym(V @ np.diag(np.clip(w, lo, hi)) @ V.T)


def extent_axes(X):
    """(longueur, largeur, orientation de l'axe majeur en degrés vrais, modulo 180)."""
    w, V = _eig(X)
    order = np.argsort(w)[::-1]
    w, V = w[order], V[:, order]
    ax = V[:, 0]
    hdg = (math.degrees(math.atan2(ax[0], ax[1])) + 360.0) % 180.0
    return 2.0 * math.sqrt(w[0]), 2.0 * math.sqrt(w[1]), hdg


# ----------------------------------------------------------------------
# Piste étendue
# ----------------------------------------------------------------------
class ExtTrack(T.Track):
    """Piste v9 augmentée d'une étendue elliptique (X, ν) estimée conjointement à la cinématique."""

    def __init__(self, m, t, prof, sx, sy, sz, job_id=None):
        super().__init__(m, t, prof, sx, sy, sz, job_id)
        r0 = max(prof.ext_init_m, prof.ext_min_m) / 2.0
        if m.spread_m > 0:                                  # naissance sur un groupe déjà étalé
            r0 = max(r0, m.spread_m)
        self.X = np.eye(2) * r0 ** 2
        self.nu = float(prof.ext_dof0)
        length, width, hdg = extent_axes(self.X)
        self.extent = length                                # le scalaire du v9 reste renseigné (sorties,
        #                                                     fusion héritée) : c'est le grand axe.
        self.ext_hist = [(t, length, width, hdg)]
        self.n_echoes = m.n_plots                           # échos absorbés sur la vie de la piste
        self.win_t = [(t, 1)]                               # fenêtre M/N datée (cf. ext_confirm_window_s)

    # ---------------------------------------------------------------- fenêtre M/N datée
    def miss(self):
        super().miss()
        self.win_t.append((self.t, 0))

    def prune_window(self, t):
        """Ne garder dans la fenêtre M/N que ce qui s'est passé récemment, en SECONDES.

        Sans cela, une piste que le radar ne regarde jamais accumule des détections sans jamais se voir
        opposer un manqué, et se confirme sur des éléments distants d'une demi-minute.
        """
        w = self.prof.ext_confirm_window_s
        if w <= 0:
            return
        self.win_t = [(tt, h) for (tt, h) in self.win_t if t - tt <= w][-self.prof.confirm_n:]
        self.window = [h for _tt, h in self.win_t]

    # ---------------------------------------------------------------- prédiction
    def predict(self, t):
        dt = t - self.t
        super().predict(t)
        if dt > 0 and self.prof.ext_tau_s > 0:
            # Oubli : ν redescend vers 2 (ignorance totale). Sans lui, ν croît sans borne et l'ellipse
            # se fige — un navire qui vire ou une piste qui change de cible ne seraient plus suivis.
            self.nu = 2.0 + math.exp(-dt / self.prof.ext_tau_s) * (self.nu - 2.0)

    # ---------------------------------------------------------------- association
    def gate(self, m, prof):
        """(d², S) de la mesure `m` pour cette piste, ou None si hors fenêtre.

        C'est LA différence de fond avec le v9 : la covariance d'innovation contient z·X. Un écho de
        poupe à 120 m du centre n'est plus une aberration statistique, c'est une observation normale
        d'une cible longue de 250 m.
        """
        eps = m.z[:2] - self.x[:2]
        dist = float(math.hypot(eps[0], eps[1]))
        semi = extent_axes(self.X)[0] / 2.0
        if dist > self.gate_max + semi + prof.ext_gate_margin_m:
            return None
        S = self.P[:2, :2] + prof.ext_z * self.X + m.R[:2, :2]
        try:
            d2 = float(eps @ np.linalg.solve(S, eps))
        except np.linalg.LinAlgError:
            return None
        return (d2, S) if d2 <= prof.ext_gate_chi2 else None

    # ---------------------------------------------------------------- mise à jour
    def update_extended(self, ms, sx, sy, sz, d2=float("nan"), merged=None):
        """Mise à jour par un ensemble d'échos. DEUX ÉTAGES, volontairement découplés :

          - la CINÉMATIQUE est corrigée par le centroïde du groupe, avec la covariance élargie que le
            v9 lui donne déjà — c'est la mesure la plus stable d'un dwell à l'autre, et la mesure a
            montré que la faire manger les échos bruts un par un dégrade le cap d'un facteur deux ;
          - la FORME est estimée sur les échos BRUTS, seuls porteurs de la dispersion de la coque.

        Le modèle FFK d'origine fait les deux d'un coup, en supposant les échos indépendants autour du
        centre. Ils ne le sont pas : ce sont des diffuseurs précis dont l'ensemble détecté change d'un
        dwell à l'autre. Leur centroïde n'est pas √n fois plus juste, il est simplement ailleurs.
        """
        prof = self.prof
        n = len(ms)
        merged = merged if merged is not None else (T.merge_meas(list(ms)) if n > 1 else ms[0])
        Z = np.array([m.z[:2] for m in ms], dtype=float)
        zbar = Z.mean(axis=0)
        dev = Z - zbar
        Zs = dev.T @ dev                                   # étalement mesuré (nul si un seul écho)
        Rbar = sum(m.R[:2, :2] for m in ms) / n

        hdg0, spd0 = self.heading_deg(), self.speed()
        Xhat = self.X.copy()
        # --- étage cinématique : centroïde groupé + étendue dans la covariance d'innovation
        zc = merged.z[:2]
        S = self.P[:2, :2] + prof.ext_z * Xhat + merged.R[:2, :2]
        eps = zc - self.x[:2]
        K = self.P[:, :2] @ np.linalg.inv(S)
        self.x = self.x + K @ eps
        self.P = _sym(self.P - K @ S @ K.T)

        if prof.ext_enabled:
            # --- étage forme : dispersion des échos bruts, normalisée par ce que le modèle prévoit
            Y = prof.ext_z * Xhat + Rbar                   # covariance d'UN écho autour du centre
            Xr = _sqrt(Xhat)
            Si, Yi = _inv_sqrt(S), _inv_sqrt(Y)
            N = Xr @ Si @ np.outer(eps, eps) @ Si.T @ Xr.T
            Zh = Xr @ Yi @ Zs @ Yi.T @ Xr.T
            # ν pondère l'ancien contre le nouveau : l'ellipse ne saute pas sur un dwell isolé.
            self.X = _clip_extent((self.nu * Xhat + N + Zh) / (self.nu + n), prof.ext_min_m, prof.ext_max_m)
            self.nu += n

        # Doppler : mise à jour séquentielle sur la seule composante v_LOS, avec la géométrie exacte du
        # v9. Le modèle de matrice aléatoire est positionnel ; traiter le Doppler à part est licite (les
        # deux mesures sont indépendantes) et garde la comparaison honnête avec le v9.
        vrs = [float(m.z[2]) for m in ms if m.has_vr]
        if prof.doppler_enabled and vrs:
            Hf = T.h_jac(self.x, sx, sy, sz, prof.sign_vlos)[2:3, :]
            zhat = T.h_meas(self.x, sx, sy, sz, prof.sign_vlos)[2]
            sig = max(float(np.mean([m.R[2, 2] for m in ms if m.has_vr])) ** 0.5, prof.sigma_vr_floor_mps)
            # PAS de division par n : les Doppler de plusieurs échos d'une MÊME coque ne sont pas des
            # tirages indépendants (mesuré sur la capture cargo : 2,9 m/s d'écart entre deux échos
            # simultanés à moins de 150 m, 10,5 m/s entre 150 et 300 m). Moyenner n'apporte donc pas le
            # gain en √n habituel ; le supposer verrouille la vitesse radiale sur la mesure, et une piste
            # de fouillis reste alors éternellement sous la MDV — donc jamais comptée en manqué, donc
            # confirmée à tort. C'est exactement ce qu'on a observé avant ce correctif.
            Rv = np.array([[sig ** 2]])
            y = np.array([float(np.mean(vrs)) - zhat])
            Sv = Hf @ self.P @ Hf.T + Rv
            Kv = self.P @ Hf.T @ np.linalg.inv(Sv)
            self.x = self.x + (Kv @ y.reshape(1, 1)).ravel()
            I_KH = np.eye(4) - Kv @ Hf
            self.P = _sym(I_KH @ self.P @ I_KH.T + Kv @ Rv @ Kv.T)

        if prof.ext_rotate_with_course and prof.ext_enabled:
            hdg1, spd1 = self.heading_deg(), self.speed()
            if min(spd0, spd1) > prof.ext_hdg_min_speed_mps:
                # La coque suit sa route : quand le cap estimé tourne, l'ellipse tourne avec lui. Sans
                # cela, l'axe majeur resterait figé sur l'ancienne route et absorberait de travers.
                a = math.radians(hdg1 - hdg0)
                M = np.array([[math.cos(a), math.sin(a)], [-math.sin(a), math.cos(a)]])
                self.X = _sym(M @ self.X @ M.T)

        # Comptabilité v9 : une seule « mesure » du point de vue de la gestion de piste, quel que soit
        # le nombre d'échos absorbés — sinon `hits` et la fenêtre M/N ne voudraient plus rien dire.
        self.assoc.append((self.t, float(zbar[0]), float(zbar[1]), float(d2),
                           float(np.mean(vrs)) if vrs else None, merged.snr_db, merged.classification))
        self.gates.append((self.t, S, float(d2)))
        self.t_last_update = self.t
        self.hits += 1
        self.n_plots_last = sum(m.n_plots for m in ms)
        self.n_echoes += self.n_plots_last
        self.window = (self.window + [1])[-prof.confirm_n:]
        self.win_t.append((self.t, 1))
        self.consecutive_obs_misses = 0
        self.misses = 0
        if merged.classification is not None:
            self.classification = merged.classification
            self.cls_counts[merged.classification] = self.cls_counts.get(merged.classification, 0) + 1
        self._update_flags(merged)
        length, width, hdg = extent_axes(self.X)
        self.extent = length
        self.ext_hist.append((self.t, length, width, hdg))

    # ---------------------------------------------------------------- sorties
    def inside(self, xy, k=1.0):
        """Le point est-il DANS l'ellipse (à k demi-axes) ? Test de Mahalanobis sur X."""
        d = np.asarray(xy, dtype=float) - self.x[:2]
        try:
            return float(d @ np.linalg.solve(self.X, d)) <= k * k
        except np.linalg.LinAlgError:
            return False

    def extent_len_m(self):
        return extent_axes(self.X)[0]

    def extent_wid_m(self):
        return extent_axes(self.X)[1]

    def hull_heading_deg(self):
        """Cap donné par l'axe de coque, levé d'ambiguïté par la vitesse (une ellipse n'a pas de proue).

        Renvoie None quand l'ellipse est trop ronde ou la piste trop lente : mieux vaut pas de cap qu'un
        cap tiré d'un axe majeur qui n'est que du bruit.
        """
        prof = self.prof
        length, width, hdg = extent_axes(self.X)
        if width <= 0 or length / width < prof.ext_hdg_min_ratio:
            return None
        if self.speed() < prof.ext_hdg_min_speed_mps:
            return None
        kin = self.heading_deg()
        return hdg if abs((hdg - kin + 180) % 360 - 180) <= 90 else (hdg + 180.0) % 360.0

    def reported_heading_deg(self):
        """Cap publié : celui de la coque si le profil le demande et qu'il est disponible."""
        if self.prof.heading_from_extent:
            h = self.hull_heading_deg()
            if h is not None:
                return h
        return self.heading_deg()


# ----------------------------------------------------------------------
# Tracker étendu
# ----------------------------------------------------------------------
class ExtTracker(T.Tracker):
    """Boucle d'association « une piste, plusieurs échos », là où le v9 fait « une piste, une mesure ».

    Le reste (confirmation M/N, coasting, suppression, fusion piste-à-piste, observabilité) est celui du
    v9, hérité tel quel : on mesure l'apport de l'étendue, pas celui d'une réécriture complète.
    """

    def __init__(self, prof, frame):
        super().__init__(prof, frame)
        self.n_multi_echo = 0        # dwells où une piste a reçu plus d'un écho
        self.n_extra_echo = 0        # échos surnuméraires absorbés (autant de pistes non ouvertes)

    def _measures(self, dwell, sx, sy, sz):
        """Échos du dwell → liste de (mesure d'association, échos qui la composent).

        Deux usages distincts, et c'est le point clé du prototype :
          - pour ASSOCIER, on présente le centroïde d'un groupe d'échos simultanés — stable d'un dwell à
            l'autre, donc une cinématique propre ;
          - pour ESTIMER LA FORME, on garde les échos BRUTS — c'est leur dispersion qui porte la coque.
        Regrouper avant l'association sans conserver les membres reviendrait à jeter l'information même
        que l'estimateur d'étendue exploite (mesuré : la coque du scénario synthétique tombe alors de
        224 m à 64 m).
        """
        prof = self.prof
        singles = T.cluster_dwell(dwell, T.profile_with(prof, cluster_enabled=False), sx, sy, sz)
        if not prof.ext_cluster_first or len(singles) < 2:
            return [(m, [m]) for m in singles]
        xy = np.array([m.z[:2] for m in singles], dtype=float)
        vr = np.array([m.z[2] if m.has_vr else np.nan for m in singles], dtype=float)
        out = []
        for g in T._single_link(xy, vr, prof.cluster_eps_xy_m, prof.cluster_eps_vr_mps):
            members = [singles[k] for k in g]
            out.append((T.merge_meas(members) if len(g) > 1 else members[0], members))
        return out

    def step(self, dwell):
        prof = self.prof
        sx, sy = self.frame.to_xy(dwell.sensor_lat, dwell.sensor_lon)
        sz = dwell.sensor_alt_m or 0.0
        if dwell.center_lat is not None:
            dwell.center_xy = self.frame.to_xy(dwell.center_lat, dwell.center_lon)

        paires = self._measures(dwell, sx, sy, sz)
        meas = [m for m, _mem in paires]
        self.n_clustered += sum(m.n_plots - 1 for m in meas)

        for tr in self.tracks:
            tr.predict(dwell.t)

        # --- association : chaque mesure va à la piste qui l'explique le mieux, une piste peut en
        #     recevoir plusieurs. C'est le principe même de la cible étendue.
        groups = {}
        for j, m in enumerate(meas):
            best = None
            for i, tr in enumerate(self.tracks):
                g = tr.gate(m, prof)
                if g is not None and (best is None or g[0] < best[1]):
                    best = (i, g[0])
            if best is not None:
                groups.setdefault(best[0], []).append((j, best[1]))

        assigned_m = set()
        for i, items in groups.items():
            tr = self.tracks[i]
            assigned_m.update(j for j, _d in items)
            # La mise à jour reçoit les échos BRUTS de tous les groupes associés : c'est leur dispersion
            # qui alimente l'estimation de forme, et le modèle FFK sait traiter n échos nativement.
            ms = [e for j, _d in items for e in paires[j][1]]
            groupes = [meas[j] for j, _d in items]
            if len(items) > 1:
                self.n_multi_echo += 1
                self.n_extra_echo += len(items) - 1
                self.n_absorbed_meas += len(items) - 1
            tr.update_extended(ms, sx, sy, sz, min(d for _j, d in items),
                               merged=T.merge_meas(groupes) if len(groupes) > 1 else groupes[0])
            if dwell.job_id is not None:
                tr.job_ids.add(dwell.job_id)

        # --- miss : inchangé, y compris l'observabilité (un dwell pointé ailleurs n'est pas un miss)
        for i, tr in enumerate(self.tracks):
            if i in groups:
                continue
            if prof.observability_enabled:
                observable = (T.track_in_dwell(tr, dwell, sx, sy)
                              and not T.doppler_blind(tr, dwell, sx, sy, sz, prof))
            else:
                observable = True
            if observable:
                tr.miss()
                self.n_obs_miss += 1
            else:
                self.n_unobservable += 1

        # --- naissances : les échos restants, regroupés, sauf ceux tombant dans une ellipse vivante
        rest = [j for j in range(len(meas)) if j not in assigned_m]
        for group in self._birth_groups(rest, meas):
            inside = any(tr.inside(group.z[:2], prof.ext_birth_k)
                         and (prof.extent_blocks_tentative or tr.state != T.TENTATIVE)
                         for tr in self.tracks)
            if inside:
                self.n_births_blocked += 1
                continue
            self.tracks.append(ExtTrack(group, dwell.t, prof, sx, sy, sz, dwell.job_id))

        for tr in self.tracks:                             # fenêtre M/N ramenée au temps présent
            tr.prune_window(dwell.t)
        self._manage(dwell.t)
        for tr in self.tracks:
            hit = tr.t_last_update == dwell.t
            tr.states.append((dwell.t, tr.x.copy(), tr.P.copy()))
            tr.history.append((dwell.t, float(tr.x[0]), float(tr.x[1]), tr.state, hit))
            if hit:
                tr.last_hit_idx = len(tr.states) - 1

    def _birth_groups(self, rest, meas):
        """Échos non associés → mesures de naissance. Deux échos proches ouvrent UNE piste, pas deux :
        c'est le seul endroit où le regroupement du v9 garde son utilité (aucune ellipse ne les couvre
        encore)."""
        if not rest:
            return []
        prof = self.prof
        if len(rest) == 1 or not prof.cluster_enabled:
            return [meas[j] for j in rest]
        xy = np.array([meas[j].z[:2] for j in rest], dtype=float)
        vr = np.array([meas[j].z[2] if meas[j].has_vr else np.nan for j in rest], dtype=float)
        out = []
        for g in T._single_link(xy, vr, prof.cluster_eps_xy_m, prof.cluster_eps_vr_mps):
            out.append(T.merge_meas([meas[rest[k]] for k in g]) if len(g) > 1 else meas[rest[g[0]]])
        return out

    def snapshot(self, t):
        out = super().snapshot(t)
        by_id = {tr.id: tr for tr in self.tracks}
        for s in out:
            tr = by_id[s["track_id"]]
            s["extent_len_m"] = round(tr.extent_len_m(), 1)
            s["extent_wid_m"] = round(tr.extent_wid_m(), 1)
            s["extent_hdg_deg"] = round(extent_axes(tr.X)[2], 1)
            h = tr.hull_heading_deg()
            s["hull_heading_deg"] = None if h is None else round(h, 1)
            s["heading_deg"] = tr.reported_heading_deg()
            s["n_echoes"] = tr.n_echoes
        return out
