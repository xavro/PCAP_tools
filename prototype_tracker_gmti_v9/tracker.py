"""
tracker.py — Tracker GMTI v9 : cible étendue + EKF Doppler.

Objectif (brief §0) : UNE piste stable par cible réelle, à partir des plots MTI 4607 bruts. Sur la scène
maritime, un cargo renvoie 2 à 3 plots par dwell (proue, superstructure, poupe) et le v8 en fait 2 à 3
pistes qui se disputent les plots ; le vecteur vitesse, dérivé de positions bruitées à ~100 m sur 1,5 s,
est inexploitable.

Quatre changements structurels par rapport au v8, activables un par un (`Profile.*_enabled`) pour mesurer
l'apport de chacun, comme demandé au §7 du brief :

  1. CLUSTERING par dwell : les plots d'une même cible étendue forment UNE mesure, plus incertaine
     (l'étalement des membres entre dans R). Le v8 traitait le problème après coup, par absorption.
  2. EKF DOPPLER : la mesure est [x, y, v_LOS] et non plus [x, y]. La vitesse radiale, mesurée
     directement par le radar à ~0,3 m/s près, contraint le vecteur vitesse au lieu d'être seulement
     un indice de classification. C'est ce qui stabilise le cap.
  3. OBSERVABILITÉ : un dwell sans plot ne compte comme miss que si la piste était dans l'empreinte du
     dwell ET hors zone aveugle Doppler. Sinon elle « coast » sans pénalité — fin des pistes supprimées
     puis recréées avec un nouvel identifiant à chaque trou de couverture ou passage perpendiculaire.
  4. FUSION piste-à-piste et suppression sur miss OBSERVABLES consécutifs, qui éliminent les doublons.

Repris du v8 sans changement de sémantique : états de piste (Faible / Confirmee / Solide / Coasting),
flags `is_air` (candidat aérien) et `is_rotator` (rotateur fixe), lisseur RTS pour le produit trajet,
repère local `LocalFrame` (même conversion, donc mêmes coordonnées affichées).

Le filtre des plots aberrants (> 400 km, hors empreinte, sentinelles) reste en amont, dans l'extracteur
4607 (`target_plausible`) : v9 consomme le même CSV que v8.

Unités : mètres, secondes, m/s, degrés. Les conversions 4607 (cm/s, cm, dm) sont faites par l'extracteur.
Convention de signe D32.7 : positif = cible s'éloignant du capteur. Si une capture montre l'inverse,
basculer `Profile.sign_vlos` à -1 (le rapport de comparaison teste ce signe, cf. brief §3).
"""
from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field, replace
from typing import Optional

import numpy as np

try:
    from scipy.optimize import linear_sum_assignment
except ImportError:                                   # repli glouton dans assign()
    linear_sum_assignment = None


# ----------------------------------------------------------------------
# États de piste — identiques au v8 (symbologie Arcade côté carte)
# ----------------------------------------------------------------------
TENTATIVE, CONFIRMED, SOLID, COASTING = "Faible", "Confirmee", "Solide", "Coasting"


@dataclass
class Profile:
    """Réglages d'un profil v9. Les quatre `*_enabled` servent à mesurer l'apport de chaque brique."""
    name: str = "defaut"
    # --- briques activables (brief §7 : une étape, une mesure) ---
    cluster_enabled: bool = True
    doppler_enabled: bool = True          # False : mesure [x, y] seule, comme le v8
    observability_enabled: bool = True    # False : tout dwell sans plot compte comme un miss
    merge_enabled: bool = True
    # --- clustering cible étendue ---
    cluster_eps_xy_m: float = 350.0       # liaison spatiale (≥ longueur du navire + bruit travers)
    cluster_eps_vr_mps: float = 3.0       # tolérance Doppler intra-cluster
    # ÉTENDUE DE CIBLE. Une coque de 250 m n'est pas un point : ses échos apparaissent à 100-300 m les uns
    # des autres, souvent dans des dwells différents. Sans étendue, chaque extrémité finit par porter sa
    # propre piste et aucune fusion a posteriori ne rattrape proprement le désordre. Une piste confirmée
    # absorbe donc les mesures orphelines tombant dans son étendue, et interdit une naissance à l'intérieur.
    target_extent_m: float = 0.0          # 0 = désactivé (cible ponctuelle)
    extent_from_cluster: bool = True      # l'étalement mesuré des clusters élargit l'étendue de la piste
    extent_max_m: float = 1000.0          # garde-fou : une étendue déduite ne dépasse pas cette valeur
    extent_blocks_tentative: bool = False # une piste encore tentative interdit-elle une naissance chez elle ?
    # --- bruit de mesure par défaut (si D32.12/13/15 absents ou sentinelles) ---
    sigma_range_m: float = 15.0
    sigma_cross_m: float = 120.0
    sigma_vr_mps: float = 1.5
    sigma_vr_floor_mps: float = 0.0       # plancher sur σ_v_LOS, quoi qu'annonce le flux (cf. ci-dessous)
    sigma_min_m: float = 5.0              # bornes de garde sur les sigmas venus du flux
    sigma_max_m: float = 500.0
    # --- dynamique ---
    q_accel_mps2: float = 0.05
    v_init_cross_std_mps: float = 8.0
    # --- gating / association ---
    gate_chi2: float = 11.34              # 99 % à 3 ddl (x, y, v_LOS) ; 9,21 à 2 ddl sans Doppler
    gate_chi2_pos: float = 9.21
    gate_max_m: float = 400.0
    # --- zone aveugle Doppler ---
    mdv_margin_mps: float = 1.0
    mdv_floor_mps: float = 0.0            # plancher si le flux annonce MDV = 0 (cas de la capture cargo)
    # --- gestion de piste ---
    confirm_m: int = 3
    confirm_n: int = 5
    solid_hits: int = 10                  # seuil « Solide » (v8)
    coast_after_sec: float = 10.0
    miss_delete_n: int = 6
    delete_sec: float = 240.0
    tentative_delete_sec: float = 20.0
    # --- fusion piste-à-piste ---
    # Deux critères, l'un OU l'autre, tenus pendant `merge_k` dwells :
    #  - statistique : distance de Mahalanobis sur la position (pistes que le filtre ne distingue plus) ;
    #  - CO-MOBILITÉ (héritage de l'absorption v8) : deux pistes proches en mètres, de même vitesse et de
    #    même cap. Indispensable sur cible étendue : la proue et la poupe d'un cargo de 250 m sont deux
    #    pistes distantes de 200 m avec des covariances de 20 m — jamais fusionnées par le seul Mahalanobis.
    merge_chi2: float = 9.21
    merge_dv_mps: float = 4.0
    merge_k: int = 2
    merge_max_dist_m: float = 0.0         # 0 = critère de co-mobilité désactivé
    merge_hdg_deg: float = 30.0
    merge_slow_mps: float = 3.0           # sous cette vitesse le cap n'est pas significatif
    # --- étage « contact » (affichage) : regroupement des pistes d'une même cible ---
    contact_dist_m: float = 0.0           # 0 = étage désactivé
    contact_dv_mps: float = 2.0
    contact_hdg_deg: float = 30.0
    contact_slow_mps: float = 3.0
    contact_memory_sec: float = 0.0       # un contact absent quelques dwells garde son identité
    # --- héritage v8 : flags niveau piste ---
    air_speed_mps: float = 42.0
    air_vlos_mps: float = 50.0
    air_confirm: int = 3
    air_q_accel: float = 4.0
    air_gate_max_m: float = 800.0
    air_min_ground: float = 15.0
    rot_max_ground: float = 3.0
    # --- divers ---
    sign_vlos: float = 1.0
    min_snr_db: float = 0.0               # déclutter (comme minSnrDb v8) ; 0 = inactif
    class_filter: tuple = ()              # classifications conservées ; vide = toutes


# ----------------------------------------------------------------------
# Entrées
# ----------------------------------------------------------------------
@dataclass
class Plot:
    """Un target report 4607 (D32.x), unités SI, sentinelles déjà remplacées par None."""
    lat: float
    lon: float
    x: float = 0.0
    y: float = 0.0
    vr: Optional[float] = None
    snr_db: Optional[float] = None
    classification: Optional[int] = None
    sigma_range_m: Optional[float] = None
    sigma_cross_m: Optional[float] = None
    sigma_vr_mps: Optional[float] = None


@dataclass
class Dwell:
    """Un dwell 4607 (D24.x) et ses plots. Les champs d'empreinte peuvent être None (CSV ancien) :
    l'observabilité est alors supposée vraie, ce qui ramène le comportement à celui du v8."""
    t: float
    sensor_lat: float
    sensor_lon: float
    sensor_alt_m: float = 0.0
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    half_range_m: Optional[float] = None
    half_angle_deg: Optional[float] = None
    mdv_mps: Optional[float] = None
    job_id: Optional[int] = None
    plots: list = field(default_factory=list)


@dataclass
class Meas:
    """Mesure présentée au filtre : un cluster de plots (souvent un seul)."""
    z: np.ndarray                  # [x, y, vr]
    R: np.ndarray                  # 3x3
    n_plots: int
    snr_db: Optional[float]
    classification: Optional[int]
    has_vr: bool
    spread_m: float = 0.0          # étalement du cluster : rayon max des membres autour du centroïde


class LocalFrame:
    """Repère local plan, identique au v8 (mêmes coordonnées affichées, même `to_ll`)."""

    def __init__(self, lat0, lon0):
        self.lat0, self.lon0 = lat0, lon0
        self.kx = 111320.0 * math.cos(math.radians(lat0))
        self.ky = 110540.0

    def to_xy(self, lat, lon):
        return (lon - self.lon0) * self.kx, (lat - self.lat0) * self.ky

    def to_ll(self, x, y):
        return self.lat0 + y / self.ky, self.lon0 + x / self.kx


# ----------------------------------------------------------------------
# Géométrie ligne de vue et modèle de mesure
# ----------------------------------------------------------------------
def los_geometry(sx, sy, sz, px, py, pz=0.0):
    """dx, dy (capteur→cible au sol), rho (distance sol), r (distance oblique)."""
    dx, dy, dz = px - sx, py - sy, pz - sz
    rho = math.hypot(dx, dy)
    r = math.sqrt(rho * rho + dz * dz)
    return dx, dy, max(rho, 1.0), max(r, 1.0)


def h_meas(x, sx, sy, sz, sign=1.0):
    """z = [px, py, v_LOS]. v_LOS = projection de la vitesse SOL sur la ligne de vue OBLIQUE :
    le facteur rho/r (implicite dans la division par r) tient compte de la dépression du capteur."""
    px, py, vx, vy = x
    dx, dy, _rho, r = los_geometry(sx, sy, sz, px, py)
    return np.array([px, py, sign * (dx * vx + dy * vy) / r])


def h_jac(x, sx, sy, sz, sign=1.0):
    px, py, vx, vy = x
    dx, dy, _rho, r = los_geometry(sx, sy, sz, px, py)
    dot = dx * vx + dy * vy
    H = np.zeros((3, 4))
    H[0, 0] = H[1, 1] = 1.0
    H[2, 0] = sign * (vx / r - dot * dx / r ** 3)
    H[2, 1] = sign * (vy / r - dot * dy / r ** 3)
    H[2, 2] = sign * dx / r
    H[2, 3] = sign * dy / r
    return H


def meas_cov(dx, dy, rho, sig_r, sig_c, sig_vr):
    """Covariance de mesure ANISOTROPE orientée ligne de vue.

    Le radar ne se trompe pas de la même façon en distance et en travers : sur la capture cargo,
    σ_distance ≈ 101 m et σ_travers ≈ 42 à 93 m (D32.12/13, présents à 100 %). Une covariance isotrope
    ouvrirait la porte trop grand dans l'axe précis et trop peu dans l'autre."""
    u = np.array([dx, dy]) / rho
    n = np.array([-dy, dx]) / rho
    R = np.zeros((3, 3))
    R[:2, :2] = sig_r ** 2 * np.outer(u, u) + sig_c ** 2 * np.outer(n, n)
    R[2, 2] = sig_vr ** 2
    return R


# ----------------------------------------------------------------------
# Étape 1 — clustering « cible étendue »
# ----------------------------------------------------------------------
def _single_link(xy, vr, eps_xy, eps_vr):
    """Regroupement single-link : deux plots sont liés si distance ≤ eps_xy ET |Δv_LOS| ≤ eps_vr
    (Doppler absent = critère ignoré). O(n²) par dwell, quelques dizaines de plots au plus."""
    n = len(xy)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        d = np.linalg.norm(xy[i + 1:] - xy[i], axis=1)
        if vr is None:
            close = d <= eps_xy
        else:
            dv = np.abs(vr[i + 1:] - vr[i])
            close = (d <= eps_xy) & (np.isnan(dv) | (dv <= eps_vr))
        for k in np.where(close)[0]:
            j = i + 1 + int(k)
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[rj] = ri
    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def cluster_dwell(dwell: Dwell, prof: Profile, sx, sy, sz) -> list:
    """Plots d'un dwell → mesures. Un cluster devient UNE mesure dont la covariance intègre
    l'étalement des membres : la cible étendue est une mesure plus incertaine, pas plusieurs mesures."""
    plots = dwell.plots
    if not plots:
        return []
    xy = np.array([[p.x, p.y] for p in plots], dtype=float)
    vr_arr = np.array([np.nan if p.vr is None else p.vr for p in plots], dtype=float)

    if prof.cluster_enabled and len(plots) > 1:
        groups = _single_link(xy, vr_arr, prof.cluster_eps_xy_m, prof.cluster_eps_vr_mps)
    else:
        groups = [[i] for i in range(len(plots))]

    def clamp(v, dflt):
        if v is None:
            return dflt
        return min(max(v, prof.sigma_min_m), prof.sigma_max_m)

    out = []
    for g in groups:
        members = [plots[i] for i in g]
        w = np.array([10 ** (m.snr_db / 10.0) if m.snr_db is not None else 1.0 for m in members])
        w = np.clip(w, 1e-3, None)
        w /= w.sum()
        cx, cy = (w[:, None] * xy[g]).sum(axis=0)
        vrs = [m.vr for m in members if m.vr is not None]
        has_vr = bool(vrs) and prof.doppler_enabled
        cvr = float(np.average([m.vr for m in members if m.vr is not None],
                               weights=[wi for wi, m in zip(w, members) if m.vr is not None])) if vrs else 0.0

        dx, dy, rho, _r = los_geometry(sx, sy, sz, cx, cy)
        sig_r = float(np.mean([clamp(m.sigma_range_m, prof.sigma_range_m) for m in members]))
        sig_c = float(np.mean([clamp(m.sigma_cross_m, prof.sigma_cross_m) for m in members]))
        # Plancher sur σ_v_LOS. Le flux annonce 0,23 à 0,51 m/s sur la capture maritime, mais deux échos
        # SIMULTANÉS de la même coque y diffèrent de 2,9 m/s (à moins de 150 m) à 10,5 m/s (150-300 m) :
        # le Doppler mesure l'agitation des diffuseurs, pas la translation du navire. Le prendre au mot
        # ferait diverger le filtre — d'où un plancher réglable par profil.
        sig_vr = float(np.mean([m.sigma_vr_mps if m.sigma_vr_mps is not None else prof.sigma_vr_mps
                                for m in members]))
        sig_vr = max(sig_vr, prof.sigma_vr_floor_mps)
        R = meas_cov(dx, dy, rho, sig_r, sig_c, sig_vr)

        if len(g) > 1:                                    # étalement de la cible étendue → incertitude
            d = xy[g] - np.array([cx, cy])
            R[:2, :2] += (w[:, None, None] * np.einsum("ni,nj->nij", d, d)).sum(axis=0)
            if vrs:
                R[2, 2] += float(np.mean([(v - cvr) ** 2 for v in vrs]))

        snr = max((m.snr_db for m in members if m.snr_db is not None), default=None)
        classes = [m.classification for m in members if m.classification is not None]
        cls = max(set(classes), key=classes.count) if classes else None
        spread = float(max((math.hypot(m.x - cx, m.y - cy) for m in members), default=0.0))
        out.append(Meas(np.array([cx, cy, cvr]), R, len(g), snr, cls, has_vr, spread))
    return out


def merge_meas(ms):
    """Agrège plusieurs mesures d'une même cible étendue en une seule (centroïde pondéré par le SNR).
    L'écart entre les membres entre dans la covariance : une coque de 250 m est UNE mesure imprécise."""
    if len(ms) == 1:
        return ms[0]
    w = np.array([10 ** (m.snr_db / 10.0) if m.snr_db is not None else 1.0 for m in ms])
    w = np.clip(w, 1e-3, None)
    w /= w.sum()
    z = np.zeros(3)
    z[:2] = sum(wi * m.z[:2] for wi, m in zip(w, ms))
    vr_ok = [(wi, m) for wi, m in zip(w, ms) if m.has_vr]
    z[2] = sum(wi * m.z[2] for wi, m in vr_ok) / sum(wi for wi, _ in vr_ok) if vr_ok else 0.0
    R = sum(wi * m.R for wi, m in zip(w, ms))
    d = np.array([m.z[:2] - z[:2] for m in ms])
    R[:2, :2] += (w[:, None, None] * np.einsum("ni,nj->nij", d, d)).sum(axis=0)
    spread = float(max(math.hypot(*(m.z[:2] - z[:2])) + m.spread_m for m in ms))
    snr = max((m.snr_db for m in ms if m.snr_db is not None), default=None)
    cls = next((m.classification for m in ms if m.classification is not None), None)
    return Meas(z, R, sum(m.n_plots for m in ms), snr, cls, bool(vr_ok), spread)


# ----------------------------------------------------------------------
# Pistes
# ----------------------------------------------------------------------
class Track:
    _ids = itertools.count(1)

    def __init__(self, m: Meas, t: float, prof: Profile, sx, sy, sz, job_id=None):
        self.id = next(Track._ids)
        self.prof = prof
        cx, cy, cvr = m.z
        dx, dy, rho, r = los_geometry(sx, sy, sz, cx, cy)
        u = np.array([dx, dy]) / rho
        n = np.array([-dy, dx]) / rho
        # Naissance : la composante de vitesse le long de la ligne de vue est DONNÉE par le Doppler
        # (facteur r/rho pour remonter de la vitesse oblique à la vitesse sol) ; la composante en
        # travers est inconnue, on l'annonce nulle avec une grande incertitude.
        v_along = prof.sign_vlos * cvr * r / rho if m.has_vr else 0.0
        self.x = np.array([cx, cy, v_along * u[0], v_along * u[1]])
        P = np.zeros((4, 4))
        P[:2, :2] = m.R[:2, :2]
        sig_along = math.sqrt(m.R[2, 2]) * r / rho if m.has_vr else prof.v_init_cross_std_mps
        P[2:, 2:] = sig_along ** 2 * np.outer(u, u) + prof.v_init_cross_std_mps ** 2 * np.outer(n, n)
        self.P = P
        self.t = t
        self.t_last_update = t
        self.hits = 1
        self.n_plots_last = m.n_plots
        self.window = [1]
        self.consecutive_obs_misses = 0
        self.state = TENTATIVE
        self.confirmed_ever = False
        self.classification = m.classification
        self.job_ids = {job_id} if job_id is not None else set()
        self.merge_counter = {}
        self.merged_from = []
        self.extent = float(prof.target_extent_m)
        if prof.extent_from_cluster and m.spread_m > 0:
            self.extent = min(max(self.extent, 2.0 * m.spread_m), prof.extent_max_m)
        self.absorbed_into = None
        self.q_accel = prof.q_accel_mps2
        self.gate_max = prof.gate_max_m
        self.is_air = False
        self.is_rotator = False
        self.air_evidence = 0
        self.rot_evidence = 0
        self.states = [(t, self.x.copy(), self.P.copy())]      # pour le lisseur RTS
        self.history = [(t, float(self.x[0]), float(self.x[1]), self.state, True)]
        self.last_hit_idx = 0

    # ---------------------------------------------------------------- filtre
    def predict(self, t):
        dt = t - self.t
        if dt <= 0:                                   # plusieurs dwells au même horodatage : rien à prédire
            return
        F = np.eye(4)
        F[0, 2] = F[1, 3] = dt
        q = self.q_accel ** 2
        dt2, dt3, dt4 = dt * dt, dt ** 3, dt ** 4
        Q = q * np.array([[dt4 / 4, 0, dt3 / 2, 0],
                          [0, dt4 / 4, 0, dt3 / 2],
                          [dt3 / 2, 0, dt2, 0],
                          [0, dt3 / 2, 0, dt2]])
        self.x = F @ self.x
        self.P = F @ self.P @ F.T + Q
        self.t = t

    def update(self, m: Meas, sx, sy, sz):
        prof = self.prof
        use_vr = m.has_vr and prof.doppler_enabled
        if use_vr:
            H = h_jac(self.x, sx, sy, sz, prof.sign_vlos)
            y = m.z - h_meas(self.x, sx, sy, sz, prof.sign_vlos)
            R = m.R
        else:                                          # repli position seule (comportement v8)
            H = np.zeros((2, 4))
            H[0, 0] = H[1, 1] = 1.0
            y = m.z[:2] - self.x[:2]
            R = m.R[:2, :2]
        S = H @ self.P @ H.T + R
        K = self.P @ H.T @ np.linalg.inv(S)
        self.x = self.x + K @ y
        I_KH = np.eye(4) - K @ H
        self.P = I_KH @ self.P @ I_KH.T + K @ R @ K.T          # forme de Joseph (symétrie garantie)
        self.t_last_update = self.t
        self.hits += 1
        self.n_plots_last = m.n_plots
        self.window = (self.window + [1])[-prof.confirm_n:]
        self.consecutive_obs_misses = 0
        if prof.extent_from_cluster and m.spread_m > 0:
            self.extent = min(max(self.extent, 2.0 * m.spread_m), prof.extent_max_m)
        if m.classification is not None:
            self.classification = m.classification
        self._update_flags(m)

    def _update_flags(self, m: Meas):
        """Flags de piste hérités du v8 : candidat aérien et rotateur fixe (éolienne, artefact)."""
        prof = self.prof
        vr = float(m.z[2]) if m.has_vr else None
        fast_los = vr is not None and abs(vr) > prof.air_vlos_mps
        spd = self.speed()
        ev = spd > prof.air_speed_mps or (fast_los and spd > prof.air_min_ground)
        self.air_evidence = self.air_evidence + 1 if ev else max(0, self.air_evidence - 1)
        ev_rot = fast_los and spd < prof.rot_max_ground and self.hits >= 4
        self.rot_evidence = self.rot_evidence + 1 if ev_rot else max(0, self.rot_evidence - 1)
        if not self.is_rotator and self.rot_evidence >= prof.air_confirm:
            self.is_rotator = True
        if not self.is_air and self.air_evidence >= prof.air_confirm:
            self.is_air = True                          # verrou : la piste reste aérienne
            self.q_accel = prof.air_q_accel
            self.gate_max = prof.air_gate_max_m

    def miss(self):
        self.window = (self.window + [0])[-self.prof.confirm_n:]
        self.consecutive_obs_misses += 1

    # ---------------------------------------------------------------- sortie
    def speed(self):
        return float(math.hypot(self.x[2], self.x[3]))

    def heading_deg(self):
        return (math.degrees(math.atan2(self.x[2], self.x[3])) + 360.0) % 360.0

    def heading_std_deg(self):
        """Écart-type du cap propagé depuis la covariance de vitesse. Sous 0,5 m/s le cap n'a pas
        de sens : on renvoie 180° plutôt qu'une valeur qui semblerait précise."""
        vx, vy = self.x[2], self.x[3]
        sp = math.hypot(vx, vy)
        if sp < 0.5:
            return 180.0
        Pv = self.P[2:, 2:]
        var = (vy ** 2 * Pv[0, 0] + vx ** 2 * Pv[1, 1] - 2 * vx * vy * Pv[0, 1]) / sp ** 4
        return math.degrees(math.sqrt(max(var, 0.0)))

    def pos_std_m(self):
        return float(math.sqrt(max(np.linalg.eigvalsh(self.P[:2, :2]).max(), 0.0)))

    def trajectory(self):
        return list(self.history)


# ----------------------------------------------------------------------
# Observabilité — le cœur du problème d'identifiants qui sautent
# ----------------------------------------------------------------------
def track_in_dwell(tr: Track, dwell: Dwell, sx, sy, margin=1.1) -> bool:
    """La piste prédite tombe-t-elle dans le secteur balayé par ce dwell ?

    Sans cette question, un dwell d'un AUTRE job, pointé ailleurs, compte comme un miss pour toutes
    les pistes — elles meurent puis renaissent avec un nouvel identifiant. Empreinte inconnue (CSV
    ancien) → on suppose la piste observable, ce qui redonne le comportement v8."""
    if dwell.center_lat is None or dwell.half_range_m is None or dwell.half_angle_deg is None:
        return True
    cx, cy = dwell.center_xy
    rc = math.hypot(cx - sx, cy - sy)
    bc = math.atan2(cx - sx, cy - sy)
    rt = math.hypot(tr.x[0] - sx, tr.x[1] - sy)
    bt = math.atan2(tr.x[0] - sx, tr.x[1] - sy)
    db = (bt - bc + math.pi) % (2 * math.pi) - math.pi
    return (abs(rt - rc) <= dwell.half_range_m * margin
            and abs(db) <= math.radians(dwell.half_angle_deg) * margin)


def doppler_blind(tr: Track, dwell: Dwell, sx, sy, sz, prof: Profile) -> bool:
    """Zone aveugle : une cible dont la vitesse radiale prédite est sous la MDV n'est PAS détectable.
    Ne pas le savoir revient à punir une piste pour une trajectoire perpendiculaire au capteur."""
    mdv = max(dwell.mdv_mps or 0.0, prof.mdv_floor_mps)
    vr_pred = h_meas(tr.x, sx, sy, sz, prof.sign_vlos)[2]
    return abs(vr_pred) < mdv + prof.mdv_margin_mps


def assign(cost: np.ndarray):
    """Association globale un-pour-un (GNN). `cost` vaut inf hors porte."""
    if cost.size == 0:
        return []
    finite = np.isfinite(cost)
    if not finite.any():
        return []
    if linear_sum_assignment is not None:
        rows, cols = linear_sum_assignment(np.where(finite, cost, 1e9))
        return [(int(i), int(j)) for i, j in zip(rows, cols) if finite[i, j]]
    pairs, used_r, used_c = [], set(), set()
    for i, j in sorted(zip(*np.where(finite)), key=lambda ij: cost[ij]):
        if i in used_r or j in used_c:
            continue
        pairs.append((int(i), int(j)))
        used_r.add(i)
        used_c.add(j)
    return pairs


# ----------------------------------------------------------------------
# Tracker
# ----------------------------------------------------------------------
class Tracker:
    def __init__(self, prof: Profile, frame: LocalFrame):
        self.prof = prof
        self.frame = frame
        self.tracks = []
        self.archive = []
        self.n_clustered = 0        # plots absorbés dans un cluster (mesure de l'étape 1)
        self.n_obs_miss = 0
        self.n_unobservable = 0     # dwells sans plot où la piste n'était PAS observable (miss évités)
        self.n_merged = 0
        self.n_absorbed_meas = 0    # mesures agrégées à une piste étendue (échos de la même coque)
        self.n_births_blocked = 0   # naissances refusées dans l'étendue d'une piste

    # ---------------------------------------------------------------- dwell
    def step(self, dwell: Dwell):
        prof = self.prof
        sx, sy = self.frame.to_xy(dwell.sensor_lat, dwell.sensor_lon)
        sz = dwell.sensor_alt_m or 0.0
        if dwell.center_lat is not None:
            dwell.center_xy = self.frame.to_xy(dwell.center_lat, dwell.center_lon)

        meas = cluster_dwell(dwell, prof, sx, sy, sz)
        self.n_clustered += sum(m.n_plots - 1 for m in meas)

        for tr in self.tracks:
            tr.predict(dwell.t)

        # --- gating + coût (Mahalanobis, 3 ddl avec Doppler, 2 sinon) ---
        cost = np.full((len(self.tracks), len(meas)), np.inf)
        for i, tr in enumerate(self.tracks):
            use_vr = prof.doppler_enabled
            if use_vr:
                zhat = h_meas(tr.x, sx, sy, sz, prof.sign_vlos)
                H = h_jac(tr.x, sx, sy, sz, prof.sign_vlos)
            else:
                zhat = np.array([tr.x[0], tr.x[1], 0.0])
                H = np.zeros((2, 4))
                H[0, 0] = H[1, 1] = 1.0
            PHt = tr.P @ H.T
            gate_m = tr.gate_max
            for j, m in enumerate(meas):
                if math.hypot(m.z[0] - zhat[0], m.z[1] - zhat[1]) > gate_m:
                    continue
                if use_vr and m.has_vr:
                    y = m.z - zhat
                    S = H @ PHt + m.R
                    thr = prof.gate_chi2
                else:
                    y = m.z[:2] - tr.x[:2]
                    Hp = np.zeros((2, 4)); Hp[0, 0] = Hp[1, 1] = 1.0
                    S = Hp @ tr.P @ Hp.T + m.R[:2, :2]
                    thr = prof.gate_chi2_pos
                try:
                    d2 = float(y @ np.linalg.solve(S, y))
                except np.linalg.LinAlgError:
                    continue
                if d2 <= thr:
                    cost[i, j] = d2

        pairs = assign(cost)
        assigned_t = {i for i, _ in pairs}
        assigned_m = {j for _, j in pairs}
        for i, j in pairs:
            tr, m = self.tracks[i], meas[j]
            # Cible étendue : les mesures orphelines tombant dans l'étendue de la piste sont des échos
            # de la MÊME cible (autre partie de la coque). On les agrège au centroïde plutôt que de les
            # laisser fonder une piste concurrente — c'est la mécanique de l'« étendue » du v8.
            if tr.extent > 0:
                rad = tr.extent / 2.0
                extra = [k for k, mm in enumerate(meas)
                         if k not in assigned_m and math.hypot(mm.z[0] - tr.x[0], mm.z[1] - tr.x[1]) < rad]
                if extra:
                    m = merge_meas([m] + [meas[k] for k in extra])
                    assigned_m.update(extra)
                    self.n_absorbed_meas += len(extra)
            tr.update(m, sx, sy, sz)
            if dwell.job_id is not None:
                tr.job_ids.add(dwell.job_id)

        # --- miss : seulement si la piste était OBSERVABLE dans ce dwell ---
        for i, tr in enumerate(self.tracks):
            if i in assigned_t:
                continue
            if prof.observability_enabled:
                observable = track_in_dwell(tr, dwell, sx, sy) and not doppler_blind(tr, dwell, sx, sy, sz, prof)
            else:
                observable = True
            if observable:
                tr.miss()
                self.n_obs_miss += 1
            else:
                self.n_unobservable += 1

        # --- naissances (jamais dans l'étendue d'une piste vivante) ---
        for j, m in enumerate(meas):
            if j in assigned_m:
                continue
            inside = any(tr.extent > 0
                         and (prof.extent_blocks_tentative or tr.state != TENTATIVE)
                         and math.hypot(m.z[0] - tr.x[0], m.z[1] - tr.x[1]) < tr.extent / 2.0
                         for tr in self.tracks)
            if inside:
                self.n_births_blocked += 1
                continue
            self.tracks.append(Track(m, dwell.t, prof, sx, sy, sz, dwell.job_id))

        self._manage(dwell.t)
        for tr in self.tracks:
            hit = tr.t_last_update == dwell.t
            tr.states.append((dwell.t, tr.x.copy(), tr.P.copy()))
            tr.history.append((dwell.t, float(tr.x[0]), float(tr.x[1]), tr.state, hit))
            if hit:
                tr.last_hit_idx = len(tr.states) - 1

    # ---------------------------------------------------------------- gestion
    def _manage(self, t):
        prof = self.prof
        for tr in self.tracks:
            if tr.state == TENTATIVE and sum(tr.window) >= prof.confirm_m:
                tr.state = CONFIRMED
                tr.confirmed_ever = True
            if tr.state != TENTATIVE:
                if (t - tr.t_last_update) > prof.coast_after_sec:
                    tr.state = COASTING
                else:
                    tr.state = SOLID if tr.hits >= prof.solid_hits else CONFIRMED

        to_drop = set()
        if prof.merge_enabled:
            alive = [tr for tr in self.tracks if tr.state != TENTATIVE]
            for a in range(len(alive)):
                for b in range(a + 1, len(alive)):
                    ta, tb = alive[a], alive[b]
                    if ta.id in to_drop or tb.id in to_drop:
                        continue
                    dp = ta.x[:2] - tb.x[:2]
                    try:
                        d2 = float(dp @ np.linalg.solve(ta.P[:2, :2] + tb.P[:2, :2], dp))
                    except np.linalg.LinAlgError:
                        continue
                    dv = float(np.linalg.norm(ta.x[2:] - tb.x[2:]))
                    older, younger = (ta, tb) if ta.id < tb.id else (tb, ta)
                    dist = float(math.hypot(dp[0], dp[1]))
                    co_mobile = False
                    if prof.merge_max_dist_m > 0 and dist <= prof.merge_max_dist_m and dv <= prof.merge_dv_mps:
                        sa, sb = ta.speed(), tb.speed()
                        if sa >= prof.merge_slow_mps and sb >= prof.merge_slow_mps:
                            dh = abs((ta.heading_deg() - tb.heading_deg() + 180) % 360 - 180)
                            co_mobile = dh <= prof.merge_hdg_deg
                        else:
                            co_mobile = True                 # trop lentes pour que le cap ait un sens
                    if (d2 <= prof.merge_chi2 and dv <= prof.merge_dv_mps) or co_mobile:
                        k = older.merge_counter.get(younger.id, 0) + 1
                        older.merge_counter[younger.id] = k
                        if k >= prof.merge_k:            # deux dwells de confirmation : pas sur un hasard
                            older.hits += younger.hits
                            older.merged_from.append(younger.id)
                            older.job_ids |= younger.job_ids
                            younger.absorbed_into = older.id
                            # La mère hérite d'une étendue couvrant les deux : sans cela, les mesures de
                            # la piste absorbée referaient naître une piste au dwell suivant.
                            older.extent = max(older.extent, younger.extent, 2.0 * dist)
                            to_drop.add(younger.id)
                            self.n_merged += 1
                    else:
                        older.merge_counter.pop(younger.id, None)

        keep = []
        for tr in self.tracks:
            age = t - tr.t_last_update
            dead = (tr.id in to_drop
                    or tr.consecutive_obs_misses >= prof.miss_delete_n
                    or (tr.state == TENTATIVE and age > prof.tentative_delete_sec)
                    or (tr.state != TENTATIVE and age > prof.delete_sec))
            (self.archive if dead else keep).append(tr)
        self.tracks = keep

    # ---------------------------------------------------------------- instantané
    def snapshot(self, t):
        out = []
        for tr in self.tracks:
            lat, lon = self.frame.to_ll(tr.x[0], tr.x[1])
            out.append({"track_id": tr.id, "t": t, "lat": lat, "lon": lon,
                        "speed_mps": tr.speed(), "speed_kmh": tr.speed() * 3.6,
                        "heading_deg": tr.heading_deg(), "heading_std_deg": tr.heading_std_deg(),
                        "pos_std_m": tr.pos_std_m(), "state": tr.state, "hits": tr.hits,
                        "n_plots_last": tr.n_plots_last, "age_since_update_s": t - tr.t_last_update,
                        "classification": tr.classification, "is_air": tr.is_air,
                        "is_rotator": tr.is_rotator, "merged_from": list(tr.merged_from),
                        "jobs": sorted(j for j in tr.job_ids if j is not None)})
        return out


# ----------------------------------------------------------------------
# Lisseur RTS — repris du v8 (produit trajet / débriefing, non causal)
# ----------------------------------------------------------------------
def rts_smooth(track: Track):
    """Passe arrière Rauch-Tung-Striebel, tronquée à la dernière détection réelle."""
    return _rts_states(track.states[:track.last_hit_idx + 1], track.q_accel)


def _rts_states(st, q_accel):
    n = len(st)
    if n < 3:
        return [(t, float(x[0]), float(x[1])) for t, x, _ in st]
    xs = [x.copy() for _, x, _ in st]
    Ps = [P.copy() for _, _, P in st]
    ts = [t for t, _, _ in st]
    x_s, P_s = xs[-1], Ps[-1]
    out = [(ts[-1], float(x_s[0]), float(x_s[1]))]
    q = q_accel ** 2
    for k in range(n - 2, -1, -1):
        dt = max(ts[k + 1] - ts[k], 1e-3)
        F = np.array([[1, 0, dt, 0], [0, 1, 0, dt], [0, 0, 1, 0], [0, 0, 0, 1]])
        G = np.array([[dt ** 2 / 2, 0], [0, dt ** 2 / 2], [dt, 0], [0, dt]])
        Q = G @ (q * np.eye(2)) @ G.T
        x_pred = F @ xs[k]
        P_pred = F @ Ps[k] @ F.T + Q
        try:
            C = Ps[k] @ F.T @ np.linalg.inv(P_pred)
        except np.linalg.LinAlgError:
            break
        x_s = xs[k] + C @ (x_s - x_pred)
        P_s = Ps[k] + C @ (P_s - P_pred) @ C.T
        out.append((ts[k], float(x_s[0]), float(x_s[1])))
    return out[::-1]


def profile_with(prof: Profile, **kw) -> Profile:
    """Copie d'un profil avec quelques réglages changés (activation des briques, tuning)."""
    return replace(prof, **kw)
