# -*- coding: utf-8 -*-
"""
Prototype tracker GMTI (plots MTI STANAG 4607 -> pistes correlees a ID unique)
Boucle : prediction Kalman CV -> gating Mahalanobis -> association GNN -> M-sur-N

Entree : plots groupes par dwell (voir csv_reader.py pour le format CSV GeoEvent)
Sortie : historique des pistes (track_id persistant, etats, trajets)

Portage processor GeoEvent : la classe Tracker est volontairement autonome
(pas d'I/O, pas de matplotlib) — c'est elle qu'on transpose en Java.
"""
import itertools
import math
import numpy as np
from scipy.optimize import linear_sum_assignment

# ----------------------------------------------------------------------
# Parametres a tuner (les valeurs par defaut sont des points de depart)
# ----------------------------------------------------------------------
class Params:
    GATE_CHI2       = 9.21    # khi2 99 %, 2 ddl : seuil de gating Mahalanobis
    Q_ACCEL         = 1.0     # bruit de process (m/s^2) : agilite supposee des cibles
    R_POS_DEFAULT   = 40.0    # ecart-type position par defaut (m) si incertitudes absentes
    CONFIRM_M       = 3       # piste confirmee si M associations...
    CONFIRM_N       = 5       # ...sur les N dernieres revisites
    DELETE_MISSES   = 4       # revisites consecutives sans association -> suppression
    SOLID_HITS      = 10      # seuil "Solide" (aligne sur votre expression Arcade)
    MIN_SPEED_INIT  = 0.0     # m/s : filtre optionnel des plots quasi statiques a l'init


# ----------------------------------------------------------------------
# Etats de piste (alignes sur vos classes de symbologie)
# ----------------------------------------------------------------------
TENTATIVE, CONFIRMED, SOLID, COASTING, DEAD = (
    "Faible", "Confirmee", "Solide", "Coasting", "Supprimee")


class Track:
    _ids = itertools.count(1)

    def __init__(self, plot, t):
        self.id = next(Track._ids)          # ID unique persistant
        self.x = np.array([plot.x, plot.y, 0.0, 0.0])   # [x, y, vx, vy]
        self.P = np.diag([plot.r_pos**2, plot.r_pos**2, 15.0**2, 15.0**2])
        self.t = t
        self.hits = 1
        self.misses = 0
        self.window = [1]                   # fenetre M-sur-N (1=hit, 0=miss)
        self.confirmed_ever = False         # a atteint l'etat Confirmee au moins une fois
        self.history = [(t, plot.x, plot.y, TENTATIVE)]

    # --- Modele vitesse constante ---
    def predict(self, t):
        dt = max(t - self.t, 1e-3)
        F = np.array([[1, 0, dt, 0], [0, 1, 0, dt], [0, 0, 1, 0], [0, 0, 0, 1]])
        q = Params.Q_ACCEL**2
        G = np.array([[dt**2 / 2, 0], [0, dt**2 / 2], [dt, 0], [0, dt]])
        Q = G @ (q * np.eye(2)) @ G.T
        self.x = F @ self.x
        self.P = F @ self.P @ F.T + Q
        self.t = t

    def innovation(self, plot):
        """Retourne (d2 Mahalanobis, y, S) entre le plot et la prediction."""
        H = np.array([[1, 0, 0, 0], [0, 1, 0, 0]])
        y = np.array([plot.x, plot.y]) - H @ self.x
        S = H @ self.P @ H.T + plot.R
        d2 = float(y @ np.linalg.solve(S, y))
        return d2, y, S

    def update(self, plot):
        H = np.array([[1, 0, 0, 0], [0, 1, 0, 0]])
        y = np.array([plot.x, plot.y]) - H @ self.x
        S = H @ self.P @ H.T + plot.R
        K = self.P @ H.T @ np.linalg.inv(S)
        self.x = self.x + K @ y
        self.P = (np.eye(4) - K @ H) @ self.P
        self.hits += 1
        self.misses = 0
        self.window = (self.window + [1])[-Params.CONFIRM_N:]

    def miss(self):
        self.misses += 1
        self.window = (self.window + [0])[-Params.CONFIRM_N:]

    @property
    def state(self):
        if self.misses >= Params.DELETE_MISSES:
            return DEAD
        if self.misses > 0:
            return COASTING
        if self.hits >= Params.SOLID_HITS:
            return SOLID
        if sum(self.window) >= Params.CONFIRM_M:
            return CONFIRMED
        return TENTATIVE

    def log(self):
        st = self.state
        if st in (CONFIRMED, SOLID):
            self.confirmed_ever = True
        self.history.append((self.t, self.x[0], self.x[1], st))

    def speed(self):
        return math.hypot(self.x[2], self.x[3])


class Plot:
    """Plot MTI en coordonnees locales metriques (ENU) avec covariance mesure."""
    def __init__(self, x, y, r_pos=Params.R_POS_DEFAULT, R=None,
                 vel_los=None, snr=None, classification=None):
        self.x, self.y = x, y
        self.r_pos = r_pos
        self.R = R if R is not None else np.eye(2) * r_pos**2
        self.vel_los = vel_los
        self.snr = snr
        self.classification = classification


class Tracker:
    def __init__(self):
        self.tracks = []      # pistes vivantes
        self.archive = []     # pistes mortes (pour analyse / trajets)

    def step(self, t, plots):
        """Traite un dwell/une revisite complete : tous les plots d'un coup."""
        for tr in self.tracks:
            tr.predict(t)

        # --- Matrice de couts pistes x plots avec gating ---
        n_t, n_p = len(self.tracks), len(plots)
        BIG = 1e9
        cost = np.full((n_t, n_p), BIG)
        for i, tr in enumerate(self.tracks):
            for j, pl in enumerate(plots):
                d2, _, S = tr.innovation(pl)
                if d2 < Params.GATE_CHI2:
                    # cout = -log vraisemblance (distance + volume d'incertitude)
                    cost[i, j] = d2 + math.log(np.linalg.det(S))

        # --- Affectation globale (GNN / hongrois) ---
        assigned_t, assigned_p = set(), set()
        if n_t and n_p:
            rows, cols = linear_sum_assignment(cost)
            for i, j in zip(rows, cols):
                if cost[i, j] < BIG:
                    self.tracks[i].update(plots[j])
                    assigned_t.add(i)
                    assigned_p.add(j)

        # --- Pistes non servies -> miss ---
        for i, tr in enumerate(self.tracks):
            if i not in assigned_t:
                tr.miss()

        # --- Plots orphelins -> nouvelles pistes tentatives ---
        for j, pl in enumerate(plots):
            if j not in assigned_p:
                self.tracks.append(Track(pl, t))

        # --- Journalisation + menage ---
        for tr in self.tracks:
            tr.log()
        dead = [tr for tr in self.tracks if tr.state == DEAD]
        self.archive.extend(dead)
        self.tracks = [tr for tr in self.tracks if tr.state != DEAD]

    def confirmed_tracks(self):
        return [tr for tr in self.tracks if tr.state in (CONFIRMED, SOLID)]


# ----------------------------------------------------------------------
# Geodesie minimale : lat/lon <-> plan local ENU (equirectangulaire)
# Suffisant pour des zones de travail de quelques dizaines de km.
# ----------------------------------------------------------------------
class LocalFrame:
    def __init__(self, lat0, lon0):
        self.lat0, self.lon0 = lat0, lon0
        self.kx = 111320.0 * math.cos(math.radians(lat0))
        self.ky = 110540.0

    def to_xy(self, lat, lon):
        return (lon - self.lon0) * self.kx, (lat - self.lat0) * self.ky

    def to_ll(self, x, y):
        return self.lat0 + y / self.ky, self.lon0 + x / self.kx


def covariance_from_4607(sensor_xy, plot_xy, sig_range_m, sig_xrange_m):
    """Covariance 2D du plot a partir des incertitudes slant/cross range 4607,
    orientee selon l'axe capteur -> cible."""
    dx, dy = plot_xy[0] - sensor_xy[0], plot_xy[1] - sensor_xy[1]
    a = math.atan2(dy, dx)
    c, s = math.cos(a), math.sin(a)
    Rrot = np.array([[c, -s], [s, c]])
    D = np.diag([sig_range_m**2, sig_xrange_m**2])
    return Rrot @ D @ Rrot.T
