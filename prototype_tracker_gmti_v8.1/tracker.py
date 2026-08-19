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
try:
    from scipy.optimize import linear_sum_assignment
except ImportError:                                  # scipy absent (serveur video AlmaLinux) : repli pur Python
    linear_sum_assignment = None


def _hungarian(cost):
    """Affectation optimale a cout minimal quand scipy manque : la matrice (tres creuse : le
    gating met BIG presque partout) est decoupee en composantes connexes pistes/plots reliees
    par un cout fini, chacune resolue par le hongrois dense (_hungarian_dense, port du Java).
    Meme cout total que scipy ; renvoie (rows, cols) des paires retenues (cout < 1e9)."""
    BIG = 1e9
    n_rows, n_cols = cost.shape
    if n_rows == 0 or n_cols == 0:
        return np.array([], dtype=int), np.array([], dtype=int)
    fin = cost < BIG
    parent = list(range(n_rows + n_cols))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    ri, cj = np.nonzero(fin)
    for i, j in zip(ri.tolist(), cj.tolist()):
        a, b = find(i), find(n_rows + j)
        if a != b:
            parent[max(a, b)] = min(a, b)
    comps = {}
    for i in set(ri.tolist()):
        comps.setdefault(find(i), [[], []])[0].append(i)
    for j in set(cj.tolist()):
        comps.setdefault(find(n_rows + j), [[], []])[1].append(j)
    rows, cols = [], []
    for rs, cs in comps.values():
        rs.sort(); cs.sort()
        sub = cost[np.ix_(rs, cs)]
        r, c = _hungarian_dense(sub)
        rows.extend(rs[k] for k in r); cols.extend(cs[k] for k in c)
    order = np.argsort(rows, kind="stable")
    return np.array(rows, dtype=int)[order], np.array(cols, dtype=int)[order]


def _hungarian_dense(cost):
    """Hongrois O(n^3) — port 1:1 de Hungarian.java (receiver GeoEvent), memes ex aequo."""
    BIG = 1e9
    n_rows, n_cols = cost.shape
    n = max(n_rows, n_cols)
    if n == 0:
        return np.array([], dtype=int), np.array([], dtype=int)
    a = np.full((n + 1, n + 1), BIG)
    a[1:n_rows + 1, 1:n_cols + 1] = cost
    INF = float("inf")
    u = np.zeros(n + 1); v = np.zeros(n + 1); p = np.zeros(n + 1, dtype=int); way = np.zeros(n + 1, dtype=int)
    idx = np.arange(n + 1)
    for i in range(1, n + 1):
        p[0] = i; j0 = 0
        minv = np.full(n + 1, INF); used = np.zeros(n + 1, dtype=bool)
        while True:
            used[j0] = True
            i0 = p[j0]
            free = ~used; free[0] = False
            cur = a[i0] - u[i0] - v                       # vectorise sur les colonnes libres
            better = free & (cur < minv)
            minv[better] = cur[better]; way[better] = j0
            cand = np.where(free, minv, INF)
            j1 = int(np.argmin(cand)); delta = cand[j1]   # premier minimum = meme choix que la boucle Java
            u[p[used]] += delta; v[used] -= delta
            minv[free] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]; p[j0] = p[j1]; j0 = j1
            if j0 == 0:
                break
    rows, cols = [], []
    for j in range(1, n + 1):
        i = p[j]
        if 1 <= i <= n_rows and j <= n_cols and cost[i - 1, j - 1] < BIG:
            rows.append(i - 1); cols.append(j - 1)
    order = np.argsort(rows, kind="stable")
    return np.array(rows, dtype=int)[order], np.array(cols, dtype=int)[order]

# ----------------------------------------------------------------------
# Parametres a tuner (les valeurs par defaut sont des points de depart)
# ----------------------------------------------------------------------
class Params:
    GATE_CHI2       = 9.21    # khi2 99 %, 2 ddl : seuil de gating Mahalanobis
    Q_ACCEL         = 3.0     # bruit de process (m/s^2) : agilite supposee des cibles (= accelStd Java)
    R_POS_DEFAULT   = 30.0    # ecart-type position par defaut (m) si incertitudes absentes (= measPosStd Java)
    CONFIRM_M       = 3       # piste confirmee si M associations...
    CONFIRM_N       = 5       # ...sur les N dernieres revisites
    DELETE_MISSES   = 8       # revisites consecutives sans association -> suppression (= deleteMisses Java)
    SOLID_HITS      = 10      # seuil "Solide" (aligne sur votre expression Arcade)
    GATE_MAX_M      = 300.0   # plafond du gate en metres (borne le gonflement en coasting) (= gateMaxM Java)
    GATE_GROW_MPS   = 0.0     # croissance du plafond de gate (m/s d'anciennete de MAJ)
    DELETE_SEC      = None    # suppression par ANCIENNETE de derniere MAJ (s) ;
                              # prioritaire sur DELETE_MISSES si defini (scan large zone
                              # ou la cadence des dwells != cadence d'observation d'une cible)
    CONFIRM_BY_HITS = False   # True : confirmation des que hits >= CONFIRM_M (sans fenetre)
                              # pour les scenes ou une cible n'est vue qu'a certains dwells
    # -- flag candidat aerien (niveau piste) --
    AIR_SPEED_MPS   = 42.0    # vitesse sol lissee soutenue (42 m/s = 150 km/h)
    AIR_VLOS_MPS    = 50.0    # |vitesse radiale| mesuree (borne inf. de la vitesse vraie)
    AIR_CONFIRM     = 3       # nb de preuves cumulees avant de poser le flag
    AIR_Q_ACCEL     = 4.0     # dynamique adoptee par la piste une fois flaggee
    AIR_GATE_MAX_M  = 800.0   # plafond de gate adopte une fois flaggee
    AIR_MIN_GROUND  = 15.0    # vitesse sol min pour que la preuve v_LOS compte (coherence)
    ROT_MAX_GROUND  = 3.0     # vitesse sol max du critere rotateur fixe (eoliennes, etc.)
    MIN_SPEED_INIT  = 0.0     # m/s : filtre optionnel des plots quasi statiques a l'init
    V_INIT_STD      = 20.0    # ecart-type vitesse a la naissance d'une piste (m/s) (= initVelStd Java)
    # -- absorption de pistes co-mobiles (cible etendue : proue/poupe d'un gros navire) --
    ABSORB_DWELLS   = 0       # nb de dwells consecutifs ou deux pistes affichables sont proches ET
                              # co-mobiles avant que la plus jeune soit ABSORBEE (0 = off) (= absorbDwells Java)
    ABSORB_DIST_M   = 400.0   # distance max entre les deux pistes (= absorbDistM Java)
    ABSORB_DV_MPS   = 2.0     # |delta vitesse sol| max (= absorbDvMps Java)
    ABSORB_HD_DEG   = 30.0    # |delta cap| max, teste seulement si les deux vont a >= ABSORB_SLOW_MPS (= absorbHeadingDeg Java)
    ABSORB_SLOW_MPS = 3.0     # en dessous, le cap n'est pas significatif (= absorbSlowMps Java)


# ----------------------------------------------------------------------
# Etats de piste (alignes sur vos classes de symbologie)
# ----------------------------------------------------------------------
TENTATIVE, CONFIRMED, SOLID, COASTING, DEAD = (
    "Faible", "Confirmee", "Solide", "Coasting", "Supprimee")

# Constantes reutilisees (evite de recreer ces matrices a chaque appel ;
# valeurs strictement identiques a np.array(...)/np.eye(...) — resultat inchange).
_H = np.array([[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]])   # observation position
_I2 = np.eye(2)
_I4 = np.eye(4)


class Track:
    _ids = itertools.count(1)

    def __init__(self, plot, t):
        self.id = next(Track._ids)          # ID unique persistant
        self.x = np.array([plot.x, plot.y, 0.0, 0.0])   # [x, y, vx, vy]
        self.P = np.diag([plot.r_pos**2, plot.r_pos**2, Params.V_INIT_STD**2, Params.V_INIT_STD**2])
        self.t = t
        self.t_last_update = t
        self.hits = 1
        self.misses = 0
        self.window = [1]                   # fenetre M-sur-N (1=hit, 0=miss)
        self.confirmed_ever = False         # a atteint l'etat Confirmee au moins une fois
        self.q_accel = Params.Q_ACCEL       # dynamique propre a la piste (bascule si aerien)
        self.gate_max = Params.GATE_MAX_M
        self.air_evidence = 0
        self.is_air = False                 # candidat aerien (vitesse incompatible routier)
        self.rot_evidence = 0
        self.is_rotator = False             # rotateur fixe : v_LOS forte MAIS immobile au sol
        self.history = [(t, plot.x, plot.y, TENTATIVE, True)]
        self.states = [(t, self.x.copy(), self.P.copy())]   # pour le lisseur RTS
        # Journal d'inspection (aucun effet sur le pistage) : plots associes et gates.
        self.assoc = [(t, plot.x, plot.y, 0.0, plot.vel_los, plot.snr, plot.classification)]
        # Classification fusionnee sur la duree de vie (vote majoritaire, comme Track.java) : la classe
        # d'un plot peut varier d'un dwell a l'autre ; la piste rapporte sa classe dominante.
        self.cls_counts = {}
        self._vote_class(plot.classification)
        self.gates = []                                     # (t, S 2x2 innovation, d2)
        self.last_hit_idx = 0
        self._hit = True
        # Cible etendue : apres absorption d'une piste co-mobile, la piste porte une ETENDUE (m)
        # qui gonfle la covariance de mesure et le gate metrique -> les echos des deux extremites
        # restent associes a la meme piste (qui converge vers le centre de la cible).
        self.extent = 0.0
        self.absorbed = []                  # ids des pistes absorbees
        self.dead_absorbed = False          # tuee par absorption
        self._pair = {}                     # id autre piste -> nb de dwells consecutifs co-mobiles

    # --- Modele vitesse constante ---
    def predict(self, t):
        dt = max(t - self.t, 1e-3)
        F = np.array([[1, 0, dt, 0], [0, 1, 0, dt], [0, 0, 1, 0], [0, 0, 0, 1]])
        q = self.q_accel**2
        G = np.array([[dt**2 / 2, 0], [0, dt**2 / 2], [dt, 0], [0, dt]])
        Q = G @ (q * _I2) @ G.T
        self.x = F @ self.x
        self.P = F @ self.P @ F.T + Q
        self.t = t

    def _R(self, plot):
        """Covariance de mesure effective : R du plot + etendue de la cible ((extent/2)^2 I)."""
        if self.extent > 0.0:
            e = (self.extent / 2.0) ** 2
            return plot.R + e * _I2
        return plot.R

    def innovation(self, plot):
        """Retourne (d2 Mahalanobis, y, S) entre le plot et la prediction."""
        H = _H
        y = np.array([plot.x, plot.y]) - H @ self.x
        S = H @ self.P @ H.T + self._R(plot)
        d2 = float(y @ np.linalg.solve(S, y))
        return d2, y, S

    def update(self, plot):
        H = _H
        y = np.array([plot.x, plot.y]) - H @ self.x
        S = H @ self.P @ H.T + self._R(plot)
        try:
            d2 = float(y @ np.linalg.solve(S, y))
        except np.linalg.LinAlgError:
            d2 = float("nan")
        self.assoc.append((self.t, plot.x, plot.y, d2, plot.vel_los, plot.snr, plot.classification))
        self._vote_class(plot.classification)
        self.gates.append((self.t, S.copy(), d2))
        K = self.P @ H.T @ np.linalg.inv(S)
        self.x = self.x + K @ y
        self.P = (_I4 - K @ H) @ self.P
        self.hits += 1
        self.misses = 0
        self.t_last_update = self.t
        self.window = (self.window + [1])[-Params.CONFIRM_N:]
        self._hit = True
        fast_los = plot.vel_los is not None and abs(plot.vel_los) > Params.AIR_VLOS_MPS
        spd = self.speed()
        # aerien : vitesse sol elevee, ou v_LOS forte COHERENTE avec un vrai deplacement
        ev = spd > Params.AIR_SPEED_MPS or (fast_los and spd > Params.AIR_MIN_GROUND)
        self.air_evidence = self.air_evidence + 1 if ev else max(0, self.air_evidence - 1)
        # rotateur fixe : v_LOS forte mais position immobile -> artefact Doppler persistant
        ev_rot = fast_los and spd < Params.ROT_MAX_GROUND and self.hits >= 4
        self.rot_evidence = self.rot_evidence + 1 if ev_rot else max(0, self.rot_evidence - 1)
        if not self.is_rotator and self.rot_evidence >= Params.AIR_CONFIRM:
            self.is_rotator = True
        if not self.is_air and self.air_evidence >= Params.AIR_CONFIRM:
            self.is_air = True                       # latch : la piste devient aerienne
            self.q_accel = Params.AIR_Q_ACCEL        # dynamique manoeuvrante
            self.gate_max = Params.AIR_GATE_MAX_M    # gate elargi

    def miss(self):
        self.misses += 1
        self.window = (self.window + [0])[-Params.CONFIRM_N:]
        self._hit = False

    @property
    def state(self):
        if self.dead_absorbed:
            return DEAD
        if Params.DELETE_SEC is not None:
            if self.t - self.t_last_update > Params.DELETE_SEC:
                return DEAD
        elif self.misses >= Params.DELETE_MISSES:
            return DEAD
        if self.misses > 0:
            return COASTING
        if self.hits >= Params.SOLID_HITS:
            return SOLID
        if Params.CONFIRM_BY_HITS:
            if self.hits >= Params.CONFIRM_M:
                return CONFIRMED
        elif sum(self.window) >= Params.CONFIRM_M:
            return CONFIRMED
        return TENTATIVE

    def log(self):
        st = self.state
        if st in (CONFIRMED, SOLID):
            self.confirmed_ever = True
        self.history.append((self.t, self.x[0], self.x[1], st, self._hit))
        self.states.append((self.t, self.x.copy(), self.P.copy()))
        if self._hit:
            self.last_hit_idx = len(self.history) - 1
        self._hit = False

    def trajectory(self):
        """Trajet exportable : tronque a la derniere detection reelle
        (supprime la queue de coasting purement predite)."""
        return self.history[:self.last_hit_idx + 1]

    def speed(self):
        return math.hypot(self.x[2], self.x[3])

    def _vote_class(self, cls):
        if cls in (None, ""):
            return
        try:
            c = int(float(cls))
        except (TypeError, ValueError):
            return
        self.cls_counts[c] = self.cls_counts.get(c, 0) + 1

    def dominant_class(self):
        """Classe STANAG 4607 (D32.11) majoritaire sur la vie de la piste ; None si aucune.
        Departage : la plus frequente, puis le code le plus bas (comme Track.java)."""
        if not self.cls_counts:
            return None
        return min(self.cls_counts, key=lambda c: (-self.cls_counts[c], c))


def merge_plots(g, weighted=True):
    """Fusionne un groupe de plots (>= 2) en UN plot : centroide pondere par l'amplitude
    (10^(SNR/20), poids egaux si SNR absent ou weighted=False), R = moyenne des R + dispersion des membres
    (covariance echantillon si > 2, sinon diag(max((dx/2)^2,1), max((dy/2)^2,1))), r_pos =
    max(r_pos, sqrt(tr(disp)/2)), v_LOS moyenne, SNR max, classe majoritaire ; attributs
    n_echoes / span_m. Utilise par le pre-clustering (track_run.cluster_plots) ET par la mise
    a jour d'une piste etendue (Tracker.step)."""
    xs = np.array([p.x for p in g]); ys = np.array([p.y for p in g])
    span = float(math.hypot(xs.max() - xs.min(), ys.max() - ys.min()))
    w = np.array([10.0 ** (float(p.snr) / 20.0) if (weighted and p.snr is not None) else 1.0 for p in g]); w = w / w.sum()
    cx, cy = float((xs * w).sum()), float((ys * w).sum())
    disp = np.cov(np.vstack([xs, ys])) if len(g) > 2 else np.array([[max((xs.max()-xs.min())**2/4, 1.0), 0.0], [0.0, max((ys.max()-ys.min())**2/4, 1.0)]])
    R = np.mean([p.R for p in g], axis=0) + disp
    r_pos = max(max(p.r_pos for p in g), math.sqrt(max(float(np.trace(disp)) / 2.0, 0.0)))
    vl = [p.vel_los for p in g if p.vel_los is not None]
    snrs = [p.snr for p in g if p.snr is not None]
    cls = [p.classification for p in g if p.classification not in (None, "")]
    cls_maj = max(set(cls), key=cls.count) if cls else None
    q = Plot(cx, cy, r_pos=r_pos, R=R, vel_los=(sum(vl) / len(vl)) if vl else None,
             snr=max(snrs) if snrs else None, classification=cls_maj)
    q.n_echoes, q.span_m = sum(getattr(p, "n_echoes", 1) or 1 for p in g), span
    return q


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
        self.n_swallowed = 0                # echos avales par une piste etendue (pas de nouvelle piste)
        self.tracks = []      # pistes vivantes
        self.archive = []     # pistes mortes (pour analyse / trajets)

    def step(self, t, plots):
        """Traite un dwell/une revisite complete : tous les plots d'un coup."""
        for tr in self.tracks:
            tr.predict(t)

        # --- Matrice de couts pistes x plots avec gating ---
        # Broad-phase spatial : les plots sont indexes sur une grille reguliere,
        # et l'innovation (2x2, couteuse) n'est evaluee QUE pour les couples dont
        # la distance predite est sous le gate. Sur un scan grande zone (gates
        # larges mais plots epars, cf. routier_zone), la quasi-totalite des
        # couples est hors gate : on evite ainsi ~99 % des solve/det. La matrice
        # de couts produite est STRICTEMENT identique a la version dense (les
        # couples hors gate valaient BIG) -> meme affectation, memes pistes.
        n_t, n_p = len(self.tracks), len(plots)
        BIG = 1e9
        cost = np.full((n_t, n_p), BIG)
        if n_t and n_p:
            # Cellule dimensionnee sur le gate MAX possible (gate_max + croissance
            # bornee par la duree de vie) : chaque piste n'interroge alors qu'un
            # voisinage 3x3 dans le cas courant (rad reste exact si depasse).
            grow_cap = Params.GATE_GROW_MPS * (Params.DELETE_SEC or 0.0)
            cell = max(50.0, Params.GATE_MAX_M + grow_cap)
            grid = {}
            for j, pl in enumerate(plots):
                grid.setdefault((int(pl.x // cell), int(pl.y // cell)), []).append(j)
            for i, tr in enumerate(self.tracks):
                gate_m = tr.gate_max + Params.GATE_GROW_MPS * (tr.t - tr.t_last_update) + tr.extent / 2.0
                px, py = tr.x[0], tr.x[1]
                cx, cy = int(px // cell), int(py // cell)
                rad = int(gate_m // cell) + 1
                for gx in range(cx - rad, cx + rad + 1):
                    for gy in range(cy - rad, cy + rad + 1):
                        for j in grid.get((gx, gy), ()):
                            pl = plots[j]
                            if math.hypot(pl.x - px, pl.y - py) >= gate_m:
                                continue
                            d2, _y, S = tr.innovation(pl)
                            if d2 < Params.GATE_CHI2:
                                # cout = -log vraisemblance (distance + incertitude)
                                cost[i, j] = d2 + math.log(np.linalg.det(S))

        # --- Affectation globale (GNN / hongrois) ---
        assigned_t, assigned_p = set(), set()
        pairs = []
        if n_t and n_p:
            rows, cols = linear_sum_assignment(cost) if linear_sum_assignment is not None else _hungarian(cost)
            for i, j in zip(rows, cols):
                if cost[i, j] < BIG:
                    pairs.append((i, j)); assigned_t.add(i); assigned_p.add(j)
        # Mise a jour ; une piste ETENDUE (apres absorption) prend en plus les plots orphelins
        # tombant dans son etendue (etendue/2 + incertitude du plot) et se met a jour avec leur
        # centroide : les echos des deux extremites de la coque tirent ensemble vers le centre.
        for i, j in pairs:
            tr = self.tracks[i]; pl = plots[j]
            if tr.extent > 0.0:
                rad = tr.extent / 2.0
                extra = [k for k, p in enumerate(plots) if k not in assigned_p
                         and math.hypot(p.x - tr.x[0], p.y - tr.x[1]) < rad + p.r_pos]
                if extra:
                    pl = merge_plots([pl] + [plots[k] for k in extra], weighted=False)   # centre geometrique de la cible
                    assigned_p.update(extra); self.n_swallowed += len(extra)
            tr.update(pl)

        # --- Pistes non servies -> miss ---
        for i, tr in enumerate(self.tracks):
            if i not in assigned_t:
                tr.miss()

        # --- Plots orphelins -> nouvelles pistes tentatives ---
        # (sauf ceux qui tombent DANS l'etendue d'une piste etendue : echos de la meme
        # coque, deja representee -> avales, pas de nouvelle piste) : rayon = etendue/2 +
        # incertitude de mesure du plot
        ext = [tr for tr in self.tracks if tr.extent > 0.0]
        for j, pl in enumerate(plots):
            if j not in assigned_p:
                if ext and any(math.hypot(pl.x - tr.x[0], pl.y - tr.x[1]) < tr.extent / 2.0 + pl.r_pos for tr in ext):
                    self.n_swallowed += 1
                    continue
                self.tracks.append(Track(pl, t))

        # --- Journalisation + absorption + menage ---
        for tr in self.tracks:
            tr.log()
        self._absorb()
        dead = [tr for tr in self.tracks if tr.state == DEAD]
        self.archive.extend(dead)
        self.tracks = [tr for tr in self.tracks if tr.state != DEAD]

    def _absorb(self):
        """Absorption des pistes co-mobiles (cible etendue). Deux pistes affichables (confirmees au
        moins une fois) qui restent a moins de ABSORB_DIST_M, a vitesses egales (ABSORB_DV_MPS) et de
        meme cap (ABSORB_HD_DEG, si toutes deux >= ABSORB_SLOW_MPS) pendant ABSORB_DWELLS dwells
        consecutifs sont un seul objet : la piste la plus riche (hits, puis la plus ancienne)
        absorbe l'autre, herite de ses hits et porte l'etendue (distance entre les deux) qui
        elargit son gate/sa covariance de mesure -> une seule piste, centree sur la cible."""
        if Params.ABSORB_DWELLS <= 0:
            return
        live = [tr for tr in self.tracks
                if tr.confirmed_ever and tr.state in (CONFIRMED, SOLID, COASTING)]
        if len(live) < 2:
            return
        seen = {tr.id: set() for tr in live}
        killed = set()
        for i in range(len(live)):
            a = live[i]
            if a.id in killed:
                continue
            for j in range(i + 1, len(live)):
                b = live[j]
                if b.id in killed or a.id in killed:
                    continue
                d = math.hypot(a.x[0] - b.x[0], a.x[1] - b.x[1])
                ok = d < Params.ABSORB_DIST_M
                if ok:
                    sa, sb = a.speed(), b.speed()
                    ok = abs(sa - sb) < Params.ABSORB_DV_MPS
                    if ok and min(sa, sb) >= Params.ABSORB_SLOW_MPS:
                        ha = math.degrees(math.atan2(a.x[2], a.x[3])); hb = math.degrees(math.atan2(b.x[2], b.x[3]))
                        dh = abs(ha - hb) % 360.0
                        ok = (360.0 - dh if dh > 180.0 else dh) < Params.ABSORB_HD_DEG
                if not ok:
                    a._pair.pop(b.id, None); b._pair.pop(a.id, None)
                    continue
                n = a._pair.get(b.id, 0) + 1
                a._pair[b.id] = n; b._pair[a.id] = n
                seen[a.id].add(b.id); seen[b.id].add(a.id)
                if n >= Params.ABSORB_DWELLS:
                    keep, gone = (a, b) if (a.hits, -a.id) >= (b.hits, -b.id) else (b, a)
                    keep.extent = max(keep.extent, d)
                    # recentrage : la piste survivante se place au milieu des deux (centre de la
                    # cible etendue) ; sa vitesse est conservee, sa covariance position s'elargit
                    keep.x[0] = 0.5 * (keep.x[0] + gone.x[0]); keep.x[1] = 0.5 * (keep.x[1] + gone.x[1])
                    keep.P[0, 0] += (d / 4.0) ** 2; keep.P[1, 1] += (d / 4.0) ** 2
                    keep.hits += gone.hits
                    keep.absorbed.append(gone.id); keep.absorbed.extend(gone.absorbed)
                    keep._pair.pop(gone.id, None)
                    gone.dead_absorbed = True; gone.absorbed_into = keep.id
                    killed.add(gone.id)
        for tr in live:                       # paires non revues ce dwell : compteur remis a zero
            for oid in list(tr._pair):
                if oid not in seen.get(tr.id, ()):
                    del tr._pair[oid]

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


def rts_smooth(track):
    """Lisseur Rauch-Tung-Striebel : passe arriere sur une piste terminee.
    Retourne [(t, x, y)] lisses, tronques a la derniere detection reelle.
    A reserver aux produits trajet/debriefing (hors temps reel, non causal)."""
    return _rts_states(track.states[:track.last_hit_idx + 1], track.q_accel)


def rts_tail(track, n=30):
    """Traine LISSEE d'une piste vivante (affichage temps reel) : passe RTS arriere sur les n
    derniers etats, ancree sur l'etat filtre COURANT (qui n'est pas modifie). Le passe proche est
    re-estime avec les mesures qui ont suivi -> la trace ne zigzague plus au gre du bruit de mesure
    (σ_range ~100 m en 4607) et donne la direction. Retourne [(t, x, y)], du plus ancien au courant."""
    st = track.states[-max(2, int(n)):]
    return _rts_states(st, track.q_accel)


def _rts_states(st, q_accel):
    n = len(st)
    if n < 3:
        return [(t, x[0], x[1]) for t, x, _ in st]
    xs = [x.copy() for _, x, _ in st]
    Ps = [P.copy() for _, _, P in st]
    ts = [t for t, _, _ in st]
    x_s, P_s = xs[-1], Ps[-1]
    out = [(ts[-1], x_s[0], x_s[1])]
    q = q_accel ** 2
    for k in range(n - 2, -1, -1):
        dt = max(ts[k + 1] - ts[k], 1e-3)
        F = np.array([[1, 0, dt, 0], [0, 1, 0, dt], [0, 0, 1, 0], [0, 0, 0, 1]])
        G = np.array([[dt**2 / 2, 0], [0, dt**2 / 2], [dt, 0], [0, dt]])
        Q = G @ (q * np.eye(2)) @ G.T
        x_pred = F @ xs[k]
        P_pred = F @ Ps[k] @ F.T + Q
        C = Ps[k] @ F.T @ np.linalg.inv(P_pred)
        x_s = xs[k] + C @ (x_s - x_pred)
        P_s = Ps[k] + C @ (P_s - P_pred) @ C.T
        out.append((ts[k], x_s[0], x_s[1]))
    return out[::-1]
