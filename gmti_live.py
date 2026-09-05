# -*- coding: utf-8 -*-
"""gmti_live.py — pistage GMTI TEMPS RÉEL sur dwells décodés + géométrie des dwells.

Partagé par la console web (`pcap_web.py` : rejeu et écoute réseau) et par le service GMTI de
StratusServer (`docker/app/gmti/live.py`, copie synchronisée par `sync_gmti_to_stratus.py`).
Ne dépend que de `tracker` / `track_run` (passés en paramètres : ils peuvent être chargés depuis
un dossier versionné) et d'un décodeur 4607 exposant `looks_like_4607` / `decode_packet_dwells`.
"""
import itertools
import math
import threading

TRACK_LOCK = threading.RLock()     # Params du tracker = classe globale : un seul utilisateur à la fois


class LiveTracker:
    """Pistage TEMPS RÉEL : Tracker.step() dwell par dwell (comme le processor GeoEvent), profil +
    surcharges (noms Java), étage d'entrée prepare_plots (déclutter → fantômes → SNR → clustering),
    fusion TrackMerger. `tr` = module track_run, `T` = module tracker."""

    def __init__(self, tr, T, profile="defaut", overrides=None):
        self.tr, self.T = tr, T
        # Le tracker est chargé depuis un dossier versionné : v8 présente `Tracker()` + `step(t, plots)`,
        # v9 un pistage par DWELL (`step(Dwell)`), qui a besoin des champs d'empreinte pour savoir si une
        # piste était observable. On détecte la génération plutôt que d'imposer une API à l'une des deux.
        self.v9 = hasattr(T, "Dwell") and hasattr(T, "Profile")
        self.prof = None
        self.profile, self.overrides = profile or "defaut", overrides or {}
        self.tk = None; self.frame = None; self.last_t = None; self.merger = None
        self.n_dwells = 0; self.n_plots = 0; self.n_resets = 0; self.n_filtered = 0; self.n_clustered = 0; self.n_ghosts = 0
        self.cfg = None
        self.tail_states = 300          # longueur de traîne (états) ; 0 = toute la piste (plafonné)
        self.tail_points = 120          # points max transportés par traîne (décimation, fin dense)
        self._tail_cache = {}           # id -> (n_states_calcules, [(t,x,y)...] lissés, n)

    def _apply(self):
        cfg = self.tr.apply_profile(self.profile, self.overrides)
        if self.v9:
            self.prof = cfg                                  # dataclass Profile
            self.cfg = self.tr.config_dict(cfg)              # vue dict, pour l'affichage et les lectures
        else:
            self.cfg = cfg
        return self.cfg

    def _reset(self):
        self._apply()
        self.T.Track._ids = itertools.count(1)
        if self.v9:
            # Le v9 tient son repère : le tracker n'est construit qu'au premier dwell géolocalisé.
            self.tk = self.T.Tracker(self.prof, self.frame) if self.frame is not None else None
            self.merger = self.tr.ContactMerger(self.prof)
        else:
            self.tk = self.T.Tracker()
            self.merger = self.tr.TrackMerger(self.cfg)
        self.last_t = None

    def set_profile(self, profile=None, overrides=None, reset=False):
        """Changement de profil / surcharges à chaud (pris en compte au prochain dwell) ;
        reset=True repart de zéro (pistes supprimées)."""
        with TRACK_LOCK:
            if profile:
                self.profile = profile
            if overrides is not None:
                self.overrides = dict(overrides)
            self.cfg = None
            if reset:
                self.tk = None; self.frame = None; self.last_t = None
            else:
                self._apply()
                if self.tk is not None:
                    self.merger = (self.tr.ContactMerger(self.prof) if self.v9
                                   else self.tr.TrackMerger(self.cfg))

    def step_dwells(self, dwells):
        """dwells : sortie de decode_packet_dwells (rows déjà validés)."""
        T = self.T
        with TRACK_LOCK:
            cfg = self._apply()
            if self.tk is None:
                self._reset()
            for d in dwells:
                if d["time"] is None:
                    continue
                t = d["time"] / 1000.0
                rows = d["rows"]
                if not rows and self.v9 and self.tk is not None:
                    # v9 : un dwell VIDE est une information — il dit que le radar regardait là et n'a
                    # rien vu. C'est ce qui distingue un vrai miss d'un faisceau pointé ailleurs.
                    self.tk.step(self._v9_dwell(d, t, []))
                    self.last_t = t
                    self.n_dwells += 1
                    continue
                if not rows:
                    # Dwell sans target report (le faisceau balaie ailleurs) : ignoré, comme le processor
                    # GeoEvent (qui ne reçoit que des GMTI_Target) et le banc hors ligne (CSV de plots)
                    # → mêmes pistes, même parité ; sinon chaque dwell vide compterait comme un miss.
                    continue
                if self.frame is None:
                    self.frame = T.LocalFrame(rows[0]["lat"], rows[0]["lon"])
                if self.last_t is not None:
                    if t < self.last_t - 5.0:                       # rejeu bouclé / retour franc → nouvelle session
                        self.n_resets += 1; self._reset()
                    elif t < self.last_t:                            # léger désordre : on ne recule pas le temps
                        t = self.last_t
                if self.v9 and self.tk is None:            # repère connu : le tracker v9 peut naître
                    if self.prof is None:
                        self._apply()
                    self.tk = T.Tracker(self.prof, self.frame)
                if self.v9:
                    self.tk.step(self._v9_dwell(d, t, rows))
                    self.last_t = t
                    self.n_dwells += 1
                    self.n_plots += len(rows)
                    continue
                sl = d["sensor"]
                sxy = self.frame.to_xy(sl[0], sl[1]) if sl and sl[0] is not None and sl[1] is not None else None
                plots = []
                for r in rows:
                    x, y = self.frame.to_xy(r["lat"], r["lon"])
                    sig_r = (r["sig_range_cm"] / 100.0) if r["sig_range_cm"] else T.Params.R_POS_DEFAULT
                    sig_x = (r["sig_xrange_dm"] / 10.0) if r["sig_xrange_dm"] else T.Params.R_POS_DEFAULT
                    R = T.covariance_from_4607(sxy, (x, y), self.tr._clamp_std(sig_r), self.tr._clamp_std(sig_x)) if sxy else None
                    plots.append(T.Plot(x, y, r_pos=max(sig_r, sig_x), R=R,
                                        vel_los=(r["vel_los_cms"] or 0) / 100.0, snr=r["snr_db"], classification=r["classification"]))
                plots, pst = self.tr.prepare_plots(plots, cfg)     # déclutter → fantômes → SNR → clustering
                self.n_filtered += pst["filtered"]; self.n_ghosts += pst["ghosts"]; self.n_clustered += pst["clustered"]
                self.tk.step(t, plots)
                self.last_t = t; self.n_dwells += 1; self.n_plots += len(plots)

    def _v9_dwell(self, d, t, rows):
        """Dwell décodé (`decode_packet_dwells`) → `tracker.Dwell` du v9, unités SI et sentinelles à None."""
        T = self.T
        sl = d.get("sensor") or (None, None, None)

        def sig(v, scale):
            return None if not v or v >= 65535 else v / scale

        plots = []
        for r in rows:
            x, y = self.frame.to_xy(r["lat"], r["lon"])
            plots.append(T.Plot(lat=r["lat"], lon=r["lon"], x=x, y=y,
                                vr=(r["vel_los_cms"] / 100.0) if r.get("vel_los_cms") is not None else None,
                                snr_db=r.get("snr_db"), classification=r.get("classification"),
                                sigma_range_m=sig(r.get("sig_range_cm"), 100.0),
                                sigma_cross_m=sig(r.get("sig_xrange_dm"), 10.0),
                                sigma_vr_mps=sig(r.get("sig_rvel_cms"), 100.0)))
        c = d.get("center") or (None, None)
        rhe = d.get("range_he_km")
        return T.Dwell(t=t, sensor_lat=sl[0], sensor_lon=sl[1], sensor_alt_m=(sl[2] or 0.0),
                       center_lat=c[0], center_lon=c[1],
                       half_range_m=(rhe * 1000.0) if rhe else None,
                       half_angle_deg=d.get("angle_he_deg"), mdv_mps=d.get("mdv"),
                       job_id=d.get("job_id"), plots=plots)

    def _tail(self, tr, n, smooth):
        """Traîne d'une piste : `n` derniers états (0 = tous, max 2000), lissée (RTS) avec cache —
        recalcul complet seulement si >= 3 nouveaux états depuis le dernier calcul, sinon réutilisation
        + ajout des états filtrés récents ; puis décimation à tail_points (les derniers restent denses)."""
        T = self.T
        n_all = len(tr.states)
        n = min(n_all, 2000) if not n or n <= 0 else min(n, n_all, 2000)
        if smooth and hasattr(T, "rts_tail"):
            c = self._tail_cache.get(tr.id)
            if c is not None and 0 <= n_all - c[0] < 3 and c[2] == n:
                pts = list(c[1]) + [(t_, x_[0], x_[1]) for (t_, x_, _P) in tr.states[c[0]:]]
            else:
                try:
                    pts = T.rts_tail(tr, n)
                except Exception:
                    pts = [(t_, x_[0], x_[1]) for (t_, x_, _P) in tr.states[-n:]]
                self._tail_cache[tr.id] = (n_all, pts, n)
        else:
            pts = [(t_, x_[0], x_[1]) for (t_, x_, _P) in tr.states[-n:]]
        m = self.tail_points
        if m and len(pts) > m:                       # décimation : 3/4 du budget sur l'ancien, 1/4 dense à la fin
            dense = max(10, m // 4); old = pts[:-dense]; step = max(1, len(old) // (m - dense))
            pts = old[::step] + pts[-dense:]
        return [[round(a, 6), round(b, 6)] for a, b in (self.frame.to_ll(float(x), float(y)) for (_t, x, y) in pts)]

    def snapshot(self, tail=None, smooth=True):
        """Pistes vivantes (état, position, vitesse, cap, traîne) + contacts fusionnés.
        tail : longueur de traîne en états (None = self.tail_states ; 0 = toute la piste) ; smooth=True :
        traîne lissée (RTS, tracker.rts_tail, cache) — la position courante reste l'estimée filtrée."""
        if tail is None:
            tail = self.tail_states
        T = self.T
        if self.tk is None or self.frame is None:
            return {"tracks": [], "contacts": None, "stats": self._stats(0, 0, 0, 0)}
        with TRACK_LOCK:
            self._apply()
            names = {T.TENTATIVE: "TENTATIVE", T.CONFIRMED: "CONFIRMED", T.SOLID: "SOLID", T.COASTING: "COASTING"}
            out, outs = [], []
            counts = {"TENTATIVE": 0, "CONFIRMED": 0, "SOLID": 0, "COASTING": 0, "EVER": 0}
            min_speed = float((self.cfg or {}).get("minTrackSpeedMps") or 0.0)   # v9 : absent → 0
            for tr in self.tk.tracks:
                st = tr.state
                if st == getattr(T, "DEAD", "\x00"):        # le v9 n'a pas d'état « Supprimee » vivant
                    continue
                name = names.get(st, str(st)); counts[name] = counts.get(name, 0) + 1
                if tr.confirmed_ever:
                    counts["EVER"] += 1
                sp = float(tr.speed())
                la, lo = self.frame.to_ll(float(tr.x[0]), float(tr.x[1]))
                tail_ll = self._tail(tr, tail, smooth)
                o = {"id": tr.id, "lat": round(la, 6), "lon": round(lo, 6), "speed": round(sp, 1),
                     "heading": round((math.degrees(math.atan2(tr.x[2], tr.x[3])) + 360.0) % 360.0, 1),
                     "state": name, "hits": tr.hits, "misses": getattr(tr, "misses", 0), "ever": bool(tr.confirmed_ever),
                     "is_air": bool(tr.is_air), "is_rotator": bool(tr.is_rotator),
                     "age_s": round(max(0.0, (self.last_t or 0) - tr.t_last_update), 1),
                     "extent_m": round(float(getattr(tr, "extent", 0.0)), 1),
                     "absorbed": list(getattr(tr, "absorbed", None) or getattr(tr, "merged_from", [])),
                     "cls": tr.dominant_class() if hasattr(tr, "dominant_class") else None,
                     "tail": tail_ll}
                out.append(o)
                if tr.confirmed_ever and name != "TENTATIVE" and (min_speed <= 0 or sp >= min_speed):   # affichables (comme le processor)
                    outs.append({"track_id": tr.id, "x": float(tr.x[0]), "y": float(tr.x[1]), "speed": sp, "heading": o["heading"],
                                 "state": name, "hits": tr.hits, "is_air": o["is_air"], "is_rotator": o["is_rotator"]})
            contacts = None
            if self.merger and self.merger.enabled():
                by_track = {}
                cs = self.merger.merge(outs, self.last_t or 0.0) if self.v9 else self.merger.merge(outs)
                for c in cs:
                    for m in c["members"]:
                        by_track[m] = c["id"]
                for o in out:
                    o["contact"] = by_track.get(o["id"])
                contacts = [{"id": c["id"], "n": c["n"], "lat": round(self.frame.to_ll(c["x"], c["y"])[0], 6),
                             "lon": round(self.frame.to_ll(c["x"], c["y"])[1], 6), "members": c["members"]} for c in cs if c["n"] > 1]
            st_ = self._stats(counts["TENTATIVE"], counts["CONFIRMED"], counts["SOLID"], counts["COASTING"]); st_["displayable"] = counts["EVER"]
            alive = {tr.id for tr in self.tk.tracks}
            for k in [k for k in self._tail_cache if k not in alive]:
                del self._tail_cache[k]
            return {"tracks": out, "contacts": contacts, "stats": st_}

    def _stats(self, tent, conf, solid, coast):
        return {"profile": self.profile, "overrides": self.overrides, "n_dwells": self.n_dwells, "n_plots": self.n_plots,
                "n_filtered": self.n_filtered, "n_resets": self.n_resets, "t": self.last_t, "n_clustered": self.n_clustered, "n_ghosts": self.n_ghosts,
                "n_absorbed": sum(1 for a in self.tk.archive if getattr(a, "dead_absorbed", False)) if self.tk else 0,
                "n_swallowed": getattr(self.tk, "n_swallowed", getattr(self.tk, "n_clustered", 0)) if self.tk else 0,
                "tentative": tent, "confirmed": conf, "solid": solid, "coasting": coast,
                "archived": len(self.tk.archive) if self.tk else 0}


# ── Géométrie des dwells + décodage « prêt à dessiner » ───────────────────────
def dest_point(lat, lon, bearing_deg, dist_m):
    """Point à `dist_m` mètres dans la direction `bearing_deg` (sphère, R = 6371 km)."""
    R = 6371000.0
    la1, lo1, br = math.radians(lat), math.radians(lon), math.radians(bearing_deg)
    dr = dist_m / R
    la2 = math.asin(math.sin(la1) * math.cos(dr) + math.cos(la1) * math.sin(dr) * math.cos(br))
    lo2 = lo1 + math.atan2(math.sin(br) * math.sin(dr) * math.cos(la1), math.cos(dr) - math.sin(la1) * math.sin(la2))
    return [round(math.degrees(la2), 6), round(math.degrees(lo2), 6)]


def dist_bearing(lat1, lon1, lat2, lon2):
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    d = 2 * R * math.asin(math.sqrt(a))
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return d, (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def dwell_area(sensor, center, range_he_km, angle_he_deg):
    """Polygone (secteur annulaire) de la zone de dwell : centre C vu du capteur S à
    distance R et gisement θ ; coins à R ± ΔR et θ ± Δθ (D24/D25). None si incomplet."""
    if not sensor or not center or sensor[0] is None or center[0] is None:
        return None
    if range_he_km is None or angle_he_deg is None or range_he_km <= 0:
        return None
    R, th = dist_bearing(sensor[0], sensor[1], center[0], center[1])
    dr = range_he_km * 1000.0
    r1, r2 = max(0.0, R - dr), R + dr
    a1, a2 = th - angle_he_deg, th + angle_he_deg
    poly = [dest_point(sensor[0], sensor[1], a1, r1)]
    for k in range(9):                                       # arc extérieur
        poly.append(dest_point(sensor[0], sensor[1], a1 + (a2 - a1) * k / 8, r2))
    poly.append(dest_point(sensor[0], sensor[1], a2, r1))
    for k in range(9):                                       # arc intérieur (retour)
        poly.append(dest_point(sensor[0], sensor[1], a2 - (a2 - a1) * k / 8, r1))
    return poly


def decode_gmti(decoder, pl):
    """Paquet(s) 4607 → (plots [[lat, lon, vel_los_cms, snr, cls]…], sensor [lat, lon] | None,
    dwells [{"center":[lat,lon], "poly":[[lat,lon]…]|None, "n":n_targets, "range_he_km", "angle_he_deg",
    "t_ms", "revisit", "dwell"}], dwells_bruts) ; None si ce n'est pas du 4607.
    `decoder` : module exposant looks_like_4607 / decode_packet_dwells."""
    if decoder is None or not decoder.looks_like_4607(pl):
        return None
    dwells = decoder.decode_packet_dwells(pl)
    plots, sensor, dw = [], None, []
    for d in dwells:
        for r in d["rows"]:
            plots.append([round(r["lat"], 6), round(r["lon"], 6), r["vel_los_cms"], r["snr_db"], r["classification"]])
        sl = d["sensor"]
        if sl and sl[0] is not None and sl[1] is not None:
            sensor = [round(sl[0], 6), round(sl[1], 6)]
        c = d["center"]
        if c and c[0] is not None:
            dw.append({"center": [round(c[0], 6), round(c[1], 6)], "n": len(d["rows"]),
                       "range_he_km": d["range_he_km"], "angle_he_deg": d["angle_he_deg"],
                       "poly": dwell_area(sensor, c, d["range_he_km"], d["angle_he_deg"]),
                       "t_ms": d["time"], "revisit": d["revisit"], "dwell": d["dwell"]})
    return plots, sensor, dw, dwells
