#!/usr/bin/env python3
"""Console pcap (interface Tkinter) — ISRBOX / 33e ESRA.

Application desktop (bibliothèque standard : tkinter) à deux onglets :

  • REJEU        : analyser un pcap, cocher les flux, router (fan-out) et rejouer
                   (pilote pcap_analyze + pcap_replay).
  • GMTI → PISTES: décoder le GMTI 4607, dérouler le tracker (profil de tuning) et
                   dessiner plots/pistes sur un canvas NATIF (pan/zoom), sans
                   matplotlib. Boucle de tuning : re-run instantané par profil.

L'onglet Rejeu ne dépend de rien (stdlib). L'onglet GMTI charge le tracker
(numpy + scipy) EN LAZY : s'ils manquent, seul cet onglet est indisponible.
"""
import base64
import importlib
import math
import os
import queue
import sys
import tempfile
import threading
import types

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_analyze          # noqa: E402
import pcap_replay           # noqa: E402
try:
    import mgrs_lite         # noqa: E402
except Exception:
    mgrs_lite = None
try:
    import arcgis_basemap    # noqa: E402
except Exception:
    arcgis_basemap = None
try:
    import gmti_pcap_to_csv  # noqa: E402
except Exception:
    gmti_pcap_to_csv = None
try:
    import cot_extract       # noqa: E402
except Exception:
    cot_extract = None
try:
    import video4609         # noqa: E402
except Exception:
    video4609 = None

# Couleurs par affiliation CoT (MIL-STD-2525 : ami=bleu, hostile=rouge, neutre=vert…).
AFFIL_COLORS = {"FRIEND": "#00c8ff", "ASSUMED_FRIEND": "#00c8ff", "JOKER": "#00c8ff",
                "HOSTILE": "#ff5252", "SUSPECT": "#ff5252", "FAKER": "#ff5252",
                "NEUTRAL": "#7cff6b", "UNKNOWN": "#ffd54f", "PENDING": "#ffd54f", "": "#8a8f98"}

SPEEDS = [("×1 (temps réel)", 1.0), ("×2", 2.0), ("×5", 5.0), ("×10", 10.0), ("max", 0.0)]
SCAN_LIMIT_DEFAULT = 300000
PROFILE_NAMES = ["defaut", "maritime", "routier", "routier_zone", "convoi", "personnel", "aerien"]
# Dossier du tracker + extracteur : on prend automatiquement la version
# `prototype_tracker_gmti_v<N>` la PLUS ÉLEVÉE contenant track_run.py — une v8
# déposée à côté est ainsi utilisée sans modifier ce code.
TRACKER_PREFIX = "prototype_tracker_gmti_v"
# Au-delà, l'extracteur (lecture intégrale en mémoire) est évité au profit du
# décodage en streaming de gmti_pcap_to_csv.
EXTRACT_MAX_BYTES = 700 * 1024 * 1024
PALETTE = ["#ffc107", "#00c8ff", "#7cff6b", "#ff6ec7", "#ff8a3d", "#b388ff",
           "#4dd0e1", "#f06292", "#aed581", "#ff5252"]
# Couleurs de plots par classification STANAG (target classification).
CLASS_COLORS = {6: "#00c8ff", 9: "#ff6ec7", 10: "#ffc107", 1: "#ff8a3d",
                2: "#ff8a3d", 3: "#7cff6b", 4: "#7cff6b"}
CLASS_DEFAULT = "#59636f"


# ── Logique pure (testable sans Tk) ─────────────────────────────────────────

def build_route_specs(selected):
    """`selected` = liste de (proto, dport, [chaînes cibles]) -> specs `--route`."""
    specs = []
    for proto, dport, targets in selected:
        tg = [t.strip() for t in targets if t and t.strip()]
        if tg:
            specs.append("%s/%s=%s" % (proto.lower(), dport, ",".join(tg)))
    return specs


def is_app_proto(dominant):
    return dominant.startswith(pcap_analyze.APP)


class GeoFrame:
    """Repère local ENU équirectangulaire (lat/lon <-> mètres). Interface
    compatible avec tracker.LocalFrame (to_xy / to_ll)."""
    def __init__(self, lat0, lon0):
        self.lat0, self.lon0 = lat0, lon0
        self.kx = 111320.0 * math.cos(math.radians(lat0))
        self.ky = 110540.0

    def to_xy(self, lat, lon):
        return (lon - self.lon0) * self.kx, (lat - self.lat0) * self.ky

    def to_ll(self, x, y):
        return self.lat0 + y / self.ky, self.lon0 + x / self.kx


_GRID_STEPS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10]


def _grid_step(span_deg):
    """Pas de graticule (°) pour ~5 lignes sur l'étendue visible."""
    target = max(span_deg, 1e-6) / 5.0
    for s in _GRID_STEPS:
        if s >= target:
            return s
    return _GRID_STEPS[-1]


def _tracker_dir():
    """Dossier du tracker : la version v<N> la plus élevée ayant track_run.py."""
    base = os.path.dirname(os.path.abspath(__file__))
    best, best_n = None, -1
    try:
        for name in os.listdir(base):
            if not name.startswith(TRACKER_PREFIX):
                continue
            suffix = name[len(TRACKER_PREFIX):]
            if (suffix.isdigit() and os.path.isdir(os.path.join(base, name))
                    and os.path.isfile(os.path.join(base, name, "track_run.py"))):
                n = int(suffix)
                if n > best_n:
                    best_n, best = n, name
    except OSError:
        pass
    return os.path.join(base, best) if best else os.path.join(base, TRACKER_PREFIX + "7")


def load_track_run():
    """Import LAZY du noyau tracker v7 (numpy+scipy). Lève ImportError si absent."""
    d = _tracker_dir()
    if d not in sys.path:
        sys.path.insert(0, d)
    return importlib.import_module("track_run")


def load_extract():
    """Import LAZY de l'extracteur 4607 complet (pur Python)."""
    d = _tracker_dir()
    if d not in sys.path:
        sys.path.insert(0, d)
    return importlib.import_module("stanag4607_extract")


def _is_pcapng(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x0a\x0d\x0d\x0a"
    except OSError:
        return False


# ── Canvas natif : plots + pistes, pan (glisser) / zoom (molette) ────────────

class TrackCanvas(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg="#0e1216", highlightthickness=0)
        self.raw = []            # (x,y) ou (x,y,classif)
        self.tracks = []
        self.zone = []           # bounding area du job [(x,y),...]
        self.porteur = []        # trajet Platform Location [(x,y),...]
        self.geo_frame = None    # repère ENU<->lat/lon (graticule + lecture)
        self.show_raw = True
        self.show_smooth = False
        self.scale = 1.0
        self.cx = 0.0
        self.cy = 0.0
        self._drag = None
        # Fond de carte ArcGIS (raster) : image + emprise + callback de requête.
        self.basemap_enabled = False
        self.basemap_photo = None
        self.basemap_bbox = None
        self.request_basemap = None    # fixé par l'app : callback(canvas)
        self._bm_after = None
        self.bind("<Configure>", lambda e: self.redraw())
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._motion)
        self.bind("<ButtonRelease-1>", lambda e: self._view_changed())
        self.bind("<Motion>", self._readout)
        self.bind("<MouseWheel>", self._wheel)          # Windows / macOS
        self.bind("<Button-4>", self._wheel)            # X11 molette haut
        self.bind("<Button-5>", self._wheel)            # X11 molette bas

    def _view_changed(self):
        """Après un pan/zoom : re-demande le fond (débattu) si activé."""
        if not (self.basemap_enabled and self.request_basemap and self.geo_frame):
            return
        if self._bm_after:
            try: self.after_cancel(self._bm_after)
            except Exception: pass
        self._bm_after = self.after(300, lambda: self.request_basemap(self))

    def apply_basemap(self, png_bytes, bbox):
        try:
            self.basemap_photo = tk.PhotoImage(data=base64.b64encode(png_bytes).decode("ascii"))
            self.basemap_bbox = bbox
            self.redraw()
        except Exception:
            pass

    def _draw_basemap(self):
        if not (self.basemap_enabled and self.basemap_photo and self.basemap_bbox and self.geo_frame):
            return
        lonmin, latmin, lonmax, latmax = self.basemap_bbox
        nx, ny = self.w2s(*self.geo_frame.to_xy(latmax, lonmin))   # coin nord-ouest
        self.create_image(nx, ny, image=self.basemap_photo, anchor="nw")

    def draw_graticule(self):
        """Grille lat/lon + labels sur l'étendue visible (si repère géo connu)."""
        if not self.geo_frame or self.scale <= 0:
            return
        W = max(self.winfo_width(), 2); H = max(self.winfo_height(), 2)
        lls = [self.geo_frame.to_ll(*self.s2w(sx, sy))
               for sx, sy in ((0, 0), (W, 0), (0, H), (W, H))]
        lats = [p[0] for p in lls]; lons = [p[1] for p in lls]
        latmin, latmax = min(lats), max(lats); lonmin, lonmax = min(lons), max(lons)
        step = _grid_step(max(latmax - latmin, lonmax - lonmin))
        la = math.floor(latmin / step) * step
        while la <= latmax + step:
            a = self.w2s(*self.geo_frame.to_xy(la, lonmin))
            b = self.w2s(*self.geo_frame.to_xy(la, lonmax))
            self.create_line(a[0], a[1], b[0], b[1], fill="#20282f")
            self.create_text(3, a[1], text="%.3f" % la, anchor="w", fill="#4a5560", font=("Consolas", 7))
            la += step
        lo = math.floor(lonmin / step) * step
        while lo <= lonmax + step:
            a = self.w2s(*self.geo_frame.to_xy(latmin, lo))
            b = self.w2s(*self.geo_frame.to_xy(latmax, lo))
            self.create_line(a[0], a[1], b[0], b[1], fill="#20282f")
            self.create_text(a[0], H - 2, text="%.3f" % lo, anchor="s", fill="#4a5560", font=("Consolas", 7))
            lo += step

    def _readout(self, e):
        """Lecture lat/lon (+ MGRS) sous le curseur, en bas à droite."""
        if not self.geo_frame:
            return
        self.delete("readout")
        lat, lon = self.geo_frame.to_ll(*self.s2w(e.x, e.y))
        mgrs = (mgrs_lite.latlon_to_mgrs(lat, lon) if mgrs_lite else None) or ""
        self.create_text(self.winfo_width() - 6, self.winfo_height() - 6,
                         text="%.5f, %.5f  %s" % (lat, lon, mgrs), anchor="se",
                         fill="#c2c8ce", font=("Consolas", 8), tags="readout")

    def set_data(self, raw, tracks, zone=None, porteur=None, frame=None, fit=True):
        self.raw = raw or []
        self.tracks = tracks or []
        self.zone = zone or []
        self.porteur = porteur or []
        self.geo_frame = frame
        if fit:
            self.fit()
        self.redraw()

    def _fit_to(self, pts):
        """Cadre la vue sur un ensemble de points (x,y). Partagé (TrackCanvas/CotCanvas)."""
        if not pts:
            self.scale, self.cx, self.cy = 1.0, 0.0, 0.0
            return
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
        self.cx, self.cy = (minx + maxx) / 2, (miny + maxy) / 2
        w = max(maxx - minx, 1.0)
        h = max(maxy - miny, 1.0)
        W = max(self.winfo_width(), 50)
        H = max(self.winfo_height(), 50)
        self.scale = min(W / (w * 1.15), H / (h * 1.15))

    def fit(self):
        pts = [(p[0], p[1]) for p in self.raw]
        for tr in self.tracks:
            pts += tr["pts"]
        pts += self.zone + self.porteur
        self._fit_to(pts)

    def w2s(self, x, y):
        W = self.winfo_width()
        H = self.winfo_height()
        return (W / 2 + (x - self.cx) * self.scale,
                H / 2 - (y - self.cy) * self.scale)

    def s2w(self, sx, sy):
        W = self.winfo_width()
        H = self.winfo_height()
        return (self.cx + (sx - W / 2) / self.scale,
                self.cy - (sy - H / 2) / self.scale)

    def redraw(self):
        self.delete("all")
        if not self.raw and not self.tracks:
            self.create_text(self.winfo_width() / 2, self.winfo_height() / 2,
                             text="(décoder le GMTI puis lancer le tracker)",
                             fill="#5a6675", font=("Segoe UI", 11))
            return
        self._draw_basemap()
        self.draw_graticule()
        # Zone de job (bounding area) : polygone tireté.
        if len(self.zone) >= 3:
            flat = []
            for x, y in self.zone + [self.zone[0]]:
                sx, sy = self.w2s(x, y)
                flat += [sx, sy]
            self.create_line(*flat, fill="#3d6e8c", width=1, dash=(5, 4))
        # Trajet porteur (Platform Location).
        if len(self.porteur) >= 2:
            flat = []
            for x, y in self.porteur:
                sx, sy = self.w2s(x, y)
                flat += [sx, sy]
            self.create_line(*flat, fill="#8a8f98", width=1, dash=(2, 3))
        if self.show_raw:
            for p in self.raw:
                sx, sy = self.w2s(p[0], p[1])
                col = CLASS_COLORS.get(p[2], CLASS_DEFAULT) if len(p) > 2 else "#59636f"
                self.create_rectangle(sx, sy, sx + 1, sy + 1, outline=col)
        for i, tr in enumerate(self.tracks):
            col = PALETTE[i % len(PALETTE)]
            pts = tr["smooth"] if (self.show_smooth and tr.get("smooth")) else tr["pts"]
            if len(pts) >= 2:
                flat = []
                for x, y in pts:
                    sx, sy = self.w2s(x, y)
                    flat += [sx, sy]
                self.create_line(*flat, fill=col, width=2)
            if pts:
                ex, ey = self.w2s(*pts[-1])
                self.create_oval(ex - 4, ey - 4, ex + 4, ey + 4, fill=col, outline="")
                self.create_text(ex + 8, ey, text="#%d" % tr["id"], anchor="w",
                                 fill=col, font=("Consolas", 8))
        # échelle
        self._draw_scalebar()

    def _draw_scalebar(self):
        if self.scale <= 0:
            return
        target_px = 90
        world = target_px / self.scale
        nice = 10 ** int(round(__import__("math").log10(max(world, 1e-6))))
        for m in (1, 2, 5, 10):
            if nice * m >= world:
                nice = nice * m
                break
        px = nice * self.scale
        H = self.winfo_height()
        x0, y0 = 12, H - 16
        self.create_line(x0, y0, x0 + px, y0, fill="#c2c8ce", width=2)
        lbl = ("%g km" % (nice / 1000)) if nice >= 1000 else ("%g m" % nice)
        self.create_text(x0 + px + 6, y0, text=lbl, anchor="w", fill="#c2c8ce",
                         font=("Consolas", 8))

    def _press(self, e):
        self._drag = (e.x, e.y)

    def _motion(self, e):
        if not self._drag:
            return
        dx = e.x - self._drag[0]
        dy = e.y - self._drag[1]
        self._drag = (e.x, e.y)
        self.cx -= dx / self.scale
        self.cy += dy / self.scale
        self.redraw()

    def _wheel(self, e):
        up = getattr(e, "delta", 0) > 0 or getattr(e, "num", 0) == 4
        f = 1.2 if up else 1 / 1.2
        wx, wy = self.s2w(e.x, e.y)          # point monde sous le curseur (fixe)
        self.scale *= f
        # recale le centre pour garder (wx,wy) sous le curseur
        W = self.winfo_width()
        H = self.winfo_height()
        self.cx = wx - (e.x - W / 2) / self.scale
        self.cy = wy + (e.y - H / 2) / self.scale
        self.redraw()
        self._view_changed()


# ── Canvas CoT : points colorés par affiliation + trace par uid ─────────────

class CotCanvas(TrackCanvas):
    """Réutilise le pan/zoom/échelle de TrackCanvas ; dessine des points CoT
    (couleur = affiliation) et une trace par uid."""

    def __init__(self, parent):
        super().__init__(parent)
        self.points = []       # (x, y, affiliation, uid)
        self.uid_tracks = []   # [[(x,y),...], ...]
        self.show_tracks = True

    def set_cot(self, points, uid_tracks, frame=None, fit=True):
        self.points = points or []
        self.uid_tracks = uid_tracks or []
        self.geo_frame = frame
        if fit:
            self.fit()
        self.redraw()

    def fit(self):
        pts = [(p[0], p[1]) for p in self.points]
        for tr in self.uid_tracks:
            pts += tr
        self._fit_to(pts)

    def redraw(self):
        self.delete("all")
        if not self.points:
            self.create_text(self.winfo_width() / 2, self.winfo_height() / 2,
                             text="(analyser le CoT du pcap)", fill="#5a6675",
                             font=("Segoe UI", 11))
            return
        self._draw_basemap()
        self.draw_graticule()
        if self.show_tracks:
            for tr in self.uid_tracks:
                if len(tr) >= 2:
                    flat = []
                    for x, y in tr:
                        sx, sy = self.w2s(x, y)
                        flat += [sx, sy]
                    self.create_line(*flat, fill="#3a4048", width=1)
        for x, y, affil, uid in self.points:
            sx, sy = self.w2s(x, y)
            col = AFFIL_COLORS.get(affil, AFFIL_COLORS[""])
            self.create_oval(sx - 3, sy - 3, sx + 3, sy + 3, fill=col, outline="#101418")
        self._draw_scalebar()
        self._legend()

    def _legend(self):
        items = [("Ami", "#00c8ff"), ("Hostile", "#ff5252"),
                 ("Neutre", "#7cff6b"), ("Inconnu", "#ffd54f")]
        x, y = 12, 14
        for label, col in items:
            self.create_oval(x, y - 4, x + 8, y + 4, fill=col, outline="")
            self.create_text(x + 14, y, text=label, anchor="w", fill="#c2c8ce",
                             font=("Consolas", 8))
            x += 78


# ── Ligne de flux (onglet Rejeu) ────────────────────────────────────────────

class FlowRow:
    def __init__(self, parent, proto, dport, dominant, pkts, default_ip):
        self.proto, self.dport, self.dominant, self.pkts = proto, dport, dominant, pkts
        self.replay = tk.BooleanVar(value=is_app_proto(dominant))
        self.frame = ttk.Frame(parent)
        ttk.Checkbutton(self.frame, variable=self.replay).grid(row=0, column=0, padx=(0, 4))
        label = "%s/%-6d %-20s %8d pkts" % (proto.lower(), dport, dominant, pkts)
        ttk.Label(self.frame, text=label, font=("Consolas", 9)).grid(row=0, column=1, sticky="w")
        self.targets_frame = ttk.Frame(self.frame)
        self.targets_frame.grid(row=0, column=2, sticky="w", padx=6)
        self.target_vars = []
        self._add_target(default_ip)
        ttk.Button(self.frame, text="+ client", width=8,
                   command=lambda: self._add_target("")).grid(row=0, column=3, padx=2)

    def _add_target(self, value):
        var = tk.StringVar(value=value)
        ttk.Entry(self.targets_frame, textvariable=var, width=20).pack(side="left", padx=2)
        self.target_vars.append(var)

    def pack(self, **kw):
        self.frame.pack(fill="x", pady=1, **kw)

    def selection(self):
        if not self.replay.get():
            return None
        return (self.proto, self.dport, [v.get() for v in self.target_vars])


# ── Application ──────────────────────────────────────────────────────────────

class Console(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Console pcap — ISRBOX / 33e ESRA")
        self.geometry("960x720")
        self.rows = []
        self.worker = None
        self.stop_event = threading.Event()
        self.q = queue.Queue()
        self.gmti_csv = None
        self.sink = None            # Sink de l'extracteur (overlays/inventaire), si dispo
        self._cot_rows = {}         # dernières valeurs CoT par uid (field=value)
        self._bm_failed = False     # fond de carte : n'alerter qu'une fois
        self.basemap_cfg = (arcgis_basemap.load_config(os.path.dirname(os.path.abspath(__file__)))
                            if arcgis_basemap else None)
        self.path_var = tk.StringVar()
        self.limit_var = tk.StringVar(value=str(SCAN_LIMIT_DEFAULT))
        self._build_ui()
        self.after(150, self._pump)

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Fichier pcap :").pack(side="left")
        ttk.Entry(top, textvariable=self.path_var, width=56).pack(side="left", padx=4)
        ttk.Button(top, text="Parcourir…", command=self._browse).pack(side="left")
        ttk.Label(top, text="limit").pack(side="left", padx=(8, 2))
        ttk.Entry(top, textvariable=self.limit_var, width=8).pack(side="left")

        nb = ttk.Notebook(self)
        self.nb = nb
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tab_overview = ttk.Frame(nb)
        self.tab_replay = ttk.Frame(nb)
        self.tab_gmti = ttk.Frame(nb)
        self.tab_inv = ttk.Frame(nb)
        self.tab_cot = ttk.Frame(nb)
        self.tab_video = ttk.Frame(nb)
        nb.add(self.tab_overview, text="  Vue d'ensemble  ")
        nb.add(self.tab_replay, text="  Rejeu  ")
        nb.add(self.tab_gmti, text="  GMTI → Pistes  ")
        nb.add(self.tab_inv, text="  Inventaire 4607  ")
        nb.add(self.tab_cot, text="  CoT  ")
        nb.add(self.tab_video, text="  Vidéo 4609  ")
        self._build_overview_tab(self.tab_overview)
        self._build_replay_tab(self.tab_replay)
        self._build_gmti_tab(self.tab_gmti)
        self._build_inventaire_tab(self.tab_inv)
        self._build_cot_tab(self.tab_cot)
        self._build_video_tab(self.tab_video)

        # Fond de carte ArcGIS piloté par l'app pour les canvas géo.
        for cv in (self.track_canvas, self.cot_canvas):
            cv.request_basemap = self._basemap_for

        self.status_var = tk.StringVar(value="Prêt.")
        ttk.Label(self, textvariable=self.status_var, padding=(8, 2),
                  font=("Consolas", 9)).pack(anchor="w")

    # ── Onglet Rejeu ─────────────────────────────────────────────────────
    def _build_replay_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser les flux", command=self._analyze).pack(side="left")
        ttk.Label(parent, text="Cocher = rejouer ; IP[:port] cible ; « + client » = fan-out :",
                  padding=(0, 2)).pack(anchor="w")

        mid = ttk.Frame(parent)
        mid.pack(fill="both", expand=True)
        canvas = tk.Canvas(mid, highlightthickness=0)
        sb = ttk.Scrollbar(mid, orient="vertical", command=canvas.yview)
        self.rows_frame = ttk.Frame(canvas)
        self.rows_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.rows_frame, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        ctl = ttk.Frame(parent, padding=(0, 6))
        ctl.pack(fill="x")
        ttk.Label(ctl, text="Vitesse :").pack(side="left")
        self.speed_var = tk.StringVar(value=SPEEDS[0][0])
        ttk.Combobox(ctl, textvariable=self.speed_var, values=[s[0] for s in SPEEDS],
                     width=14, state="readonly").pack(side="left", padx=4)
        self.loop_var = tk.BooleanVar()
        ttk.Checkbutton(ctl, text="Boucle", variable=self.loop_var).pack(side="left", padx=6)
        self.drop_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Ignorer flux non cochés", variable=self.drop_var).pack(side="left", padx=6)
        self.start_btn = ttk.Button(ctl, text="▶ Start", command=self._start)
        self.start_btn.pack(side="left", padx=(16, 2))
        self.stop_btn = ttk.Button(ctl, text="■ Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=2)

        self.log = scrolledtext.ScrolledText(parent, height=7, font=("Consolas", 9))
        self.log.pack(fill="both", expand=False, pady=(4, 0))

    # ── Onglet GMTI → Pistes ─────────────────────────────────────────────
    def _build_gmti_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="1. Décoder GMTI", command=self._decode_gmti).pack(side="left")
        ttk.Label(bar, text="Profil :").pack(side="left", padx=(12, 2))
        self.profile_var = tk.StringVar(value="maritime")
        ttk.Combobox(bar, textvariable=self.profile_var, values=PROFILE_NAMES,
                     width=12, state="readonly").pack(side="left")
        self.track_btn = ttk.Button(bar, text="2. Lancer le tracker", command=self._run_tracker)
        self.track_btn.pack(side="left", padx=8)
        self.raw_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="plots bruts", variable=self.raw_var,
                        command=self._toggle_view).pack(side="left", padx=6)
        self.smooth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="lissage RTS", variable=self.smooth_var,
                        command=self._toggle_view).pack(side="left", padx=2)
        ttk.Button(bar, text="Ajuster la vue", command=self._fit_view).pack(side="left", padx=6)
        self.gmti_bm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Fond ArcGIS", variable=self.gmti_bm_var,
                        command=lambda: self._toggle_basemap(self.track_canvas, self.gmti_bm_var)).pack(side="left")

        self.gmti_status = tk.StringVar(value="Décoder le GMTI d'un pcap, puis lancer le tracker.")
        ttk.Label(parent, textvariable=self.gmti_status, padding=(0, 2),
                  font=("Consolas", 9)).pack(anchor="w")
        self.track_canvas = TrackCanvas(parent)
        self.track_canvas.pack(fill="both", expand=True)

    # ── Actions communes ─────────────────────────────────────────────────
    # ── Onglet Inventaire 4607 ───────────────────────────────────────────
    def _build_inventaire_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser (inventaire 4607)", command=self._inventaire).pack(side="left")
        ttk.Label(bar, text="Ce que le vecteur émet : segments, présence des champs, "
                  "plages, classifications, job def, porteur.", padding=(8, 0)).pack(side="left")
        self.inv_text = scrolledtext.ScrolledText(parent, font=("Consolas", 9), wrap="none")
        self.inv_text.pack(fill="both", expand=True)

    def _inventaire(self):
        path = self._valid_path()
        if not path:
            return
        if _is_pcapng(path):
            messagebox.showinfo("Inventaire", "L'inventaire complet lit le pcap CLASSIQUE.\n"
                                "Convertis le pcapng :  editcap -F pcap in.pcapng out.pcap")
            return
        if os.path.getsize(path) > EXTRACT_MAX_BYTES and not messagebox.askyesno(
                "Inventaire", "Fichier volumineux : l'inventaire lit tout en mémoire. Continuer ?"):
            return
        self.inv_text.delete("1.0", "end")
        self.inv_text.insert("end", "Analyse en cours…\n")
        threading.Thread(target=self._inventaire_worker, args=(path,), daemon=True).start()

    def _inventaire_worker(self, path):
        try:
            ex = load_extract()
            sink = ex.extract(path)
            self.sink = sink
            self.q.put(("inventaire", ex.rapport(sink)))
        except Exception as e:
            self.q.put(("inventaire", "Inventaire échoué : %s" % e))

    # ── Onglet Vue d'ensemble ────────────────────────────────────────────
    def _build_overview_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser le pcap", command=self._analyze_overview).pack(side="left")
        ttk.Label(bar, text="Détecte les protocoles présents et leur port. "
                  "Double-clic sur une ligne → ouvre l'onglet dédié.", padding=(8, 0)).pack(side="left")
        self.ov_status = tk.StringVar(value="Choisis un pcap et lance l'analyse.")
        ttk.Label(parent, textvariable=self.ov_status, padding=(0, 2), font=("Consolas", 9)).pack(anchor="w")
        cols = ("proto", "port", "protocole", "paquets", "octets")
        self.ov_tree = ttk.Treeview(parent, columns=cols, show="headings", height=16)
        for c, w in (("proto", 60), ("port", 70), ("protocole", 220), ("paquets", 90), ("octets", 110)):
            self.ov_tree.heading(c, text=c)
            self.ov_tree.column(c, width=w, stretch=(c == "protocole"))
        self.ov_tree.pack(fill="both", expand=True)
        self.ov_tree.bind("<Double-1>", self._overview_open)

    def _analyze_overview(self):
        path = self._valid_path()
        if not path:
            return
        self.ov_status.set("Analyse en cours…")
        threading.Thread(target=self._overview_worker, args=(path, self._limit()), daemon=True).start()

    def _overview_worker(self, path, limit):
        try:
            res = pcap_analyze.scan(path, limit)
            self.q.put(("overview", pcap_analyze.port_rows(res["ports"]), res))
        except Exception as e:
            self.q.put(("ov_status", "Analyse échouée : %s" % e))

    def _populate_overview(self, rows, res):
        self.ov_tree.delete(*self.ov_tree.get_children())
        apps = []
        for proto, dport, dominant, pkts, nbytes, dsts in rows:
            self.ov_tree.insert("", "end", values=(proto, dport, dominant, pkts, nbytes))
            if is_app_proto(dominant):
                apps.append(dominant.split("/")[0].split("-")[0])
        uniq = ", ".join(sorted(set(apps))) or "aucun protocole applicatif reconnu"
        self.ov_status.set("%d paquets, %d ports. Protocoles : %s"
                           % (res["npkt"], len(rows), uniq))

    def _overview_open(self, _e):
        sel = self.ov_tree.selection()
        if not sel:
            return
        proto, port, dominant, *_ = self.ov_tree.item(sel[0], "values")
        if dominant.startswith("GMTI"):
            self.nb.select(self.tab_gmti)
        elif dominant.startswith("CoT"):
            self.nb.select(self.tab_cot)
        elif dominant.startswith("MPEG"):
            self.video_port.set(str(port))
            self.nb.select(self.tab_video)
        else:
            self.nb.select(self.tab_replay)

    # ── Onglet Vidéo 4609 ────────────────────────────────────────────────
    def _build_video_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser vidéo 4609", command=self._analyze_video).pack(side="left")
        ttk.Label(bar, text="port :").pack(side="left", padx=(10, 2))
        self.video_port = tk.StringVar()
        ttk.Combobox(bar, textvariable=self.video_port, width=8, values=[]).pack(side="left")
        self.video_port_cb = bar.winfo_children()[-1]
        ttk.Button(bar, text="Extraire .ts + ouvrir", command=self._extract_video).pack(side="left", padx=8)
        self.video_status = tk.StringVar(value="Analyser la vidéo 4609 (MPEG-TS + KLV MISB 0601). "
                                         "La lecture ouvre le .ts dans le lecteur système.")
        ttk.Label(parent, textvariable=self.video_status, padding=(0, 2), font=("Consolas", 9)).pack(anchor="w")
        self.video_text = scrolledtext.ScrolledText(parent, font=("Consolas", 9), wrap="none")
        self.video_text.pack(fill="both", expand=True)

    def _analyze_video(self):
        if video4609 is None:
            messagebox.showerror("Vidéo", "video4609 indisponible."); return
        path = self._valid_path()
        if not path:
            return
        self.video_status.set("Analyse vidéo en cours…")
        self.video_text.delete("1.0", "end"); self.video_text.insert("end", "Analyse en cours…\n")
        threading.Thread(target=self._video_worker, args=(path, self._limit()), daemon=True).start()

    def _video_worker(self, path, limit):
        try:
            infos = video4609.inspect(path, None, limit)
            self.q.put(("video", infos, video4609._report(infos)))
        except Exception as e:
            self.q.put(("video_status", "Analyse vidéo échouée : %s" % e))

    def _extract_video(self):
        if video4609 is None:
            return
        path = self._valid_path()
        if not path:
            return
        try:
            dport = int(self.video_port.get())
        except ValueError:
            messagebox.showwarning("Vidéo", "Analyse d'abord, puis choisis un port de flux vidéo."); return
        out = filedialog.asksaveasfilename(defaultextension=".ts", initialfile="flux_%d.ts" % dport,
                                           filetypes=[("MPEG-TS", "*.ts")])
        if not out:
            return
        self.video_status.set("Extraction du flux %d…" % dport)
        threading.Thread(target=self._extract_worker, args=(path, dport, out, self._limit()), daemon=True).start()

    def _extract_worker(self, path, dport, out, limit):
        try:
            n = video4609.extract_ts(path, dport, out, None, limit)
            self.q.put(("video_status", "TS écrit : %s (%.1f Mo) — ouverture…" % (out, n / 1e6)))
            try:
                os.startfile(out)   # lecteur système (Windows)
            except AttributeError:
                self.q.put(("video_status", "TS écrit : %s — ouvre-le dans VLC/ffplay." % out))
        except Exception as e:
            self.q.put(("video_status", "Extraction échouée : %s" % e))

    # ── Onglet CoT ───────────────────────────────────────────────────────
    def _build_cot_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser CoT", command=self._analyze_cot).pack(side="left")
        ttk.Label(bar, text="filtre type :").pack(side="left", padx=(10, 2))
        self.cot_filter = tk.StringVar()
        ttk.Entry(bar, textvariable=self.cot_filter, width=12).pack(side="left")
        self.cot_tracks_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="trace par uid", variable=self.cot_tracks_var,
                        command=self._cot_toggle_tracks).pack(side="left", padx=8)
        ttk.Button(bar, text="Ajuster la vue", command=self._cot_fit).pack(side="left")
        self.cot_bm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Fond ArcGIS", variable=self.cot_bm_var,
                        command=lambda: self._toggle_basemap(self.cot_canvas, self.cot_bm_var)).pack(side="left", padx=6)

        self.cot_status = tk.StringVar(value="Analyser le CoT d'un pcap (events, affiliations, positions).")
        ttk.Label(parent, textvariable=self.cot_status, padding=(0, 2),
                  font=("Consolas", 9)).pack(anchor="w")

        pan = ttk.Panedwindow(parent, orient="horizontal")
        pan.pack(fill="both", expand=True)
        left = ttk.Frame(pan)
        cols = ("uid", "type", "aff", "callsign")
        self.cot_tree = ttk.Treeview(left, columns=cols, show="headings", height=12)
        for c, w in (("uid", 130), ("type", 110), ("aff", 70), ("callsign", 90)):
            self.cot_tree.heading(c, text=c)
            self.cot_tree.column(c, width=w, stretch=False)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.cot_tree.yview)
        self.cot_tree.configure(yscrollcommand=sb.set)
        self.cot_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.cot_tree.bind("<<TreeviewSelect>>", self._cot_select)
        right = ttk.Frame(pan)
        self.cot_canvas = CotCanvas(right)
        self.cot_canvas.pack(fill="both", expand=True)
        pan.add(left, weight=0)
        pan.add(right, weight=1)

        self.cot_detail = scrolledtext.ScrolledText(parent, height=8, font=("Consolas", 9))
        self.cot_detail.pack(fill="both", expand=False, pady=(4, 0))

    def _analyze_cot(self):
        if cot_extract is None:
            messagebox.showerror("CoT", "cot_extract indisponible."); return
        path = self._valid_path()
        if not path:
            return
        self.cot_status.set("Analyse CoT en cours…")
        flt = self.cot_filter.get().strip() or None
        threading.Thread(target=self._cot_worker, args=(path, flt), daemon=True).start()

    def _cot_worker(self, path, flt):
        try:
            res = cot_extract.scan_cot(path, flt)
        except Exception as e:
            self.q.put(("cot_status", "Analyse CoT échouée : %s" % e)); return
        rows = res["rows"]
        # Repère ENU depuis la 1re position valide.
        lat0 = lon0 = None
        for r in rows.values():
            la, lo = cot_extract._fnum(r["lat"]), cot_extract._fnum(r["lon"])
            if la is not None and lo is not None and not (la == 0 and lo == 0):
                lat0, lon0 = la, lo; break
        points, uid_tracks = [], []
        frame = None
        if lat0 is not None:
            frame = GeoFrame(lat0, lon0)
            for uid, r in rows.items():
                la, lo = cot_extract._fnum(r["lat"]), cot_extract._fnum(r["lon"])
                if la is None or lo is None or (la == 0 and lo == 0):
                    continue
                points.append((*frame.to_xy(la, lo), r["affiliation"], uid))
            for uid, tr in res["tracks"].items():
                if len(tr) >= 2:
                    uid_tracks.append([frame.to_xy(la, lo) for (_t, la, lo) in tr])
        self.q.put(("cot", res, points, uid_tracks, frame))

    def _cot_select(self, _e):
        sel = self.cot_tree.selection()
        if not sel or not self._cot_rows:
            return
        uid = self.cot_tree.item(sel[0], "values")[0]
        row = self._cot_rows.get(uid)
        if not row:
            return
        self.cot_detail.delete("1.0", "end")
        for k in ("uid", "type", "type_description", "affiliation", "dimension",
                  "sidc_algo", "callsign", "how", "lat", "lon", "hae", "ce", "le",
                  "course", "speed", "time", "src", "track_number"):
            v = row.get(k)
            if v not in (None, ""):
                self.cot_detail.insert("end", "%-18s = %s\n" % (k, v))

    def _cot_toggle_tracks(self):
        self.cot_canvas.show_tracks = self.cot_tracks_var.get()
        self.cot_canvas.redraw()

    def _cot_fit(self):
        self.cot_canvas.fit(); self.cot_canvas.redraw()

    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[("Captures", "*.pcap *.pcapng *.cap"), ("Tous", "*.*")])
        if p:
            self.path_var.set(p)
            self.gmti_csv = None
            self.sink = None

    def _limit(self):
        try:
            return max(0, int(self.limit_var.get()))
        except ValueError:
            return 0

    def _valid_path(self):
        p = self.path_var.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showerror("Fichier", "Sélectionne un fichier pcap valide.")
            return None
        return p

    # ── Rejeu ────────────────────────────────────────────────────────────
    def _analyze(self):
        path = self._valid_path()
        if not path:
            return
        self.status_var.set("Analyse en cours…")
        threading.Thread(target=self._analyze_worker, args=(path, self._limit()), daemon=True).start()

    def _analyze_worker(self, path, limit):
        try:
            res = pcap_analyze.scan(path, limit)
            self.q.put(("analyzed", pcap_analyze.port_rows(res["ports"]), res))
        except Exception as e:
            self.q.put(("error", "Analyse échouée : %s" % e))

    def _populate(self, rows, res):
        for r in self.rows:
            r.frame.destroy()
        self.rows = []
        for proto, dport, dominant, pkts, nbytes, dsts in rows:
            row = FlowRow(self.rows_frame, proto, dport, dominant, pkts, dsts[0] if dsts else "")
            row.pack()
            self.rows.append(row)
        n_app = sum(1 for r in rows if is_app_proto(r[2]))
        self.status_var.set("Analyse : %d paquets, %d ports, %d protocole(s) applicatif(s)."
                            % (res["npkt"], len(rows), n_app))

    def _make_args(self):
        speed = dict(SPEEDS)[self.speed_var.get()]
        return types.SimpleNamespace(target=None, target_port=None, speed=speed,
                                     precise=False, loop=self.loop_var.get(),
                                     rebase_time=False, drop_unmatched=self.drop_var.get())

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        path = self._valid_path()
        if not path:
            return
        specs = build_route_specs([s for s in (r.selection() for r in self.rows) if s])
        if not specs:
            messagebox.showwarning("Routage", "Coche au moins un flux et renseigne une cible IP[:port].")
            return
        try:
            table = pcap_replay.parse_routes(specs)
        except ValueError as e:
            messagebox.showerror("Routage", str(e))
            return
        self.log.delete("1.0", "end")
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.worker = threading.Thread(target=self._replay_worker,
                                       args=(path, self._make_args(), table), daemon=True)
        self.worker.start()

    def _replay_worker(self, path, args, table):
        try:
            pcap_replay.do_routed_replay(
                path, args, table,
                should_stop=self.stop_event.is_set,
                on_progress=lambda sent, passes: self.q.put(("progress", sent, passes)),
                log=lambda m: self.q.put(("log", m)))
        except Exception as e:
            self.q.put(("log", "ERREUR : %s" % e))
        finally:
            self.q.put(("done",))

    def _stop(self):
        self.stop_event.set()
        self.status_var.set("Arrêt demandé…")

    # ── GMTI → Pistes ────────────────────────────────────────────────────
    def _decode_gmti(self):
        if gmti_pcap_to_csv is None:
            messagebox.showerror("GMTI", "gmti_pcap_to_csv indisponible.")
            return
        path = self._valid_path()
        if not path:
            return
        out = os.path.join(tempfile.gettempdir(), "pcap_console_gmti_plots.csv")
        self.gmti_status.set("Décodage GMTI…")
        threading.Thread(target=self._decode_worker, args=(path, out, self._limit()), daemon=True).start()

    def _decode_worker(self, path, out, limit):
        # 1) Décodeur complet (pcap classique, taille raisonnable) -> Sink riche
        #    (overlays zone/porteur + classification + hauteur).
        if not _is_pcapng(path) and os.path.getsize(path) <= EXTRACT_MAX_BYTES:
            try:
                ex = load_extract()
                sink = ex.extract(path)
                if sink.plots:
                    ex.write_csv(sink, out)
                    self.sink = sink
                    self.gmti_csv = out
                    self.q.put(("gmti_status", "GMTI décodé (extracteur complet) : %d plots, "
                                "%d dwells. Profil + Lancer le tracker." % (len(sink.plots), sink.dwell_count)))
                    return
            except Exception:
                pass   # repli ci-dessous
        # 2) Repli STREAMING (pcapng / gros fichier / extracteur KO) — sans overlays.
        self.sink = None
        if gmti_pcap_to_csv is None:
            self.q.put(("gmti_status", "Aucun décodeur GMTI disponible.")); return
        try:
            rc = gmti_pcap_to_csv.export(path, out, None, limit)
            if rc != 0:
                self.q.put(("gmti_status", "Aucun flux GMTI détecté dans ce pcap.")); return
            with open(out, encoding="utf-8") as f:
                n = max(0, sum(1 for _ in f) - 1)
            self.gmti_csv = out
            self.q.put(("gmti_status", "GMTI décodé (streaming) : %d plots. "
                        "(overlays zone/porteur indisponibles en repli)" % n))
        except Exception as e:
            self.q.put(("gmti_status", "Décodage GMTI échoué : %s" % e))

    def _run_tracker(self):
        if not self.gmti_csv or not os.path.isfile(self.gmti_csv):
            # décoder d'abord, puis relancer automatiquement
            self._decode_gmti()
            self.after(400, self._run_tracker_if_ready)
            return
        self._launch_tracker()

    def _run_tracker_if_ready(self):
        if self.gmti_csv and os.path.isfile(self.gmti_csv):
            self._launch_tracker()
        else:
            self.after(400, self._run_tracker_if_ready)

    def _launch_tracker(self):
        profile = self.profile_var.get()
        self.gmti_status.set("Tracker en cours (profil %s)…" % profile)
        self.track_btn.config(state="disabled")
        threading.Thread(target=self._tracker_worker, args=(self.gmti_csv, profile), daemon=True).start()

    def _tracker_worker(self, csv_path, profile):
        try:
            tr = load_track_run()
        except Exception as e:
            self.q.put(("track_err", "Tracker indisponible : %s\n(installe numpy + scipy)" % e)); return
        try:
            res = tr.run_tracking(csv_path, profile)
            self.q.put(("tracked", res, profile))
        except Exception as e:
            self.q.put(("track_err", "Tracker échoué : %s" % e))

    def _populate_cot(self, res, points, uid_tracks, frame=None):
        self._cot_rows = res["rows"]
        self.cot_tree.delete(*self.cot_tree.get_children())
        for uid, r in sorted(res["rows"].items()):
            self.cot_tree.insert("", "end", values=(uid, r["type"], r["affiliation"], r.get("callsign") or ""))
        self.cot_canvas.show_tracks = self.cot_tracks_var.get()
        self.cot_canvas.set_cot(points, uid_tracks, frame=frame, fit=True)
        # Inventaire des types dans le panneau détail (avant sélection).
        self.cot_detail.delete("1.0", "end")
        self.cot_detail.insert("end", "INVENTAIRE CoT — %d events, %d types, %d objets (malformés %d)\n\n"
                               % (res["kept"], len(res["types"]), len(res["rows"]), res["malformed"]))
        self.cot_detail.insert("end", "%-24s %6s  %-14s %s\n" % ("type", "count", "affiliation", "dim"))
        for t, n in res["types"].most_common():
            self.cot_detail.insert("end", "%-24s %6d  %-14s %s\n"
                                   % (t, n, cot_extract.affiliation(t), cot_extract.dimension(t)))
        self.cot_status.set("CoT : %d events, %d types, %d objets positionnés."
                            % (res["kept"], len(res["types"]), len(points)))

    # ── Fond de carte ArcGIS ─────────────────────────────────────────────
    def _toggle_basemap(self, canvas, var):
        if arcgis_basemap is None or not self.basemap_cfg:
            messagebox.showwarning("Fond de carte", "Module arcgis_basemap indisponible.")
            var.set(False); return
        canvas.basemap_enabled = var.get()
        if not canvas.basemap_enabled:
            canvas.basemap_photo = None
            canvas.redraw()
        else:
            self._basemap_for(canvas)

    def _basemap_for(self, canvas):
        if not (canvas.geo_frame and canvas.basemap_enabled and self.basemap_cfg):
            return
        W = max(canvas.winfo_width(), 2); H = max(canvas.winfo_height(), 2)
        corners = [canvas.geo_frame.to_ll(*canvas.s2w(sx, sy))
                   for sx, sy in ((0, 0), (W, 0), (0, H), (W, H))]
        lats = [c[0] for c in corners]; lons = [c[1] for c in corners]
        bbox = (min(lons), min(lats), max(lons), max(lats))
        url = arcgis_basemap.export_url(self.basemap_cfg["url"], *bbox, W, H, self.basemap_cfg["token"])
        threading.Thread(target=self._bm_worker, args=(canvas, url, bbox), daemon=True).start()

    def _bm_worker(self, canvas, url, bbox):
        try:
            png = arcgis_basemap.fetch_png(url, self.basemap_cfg.get("insecure", True))
            self.after(0, lambda: canvas.apply_basemap(png, bbox))
        except Exception as e:
            if not self._bm_failed:
                self._bm_failed = True
                self.after(0, lambda: messagebox.showwarning(
                    "Fond de carte", "Fond ArcGIS indisponible :\n%s\n\n"
                    "Le graticule reste affiché. Vérifie l'URL/token dans basemap.json." % e))

    def _overlays(self, res):
        """Construit (raw_coloré, zone_job, trajet_porteur) depuis le Sink de
        l'extracteur, projetés dans le repère ENU du run. Sans Sink : raw brut."""
        frame = res.get("frame")
        if self.sink is None or frame is None:
            return res["raw"], [], []
        raw = []
        for d, t, (la, lo) in self.sink.plots:
            x, y = frame.to_xy(la, lo)
            c = t.get("classification")
            raw.append((x, y, int(c)) if c is not None else (x, y))
        zone = []
        for j in self.sink.jobdefs:
            ba = j.get("bounding_area") or []
            if len(ba) >= 3 and any(abs(a) + abs(b) > 1e-6 for a, b in ba):
                zone = [frame.to_xy(la, lo) for la, lo in ba]
                break
        porteur = [frame.to_xy(la, lo) for (la, lo) in self.sink.platlocs]
        return raw, zone, porteur

    def _toggle_view(self):
        self.track_canvas.show_raw = self.raw_var.get()
        self.track_canvas.show_smooth = self.smooth_var.get()
        self.track_canvas.redraw()

    def _fit_view(self):
        self.track_canvas.fit()
        self.track_canvas.redraw()

    # ── Pompe file -> UI (thread-safe) ───────────────────────────────────
    def _pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "analyzed":
                    self._populate(msg[1], msg[2])
                elif kind == "progress":
                    self.status_var.set("Rejeu : %d messages routés · passe %d" % (msg[1], msg[2]))
                elif kind == "log":
                    self.log.insert("end", msg[1] + "\n"); self.log.see("end")
                elif kind == "error":
                    self.status_var.set(msg[1]); messagebox.showerror("Erreur", msg[1])
                elif kind == "done":
                    self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled")
                    self.status_var.set(self.status_var.get() + "  — terminé.")
                elif kind == "gmti_status":
                    self.gmti_status.set(msg[1])
                elif kind == "tracked":
                    res, profile = msg[1], msg[2]
                    raw, zone, porteur = self._overlays(res)
                    self.track_canvas.show_raw = self.raw_var.get()
                    self.track_canvas.show_smooth = self.smooth_var.get()
                    self.track_canvas.set_data(raw, res["tracks"], zone=zone, porteur=porteur,
                                               frame=res.get("frame"), fit=True)
                    extra = ""
                    if zone:
                        extra += " · zone job"
                    if porteur:
                        extra += " · porteur %d pos" % len(porteur)
                    self.gmti_status.set("Profil %s : %d pistes, %d rejetées (%d plots)%s."
                                        % (profile, res["n_kept"], res["n_rejected"], len(res["raw"]), extra))
                    self.track_btn.config(state="normal")
                elif kind == "inventaire":
                    self.inv_text.delete("1.0", "end"); self.inv_text.insert("end", msg[1])
                elif kind == "cot_status":
                    self.cot_status.set(msg[1])
                elif kind == "cot":
                    self._populate_cot(msg[1], msg[2], msg[3], msg[4])
                elif kind == "ov_status":
                    self.ov_status.set(msg[1])
                elif kind == "overview":
                    self._populate_overview(msg[1], msg[2])
                elif kind == "video_status":
                    self.video_status.set(msg[1])
                elif kind == "video":
                    infos, report = msg[1], msg[2]
                    self.video_text.delete("1.0", "end"); self.video_text.insert("end", report)
                    ports = [str(i["dport"]) for i in infos]
                    self.video_port_cb.configure(values=ports)
                    if ports and not self.video_port.get():
                        self.video_port.set(ports[0])
                    nk = sum(1 for i in infos if i.get("klv"))
                    self.video_status.set("Vidéo : %d flux TS, %d avec KLV décodé." % (len(infos), nk))
                elif kind == "track_err":
                    self.gmti_status.set(msg[1]); self.track_btn.config(state="normal")
                    messagebox.showerror("Tracker", msg[1])
        except queue.Empty:
            pass
        self.after(150, self._pump)


if __name__ == "__main__":
    Console().mainloop()
