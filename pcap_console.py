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

Thème : sombre par défaut via sv_ttk (pip install sv-ttk, optionnel) avec fallback
ttk `clam` sombre intégré ; F2 / bouton ☾☀ bascule sombre ↔ clair (voir apply_theme).
"""
import base64
import importlib
import importlib.util
import json
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
try:
    import sv_ttk            # noqa: E402  thème sombre « Sun Valley » (optionnel : pip install sv-ttk)
except Exception:
    sv_ttk = None

# Palette sombre partagée (alignée sur sv_ttk dark + canvas géo).
UI_BG = "#1c1c1c"          # fond fenêtre sv_ttk dark
UI_PANEL = "#0e1216"       # zones texte / canvas (déjà utilisé par les canvas géo)
UI_FG = "#e6edf3"
UI_MUTED = "#8a8f98"
UI_ACCENT = "#00c8ff"
MONO_FONT = ("Consolas", -13)   # taille en px : cohérent avec les polices sv_ttk (px) quel que soit le DPI


UI_LIGHT = {"bg": "#fafafa", "panel": "#ffffff", "fg": "#1b1b1b", "muted": "#6b7280"}
UI_DARK = {"bg": UI_BG, "panel": UI_PANEL, "fg": UI_FG, "muted": UI_MUTED}


def apply_theme(root, mode="dark"):
    """Applique le thème (« dark » ou « light ») : sv_ttk si installé, sinon fallback ttk
    `clam` recoloré. Les widgets tk non-ttk (ScrolledText, Canvas) sont recolorés via
    option_add (pris en compte pour les widgets créés ensuite) — pour un changement à
    chaud, `Console._retheme_text_widgets` repasse sur les widgets existants."""
    pal = UI_DARK if mode == "dark" else UI_LIGHT
    st = ttk.Style(root)
    if sv_ttk is not None:
        sv_ttk.set_theme(mode)
    else:
        st.theme_use("clam")
        field = pal["panel"]
        st.configure(".", background=pal["bg"], foreground=pal["fg"], fieldbackground=field,
                     bordercolor="#333" if mode == "dark" else "#c8c8c8",
                     troughcolor=pal["bg"], selectbackground=UI_ACCENT)
        st.configure("TNotebook", background=pal["bg"], borderwidth=0)
        st.configure("TNotebook.Tab", background=pal["bg"], padding=(10, 5))
        st.map("TNotebook.Tab", background=[("selected", "#2a2f36" if mode == "dark" else "#e4e4e4")])
        st.configure("Treeview", background=field, fieldbackground=field, foreground=pal["fg"])
        st.configure("Treeview.Heading", background="#2a2f36" if mode == "dark" else "#e4e4e4",
                     foreground=pal["fg"])
        st.configure("Accent.TButton", background=UI_ACCENT, foreground="#000")
        root.configure(bg=pal["bg"])
    # Boutons d'action : Start en accent (sv_ttk fournit Accent.TButton), Stop en rouge.
    st.configure("Stop.TButton", foreground="#ff5252")
    st.configure("Status.TLabel", foreground=pal["muted"], font=MONO_FONT)
    st.configure("Muted.TLabel", foreground=pal["muted"])
    # Bandeau d'en-tête : titre en accent + sous-titre atténué (fond = fond fenêtre,
    # sv_ttk ne repeint pas le fond des TFrame ; un Separator délimite le bandeau).
    st.configure("HeaderTitle.TLabel", foreground=UI_ACCENT, font=("Segoe UI Semibold", 12))
    st.configure("HeaderSub.TLabel", foreground=pal["muted"])
    # Widgets tk classiques (ScrolledText…) : fond panneau, texte clair, curseur clair.
    for opt, val in (("*Text.background", pal["panel"]), ("*Text.foreground", pal["fg"]),
                     ("*Text.insertBackground", pal["fg"]), ("*Text.selectBackground", "#264f78"),
                     ("*Text.borderWidth", 0), ("*Text.highlightThickness", 0),
                     ("*Canvas.background", pal["bg"])):
        root.option_add(opt, val)
    return pal

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
MAX_DISPLAY_PLOTS = 50000            # plafond de plots dessinés (décimation au-delà)


def _csv_time_span(path):
    """Étendue temporelle (s) du CSV GMTI d'après la colonne 0 dwell_time_ms.
    Renvoie None si illisible/vide. Lecture streaming, ne charge pas tout."""
    tmin = tmax = None
    try:
        with open(path, encoding="utf-8") as f:
            next(f, None)                       # en-tête
            for line in f:
                c = line.split(";", 1)[0]
                if not c:
                    continue
                v = int(c)
                tmin = v if tmin is None else min(tmin, v)
                tmax = v if tmax is None else max(tmax, v)
    except Exception:
        return None
    return (tmax - tmin) / 1000.0 if tmin is not None else None
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


def _version_tuple(suffix):
    """'8' -> (8,) ; '8.1' -> (8,1) ; None si non versionné."""
    parts = suffix.split(".")
    if parts and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return None


def _tracker_dir():
    """Dossier du tracker : la version v<N[.M]> la plus élevée ayant track_run.py
    (gère les versions à point, ex. v8.1 > v8 > v7)."""
    base = os.path.dirname(os.path.abspath(__file__))
    best, best_ver = None, ()
    try:
        for name in os.listdir(base):
            if not name.startswith(TRACKER_PREFIX):
                continue
            ver = _version_tuple(name[len(TRACKER_PREFIX):])
            if (ver and os.path.isdir(os.path.join(base, name))
                    and os.path.isfile(os.path.join(base, name, "track_run.py"))):
                if ver > best_ver:
                    best_ver, best = ver, name
    except OSError:
        pass
    return os.path.join(base, best) if best else os.path.join(base, TRACKER_PREFIX + "7")


def _purge_tracker_paths():
    """Retire de sys.path tout dossier de version tracker (évite qu'un `import
    tracker` interne résolve vers une VIEILLE version restée sur le chemin)."""
    for p in list(sys.path):
        if os.path.basename(p).startswith(TRACKER_PREFIX):
            sys.path.remove(p)


def _load_module_from(path, modname):
    """Charge un module par CHEMIN explicite (pas de cache sys.modules périmé) :
    re-exécute à chaque appel -> une nouvelle version déposée est bien prise."""
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def load_track_run():
    """Import LAZY du noyau tracker (numpy+scipy) par chemin explicite.

    Charge `tracker.py` AVANT `track_run.py` (qui fait `import tracker`) en
    l'injectant dans sys.modules — plus sous un nom qualifié par version pour
    tracer. Purge d'abord sys.path des anciennes versions."""
    d = _tracker_dir()
    _purge_tracker_paths()
    qual = os.path.basename(d).replace(".", "_").replace("-", "_")
    tracker_mod = _load_module_from(os.path.join(d, "tracker.py"), "tracker")
    sys.modules["%s_tracker" % qual] = tracker_mod       # nom qualifié (traçabilité)
    return _load_module_from(os.path.join(d, "track_run.py"), "track_run")


def load_extract():
    """Import LAZY de l'extracteur 4607 (pur Python) par chemin explicite.
    (Il fait `from pcap_frames import …` : la racine Tools reste sur sys.path.)"""
    d = _tracker_dir()
    _purge_tracker_paths()
    return _load_module_from(os.path.join(d, "stanag4607_extract.py"), "stanag4607_extract")


def tracker_version():
    """Nom de la version de tracker qui sera chargée (ex. 'v8.1')."""
    return os.path.basename(_tracker_dir())[len("prototype_tracker_gmti_"):]


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
        self._decim_step = 1
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
            step = self._decim(len(self.raw))       # décimation si trop de plots
            for p in self.raw[::step]:
                sx, sy = self.w2s(p[0], p[1])
                col = CLASS_COLORS.get(p[2], CLASS_DEFAULT) if len(p) > 2 else "#59636f"
                self.create_rectangle(sx, sy, sx + 1, sy + 1, outline=col)
        for i, tr in enumerate(self.tracks):
            # v8+ : rotateur fixe (probable éolienne) grisé ; candidat aérien violet.
            if tr.get("is_rotator"):
                col, tag = "#6b7280", " ⊗"
            elif tr.get("is_air"):
                col, tag = "#b388ff", " ✈"
            else:
                col, tag = PALETTE[i % len(PALETTE)], ""
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
                self.create_text(ex + 8, ey, text="#%d%s" % (tr["id"], tag), anchor="w",
                                 fill=col, font=("Consolas", 8))
        # échelle
        self._draw_scalebar()

    def _decim(self, n):
        """Pas de décimation d'AFFICHAGE des plots pour rester sous ~50 000 items
        (les pistes ne sont jamais décimées). Renvoie N (1 = pas de décimation)."""
        step = (n // MAX_DISPLAY_PLOTS) + 1 if n > MAX_DISPLAY_PLOTS else 1
        self._decim_step = step
        return step

    def _draw_scalebar(self):
        if self.scale <= 0:
            return
        target_px = 90
        world = target_px / self.scale
        nice = 10 ** int(round(math.log10(max(world, 1e-6))))
        for m in (1, 2, 5, 10):
            if nice * m >= world:
                nice = nice * m
                break
        px = nice * self.scale
        H = self.winfo_height()
        x0, y0 = 12, H - 16
        self.create_line(x0, y0, x0 + px, y0, fill="#c2c8ce", width=2)
        lbl = ("%g km" % (nice / 1000)) if nice >= 1000 else ("%g m" % nice)
        if getattr(self, "_decim_step", 1) > 1:
            lbl += "  · affichage décimé 1/%d" % self._decim_step
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


# ── Canvas fusionné : GMTI + CoT + empreinte vidéo sur une même carte ───────

class FusedCanvas(TrackCanvas):
    """Superpose plusieurs couches (repère ENU commun) : pistes GMTI, points CoT
    (par affiliation), position capteur vidéo + empreinte au sol. Hérite le
    pan/zoom, le graticule, le fond ArcGIS et la lecture au survol."""

    def __init__(self, parent):
        super().__init__(parent)
        self.layers = {"gmti_tracks": [], "gmti_raw": [], "cot_points": [],
                       "cot_tracks": [], "video_sensor": [], "video_footprints": []}
        self.show_gmti = True
        self.show_cot = True
        self.show_video = True

    def set_fused(self, layers, frame, fit=True):
        self.layers = layers
        self.geo_frame = frame
        if fit:
            self._fit_visible()
        self.redraw()

    def _fit_visible(self):
        """Cadre uniquement sur les couches ACTIVÉES (les flux peuvent être dans
        des zones géographiques différentes)."""
        L = self.layers
        pts = []
        if self.show_gmti:
            for tr in L["gmti_tracks"]:
                pts += tr
            pts += [(p[0], p[1]) for p in L["gmti_raw"]]
        if self.show_cot:
            for tr in L["cot_tracks"]:
                pts += tr
            pts += [(p[0], p[1]) for p in L["cot_points"]]
        if self.show_video:
            pts += L["video_sensor"]
            for sx, sy, fx, fy in L["video_footprints"]:
                pts += [(sx, sy), (fx, fy)]
        self._fit_to(pts)

    def redraw(self):
        self.delete("all")
        L = self.layers
        if not any(L.values()):
            self.create_text(self.winfo_width() / 2, self.winfo_height() / 2,
                             text="(fusionner les couches d'un pcap)", fill="#5a6675",
                             font=("Segoe UI", 11))
            return
        self._draw_basemap()
        self.draw_graticule()
        # Vidéo : empreinte (capteur -> centre image) + position capteur.
        if self.show_video:
            for sx, sy, fx, fy in L["video_footprints"]:
                a = self.w2s(sx, sy); b = self.w2s(fx, fy)
                self.create_line(a[0], a[1], b[0], b[1], fill="#8a8f98", width=1)
            for x, y in L["video_sensor"]:
                sx, sy = self.w2s(x, y)
                self.create_rectangle(sx - 3, sy - 3, sx + 3, sy + 3, fill="#b388ff", outline="#101418")
        # GMTI : plots faibles + pistes ambre.
        if self.show_gmti:
            step = self._decim(len(L["gmti_raw"]))
            for p in L["gmti_raw"][::step]:
                sx, sy = self.w2s(p[0], p[1])
                self.create_rectangle(sx, sy, sx + 1, sy + 1, outline="#59503a")
            for tr in L["gmti_tracks"]:
                if len(tr) >= 2:
                    flat = []
                    for x, y in tr:
                        s = self.w2s(x, y); flat += [s[0], s[1]]
                    self.create_line(*flat, fill="#ffc107", width=2)
        # CoT : points par affiliation + trace.
        if self.show_cot:
            for tr in L["cot_tracks"]:
                if len(tr) >= 2:
                    flat = []
                    for x, y in tr:
                        s = self.w2s(x, y); flat += [s[0], s[1]]
                    self.create_line(*flat, fill="#3a4048", width=1)
            for x, y, affil in L["cot_points"]:
                sx, sy = self.w2s(x, y)
                self.create_oval(sx - 3, sy - 3, sx + 3, sy + 3,
                                 fill=AFFIL_COLORS.get(affil, AFFIL_COLORS[""]), outline="#101418")
        self._draw_scalebar()
        self._fused_legend()

    def _fused_legend(self):
        items = [("Pistes GMTI", "#ffc107"), ("CoT (ami/host/…)", "#00c8ff"),
                 ("Capteur vidéo", "#b388ff")]
        x, y = 12, 14
        for label, col in items:
            self.create_rectangle(x, y - 4, x + 8, y + 4, fill=col, outline="")
            self.create_text(x + 12, y, text=label, anchor="w", fill="#c2c8ce", font=("Consolas", 8))
            x += 130


# ── Ligne de flux (onglet Rejeu) ────────────────────────────────────────────

class FlowRow:
    def __init__(self, parent, proto, dport, dominant, pkts, default_ip):
        self.proto, self.dport, self.dominant, self.pkts = proto, dport, dominant, pkts
        self.replay = tk.BooleanVar(value=is_app_proto(dominant))
        self.frame = ttk.Frame(parent)
        ttk.Checkbutton(self.frame, variable=self.replay).grid(row=0, column=0, padx=(0, 4))
        label = "%s/%-6d %-20s %8d pkts" % (proto.lower(), dport, dominant, pkts)
        ttk.Label(self.frame, text=label, font=MONO_FONT).grid(row=0, column=1, sticky="w")
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
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.rows = []
        self.worker = None
        self.stop_event = threading.Event()
        self.q = queue.Queue()
        self.gmti_csv = None
        self.sink = None            # Sink de l'extracteur (overlays/inventaire), si dispo
        self.fused_export = None     # dernière fusion en WGS84 (export GeoJSON)
        self._cot_rows = {}         # dernières valeurs CoT par uid (field=value)
        self._bm_failed = False     # fond de carte : n'alerter qu'une fois
        self.basemap_cfg = (arcgis_basemap.load_config(os.path.dirname(os.path.abspath(__file__)))
                            if arcgis_basemap else None)
        self.path_var = tk.StringVar()
        self.limit_var = tk.StringVar(value=str(SCAN_LIMIT_DEFAULT))
        self.theme_mode = "dark"
        self.pal = apply_theme(self, self.theme_mode)
        self._build_ui()
        self.bind("<F2>", lambda _e: self._toggle_theme())
        # sv_ttk repeint les widgets tk (tk_setPalette) sur <<ThemeChanged>>, événement
        # asynchrone : on repasse derrière pour garder le fond « panneau » des zones texte.
        self.bind("<<ThemeChanged>>",
                  lambda _e: self.after_idle(self._retheme_text_widgets, self, self.pal), add="+")
        self.after(150, self._pump)

    def _build_ui(self):
        # Bandeau d'en-tête : titre à gauche, sélection du pcap à droite.
        top = ttk.Frame(self, padding=(12, 8))
        top.pack(fill="x")
        ttk.Separator(self).pack(fill="x")
        title = ttk.Frame(top)
        title.pack(side="left", padx=(0, 16))
        ttk.Label(title, text="◉ Console pcap", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(title, text="ISRBOX / 33e ESRA · analyse · rejeu · GMTI · CoT · vidéo",
                  style="HeaderSub.TLabel").pack(anchor="w")
        # Éléments de droite d'abord (pack right), le champ pcap prend l'espace restant.
        self.theme_btn = ttk.Button(top, text="☾", width=3, command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=(12, 0))
        ttk.Label(top, text="F2", style="HeaderSub.TLabel").pack(side="right")
        ttk.Entry(top, textvariable=self.limit_var, width=8).pack(side="right")
        ttk.Label(top, text="limit").pack(side="right", padx=(8, 2))
        ttk.Button(top, text="Parcourir…", command=self._browse).pack(side="right")
        ttk.Label(top, text="Fichier pcap :").pack(side="left")
        ttk.Entry(top, textvariable=self.path_var, width=30).pack(side="left", padx=4, fill="x", expand=True)

        nb = ttk.Notebook(self)
        self.nb = nb
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tab_overview = ttk.Frame(nb)
        self.tab_replay = ttk.Frame(nb)
        self.tab_gmti = ttk.Frame(nb)
        self.tab_cot = ttk.Frame(nb)
        self.tab_video = ttk.Frame(nb)
        self.tab_fused = ttk.Frame(nb)
        nb.add(self.tab_overview, text="  ⌂  Vue d'ensemble  ")
        nb.add(self.tab_replay, text="  ▶  Rejeu  ")
        nb.add(self.tab_gmti, text="  ◎  GMTI → Pistes  ")
        nb.add(self.tab_cot, text="  ✦  CoT  ")
        nb.add(self.tab_video, text="  ▣  Vidéo 4609  ")
        nb.add(self.tab_fused, text="  ⊕  Carte fusionnée  ")
        self._build_overview_tab(self.tab_overview)
        self._build_replay_tab(self.tab_replay)
        self._build_gmti_tab(self.tab_gmti)
        self._build_cot_tab(self.tab_cot)
        self._build_video_tab(self.tab_video)
        self._build_fused_tab(self.tab_fused)

        # Fond de carte ArcGIS piloté par l'app pour les canvas géo.
        for cv in (self.track_canvas, self.cot_canvas, self.fused_canvas):
            cv.request_basemap = self._basemap_for

        self.status_var = tk.StringVar(value="Prêt.  Tracker : %s" % tracker_version())
        ttk.Separator(self).pack(fill="x")
        ttk.Label(self, textvariable=self.status_var, padding=(8, 3),
                  style="Status.TLabel").pack(anchor="w")

    def _toggle_theme(self):
        """Bascule sombre/clair (bouton ☾/☀ ou F2) et repasse sur les widgets tk déjà créés."""
        self.theme_mode = "light" if self.theme_mode == "dark" else "dark"
        self.pal = apply_theme(self, self.theme_mode)
        self.theme_btn.configure(text="☾" if self.theme_mode == "dark" else "☀")
        self._retheme_text_widgets(self, self.pal)

    def _retheme_text_widgets(self, w, pal):
        for c in w.winfo_children():
            if isinstance(c, tk.Text):
                c.configure(bg=pal["panel"], fg=pal["fg"], insertbackground=pal["fg"])
            elif isinstance(c, tk.Canvas) and not isinstance(c, TrackCanvas):
                c.configure(bg=pal["bg"])
            self._retheme_text_widgets(c, pal)

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
        self.start_btn = ttk.Button(ctl, text="▶ Start", command=self._start, style="Accent.TButton")
        self.start_btn.pack(side="left", padx=(16, 2))
        self.stop_btn = ttk.Button(ctl, text="■ Stop", command=self._stop, state="disabled",
                                   style="Stop.TButton")
        self.stop_btn.pack(side="left", padx=2)

        self.log = scrolledtext.ScrolledText(parent, height=7, font=MONO_FONT)
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
                  font=MONO_FONT).pack(anchor="w")

        # Écran partagé (comme l'onglet CoT) : à gauche l'analyse du flux (inventaire
        # 4607), à droite la carte du tracker (plots + pistes).
        pan = ttk.Panedwindow(parent, orient="horizontal")
        pan.pack(fill="both", expand=True)
        left = ttk.Frame(pan, width=420)
        self._build_inventaire_pane(left)
        right = ttk.Frame(pan)
        self.track_canvas = TrackCanvas(right)
        self.track_canvas.pack(fill="both", expand=True)
        pan.add(left, weight=0)
        pan.add(right, weight=1)

    # ── Actions communes ─────────────────────────────────────────────────
    # ── Volet Inventaire 4607 (gauche de l'onglet GMTI) ──────────────────
    def _build_inventaire_pane(self, parent):
        bar = ttk.Frame(parent, padding=(0, 0, 6, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="☰ Inventaire 4607", command=self._inventaire).pack(side="left")
        ttk.Label(bar, text="segments, champs, plages, job def, porteur",
                  style="Muted.TLabel", padding=(8, 0)).pack(side="left")
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True, padx=(0, 6))
        self.inv_text = tk.Text(box, font=MONO_FONT, wrap="none", width=52)
        vsb = ttk.Scrollbar(box, orient="vertical", command=self.inv_text.yview)
        hsb = ttk.Scrollbar(box, orient="horizontal", command=self.inv_text.xview)
        self.inv_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.inv_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        box.rowconfigure(0, weight=1); box.columnconfigure(0, weight=1)
        self.inv_text.insert("end", "Ce que le vecteur émet : segments, présence des champs, "
                             "plages, classifications, job def, porteur.\n\n"
                             "→ « Inventaire 4607 » pour analyser le pcap courant.")

    def _inventaire(self):
        path = self._valid_path()
        if not path:
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
            self.q.put(("inventaire", ex.rapport(sink), sink))   # sink via queue
        except Exception as e:
            self.q.put(("inventaire", "Inventaire échoué : %s" % e, None))

    # ── Onglet Carte fusionnée ───────────────────────────────────────────
    def _build_fused_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Fusionner", command=self._fuse).pack(side="left")
        ttk.Label(bar, text="profil GMTI :").pack(side="left", padx=(10, 2))
        self.fused_profile = tk.StringVar(value="maritime")
        ttk.Combobox(bar, textvariable=self.fused_profile, values=PROFILE_NAMES,
                     width=12, state="readonly").pack(side="left")
        self.f_gmti = tk.BooleanVar(value=True)
        self.f_cot = tk.BooleanVar(value=True)
        self.f_video = tk.BooleanVar(value=True)
        for txt, var in (("GMTI", self.f_gmti), ("CoT", self.f_cot), ("Vidéo", self.f_video)):
            ttk.Checkbutton(bar, text=txt, variable=var,
                            command=self._fused_toggle).pack(side="left", padx=4)
        ttk.Button(bar, text="Ajuster la vue", command=self._fused_fit).pack(side="left", padx=4)
        self.fused_bm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Fond ArcGIS", variable=self.fused_bm_var,
                        command=lambda: self._toggle_basemap(self.fused_canvas, self.fused_bm_var)).pack(side="left")
        self.fused_export_btn = ttk.Button(bar, text="Exporter GeoJSON",
                                           command=self._fused_export, state="disabled")
        self.fused_export_btn.pack(side="left", padx=4)

        self.fused_status = tk.StringVar(value="Fusionne GMTI + CoT + empreinte vidéo sur une carte.")
        ttk.Label(parent, textvariable=self.fused_status, padding=(0, 2), font=MONO_FONT).pack(anchor="w")
        self.fused_canvas = FusedCanvas(parent)
        self.fused_canvas.pack(fill="both", expand=True)

    def _fuse(self):
        path = self._valid_path()
        if not path:
            return
        self.fused_status.set("Fusion en cours (GMTI + CoT + vidéo)…")
        threading.Thread(target=self._fuse_worker,
                         args=(path, self.fused_profile.get(), self._limit()), daemon=True).start()

    def _fuse_worker(self, path, profile, limit):
        latlon = {"gmti_tracks": [], "gmti_raw": [], "cot_points": [],
                  "cot_tracks": [], "video_sensor": [], "video_footprints": []}
        export = {"gmti": [], "cot": []}    # WGS84 (lon,lat) + propriétés, pour GeoJSON
        ref = [None]
        def note(la, lo):
            if ref[0] is None:
                ref[0] = (la, lo)
        parts = []
        # P3.1 : la limite --limit borne GMTI et vidéo (lecture partielle du pcap)
        # mais PAS CoT (scan_cot lit tout) → périmètres temporels potentiellement
        # différents ; on l'annonce et on affiche la fenêtre temps GMTI décodée.
        gmti_span = None
        # GMTI
        try:
            if gmti_pcap_to_csv is not None:
                out = os.path.join(tempfile.gettempdir(), "fused_gmti.csv")
                if gmti_pcap_to_csv.export(path, out, None, limit) == 0:
                    gmti_span = _csv_time_span(out)
                    res = load_track_run().run_tracking(out, profile)
                    fr = res.get("frame")
                    if fr:
                        for t in res["tracks"]:
                            ll = [fr.to_ll(x, y) for x, y in t["pts"]]
                            if ll:
                                note(*ll[0]); latlon["gmti_tracks"].append(ll)
                                export["gmti"].append({
                                    "coords": [(lo, la) for la, lo in ll],
                                    "track_id": t["id"], "etat": t.get("etat", ""),
                                    "aerien": bool(t["is_air"]),
                                    "rotateur": bool(t["is_rotator"]),
                                    "hits": t["hits"]})
                        latlon["gmti_raw"] = [fr.to_ll(x, y) for x, y in res["raw"]]
                        lbl = "GMTI %d pistes" % len(res["tracks"])
                        if gmti_span is not None:
                            lbl += " (0–%.0f s)" % gmti_span
                        parts.append(lbl)
        except Exception as e:
            parts.append("GMTI KO (%s)" % type(e).__name__)
        # CoT
        try:
            if cot_extract is not None:
                r = cot_extract.scan_cot(path)
                for uid, row in r["rows"].items():
                    la, lo = cot_extract._fnum(row["lat"]), cot_extract._fnum(row["lon"])
                    if la is not None and lo is not None and not (la == 0 and lo == 0):
                        note(la, lo); latlon["cot_points"].append((la, lo, row["affiliation"]))
                        export["cot"].append({"lon": lo, "lat": la, "uid": uid,
                                              "affiliation": row["affiliation"]})
                for uid, tr in r["tracks"].items():
                    if len(tr) >= 2:
                        latlon["cot_tracks"].append([(la, lo) for (_t, la, lo) in tr])
                parts.append("CoT %d objets" % len(latlon["cot_points"]))
        except Exception as e:
            parts.append("CoT KO (%s)" % type(e).__name__)
        # Vidéo (KLV : position capteur + empreinte)
        try:
            if video4609 is not None:
                for slat, slon, fclat, fclon in video4609.sensor_samples(path, None, limit):
                    note(slat, slon); latlon["video_sensor"].append((slat, slon))
                    if fclat is not None and fclon is not None:
                        latlon["video_footprints"].append((slat, slon, fclat, fclon))
                if latlon["video_sensor"]:
                    parts.append("vidéo %d pos capteur" % len(latlon["video_sensor"]))
        except Exception as e:
            parts.append("vidéo KO (%s)" % type(e).__name__)

        if limit and limit > 0:
            parts.append("[limite %d pq : GMTI/vidéo bornés, CoT complet — "
                         "périmètres temporels différents]" % limit)

        if ref[0] is None:
            self.q.put(("fused_status", "Aucune donnée géolocalisée à fusionner.")); return
        frame = GeoFrame(*ref[0])
        L = {"gmti_tracks": [[frame.to_xy(la, lo) for la, lo in tr] for tr in latlon["gmti_tracks"]],
             "gmti_raw": [frame.to_xy(la, lo) for la, lo in latlon["gmti_raw"]],
             "cot_points": [(*frame.to_xy(la, lo), aff) for la, lo, aff in latlon["cot_points"]],
             "cot_tracks": [[frame.to_xy(la, lo) for la, lo in tr] for tr in latlon["cot_tracks"]],
             "video_sensor": [frame.to_xy(la, lo) for la, lo in latlon["video_sensor"]],
             "video_footprints": [(*frame.to_xy(sla, slo), *frame.to_xy(fla, flo))
                                  for sla, slo, fla, flo in latlon["video_footprints"]]}
        self.q.put(("fused", L, frame, " · ".join(parts) or "rien", export))

    def _fused_toggle(self):
        self.fused_canvas.show_gmti = self.f_gmti.get()
        self.fused_canvas.show_cot = self.f_cot.get()
        self.fused_canvas.show_video = self.f_video.get()
        self.fused_canvas.redraw()

    def _fused_fit(self):
        self.fused_canvas._fit_visible()
        self.fused_canvas.redraw()

    def _fused_export(self):
        """P3.4 : exporte la dernière fusion en GeoJSON WGS84 (lon,lat).
        Pistes GMTI = LineString (track_id, etat, aerien, rotateur, hits) ;
        objets CoT = Point (uid, affiliation)."""
        exp = self.fused_export
        if not exp or not (exp["gmti"] or exp["cot"]):
            messagebox.showinfo("Export", "Rien à exporter : lance d'abord une fusion.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".geojson",
                                           initialfile="fusion.geojson",
                                           filetypes=[("GeoJSON", "*.geojson *.json"), ("Tous", "*.*")])
        if not out:
            return
        feats = []
        for t in exp["gmti"]:
            if len(t["coords"]) < 2:
                continue
            feats.append({
                "type": "Feature",
                "geometry": {"type": "LineString",
                             "coordinates": [[round(lo, 7), round(la, 7)] for lo, la in t["coords"]]},
                "properties": {"track_id": t["track_id"], "etat": t["etat"],
                               "aerien": t["aerien"], "rotateur": t["rotateur"],
                               "hits": t["hits"]}})
        for c in exp["cot"]:
            feats.append({
                "type": "Feature",
                "geometry": {"type": "Point",
                             "coordinates": [round(c["lon"], 7), round(c["lat"], 7)]},
                "properties": {"uid": c["uid"], "affiliation": c["affiliation"]}})
        fc = {"type": "FeatureCollection",
              "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:OGC:1.3:CRS84"}},
              "features": feats}
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(fc, f, ensure_ascii=False, indent=1)
        except Exception as e:
            messagebox.showerror("Export", "Écriture impossible : %s" % e)
            return
        self.fused_status.set("Export GeoJSON : %d entités → %s" % (len(feats), out))

    # ── Onglet Vue d'ensemble ────────────────────────────────────────────
    def _build_overview_tab(self, parent):
        bar = ttk.Frame(parent, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Analyser le pcap", command=self._analyze_overview).pack(side="left")
        ttk.Label(bar, text="Détecte les protocoles présents et leur port. "
                  "Double-clic sur une ligne → ouvre l'onglet dédié.", padding=(8, 0)).pack(side="left")
        self.ov_status = tk.StringVar(value="Choisis un pcap et lance l'analyse.")
        ttk.Label(parent, textvariable=self.ov_status, padding=(0, 2), font=MONO_FONT).pack(anchor="w")
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
        ttk.Label(parent, textvariable=self.video_status, padding=(0, 2), font=MONO_FONT).pack(anchor="w")
        self.video_text = scrolledtext.ScrolledText(parent, font=MONO_FONT, wrap="none")
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
                  font=MONO_FONT).pack(anchor="w")

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
        for aff, color in AFFIL_COLORS.items():      # lignes colorées comme les symboles carte
            self.cot_tree.tag_configure("aff_%s" % aff, foreground=color)
        right = ttk.Frame(pan)
        self.cot_canvas = CotCanvas(right)
        self.cot_canvas.pack(fill="both", expand=True)
        pan.add(left, weight=0)
        pan.add(right, weight=1)

        self.cot_detail = scrolledtext.ScrolledText(parent, height=8, font=MONO_FONT)
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
        # État (sink, gmti_csv) transmis par la QUEUE, jamais écrit depuis le thread.
        # 1) Décodeur complet (taille raisonnable ; pcap ET pcapng via pcap_frames)
        #    -> Sink riche (overlays zone/porteur + classification + hauteur).
        if os.path.getsize(path) <= EXTRACT_MAX_BYTES:
            try:
                ex = load_extract()
                sink = ex.extract(path)
                if sink.plots:
                    ex.write_csv(sink, out)
                    self.q.put(("gmti_decoded", sink, out,
                                "GMTI décodé (extracteur complet) : %d plots, %d dwells. "
                                "Profil + Lancer le tracker." % (len(sink.plots), sink.dwell_count)))
                    return
            except Exception:
                pass   # repli ci-dessous
        # 2) Repli STREAMING (gros fichier / extracteur KO) — sans overlays.
        if gmti_pcap_to_csv is None:
            self.q.put(("gmti_status", "Aucun décodeur GMTI disponible.")); return
        try:
            rc = gmti_pcap_to_csv.export(path, out, None, limit)
            if rc != 0:
                self.q.put(("gmti_status", "Aucun flux GMTI détecté dans ce pcap.")); return
            with open(out, encoding="utf-8") as f:
                n = max(0, sum(1 for _ in f) - 1)
            self.q.put(("gmti_decoded", None, out, "GMTI décodé (streaming) : %d plots. "
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
            aff = r["affiliation"]
            self.cot_tree.insert("", "end", values=(uid, r["type"], aff, r.get("callsign") or ""),
                                 tags=("aff_%s" % (aff if aff in AFFIL_COLORS else ""),))
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
                elif kind == "gmti_decoded":
                    self.sink = msg[1]; self.gmti_csv = msg[2]; self.gmti_status.set(msg[3])
                elif kind == "inventaire":
                    self.inv_text.delete("1.0", "end"); self.inv_text.insert("end", msg[1])
                    if len(msg) > 2 and msg[2] is not None:
                        self.sink = msg[2]
                elif kind == "cot_status":
                    self.cot_status.set(msg[1])
                elif kind == "cot":
                    self._populate_cot(msg[1], msg[2], msg[3], msg[4])
                elif kind == "ov_status":
                    self.ov_status.set(msg[1])
                elif kind == "fused_status":
                    self.fused_status.set(msg[1])
                elif kind == "fused":
                    L, frame, summary, export = msg[1], msg[2], msg[3], msg[4]
                    self.fused_export = export
                    self.fused_canvas.show_gmti = self.f_gmti.get()
                    self.fused_canvas.show_cot = self.f_cot.get()
                    self.fused_canvas.show_video = self.f_video.get()
                    self.fused_canvas.set_fused(L, frame, fit=True)
                    self.fused_status.set("Fusion : " + summary)
                    self.fused_export_btn.config(
                        state=("normal" if (export["gmti"] or export["cot"]) else "disabled"))
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
