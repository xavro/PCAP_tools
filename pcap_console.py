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
import importlib
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
    import gmti_pcap_to_csv  # noqa: E402
except Exception:
    gmti_pcap_to_csv = None

SPEEDS = [("×1 (temps réel)", 1.0), ("×2", 2.0), ("×5", 5.0), ("×10", 10.0), ("max", 0.0)]
SCAN_LIMIT_DEFAULT = 300000
PROFILE_NAMES = ["defaut", "maritime", "routier", "convoi", "personnel", "aerien"]
PALETTE = ["#ffc107", "#00c8ff", "#7cff6b", "#ff6ec7", "#ff8a3d", "#b388ff",
           "#4dd0e1", "#f06292", "#aed581", "#ff5252"]


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


def load_track_run():
    """Import LAZY du noyau tracker (numpy+scipy). Lève ImportError si absent."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prototype_tracker_gmti_v5")
    if d not in sys.path:
        sys.path.insert(0, d)
    return importlib.import_module("track_run")


# ── Canvas natif : plots + pistes, pan (glisser) / zoom (molette) ────────────

class TrackCanvas(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg="#0e1216", highlightthickness=0)
        self.raw = []
        self.tracks = []
        self.show_raw = True
        self.show_smooth = False
        self.scale = 1.0
        self.cx = 0.0
        self.cy = 0.0
        self._drag = None
        self.bind("<Configure>", lambda e: self.redraw())
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._motion)
        self.bind("<MouseWheel>", self._wheel)          # Windows / macOS
        self.bind("<Button-4>", self._wheel)            # X11 molette haut
        self.bind("<Button-5>", self._wheel)            # X11 molette bas

    def set_data(self, raw, tracks, fit=True):
        self.raw = raw or []
        self.tracks = tracks or []
        if fit:
            self.fit()
        self.redraw()

    def fit(self):
        pts = list(self.raw)
        for tr in self.tracks:
            pts += tr["pts"]
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
        if self.show_raw:
            for x, y in self.raw:
                sx, sy = self.w2s(x, y)
                self.create_rectangle(sx, sy, sx + 1, sy + 1, outline="#59636f")
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
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tab_replay = ttk.Frame(nb)
        self.tab_gmti = ttk.Frame(nb)
        nb.add(self.tab_replay, text="  Rejeu  ")
        nb.add(self.tab_gmti, text="  GMTI → Pistes  ")
        self._build_replay_tab(self.tab_replay)
        self._build_gmti_tab(self.tab_gmti)

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

        self.gmti_status = tk.StringVar(value="Décoder le GMTI d'un pcap, puis lancer le tracker.")
        ttk.Label(parent, textvariable=self.gmti_status, padding=(0, 2),
                  font=("Consolas", 9)).pack(anchor="w")
        self.track_canvas = TrackCanvas(parent)
        self.track_canvas.pack(fill="both", expand=True)

    # ── Actions communes ─────────────────────────────────────────────────
    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[("Captures", "*.pcap *.pcapng *.cap"), ("Tous", "*.*")])
        if p:
            self.path_var.set(p)
            self.gmti_csv = None

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
        try:
            rc = gmti_pcap_to_csv.export(path, out, None, limit)
            if rc != 0:
                self.q.put(("gmti_status", "Aucun flux GMTI détecté dans ce pcap.")); return
            n = 0
            with open(out, encoding="utf-8") as f:
                n = max(0, sum(1 for _ in f) - 1)
            self.gmti_csv = out
            self.q.put(("gmti_status", "GMTI décodé : %d plots. Choisis un profil et lance le tracker." % n))
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
                    self.track_canvas.show_raw = self.raw_var.get()
                    self.track_canvas.show_smooth = self.smooth_var.get()
                    self.track_canvas.set_data(res["raw"], res["tracks"], fit=True)
                    self.gmti_status.set("Profil %s : %d pistes retenues, %d ébauches rejetées (%d plots)."
                                        % (profile, res["n_kept"], res["n_rejected"], len(res["raw"])))
                    self.track_btn.config(state="normal")
                elif kind == "track_err":
                    self.gmti_status.set(msg[1]); self.track_btn.config(state="normal")
                    messagebox.showerror("Tracker", msg[1])
        except queue.Empty:
            pass
        self.after(150, self._pump)


if __name__ == "__main__":
    Console().mainloop()
