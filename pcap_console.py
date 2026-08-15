#!/usr/bin/env python3
"""Console de rejeu pcap (interface Tkinter) — ISRBOX / 33e ESRA.

Petite application desktop (bibliothèque standard : tkinter) pour piloter le
rejeu multi-flux sans taper les lignes de commande `--route` :

  1. Charger un pcap  ->  analyse automatique (pcap_analyze.scan)
  2. Tableau des flux : cocher ceux à rejouer, saisir IP[:port] cible,
     « + client » pour dupliquer un flux vers plusieurs destinations (fan-out)
  3. Start / Stop, vitesse, boucle -> pilote pcap_replay.do_routed_replay
  4. Bonus : « Exporter GMTI -> CSV » (gmti_pcap_to_csv) pour le tracker

Zéro dépendance (tkinter est fourni avec Python). Le rejeu tourne dans un thread ;
l'UI est mise à jour via une file (Tk n'est pas thread-safe).
"""
import os
import queue
import sys
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


# ── Logique pure (testable sans Tk) ─────────────────────────────────────────

def build_route_specs(selected):
    """`selected` = liste de (proto, dport, [chaînes cibles]) -> specs `--route`.

    Ignore les cibles vides et les flux sans cible. Réutilise le format déjà
    validé par pcap_replay.parse_routes.
    """
    specs = []
    for proto, dport, targets in selected:
        tg = [t.strip() for t in targets if t and t.strip()]
        if tg:
            specs.append("%s/%s=%s" % (proto.lower(), dport, ",".join(tg)))
    return specs


def is_app_proto(dominant):
    return dominant.startswith(pcap_analyze.APP)


# ── Ligne de flux (widgets) ─────────────────────────────────────────────────

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
        e = ttk.Entry(self.targets_frame, textvariable=var, width=20)
        e.pack(side="left", padx=2)
        self.target_vars.append(var)

    def pack(self, **kw):
        self.frame.pack(fill="x", pady=1, **kw)

    def selection(self):
        """(proto, dport, [cibles]) si coché, sinon None."""
        if not self.replay.get():
            return None
        return (self.proto, self.dport, [v.get() for v in self.target_vars])


# ── Application ──────────────────────────────────────────────────────────────

class Console(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Console de rejeu pcap — ISRBOX / 33e ESRA")
        self.geometry("860x640")
        self.rows = []
        self.worker = None
        self.stop_event = threading.Event()
        self.q = queue.Queue()
        self._build_ui()
        self.after(150, self._pump)

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Fichier pcap :").pack(side="left")
        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var, width=52).pack(side="left", padx=4)
        ttk.Button(top, text="Parcourir…", command=self._browse).pack(side="left")
        ttk.Button(top, text="Analyser", command=self._analyze).pack(side="left", padx=4)
        ttk.Label(top, text="limit").pack(side="left", padx=(8, 2))
        self.limit_var = tk.StringVar(value=str(SCAN_LIMIT_DEFAULT))
        ttk.Entry(top, textvariable=self.limit_var, width=8).pack(side="left")

        ttk.Label(self, text="Flux détectés (cocher = rejouer ; IP[:port] cible ; + client = fan-out) :",
                  padding=(8, 4)).pack(anchor="w")
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=8)
        canvas = tk.Canvas(mid, highlightthickness=0)
        sb = ttk.Scrollbar(mid, orient="vertical", command=canvas.yview)
        self.rows_frame = ttk.Frame(canvas)
        self.rows_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.rows_frame, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        ctl = ttk.Frame(self, padding=8)
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
        if gmti_pcap_to_csv is not None:
            ttk.Button(ctl, text="Exporter GMTI → CSV", command=self._export_gmti).pack(side="right")

        self.status_var = tk.StringVar(value="Prêt.")
        ttk.Label(self, textvariable=self.status_var, padding=(8, 2),
                  font=("Consolas", 9)).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(self, height=9, font=("Consolas", 9))
        self.log.pack(fill="both", expand=False, padx=8, pady=(0, 8))

    # ── Actions ──────────────────────────────────────────────────────────
    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[("Captures", "*.pcap *.pcapng *.cap"), ("Tous", "*.*")])
        if p:
            self.path_var.set(p)

    def _limit(self):
        try:
            return max(0, int(self.limit_var.get()))
        except ValueError:
            return 0

    def _analyze(self):
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Fichier", "Sélectionne un fichier pcap valide.")
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
            default_ip = dsts[0] if dsts else ""
            row = FlowRow(self.rows_frame, proto, dport, dominant, pkts, default_ip)
            row.pack()
            self.rows.append(row)
        n_app = sum(1 for r in rows if is_app_proto(r[2]))
        self.status_var.set("Analyse : %d paquets, %d flux/ports, %d protocole(s) applicatif(s)."
                            % (res["npkt"], len(rows), n_app))

    def _collect_specs(self):
        selected = [s for s in (row.selection() for row in self.rows) if s]
        return build_route_specs(selected)

    def _make_args(self):
        speed = dict(SPEEDS)[self.speed_var.get()]
        return types.SimpleNamespace(
            target=None, target_port=None, speed=speed,
            precise=False, loop=self.loop_var.get(),
            rebase_time=False, drop_unmatched=self.drop_var.get())

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Fichier", "Sélectionne un fichier pcap valide.")
            return
        specs = self._collect_specs()
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
        args = self._make_args()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.worker = threading.Thread(target=self._replay_worker, args=(path, args, table), daemon=True)
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

    def _export_gmti(self):
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Fichier", "Sélectionne un fichier pcap valide.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".csv",
                                           initialfile="plots.csv", filetypes=[("CSV", "*.csv")])
        if not out:
            return
        self.status_var.set("Décodage GMTI → CSV…")
        threading.Thread(target=self._export_worker, args=(path, out, self._limit()), daemon=True).start()

    def _export_worker(self, path, out, limit):
        try:
            gmti_pcap_to_csv.export(path, out, None, limit)
            self.q.put(("log", "CSV écrit : %s" % out))
            self.q.put(("status", "Export GMTI terminé : %s" % out))
        except Exception as e:
            self.q.put(("log", "Export GMTI échoué : %s" % e))

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
                    self.log.insert("end", msg[1] + "\n")
                    self.log.see("end")
                elif kind == "status":
                    self.status_var.set(msg[1])
                elif kind == "error":
                    self.status_var.set(msg[1])
                    messagebox.showerror("Erreur", msg[1])
                elif kind == "done":
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.status_var.set(self.status_var.get() + "  — terminé.")
        except queue.Empty:
            pass
        self.after(150, self._pump)


if __name__ == "__main__":
    Console().mainloop()
