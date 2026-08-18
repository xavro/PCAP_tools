# -*- coding: utf-8 -*-
"""net_capture.py — écoute réseau LIVE (sans fichier pcap) pour la console web.

Trois façons d'obtenir une copie des trames, selon la plateforme et les droits :

  * Linux  : socket AF_PACKET (trames Ethernet brutes) + filtre BPF « ip and udp » posé
             dans le noyau (SO_ATTACH_FILTER) → seuls les datagrammes UDP remontent, sans
             toucher aux sockets des autres applications (GeoEvent, serveur vidéo).
             Droits : CAP_NET_RAW (setcap cap_net_raw+ep sur l'exécutable python) ou root.
  * Windows: socket raw IP + SIO_RCVALL (copie de tout l'IP reçu par l'interface).
             Droits : administrateur. Les paquets IP sont ré-encapsulés dans une trame
             Ethernet fictive pour que la suite du pipeline (et l'enregistrement pcap)
             soit identique au chemin fichier.
  * Repli  : sockets UDP classiques sur une liste de ports (« udp ») — indispensable
             quand le raw est refusé ; en unicast un seul processus reçoit un port donné
             (à réserver aux flux dupliqués ou au multicast).

Multicast : les groupes déclarés font l'objet d'un IP_ADD_MEMBERSHIP (socket dédié,
SO_REUSEADDR) pour que le switch/la carte laissent passer les trames ; la capture raw
les voit ensuite comme le reste.

Enregistrement : PcapWriter écrit un pcap classique (linktype 1) glissant (taille max,
N fichiers gardés) → analysable/rejouable ensuite avec les outils habituels.
"""
import ctypes
import os
import socket
import struct
import sys
import threading
import time

IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")


# ── Interfaces ────────────────────────────────────────────────────────────────
def list_interfaces():
    """[{name, ip}] des interfaces IPv4 utilisables (Linux : nom réel ; Windows : IP)."""
    out = []
    if IS_LINUX:
        try:
            import fcntl
            for idx, name in socket.if_nameindex():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,           # SIOCGIFADDR
                                                      struct.pack("256s", name[:15].encode()))[20:24])
                    s.close()
                except OSError:
                    ip = None
                out.append({"name": name, "ip": ip})
        except Exception:
            pass
    else:
        seen = set()
        try:
            for fam, _t, _p, _c, sa in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                if sa[0] not in seen:
                    seen.add(sa[0]); out.append({"name": sa[0], "ip": sa[0]})
        except Exception:
            pass
        if not any(i["ip"] == "127.0.0.1" for i in out):
            out.append({"name": "127.0.0.1", "ip": "127.0.0.1"})
    return out


# ── Filtre BPF classique « ip and udp » (tcpdump -dd udp, Ethernet) ───────────
_BPF_UDP = [
    (0x28, 0, 0, 0x0000000c), (0x15, 0, 5, 0x000086dd), (0x30, 0, 0, 0x00000014),
    (0x15, 6, 0, 0x00000011), (0x15, 0, 6, 0x0000002c), (0x30, 0, 0, 0x00000036),
    (0x15, 3, 4, 0x00000011), (0x15, 0, 3, 0x00000800), (0x30, 0, 0, 0x00000017),
    (0x15, 0, 1, 0x00000011), (0x06, 0, 0, 0x00040000), (0x06, 0, 0, 0x00000000),
]


def _attach_bpf_udp(sock):
    insns = b"".join(struct.pack("HBBI", *i) for i in _BPF_UDP)
    buf = ctypes.create_string_buffer(insns)
    fprog = struct.pack("HL", len(_BPF_UDP), ctypes.addressof(buf))
    SO_ATTACH_FILTER = 26
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    return buf                                   # garder une référence tant que le socket vit


def _fake_eth(ip_packet):
    """Encapsule un paquet IP dans une trame Ethernet fictive (linktype 1)."""
    return b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00" + ip_packet


def _udp_frame(src, sport, dst, dport, payload):
    """Fabrique une trame Ethernet/IPv4/UDP (repli sockets UDP : pour l'enregistrement pcap)."""
    ulen = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, ulen, 0) + payload
    tot = 20 + ulen
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    return _fake_eth(ip)


# ── Enregistrement pcap glissant ──────────────────────────────────────────────
class PcapWriter:
    def __init__(self, directory, prefix="live", max_mb=200, keep=5):
        self.dir = directory; self.prefix = prefix
        self.max_bytes = max(1, int(max_mb)) * 1024 * 1024; self.keep = max(1, int(keep))
        self.f = None; self.size = 0; self.files = []; self.lock = threading.Lock()
        os.makedirs(directory, exist_ok=True)

    def _open(self):
        name = os.path.join(self.dir, "%s_%s.pcap" % (self.prefix, time.strftime("%Y%m%d_%H%M%S")))
        self.f = open(name, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        self.size = 24; self.files.append(name)
        while len(self.files) > self.keep:
            old = self.files.pop(0)
            try:
                os.remove(old)
            except OSError:
                pass

    def write(self, ts, frame):
        with self.lock:
            if self.f is None or self.size >= self.max_bytes:
                if self.f:
                    self.f.close()
                self._open()
            sec = int(ts); usec = int((ts - sec) * 1e6)
            self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
            self.size += 16 + len(frame)

    def current(self):
        return self.files[-1] if self.files else None

    def close(self):
        with self.lock:
            if self.f:
                self.f.close(); self.f = None


# ── Capture ───────────────────────────────────────────────────────────────────
class Capture:
    """Thread de capture. `on_frame(ts, frame_bytes)` reçoit des trames Ethernet (linktype 1)
    — identiques à ce que donnerait un pcap — pour tous les backends.
    backend : 'auto' | 'raw' | 'udp'. `groups` : ["239.1.2.3", "239.1.2.3:5454"] ;
    `ports` : liste de ports (backend udp)."""

    def __init__(self, on_frame, iface=None, ip=None, groups=(), ports=(), backend="auto", log=None):
        self.on_frame = on_frame; self.iface = iface; self.ip = ip
        self.groups = list(groups or []); self.ports = [int(p) for p in (ports or [])]
        self.backend = backend; self.log = log or (lambda m: None)
        self.stop_event = threading.Event(); self.threads = []; self.socks = []; self.join_socks = []
        self.mode = None; self.err = None; self.n_frames = 0; self.n_bytes = 0; self._keep = []

    # -- multicast : abonnements (le socket ne sert qu'à tenir l'IGMP) --
    def _join_groups(self):
        for g in self.groups:
            grp, _, port = g.partition(":")
            grp = grp.strip()
            if not grp:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind(("", int(port) if port else 0))
                local = socket.inet_aton(self.ip) if self.ip else socket.INADDR_ANY.to_bytes(4, "big")
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(grp) + local)
                self.join_socks.append(s)
                self.log("multicast : abonné à %s%s" % (grp, (" (port %s)" % port) if port else ""))
            except OSError as e:
                self.log("multicast %s : abonnement impossible (%s)" % (g, e))

    def start(self):
        self._join_groups()
        errs = []
        if self.backend in ("auto", "raw"):
            try:
                if IS_LINUX:
                    self._start_linux_raw()
                elif IS_WIN:
                    self._start_win_raw()
                else:
                    raise OSError("capture raw non prise en charge sur %s" % sys.platform)
                return self.mode
            except OSError as e:
                errs.append("raw : %s" % e)
                if self.backend == "raw":
                    raise OSError("; ".join(errs))
        if self.backend in ("auto", "udp"):
            if not self.ports:
                raise OSError("; ".join(errs + ["udp : aucun port indiqué"]))
            self._start_udp()
            if errs:
                self.log("capture raw indisponible (%s) → repli sockets UDP sur %s" % (errs[0], self.ports))
            return self.mode
        raise OSError("backend inconnu : %s" % self.backend)

    def _start_linux_raw(self):
        ETH_P_ALL = 0x0003
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self._keep.append(_attach_bpf_udp(s))
        if self.iface:
            s.bind((self.iface, 0))
        s.settimeout(0.5)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self.socks.append(s); self.mode = "raw:af_packet%s" % ((" " + self.iface) if self.iface else "")
        self._spawn(self._loop_frames, s, False)

    def _start_win_raw(self):
        ip = self.ip
        if not ip:
            ifs = [i for i in list_interfaces() if i["ip"] and not i["ip"].startswith("127.")]
            ip = ifs[0]["ip"] if ifs else "127.0.0.1"
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(0.5)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self.socks.append(s); self.mode = "raw:sio_rcvall %s" % ip
        self._spawn(self._loop_frames, s, True)

    def _start_udp(self):
        for p in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind(("", p)); s.settimeout(0.5)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            self.socks.append(s)
            self._spawn(self._loop_udp, s, p)
        self.mode = "udp:%s" % ",".join(str(p) for p in self.ports)

    def _spawn(self, fn, *a):
        t = threading.Thread(target=fn, args=a, daemon=True); t.start(); self.threads.append(t)

    def _loop_frames(self, s, ip_only):
        while not self.stop_event.is_set():
            try:
                data = s.recv(262144)
            except socket.timeout:
                continue
            except OSError as e:
                if not self.stop_event.is_set():
                    self.err = str(e); self.log("capture : %s" % e)
                break
            if not data:
                continue
            if ip_only:
                if data[0] >> 4 != 4 or len(data) < 28 or data[9] != 17:      # IPv4 + UDP seulement
                    continue
                data = _fake_eth(data)
            self.n_frames += 1; self.n_bytes += len(data)
            self.on_frame(time.time(), data)

    def _loop_udp(self, s, port):
        local = self.ip or "127.0.0.1"                       # destination réelle inconnue (socket lié à toutes) → local
        while not self.stop_event.is_set():
            try:
                pl, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if not self.stop_event.is_set():
                    self.err = str(e); self.log("capture udp/%d : %s" % (port, e))
                break
            fr = _udp_frame(addr[0], addr[1], local, port, pl)
            self.n_frames += 1; self.n_bytes += len(fr)
            self.on_frame(time.time(), fr)

    def stop(self):
        self.stop_event.set()
        for s in self.socks:
            try:
                if IS_WIN and self.mode and self.mode.startswith("raw"):
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        for s in self.join_socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self.threads:
            t.join(timeout=2)
