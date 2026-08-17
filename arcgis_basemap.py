# -*- coding: utf-8 -*-
"""arcgis_basemap.py — fond de carte raster depuis un ArcGIS Server MapServer.

Construit l'URL de l'opération `export` d'un MapServer et récupère le PNG
(bibliothèque standard : urllib + ssl). Demande l'image en EPSG:4326 pour
qu'elle s'aligne EXACTEMENT sur un canvas ENU équirectangulaire.

Config optionnelle `basemap.json` (à côté du script) :
  {"url": "https://serveur/arcgis/rest/services/WorldTopoMap/MapServer",
   "token": null, "insecure": true}
`insecure` = accepter un certificat auto-signé (serveur DEV local).
"""
import json
import os
import ssl
import urllib.parse
import urllib.request

# Défaut (racine du service fournie ; adapter via basemap.json si besoin).
DEFAULT_URL = "https://asus-xav/arcgis/rest/services/WorldTopoMap/MapServer"


def mapserver_root(url):
    """Racine `.../MapServer` (retire un éventuel /<layerId> terminal)."""
    if not url:
        return url
    key = "/MapServer"
    i = url.find(key)
    return url[:i + len(key)] if i >= 0 else url.rstrip("/")


def load_config(script_dir):
    """Charge basemap.json s'il existe, sinon les défauts."""
    cfg = {"url": DEFAULT_URL, "token": None, "insecure": True}
    path = os.path.join(script_dir, "basemap.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    cfg["url"] = mapserver_root(cfg.get("url") or DEFAULT_URL)
    return cfg


def export_url(root, lonmin, latmin, lonmax, latmax, w, h, token=None, sr=4326):
    """URL de l'opération export (image PNG de la bbox, EPSG `sr` : 4326 par défaut
    pour le canvas ENU de la console Tkinter, 3857 pour la carte web Leaflet)."""
    params = {
        "bbox": "%f,%f,%f,%f" % (lonmin, latmin, lonmax, latmax),
        "bboxSR": str(sr), "imageSR": str(sr),
        "size": "%d,%d" % (int(w), int(h)),
        "format": "png", "transparent": "false", "f": "image",
    }
    if token:
        params["token"] = token
    return mapserver_root(root) + "/export?" + urllib.parse.urlencode(params)


def fetch_png(url, insecure=True, timeout=15):
    """Récupère les octets PNG. Lève si erreur réseau/HTTP ou réponse non-image."""
    ctx = None
    if insecure and url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "pcap_console"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        ctype = r.headers.get("Content-Type", "")
        data = r.read()
    if "image" not in ctype:
        # ArcGIS renvoie souvent une erreur JSON avec un 200
        raise ValueError("réponse non-image (%s) : %s" % (ctype, data[:180].decode("utf-8", "replace")))
    return data


if __name__ == "__main__":
    import sys
    cfg = load_config(os.path.dirname(os.path.abspath(__file__)))
    u = export_url(cfg["url"], 0.30, 45.60, 0.34, 45.63, 512, 384, cfg["token"])
    print("URL export :", u)
    if "--fetch" in sys.argv:
        try:
            png = fetch_png(u, cfg["insecure"])
            out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "basemap_test.png")
            open(out, "wb").write(png)
            print("OK, %d octets -> %s" % (len(png), out))
        except Exception as e:
            print("échec fetch :", e)
