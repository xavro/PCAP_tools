# -*- coding: utf-8 -*-
"""mgrs_lite.py — conversion lat/lon (WGS84) -> MGRS, pur Python (aucune dépendance).

Suffisant pour l'affichage d'une position au survol (lecture opérateur). Couvre
les zones UTM standard (80°S..84°N) ; hors de cette plage renvoie None.
"""
import math

_A = 6378137.0            # demi-grand axe WGS84
_F = 1 / 298.257223563
_E2 = _F * (2 - _F)
_K0 = 0.9996

_LAT_BANDS = "CDEFGHJKLMNPQRSTUVWX"       # bandes de latitude 8° (C=-80..-72 … X=72..84)
_COL = "ABCDEFGH", "JKLMNPQR", "STUVWXYZ"  # colonnes 100 km par (zone-1)%3
_ROW = "ABCDEFGHJKLMNPQRSTUV"             # lignes 100 km (cycle 20), décalage zone paire


def _lat_band(lat):
    if lat < -80 or lat > 84:
        return None
    idx = int((lat + 80) // 8)
    return _LAT_BANDS[min(idx, len(_LAT_BANDS) - 1)]


def latlon_to_mgrs(lat, lon, precision=5):
    """(lat, lon) WGS84 -> chaîne MGRS (ex. '31UDQ4825111932'), ou None hors zone."""
    band = _lat_band(lat)
    if band is None:
        return None
    zone = int((lon + 180) / 6) + 1
    # Exceptions Norvège/Svalbard ignorées (marginales pour l'affichage).
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    rlat, rlon = math.radians(lat), math.radians(lon)

    n = _A / math.sqrt(1 - _E2 * math.sin(rlat) ** 2)
    t = math.tan(rlat) ** 2
    c = (_E2 / (1 - _E2)) * math.cos(rlat) ** 2
    a = math.cos(rlat) * (rlon - lon0)
    e2 = _E2
    m = _A * ((1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256) * rlat
              - (3 * e2 / 8 + 3 * e2 ** 2 / 32 + 45 * e2 ** 3 / 1024) * math.sin(2 * rlat)
              + (15 * e2 ** 2 / 256 + 45 * e2 ** 3 / 1024) * math.sin(4 * rlat)
              - (35 * e2 ** 3 / 3072) * math.sin(6 * rlat))
    ep2 = e2 / (1 - e2)
    easting = (_K0 * n * (a + (1 - t + c) * a ** 3 / 6
               + (5 - 18 * t + t ** 2 + 72 * c - 58 * ep2) * a ** 5 / 120) + 500000.0)
    northing = (_K0 * (m + n * math.tan(rlat) * (a ** 2 / 2
                + (5 - t + 9 * c + 4 * c ** 2) * a ** 4 / 24
                + (61 - 58 * t + t ** 2 + 600 * c - 330 * ep2) * a ** 6 / 720)))
    if lat < 0:
        northing += 10000000.0

    # Carré 100 km : colonne (easting) + ligne (northing, décalage zones paires).
    col_letters = _COL[(zone - 1) % 3]
    col = col_letters[int(easting // 100000) - 1]
    row_idx = int(northing // 100000) % 20
    if zone % 2 == 0:
        row_idx = (row_idx + 5) % 20
    row = _ROW[row_idx]

    p = max(1, min(5, precision))
    ea = int(round(easting % 100000)) // (10 ** (5 - p))
    no = int(round(northing % 100000)) // (10 ** (5 - p))
    return "%d%s%s%s%0*d%0*d" % (zone, band, col, row, p, ea, p, no)


if __name__ == "__main__":
    # Points de contrôle (valeurs de référence connues).
    tests = [
        (48.85826, 2.29450, "31U"),      # Tour Eiffel -> 31U DQ ...
        (45.60129, 0.30707, "31T"),      # sud-ouest France (capteur pré-prod)
        (35.62457, 16.89987, "33S"),     # sud Sicile (GMTI pré-prod maritime)
    ]
    for lat, lon, gzd in tests:
        m = latlon_to_mgrs(lat, lon)
        ok = m and m.startswith(gzd)
        print("%s , %s -> %s   %s" % (lat, lon, m, "OK" if ok else "?? attendu " + gzd))
