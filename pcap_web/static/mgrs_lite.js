/* mgrs_lite.js — lat/lon WGS84 → MGRS, port de mgrs_lite.py (même algorithme UTM + carré 100 km).
   Couvre 80°S..84°N ; renvoie null hors zone. Exceptions Norvège/Svalbard ignorées (affichage). */
(function (global) {
  "use strict";
  const A = 6378137.0, F = 1 / 298.257223563, E2 = F * (2 - F), K0 = 0.9996;
  const LAT_BANDS = "CDEFGHJKLMNPQRSTUVWX";
  const COL = ["ABCDEFGH", "JKLMNPQR", "STUVWXYZ"];
  const ROW = "ABCDEFGHJKLMNPQRSTUV";
  const rad = d => d * Math.PI / 180;

  function latBand(lat) {
    if (lat < -80 || lat > 84) return null;
    return LAT_BANDS[Math.min(Math.floor((lat + 80) / 8), LAT_BANDS.length - 1)];
  }

  /** (lat, lon) → { zone, band, easting, northing } (UTM) ou null. */
  function toUTM(lat, lon) {
    const band = latBand(lat); if (band == null) return null;
    const zone = Math.floor((lon + 180) / 6) + 1;
    const lon0 = rad((zone - 1) * 6 - 180 + 3), rlat = rad(lat), rlon = rad(lon);
    const n = A / Math.sqrt(1 - E2 * Math.sin(rlat) ** 2), t = Math.tan(rlat) ** 2;
    const c = (E2 / (1 - E2)) * Math.cos(rlat) ** 2, a = Math.cos(rlat) * (rlon - lon0), e2 = E2;
    const m = A * ((1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256) * rlat
      - (3 * e2 / 8 + 3 * e2 ** 2 / 32 + 45 * e2 ** 3 / 1024) * Math.sin(2 * rlat)
      + (15 * e2 ** 2 / 256 + 45 * e2 ** 3 / 1024) * Math.sin(4 * rlat)
      - (35 * e2 ** 3 / 3072) * Math.sin(6 * rlat));
    const ep2 = e2 / (1 - e2);
    const easting = K0 * n * (a + (1 - t + c) * a ** 3 / 6 + (5 - 18 * t + t ** 2 + 72 * c - 58 * ep2) * a ** 5 / 120) + 500000.0;
    let northing = K0 * (m + n * Math.tan(rlat) * (a ** 2 / 2 + (5 - t + 9 * c + 4 * c ** 2) * a ** 4 / 24
      + (61 - 58 * t + t ** 2 + 600 * c - 330 * ep2) * a ** 6 / 720));
    if (lat < 0) northing += 10000000.0;
    return { zone, band, easting, northing };
  }

  /** (lat, lon, precision 1..5) → '31UDQ4825111932' ou null. */
  function toMGRS(lat, lon, precision = 5) {
    const u = toUTM(lat, lon); if (!u) return null;
    const colLetters = COL[(u.zone - 1) % 3];
    const col = colLetters[Math.floor(u.easting / 100000) - 1];
    let rowIdx = Math.floor(u.northing / 100000) % 20;
    if (u.zone % 2 === 0) rowIdx = (rowIdx + 5) % 20;
    const row = ROW[rowIdx];
    const p = Math.max(1, Math.min(5, precision)), div = 10 ** (5 - p);
    const ea = Math.floor(Math.round(u.easting % 100000) / div), no = Math.floor(Math.round(u.northing % 100000) / div);
    return `${u.zone}${u.band}${col}${row}${String(ea).padStart(p, "0")}${String(no).padStart(p, "0")}`;
  }

  /** Distance géodésique (haversine, m) et gisement (°) entre deux points. */
  function distBearing(lat1, lon1, lat2, lon2) {
    const R = 6371000, p1 = rad(lat1), p2 = rad(lat2), dl = rad(lon2 - lon1);
    const a = Math.sin((p2 - p1) / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
    const d = 2 * R * Math.asin(Math.sqrt(a));
    const y = Math.sin(dl) * Math.cos(p2), x = Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl);
    return { d, bearing: (Math.atan2(y, x) * 180 / Math.PI + 360) % 360 };
  }

  global.MGRS = { toUTM, toMGRS, distBearing };
})(window);
