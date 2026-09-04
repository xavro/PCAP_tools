/* klv0601.js — décodeur MISB ST 0601 (UAS Datalink Local Set) côté navigateur.
   Entrée : Uint8Array (payload PES d'un PID KLV synchrone, tel que remonté par
   mpegts.js). Sortie : { fields: [{tag,name,value,unit}], num: {lat,lon,...,corners} }.
   Mêmes formules que video4609.py (linéaire signé/non signé). */
(function (global) {
  "use strict";
  const KEY = [0x06,0x0e,0x2b,0x34,0x02,0x0b,0x01,0x01,0x0e,0x01,0x03,0x01,0x01,0x00,0x00,0x00];

  function u(b) { let v = 0; for (const x of b) v = v * 256 + x; return v; }
  function s(b) { let v = u(b); const bits = b.length * 8; if (v >= 2 ** (bits - 1)) v -= 2 ** bits; return v; }
  const linS = (raw, bits, rng) => raw * (rng / (2 ** (bits - 1) - 1));
  const linU = (raw, bits, rng, off = 0) => raw * (rng / (2 ** bits - 1)) + off;
  const ascii = b => Array.from(b, c => (c >= 32 && c < 127) ? String.fromCharCode(c) : "·").join("");
  const hex = b => Array.from(b, c => c.toString(16).padStart(2, "0")).join("");

  // Tag 63 — Sensor Field of View Name : énumération ST 0601 (le brut est un simple index).
  const FOV_NAME = { 0: "Ultranarrow", 1: "Narrow", 2: "Medium", 3: "Wide", 4: "Ultrawide", 5: "Narrow Medium",
    6: "2x Ultranarrow", 7: "4x Ultranarrow", 8: "Continuous Zoom" };

  /* Nom NORMALISÉ du tag dans MISB ST 0601 (UAS Datalink Local Set), affiché au survol de la table :
     les libellés ci-dessous sont traduits et abrégés pour tenir dans la colonne, alors que l'opérateur
     a besoin du nom du standard pour recouper avec la documentation, GeoEvent ou un autre décodeur. */
  const STD = {
    1: "Checksum", 2: "Precision Time Stamp", 3: "Mission ID", 4: "Platform Tail Number",
    5: "Platform Heading Angle", 6: "Platform Pitch Angle", 7: "Platform Roll Angle",
    8: "Platform True Airspeed", 9: "Platform Indicated Airspeed", 10: "Platform Designation",
    11: "Image Source Sensor", 12: "Image Coordinate System", 13: "Sensor Latitude", 14: "Sensor Longitude",
    15: "Sensor True Altitude", 16: "Sensor Horizontal Field of View", 17: "Sensor Vertical Field of View",
    18: "Sensor Relative Azimuth Angle", 19: "Sensor Relative Elevation Angle", 20: "Sensor Relative Roll Angle",
    21: "Slant Range", 22: "Target Width", 23: "Frame Center Latitude", 24: "Frame Center Longitude",
    25: "Frame Center Elevation",
    26: "Offset Corner Latitude Point 1", 27: "Offset Corner Longitude Point 1",
    28: "Offset Corner Latitude Point 2", 29: "Offset Corner Longitude Point 2",
    30: "Offset Corner Latitude Point 3", 31: "Offset Corner Longitude Point 3",
    32: "Offset Corner Latitude Point 4", 33: "Offset Corner Longitude Point 4",
    34: "Icing Detected", 35: "Wind Direction", 36: "Wind Speed", 37: "Static Pressure",
    38: "Density Altitude", 39: "Outside Air Temperature",
    40: "Target Location Latitude", 41: "Target Location Longitude", 42: "Target Location Elevation",
    43: "Target Track Gate Width", 44: "Target Track Gate Height",
    45: "Target Error Estimate CE90", 46: "Target Error Estimate LE90",
    47: "Generic Flag Data", 48: "Security Local Set",
    56: "Platform Ground Speed", 57: "Ground Range", 58: "Platform Fuel Remaining", 59: "Platform Call Sign",
    62: "Laser PRF Code", 63: "Sensor Field of View Name", 64: "Platform Magnetic Heading",
    65: "UAS Datalink LS Version Number", 72: "Event Start Time UTC", 73: "RVT Local Set", 74: "VMTI Local Set",
    75: "Sensor Ellipsoid Height", 76: "Alternate Platform Ellipsoid Height", 77: "Operational Mode",
    78: "Frame Center Height Above Ellipsoid", 79: "Sensor North Velocity", 80: "Sensor East Velocity",
    82: "Corner Latitude Point 1 (Full)", 83: "Corner Longitude Point 1 (Full)",
    84: "Corner Latitude Point 2 (Full)", 85: "Corner Longitude Point 2 (Full)",
    86: "Corner Latitude Point 3 (Full)", 87: "Corner Longitude Point 3 (Full)",
    88: "Corner Latitude Point 4 (Full)", 89: "Corner Longitude Point 4 (Full)",
    94: "MIIS Core Identifier"
  };

  // tag -> [nom, unité, fn(bytes) -> valeur (number|string)]
  const TAGS = {
    1:  ["Checksum", "", b => hex(b)],
    2:  ["Horodatage UNIX", "µs", b => u(b)],
    3:  ["Mission ID", "", ascii],
    4:  ["Plateforme (tail)", "", ascii],
    5:  ["Cap plateforme", "°", b => linU(u(b), 16, 360)],
    6:  ["Tangage plateforme", "°", b => linS(s(b), 16, 20)],
    7:  ["Roulis plateforme", "°", b => linS(s(b), 16, 50)],
    8:  ["Vitesse air vraie", "m/s", b => u(b)],
    9:  ["Vitesse air indiquée", "m/s", b => u(b)],
    10: ["Désignation plateforme", "", ascii],
    11: ["Capteur (source image)", "", ascii],
    12: ["Système de coord. image", "", ascii],
    13: ["Latitude capteur", "°", b => linS(s(b), 32, 90)],
    14: ["Longitude capteur", "°", b => linS(s(b), 32, 180)],
    15: ["Altitude capteur (MSL)", "m", b => linU(u(b), 16, 19900, -900)],
    16: ["HFOV capteur", "°", b => linU(u(b), 16, 180)],
    17: ["VFOV capteur", "°", b => linU(u(b), 16, 180)],
    18: ["Azimut relatif capteur", "°", b => linU(u(b), 32, 360)],
    19: ["Élévation relative capteur", "°", b => linS(s(b), 32, 180)],
    20: ["Roulis relatif capteur", "°", b => linU(u(b), 32, 360)],
    21: ["Portée oblique", "m", b => linU(u(b), 32, 5000000)],
    22: ["Largeur cible", "m", b => linU(u(b), 16, 10000)],
    23: ["Latitude centre image", "°", b => linS(s(b), 32, 90)],
    24: ["Longitude centre image", "°", b => linS(s(b), 32, 180)],
    25: ["Altitude centre image", "m", b => linU(u(b), 16, 19900, -900)],
    26: ["Δlat coin 1", "°", b => linS(s(b), 16, 0.075)],
    27: ["Δlon coin 1", "°", b => linS(s(b), 16, 0.075)],
    28: ["Δlat coin 2", "°", b => linS(s(b), 16, 0.075)],
    29: ["Δlon coin 2", "°", b => linS(s(b), 16, 0.075)],
    30: ["Δlat coin 3", "°", b => linS(s(b), 16, 0.075)],
    31: ["Δlon coin 3", "°", b => linS(s(b), 16, 0.075)],
    32: ["Δlat coin 4", "°", b => linS(s(b), 16, 0.075)],
    33: ["Δlon coin 4", "°", b => linS(s(b), 16, 0.075)],
    34: ["Icing", "", b => u(b)],
    35: ["Direction du vent", "°", b => linU(u(b), 16, 360)],
    36: ["Vitesse du vent", "m/s", b => linU(u(b), 8, 100)],
    37: ["Pression statique", "mbar", b => linU(u(b), 16, 5000)],
    38: ["Altitude densité", "m", b => linU(u(b), 16, 19900, -900)],
    39: ["Température air ext.", "°C", b => s(b)],
    40: ["Latitude cible", "°", b => linS(s(b), 32, 90)],
    41: ["Longitude cible", "°", b => linS(s(b), 32, 180)],
    42: ["Altitude cible", "m", b => linU(u(b), 16, 19900, -900)],
    43: ["Largeur piste cible", "px", b => u(b)],
    44: ["Hauteur piste cible", "px", b => u(b)],
    45: ["Erreur cible CE90", "m", b => linU(u(b), 16, 4095)],
    46: ["Erreur cible LE90", "m", b => linU(u(b), 16, 4095)],
    47: ["Flags génériques", "", b => u(b)],
    48: ["Local set sécurité", "", b => hex(b).slice(0, 32)],
    56: ["Vitesse sol plateforme", "m/s", b => u(b)],
    57: ["Distance sol", "m", b => linU(u(b), 32, 5000000)],
    58: ["Carburant restant", "kg", b => linU(u(b), 16, 10000)],
    59: ["Indicatif plateforme", "", ascii],
    62: ["Code PRF laser", "", b => u(b)],
    63: ["Nom du champ de vision", "", b => FOV_NAME[u(b)] || u(b)],
    64: ["Cap magnétique plateforme", "°", b => linU(u(b), 16, 360)],
    65: ["Version LS MISB 0601", "", b => u(b)],
    72: ["Événement", "µs", b => u(b)],
    73: ["Local set RVT", "", b => hex(b).slice(0, 32)],
    74: ["Local set VMTI", "", b => "(" + b.length + " o)"],
    75: ["Altitude capteur (HAE)", "m", b => linU(u(b), 16, 19900, -900)],
    76: ["Altitude plateforme alt. (HAE)", "m", b => linU(u(b), 16, 19900, -900)],
    77: ["Mode opérationnel", "", b => u(b)],
    78: ["Altitude centre image (HAE)", "m", b => linU(u(b), 16, 19900, -900)],
    79: ["Vitesse capteur nord", "m/s", b => linS(s(b), 16, 327)],
    80: ["Vitesse capteur est", "m/s", b => linS(s(b), 16, 327)],
    82: ["Latitude coin 1", "°", b => linS(s(b), 32, 90)],
    83: ["Longitude coin 1", "°", b => linS(s(b), 32, 180)],
    84: ["Latitude coin 2", "°", b => linS(s(b), 32, 90)],
    85: ["Longitude coin 2", "°", b => linS(s(b), 32, 180)],
    86: ["Latitude coin 3", "°", b => linS(s(b), 32, 90)],
    87: ["Longitude coin 3", "°", b => linS(s(b), 32, 180)],
    88: ["Latitude coin 4", "°", b => linS(s(b), 32, 90)],
    89: ["Longitude coin 4", "°", b => linS(s(b), 32, 180)],
    94: ["MIIS core identifier", "", b => hex(b).slice(0, 32)],
  };

  function findKey(b) {
    outer: for (let i = 0; i + 16 <= b.length; i++) {
      for (let k = 0; k < 16; k++) if (b[i + k] !== KEY[k]) continue outer;
      return i;
    }
    return -1;
  }
  function berLen(b, i) {
    if (i >= b.length) return [null, i];
    const b0 = b[i];
    if (b0 < 0x80) return [b0, i + 1];
    const n = b0 & 0x7f; if (i + 1 + n > b.length) return [null, i];
    return [u(b.subarray(i + 1, i + 1 + n)), i + 1 + n];
  }

  /** Décode le premier LS 0601 complet de `bytes`. Renvoie null si absent/incomplet. */
  function decode(bytes) {
    const k = findKey(bytes); if (k < 0) return null;
    let i = k + 16; let total; [total, i] = berLen(bytes, i);
    if (total == null || i + total > bytes.length) return null;
    const end = i + total, raw = {}, fields = [];
    while (i < end) {
      let tag = bytes[i++]; if (tag & 0x80) tag = ((tag & 0x7f) << 7) | bytes[i++];
      let ln; [ln, i] = berLen(bytes, i); if (ln == null || i + ln > end) break;
      const val = bytes.subarray(i, i + ln); i += ln; raw[tag] = val;
      const d = TAGS[tag];
      let value, name = d ? d[0] : "tag " + tag, unit = d ? d[1] : "";
      try { value = d ? d[2](val) : hex(val).slice(0, 32); } catch (e) { value = hex(val); }
      fields.push({ tag, name, unit, value });
    }
    // Ordre des coins : l'ordre MISB (haut-gauche, haut-droit, bas-droit, bas-gauche) n'est pas respecté par tous les flux ; un ordre permuté trace un quadrilatère CROISÉ (« nœud papillon »). Tri par angle polaire autour du barycentre : le polygone obtenu est simple quel que soit l'ordre publié.
  function orderCorners(c) {
    if (!c || c.length !== 4 || c.some(p => p == null || p[0] == null || p[1] == null)) return c;
    const cLat = (c[0][0] + c[1][0] + c[2][0] + c[3][0]) / 4, cLon = (c[0][1] + c[1][1] + c[2][1] + c[3][1]) / 4;
    const kx = Math.cos(cLat * Math.PI / 180);
    return c.slice().sort((a, b) => Math.atan2(a[0] - cLat, (a[1] - cLon) * kx) - Math.atan2(b[0] - cLat, (b[1] - cLon) * kx));
  }
  const g = t => raw[t] ? TAGS[t][2](raw[t]) : null;
    const num = { ts_us: g(2), hdg: g(5), pitch: g(6), roll: g(7), lat: g(13), lon: g(14), alt: g(15),
      hfov: g(16), vfov: g(17), rel_az: g(18), rel_el: g(19), slant: g(21),
      fc_lat: g(23), fc_lon: g(24), fc_alt: g(25), tgt_lat: g(40), tgt_lon: g(41), corners: null };
    if ([82,83,84,85,86,87,88,89].every(t => raw[t])) {
      num.corners = [0,1,2,3].map(c => [g(82 + 2 * c), g(83 + 2 * c)]);
    } else if (num.fc_lat != null && [26,27,28,29,30,31,32,33].every(t => raw[t])) {
      num.corners = [0,1,2,3].map(c => [num.fc_lat + g(26 + 2 * c), num.fc_lon + g(27 + 2 * c)]);
    }
    num.corners = orderCorners(num.corners);
    return { fields, num };
  }

  global.KLV0601 = { decode, TAGS, STD };
})(window);
