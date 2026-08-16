# Scenario synthetique pour exercer les latchs aerien/rotateur (Phase E).
# Ecrit un CSV au schema gmti_pcap_to_csv.
import math

lat0, lon0 = 45.0, 5.0
ky = 110540.0
kx = 111320.0 * math.cos(math.radians(lat0))
slat, slon = 45.20, 5.0            # capteur au nord

N = 14
DT = 1000
t0 = 10000000
rows = []
# Cible aerienne : ~60 m/s vers le nord, v_LOS forte, vue a chaque dwell.
ax, ay = 0.0, 0.0
for d in range(N):
    t = t0 + d * DT
    ay += 60.0 * DT / 1000.0                     # 60 m/s
    alat = lat0 + ay / ky
    alon = lon0 + ax / kx
    rows.append((t, d, 0, alat, alon, -6000, 30, 6))   # vel_los=-60 m/s
    # Rotateur fixe : position quasi immobile, v_LOS forte (artefact Doppler).
    jit = (0.5 if d % 2 == 0 else -0.5) / ky
    rows.append((t, d, 0, lat0 + jit, lon0 + 0.02, -6000, 30, 6))

with open("parity_input_air.csv", "w", newline="") as f:
    f.write("dwell_time_ms;revisit_idx;dwell_idx;lat;lon;vel_los_cms;snr_db;classification;"
            "sig_range_cm;sig_xrange_dm;sig_rvel_cms;sensor_lat;sensor_lon\n")
    for (t, rev, dwi, la, lo, vl, snr, cls) in rows:
        f.write("%d;%d;%d;%.7f;%.7f;%d;%d;%d;3000;300;26;%.7f;%.7f\n"
                % (t, rev, dwi, la, lo, vl, snr, cls, slat, slon))
print("ecrit parity_input_air.csv :", len(rows), "detections,", N, "dwells")
