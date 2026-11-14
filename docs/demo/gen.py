"""Fake home network for the demo GIF: never film real traffic.

python3 docs/demo/gen.py <dir>   copies khada3 into <dir> and fills <dir>/khada3.db with 24 h of made-up requests.
"""
import random
import shutil
import sys
import time
from pathlib import Path

ICI = Path(__file__).resolve().parents[2]
DEMO = Path(sys.argv[1]).resolve()
if "--live" in sys.argv:  # while filming: a few requests per second, for the radar echoes and the live feed
    import sqlite3
    db = sqlite3.connect(DEMO / "khada3.db")
    vivants = [("192.168.1.21", "instagram.com", 0), ("192.168.1.20", "nflxvideo.net", 0), ("192.168.1.22", "github.com", 0),
               ("192.168.1.20", "samsungads.com", 1), ("192.168.1.23", "nintendowifi.net", 0), ("192.168.1.21", "app-measurement.com", 1)]
    while True:
        db.execute("INSERT INTO requetes VALUES (?, ?, ?, ?)", (time.time(), *random.choice(vivants)))
        db.commit()
        time.sleep(random.uniform(0.3, 1.2))
DEMO.mkdir(parents=True, exist_ok=True)
for f in ("khada3.py", "web.py", "page.html", "messager.py", "qui.py", "resume.py", "bloquer.txt"):
    shutil.copy(ICI / f, DEMO)
if not (DEMO / "listes").exists():
    shutil.copytree(ICI / "listes", DEMO / "listes")  # blocklist, companies and countries, without downloading them again
(DEMO / "khada3.db").unlink(missing_ok=True)
(DEMO / "pause").unlink(missing_ok=True)  # left by the previous recording
(DEMO / "regles.txt").write_text("tiktok.com 23-7 Sara's iPhone\nfortnite.com 21-8 192.168.1.23\n")

sys.path.insert(0, str(DEMO))
import khada3  # noqa: E402  creates the empty base in DEMO

random.seed(7)
maintenant = time.time()
APPAREILS = {  # ip: (mac, name, {domain: weight})
    "192.168.1.20": ("8c:79:f5:10:20:30", "Living room TV", {"samsungotn.net": 3, "samsungads.com": 8, "samsungacr.com": 6,
                     "netflix.com": 10, "nflxvideo.net": 14, "youtube.com": 6, "doubleclick.net": 4}),
    "192.168.1.21": ("5a:11:22:33:44:55", "Sara's iPhone", {"captive.apple.com": 3, "icloud.com": 6, "instagram.com": 12,
                     "tiktok.com": 10, "tiktokcdn.com": 12, "graph.facebook.com": 5, "app-measurement.com": 4, "snapchat.com": 6}),
    "192.168.1.22": ("3c:22:fb:aa:bb:cc", "Work laptop", {"msftconnecttest.com": 2, "outlook.office365.com": 10,
                     "teams.microsoft.com": 8, "github.com": 6, "google-analytics.com": 3, "googlesyndication.com": 3}),
    "192.168.1.23": ("98:41:5c:01:02:03", None, {"nintendowifi.net": 4, "fortnite.com": 6, "epicgames.com": 4, "youtube.com": 2}),
}
ADRESSES = {"samsungotn.net": "211.45.27.231", "samsungads.com": "211.45.27.10", "samsungacr.com": "34.111.10.2",
            "netflix.com": "54.155.178.5", "nflxvideo.net": "45.57.90.1", "youtube.com": "142.250.179.110",
            "doubleclick.net": "142.250.75.238", "icloud.com": "17.253.144.10", "instagram.com": "157.240.202.174",
            "tiktok.com": "23.40.62.48", "tiktokcdn.com": "23.40.62.49", "graph.facebook.com": "157.240.202.15",
            "snapchat.com": "35.190.43.134", "outlook.office365.com": "52.97.146.2", "teams.microsoft.com": "52.113.194.132",
            "github.com": "140.82.121.4", "fortnite.com": "18.66.196.20", "epicgames.com": "18.66.196.21", "dc.di.atlas.samsung.com": "13.248.130.17"}

with khada3.verrou:
    db = khada3.db
    for ip, (mac, nom, domaines) in APPAREILS.items():
        db.execute("INSERT INTO appareils VALUES (?, ?, ?, ?)", (ip, mac, maintenant - 9 * 86400, nom))
        for k in range(24):
            t0 = maintenant - maintenant % 3600 - k * 3600  # whole hours, like the timeline
            duree = min(3600, maintenant - t0)
            heure = time.localtime(t0).tm_hour
            n = random.randint(25, 70) if 8 <= heure <= 23 else random.randint(0, 6)
            if ip == "192.168.1.20" and heure == 3:
                n = 260  # the TV calling home in the middle of the night
            for _ in range(n):
                domaine = random.choices(list(domaines), weights=list(domaines.values()))[0]
                if ip == "192.168.1.20" and heure == 3:
                    domaine = random.choice(["samsungads.com", "dc.di.atlas.samsung.com", "dc.di.atlas.samsung.com"])
                bloque = khada3.est_bloque(domaine) or khada3.bloque_par_regle(ip, domaine, heure)
                db.execute("INSERT INTO requetes VALUES (?, ?, ?, ?)", (t0 + random.random() * duree, ip, domaine, int(bloque)))
                khada3.deviner(db, ip, domaine)
    db.executemany("INSERT OR REPLACE INTO domaines VALUES (?, ?)", ADRESSES.items())
    db.execute("INSERT INTO propositions (t, domaine, raison) VALUES (?, ?, ?)",
               (maintenant - 600, "dc.di.atlas.samsung.com", "Samsung telemetry: the TV called it 170 times at 3 am"))
    db.executemany("INSERT INTO hors_khada3 VALUES (?, ?, ?)", [("cc:7b:5c:12:34:56", "192.168.1.80", maintenant - 300),
                                                               ("6e:4a:10:22:8f:31", "192.168.1.41", maintenant - 900)])
    db.commit()
print(f"demo ready in {DEMO}")
