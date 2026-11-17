"""Agent du soir : une IA lit les domaines des dernières 24 h et explique en clair qui parle à qui.

Il propose aussi des domaines à bloquer : rien n'est bloqué sans un « oui » (tableau de bord ou bouton Telegram).

Usage : python3 resume.py           -> envoie le rapport et les propositions sur Telegram
        python3 resume.py --semaine -> envoie le rapport de la semaine (sans IA)
        ajouter --ecran             -> affiche seulement
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import qui
import messager
from khada3 import BASE, DOMAINE, candidats, est_bloque, fabricant, nom_appareil, verrou

MODELE = os.environ.get("KHADA3_MODELE", "gemini-3.1-flash-lite")
FAKH = Path(os.environ.get("KHADA3_FAKH", "/var/lib/fakh/fakh.db"))  # base du piège fakh, s'il est installé
LANGUE = os.environ.get("KHADA3_LANGUE", "English")  # langue du rapport du jour
CONSIGNE = f"""You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours: number of requests, how many were blocked, the company behind the domain and its activity
when known (from the Disconnect tracker list), and the country of its server. Device names may be set by the owner,
otherwise use the maker. Write in plain {LANGUE}, for Telegram:
- one line per device: what it does, judging by its domains (e.g. "TV box: mostly ads and audience tracking");
- anything suspicious or surprising (trackers, unexpected countries, activity at night).
Put this text in "rapport": no markdown, 1500 characters at most.
In "a_bloquer", list up to 8 ad or tracking domains worth blocking, each with a one-sentence reason in {LANGUE};
only domains whose "bloquable" is true (listed as trackers by a curated blocklist, and not blocked yet).
An empty list is fine when nothing deserves it.
Only mention domains present in the data.
When a device has "envoye_a", it lists where it sent the most data (byte volumes only, never the content):
point out large uploads to trackers or unexpected places."""
SCHEMA = {"type": "OBJECT", "required": ["rapport", "a_bloquer"], "properties": {
    "rapport": {"type": "STRING"},
    "a_bloquer": {"type": "ARRAY", "items": {"type": "OBJECT", "required": ["domaine", "raison"],
                                             "properties": {"domaine": {"type": "STRING"}, "raison": {"type": "STRING"}}}}}}


def donnees(depuis):
    """Pour chaque appareil, ses 40 domaines les plus demandés depuis `depuis`."""
    db = sqlite3.connect(BASE)
    lignes = db.execute("""SELECT r.ip, a.mac, COALESCE(a.nom, d.genre), r.domaine, COUNT(*), SUM(r.bloque),
                                  SUM(CAST(strftime('%H', r.t, 'unixepoch', 'localtime') AS INTEGER) < 6)
                           FROM requetes r LEFT JOIN appareils a ON a.ip = r.ip LEFT JOIN devinettes d ON d.ip = r.ip
                           WHERE r.t >= ? GROUP BY r.ip, r.domaine ORDER BY r.ip, COUNT(*) DESC""", (depuis,)).fetchall()
    appareils, ips = {}, dict(db.execute("SELECT domaine, ip FROM domaines"))
    for ip, mac, nom, domaine, n, bloques, nuit in lignes:
        app = appareils.setdefault(ip, {"ip": ip, "nom": nom, "fabricant": fabricant(mac or ""), "domaines": []})
        if len(app["domaines"]) < 40:  # shortcut: top 40 par appareil pour tenir dans le prompt ; agréger par domaine parent si trop court
            entreprise, categorie = qui.entreprise(domaine)
            app["domaines"].append({"domaine": domaine, "requetes": n, "bloquees": bloques, "bloquable": candidats.contient(domaine) and not est_bloque(domaine), "entre_0h_et_6h": nuit,
                                    "entreprise": entreprise, "categorie": categorie, "pays_serveur": qui.pays(ips.get(domaine))})
    # connexions sorties par le serveur (flux.py) : les volumes envoyés, jamais le contenu
    for ip, cible, envoye, recu in db.execute("""SELECT ip, COALESCE(domaine, dest), SUM(envoye), SUM(recu) FROM connexions
                                                  WHERE t >= ? GROUP BY ip, 2 ORDER BY SUM(envoye) DESC""", (depuis,)):
        if ip in appareils and len(appareils[ip].setdefault("envoye_a", [])) < 15:
            appareils[ip]["envoye_a"].append({"destination": cible, "octets_envoyes": envoye, "octets_recus": recu})
    return list(appareils.values())


CONSIGNE_QUESTION = """You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours (with the company, activity and server country when known) and, in "envoye_a", the byte volumes
it sent and received per destination when it goes out through the server (never the content), then a question. Answer briefly and simply, in the language of the question, using only this data;
if the data cannot answer it, say so."""


def cle():
    """La variable GEMINI_API_KEY, sinon le fichier ~/.config/khada3/cle (pour ne pas la taper en clair)."""
    fichier = Path.home() / ".config/khada3/cle"
    return os.environ.get("GEMINI_API_KEY") or (fichier.read_text().strip() if fichier.exists() else "")


def demander(donnees_json, question=None):
    """Sans question : le rapport du soir, en JSON (SCHEMA). Avec : la réponse de l'agent à cette question."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODELE}:generateContent"
    texte = donnees_json + (f"\n\nQuestion: {question}" if question else "")
    corps = {"systemInstruction": {"parts": [{"text": CONSIGNE_QUESTION if question else CONSIGNE}]},
             "contents": [{"role": "user", "parts": [{"text": texte}]}]}
    if not question:
        corps["generationConfig"] = {"responseMimeType": "application/json", "responseSchema": SCHEMA}
    req = urllib.request.Request(url, json.dumps(corps).encode(), {
        "Content-Type": "application/json", "x-goog-api-key": cle()})
    reponse = json.load(urllib.request.urlopen(req, timeout=120))
    return "".join(p.get("text", "") for p in reponse["candidates"][0]["content"]["parts"])


def attaques(maintenant=None, jours=1):
    """Le piège fakh sur `jours` jours, ou None s'il n'est pas installé. Lecture seule : khada3 n'écrit jamais dans sa base."""
    if not FAKH.exists():
        return None
    depuis = (maintenant or time.time()) - jours * 86400
    try:
        db = sqlite3.connect(f"file:{FAKH}?mode=ro", uri=True, timeout=2)
        total, ips = db.execute("SELECT COUNT(*), COUNT(DISTINCT ip) FROM coups WHERE t >= ?", (depuis,)).fetchone()
        services = dict(db.execute("SELECT service, COUNT(*) FROM coups WHERE t >= ? GROUP BY service", (depuis,)))
        mdp = [dict(zip(("identifiant", "mdp", "n"), l)) for l in db.execute(
            """SELECT identifiant, mdp, COUNT(*) FROM coups WHERE t >= ? AND mdp IS NOT NULL
               GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 8""", (depuis,))]
        pages = [dict(zip(("demande", "n"), l)) for l in db.execute(
            "SELECT demande, COUNT(*) FROM coups WHERE t >= ? AND demande IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (depuis,))]
        par_pays = {}
        for ip, n in db.execute("SELECT ip, COUNT(*) FROM coups WHERE t >= ? GROUP BY ip", (depuis,)):
            code = qui.pays(ip) or "?"
            par_pays[code] = par_pays.get(code, 0) + n
        direct = [dict(zip(("t", "ip", "service", "identifiant", "mdp", "demande", "logiciel"), l)) for l in db.execute(
            "SELECT t, ip, service, identifiant, mdp, demande, logiciel FROM coups ORDER BY t DESC LIMIT 30")]
        db.close()
    except sqlite3.Error as e:  # fakh démarre ou écrit : on réessaiera au prochain rafraîchissement
        print("fakh database not readable:", e, flush=True)
        return None
    for d in direct:
        d["pays"] = qui.pays(d["ip"])
    pays = sorted(({"pays": p, "n": n} for p, n in par_pays.items()), key=lambda x: -x["n"])[:10]
    return {"total": total, "ips": ips, "services": services, "mdp": mdp, "pages": pages, "pays": pays, "direct": direct}


def ligne_attaques(a):
    """Une ligne pour le rapport du soir."""
    if not a or not a["total"]:
        return ""
    texte = f"\n\nTrap (fakh): {a['total']} attempts from {a['ips']} IPs"
    if a["mdp"]:
        texte += f" · top login {a['mdp'][0]['identifiant']} / {a['mdp'][0]['mdp']} ({a['mdp'][0]['n']})"
    if a["pays"]:
        texte += f" · top country {a['pays'][0]['pays']}"
    return texte


def rapport():
    """(texte du rapport, nouvelles propositions enregistrées) ; les propositions sont filtrées avant d'être gardées."""
    appareils = donnees(time.time() - 86400)
    if not appareils:
        return "khada3: no DNS request in the last 24 hours. Is the server running?", []
    reponse = json.loads(demander(json.dumps(appareils, ensure_ascii=False)))
    vus = {d["domaine"] for a in appareils for d in a["domaines"]}
    nouvelles = []
    with verrou, sqlite3.connect(BASE) as db:
        for p in reponse.get("a_bloquer", [])[:8]:
            domaine, raison = str(p.get("domaine", "")).strip().lower(), " ".join(str(p.get("raison", "")).split())[:300]
            # garde-fou : un domaine vu, dans la liste candidate (Hagezi Pro), pas déjà bloqué, jamais proposé deux fois.
            # Sans ça, le modèle a proposé connectivitycheck.gstatic.com, dont Android a besoin pour savoir s'il a Internet.
            if domaine in vus and DOMAINE.match(domaine) and candidats.contient(domaine) and not est_bloque(domaine):
                curseur = db.execute("INSERT OR IGNORE INTO propositions (t, domaine, raison) VALUES (?, ?, ?)", (time.time(), domaine, raison))
                if curseur.rowcount:
                    nouvelles.append({"id": curseur.lastrowid, "domaine": domaine, "raison": raison})
    return "khada3, daily report\n\n" + reponse.get("rapport", "") + ligne_attaques(attaques()), nouvelles


def semaine(maintenant=None, db=None):
    """Rapport de la semaine, sans IA : requêtes par appareil comparées à la semaine d'avant, appareils devenus muets
    (éteints, ou qui ne passent plus par khada3), domaines les plus bloqués."""
    maintenant, db = maintenant or time.time(), db or sqlite3.connect(BASE)
    debut = maintenant - 7 * 86400
    appareils = db.execute("""SELECT ip, SUM(t >= ?), SUM(t >= ? AND bloque), SUM(t < ?), MAX(t) FROM requetes
                              WHERE t >= ? AND t < ? GROUP BY ip ORDER BY SUM(t >= ?) DESC""",
                           (debut, debut, debut, debut - 7 * 86400, maintenant, debut)).fetchall()
    if not appareils:
        return "khada3: no DNS request in the last two weeks. Is the server running?"
    lignes = ["khada3, weekly report", ""]
    for ip, n, bloques, avant, _ in appareils:
        evolution = f"{(n - avant) * 100 // avant:+d} % vs last week" if avant else "new this week"
        if n:
            lignes.append(f"- {nom_appareil(db, ip)}: {n:,} requests ({evolution}), {bloques:,} blocked")
    muets = [f"{nom_appareil(db, ip)} (last request {time.strftime('%a %d %b', time.localtime(dernier))})"
             for ip, *_, dernier in appareils if dernier < maintenant - 86400]
    if muets:
        lignes += ["", "Silent for over a day, switched off or no longer using khada3:", *(f"- {m}" for m in muets)]
    bloques = db.execute("""SELECT domaine, COUNT(*) FROM requetes WHERE t >= ? AND bloque = 1
                            GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 5""", (debut,)).fetchall()
    if bloques:
        lignes += ["", "Most blocked:", *(f"- {d}: {n:,}" for d, n in bloques)]
    return "\n".join(lignes)


PISTAGE = {"advertising", "analytics", "social", "fingerprinting", "email tracking"}


def echapper(texte):
    return str(texte).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def carte(maintenant=None, db=None):
    """La semaine en une image à partager (SVG 1080x1350) : chiffres, appareils, qui piste, où partent les requêtes."""
    maintenant, db = maintenant or time.time(), db or sqlite3.connect(BASE)
    debut = maintenant - 7 * 86400
    total, bloques = db.execute("SELECT COUNT(*), COALESCE(SUM(bloque), 0) FROM requetes WHERE t >= ?", (debut,)).fetchone()
    if not total:
        return None
    appareils = db.execute("""SELECT ip, COUNT(*), SUM(bloque) FROM requetes WHERE t >= ? GROUP BY ip
                              ORDER BY COUNT(*) DESC LIMIT 6""", (debut,)).fetchall()
    pisteurs, pays, ips = {}, {}, dict(db.execute("SELECT domaine, ip FROM domaines"))
    for domaine, n, n_bloques in db.execute("SELECT domaine, COUNT(*), SUM(bloque) FROM requetes WHERE t >= ? GROUP BY domaine", (debut,)):
        nom, categorie = qui.entreprise(domaine)
        if categorie in PISTAGE:
            pisteurs[nom] = pisteurs.get(nom, 0) + n
        if n > n_bloques and (code := qui.pays(ips.get(domaine))):  # une requête bloquée n'est partie nulle part
            pays[code] = pays.get(code, 0) + n - n_bloques
    pisteurs = sorted(pisteurs.items(), key=lambda x: -x[1])[:5]
    partis = sum(pays.values()) or 1
    pays = sorted(pays.items(), key=lambda x: -x[1])[:5]

    fond, texte, gris, trait, accent = "#0b0b0c", "#ededed", "#8a8f98", "#26282d", "#5e6ad2"
    du, au = time.strftime("%d %b", time.localtime(debut)), time.strftime("%d %b %Y", time.localtime(maintenant))
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1350" font-family="Noto Sans, sans-serif">',
         f'<rect width="1080" height="1350" fill="{fond}"/>',
         f'<text x="72" y="120" fill="{texte}" font-size="44" font-weight="700">khada3</text>',
         f'<text x="72" y="166" fill="{gris}" font-size="28">Your home network, {du} to {au}</text>']
    for i, (valeur, legende) in enumerate([(f"{total:,}", "lookups"), (f"{bloques:,}", f"blocked · {bloques * 100 // total} %"),
                                           (str(len(appareils)), "devices")]):
        x = 72 + i * 320
        s += [f'<text x="{x}" y="290" fill="{accent if i == 1 else texte}" font-size="72" font-weight="700">{valeur}</text>',
              f'<text x="{x}" y="334" fill="{gris}" font-size="26">{legende}</text>']
    piege = attaques(maintenant, jours=7)
    if piege and piege["total"]:  # fakh : ce qui a frappé aux fausses portes cette semaine
        haut = f" · top country {piege['pays'][0]['pays']}" if piege["pays"] else ""
        s.append(f'<text x="72" y="388" fill="{accent}" font-size="26">Trap: {piege["total"]:,} break-in attempts from {piege["ips"]:,} IPs{haut}</text>')
    s.append(f'<text x="72" y="440" fill="{gris}" font-size="24" letter-spacing="2">DEVICES</text>')
    plus = appareils[0][1]
    for i, (ip, n, nb) in enumerate(appareils):
        y = 490 + i * 62
        largeur = max(4, 480 * n / plus)
        nom = re.sub(r"\s*\d+\.\d+\.\d+\.\d+$", "", nom_appareil(db, ip))  # pas d'adresse IP sur une image faite pour être partagée
        s += [f'<text x="72" y="{y + 22}" fill="{texte}" font-size="26">{echapper(nom)[:22]}</text>',
              f'<rect x="420" y="{y}" width="{largeur:.0f}" height="28" rx="6" fill="{trait}"/>',
              f'<rect x="420" y="{y}" width="{max(2, largeur * (nb or 0) / n):.0f}" height="28" rx="6" fill="{accent}"/>',
              f'<text x="{430 + largeur:.0f}" y="{y + 22}" fill="{gris}" font-size="22">{n:,}</text>']
    for colonne, (titre, lignes) in enumerate([("WHO TRACKED YOU", [(nom, f"{n:,}") for nom, n in pisteurs]),
                                               ("WHERE IT WENT", [(code, f"{n * 100 // partis} %") for code, n in pays])]):
        x = 72 + colonne * 500
        s.append(f'<text x="{x}" y="900" fill="{gris}" font-size="24" letter-spacing="2">{titre}</text>')
        for i, (gauche, droite) in enumerate(lignes):
            y = 960 + i * 58
            s += [f'<text x="{x}" y="{y}" fill="{texte}" font-size="30">{echapper(gauche)[:18]}</text>',
                  f'<text x="{x + 420}" y="{y}" fill="{gris}" font-size="28" text-anchor="end">{droite}</text>']
    s += [f'<line x1="72" y1="1250" x2="1008" y2="1250" stroke="{trait}" stroke-width="2"/>',
          f'<text x="72" y="1296" fill="{gris}" font-size="22">Self-hosted DNS + AI agent · github.com/onezdtr/khada3</text>', "</svg>"]
    return "\n".join(s)


def png(svg):
    """PNG de la carte avec rsvg-convert (paquet librsvg2-tools) ; None s'il n'est pas installé."""
    try:
        return subprocess.run(["rsvg-convert", "-f", "png"], input=svg.encode(), capture_output=True, check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None


if __name__ == "__main__" and "--semaine" in sys.argv:
    texte, image = semaine(), carte()
    if "--ecran" in sys.argv:
        print(texte)
        if image and (contenu := png(image)):
            Path("semaine.png").write_bytes(contenu)
            print("\nimage: semaine.png")
    else:
        messager.envoyer(texte)
        if image and (contenu := png(image)):
            messager.photo(contenu, "Your week")
elif __name__ == "__main__":
    texte, propositions = rapport()
    if "--ecran" in sys.argv:
        print(texte, *(f"\n? {p['domaine']}: {p['raison']}" for p in propositions))
    else:
        messager.envoyer(texte)
        for p in propositions:
            messager.proposer(p)
