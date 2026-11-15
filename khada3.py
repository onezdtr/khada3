"""khada3 : serveur DNS qui note, appareil par appareil, les domaines contactés.

Les requêtes sont relayées vers un vrai serveur DNS ; les domaines de bloquer.txt reçoivent « n'existe pas ».
Chaque nouvel appareil déclenche une alerte Telegram (voir messager.py).
"""
import json
import os
import re
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import messager
import qui

ICI = Path(__file__).parent
BASE = ICI / "khada3.db"
LISTE = ICI / "bloquer.txt"
AUTORISER = ICI / "autoriser.txt"
PUBLIQUE = ICI / "listes/publique.txt"
CANDIDATS = ICI / "listes/candidats.txt"  # liste plus stricte, non appliquée : ce que l'agent a le droit de proposer
URL_CANDIDATS = os.environ.get("KHADA3_CANDIDATS_URL", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt")
DOMAINE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")
URL_PUBLIQUE = os.environ.get("KHADA3_LISTE_URL", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")  # vide : désactivée
ECOUTE = os.environ.get("KHADA3_ECOUTE", "127.0.0.1")  # 0.0.0.0 sur le serveur, jamais sur un réseau qui n'est pas le nôtre
PORT = int(os.environ.get("KHADA3_PORT", "5300"))  # 53 sur le serveur
AMONTS = [(ip.strip(), 53) for ip in os.environ.get("KHADA3_AMONT", "1.1.1.1,9.9.9.9").split(",")]  # le suivant si le premier ne répond pas
REGLES = ICI / "regles.txt"  # blocages pour un seul appareil, éventuellement à certaines heures
PAUSE = ICI / "pause"  # date de fin d'une pause du blocage ; un fichier, car web.py importe une seconde copie de ce module
SANTE = "sante.khada3.invalid"  # question que khada3 se pose à lui-même : répondue sur place, jamais notée
PRIVE = "(private)"  # noté à la place du domaine pour un appareil privé : il est filtré, pas surveillé

# DNS chiffré et Relais privé iCloud : l'appareil qui les utilise ne passe plus par khada3 (un domaine couvre ses sous-domaines)
CONTOURNEMENTS = {"dns.google": "Google encrypted DNS", "cloudflare-dns.com": "Cloudflare encrypted DNS",
                  "one.one.one.one": "Cloudflare encrypted DNS", "dns.quad9.net": "Quad9 encrypted DNS",
                  "doh.opendns.com": "OpenDNS encrypted DNS", "dns.nextdns.io": "NextDNS encrypted DNS",
                  "dns.adguard-dns.com": "AdGuard encrypted DNS", "dns.mullvad.net": "Mullvad encrypted DNS",
                  "doh.mullvad.net": "Mullvad encrypted DNS", "mask.icloud.com": "iCloud Private Relay",
                  "mask-h2.icloud.com": "iCloud Private Relay"}

# domaine qui trahit le type d'appareil ; le plus haut gagne. Les tests réseau d'Apple, Android et Windows passent
# avant PlayStation et Roku : un téléphone avec leur appli reste un téléphone. Les TV d'abord : elles n'ont pas ces tests.
# Android en dernier : Chrome et Brave appellent ses domaines (notifications) sur tous les systèmes.
SIGNATURES = {domaine: (rang, genre) for rang, (domaine, genre) in enumerate([
    ("samsungotn.net", "Samsung TV"), ("lgtvsdp.com", "LG TV"), ("lgsmartad.com", "LG TV"),
    ("firetvcaptiveportal.com", "Fire TV"), ("nintendowifi.net", "Nintendo console"),
    # avant Windows : des applis Android (Tailscale…) testent aussi msftconnecttest.com ; iron passait pour un PC
    ("nflx-android-tv.prod.partner.netflix.net", "Android TV"), ("androidtvchannels-pa.googleapis.com", "Android TV"),
    ("captive.apple.com", "Apple device"), ("msftconnecttest.com", "Windows PC"),
    ("nmcheck.gnome.org", "Linux computer"), ("connectivity-check.ubuntu.com", "Linux computer"),
    ("fedoraproject.org", "Linux computer"), ("connectivitycheck.android.com", "Android device"),
    ("android.clients.google.com", "Android device"), ("playstation.net", "PlayStation"), ("roku.com", "Roku")])}

verrou = threading.RLock()  # réentrant : décider d'une proposition puis bloquer le domaine le reprend
db = sqlite3.connect(BASE, check_same_thread=False)
# WAL : une écriture coûte 0,1 ms au lieu de 10 sur le serveur (chaque réponse DNS l'attend), et le tableau de bord
# peut lire pendant qu'on écrit. synchronous=NORMAL : une coupure de courant peut perdre les dernières requêtes notées, jamais abîmer la base.
db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
db.executescript("""
CREATE TABLE IF NOT EXISTS requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);
CREATE TABLE IF NOT EXISTS appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL);
CREATE INDEX IF NOT EXISTS requetes_t ON requetes (t);
CREATE TABLE IF NOT EXISTS domaines (domaine TEXT PRIMARY KEY, ip TEXT);
CREATE TABLE IF NOT EXISTS propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');
CREATE TABLE IF NOT EXISTS habitudes (ip TEXT, genre TEXT, valeur TEXT, PRIMARY KEY (ip, genre, valeur));
CREATE TABLE IF NOT EXISTS devinettes (ip TEXT PRIMARY KEY, genre TEXT, rang INTEGER);
CREATE TABLE IF NOT EXISTS hors_khada3 (mac TEXT PRIMARY KEY, ip TEXT, vu_le REAL);
CREATE TABLE IF NOT EXISTS prives (cle TEXT PRIMARY KEY);  -- MAC (ou IP sans MAC) des appareils privés
""")
if "nom" not in [c[1] for c in db.execute("PRAGMA table_info(appareils)")]:
    db.execute("ALTER TABLE appareils ADD COLUMN nom TEXT")  # bases créées avant les noms d'appareils
GARDER = 30 * 86400  # au-delà, les requêtes sont effacées
APPRENTISSAGE = 86400  # un appareil neuf contacte tout : pas d'alerte « première fois » pendant son premier jour
EXPIRATION = 7 * 86400  # une suggestion sans réponse depuis une semaine sort de la liste (et n'est pas reproposée)
MAX_ALERTES = 10  # par heure : une appli neuve qui contacte 30 pisteurs ne doit pas inonder Telegram
alertes = []  # dates des dernières alertes envoyées
cache, verrou_cache = {}, threading.Lock()


def lire_question(paquet):
    """Renvoie (domaine, fin de la question) ; ValueError si le paquet est mal formé."""
    if len(paquet) < 12 or paquet[4:6] != b"\x00\x01":  # une seule question, comme tous les clients
        raise ValueError("paquet DNS inattendu")
    i, morceaux = 12, []
    while True:
        n = paquet[i]
        if n == 0:
            break
        if n > 63 or i + 1 + n > len(paquet):  # 63 max ; pas de compression dans une question
            raise ValueError("nom invalide")
        morceaux.append(paquet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    fin = i + 5  # octet nul + type + classe
    if fin > len(paquet):
        raise ValueError("question tronquée")
    return ".".join(morceaux).lower(), fin


def sauter_nom(paquet, i):
    """Position après un nom DNS (compressé ou non) dans une réponse."""
    while True:
        n = paquet[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # pointeur de compression : 2 octets, fin du nom
            return i + 2
        i += 1 + n


def lire_reponse(reponse, fin):
    """Adresses IPv4 et plus petit TTL des réponses ; IndexError si le paquet est tronqué."""
    i, ips, ttl = fin, [], None
    for _ in range(int.from_bytes(reponse[6:8], "big")):
        i = sauter_nom(reponse, i)
        type_, duree, taille = int.from_bytes(reponse[i:i + 2], "big"), int.from_bytes(reponse[i + 4:i + 8], "big"), int.from_bytes(reponse[i + 8:i + 10], "big")
        if i + 10 + taille > len(reponse):
            raise IndexError("réponse tronquée")
        if type_ == 1 and taille == 4:
            ips.append(socket.inet_ntoa(reponse[i + 10:i + 14]))
        ttl = duree if ttl is None else min(ttl, duree)
        i += 10 + taille
    return ips, ttl


def reponse_vide(paquet, fin, code):
    """Réponse sans enregistrement : code 3 = domaine inexistant, 2 = échec du serveur."""
    drapeaux = 0x8080 | (paquet[2] & 0x79) << 8 | code  # réponse + opcode et RD du client + RA
    return paquet[:2] + drapeaux.to_bytes(2, "big") + b"\x00\x01" + b"\x00" * 6 + paquet[12:fin]


def lire_liste(chemin):
    """Domaines d'un fichier : « domaine » ou le format hosts « 0.0.0.0 domaine » des listes publiques."""
    domaines = set()
    for ligne in chemin.read_text().split("\n"):
        mots = ligne.split("#")[0].lower().split()
        if len(mots) == 2 and mots[0] in ("0.0.0.0", "127.0.0.1"):
            mots = mots[1:]
        if len(mots) == 1 and "." in mots[0] and mots[0] != "0.0.0.0":
            domaines.add(mots[0])
    return domaines


class Liste(qui.Charge):
    """Fichier de domaines relu dès qu'il change ; un domaine couvre tous ses sous-domaines."""
    def __init__(self, chemin):
        super().__init__(chemin, lire_liste)

    def contient(self, domaine):
        domaines = self() or set()
        return any(d in domaines for d in parents(domaine))


liste, autorises, publique, candidats = Liste(LISTE), Liste(AUTORISER), Liste(PUBLIQUE), Liste(CANDIDATS)


def est_bloque(domaine):
    return not autorises.contient(domaine) and (liste.contient(domaine) or publique.contient(domaine))


def parents(domaine):
    """exemple.fr pour www.exemple.fr, etc. : le domaine et tous ceux qui le contiennent."""
    morceaux = domaine.split(".")
    return [".".join(morceaux[i:]) for i in range(len(morceaux))]


regles_lues = {"date": None, "regles": []}


def regles():
    """Lignes de regles.txt « domaine [heures] appareil », ex. « tiktok.com 23-7 TV du salon » ; relu dès qu'il change.
    L'appareil est son IP ou le nom donné dans le tableau de bord, sans appareil la règle vaut pour tous ;
    sans heures, elle vaut tout le temps."""
    date = REGLES.stat().st_mtime if REGLES.exists() else None
    if date != regles_lues["date"]:
        lignes = REGLES.read_text().split("\n") if date else []
        regles_lues.update(date=date, regles=[r for ligne in lignes if (r := lire_regle(ligne))])
    return regles_lues["regles"]


def lire_regle(ligne):
    """(domaine, début, fin, appareil) d'une ligne de regles.txt, ou None si elle n'est pas valable."""
    mots = ligne.split("#")[0].split()
    heures = re.fullmatch(r"(\d{1,2})-(\d{1,2})", mots[1]) if len(mots) > 1 else None
    debut, fin = (int(heures[1]), int(heures[2])) if heures else (0, 24)
    if not mots or not DOMAINE.match(mots[0].lower()) or debut > 24 or fin > 24:
        return None
    return mots[0].lower(), debut, fin, " ".join(mots[2:] if heures else mots[1:]).lower()


def bloque_par_regle(ip, domaine, heure):
    """Vrai si une règle de regles.txt bloque ce domaine pour cet appareil à cette heure (23-7 passe minuit)."""
    for cible, debut, fin, appareil in regles():
        if cible in parents(domaine) and (debut <= heure < fin if debut <= fin else heure >= debut or heure < fin):
            if appareil in ("", ip):
                return True
            with verrou:  # le nom n'est cherché que si le domaine et l'heure correspondent
                nom = db.execute("SELECT nom FROM appareils WHERE ip = ?", (ip,)).fetchone()
            if nom and (nom[0] or "").lower() == appareil:
                return True
    return False


def contournement(db, ip, domaine):
    """Propose de bloquer un service de contournement la 1re fois qu'un appareil le demande ; renvoie la proposition."""
    service = next((CONTOURNEMENTS[d] for d in parents(domaine) if d in CONTOURNEMENTS), None)
    if not service:
        return None
    raison = (f"{nom_appareil(db, ip)} tried {service}: its requests would stop going through khada3. "
              "Blocking it makes the device fall back to khada3.")
    curseur = db.execute("INSERT OR IGNORE INTO propositions (t, domaine, raison) VALUES (?, ?, ?)", (time.time(), domaine, raison))
    return {"id": curseur.lastrowid, "domaine": domaine, "raison": raison} if curseur.rowcount else None


def pause_restante():
    """Secondes de pause du blocage qui restent (0 : le blocage marche)."""
    try:
        return max(0.0, float(PAUSE.read_text()) - time.time())
    except (OSError, ValueError):
        return 0.0


def telecharger(urls, chemin, taille_min):
    """Premier lien qui marche, écrit d'un coup (jamais de fichier à moitié écrit pendant qu'on le lit)."""
    for url in urls:
        try:
            requete = urllib.request.Request(url, headers={"User-Agent": "khada3 (+https://github.com/onezdtr/khada3)"})  # DB-IP refuse Python-urllib
            donnees = urllib.request.urlopen(requete, timeout=60).read()
        except OSError as e:
            erreur = e
            continue
        if len(donnees) < taille_min:
            erreur = ValueError(f"{url} : fichier trop petit, téléchargement suspect")
            continue
        chemin.parent.mkdir(exist_ok=True)
        provisoire = chemin.with_name(chemin.name + ".tmp")
        provisoire.write_bytes(donnees)
        provisoire.replace(chemin)
        print(f"{chemin.name} updated ({len(donnees) // 1024} KB)", flush=True)
        return
    print(f"{chemin.name} not updated:", erreur, flush=True)


def maj_listes():
    """Liste de blocage et entreprises chaque semaine, pays chaque mois ; on revérifie chaque jour."""
    while True:
        mois = time.strftime("%Y-%m"), time.strftime("%Y-%m", time.localtime(time.time() - 28 * 86400))
        for chemin, jours, urls, taille_min in (
                (PUBLIQUE, 7, [URL_PUBLIQUE] if URL_PUBLIQUE else [], 100_000),
                (CANDIDATS, 7, [URL_CANDIDATS] if URL_CANDIDATS else [], 100_000),
                (qui.DISCONNECT, 7, [qui.URL_DISCONNECT], 50_000),
                (qui.DBIP, 30, [qui.URL_DBIP.format(mois=m) for m in mois], 1_000_000)):  # le fichier du mois sort parfois en retard
            if urls and (not chemin.exists() or chemin.stat().st_mtime < time.time() - jours * 86400):
                telecharger(urls, chemin, taille_min)
        time.sleep(86400)


def mac_de(ip):
    """Adresse MAC vue dans la table ARP du serveur (vide pour la machine elle-même)."""
    try:
        for ligne in Path("/proc/net/arp").read_text().splitlines()[1:]:
            champs = ligne.split()
            if champs[0] == ip:
                return champs[3]
    except OSError:
        pass
    return ""


OUI = Path("/usr/share/hwdata/oui.txt")  # paquet hwdata : fabricants des cartes réseau
fabricants = {}


def fabricant(mac):
    """Fabricant d'après le début de l'adresse MAC ; les iPhone et Android récents en tirent une au hasard."""
    if len(mac) < 8:
        return ""
    if int(mac[1], 16) & 2:  # bit « adresse locale » : MAC aléatoire, pas de fabricant
        return "private MAC address"
    if not fabricants and OUI.exists():
        for ligne in OUI.read_text(errors="replace").splitlines():
            if "(hex)" in ligne:
                prefixe, _, nom = ligne.partition("(hex)")
                fabricants[prefixe.strip().replace("-", ":").lower()] = nom.strip()
    return fabricants.get(mac[:8].lower(), "")


def etat_tailscale():
    """`tailscale status --json`, ou {} sans Tailscale."""
    try:
        return json.loads(subprocess.run(["tailscale", "status", "--json"], capture_output=True, timeout=3).stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def lan_tailscale(etat):
    """{IP locale: IP Tailscale} des appareils Tailscale joints en direct (CurAddr « 192.168.1.176:43661 »).
    Tailscale ne la donne que pendant que la connexion est active."""
    return {p["CurAddr"].rpartition(":")[0]: (p.get("TailscaleIPs") or [""])[0]
            for p in (etat.get("Peer") or {}).values() if p.get("CurAddr")}


def lier_tailscale(db, arp, liens):
    """Donne à un appareil Tailscale la MAC de son IP locale (liens : voir lan_tailscale). Son DNS passe par khada3
    dans le tunnel : avec sa MAC, il n'est plus pris pour un appareil qui contourne khada3, même au repos."""
    macs = {c[0]: c[3] for c in (ligne.split() for ligne in arp.splitlines()[1:]) if len(c) >= 4 and c[2] == "0x2"}
    for lan, ts in liens.items():
        if macs.get(lan):
            db.execute("UPDATE appareils SET mac = ? WHERE ip = ? AND COALESCE(mac, '') = ''", (macs[lan], ts))


def nom_tailscale(ip):
    """Nom de la machine dans Tailscale (pas d'adresse MAC à travers le tunnel) ; vide hors Tailscale."""
    if not ip.startswith("100."):
        return ""
    etat = etat_tailscale()
    for machine in [etat.get("Self") or {}, *(etat.get("Peer") or {}).values()]:
        if ip in (machine.get("TailscaleIPs") or []):
            return (machine.get("DNSName") or "").split(".")[0]  # le HostName d'un iPhone vaut « localhost »
    return ""


def nommer_tailscale(db):
    """Au démarrage : nomme les appareils Tailscale déjà vus et encore sans nom."""
    for (ip,) in db.execute("SELECT ip FROM appareils WHERE nom IS NULL AND ip LIKE '100.%'").fetchall():
        if nom := nom_tailscale(ip):
            db.execute("UPDATE appareils SET nom = ? WHERE ip = ?", (nom, ip))
    db.commit()


def nom_appareil(db, ip):
    """Le nom donné, sinon le type deviné, sinon le fabricant, suivi de l'IP."""
    nom, mac, genre = db.execute("""SELECT a.nom, a.mac, d.genre FROM appareils a LEFT JOIN devinettes d ON d.ip = a.ip
                                    WHERE a.ip = ?""", (ip,)).fetchone() or (None, "", None)
    return nom or f"{genre or fabricant(mac or '') or 'device'} {ip}"


def deviner(db, ip, domaine):
    """Retient le type de l'appareil quand ce domaine le trahit, si la signature est plus sûre que la précédente."""
    for d in parents(domaine):
        if d in SIGNATURES:
            rang, genre = SIGNATURES[d]
            db.execute("""INSERT INTO devinettes VALUES (?, ?, ?) ON CONFLICT (ip) DO UPDATE
                          SET genre = excluded.genre, rang = excluded.rang WHERE excluded.rang < devinettes.rang""", (ip, genre, rang))


def nouveautes(db, ip, domaine):
    """Pays de serveur et entreprises que cet appareil contacte pour la première fois (les retient au passage)."""
    adresse = db.execute("SELECT ip FROM domaines WHERE domaine = ?", (domaine,)).fetchone()
    entreprise, categorie = qui.entreprise(domaine)
    vues = []
    for genre, valeur, texte in (("pays", qui.pays(adresse and adresse[0]), "a server in {}"), ("entreprise", entreprise, f"{{}} ({categorie})")):
        if valeur and db.execute("INSERT OR IGNORE INTO habitudes VALUES (?, ?, ?)", (ip, genre, valeur)).rowcount:
            vues.append(texte.format(valeur))
    return vues


def alerter(texte):
    maintenant = time.time()
    alertes[:] = [t for t in alertes if t > maintenant - 3600]
    if len(alertes) < MAX_ALERTES:  # shortcut: au-delà, l'alerte est perdue (l'habitude reste notée) ; les regrouper si ça arrive souvent
        alertes.append(maintenant)
        threading.Thread(target=messager.envoyer, args=(texte,)).start()


def identifier(db, ip):
    """Date de première vue de l'appareil derrière cette IP, ou None s'il est nouveau (il est alors enregistré).
    Un appareil est suivi par son adresse MAC : si la box a donné cette IP à un autre appareil, l'ancien est mis de
    côté sous sa MAC (une règle par nom ne doit pas bloquer le nouveau venu) ; quand il revient avec une autre IP,
    il retrouve son nom, son type et ses habitudes. Sans MAC (Tailscale, le serveur lui-même), l'IP suffit."""
    mac = mac_de(ip)
    ligne = db.execute("SELECT vu_le, mac FROM appareils WHERE ip = ?", (ip,)).fetchone()
    if ligne and not (mac and ligne[1] and mac != ligne[1]):
        if mac and not ligne[1]:  # MAC encore inconnue à la première requête
            db.execute("UPDATE appareils SET mac = ? WHERE ip = ?", (mac, ip))
        return ligne[0]
    if ligne:  # IP reprise par un autre appareil
        deplacer(db, ip, ligne[1])
    ancien = db.execute("""SELECT ip, vu_le FROM appareils WHERE mac = ? AND ip NOT LIKE '100.%'
                           ORDER BY vu_le LIMIT 1""", (mac,)).fetchone() if mac else None  # un appareil Tailscale garde son IP Tailscale
    if ancien:  # appareil connu, nouvelle IP
        deplacer(db, ancien[0], ip)
        return ancien[1]
    db.execute("INSERT INTO appareils (ip, mac, vu_le, nom) VALUES (?, ?, ?, ?)", (ip, mac, time.time(), nom_tailscale(ip) or None))
    return None


def deplacer(db, de, vers):
    """Passe le nom, le type deviné et les habitudes d'un appareil d'une adresse à une autre (l'historique reste par IP)."""
    for table in ("appareils", "devinettes", "habitudes"):
        db.execute(f"UPDATE OR REPLACE {table} SET ip = ? WHERE ip = ?", (vers, de))


def est_prive(db, ip):
    """Appareil privé (par sa MAC, ou son IP sans MAC) : bloqué comme les autres, mais rien de ce qu'il visite n'est gardé."""
    return bool(db.execute("SELECT 1 FROM prives WHERE cle IN (?, ?)", (ip, mac_de(ip) or ip)).fetchone())


def noter(ip, domaine, bloque, prive=False):
    """prive : seulement le nombre de requêtes et de blocages ; ni domaine, ni type deviné, ni habitudes, ni proposition."""
    with verrou:
        vu_le = identifier(db, ip)
        db.execute("INSERT INTO requetes VALUES (?, ?, ?, ?)", (time.time(), ip, PRIVE if prive else domaine, int(bloque)))
        if not prive:
            deviner(db, ip, domaine)  # avant le nom : l'alerte « nouvel appareil » en profite déjà
        vues = [] if bloque or prive else nouveautes(db, ip, domaine)  # bloqué : l'appareil n'a rien contacté
        proposition = None if bloque or prive else contournement(db, ip, domaine)
        nom = nom_appareil(db, ip)
        db.commit()
    if proposition:
        threading.Thread(target=messager.proposer, args=(proposition,)).start()
    if vu_le is None:
        alerter(f"New device on the network: {nom} {mac_de(ip)}" + ("" if prive else f"\nFirst domain: {domaine}"))
    elif vues and vu_le < time.time() - APPRENTISSAGE:
        alerter(f"{nom} contacted {' and '.join(vues)} for the first time\nDomain: {domaine}")


def pics_nocturnes(db, maintenant):
    """Appareils qui, entre 0 h et 6 h, ont fait dans l'heure passée 3 fois plus de requêtes que d'habitude (moyenne horaire sur 7 jours)."""
    if time.localtime(maintenant - 3600).tm_hour >= 6:
        return []
    messages = []
    for ip, n in db.execute("SELECT ip, COUNT(*) FROM requetes WHERE t >= ? GROUP BY ip", (maintenant - 3600,)).fetchall():
        moyenne = db.execute("SELECT COUNT(*) / 168.0 FROM requetes WHERE ip = ? AND t >= ? AND t < ?",
                             (ip, maintenant - 7 * 86400, maintenant - 3600)).fetchone()[0]
        if n >= max(100, 3 * moyenne):
            top = db.execute("SELECT domaine, COUNT(*) FROM requetes WHERE ip = ? AND t >= ? GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 3",
                             (ip, maintenant - 3600)).fetchall()
            messages.append(f"{nom_appareil(db, ip)}: {n} requests between {time.strftime('%H:%M', time.localtime(maintenant - 3600))} "
                            f"and {time.strftime('%H:%M', time.localtime(maintenant))}, usually {moyenne:.0f} an hour.\n"
                            + "\n".join(f"{d} ({k})" for d, k in top))
    return messages


def recevoir(sock, n):
    donnees = b""
    while len(donnees) < n:
        morceau = sock.recv(n - len(donnees))
        if not morceau:
            raise ConnectionError("connexion fermée")
        donnees += morceau
    return donnees


def noter_ip(domaine, reponse, fin):
    """Première adresse du domaine, pour retrouver le pays de son serveur."""
    try:
        ips, _ = lire_reponse(reponse, fin)
    except IndexError:
        return
    if ips:
        try:
            with verrou:
                db.execute("INSERT OR REPLACE INTO domaines VALUES (?, ?)", (domaine, ips[0]))
                db.commit()
        except sqlite3.Error as e:
            print("ip not logged:", e, flush=True)


def relayer(paquet, tcp=False):
    """Essaie chaque serveur amont dans l'ordre ; lève la dernière erreur si aucun ne répond."""
    for amont in AMONTS:
        try:
            return relayer_vers(amont, paquet, tcp)
        except OSError as e:
            erreur = e
    raise erreur


def relayer_vers(amont, paquet, tcp):
    """En TCP pour les réponses trop grosses pour l'UDP (le client réessaie en TCP quand le bit TC est levé)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        if tcp:
            s.connect(amont)
            s.sendall(len(paquet).to_bytes(2, "big") + paquet)
            return recevoir(s, int.from_bytes(recevoir(s, 2), "big"))
        s.sendto(paquet, amont)
        return s.recv(4096)


def depuis_cache(paquet, fin, perime=False):
    """perime : accepte une réponse expirée, pour que les sites déjà vus marchent encore quand l'amont est en panne."""
    with verrou_cache:
        entree = cache.get(paquet[12:fin])
    if entree and (perime or entree[0] > time.time()):
        return paquet[:2] + entree[1][2:]  # la réponse gardée, avec l'identifiant de la nouvelle question
    return None


def mettre_en_cache(paquet, fin, reponse):
    """shortcut: les TTL ne sont pas décomptés (un client peut voir jusqu'à 5 min de trop) ; les réécrire si ça gêne."""
    if reponse[2] & 0x02 or reponse[3] & 0x0F not in (0, 3):  # tronquée, ou erreur du serveur
        return
    try:
        _, ttl = lire_reponse(reponse, fin)
    except IndexError:
        return
    with verrou_cache:
        if len(cache) > 5000:
            cache.clear()
        cache[paquet[12:fin]] = (time.time() + min(ttl if ttl is not None else 60, 300), reponse)


def traiter(paquet, ip, tcp=False):
    """Réponse à une question DNS, ou None si ce n'en est pas une."""
    try:
        domaine, fin = lire_question(paquet)
    except (ValueError, IndexError):
        return None
    if domaine == SANTE:
        return reponse_vide(paquet, fin, 0)
    bloque = (est_bloque(domaine) or bloque_par_regle(ip, domaine, time.localtime().tm_hour)) and not pause_restante()  # pause lue seulement pour les domaines bloqués
    try:
        with verrou:
            prive = est_prive(db, ip)
    except sqlite3.Error:
        prive = True  # dans le doute, on ne garde rien
    if bloque:
        reponse = reponse_vide(paquet, fin, 3)
    elif not (reponse := depuis_cache(paquet, fin)):
        try:
            reponse = relayer(paquet, tcp)
            mettre_en_cache(paquet, fin, reponse)
            if not prive:
                noter_ip(domaine, reponse, fin)
        except OSError:
            reponse = depuis_cache(paquet, fin, perime=True) or reponse_vide(paquet, fin, 2)
    try:
        noter(ip, domaine, bloque, prive)
    except sqlite3.Error as e:  # un journal raté ne doit jamais priver l'appareil de sa réponse
        print("not logged:", e, flush=True)
    return reponse


class GestionUDP(socketserver.BaseRequestHandler):
    def handle(self):
        paquet, sock = self.request
        reponse = traiter(paquet, self.client_address[0])
        if reponse:
            sock.sendto(reponse, self.client_address)


class GestionTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:  # un client peut enchaîner plusieurs questions sur la même connexion
                paquet = recevoir(self.request, int.from_bytes(recevoir(self.request, 2), "big"))
                reponse = traiter(paquet, self.client_address[0], tcp=True)
                if not reponse:
                    return
                self.request.sendall(len(reponse).to_bytes(2, "big") + reponse)
        except OSError:
            pass


def deviner_depuis_historique(db):
    """Au premier démarrage avec cette fonction : devine les appareils déjà vus."""
    if not db.execute("SELECT 1 FROM devinettes LIMIT 1").fetchone():
        for ip, domaine in db.execute("SELECT DISTINCT ip, domaine FROM requetes").fetchall():
            deviner(db, ip, domaine)
        db.commit()


def apprendre(db):
    """Remplit les habitudes depuis l'historique, pour qu'une mise à jour n'envoie pas une alerte par entreprise déjà connue."""
    if db.execute("SELECT 1 FROM habitudes LIMIT 1").fetchone():
        return
    for ip, domaine in db.execute("SELECT DISTINCT ip, domaine FROM requetes WHERE bloque = 0").fetchall():
        nouveautes(db, ip, domaine)
    db.commit()


def expirer(db, maintenant):
    return db.execute("UPDATE propositions SET etat = 'expiree' WHERE etat = 'attente' AND t < ?", (maintenant - EXPIRATION,)).rowcount


def purger():
    """Chaque heure : efface le vieil historique, fait expirer les vieilles suggestions et cherche les pics de trafic nocturnes."""
    while True:
        with verrou:
            db.execute("DELETE FROM requetes WHERE t < ?", (time.time() - GARDER,))
            expirer(db, time.time())
            db.commit()
            pics = pics_nocturnes(db, time.time())
        for texte in pics:
            alerter("Unusual night activity\n" + texte)
        time.sleep(3600)


def passerelle():
    """IP de la box (route par défaut) : toujours présente sur le réseau, elle ne demande rien à khada3."""
    try:
        for ligne in Path("/proc/net/route").read_text().splitlines()[1:]:
            champs = ligne.split()
            if champs[1] == "00000000":
                return socket.inet_ntoa(bytes.fromhex(champs[2])[::-1])
    except (OSError, ValueError, IndexError):
        pass
    return ""


def hors_khada3(db, arp, box, maintenant):
    """Appareils de la table ARP (texte de /proc/net/arp) qui n'ont jamais demandé un domaine à khada3 :
    ils utilisent un autre DNS. Les retient et renvoie ceux vus pour la première fois [(ip, mac)]."""
    connus = {m or i for i, m in db.execute("SELECT ip, mac FROM appareils")}  # par MAC, par IP si la MAC manquait
    nouveaux = []
    for ligne in arp.splitlines()[1:]:
        champs = ligne.split()
        if len(champs) < 4 or champs[2] != "0x2" or champs[0] in (box, *connus) or champs[3] in connus:
            continue  # 0x2 : adresse résolue, l'appareil a parlé récemment
        ip, mac = champs[0], champs[3]
        if db.execute("INSERT OR IGNORE INTO hors_khada3 VALUES (?, ?, ?)", (mac, ip, maintenant)).rowcount:
            nouveaux.append((ip, mac))
        db.execute("UPDATE hors_khada3 SET ip = ?, vu_le = ? WHERE mac = ?", (ip, maintenant, mac))
    db.execute("DELETE FROM hors_khada3 WHERE mac IN (SELECT mac FROM appareils)")  # il a fini par passer par khada3
    return nouveaux


SILENCE = 2 * 3600  # un appareil bavard qui ne demande plus rien depuis 2 h alors qu'il est allumé a changé de DNS
BAVARD = 5  # requêtes par heure en moyenne sur 7 jours : en dessous, un silence de 2 h est normal
silencieux = set()  # MAC déjà signalées ; une MAC en sort dès que l'appareil redemande un domaine


def repond(ip):
    return subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True).returncode == 0


def muets(db, arp, maintenant, joignable=repond):
    """Appareils connus, allumés (dans l'ARP et répondant au ping), d'habitude bavards, mais muets depuis SILENCE :
    ils ont sans doute activé un DNS chiffré ou le Relais privé d'iCloud. Renvoie ceux signalés pour la première fois [(nom, heures)]."""
    nouveaux = []
    for ligne in arp.splitlines()[1:]:
        champs = ligne.split()
        if len(champs) < 4 or champs[2] != "0x2":
            continue
        ip_lan, mac = champs[0], champs[3]
        ips = [i for (i,) in db.execute("SELECT ip FROM appareils WHERE mac = ?", (mac,))]  # IP du réseau et IP Tailscale
        if not ips:
            continue
        marques = ",".join("?" * len(ips))
        dernier, semaine = db.execute(f"SELECT MAX(t), SUM(t > ?) FROM requetes WHERE ip IN ({marques})",
                                      (maintenant - 7 * 86400, *ips)).fetchone()
        if dernier is None or maintenant - dernier < SILENCE:
            silencieux.discard(mac)
            continue
        if mac in silencieux or (semaine or 0) < BAVARD * 7 * 24 or not joignable(ip_lan):
            continue
        silencieux.add(mac)
        nouveaux.append((nom_appareil(db, ips[0]), round((maintenant - dernier) / 3600, 1)))
    return nouveaux


def surveiller_reseau():
    """Toutes les 5 min : signale une fois chaque appareil du réseau qui contourne khada3.
    shortcut: ne voit que les appareils déjà dans la table ARP du serveur (pas de scan), ajouter un ping des IP du réseau si ça ne suffit pas."""
    if ECOUTE.startswith("127."):
        return  # khada3 ne sert que cette machine : la table ARP est celle d'un réseau qui n'est pas le nôtre
    while True:
        try:
            arp = Path("/proc/net/arp").read_text()
        except OSError:
            arp = ""
        with verrou:
            lier_tailscale(db, arp, lan_tailscale(etat_tailscale()))
            nouveaux = hors_khada3(db, arp, passerelle(), time.time())
            db.commit()
            taiseux = muets(db, arp, time.time())
        for nom, heures in taiseux:
            alerter(f"{nom} is on and connected but has not asked khada3 anything for {heures} h.\n"
                    "It probably switched to its own encrypted DNS (DoH, iCloud Private Relay, an app's VPN): khada3 no longer sees or filters it.")
        if nouveaux:
            alerter("On the network but NOT using khada3 (they ask another DNS, probably the box):\n"
                    + "\n".join(f"{fabricant(mac) or 'device'} {ip} {mac}" for ip, mac in nouveaux)
                    + "\nSet their DNS to this server to see and filter them.")
        time.sleep(300)


def question_sante():
    """Question « A sante.khada3.invalid » : identifiant au hasard, puis l'en-tête de 10 octets (RD, une question)."""
    return os.urandom(2) + bytes.fromhex("01000001000000000000") + b"".join(
        bytes([len(m)]) + m.encode() for m in SANTE.split(".")) + b"\x00\x00\x01\x00\x01"


def en_forme():
    """Vrai si le serveur DNS répond et que la base n'est pas bloquée."""
    question = question_sante()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(question, ("127.0.0.1" if ECOUTE == "0.0.0.0" else ECOUTE, PORT))  # là où khada3 écoute vraiment
            if s.recv(512)[:2] != question[:2]:
                return False
        with verrou:
            db.execute("SELECT 1")
        return True
    except (OSError, sqlite3.Error):
        return False


def veiller():
    """Chien de garde systemd (WatchdogSec) : sans signe de vie, systemd redémarre khada3 au lieu de le laisser figé."""
    adresse = os.environ.get("NOTIFY_SOCKET")
    if not adresse:
        return  # lancé à la main, sans systemd
    if adresse.startswith("@"):
        adresse = "\0" + adresse[1:]
    while True:
        if en_forme():
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
                s.sendto(b"WATCHDOG=1", adresse)
        time.sleep(10)


if __name__ == "__main__":
    import sys
    sys.modules["khada3"] = sys.modules[__name__]  # web et resume importent « khada3 » : le même module, pas une 2e copie (listes, verrou)
    import web  # ici, pas en haut : web importe ce module
    apprendre(db)
    deviner_depuis_historique(db)
    nommer_tailscale(db)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    tcp = socketserver.ThreadingTCPServer((ECOUTE, PORT), GestionTCP)
    serveur = socketserver.ThreadingUDPServer((ECOUTE, PORT), GestionUDP)
    print(f"khada3 listening on {ECOUTE}:{PORT} (UDP and TCP), upstream {', '.join(a[0] for a in AMONTS)}", flush=True)
    for cible in (tcp.serve_forever, veiller, purger, surveiller_reseau, maj_listes, messager.ecouter, lambda: web.servir(ECOUTE)):
        threading.Thread(target=cible, daemon=True).start()
    serveur.serve_forever()
