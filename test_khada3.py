import os
import tempfile
from pathlib import Path

import khada3

# requête « A exemple.fr », id 0xabcd, RD levé
REQUETE = bytes.fromhex("abcd01000001000000000000") + b"\x07exemple\x02fr\x00" + b"\x00\x01\x00\x01"


def test_lire_question():
    domaine, fin = khada3.lire_question(REQUETE)
    assert domaine == "exemple.fr" and fin == len(REQUETE)


def test_paquets_mal_formes():
    for mauvais in (b"", REQUETE[:14], REQUETE[:-2], REQUETE[:12] + b"\x50" + b"a" * 80):
        try:
            khada3.lire_question(mauvais)
        except (ValueError, IndexError):
            continue
        raise AssertionError(mauvais)


def test_reponse_bloquee():
    _, fin = khada3.lire_question(REQUETE)
    r = khada3.reponse_vide(REQUETE, fin, 3)
    assert r[:2] == b"\xab\xcd"  # même identifiant
    assert r[2] == 0x81 and r[3] == 0x83  # réponse, RD recopié, RA, domaine inexistant
    assert r[4:12] == b"\x00\x01" + b"\x00" * 6 and r[12:] == REQUETE[12:]


def test_liste_sous_domaines_et_relecture():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "bloquer.txt"
        f.write_text("# commentaire\ndoubleclick.net  # pub\n")
        liste = khada3.Liste(f)
        assert liste.contient("ad.doubleclick.net") and liste.contient("doubleclick.net")
        assert not liste.contient("notdoubleclick.net") and not liste.contient("net")
        f.write_text("exemple.fr\n")
        os.utime(f, (1, 1))  # date différente même si l'écriture tombe dans la même seconde
        assert liste.contient("www.exemple.fr") and not liste.contient("ad.doubleclick.net")


def test_bloquer_refuse_les_domaines_invalides():
    import web
    for mauvais in ("", "pas un domaine", "a\nb.com", "x" * 300 + ".com", "../etc", "com"):
        try:
            web.bloquer(mauvais)
        except ValueError:
            continue
        raise AssertionError(mauvais)
    assert web.DOMAINE.match("ads.tiktok.com") and web.DOMAINE.match("_dns.example.fr")


# réponse à REQUETE : 2 enregistrements A dont le nom pointe vers la question (compression 0xc00c), TTL 120 et 30
REPONSE = (bytes.fromhex("abcd81800001000200000000") + REQUETE[12:]
           + bytes.fromhex("c00c00010001000000780004") + bytes([93, 184, 215, 14])
           + bytes.fromhex("c00c000100010000001e0004") + bytes([93, 184, 215, 15]))


def test_lire_reponse():
    _, fin = khada3.lire_question(REQUETE)
    assert khada3.lire_reponse(REPONSE, fin) == (["93.184.215.14", "93.184.215.15"], 30)
    try:
        khada3.lire_reponse(REPONSE[:-3], fin)
        raise AssertionError("réponse tronquée acceptée")
    except IndexError:
        pass


def test_cache_garde_la_reponse_avec_le_nouvel_identifiant():
    _, fin = khada3.lire_question(REQUETE)
    khada3.cache.clear()
    khada3.mettre_en_cache(REQUETE, fin, REPONSE)
    autre = b"\x12\x34" + REQUETE[2:]
    assert khada3.depuis_cache(autre, fin) == b"\x12\x34" + REPONSE[2:]
    khada3.cache.clear()
    tronquee = REPONSE[:2] + bytes([REPONSE[2] | 0x02]) + REPONSE[3:]
    khada3.mettre_en_cache(REQUETE, fin, tronquee)
    assert khada3.depuis_cache(REQUETE, fin) is None


def test_renommage_refuse_ne_verrouille_pas_la_base():
    import sqlite3
    import web
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "t.db")
        sqlite3.connect(base).executescript("CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);"
                                            "CREATE TABLE requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);")
        ancienne, web.BASE = web.BASE, base
        try:
            web.nommer("10.9.9.9", "x")
            raise AssertionError("appareil inconnu accepté")
        except ValueError:
            pass
        finally:
            web.BASE = ancienne
        c = sqlite3.connect(base, timeout=0.5)
        c.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 0)")  # lèverait « database is locked »
        c.commit()


def test_liste_format_hosts():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "hosts"
        f.write_text("# en-tête\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.exemple.com  # pub\n127.0.0.1 traque.fr\n::1 ip6-localhost\n")
        liste = khada3.Liste(f)
        assert liste.contient("ads.exemple.com") and liste.contient("x.traque.fr")
        assert liste.domaines == {"ads.exemple.com", "traque.fr"}


def test_autoriser_passe_avant_les_listes():
    with tempfile.TemporaryDirectory() as d:
        anciennes = khada3.liste, khada3.autorises, khada3.publique
        (Path(d) / "pub").write_text("0.0.0.0 cdn.exemple.com\n")
        (Path(d) / "perso").write_text("exemple.org\n")
        (Path(d) / "ok").write_text("cdn.exemple.com\n")
        khada3.liste, khada3.autorises, khada3.publique = (khada3.Liste(Path(d) / n) for n in ("perso", "ok", "pub"))
        try:
            assert not khada3.est_bloque("cdn.exemple.com") and khada3.est_bloque("www.exemple.org")
        finally:
            khada3.liste, khada3.autorises, khada3.publique = anciennes


def test_qui_entreprise_et_pays():
    import gzip
    import json
    import qui
    with tempfile.TemporaryDirectory() as d:
        dis = Path(d) / "dis.json"
        dis.write_text(json.dumps({"categories": {
            "Content": [{"Pubco": {"https://pub.co/": ["pub.co"], "performance": "true"}}],
            "Advertising": [{"Pubco": {"https://pub.co/": ["pub.co"]}}],
            "Social": [{"Amis": {"https://amis.fr/": ["amis.fr"]}}]}}))
        ip = Path(d) / "ip.csv.gz"
        with gzip.open(ip, "wt") as f:
            f.write("0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n2.0.0.0,2.255.255.255,FR\n::,ffff::,US\n")
        anciens = qui.entreprises, qui.plages
        qui.entreprises, qui.plages = qui.Charge(dis, qui.lire_disconnect), qui.Charge(ip, qui.lire_dbip)
        try:
            assert qui.entreprise("ads.pub.co") == ("Pubco", "advertising")  # la pub passe avant le contenu
            assert qui.entreprise("amis.fr") == ("Amis", "social") and qui.entreprise("co") == (None, None)
            assert qui.pays("2.4.5.6") == "FR" and qui.pays("1.0.0.9") == "AU"
            assert qui.pays("0.1.2.3") is None and qui.pays("pas une ip") is None and qui.pays(None) is None
        finally:
            qui.entreprises, qui.plages = anciens



def test_proposition_acceptee_bloque_le_domaine_une_seule_fois():
    import sqlite3
    import web
    with tempfile.TemporaryDirectory() as d:
        base, perso = os.path.join(d, "t.db"), Path(d) / "bloquer.txt"
        sqlite3.connect(base).executescript("CREATE TABLE propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');"
                                            "INSERT INTO propositions (t, domaine, raison) VALUES (1, 'pub.exemple.com', 'pub'), (2, 'mesure.exemple.com', 'stats');")
        sauve = web.BASE, web.LISTE, web.AUTORISER, khada3.liste, khada3.autorises, khada3.publique
        web.BASE, web.LISTE, web.AUTORISER = base, perso, Path(d) / "autoriser.txt"
        khada3.liste, khada3.autorises, khada3.publique = khada3.Liste(perso), khada3.Liste(web.AUTORISER), khada3.Liste(Path(d) / "rien")
        try:
            assert web.decider(1, True) == "pub.exemple.com" and khada3.est_bloque("x.pub.exemple.com")
            assert web.decider(2, False) == "mesure.exemple.com" and not khada3.est_bloque("mesure.exemple.com")
            for ident in (1, 2, 99):  # déjà décidée ou inconnue
                try:
                    web.decider(ident, True)
                    raise AssertionError(ident)
                except ValueError:
                    pass
            assert perso.read_text() == "pub.exemple.com\n"
        finally:
            web.BASE, web.LISTE, web.AUTORISER, khada3.liste, khada3.autorises, khada3.publique = sauve


def test_agent_ne_peut_proposer_que_des_pisteurs_reconnus():
    import json
    import sqlite3
    import time
    import resume
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "t.db")
        db = sqlite3.connect(base)
        db.executescript("CREATE TABLE requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);"
                         "CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);"
                         "CREATE TABLE domaines (domaine TEXT PRIMARY KEY, ip TEXT);"
                         "CREATE TABLE devinettes (ip TEXT PRIMARY KEY, genre TEXT, rang INTEGER);"
                         "CREATE TABLE propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');")
        for dom in ("connectivitycheck.gstatic.com", "unagi-na.amazon.com", "deja.bloque.com"):
            db.execute("INSERT INTO requetes VALUES (?, '10.0.0.2', ?, 0)", (time.time(), dom))
        db.commit()
        (Path(d) / "cand").write_text("unagi-na.amazon.com\nbloque.com\npas-vu.com\n")
        (Path(d) / "perso").write_text("deja.bloque.com\n")
        sauve = resume.BASE, resume.demander, resume.candidats, khada3.liste, khada3.autorises, khada3.publique
        resume.BASE, resume.candidats = base, khada3.Liste(Path(d) / "cand")
        khada3.liste, khada3.autorises, khada3.publique = khada3.Liste(Path(d) / "perso"), khada3.Liste(Path(d) / "x"), khada3.Liste(Path(d) / "y")
        proposees = ["connectivitycheck.gstatic.com", "unagi-na.amazon.com", "deja.bloque.com", "pas-vu.com"]
        resume.demander = lambda *a: json.dumps({"rapport": "ok", "a_bloquer": [{"domaine": x, "raison": "r"} for x in proposees]})
        try:
            _, nouvelles = resume.rapport()
            assert [p["domaine"] for p in nouvelles] == ["unagi-na.amazon.com"]
            _, nouvelles = resume.rapport()
            assert nouvelles == []  # jamais deux fois
        finally:
            resume.BASE, resume.demander, resume.candidats, khada3.liste, khada3.autorises, khada3.publique = sauve


def test_messager_boutons_et_questions():
    import messager
    import web
    appels = []
    sauve = web.decider, web.demander
    web.decider = lambda ident, accepter: appels.append((ident, accepter)) or "pub.exemple.com"
    web.demander = lambda q: f"réponse à {q}"
    try:
        assert messager.traiter({"callback_query": {"data": "b:7"}}, "1") == "pub.exemple.com blocked."
        assert messager.traiter({"callback_query": {"data": "i:8"}}, "1") == "pub.exemple.com ignored."
        assert appels == [(7, True), (8, False)]
        assert messager.traiter({"callback_query": {"data": "b:pas-un-nombre"}}, "1").startswith("Nothing done")
        assert messager.traiter({"message": {"text": "qui parle la nuit ?"}}, "1") == "réponse à qui parle la nuit ?"
        assert messager.traiter({"message": {}}, "1") is None
    finally:
        web.decider, web.demander = sauve


def base_test():
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);"
                     "CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);"
                     "CREATE TABLE domaines (domaine TEXT PRIMARY KEY, ip TEXT);"
                     "CREATE TABLE habitudes (ip TEXT, genre TEXT, valeur TEXT, PRIMARY KEY (ip, genre, valeur));"
                     "CREATE TABLE devinettes (ip TEXT PRIMARY KEY, genre TEXT, rang INTEGER);")
    return db


def test_nouveautes_une_seule_fois_par_appareil():
    import qui
    db = base_test()
    db.execute("INSERT INTO domaines VALUES ('graph.facebook.com', '2.3.4.5')")
    sauve = qui.entreprise, qui.pays
    qui.entreprise = lambda d: ("Facebook", "social") if d.endswith("facebook.com") else (None, None)
    qui.pays = lambda ip: "IE" if ip else None
    try:
        assert khada3.nouveautes(db, "10.0.0.2", "graph.facebook.com") == ["a server in IE", "Facebook (social)"]
        assert khada3.nouveautes(db, "10.0.0.2", "graph.facebook.com") == []
        assert khada3.nouveautes(db, "10.0.0.3", "graph.facebook.com") != []  # autre appareil : nouveau pour lui
        assert khada3.nouveautes(db, "10.0.0.2", "inconnu.fr") == []
    finally:
        qui.entreprise, qui.pays = sauve


def test_alertes_plafonnees():
    import messager
    envoyes, sauve = [], messager.envoyer
    messager.envoyer = envoyes.append
    khada3.alertes.clear()
    try:
        for i in range(khada3.MAX_ALERTES + 5):
            khada3.alerter(str(i))
        import time
        time.sleep(0.2)
        assert len(envoyes) == khada3.MAX_ALERTES
    finally:
        messager.envoyer = sauve
        khada3.alertes.clear()


def test_pic_nocturne():
    import time
    db = base_test()
    nuit = time.mktime((2026, 11, 13, 4, 0, 0, 0, 0, -1))  # 4 h du matin, heure locale
    db.execute("INSERT INTO appareils VALUES ('10.0.0.2', '', 0, 'TV')")
    for k in range(7 * 24):  # habitude : 10 requêtes par heure
        db.executemany("INSERT INTO requetes VALUES (?, '10.0.0.2', 'x.fr', 0)", [(nuit - 7200 - k * 3600,)] * 10)
    db.executemany("INSERT INTO requetes VALUES (?, '10.0.0.2', 'pub.tv', 0)", [(nuit - 60,)] * 150)
    db.executemany("INSERT INTO requetes VALUES (?, '10.0.0.3', 'calme.fr', 0)", [(nuit - 60,)] * 20)
    pics = khada3.pics_nocturnes(db, nuit)
    assert len(pics) == 1 and pics[0].startswith("TV: 150 requests between 03:00 and 04:00") and "pub.tv (150)" in pics[0]
    assert khada3.pics_nocturnes(db, nuit + 6 * 3600) == []  # 10 h : on ne regarde que la nuit


def test_chronologie_24_cases():
    import web
    db = base_test()
    maintenant = 1_800_000_000 + 1800  # milieu d'une heure
    db.executemany("INSERT INTO requetes VALUES (?, ?, ?, ?)", [(maintenant, "a", "pub.fr", 1), (maintenant - 60, "b", "ok.fr", 0),
                                                                 (maintenant - 5 * 3600, "a", "ok.fr", 0), (maintenant - 30 * 3600, "a", "vieux.fr", 0)])
    cases = web.heures(db, "", (), maintenant)
    assert len(cases) == 24 and cases[-1]["t"] == 1_800_000_000 and cases[-1]["requetes"] == 2 and cases[-1]["bloquees"] == 1
    assert cases[-6]["top"] == [{"domaine": "ok.fr", "requetes": 1}] and sum(c["requetes"] for c in cases) == 3
    assert web.heures(db, "AND ip = ?", ("a",), maintenant)[-1]["requetes"] == 1


def test_amont_de_secours_et_cache_perime():
    import socket, threading
    faux = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # faux serveur amont qui répond REPONSE
    faux.bind(("127.0.0.1", 0))
    mort = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mort.bind(("127.0.0.1", 0))
    port_mort = mort.getsockname()[1]
    mort.close()  # port fermé : le premier amont ne répond pas
    threading.Thread(target=lambda: faux.sendto(REPONSE, faux.recvfrom(512)[1]), daemon=True).start()
    avant, noter = khada3.AMONTS, khada3.noter
    khada3.noter = lambda *a: None  # ne rien écrire dans la vraie base
    try:
        khada3.AMONTS = [("127.0.0.1", port_mort), faux.getsockname()]
        assert khada3.relayer(REQUETE) == REPONSE  # bascule sur le second
        _, fin = khada3.lire_question(REQUETE)
        khada3.cache.clear()
        khada3.cache[REQUETE[12:fin]] = (0, REPONSE)  # entrée expirée depuis longtemps
        khada3.AMONTS = [("127.0.0.1", port_mort)]  # plus aucun amont
        assert khada3.depuis_cache(REQUETE, fin) is None
        assert khada3.traiter(REQUETE, "test")[2:] == REPONSE[2:]  # réponse périmée plutôt qu'une panne
        khada3.cache.clear()
        assert khada3.traiter(REQUETE, "test")[3] & 0x0F == 2  # rien en réserve : SERVFAIL
    finally:
        khada3.AMONTS, khada3.noter = avant, noter
        khada3.cache.clear()
        faux.close()


def test_question_de_sante_repondue_sur_place():
    q = bytes.fromhex("beef01000001000000000000") + b"".join(bytes([len(m)]) + m.encode() for m in khada3.SANTE.split(".")) + b"\x00\x00\x01\x00\x01"
    r = khada3.traiter(q, "127.0.0.1")
    assert r[:2] == b"\xbe\xef" and r[3] & 0x0F == 0


def test_noms_tailscale():
    import json, stat
    etat = {"Self": {"TailscaleIPs": ["100.64.0.1"], "DNSName": "server.tail.ts.net."},
            "Peer": {"k": {"TailscaleIPs": ["100.64.0.2"], "HostName": "localhost", "DNSName": "phone.tail.ts.net."}}}
    with tempfile.TemporaryDirectory() as d:
        faux = Path(d) / "tailscale"
        faux.write_text("#!/bin/sh\ncat <<'FIN'\n" + json.dumps(etat) + "\nFIN\n")
        faux.chmod(faux.stat().st_mode | stat.S_IEXEC)
        chemin = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + chemin
        try:
            assert khada3.nom_tailscale("100.64.0.2") == "phone"  # DNSName, pas « localhost »
            assert khada3.nom_tailscale("100.1.2.3") == "" and khada3.nom_tailscale("192.168.1.10") == ""
            db = base_test()
            db.executemany("INSERT INTO appareils VALUES (?, '', 0, ?)", [("100.64.0.2", None), ("100.64.0.1", "mon nom"), ("192.168.1.5", None)])
            khada3.nommer_tailscale(db)
            assert dict(db.execute("SELECT ip, nom FROM appareils")) == {"100.64.0.2": "phone", "100.64.0.1": "mon nom", "192.168.1.5": None}
        finally:
            os.environ["PATH"] = chemin
    os.environ["PATH"] = "/nonexistent"
    try:
        assert khada3.nom_tailscale("100.64.0.2") == ""  # pas de Tailscale : pas de nom, pas de plantage
    finally:
        os.environ["PATH"] = chemin


def test_pause_du_blocage():
    import messager
    import web
    avant, noter, relayer = khada3.PAUSE, khada3.noter, khada3.relayer
    d = Path(tempfile.mkdtemp())
    khada3.PAUSE = web.PAUSE = d / "pause"
    khada3.noter = lambda *a: None
    khada3.relayer = lambda *a: REPONSE
    khada3.liste.domaines, khada3.liste.date = {"exemple.fr"}, khada3.LISTE.stat().st_mtime if khada3.LISTE.exists() else None
    try:
        assert khada3.traiter(REQUETE, "test")[3] & 0x0F == 3  # bloqué
        assert messager.traiter({"message": {"text": "/pause 5"}}, "1") == "Blocking paused for 5 min."
        assert 290 < khada3.pause_restante() <= 300
        assert messager.traiter({"message": {"text": "/pause abc"}}, "1").startswith("Usage")
        khada3.cache.clear()
        assert khada3.traiter(REQUETE, "test")[2:] == REPONSE[2:]  # en pause : relayé normalement
        assert khada3.est_bloque("exemple.fr")  # la liste ne change pas : débloquer pendant une pause reste juste
        assert messager.traiter({"message": {"text": "/resume"}}, "1") == "Blocking is on again."
        assert khada3.pause_restante() == 0 and khada3.traiter(REQUETE, "test")[3] & 0x0F == 3
        assert web.pause(99999) == 1440  # jamais plus d'un jour
        (d / "pause").write_text("pas un nombre")
        assert khada3.pause_restante() == 0  # fichier abîmé : le blocage reste actif
    finally:
        khada3.PAUSE, khada3.noter, khada3.relayer = avant, noter, relayer
        web.PAUSE = avant
        khada3.liste.date = None  # relire le vrai fichier au prochain appel
        khada3.cache.clear()


def test_regles_par_appareil():
    avant, base = khada3.REGLES, khada3.db
    khada3.REGLES = Path(tempfile.mkdtemp()) / "regles.txt"
    khada3.REGLES.write_text("tiktok.com 23-7 TV du Salon  # la nuit\ninstagram.com 192.168.1.9\nyoutube.com 8-16\npas un domaine 192.168.1.9\n")
    khada3.db = base_test()
    khada3.db.execute("INSERT INTO appareils VALUES ('192.168.1.5', '', 0, 'tv du salon')")
    try:
        r = khada3.bloque_par_regle
        assert r("192.168.1.5", "www.tiktok.com", 23) and r("192.168.1.5", "tiktok.com", 6)  # passe minuit, nom sans casse
        assert not r("192.168.1.5", "tiktok.com", 7) and not r("192.168.1.6", "tiktok.com", 23)  # 7 h exclu, autre appareil
        assert r("192.168.1.9", "instagram.com", 12) and not r("192.168.1.5", "instagram.com", 12)  # IP, toute la journée
        assert r("192.168.1.6", "youtube.com", 8) and not r("192.168.1.6", "youtube.com", 16)  # sans appareil : tous
        assert len(khada3.regles()) == 3  # la ligne invalide est ignorée
    finally:
        khada3.REGLES, khada3.db = avant, base


def test_contournement_propose_une_seule_fois():
    db = base_test()
    db.execute("CREATE TABLE propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente')")
    db.execute("INSERT INTO appareils VALUES ('192.168.1.5', '', 0, 'iphone')")
    p = khada3.contournement(db, "192.168.1.5", "mozilla.cloudflare-dns.com")
    assert p["domaine"] == "mozilla.cloudflare-dns.com" and p["raison"].startswith("iphone tried Cloudflare encrypted DNS")
    assert khada3.contournement(db, "192.168.1.5", "mozilla.cloudflare-dns.com") is None  # déjà proposé
    assert khada3.contournement(db, "192.168.1.5", "example.com") is None
    assert khada3.contournement(db, "192.168.1.5", "mask.icloud.com")["raison"].endswith("fall back to khada3.")


def test_rapport_de_la_semaine():
    import resume
    db = base_test()
    jour, maintenant = 86400, 1_000_000_000
    db.executemany("INSERT INTO appareils VALUES (?, '', 0, ?)", [("1.1.1.5", "tv"), ("1.1.1.6", "iphone")])
    db.executemany("INSERT INTO requetes VALUES (?, ?, ?, ?)",
                   [(maintenant - 10 * jour, "1.1.1.5", "a.com", 0)] * 4 +  # semaine d'avant : 4
                   [(maintenant - 3 * jour, "1.1.1.5", "pub.com", 1)] * 6 +  # cette semaine : 6, puis plus rien
                   [(maintenant - 3600, "1.1.1.6", "b.com", 0)])
    texte = resume.semaine(maintenant, db)
    assert "- tv: 6 requests (+50 % vs last week), 6 blocked" in texte
    assert "- iphone: 1 requests (new this week), 0 blocked" in texte
    assert texte.split("no longer using khada3:")[1].split("\n")[1].startswith("- tv (last request")
    assert "- pub.com: 6" in texte
    assert "Is the server running" in resume.semaine(maintenant + 30 * jour, db)


def test_regles_depuis_telegram_et_la_page():
    import messager
    import web
    avant = web.REGLES, khada3.REGLES
    web.REGLES = Path(tempfile.mkdtemp()) / "regles.txt"
    web.REGLES.write_text("youtube.com 8-16  # école")  # édité à la main, sans retour à la ligne final
    try:
        m = lambda texte: messager.traiter({"message": {"text": texte}}, "1")
        assert m("/rule  tiktok.com 23-7  TV du salon") == "Rule added: tiktok.com 23-7 TV du salon"
        assert m("/rule tiktok.com 23-7 TV du salon") == "Rule added: tiktok.com 23-7 TV du salon"  # pas de doublon
        assert m("/rule pas un domaine").startswith("Nothing done")
        assert m("/rule a.com\nb.com") == "Rule added: a.com b.com"  # jamais deux lignes : « b.com » devient le nom d'appareil
        assert m("/rules") == "1. youtube.com 8-16\n2. tiktok.com 23-7 TV du salon\n3. a.com b.com"
        assert m("/unrule 3") == "Rule removed: a.com b.com"
        assert m("/unrule tiktok.com 23-7 TV du salon").startswith("Rule removed")
        assert m("/unrule 9").startswith("Nothing done")
        assert web.REGLES.read_text().count("youtube.com 8-16  # école") == 1 and web.regles() == ["youtube.com 8-16"]
        khada3.REGLES = web.REGLES
        assert khada3.regles() == [("youtube.com", 8, 16, "")]  # le DNS lit bien ce que la page écrit
    finally:
        web.REGLES, khada3.REGLES = avant


def test_deviner_le_type_d_appareil():
    db = base_test()
    db.executemany("INSERT INTO appareils VALUES (?, '', 0, ?)", [("10.0.0.2", None), ("10.0.0.3", None), ("10.0.0.4", "salon")])
    for ip, domaine in [("10.0.0.2", "auth.np.playstation.net"), ("10.0.0.2", "captive.apple.com"),  # téléphone avec l'appli PS
                        ("10.0.0.2", "playstation.net"), ("10.0.0.3", "eu.lgtvsdp.com"), ("10.0.0.3", "android.clients.google.com"),
                        ("10.0.0.6", "android.clients.google.com"), ("10.0.0.6", "mirrors.fedoraproject.org"),  # Linux avec Brave
                        ("10.0.0.4", "captive.apple.com"), ("10.0.0.5", "example.com")]:
        khada3.deviner(db, ip, domaine)
    assert khada3.nom_appareil(db, "10.0.0.2") == "Apple device 10.0.0.2"  # le test réseau d'Apple bat l'appli PlayStation
    assert khada3.nom_appareil(db, "10.0.0.3") == "LG TV 10.0.0.3"  # la TV n'est pas rétrogradée en « Android »
    assert khada3.nom_appareil(db, "10.0.0.4") == "salon"  # le nom donné passe avant
    assert db.execute("SELECT genre FROM devinettes WHERE ip = '10.0.0.6'").fetchone() == ("Linux computer",)
    assert db.execute("SELECT COUNT(*) FROM devinettes").fetchone()[0] == 4


def test_hors_khada3():
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.executescript("""CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);
                        CREATE TABLE hors_khada3 (mac TEXT PRIMARY KEY, ip TEXT, vu_le REAL);""")
    db.execute("INSERT INTO appareils VALUES ('192.168.1.172', 'aa:bb:cc:00:00:02', 0, NULL)")
    arp = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:11:22:33:44:01     *        wlp3s0
192.168.1.172    0x1         0x2         aa:bb:cc:00:00:02     *        wlp3s0
192.168.1.176    0x1         0x2         aa:bb:cc:00:00:03     *        wlp3s0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlp3s0
"""
    assert khada3.hors_khada3(db, arp, "192.168.1.1", 1) == [("192.168.1.176", "aa:bb:cc:00:00:03")]  # ni la box, ni un connu, ni une IP non résolue
    assert khada3.hors_khada3(db, arp.replace(".176", ".177"), "192.168.1.1", 2) == []  # une seule alerte, même si l'IP change
    assert db.execute("SELECT ip, vu_le FROM hors_khada3").fetchall() == [("192.168.1.177", 2)]
    db.execute("INSERT INTO appareils VALUES ('192.168.1.177', 'aa:bb:cc:00:00:03', 3, NULL)")
    assert khada3.hors_khada3(db, arp, "192.168.1.1", 3) == [] and not db.execute("SELECT * FROM hors_khada3").fetchall()


if __name__ == "__main__":
    for nom, f in list(globals().items()):
        if nom.startswith("test_"):
            f()
    print("ok")
