"""fakh (« piège » en darija) : faux services SSH, Telnet et web qui notent qui essaie d'entrer.

Aucun vrai shell : chaque connexion est lue, notée dans fakh.db, puis refusée.
Tourne à part de khada3, sous son propre utilisateur sans droits (fakh.service) ; khada3 ne fait que lire la base.
"""
import base64
import os
import socketserver
import sqlite3
import threading
import time
from pathlib import Path

BASE = Path(os.environ.get("FAKH_BASE", Path(__file__).parent / "fakh.db"))
ECOUTE = os.environ.get("FAKH_ECOUTE", "127.0.0.1")  # 0.0.0.0 sur le serveur
PORTS = {"ssh": int(os.environ.get("FAKH_SSH", "2222")), "telnet": int(os.environ.get("FAKH_TELNET", "2323")),
         "web": int(os.environ.get("FAKH_WEB", "8080"))}
BANNIERE = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"  # une version courante : un piège qui se voit n'attrape rien
DELAI = 10  # secondes : un attaquant lent ne garde pas un fil
TAILLE = 200  # caractères gardés par champ
GARDER = 30 * 86400
# shortcut: un seul attaquant peut occuper les 50 places, mais il ne peut rien casser ; filtrer par IP si ça arrive
places = threading.BoundedSemaphore(50)
verrou = threading.Lock()
db = None


def ouvrir(chemin=BASE):
    global db
    db = sqlite3.connect(chemin, check_same_thread=False)
    db.execute("""CREATE TABLE IF NOT EXISTS coups (t REAL, ip TEXT, service TEXT, identifiant TEXT, mdp TEXT,
                  demande TEXT, logiciel TEXT)""")
    db.execute("CREATE INDEX IF NOT EXISTS coups_t ON coups(t)")
    db.commit()


def propre(texte):
    """Tout vient de l'attaquant : texte imprimable seulement, longueur bornée."""
    return None if texte is None else "".join(c for c in texte if c.isprintable())[:TAILLE]


def noter(ip, service, identifiant=None, mdp=None, demande=None, logiciel=None):
    with verrou:
        db.execute("INSERT INTO coups VALUES (?, ?, ?, ?, ?, ?, ?)", (time.time(), ip, service, *map(propre, (identifiant, mdp, demande, logiciel))))
        db.commit()


def sans_telnet(octets):
    """Retire les négociations Telnet (IAC …) pour ne garder que ce que l'attaquant a tapé."""
    sortie, i = bytearray(), 0
    while i < len(octets):
        if octets[i] != 255:
            sortie.append(octets[i])
            i += 1
        elif octets[i + 1:i + 2] == b"\xff":  # 255 doublé = l'octet 255 lui-même
            sortie.append(255)
            i += 2
        elif octets[i + 1:i + 2] == b"\xfa":  # sous-négociation, jusqu'à IAC SE
            fin = octets.find(b"\xff\xf0", i + 2)
            i = len(octets) if fin < 0 else fin + 2
        else:  # WILL/WONT/DO/DONT + option : 3 octets ; les autres commandes : 2
            i += 3 if octets[i + 1:i + 2] and 251 <= octets[i + 1] <= 254 else 2
    return bytes(sortie)


def ligne(f, telnet=False):
    """Une ligne envoyée par l'attaquant, ou None s'il est parti ou se tait."""
    try:
        brut = f.readline(512)
    except OSError:  # délai dépassé ou connexion coupée
        return None
    if not brut:
        return None
    # shortcut: une ligne finie par \r\0 (vieux clients Telnet) attend le délai ; les botnets envoient \r\n
    return propre((sans_telnet(brut) if telnet else brut).decode("utf-8", "replace"))


class Piege(socketserver.StreamRequestHandler):
    timeout = DELAI
    service = None

    def handle(self):
        if not places.acquire(blocking=False):
            return
        try:
            getattr(self, self.service)(self.client_address[0])
        except OSError:  # l'attaquant a coupé : rien à faire
            pass
        finally:
            places.release()

    def ssh(self, ip):
        # shortcut: on note l'IP et le logiciel du client, pas le mot de passe (il faut le chiffrement SSH pour ça)
        self.wfile.write(BANNIERE)
        noter(ip, "ssh", logiciel=ligne(self.rfile))

    def telnet(self, ip):
        for _ in range(3):  # comme un vrai login : 3 essais
            self.wfile.write(b"login: ")
            if (identifiant := ligne(self.rfile, telnet=True)) is None:
                return
            self.wfile.write(b"Password: ")
            mdp = ligne(self.rfile, telnet=True)
            if identifiant or mdp:
                noter(ip, "telnet", identifiant, mdp)
            if mdp is None:
                return
            time.sleep(1)  # un vrai login fait attendre après un échec
            self.wfile.write(b"\r\nLogin incorrect\r\n")

    def web(self, ip):
        demande, entetes = ligne(self.rfile), {}
        if demande is None:
            return
        for _ in range(50):
            if not (l := ligne(self.rfile)):
                break
            nom, _, valeur = l.partition(":")
            entetes[nom.strip().lower()] = valeur.strip()
        identifiant = mdp = None
        if entetes.get("authorization", "").lower().startswith("basic "):  # identifiants d'un routeur, d'une caméra…
            try:
                identifiant, _, mdp = base64.b64decode(entetes["authorization"][6:]).decode("utf-8", "replace").partition(":")
            except ValueError:
                pass
        noter(ip, "web", identifiant, mdp, demande, entetes.get("user-agent"))
        corps = b"<html><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\r\n"
        self.wfile.write(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(corps) + corps)


class Serveur(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def lancer(ecoute=ECOUTE, ports=PORTS):
    serveurs = []
    for service, port in ports.items():
        s = Serveur((ecoute, port), type(service, (Piege,), {"service": service}))
        threading.Thread(target=s.serve_forever, daemon=True).start()
        serveurs.append(s)
    return serveurs


def purger():
    with verrou:
        db.execute("DELETE FROM coups WHERE t < ?", (time.time() - GARDER,))
        db.commit()


if __name__ == "__main__":
    ouvrir()
    lancer()
    print("fakh:", ", ".join(f"{s} {ECOUTE}:{p}" for s, p in PORTS.items()), flush=True)
    while True:
        purger()
        time.sleep(3600)
