import base64
import socket
import tempfile
import time
from pathlib import Path

import fakh


def connecter(port, envoi, attendre=b""):
    """Joue un attaquant : envoie tout d'un coup, lit jusqu'à la fermeture (ou `attendre`)."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(envoi)
        recu = b""
        while attendre not in recu or not attendre:
            morceau = s.recv(4096)
            if not morceau:
                break
            recu += morceau
        return recu


def coups():
    time.sleep(0.2)  # le fil du serveur note après avoir répondu
    return fakh.db.execute("SELECT service, identifiant, mdp, demande, logiciel FROM coups ORDER BY rowid").fetchall()


def test_sans_telnet():
    assert fakh.sans_telnet(b"\xff\xfb\x01\xff\xfd\x03root\r\n") == b"root\r\n"  # WILL ECHO, DO SGA
    assert fakh.sans_telnet(b"\xff\xfa\x18\x00xterm\xff\xf0admin") == b"admin"  # sous-négociation du type de terminal
    assert fakh.sans_telnet(b"a\xff\xffb\xff") == b"a\xffb"  # 255 doublé ; IAC coupé en fin de paquet


def test_propre():
    assert fakh.propre("ro\x1b[31mot\x00\r\n") == "ro[31mot"
    assert len(fakh.propre("x" * 5000)) == fakh.TAILLE


def test_pieges():
    with tempfile.TemporaryDirectory() as d:
        fakh.ouvrir(Path(d) / "fakh.db")
        fakh.DELAI = fakh.Piege.timeout = 1
        ssh, telnet, web = (s.server_address[1] for s in fakh.lancer("127.0.0.1", {"ssh": 0, "telnet": 0, "web": 0}))

        assert connecter(ssh, b"SSH-2.0-libssh_0.9.6\r\n").startswith(b"SSH-2.0-OpenSSH")

        # comme Mirai : négociation Telnet puis 2 essais d'un coup, puis il raccroche
        recu = connecter(telnet, b"\xff\xfb\x18root\r\nxc3511\r\nadmin\r\nadmin\r\n", b"login: " * 3)
        assert recu.count(b"Login incorrect") == 2

        auth = base64.b64encode(b"admin:1234")
        recu = connecter(web, b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: zgrab/0.x\r\nAuthorization: Basic " + auth + b"\r\n\r\n")
        assert recu.startswith(b"HTTP/1.1 404")

        connecter(telnet, b"")  # se connecte et ne dit rien : rien n'est noté
        assert coups() == [("ssh", None, None, None, "SSH-2.0-libssh_0.9.6"),
                           ("telnet", "root", "xc3511", None, None), ("telnet", "admin", "admin", None, None),
                           ("web", "admin", "1234", "GET /.env HTTP/1.1", "zgrab/0.x")]

        # khada3 lit la même base, en lecture seule, pour le tableau de bord et le rapport du soir
        import resume
        resume.FAKH = Path(d) / "fakh.db"
        a = resume.attaques()
        assert (a["total"], a["ips"], a["services"]) == (4, 1, {"ssh": 1, "telnet": 2, "web": 1})
        assert a["mdp"][0]["n"] == 1 and a["pages"] == [{"demande": "GET /.env HTTP/1.1", "n": 1}]
        assert a["pays"] == [{"pays": "?", "n": 4}] and a["direct"][0]["service"] == "web"
        assert resume.ligne_attaques(a).startswith("\n\nTrap (fakh): 4 attempts from 1 IPs")
        resume.FAKH = Path(d) / "absent.db"
        assert resume.attaques() is None and resume.ligne_attaques(None) == ""

        fakh.db.execute("UPDATE coups SET t = 0 WHERE service = 'ssh'")
        fakh.purger()
        assert len(coups()) == 3


if __name__ == "__main__":
    for nom, f in list(globals().items()):
        if nom.startswith("test_"):
            f()
            print("ok", nom)
