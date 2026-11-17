"""Connexions des appareils qui sortent sur Internet par le serveur (exit node Tailscale) : vers où, combien envoyé et reçu.

Le noyau suit chaque connexion qu'il fait passer (conntrack). Quand elle se termine, on note l'appareil, la destination
(avec le nom que khada3 lui a donné en DNS), le port et les octets dans chaque sens. Jamais le contenu.
Service à part (flux.service) : écouter le noyau demande CAP_NET_ADMIN, et le serveur DNS n'a pas à l'avoir.
Prérequis : paquet conntrack-tools et sysctl net.netfilter.nf_conntrack_acct=1 (sinon les octets valent 0).
"""
import ipaddress
import re
import subprocess
import time

from khada3 import db, etat_tailscale  # crée les tables si besoin

TAILSCALE = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))  # IPv4 et IPv6 des appareils
COMMANDE = ["conntrack", "-E", "-e", "DESTROY", "-o", "timestamp"]  # une ligne par connexion terminée
CHAMP = re.compile(r"(\w+)=(\S+)")


def lire(ligne):
    """(t, appareil, destination, proto, port, octets envoyés, octets reçus), ou None.
    conntrack écrit deux séries src/dst/bytes : l'aller (vu par l'appareil), puis le retour."""
    v = {}
    for cle, valeur in CHAMP.findall(ligne):
        v.setdefault(cle, []).append(valeur)
    proto, t = re.search(r"\b(tcp|udp)\b", ligne), re.match(r"\s*\[(\d+\.\d+)\]", ligne)
    if not proto or len(v.get("src", [])) < 2 or len(v.get("bytes", [])) < 2 or "dport" not in v:
        return None
    return (float(t[1]) if t else time.time(), v["src"][0], v["dst"][0], proto[1], int(v["dport"][0]),
            int(v["bytes"][0]), int(v["bytes"][1]))


def a_noter(appareil, destination):
    """Un appareil Tailscale qui sort sur Internet ; pas le trafic vers le serveur, ni entre appareils."""
    try:
        a = ipaddress.ip_address(appareil)
        return any(a in reseau for reseau in TAILSCALE) and ipaddress.ip_address(destination).is_global
    except ValueError:
        return False


def ipv4_tailscale(etat):
    """{IPv6 Tailscale: IPv4 Tailscale} : khada3 connaît chaque appareil par l'IPv4 de ses requêtes DNS."""
    return {ip: ips[0] for p in (etat.get("Peer") or {}).values()
            if (ips := p.get("TailscaleIPs") or []) and ":" not in ips[0] for ip in ips[1:]}


def noter(db, c):
    t, ip, dest, proto, port, envoye, recu = c
    # appareil privé (par son IP, ou la MAC que khada3 lui connaît) : rien n'est gardé, comme pour ses requêtes DNS
    if db.execute("SELECT 1 FROM prives WHERE cle IN (?, (SELECT mac FROM appareils WHERE ip = ?))", (ip, ip)).fetchone():
        return
    nom = db.execute("SELECT domaine FROM adresses WHERE ip = ?", (dest,)).fetchone()
    db.execute("INSERT INTO connexions VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (t, ip, dest, nom and nom[0], proto, port, envoye, recu))
    db.commit()


if __name__ == "__main__":
    liens = {}
    with subprocess.Popen(COMMANDE, stdout=subprocess.PIPE, text=True) as p:
        print("flux: listening to conntrack", flush=True)
        for ligne in p.stdout:
            if (c := lire(ligne)) and a_noter(c[1], c[2]):
                if ":" in c[1] and c[1] not in liens:  # appareil inconnu ou nouveau : on relit Tailscale
                    liens = ipv4_tailscale(etat_tailscale())
                noter(db, (c[0], liens.get(c[1], c[1]), *c[2:]))
    raise SystemExit(f"conntrack stopped ({p.returncode})")  # systemd le relance
