#!/usr/bin/env python3
"""
Générateur de logs auth.log réalistes pour évaluation de triage.

Principe : on ne génère pas des lignes isolées au hasard, mais des SÉQUENCES
cohérentes produites par des "profils d'activité" (personas). Chaque profil a
une identité stable (ses IP, ses utilisateurs, ses horaires) et un comportement
propre. C'est cette cohérence qui crée le réalisme — et les cas ambigus.

Chaque log généré porte sa VÉRITÉ TERRAIN par construction : le profil qui l'a
produit détermine si c'est benin / malveillant / ambigu. On produit donc DEUX
fichiers :
  - logs.txt        : les lignes de log (à injecter dans Wazuh)
  - verite.jsonl    : pour chaque ligne, son étiquette et sa justification
                      (le "corrigé", à ne PAS donner au LLM)

MVP : format auth.log (SSH + sudo), 4 profils. Conçu pour être étendu.
"""

import json
import random
import argparse
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# Format d'horodatage. Wazuh décode les deux, MAIS il faut que ça corresponde
# à ce que produit TON vrai auth.log. Vérifie une ligne de ton fichier réel
# et choisis en conséquence.
#   "bsd"  -> "Jul  7 14:32:05"          (syslog traditionnel)
#   "iso"  -> "2026-07-07T14:32:05+02:00" (rsyslog / journald moderne)
TIMESTAMP_FORMAT = "bsd"

# Nom(s) de machine surveillée(s). L'identité de la cible est un signal.
HOSTNAMES = ["web-server-prod", "db-server-prod", "vm-app-01"]

# --- Identités stables par profil (la cohérence = le réalisme) ---

# L'administrateur légitime : IP internes connues, comptes d'admin réels.
ADMIN_IPS = ["10.0.1.10", "10.0.1.11"]
ADMIN_USERS = ["thomas", "admin-sys"]

# Les utilisateurs normaux : IP internes, comptes nominatifs.
USER_IPS = ["10.0.2.34", "10.0.2.35", "10.0.2.36", "10.0.2.51"]
NORMAL_USERS = ["camille", "leo", "sarah", "yanis", "marie"]

# Le scanner de vulnérabilités interne : une IP interne dédiée, connue.
SCANNER_IP = "10.0.9.5"

# Les attaquants externes : IP publiques (motif d'attaque).
ATTACKER_IPS = ["45.83.192.44", "185.220.101.7", "193.106.191.22"]

# Comptes souvent visés par les attaques automatisées.
ATTACKED_USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu"]

# Heures ouvrées (pour rendre les horaires réalistes).
WORK_HOURS = range(8, 19)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def format_timestamp(dt):
    """Formate un datetime selon TIMESTAMP_FORMAT."""
    if TIMESTAMP_FORMAT == "iso":
        # +02:00 : ajuste selon ton fuseau si besoin
        return dt.strftime("%Y-%m-%dT%H:%M:%S+02:00")
    # BSD : le jour est sur 2 caractères, espace de tête si < 10
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")  # normalise l'espace


def ligne_ssh_echec(dt, host, user, srcip, port, utilisateur_valide=True):
    """Ligne d'échec d'authentification SSH.
    utilisateur_valide=False -> 'invalid user' (compte inexistant, typique des scans)."""
    pid = random.randint(1000, 65000)
    ts = format_timestamp(dt)
    if utilisateur_valide:
        msg = f"Failed password for {user} from {srcip} port {port} ssh2"
    else:
        msg = f"Failed password for invalid user {user} from {srcip} port {port} ssh2"
    return f"{ts} {host} sshd[{pid}]: {msg}"


def ligne_ssh_succes(dt, host, user, srcip, port):
    """Ligne de connexion SSH réussie."""
    pid = random.randint(1000, 65000)
    ts = format_timestamp(dt)
    return f"{ts} {host} sshd[{pid}]: Accepted password for {user} from {srcip} port {port} ssh2"


def ligne_sudo(dt, host, user, commande):
    """Ligne d'usage de sudo (élévation de privilèges)."""
    ts = format_timestamp(dt)
    return f"{ts} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={commande}"


def evenement(ligne, profil, verite, raison):
    """Emballe une ligne avec sa vérité terrain (étiquetage par construction).
    'verite' ∈ {'benin', 'malveillant', 'ambigu'}."""
    return {"ligne": ligne, "profil": profil, "verite": verite, "raison": raison}


def heure_ouvree(base_day):
    """Un datetime aléatoire pendant les heures ouvrées du jour donné."""
    h = random.choice(list(WORK_HOURS))
    return base_day.replace(hour=h, minute=random.randint(0, 59),
                            second=random.randint(0, 59))


# ---------------------------------------------------------------------------
# PROFILS D'ACTIVITÉ
# Chaque profil retourne une liste d'événements (ligne + vérité terrain).
# ---------------------------------------------------------------------------

def profil_admin_legitime(base_day):
    """BÉNIN. L'admin se connecte en root depuis une IP interne connue, en
    heures ouvrées, et lance des commandes sudo. Génère des alertes Wazuh
    (connexion root, sudo) mais c'est parfaitement légitime : faux positif type."""
    events = []
    host = random.choice(HOSTNAMES)
    ip = random.choice(ADMIN_IPS)
    user = random.choice(ADMIN_USERS)
    dt = heure_ouvree(base_day)

    # Parfois une faute de frappe avant de réussir (très banal)
    if random.random() < 0.3:
        events.append(evenement(
            ligne_ssh_echec(dt, host, user, ip, random.randint(40000, 60000)),
            "admin_legitime", "benin",
            "Echec isole d'un admin (faute de frappe) depuis IP interne connue"))
        dt += timedelta(seconds=random.randint(5, 20))

    events.append(evenement(
        ligne_ssh_succes(dt, host, user, ip, random.randint(40000, 60000)),
        "admin_legitime", "benin",
        "Connexion admin depuis IP interne connue en heures ouvrees"))

    # Quelques commandes sudo (travail d'admin normal)
    for _ in range(random.randint(1, 3)):
        dt += timedelta(seconds=random.randint(10, 120))
        cmd = random.choice(["/usr/bin/apt update", "/bin/systemctl restart nginx",
                             "/usr/bin/vim /etc/hosts", "/bin/journalctl -xe"])
        events.append(evenement(
            ligne_sudo(dt, host, user, cmd),
            "admin_legitime", "benin",
            "Commande sudo d'un admin legitime en heures ouvrees"))
    return events


def profil_utilisateur_distrait(base_day):
    """BÉNIN. Un utilisateur normal rate son mot de passe quelques fois puis
    réussit. C'est LE faux positif classique : ça ressemble à une petite force
    brute, mais c'est juste quelqu'un de distrait."""
    events = []
    host = random.choice(HOSTNAMES)
    ip = random.choice(USER_IPS)
    user = random.choice(NORMAL_USERS)
    dt = heure_ouvree(base_day)

    nb_echecs = random.randint(2, 4)
    for _ in range(nb_echecs):
        events.append(evenement(
            ligne_ssh_echec(dt, host, user, ip, random.randint(40000, 60000)),
            "utilisateur_distrait", "benin",
            f"{nb_echecs} echecs puis succes, meme utilisateur depuis IP interne : distraction"))
        dt += timedelta(seconds=random.randint(3, 15))

    events.append(evenement(
        ligne_ssh_succes(dt, host, user, ip, random.randint(40000, 60000)),
        "utilisateur_distrait", "benin",
        "Succes apres quelques echecs, meme compte, IP interne : utilisateur legitime"))
    return events


def profil_scanner_interne(base_day):
    """BÉNIN (mais bruyant). Le scanner de vulnérabilités interne balaie une
    machine : ça génère plein d'événements qui RESSEMBLENT à de la reconnaissance
    hostile, mais l'IP source est le scanner interne connu. Gros volume de faux
    positifs."""
    events = []
    host = random.choice(HOSTNAMES)
    # Le scan tourne souvent la nuit
    dt = base_day.replace(hour=random.choice([2, 3, 4]),
                          minute=random.randint(0, 59), second=0)

    # Le scanner tente plein de comptes rapidement
    for user in random.sample(ATTACKED_USERS, k=random.randint(3, 6)):
        events.append(evenement(
            ligne_ssh_echec(dt, host, user, SCANNER_IP, random.randint(40000, 60000),
                            utilisateur_valide=False),
            "scanner_interne", "benin",
            "Balayage du scanner de vulnerabilites interne (IP interne dediee connue)"))
        dt += timedelta(seconds=random.randint(1, 4))
    return events


def profil_brute_force_reussie(base_day):
    """MALVEILLANT. Attaque par force brute depuis une IP externe : rafale
    d'échecs sur des comptes variés, puis un SUCCÈS. C'est le scénario grave :
    l'attaquant a fini par entrer."""
    events = []
    host = random.choice(HOSTNAMES)
    ip = random.choice(ATTACKER_IPS)
    # Une attaque peut survenir n'importe quand
    dt = base_day.replace(hour=random.randint(0, 23),
                          minute=random.randint(0, 59), second=random.randint(0, 59))

    # Rafale d'échecs sur des comptes variés (souvent invalides)
    for _ in range(random.randint(8, 20)):
        user = random.choice(ATTACKED_USERS)
        events.append(evenement(
            ligne_ssh_echec(dt, host, user, ip, random.randint(30000, 60000),
                            utilisateur_valide=(user in ["root", "ubuntu"])),
            "brute_force_reussie", "malveillant",
            "Rafale d'echecs sur comptes varies depuis IP externe : force brute"))
        dt += timedelta(seconds=random.randint(1, 3))

    # Le succès final : l'attaque a abouti
    events.append(evenement(
        ligne_ssh_succes(dt, host, "root", ip, random.randint(30000, 60000)),
        "brute_force_reussie", "malveillant",
        "SUCCES sur root depuis IP externe apres rafale d'echecs : compromission probable"))
    return events


def profil_cas_ambigu(base_day):
    """AMBIGU. Série d'échecs suivie d'un succès, MAIS depuis une IP interne
    inhabituelle (ni admin connu, ni scanner). Est-ce un utilisateur qui a
    galéré, ou un mouvement latéral interne (machine déjà compromise) ? Un
    analyste humain hésiterait aussi. C'est le coeur du test de discernement."""
    events = []
    host = random.choice(HOSTNAMES)
    # IP interne mais PAS dans les listes connues (admin/scanner)
    ip = f"10.0.{random.randint(3, 8)}.{random.randint(100, 200)}"
    user = random.choice(["root"] + NORMAL_USERS)
    dt = base_day.replace(hour=random.choice([1, 2, 22, 23]),  # heure inhabituelle
                          minute=random.randint(0, 59), second=random.randint(0, 59))

    for _ in range(random.randint(5, 9)):
        events.append(evenement(
            ligne_ssh_echec(dt, host, user, ip, random.randint(40000, 60000)),
            "cas_ambigu", "ambigu",
            "Echecs puis succes depuis IP interne INCONNUE a heure inhabituelle : "
            "mouvement lateral possible OU utilisateur legitime en difficulte"))
        dt += timedelta(seconds=random.randint(2, 8))

    events.append(evenement(
        ligne_ssh_succes(dt, host, user, ip, random.randint(40000, 60000)),
        "cas_ambigu", "ambigu",
        "Succes final : ambigu (IP interne inconnue, heure creuse, compte sensible)"))
    return events


# ---------------------------------------------------------------------------
# ORCHESTRATEUR
# ---------------------------------------------------------------------------

# Proportions réalistes AU NIVEAU SESSION (≈ unité de triage après corrélation
# Wazuh). Massivement du bénin, comme dans un vrai SOC. (profil, poids).
#
# Cible ici : ~92% bénin, ~4% malveillant, ~4% ambigu au niveau session.
# ATTENTION : au niveau LIGNE, le malveillant paraîtra sur-représenté car la
# force brute génère beaucoup de lignes par session. C'est normal : Wazuh les
# corrèlera en peu d'alertes. Le niveau session est le bon repère.
#
# Compromis à connaître : plus tu es réaliste (bénin dominant), moins tu as de
# cas rares. Pour en avoir assez à mesurer, AUGMENTE -n (ex : -n 500 -> ~20
# sessions malveillantes + ~20 ambiguës). Vise le volume, pas juste la
# proportion.
POIDS_PROFILS = [
    (profil_admin_legitime,       40),
    (profil_utilisateur_distrait, 35),
    (profil_scanner_interne,      17),
    (profil_cas_ambigu,            4),
    (profil_brute_force_reussie,   4),
]


def generer(nb_sessions, nb_jours=7):
    """Génère nb_sessions "sessions" (chaque session = une exécution d'un profil,
    produisant plusieurs lignes) réparties sur nb_jours. Retourne la liste de
    tous les événements, triés chronologiquement."""
    profils = [p for p, _ in POIDS_PROFILS]
    poids = [w for _, w in POIDS_PROFILS]

    debut = datetime.now() - timedelta(days=nb_jours)
    tous_events = []
    sessions = []  # trace de chaque session : (profil, verite) — l'unite de triage

    for _ in range(nb_sessions):
        profil = random.choices(profils, weights=poids, k=1)[0]
        jour = debut + timedelta(days=random.randint(0, nb_jours - 1))
        events_session = profil(jour)
        if events_session:
            # La vérité de la session = celle de ses événements (homogène par profil)
            sessions.append((events_session[0]["profil"], events_session[0]["verite"]))
        tous_events.extend(events_session)

    # Tri chronologique : on relit le timestamp depuis la ligne serait fragile,
    # donc on trie sur l'ordre de génération par jour est insuffisant.
    # Ici on trie en re-parsant le timestamp de chaque ligne.
    def cle_tri(ev):
        return ev["ligne"][:15] if TIMESTAMP_FORMAT == "bsd" else ev["ligne"][:19]

    tous_events.sort(key=cle_tri)
    return tous_events, sessions


def ecrire_sorties(events, fichier_logs, fichier_verite):
    """Écrit les deux fichiers : les logs (pour Wazuh) et la vérité terrain."""
    with open(fichier_logs, "w") as f_log, open(fichier_verite, "w") as f_ver:
        for ev in events:
            f_log.write(ev["ligne"] + "\n")
            # La vérité est indexée par la ligne exacte : Wazuh renvoie le
            # 'full_log' dans ses alertes, ce qui permet de faire la jointure.
            f_ver.write(json.dumps({
                "ligne": ev["ligne"],
                "profil": ev["profil"],
                "verite": ev["verite"],
                "raison": ev["raison"],
            }, ensure_ascii=False) + "\n")


def afficher_stats(events, sessions):
    """Affiche la répartition à DEUX niveaux :
      - SESSION : l'unité de triage (≈ alerte après corrélation Wazuh). C'est
        le repère réaliste — c'est ici qu'on veut voir le bénin dominer.
      - LIGNE   : brut, moins parlant (le malveillant y paraît gonflé car la
        force brute est bavarde). Donné pour information."""
    from collections import Counter

    # --- Niveau session (le repère réaliste) ---
    sess_verite = Counter(v for _, v in sessions)
    sess_profil = Counter(p for p, _ in sessions)
    total_sess = len(sessions)
    print(f"\n=== NIVEAU SESSION ({total_sess} sessions ≈ unites de triage) ===")
    print("Repartition par verite terrain :")
    for k in ("benin", "malveillant", "ambigu"):
        v = sess_verite.get(k, 0)
        print(f"  {k:12} : {v:4} ({100*v/total_sess:.1f}%)")
    print("Repartition par profil :")
    for k, v in sess_profil.most_common():
        print(f"  {k:22} : {v:4}")

    # --- Niveau ligne (pour information) ---
    ligne_verite = Counter(ev["verite"] for ev in events)
    total_lignes = len(events)
    print(f"\n=== NIVEAU LIGNE ({total_lignes} lignes, pour info) ===")
    for k in ("benin", "malveillant", "ambigu"):
        v = ligne_verite.get(k, 0)
        print(f"  {k:12} : {v:5} ({100*v/total_lignes:.1f}%)")

    # --- Garde-fou : assez de cas rares pour mesurer ? ---
    n_malv = sess_verite.get("malveillant", 0)
    n_amb = sess_verite.get("ambigu", 0)
    if n_malv < 10 or n_amb < 10:
        print(f"\n[!] Peu de cas rares (malveillant={n_malv}, ambigu={n_amb}).")
        print("    Augmente -n pour une mesure fiable (vise >=15 par classe rare).")


# ---------------------------------------------------------------------------
# POINT D'ENTRÉE
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generateur de logs auth.log realistes")
    parser.add_argument("-n", "--sessions", type=int, default=100,
                        help="Nombre de sessions a generer (defaut 100)")
    parser.add_argument("-j", "--jours", type=int, default=7,
                        help="Etaler sur N jours (defaut 7)")
    parser.add_argument("--logs", default="logs.txt", help="Fichier de sortie des logs")
    parser.add_argument("--verite", default="verite.jsonl", help="Fichier de verite terrain")
    args = parser.parse_args()

    events, sessions = generer(args.sessions, args.jours)
    ecrire_sorties(events, args.logs, args.verite)
    afficher_stats(events, sessions)
    print(f"\n-> Logs      : {args.logs}")
    print(f"-> Verite    : {args.verite}")
    print("\nPROCHAINE ETAPE : valide quelques lignes dans wazuh-logtest AVANT")
    print("d'en generer des centaines, pour confirmer qu'elles declenchent bien")
    print("les regles attendues (et que le format d'horodatage correspond au tien).")
