#!/usr/bin/env python3
"""
Injecteur de logs synthétiques dans Wazuh, avec REJEU TEMPOREL.

Problème résolu
---------------
mvp.py génère des lignes horodatées dans le passé (sur N jours). Or Wazuh, en
flux réel, corrèle sur une FENÊTRE DE TEMPS courante (le <timeframe> des règles
composites, ex : la 5763 "brute force" qui regroupe plusieurs échecs proches).
Si on fait un simple `cat logs.txt >> fichier_suivi`, deux problèmes :
  - les timestamps sont vieux → la corrélation peut ne pas se déclencher ;
  - tout arrive sur la même milliseconde → on écrase la notion de séquence.

Ce script NE rejoue PAS les vieux timestamps. Il :
  1. regroupe les lignes par session_id (fourni par mvp.py) ;
  2. calcule les écarts RELATIFS entre lignes d'une même session ;
  3. ré-horodate chaque ligne à l'instant de l'injection (now) ;
  4. respecte les délais intra-session (pour que la corrélation se déclenche),
     avec une petite pause fixe entre sessions (au lieu des heures/jours réels).

Ainsi une force brute reste une rafale serrée (→ 5763), mais l'injection totale
prend quelques minutes, pas 7 jours.

Le fichier cible doit être un fichier DÉDIÉ, déjà suivi par le manager
(bloc <localfile> avec <log_format>syslog</log_format>), monté en bind mount.
On APPEND ligne à ligne : le manager n'analyse que ce qui arrive après le
démarrage du suivi.
"""

import json
import time
import argparse
from datetime import datetime, timedelta

# Formats de timestamp reconnus en tête de ligne (doit matcher mvp.py).
FMT_ISO = "%Y-%m-%dT%H:%M:%S"   # ex : 2026-06-30T03:31:00+02:00 (on ignore le TZ au parsing)
FMT_BSD = "%b %d %H:%M:%S"      # ex : Jun 30 03:31:00


def parse_timestamp(ligne):
    """Extrait le datetime en tête de ligne. Retourne None si non parsable.
    Sert UNIQUEMENT à calculer les deltas intra-session, pas à réinjecter."""
    # ISO : les 19 premiers caractères (YYYY-MM-DDTHH:MM:SS)
    try:
        return datetime.strptime(ligne[:19], FMT_ISO)
    except (ValueError, IndexError):
        pass
    # BSD : les 15 premiers caractères (Mon DD HH:MM:SS)
    try:
        # strptime BSD n'a pas d'année → on met une année neutre, seul le delta compte
        return datetime.strptime(ligne[:15].strip(), FMT_BSD)
    except (ValueError, IndexError):
        return None


def rehorodater(ligne, ts_ancien, maintenant, fmt):
    """Remplace le timestamp en tête de ligne par 'maintenant'.
    Le corps de la ligne (host, sshd[pid], message) est conservé tel quel."""
    if fmt == "iso":
        nouveau_ts = maintenant.strftime("%Y-%m-%dT%H:%M:%S+02:00")
        reste = ligne[len("2026-06-30T03:31:00+02:00"):]
        # Plus robuste : on coupe après le premier espace (le TS ISO n'a pas d'espace)
        reste = ligne.split(" ", 1)[1] if " " in ligne else ""
        return f"{nouveau_ts} {reste}"
    else:  # bsd
        nouveau_ts = maintenant.strftime("%b %e %H:%M:%S").replace("  ", " ")
        # Le TS BSD occupe 3 champs (mois, jour, heure) → on saute 3 espaces
        parts = ligne.split(" ", 3)
        reste = parts[3] if len(parts) > 3 else ""
        return f"{nouveau_ts} {reste}"


def charger_sessions(fichier_verite):
    """Lit verite.jsonl et regroupe les lignes par session_id, en préservant
    l'ordre chronologique d'origine à l'intérieur de chaque session."""
    sessions = {}  # session_id -> liste de dicts {ligne, ts, ...}
    with open(fichier_verite) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            rec = json.loads(raw)
            sid = rec.get("session_id")
            if sid is None:
                # Compat : ancien verite.jsonl sans session_id → 1 ligne = 1 session
                sid = f"orphan-{len(sessions)}"
            rec["_ts"] = parse_timestamp(rec["ligne"])
            sessions.setdefault(sid, []).append(rec)
    # Trier chaque session par timestamp d'origine (sécurité)
    for sid in sessions:
        sessions[sid].sort(key=lambda r: r["_ts"] or datetime.min)
    return sessions


def deltas_intra_session(records, delai_max, facteur):
    """Pour une session, calcule le délai d'attente AVANT chaque ligne.
    La 1re ligne : 0. Les suivantes : (ts[i] - ts[i-1]) plafonné et accéléré."""
    delais = [0.0]
    for i in range(1, len(records)):
        t_prev, t_cur = records[i - 1]["_ts"], records[i]["_ts"]
        if t_prev is None or t_cur is None:
            d = 1.0  # fallback si timestamp illisible
        else:
            d = (t_cur - t_prev).total_seconds()
            if d < 0:
                d = 0.0
        d = min(d, delai_max) / facteur
        delais.append(d)
    return delais


def injecter(fichier_verite, fichier_cible, fmt, delai_max, facteur,
             pause_session, dry_run):
    sessions = charger_sessions(fichier_verite)
    # Ordonner les sessions par timestamp de leur 1re ligne (ordre naturel)
    ordre = sorted(sessions.items(),
                   key=lambda kv: kv[1][0]["_ts"] or datetime.min)

    total_lignes = sum(len(recs) for _, recs in ordre)
    print(f"[i] {len(ordre)} sessions, {total_lignes} lignes à injecter.")
    print(f"[i] Cible : {fichier_cible}")
    print(f"[i] Mode  : rafale intra-session (délai max {delai_max}s, "
          f"facteur {facteur}x), pause inter-session {pause_session}s.")
    if dry_run:
        print("[i] DRY-RUN : rien n'est écrit, on affiche seulement le plan.\n")

    n = 0
    # Horodatage LOGIQUE : part de now() au démarrage et avance des délais
    # rejoués. Ainsi le timestamp écrit progresse ligne à ligne même quand
    # deux lignes tombent dans la même seconde réelle, et le dry-run montre
    # un temps réaliste. En injection réelle il colle au temps qui passe.
    horloge = datetime.now()
    # 'a' = append : indispensable, le manager ne lit que ce qui arrive après
    f_out = None if dry_run else open(fichier_cible, "a")
    try:
        for idx, (sid, records) in enumerate(ordre):
            delais = deltas_intra_session(records, delai_max, facteur)
            profil = records[0].get("profil", "?")
            verite = records[0].get("verite", "?")
            print(f"--- session {sid} [{profil}/{verite}] "
                  f"({len(records)} lignes) ---")
            for rec, attente in zip(records, delais):
                if attente > 0 and not dry_run:
                    time.sleep(attente)
                # Avancer l'horloge logique du délai rejoué
                horloge = horloge + timedelta(seconds=attente)
                nouvelle = rehorodater(rec["ligne"], rec["_ts"], horloge, fmt)
                n += 1
                if dry_run:
                    print(f"  [+{attente:5.1f}s] {nouvelle}")
                else:
                    f_out.write(nouvelle + "\n")
                    f_out.flush()  # forcer l'écriture pour que Wazuh voie tout de suite
            # Pause entre sessions (sauf après la dernière)
            if idx < len(ordre) - 1:
                horloge = horloge + timedelta(seconds=pause_session)
                if not dry_run:
                    time.sleep(pause_session)
    finally:
        if f_out:
            f_out.close()

    print(f"\n[✓] {n} lignes injectées dans {fichier_cible}"
          if not dry_run else f"\n[✓] DRY-RUN terminé ({n} lignes simulées).")


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Injecte les logs synthétiques dans Wazuh avec rejeu temporel.")
    p.add_argument("--verite", default="verite.jsonl",
                   help="Fichier de vérité terrain produit par mvp.py (contient session_id)")
    p.add_argument("--cible", required=True,
                   help="Fichier suivi par Wazuh où append les logs (bind mount)")
    p.add_argument("--format", choices=["iso", "bsd"], default="iso",
                   help="Format d'horodatage à écrire (doit matcher le <localfile> Wazuh)")
    p.add_argument("--delai-max", type=float, default=5.0,
                   help="Plafond du délai intra-session en secondes (défaut 5)")
    p.add_argument("--facteur", type=float, default=1.0,
                   help="Facteur d'accélération des délais intra-session (>1 = plus rapide)")
    p.add_argument("--pause-session", type=float, default=1.5,
                   help="Pause fixe entre deux sessions en secondes (défaut 1.5)")
    p.add_argument("--dry-run", action="store_true",
                   help="Affiche le plan d'injection sans rien écrire")
    args = p.parse_args()

    injecter(args.verite, args.cible, args.format, args.delai_max,
             args.facteur, args.pause_session, args.dry_run)
