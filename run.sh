#!/usr/bin/env bash
#
# run_pipeline.sh — génère des logs synthétiques et les injecte dans Wazuh.
#
# Enchaîne mvp.py (génération + vérité terrain) puis injecteur.py (rejeu
# temporel dans le fichier suivi par le manager). Pensé pour la machine de
# stage : pas de root requis, Wazuh en conteneur, API/Ollama sur l'hôte.
#
# Deux modes d'écriture vers le fichier suivi par Wazuh :
#   - bind mount (défaut) : l'injecteur écrit un fichier hôte que le conteneur
#     voit via le montage. Le plus simple.
#   - docker exec         : si le fichier n'est PAS un bind mount, on injecte
#     dans le conteneur. Nécessite CONTAINER renseigné.
#
# Usage :
#   ./run_pipeline.sh [-n SESSIONS] [-j JOURS] [-c CIBLE] [-f FACTEUR] [--dry-run]
#
# Exemples :
#   ./run_pipeline.sh --dry-run                 # tout simuler, rien n'est écrit
#   ./run_pipeline.sh -n 500 -f 3               # gros jeu, injection accélérée
#   ./run_pipeline.sh -c /chemin/synth_auth.log # cibler un fichier précis

set -euo pipefail

# ---------------------------------------------------------------------------
# PARAMÈTRES (surchargables en ligne de commande ou par variable d'env)
# ---------------------------------------------------------------------------

# Emplacement des scripts (par défaut : le dossier de ce script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Environnement virtuel Python -------------------------------------------
# Chemin du venv à activer (surchargeable par variable d'env VENV).
# Mets VENV= (vide) pour utiliser le python3 du système sans venv.
VENV="${VENV-/scratch/ui11_2/tcosmo/fastAPI-project/.venv}"

if [[ -n "$VENV" ]]; then
    ACTIVATE="$VENV/bin/activate"
    if [[ ! -f "$ACTIVATE" ]]; then
        echo "[✗] Venv introuvable : $ACTIVATE" >&2
        echo "    Corrige la variable VENV ou mets-la à \"\" pour t'en passer." >&2
        exit 1
    fi
    # 'activate' référence des variables non définies (ex : PS1, PYTHONHOME) ;
    # on désactive temporairement set -u le temps du sourcing pour éviter un
    # plantage sous 'set -euo pipefail'.
    set +u
    # shellcheck disable=SC1090
    source "$ACTIVATE"
    set -u
    echo "[i] Venv activé : $VENV"
fi

# Fichiers intermédiaires
LOGS="${LOGS:-$SCRIPT_DIR/logs.txt}"
VERITE="${VERITE:-$SCRIPT_DIR/verite.jsonl}"

# Paramètres de génération
SESSIONS="${SESSIONS:-100}"
JOURS="${JOURS:-7}"

# Fichier cible SUIVI PAR WAZUH (bind mount côté hôte, ou chemin dans le conteneur)
# ADAPTE ce chemin à ton montage réel.
CIBLE="${CIBLE:-$SCRIPT_DIR/synthetic_auth.log}"

# Format d'horodatage : doit matcher le <localfile> Wazuh (iso ou bsd)
FORMAT="${FORMAT:-iso}"

# Paramètres d'injection
FACTEUR="${FACTEUR:-1}"
DELAI_MAX="${DELAI_MAX:-5}"
PAUSE_SESSION="${PAUSE_SESSION:-1.5}"

# Mode d'écriture : "bind" (défaut) ou "exec"
MODE_ECRITURE="${MODE_ECRITURE:-bind}"
# Nom du conteneur manager (utilisé seulement si MODE_ECRITURE=exec)
CONTAINER="${CONTAINER:-single-node-wazuh.manager-1}"
# Chemin du fichier À L'INTÉRIEUR du conteneur (si MODE_ECRITURE=exec)
CIBLE_CONTENEUR="${CIBLE_CONTENEUR:-/var/ossec/logs/synthetic_auth.log}"

DRY_RUN=""

# ---------------------------------------------------------------------------
# PARSING DES ARGUMENTS
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--sessions)  SESSIONS="$2"; shift 2 ;;
        -j|--jours)     JOURS="$2"; shift 2 ;;
        -c|--cible)     CIBLE="$2"; shift 2 ;;
        -f|--facteur)   FACTEUR="$2"; shift 2 ;;
        --format)       FORMAT="$2"; shift 2 ;;
        --dry-run)      DRY_RUN="--dry-run"; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -30
            exit 0 ;;
        *) echo "Argument inconnu : $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# GARDE-FOUS
# ---------------------------------------------------------------------------

echo "=== Vérifications préalables ==="

# Python dispo ?
command -v python3 >/dev/null 2>&1 || { echo "[✗] python3 introuvable." >&2; exit 1; }

# Scripts présents ?
for f in mvp.py injecteur.py; do
    [[ -f "$SCRIPT_DIR/$f" ]] || { echo "[✗] $f manquant dans $SCRIPT_DIR." >&2; exit 1; }
done

# En mode bind, on écrit dans un fichier hôte : son dossier doit exister et
# être accessible en écriture. On NE crée PAS le fichier ici pour ne pas
# perturber un suivi Wazuh déjà en place ; on avertit juste s'il est absent.
if [[ "$MODE_ECRITURE" == "bind" && -z "$DRY_RUN" ]]; then
    CIBLE_DIR="$(dirname "$CIBLE")"
    [[ -d "$CIBLE_DIR" ]] || { echo "[✗] Dossier cible inexistant : $CIBLE_DIR" >&2; exit 1; }
    if [[ ! -e "$CIBLE" ]]; then
        echo "[!] Le fichier cible $CIBLE n'existe pas encore."
        echo "    Il sera créé par l'injection, MAIS Wazuh ne le suivra que"
        echo "    s'il est déclaré en <localfile> ET que le suivi a démarré."
    fi
fi

# En mode exec, le conteneur doit tourner.
if [[ "$MODE_ECRITURE" == "exec" && -z "$DRY_RUN" ]]; then
    command -v docker >/dev/null 2>&1 || { echo "[✗] docker introuvable." >&2; exit 1; }
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$" \
        || { echo "[✗] Conteneur '$CONTAINER' non démarré." >&2; exit 1; }
fi

echo "[✓] Vérifications OK."
echo

# ---------------------------------------------------------------------------
# ÉTAPE 1 — GÉNÉRATION
# ---------------------------------------------------------------------------

echo "=== 1/2 Génération ($SESSIONS sessions sur $JOURS jours) ==="
python3 "$SCRIPT_DIR/mvp.py" \
    -n "$SESSIONS" -j "$JOURS" \
    --logs "$LOGS" --verite "$VERITE"
echo

# ---------------------------------------------------------------------------
# ÉTAPE 2 — INJECTION
# ---------------------------------------------------------------------------

echo "=== 2/2 Injection (format=$FORMAT, facteur=${FACTEUR}x) ==="

if [[ "$MODE_ECRITURE" == "exec" && -z "$DRY_RUN" ]]; then
    # L'injecteur écrit sur stdout ? Non : il écrit dans un fichier. Pour le
    # mode exec, on l'écrit d'abord dans un fichier hôte temporaire, puis on
    # l'append dans le conteneur. On réutilise donc l'injecteur en le pointant
    # vers un fichier temporaire, et on streame vers docker exec.
    #
    # Plus simple et fidèle au rejeu temporel : on laisse l'injecteur gérer le
    # timing, mais on redirige son écriture vers le conteneur via un tube.
    # Comme injecteur.py ouvre le fichier lui-même, on passe par un FIFO.
    TMP_FIFO="$(mktemp -u)"
    mkfifo "$TMP_FIFO"
    # Consommateur : tout ce qui arrive dans le FIFO est appendé dans le conteneur
    ( docker exec -i "$CONTAINER" sh -c "cat >> '$CIBLE_CONTENEUR'" < "$TMP_FIFO" ) &
    CONSUMER_PID=$!
    python3 "$SCRIPT_DIR/injecteur.py" \
        --verite "$VERITE" --cible "$TMP_FIFO" \
        --format "$FORMAT" --facteur "$FACTEUR" \
        --delai-max "$DELAI_MAX" --pause-session "$PAUSE_SESSION"
    wait "$CONSUMER_PID"
    rm -f "$TMP_FIFO"
else
    # Mode bind (ou dry-run) : l'injecteur écrit directement le fichier cible.
    python3 "$SCRIPT_DIR/injecteur.py" \
        --verite "$VERITE" --cible "$CIBLE" \
        --format "$FORMAT" --facteur "$FACTEUR" \
        --delai-max "$DELAI_MAX" --pause-session "$PAUSE_SESSION" \
        $DRY_RUN
fi

echo
echo "=== Terminé ==="
echo "Logs générés   : $LOGS"
echo "Vérité terrain : $VERITE  (à NE PAS donner au LLM)"
if [[ -z "$DRY_RUN" ]]; then
    echo
    echo "PROCHAINE ÉTAPE : vérifier côté manager que les alertes remontent :"
    echo "  - la corrélation force brute (règle 5763, niveau 10) doit apparaître"
    echo "  - inspecter /var/ossec/logs/alerts/alerts.json"
    echo "  - puis matcher les alertes à $VERITE via le champ full_log"
fi
