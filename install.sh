#!/usr/bin/env bash
set -euo pipefail

readonly REPO_URL="https://github.com/mrcyberharsh/iot-hunter.git"
readonly SERVICE_NAME="iot-hunter.service"
readonly MANAGED_MARKER=".iot-hunter-managed"

if [[ -z "${HOME:-}" ]]; then
    printf 'Error: HOME must be set.\n' >&2
    exit 1
fi

INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/iot-hunter"
MODE="auto"
MODE_SELECTED=false
PORT="8080"
INSTALL_SERVICE=false
UNINSTALL=false

usage() {
    cat <<'EOF'
Usage: install.sh [--docker | --venv] [--dir PATH] [--port PORT] [--service] [--uninstall]

  --docker     Use Docker Compose (default when docker compose is available)
  --venv       Install into a Python virtual environment
  --dir PATH   Installation directory (default: ~/.local/share/iot-hunter)
  --port PORT  Local dashboard port (default: 8080)
  --service    Install/start a systemd user service; never uses sudo
  --uninstall  Stop/remove the managed app and service, preserving .env/data/reports
  --help       Show this help
EOF
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --docker|--venv)
            [[ "$MODE_SELECTED" == false ]] || fail "Choose only one of --docker and --venv."
            MODE="${1#--}"
            MODE_SELECTED=true
            shift
            ;;
        --dir)
            (($# >= 2)) || fail "--dir requires a path."
            INSTALL_DIR="$2"
            shift 2
            ;;
        --dir=*)
            INSTALL_DIR="${1#*=}"
            [[ -n "$INSTALL_DIR" ]] || fail "--dir requires a path."
            shift
            ;;
        --port)
            (($# >= 2)) || fail "--port requires a number."
            PORT="$2"
            shift 2
            ;;
        --port=*)
            PORT="${1#*=}"
            shift
            ;;
        --service)
            INSTALL_SERVICE=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

if [[ "$UNINSTALL" == true ]]; then
    [[ "$MODE_SELECTED" == false && "$INSTALL_SERVICE" == false && "$PORT" == "8080" ]] ||
        fail "--uninstall may only be combined with --dir."
fi

if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || ((10#$PORT < 1 || 10#$PORT > 65535)); then
    fail "--port must be an integer from 1 to 65535."
fi
PORT=$((10#$PORT))

case "$INSTALL_DIR" in
    /*) ;;
    *) INSTALL_DIR="$PWD/$INSTALL_DIR" ;;
esac
[[ ! -L "${INSTALL_DIR%/}" ]] || fail "The installation directory must not be a symbolic link."
[[ "$INSTALL_DIR" != / ]] || fail "Refusing to use / as the installation directory."
INSTALL_PARENT="$(dirname -- "$INSTALL_DIR")"
INSTALL_NAME="$(basename -- "$INSTALL_DIR")"
[[ "$INSTALL_NAME" != "." && "$INSTALL_NAME" != ".." ]] || fail "Choose a dedicated installation directory."
mkdir -p -- "$INSTALL_PARENT"
INSTALL_PARENT="$(cd -P -- "$INSTALL_PARENT" && pwd)"
INSTALL_DIR="$INSTALL_PARENT/$INSTALL_NAME"
HOME_REAL="$(cd -P -- "$HOME" && pwd)"
[[ "$INSTALL_DIR" != / && "$INSTALL_DIR" != "$HOME_REAL" ]] ||
    fail "Refusing to use / or HOME as the installation directory."
case "$HOME_REAL" in
    "$INSTALL_DIR"/*) fail "Refusing to use an ancestor of HOME as the installation directory." ;;
esac
[[ ! -L "$INSTALL_DIR" ]] || fail "The installation directory must not be a symbolic link."

ENV_FILE="$INSTALL_DIR/.env"
DATA_DIR="$INSTALL_DIR/data"
REPORTS_DIR="$INSTALL_DIR/reports"
LOG_DIR="$INSTALL_DIR/logs"
PID_FILE="$INSTALL_DIR/.iot-hunter.pid"
MODE_FILE="$INSTALL_DIR/.iot-hunter-mode"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_FILE="$UNIT_DIR/$SERVICE_NAME"
[[ "$UNIT_DIR" == /* ]] || fail "XDG_CONFIG_HOME must be an absolute path."
STAGING_DIR=""

cleanup() {
    if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
        rm -rf -- "$STAGING_DIR"
    fi
}
trap cleanup EXIT

unit_is_managed() {
    [[ -f "$UNIT_FILE" ]] && grep -Fqx '# Managed by IoT Hunter install.sh' "$UNIT_FILE"
}

stop_user_service() {
    [[ -e "$UNIT_FILE" ]] || return 0
    [[ ! -L "$UNIT_FILE" ]] || fail "Refusing to modify a symbolic-link service file at $UNIT_FILE."
    unit_is_managed || fail "Refusing to modify an unmanaged user service at $UNIT_FILE."
    command -v systemctl >/dev/null 2>&1 ||
        fail "systemctl is required to stop the existing IoT Hunter user service."
    systemctl --user show-environment >/dev/null 2>&1 ||
        fail "An active systemd user manager is required to stop the IoT Hunter service."
    if systemctl --user is-active --quiet "$SERVICE_NAME"; then
        systemctl --user stop "$SERVICE_NAME"
    fi
    if systemctl --user is-enabled --quiet "$SERVICE_NAME"; then
        systemctl --user disable "$SERVICE_NAME"
    fi
    rm -f -- "$UNIT_FILE"
    systemctl --user daemon-reload
}

stop_local_venv() {
    [[ -f "$PID_FILE" ]] || return 0
    [[ ! -L "$PID_FILE" ]] || fail "Refusing to read a symbolic-link PID file at $PID_FILE."
    local pid process_args process_state
    pid="$(<"$PID_FILE")"
    [[ "$pid" =~ ^[0-9]+$ ]] || fail "Invalid PID file at $PID_FILE; inspect it before removing it."
    if kill -0 "$pid" 2>/dev/null; then
        process_args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
        [[ "$process_args" == *"$INSTALL_DIR/.venv/bin/uvicorn"* ]] ||
            fail "PID $pid is not the expected IoT Hunter process; refusing to stop it."
        kill -TERM "$pid"
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            process_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
            [[ "$process_state" == *Z* ]] && break
            sleep 0.25
        done
        process_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
        if kill -0 "$pid" 2>/dev/null && [[ "$process_state" != *Z* ]]; then
            fail "IoT Hunter process $pid did not stop; refusing to force-kill it."
        fi
    fi
    rm -f -- "$PID_FILE"
}

compose_down() {
    local compose_file="$INSTALL_DIR/docker/docker-compose.yml"
    [[ -f "$compose_file" ]] || return 0
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
        fail "Docker Compose is needed to stop the installed containers; no containers were removed."
    fi
    IOT_HUNTER_PORT="$PORT" \
        IOT_HUNTER_UID="$(id -u)" \
        IOT_HUNTER_GID="$(id -g)" \
        docker compose --env-file "$ENV_FILE" -f "$compose_file" down
}

uninstall() {
    if [[ ! -e "$INSTALL_DIR" ]]; then
        printf 'Nothing is installed at %s.\n' "$INSTALL_DIR"
        return
    fi
    [[ ! -L "$INSTALL_DIR/$MANAGED_MARKER" ]] ||
        fail "Refusing to trust a symbolic-link install marker at $INSTALL_DIR/$MANAGED_MARKER."
    [[ -f "$INSTALL_DIR/$MANAGED_MARKER" ]] ||
        fail "No IoT Hunter install marker at $INSTALL_DIR; refusing to remove this directory."

    stop_user_service
    local installed_mode=""
    [[ ! -L "$MODE_FILE" ]] || fail "Refusing to read a symbolic-link mode file at $MODE_FILE."
    if [[ -f "$MODE_FILE" ]]; then
        installed_mode="$(<"$MODE_FILE")"
    fi
    case "$installed_mode" in
        docker) compose_down ;;
        venv) stop_local_venv ;;
        "" ) ;;
        *) fail "Unknown installation mode in $MODE_FILE; refusing to uninstall." ;;
    esac

    find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 \
        ! -name ".env" \
        ! -name "data" \
        ! -name "reports" \
        ! -name "$MANAGED_MARKER" \
        -exec rm -rf -- {} +
    printf 'IoT Hunter app/service removed. Preserved:\n'
    printf '  Secret file: %s\n  Data: %s\n  Reports: %s\n' "$ENV_FILE" "$DATA_DIR" "$REPORTS_DIR"
}

if [[ "$UNINSTALL" == true ]]; then
    uninstall
    exit 0
fi

COMPOSE_AVAILABLE=false
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_AVAILABLE=true
fi
if [[ "$MODE" == "auto" ]]; then
    if [[ "$COMPOSE_AVAILABLE" == true ]]; then
        MODE="docker"
    else
        MODE="venv"
    fi
fi

PYTHON_BIN=""
for candidate in python3 python3.15 python3.14 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1 &&
        "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

MISSING=()
PACKAGES=(git openssl curl tar ps find grep awk mktemp)
for package in "${PACKAGES[@]}"; do
    command -v "$package" >/dev/null 2>&1 || MISSING+=("$package")
done
if [[ -z "$PYTHON_BIN" ]]; then
    MISSING+=("python3 >= 3.11")
fi
if [[ "$MODE" == "venv" && -n "$PYTHON_BIN" ]] && command -v mktemp >/dev/null 2>&1; then
    venv_check_dir="$(mktemp -d)"
    if ! "$PYTHON_BIN" -m venv "$venv_check_dir/check" >/dev/null 2>&1; then
        MISSING+=("python3-venv")
    fi
    rm -rf -- "${venv_check_dir:?}"
elif [[ "$MODE" == "venv" && -n "$PYTHON_BIN" ]]; then
    MISSING+=("mktemp")
fi
if [[ "$MODE" == "docker" && "$COMPOSE_AVAILABLE" == false ]]; then
    MISSING+=("docker compose")
fi

if ((${#MISSING[@]} > 0)); then
    printf 'Missing dependencies: %s\n' "${MISSING[*]}" >&2
    if command -v python3 >/dev/null 2>&1 &&
        ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
        printf 'The installed python3 is older than 3.11; upgrade to Ubuntu 24.04+ or install Python 3.11+ from a trusted repository.\n' >&2
    fi
    apt_packages=(git python3 openssl curl tar coreutils findutils grep gawk procps)
    if [[ "$MODE" == "venv" ]]; then
        if [[ "$PYTHON_BIN" == python3.* ]]; then
            apt_packages+=("$PYTHON_BIN-venv")
        else
            apt_packages+=(python3-venv)
        fi
    fi
    if [[ "$MODE" == "docker" ]]; then
        apt_packages+=(docker.io docker-compose-v2)
    fi
    printf 'On Ubuntu 24.04+, install them explicitly with:\n  sudo apt-get update && sudo apt-get install -y %s\n' \
        "${apt_packages[*]}" >&2
    printf 'This installer will not run sudo or install packages for you.\n' >&2
    exit 1
fi

if [[ "$MODE" == "venv" && "$PORT" -lt 1024 ]]; then
    fail "The venv server cannot bind ports below 1024 without elevated privileges; choose a port from 1024 to 65535."
fi
if [[ "$MODE" == "docker" ]]; then
    docker info >/dev/null 2>&1 ||
        fail "Docker Compose is installed but the Docker daemon is unavailable or inaccessible; start it or configure user access without sudo."
fi
if [[ "$INSTALL_SERVICE" == true ]]; then
    command -v systemctl >/dev/null 2>&1 ||
        fail "--service requires systemd with an active user manager."
    systemctl --user show-environment >/dev/null 2>&1 ||
        fail "--service requires an active systemd user manager; the installer will not use sudo."
    if [[ -e "$UNIT_FILE" ]] && ! unit_is_managed; then
        fail "An unmanaged user service already exists at $UNIT_FILE."
    fi
fi

if [[ -e "$INSTALL_DIR" ]]; then
    [[ -d "$INSTALL_DIR" ]] || fail "$INSTALL_DIR exists but is not a directory."
    [[ ! -L "$INSTALL_DIR/$MANAGED_MARKER" ]] ||
        fail "Refusing to trust a symbolic-link install marker at $INSTALL_DIR/$MANAGED_MARKER."
    if [[ ! -f "$INSTALL_DIR/$MANAGED_MARKER" ]]; then
        shopt -s dotglob nullglob
        existing_entries=("$INSTALL_DIR"/*)
        shopt -u dotglob nullglob
        ((${#existing_entries[@]} == 0)) ||
            fail "$INSTALL_DIR already contains files and is not managed by this installer. Choose an empty --dir."
    fi
fi
mkdir -p -- "$INSTALL_DIR"
touch "$INSTALL_DIR/$MANAGED_MARKER"

STAGING_DIR="$(mktemp -d)"
LOCAL_SOURCE=""
SCRIPT_PATH="${BASH_SOURCE[0]}"
if [[ -f "$SCRIPT_PATH" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P)"
    if git -C "$SCRIPT_DIR" rev-parse --show-toplevel >/dev/null 2>&1 &&
        [[ -f "$SCRIPT_DIR/backend/webapp.py" ]]; then
        LOCAL_SOURCE="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
    fi
fi

if [[ -n "$LOCAL_SOURCE" ]]; then
    git -C "$LOCAL_SOURCE" archive --format=tar HEAD | tar -xf - -C "$STAGING_DIR"
else
    git clone --quiet --depth 1 --branch main "$REPO_URL" "$STAGING_DIR/repository"
    git -C "$STAGING_DIR/repository" archive --format=tar HEAD | tar -xf - -C "$STAGING_DIR"
    rm -rf -- "$STAGING_DIR/repository"
fi

shopt -s dotglob nullglob
for source_path in "$STAGING_DIR"/*; do
    name="$(basename -- "$source_path")"
    case "$name" in
        .env|data|reports|logs|.venv|"$MANAGED_MARKER"|.iot-hunter.pid|.iot-hunter-mode)
            continue
            ;;
    esac
    [[ -n "$INSTALL_DIR" && "$INSTALL_DIR" != / ]] ||
        fail "Refusing to replace files without a valid installation directory."
    rm -rf -- "${INSTALL_DIR:?}/$name"
    cp -a -- "$source_path" "$INSTALL_DIR/$name"
done
shopt -u dotglob nullglob
touch "$INSTALL_DIR/$MANAGED_MARKER"

[[ ! -L "$ENV_FILE" ]] || fail "Refusing to read a symbolic-link secret file at $ENV_FILE."
if [[ ! -e "$ENV_FILE" ]]; then
    admin_secret="$(openssl rand -hex 24)"
    (umask 077; printf 'IOT_HUNTER_ADMIN_SECRET=%s\n' "$admin_secret" > "$ENV_FILE")
    chmod 600 "$ENV_FILE"
fi
admin_secret="$(awk -F= '$1 == "IOT_HUNTER_ADMIN_SECRET" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
admin_secret="${admin_secret%$'\r'}"
if [[ ${#admin_secret} -ge 2 && "${admin_secret:0:1}" == '"' && "${admin_secret: -1}" == '"' ]]; then
    admin_secret="${admin_secret:1:${#admin_secret}-2}"
elif [[ ${#admin_secret} -ge 2 && "${admin_secret:0:1}" == "'" && "${admin_secret: -1}" == "'" ]]; then
    admin_secret="${admin_secret:1:${#admin_secret}-2}"
fi
[[ -n "$admin_secret" && "$admin_secret" != "replace-with-a-long-random-secret" ]] ||
    fail "IOT_HUNTER_ADMIN_SECRET is missing or still a placeholder in $ENV_FILE; update it without sharing it."
[[ ${#admin_secret} -ge 32 ]] ||
    fail "IOT_HUNTER_ADMIN_SECRET must contain at least 32 characters in $ENV_FILE; update it without sharing it."

mkdir -p -- "$DATA_DIR" "$REPORTS_DIR" "$LOG_DIR"
for writable_dir in "$DATA_DIR" "$REPORTS_DIR"; do
    [[ ! -L "$writable_dir" ]] || fail "Refusing to use symbolic-link data directory $writable_dir."
    if [[ ! -O "$writable_dir" ]]; then
        printf -v quoted_data '%q' "$DATA_DIR"
        printf -v quoted_reports '%q' "$REPORTS_DIR"
        fail "Data directories must belong to the current user. If appropriate, run manually: sudo chown -R %s:%s -- %s %s" \
            "$(id -u)" "$(id -g)" "$quoted_data" "$quoted_reports"
    fi
    [[ -w "$writable_dir" ]] || fail "Data directory $writable_dir is not writable by the current user."
done

if [[ -f "$UNIT_FILE" ]]; then
    stop_user_service
fi
previous_mode=""
[[ ! -L "$MODE_FILE" ]] || fail "Refusing to read a symbolic-link mode file at $MODE_FILE."
if [[ -f "$MODE_FILE" ]]; then
    previous_mode="$(<"$MODE_FILE")"
fi
case "$previous_mode" in
    docker) compose_down ;;
    venv) stop_local_venv ;;
    "" ) ;;
    *) fail "Unknown installation mode in $MODE_FILE; refusing to replace the running app." ;;
esac

port_is_available() {
    "$PYTHON_BIN" - "$PORT" <<'PY'
import socket
import sys

with socket.socket() as sock:
    try:
        sock.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        sys.exit(1)
PY
}

if ! port_is_available; then
    fail "Port $PORT is already in use on 127.0.0.1; stop that service or choose another --port."
fi

systemd_quote() {
    local input="$1"
    local escaped=""
    local character
    local index
    for ((index = 0; index < ${#input}; index++)); do
        character="${input:index:1}"
        case "$character" in
            \\) escaped+="\\\\" ;;
            '"') escaped+="\\\"" ;;
            '%') escaped+="%%" ;;
            '$') escaped+='\$\$' ;;
            *) escaped+="$character" ;;
        esac
    done
    printf '"%s"' "$escaped"
}

format_exec() {
    local result=""
    local argument
    for argument in "$@"; do
        result+="$(systemd_quote "$argument") "
    done
    printf '%s' "${result% }"
}

install_user_service() {
    local docker_bin unit_temp
    mkdir -p -- "$UNIT_DIR"
    unit_temp="$(mktemp "$UNIT_DIR/.iot-hunter.XXXXXX")"
    {
        printf '[Unit]\nDescription=IoT Hunter dashboard\nAfter=network-online.target\n\n[Service]\n'
        printf 'Type=simple\n'
        printf '# Managed by IoT Hunter install.sh\n'
        printf 'WorkingDirectory=%s\n' "$(systemd_quote "$INSTALL_DIR")"
        printf 'EnvironmentFile=%s\n' "$(systemd_quote "$ENV_FILE")"
        printf 'Environment=%s\n' "$(systemd_quote "IOT_HUNTER_DATA=$DATA_DIR")"
        printf 'Environment=%s\n' "$(systemd_quote "IOT_HUNTER_CONFIG=$INSTALL_DIR/backend/config.yaml")"
        if [[ "$MODE" == "docker" ]]; then
            docker_bin="$(command -v docker)"
            printf 'Environment=%s\n' "$(systemd_quote "IOT_HUNTER_PORT=$PORT")"
            printf 'Environment=%s\n' "$(systemd_quote "IOT_HUNTER_UID=$(id -u)")"
            printf 'Environment=%s\n' "$(systemd_quote "IOT_HUNTER_GID=$(id -g)")"
            printf 'ExecStart=%s\n' "$(format_exec "$docker_bin" compose --env-file "$ENV_FILE" -f "$INSTALL_DIR/docker/docker-compose.yml" up --remove-orphans)"
            printf 'ExecStop=%s\n' "$(format_exec "$docker_bin" compose --env-file "$ENV_FILE" -f "$INSTALL_DIR/docker/docker-compose.yml" down)"
        else
            printf 'Environment=%s\n' "$(systemd_quote "PYTHONPATH=$INSTALL_DIR/backend")"
            printf 'ExecStart=%s\n' "$(format_exec "$INSTALL_DIR/.venv/bin/uvicorn" webapp:app --app-dir "$INSTALL_DIR/backend" --host 127.0.0.1 --port "$PORT")"
        fi
        printf 'Restart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n'
    } > "$unit_temp"
    chmod 644 "$unit_temp"
    mv -f -- "$unit_temp" "$UNIT_FILE"
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE_NAME"
    systemctl --user is-active --quiet "$SERVICE_NAME" ||
        fail "The systemd user service did not become active; inspect systemctl --user status $SERVICE_NAME."
}

if [[ "$MODE" == "docker" ]]; then
    if [[ "$INSTALL_SERVICE" == true ]]; then
        install_user_service
    else
        IOT_HUNTER_PORT="$PORT" \
            IOT_HUNTER_UID="$(id -u)" \
            IOT_HUNTER_GID="$(id -g)" \
            docker compose --env-file "$ENV_FILE" -f "$INSTALL_DIR/docker/docker-compose.yml" up -d --build
    fi
else
    "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
    "$INSTALL_DIR/.venv/bin/python" -m pip install --disable-pip-version-check --quiet \
        -r "$INSTALL_DIR/backend/requirements.txt"
    if [[ "$INSTALL_SERVICE" == true ]]; then
        install_user_service
    else
        nohup env \
            "IOT_HUNTER_ADMIN_SECRET=$admin_secret" \
            "IOT_HUNTER_DATA=$DATA_DIR" \
            "IOT_HUNTER_CONFIG=$INSTALL_DIR/backend/config.yaml" \
            "PYTHONPATH=$INSTALL_DIR/backend" \
            "$INSTALL_DIR/.venv/bin/uvicorn" webapp:app \
            --app-dir "$INSTALL_DIR/backend" --host 127.0.0.1 --port "$PORT" \
            >> "$LOG_DIR/webapp.log" 2>&1 </dev/null &
        printf '%s\n' "$!" > "$PID_FILE"
    fi
fi

printf '%s\n' "$MODE" > "$MODE_FILE"
dashboard_url="http://127.0.0.1:$PORT"
ready=false
for _ in {1..60}; do
    status_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --max-time 2 "$dashboard_url" 2>/dev/null || true)"
    if [[ "$status_code" == "200" ]]; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" == false ]]; then
    if [[ "$INSTALL_SERVICE" == true ]]; then
        if systemctl --user is-active --quiet "$SERVICE_NAME"; then
            systemctl --user stop "$SERVICE_NAME"
        fi
        fail "Dashboard did not become ready at $dashboard_url. Inspect systemctl --user status $SERVICE_NAME and journalctl --user -u $SERVICE_NAME."
    fi
    if [[ "$MODE" == "docker" ]]; then
        compose_down
    else
        stop_local_venv
    fi
    rm -f -- "$MODE_FILE"
    if [[ "$MODE" == "docker" ]]; then
        fail "Dashboard did not become ready at $dashboard_url. Inspect the Compose logs with docker compose --env-file $ENV_FILE -f $INSTALL_DIR/docker/docker-compose.yml logs."
    fi
    fail "Dashboard did not become ready at $dashboard_url. Check logs at $LOG_DIR/webapp.log."
fi

printf 'IoT Hunter is ready: %s\n' "$dashboard_url"
printf 'Admin secret is stored in %s (the secret is not displayed).\n' "$ENV_FILE"
if [[ "$INSTALL_SERVICE" == true ]]; then
    printf 'User service: systemctl --user status %s\n' "$SERVICE_NAME"
fi
