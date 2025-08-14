#!/bin/bash
set -euo pipefail
# generate-hash-ssh-keys.sh
USER="ubuntu"
PASS="ubuntu"          # Cambia aquí la contraseña que quieras
SSH_PUB_KEY_FILE="$HOME/.ssh/id_rsa.pub"

# Generar hash de la contraseña con openssl (formato SHA-512)
PASSWORD_HASH=$(openssl passwd -6 "$PASS")

# Leer clave pública (1 línea, sin saltos)
SSH_PUB_KEY=$(head -n 1 "$SSH_PUB_KEY_FILE")

# Crear user-data.yaml con valores inyectados
sed -e "s|__PASSWORD_HASH__|$PASSWORD_HASH|" \
    -e "s|__SSH_PUB_KEY__|$SSH_PUB_KEY|" \
    user-data.template.yaml > user-data.yaml

echo "user-data.yaml generado con password y clave pública SSH."
