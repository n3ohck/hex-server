#!/usr/bin/env bash
set -euo pipefail

HOST="158.23.56.102"
PORT="9100"
ROOT="${1:-.}"   # ruta a la carpeta con logs (default: .)

echo "Recolectando archivos .log en: $ROOT"

# GNU find + sort por mtime ascendente (más viejos primero)
mapfile -d '' FILES < <(find "$ROOT" -type f -name '*.log' -print0 | \
  xargs -0 stat -c '%Y %n' | sort -n | cut -d' ' -f2- | tr '\n' '\0')

count=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  (( sz == 0 )) && { echo "Skip vacío: $f"; continue; }

  echo "[$(date -Is)] Enviando: $f ($sz bytes)"
  # OpenBSD nc => -N ; netcat-traditional => -q 0 ; ncat => --send-only
  if nc -N "$HOST" "$PORT" < "$f" 2>/dev/null; then
    :
  elif nc -q 0 "$HOST" "$PORT" < "$f" 2>/dev/null; then
    :
  else
    ncat --send-only "$HOST" "$PORT" < "$f" 2>/dev/null || {
      echo "ERROR enviando $f"
      continue
    }
  fi
  sleep 0.2
  ((count++))
done

echo "Listo. Archivos enviados: $count"