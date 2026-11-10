#!/usr/bin/env bash
# Liga o SOC neste PC (Linux/macOS) e aponta o agente da VPS para cá.
#
#   ./scripts/soc-up.sh
#
# 1. descobre o IP do Tailscale deste PC
# 2. sobe o painel nesse IP (sem editar o .env)
# 3. entra na VPS por SSH (SOC_VPS_SSH no .env) e troca o SOC_SERVER_URL do agente
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Falta o arquivo .env. Copie o .env.example e preencha os 3 segredos (veja docs/GUIA.md)." >&2
  exit 1
fi

env_get() { grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- | tr -d '\r' || true; }
PORT="$(env_get SOC_PORT)"; PORT="${PORT:-8088}"
VPS="$(env_get SOC_VPS_SSH)"

IP="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
if [ -z "$IP" ]; then
  echo "Não achei o IP do Tailscale. Ligue o Tailscale (tailscale up) e rode de novo." >&2
  exit 1
fi
URL="http://$IP:$PORT"

echo "1/3 Subindo o SOC em $URL ..."
SOC_BIND="$IP" SOC_PORT="$PORT" docker compose up -d --build

echo "2/3 Esperando o painel responder..."
for _ in $(seq 1 60); do
  if curl -fs -o /dev/null "$URL/"; then break; fi
  sleep 2
done

if [ -n "$VPS" ]; then
  echo "3/3 Apontando o agente da VPS ($VPS) para este PC..."
  if ssh -o ConnectTimeout=10 "$VPS" \
    "sed -i 's|^SOC_SERVER_URL=.*|SOC_SERVER_URL=$URL|' /etc/vps-soc-agent/agent.env && systemctl restart vps-soc-agent"; then
    echo "    agente agora manda os dados para $URL"
  else
    echo "    Não consegui entrar na VPS por SSH. O painel está no ar, mas o agente continua apontando para o PC anterior." >&2
    echo "    Veja docs/GUIA.md, seção 'Usando em mais de um PC'." >&2
  fi
else
  echo "3/3 SOC_VPS_SSH não está no .env: o agente da VPS não foi alterado."
fi

echo
echo "Pronto. Abra $URL"
