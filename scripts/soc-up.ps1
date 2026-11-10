# Liga o SOC neste PC (Windows) e aponta o agente da VPS para ca.
#
#   Duplo clique em scripts\soc-up.cmd   (ou: powershell -ExecutionPolicy Bypass -File scripts\soc-up.ps1)
#
# 1. descobre o IP do Tailscale deste PC
# 2. sobe o painel nesse IP (sem editar o .env)
# 3. entra na VPS por SSH (SOC_VPS_SSH no .env) e troca o SOC_SERVER_URL do agente
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not (Test-Path .env)) {
  Write-Host 'Falta o arquivo .env. Copie o .env.example e preencha os 3 segredos (veja docs\GUIA.md).' -ForegroundColor Red
  exit 1
}

function Get-EnvValue([string]$name) {
  $line = Get-Content .env | Where-Object { $_ -match "^$name=" } | Select-Object -Last 1
  if ($line) { return ($line -split '=', 2)[1].Trim() }
  return ''
}

$port = Get-EnvValue 'SOC_PORT'
if (-not $port) { $port = '8088' }
$vps = Get-EnvValue 'SOC_VPS_SSH'

$ip = ''
try { $ip = (& tailscale ip -4 2>$null | Select-Object -First 1) } catch { }
if (-not $ip) {
  Write-Host 'Nao achei o IP do Tailscale. Abra o Tailscale, conecte e rode de novo.' -ForegroundColor Red
  exit 1
}
$ip = "$ip".Trim()
$url = "http://${ip}:$port"

Write-Host "1/3 Subindo o SOC em $url ..."
$env:SOC_BIND = $ip
$env:SOC_PORT = $port
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
  # Some Docker Desktop setups cannot publish on a single host IP; fall back to all interfaces.
  Write-Host 'Nao deu para publicar so no IP do Tailscale; tentando em todas as interfaces (0.0.0.0)...' -ForegroundColor Yellow
  $env:SOC_BIND = '0.0.0.0'
  docker compose up -d
  if ($LASTEXITCODE -ne 0) {
    Write-Host 'O docker compose falhou. O Docker Desktop esta aberto? Veja a mensagem acima.' -ForegroundColor Red
    exit 1
  }
}

Write-Host '2/3 Esperando o painel responder...'
for ($i = 0; $i -lt 60; $i++) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "$url/" | Out-Null; break } catch { Start-Sleep -Seconds 2 }
}

if ($vps) {
  Write-Host "3/3 Apontando o agente da VPS ($vps) para este PC..."
  ssh -o ConnectTimeout=10 $vps "sed -i 's|^SOC_SERVER_URL=.*|SOC_SERVER_URL=$url|' /etc/vps-soc-agent/agent.env && systemctl restart vps-soc-agent"
  if ($LASTEXITCODE -eq 0) {
    Write-Host "    agente agora manda os dados para $url"
  } else {
    Write-Host '    Nao consegui entrar na VPS por SSH. O painel esta no ar, mas o agente continua apontando para o PC anterior.' -ForegroundColor Yellow
    Write-Host "    Veja docs\GUIA.md, secao 'Usando em mais de um PC'." -ForegroundColor Yellow
  }
} else {
  Write-Host '3/3 SOC_VPS_SSH nao esta no .env: o agente da VPS nao foi alterado.'
}

Write-Host ''
Write-Host "Pronto. Abra $url" -ForegroundColor Green
