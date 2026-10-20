# VPS-SOC

Mini SOC/SIEM para uma VPS: um agente em Go coleta eventos de segurança, o backend Spring Boot
detecta, correlaciona e abre incidentes (com MITRE ATT&CK), e um dashboard React mostra tudo.

```
 VPS (Linux)                              Sua máquina / outra VPS
┌───────────────────┐   HTTPS + token   ┌──────────────────────────────────────┐
│ vps-soc-agent     │ ────────────────▶ │ nginx :8088  ─┬─ /      dashboard     │
│  • journald/auth  │  eventos (batch)  │               └─ /api   Spring Boot   │
│  • portas (/proc) │  heartbeat 30s    │                          │            │
│  • CPU/RAM/disco  │                   │   detecção → correlação → incidentes  │
└───────────────────┘                   │                          │            │
                                        │   PostgreSQL        Telegram (opc.)   │
                                        └──────────────────────────────────────┘
```

O backend roda **fora** da VPS monitorada. Se a VPS for comprometida, o atacante não consegue
apagar o histórico, e o próprio silêncio do agente vira um incidente (`AGENT_OFFLINE`).

## O que detecta (MVP)

| Regra | Gatilho | Severidade | MITRE |
|---|---|---|---|
| `SSH_BRUTE_FORCE` | ≥10 falhas SSH do mesmo IP em 60s (um incidente por IP; marca spraying se ≥5 usuários) | Médio | T1110.001 / .003 |
| `SSH_LOGIN_AFTER_BRUTE_FORCE` | login bem-sucedido de um IP com ≥5 falhas nos últimos 30 min | **Crítico** | T1110, T1078 |
| ↳ correlação | `sudo` do mesmo usuário, portas novas, arquivos monitorados alterados e processos suspeitos no host entram nesse incidente | risco 100 | +T1548.003, T1571, T1098.004, T1053.003, T1505.003, T1059.004 |
| `SSH_ROOT_LOGIN` | login direto como root | Alto | T1078.003 |
| `SSH_LOGIN_NEW_SOURCE` | primeiro login de um usuário a partir de um IP | Médio | T1078 |
| `SUDO_FAILURE` | senha errada no sudo / usuário fora do sudoers | Médio / Alto | T1548.003 |
| `NEW_LISTENING_PORT` | porta nova em escuta (Crítico se o binário está em `/tmp`, `/dev/shm` ou foi apagado) | Baixo → Crítico | T1571 |
| `FIM_AUTHORIZED_KEYS` | `/root/.ssh/authorized_keys` ou `/home/*/.ssh/authorized_keys` criado/alterado (removido = Médio) | Alto | T1098.004 |
| `FIM_SSHD_CONFIG` | `sshd_config` ou `sshd_config.d/*` alterado, com as diretivas adicionadas/removidas (Alto se entrar `PermitRootLogin yes`, `PasswordAuthentication yes`, `PermitEmptyPasswords yes` ou `AuthorizedKeys*`) | Médio / Alto | T1098.004 |
| `FIM_SUDOERS` | `/etc/sudoers` ou `/etc/sudoers.d/*` alterado | Alto | T1548.003 |
| `FIM_CRON` | `/etc/crontab`, `/etc/cron.d/*` ou crontab de usuário (criado = Alto) | Médio / Alto | T1053.003 |
| `FIM_ACCOUNTS` | `/etc/passwd`, `/etc/group` ou `/etc/shadow` alterado | Médio | T1136.001, T1098 |
| `WEB_SHELL` | `sh`/`bash`/`dash` filho de nginx/apache/php-fpm/node/java ou rodando como `www-data` | **Crítico** | T1505.003, T1059.004 |
| `SUSPICIOUS_PROCESS` | processo com binário em `/tmp`, `/var/tmp`, `/dev/shm` ou fileless (memfd); binário de sistema apagado (atualização sem restart) = Baixo | Baixo / **Crítico** | T1059, T1070.004 |
| `AGENT_OFFLINE` | 3 heartbeats perdidos (resolve sozinho quando volta) | Alto | T1562.001 |
| `DISK_USAGE_HIGH` | partição `/` ≥ 90% (resolve sozinho) | Médio / Alto | - |
| `SERVICE_FAILED` | serviço systemd em estado `failed` (um incidente por unidade; resolve sozinho) | Médio | - |
| `SECURITY_UPDATES` | atualizações de segurança pendentes (update-notifier do Ubuntu) | Baixo / Médio (≥10) | T1190 |
| `REBOOT_REQUIRED` | `/var/run/reboot-required` existe | Baixo | - |
| `SSH_WEAK_CONFIG` | `sshd -T` mostra `PasswordAuthentication yes` ou `PermitRootLogin yes` | Médio | T1110 |

Os quatro últimos são **postura** (não são ataques): resolvem sozinhos quando a condição some, e
marcar um deles como falso positivo vale como “risco aceito” (não reabre enquanto nada mudar).

Qualquer arquivo monitorado que fique gravável por todos (`o+w`) sobe para Alto.

**Integridade de arquivos (FIM)**: o agente calcula o SHA-256 dos arquivos acima a cada
`SOC_FIM_INTERVAL` (60s) e guarda a baseline em `/var/lib/vps-soc-agent/fim.json` (hash, tamanho,
mtime, dono e permissão; nunca o conteúdo). A única exceção são as diretivas efetivas do
`sshd_config`, guardadas para o evento dizer quais linhas mudaram. O `/etc/shadow` é só lido em
streaming para o hash: o conteúdo nunca é interpretado, guardado ou enviado.
**Processos**: `/proc` é varrido a cada `SOC_PROCESS_SCAN_INTERVAL` (15s); cada processo suspeito
gera um `PROCESS_SUSPICIOUS` uma vez enquanto estiver rodando.

Um incidente fica ativo (`OPEN`/`ACKNOWLEDGED`) por regra + chave. Novas evidências entram nele
em vez de abrir outro. O security score parte de 100 e perde 40/20/5/1 por incidente
crítico/alto/médio/baixo aberto.

## Incidentes explicados

Cada incidente traz, na tela e no Telegram, um texto escrito com os dados reais dele:

- **O que aconteceu**: quem, de onde, quando, quantas vezes, o que fez depois (ex.: “entrou como deploy
  após 14 falhas, usou sudo para ler /etc/shadow, abriu a porta 4444…”).
- **Por que importa**: o impacto real e os fatores que formaram o risco.
- **Evidências**: os fatos-chave (usuários testados, ritmo, hashes, chaves SSH novas, processo pai…).
- **Resposta do SOC**: o que já foi feito sozinho, o que espera sua aprovação, o que falhou.
- **Próximos passos**: checklist com os comandos prontos para colar no terminal da VPS.
- **Pode ser falso positivo?**: quando é benigno e como fazer o alerta parar.
- **Perfil do IP**: histórico completo do endereço (falhas, logins, usuários tentados, incidentes,
  bloqueio ativo, se é rede protegida) e botão para bloquear manualmente.

## Resposta ativa

O agente executa **só um conjunto fechado de ações**, com parâmetros validados e checagens feitas
na própria VPS. O SOC nunca manda comandos de shell.

| Ação | Quando | Padrão | Salvaguardas no agente |
|---|---|---|---|
| `BLOCK_IP` | brute force SSH (24 h); login após brute force (7 dias, derruba as sessões) | Automático | nunca bloqueia loopback, redes privadas, Tailscale `100.64.0.0/10`, link-local (terminal do hPanel), o IP do SOC nem `SOC_RESPONSE_ALLOWLIST`; o bloqueio tem prazo no kernel e expira sozinho |
| `UNBLOCK_IP` | botão no painel | manual | - |
| `KILL_PROCESS` | processo em `/tmp`/fileless ou web shell (Crítico) | Com aprovação | só mata se pid + start time + executável ainda batem e o processo continua suspeito; antes copia o binário para `/var/lib/vps-soc-agent/quarantine/<sha256>.bin` (evidência, só leitura) |
| `DISK_CLEANUP` | disco ≥ 90% | Automático | só `journalctl --vacuum-size=500M` e `apt-get clean` |
| `RESTART_SERVICE` | serviço em falha | Com aprovação | só reinicia se ainda estiver `failed` |

**Inteligência dos playbooks**: um IP que já fez login com sucesso antes do brute force (provavelmente
você errando a senha) só recebe uma *proposta* de bloqueio; se o atacante entra, o bloqueio de 24 h
vira 7 dias; um bloqueio já feito pelo agente faz o SOC descartar o seu, que seria redundante; um brute
force contido (IP bloqueado e nenhum login com sucesso) é resolvido sozinho, enquanto um
comprometimento fica aberto, porque alguém ainda precisa limpar a conta.

**Guarda local**: o agente bloqueia brute force sozinho (10 falhas em 2 min → 24 h), **mesmo com o
SOC desligado**, e conta para o SOC quando ele volta. Ele nunca bloqueia IPs que já fizeram login
limpo nos últimos 30 dias.

Os bloqueios ficam numa tabela própria do nftables (`inet vps_soc`, hook `prerouting`, antes do
Docker, então cobrem também as portas de containers). Para conferir na VPS:
`sudo nft list table inet vps_soc`.

Políticas no `.env` do SOC (`AUTO`, `APPROVAL` ou `OFF`): `SOC_RESPONSE_BLOCK_BRUTE_FORCE`,
`SOC_RESPONSE_BLOCK_COMPROMISE`, `SOC_RESPONSE_KILL_PROCESS`, `SOC_RESPONSE_DISK_CLEANUP`,
`SOC_RESPONSE_RESTART_SERVICE`; `SOC_RESPONSE_ENABLED=false` desliga tudo. No agente:
`SOC_RESPONSE_ENABLED`, `SOC_AUTOBLOCK*`, `SOC_RESPONSE_ALLOWLIST` (veja `agent/deploy/agent.env.example`).

## Métricas

- **Desempenho do SOC** (7/30/90 dias): MTTD (evidência → incidente), MTTA (→ alguém assumir),
  MTTC (→ contido), MTTR (→ resolvido), backlog, taxa de contenção automática, taxa de falsos
  positivos por regra, ações automáticas/manuais/falhas, IPs bloqueados, pacotes descartados pelo
  firewall, eventos por minuto e atraso dos dados (frescor do agente).
- **Tendência**: incidentes abertos × fechados por dia, detecções mais frequentes, usuários mais atacados.
- **Servidor**: CPU, RAM, swap, disco, load, rede (entrada/saída), conexões TCP, processos,
  sessões abertas (`who`), atualizações pendentes, reboot pendente, serviços em falha e configuração
  efetiva do SSH, num checklist de postura por host.

## Rodando localmente

Requisitos: Docker Desktop. Node é necessário só para o simulador.

```bash
cp .env.example .env        # preencha os 3 segredos: openssl rand -hex 32
docker compose up -d --build
node scripts/simulate-attack.mjs   # brute force → login → sudo → porta, chave SSH, cron e web shell
node scripts/simulate-attack.mjs --play-agent   # idem, e faz o papel do agente executando as ações por 30 s
```

Abra http://localhost:8088 e entre com o `SOC_DASHBOARD_TOKEN`.

Como o host `vps-demo` do simulador não manda mais heartbeats, depois de ~90s ele aparece
como `AGENT_OFFLINE`. Esse é o comportamento esperado.

### Desenvolvimento

```bash
docker compose up -d db                       # só o Postgres (porta interna; veja abaixo)
cd backend && ./mvnw spring-boot:run          # API em :8080 (precisa de SOC_* no ambiente)
cd frontend && npm install && npm run dev     # dashboard em :5173, proxy de /api para :8080
cd backend && ./mvnw test                     # testes de integração (Testcontainers, precisa do Docker)
```

Para rodar o backend fora do compose, exponha o Postgres adicionando `ports: ["5432:5432"]`
ao serviço `db`.

## Instalando o agente na VPS

1. **Compile** (não precisa de Go instalado, usa Docker):
   ```bash
   docker build -t vps-soc-agent-build agent
   docker run --rm -v "$PWD/dist:/out" vps-soc-agent-build
   ```
   Isso gera `dist/vps-soc-agent-linux-amd64` e `-arm64` (≈6 MB, estáticos).

2. **Conectividade**: a VPS precisa alcançar o backend. Opção recomendada: **Tailscale**
   nas duas máquinas, `SOC_BIND=<ip tailscale da sua máquina>` no `.env`, e no agente
   `SOC_SERVER_URL=http://100.x.y.z:8088` + `SOC_ALLOW_INSECURE_HTTP=true` (o túnel
   WireGuard já criptografa). Alternativa: um proxy HTTPS público (Caddy/Cloudflare Tunnel)
   na frente da porta 8088.

3. **Instale**:
   ```bash
   scp dist/vps-soc-agent-linux-amd64 agent/deploy/* root@sua-vps:/tmp/soc/
   ssh root@sua-vps
   cd /tmp/soc && chmod +x install.sh && ./install.sh vps-soc-agent-linux-amd64
   nano /etc/vps-soc-agent/agent.env      # SOC_SERVER_URL e SOC_AGENT_TOKEN
   vps-soc-agent -dry-run                 # confere o que seria enviado (Ctrl+C)
   systemctl enable --now vps-soc-agent
   journalctl -u vps-soc-agent -f
   ```

O agente lê o journald (Ubuntu/Debian modernos) ou faz fallback para `/var/log/auth.log` e
`/var/log/secure`. Ele guarda o cursor do journal, então não perde nem duplica eventos ao
reiniciar, e mantém até 10 mil eventos em memória se o backend ficar fora do ar. O serviço
systemd roda com `ProtectSystem=strict`, 128 MB de RAM e 20% de CPU no máximo.

## Estrutura

```
agent/      Go 1.23, só stdlib: coletores (auth log, portas, FIM, processos, métricas), sender com retry
backend/    Java 21 + Spring Boot 3.5, Flyway, PostgreSQL, regras em detection/rules
frontend/   React 18 + TypeScript + Tailwind + TanStack Query + Recharts
scripts/    simulate-attack.mjs
```

## Próximas fases

- **FIM com autoria**: integrar auditd para saber quem alterou cada arquivo monitorado.
- **Processos**: conexões de saída novas.
- **Threat intel**: AbuseIPDB + GeoLite2 (offline), com cache por IP.
- **Resposta**: remover chave SSH plantada (com backup) e isolar conta comprometida; bloqueio também no firewall da Hostinger via API.
