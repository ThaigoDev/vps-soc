package com.vpssoc.insight;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.*;
import com.vpssoc.domain.ResponseAction.Status;
import com.vpssoc.insight.Explanation.Fact;
import com.vpssoc.insight.Explanation.IpProfile;
import com.vpssoc.insight.Explanation.Step;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Writes the incident up the way an analyst would explain it to the server's owner: what
 * happened (with the real numbers), why it matters, why it got this risk score, what the SOC
 * already did, what to do next (with the exact commands) and when it is a false positive.
 */
@Component
public class IncidentExplainer {

    static final ZoneId ZONE = ZoneId.of("America/Sao_Paulo");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MM HH:mm:ss").withZone(ZONE);
    private static final DateTimeFormatter TIME_SHORT = DateTimeFormatter.ofPattern("dd/MM HH:mm").withZone(ZONE);

    /** Everything one explanation needs, gathered by the caller. */
    public record Context(Incident incident, List<SecurityEvent> events, IpProfile ip, Host host,
                          List<ResponseAction> actions, SocProperties.Response policy) {
    }

    public Explanation explain(Context c) {
        Incident i = c.incident();
        Stats s = new Stats(c.events());
        Builder b = new Builder();
        switch (i.getRuleId()) {
            case RuleIds.SSH_BRUTE_FORCE -> bruteForce(c, s, b);
            case RuleIds.SSH_COMPROMISE -> compromise(c, s, b);
            case RuleIds.SSH_ROOT_LOGIN -> rootLogin(c, s, b);
            case RuleIds.SSH_NEW_SOURCE -> newSource(c, s, b);
            case RuleIds.SUDO_FAILURE -> sudoFailure(c, s, b);
            case RuleIds.NEW_LISTENING_PORT -> newPort(c, s, b);
            case RuleIds.FIM_AUTHORIZED_KEYS, RuleIds.FIM_SSHD_CONFIG, RuleIds.FIM_SUDOERS, RuleIds.FIM_CRON,
                 RuleIds.FIM_ACCOUNTS -> fileChange(c, s, b);
            case RuleIds.SUSPICIOUS_PROCESS, RuleIds.WEB_SHELL -> process(c, s, b);
            case RuleIds.AGENT_OFFLINE -> agentOffline(c, b);
            case RuleIds.DISK_USAGE_HIGH -> disk(c, b);
            case RuleIds.SERVICE_FAILED -> serviceFailed(c, b);
            case RuleIds.SECURITY_UPDATES -> updates(c, b);
            case RuleIds.REBOOT_REQUIRED -> reboot(c, b);
            case RuleIds.SSH_WEAK_CONFIG -> sshWeak(c, b);
            default -> b.summary = Objects.toString(i.getDescription(), i.getTitle());
        }
        commonRisk(c, s, b);
        b.response = describeResponse(c);
        return b.build();
    }

    // ---------------------------------------------------------------- SSH

    private void bruteForce(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        String ip = i.getSourceIp();
        long fails = s.count(EventType.SSH_FAILED_LOGIN, EventType.SSH_INVALID_USER);
        List<String> users = s.usernames(EventType.SSH_FAILED_LOGIN, EventType.SSH_INVALID_USER);
        long invalid = s.count(EventType.SSH_INVALID_USER);
        b.summary = "Entre %s e %s (%s), o endereço %s fez %d tentativas de login SSH em %s e todas falharam. Testou %d usuário%s: %s.%s"
                .formatted(t(s.first), t(s.last), human(s.span()), ip, fails, i.getHostId(), users.size(), users.size() == 1 ? "" : "s",
                        list(users, 8),
                        invalid > 0 ? " %d tentativas usaram nomes que nem existem no servidor, típico de robôs que varrem a internet com listas prontas.".formatted(invalid) : "");
        b.impact = "Robôs testam senhas comuns em todo servidor exposto na internet. Não é um ataque direcionado, mas basta uma conta com senha "
                + "fraca para o invasor entrar com shell no servidor. O risco real depende de o SSH aceitar login por senha"
                + sshPasswordNote(c.host()) + ".";
        b.fact("IP de origem", ip + (c.ip() != null ? " · " + c.ip().kindLabel() : ""));
        b.fact("Tentativas neste incidente", String.valueOf(fails));
        b.fact("Ritmo", "%.1f tentativas/min".formatted(s.perMinute(fails)));
        b.fact("Usuários testados", list(users, 12));
        b.fact("Algum login funcionou?", c.ip() != null && c.ip().everLoggedIn() ? "SIM, este IP já entrou no servidor (veja o histórico)" : "Não");
        b.step("Confirmar que o IP está bloqueado", "A lista mostra os IPs bloqueados pelo agente e por quanto tempo ainda.",
                "sudo nft list set inet vps_soc blocked" + (ip != null && ip.contains(":") ? "6" : "4"));
        b.step("Conferir se algum login teve sucesso", "Qualquer linha 'Accepted' vinda desse IP significa invasão: trate como conta comprometida.",
                "sudo journalctl -u ssh --since '-24h' | grep -E 'Accepted .* from %s'".formatted(ip));
        sshHardeningSteps(c.host(), b);
        b.falsePositive = "Só é falso positivo se o IP for seu, por exemplo um script ou cliente SSH salvo com a senha errada."
                + (c.ip() != null && c.ip().everLoggedIn()
                ? " Atenção: esse IP já fez login com sucesso antes, então pode ser você. Por isso o bloqueio não é automático nesse caso."
                : " Esse IP nunca fez login com sucesso no servidor.");
    }

    private void compromise(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        String ip = i.getSourceIp();
        String user = i.getUsername();
        SecurityEvent login = s.latest(EventType.SSH_LOGIN_SUCCESS);
        long fails = s.count(EventType.SSH_FAILED_LOGIN, EventType.SSH_INVALID_USER);
        List<SecurityEvent> sudo = s.of(EventType.SUDO_COMMAND);
        List<String> after = new ArrayList<>();
        if (!sudo.isEmpty()) {
            after.add("executou %d comando%s com sudo (ex.: %s)".formatted(sudo.size(), sudo.size() == 1 ? "" : "s",
                    sudo.stream().map(e -> "'" + e.meta("command") + "'").limit(3).collect(Collectors.joining(", "))));
        }
        if (s.count(EventType.PORT_OPENED) > 0) {
            after.add("abriu %d porta(s) nova(s) em escuta (%s)".formatted(s.count(EventType.PORT_OPENED),
                    s.of(EventType.PORT_OPENED).stream().map(e -> e.meta("port") + "/" + e.meta("process")).limit(3).collect(Collectors.joining(", "))));
        }
        long files = s.count(EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED);
        if (files > 0) {
            after.add("alterou %d arquivo(s) sensível(is) (%s)".formatted(files,
                    s.ofAny(EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED).stream()
                            .map(e -> String.valueOf(e.meta("path"))).distinct().limit(3).collect(Collectors.joining(", "))));
        }
        if (s.count(EventType.PROCESS_SUSPICIOUS) > 0) {
            after.add("executou processo(s) suspeito(s) (%s)".formatted(s.of(EventType.PROCESS_SUSPICIOUS).stream()
                    .map(e -> String.valueOf(e.meta("exe"))).distinct().limit(3).collect(Collectors.joining(", "))));
        }
        b.summary = "%s conseguiu entrar via SSH como '%s'%s depois de %d tentativas que falharam vindas do mesmo IP. Esse padrão, muitas falhas e depois um acerto, "
                .formatted(ip, user, login != null ? " às " + t(login.getOccurredAt()) + " (método " + login.meta("method") + ")" : "", fails)
                + "é a assinatura de uma senha descoberta por força bruta."
                + (after.isEmpty() ? " Até agora o SOC não viu atividade depois do login." : " Depois de entrar, o invasor " + String.join("; ", after) + ".");
        b.impact = "O invasor tem um shell no servidor como '%s'%s. Com isso pode ler e roubar dados, instalar backdoors (chaves SSH, cron, serviços), minerar criptomoeda "
                .formatted(user, sudo.isEmpty() ? "" : " e, como usou sudo, muito provavelmente tem root")
                + "ou usar a VPS para atacar outros servidores, o que pode levar a Hostinger a suspendê-la.";
        b.fact("Conta comprometida", user);
        b.fact("IP do invasor", ip + (c.ip() != null ? " · " + c.ip().kindLabel() : ""));
        b.fact("Falhas antes do acesso", String.valueOf(fails));
        if (login != null) {
            b.fact("Horário do acesso", t(login.getOccurredAt()));
        }
        b.fact("Ações após o login", after.isEmpty() ? "nenhuma detectada ainda" : String.valueOf(after.size()) + " tipo(s) de atividade");
        b.step("Derrubar todas as sessões da conta", "Encerra shells e processos abertos pelo invasor com esse usuário.",
                "sudo pkill -KILL -u " + user);
        b.step("Trocar a senha (ou travar a conta)", "Se a conta não precisa de login por senha, trave-a e use só chave SSH.",
                "sudo passwd %s   # ou: sudo usermod -L %s".formatted(user, user));
        b.step("Procurar persistência", "Chaves SSH novas, cron jobs e usuários criados são como o invasor volta depois.",
                "sudo cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; sudo ls -la /etc/cron.d /var/spool/cron/crontabs; awk -F: '$3==0' /etc/passwd");
        b.step("Ver o que foi executado", "Histórico de sudo desde o primeiro ataque e o histórico do shell da conta.",
                "sudo journalctl _COMM=sudo --since '%s'; sudo cat /home/%s/.bash_history".formatted(isoLocal(i.getFirstSeen()), user));
        b.step("Se houver dúvida, restaurar", "Com root comprometido não há como garantir que tudo foi limpo: restaure um snapshot anterior a "
                + t(i.getFirstSeen()) + " (hPanel → VPS → Snapshots) e troque todas as senhas e chaves.", null);
        sshHardeningSteps(c.host(), b);
        b.falsePositive = "Só é falso positivo se foi você que errou a senha várias vezes e depois acertou, a partir de " + ip
                + ". Se não reconhece o IP, trate como invasão real.";
    }

    private void rootLogin(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        SecurityEvent login = s.latest(EventType.SSH_LOGIN_SUCCESS);
        b.summary = "Alguém entrou direto como root via SSH a partir de %s%s. Root não tem nenhum limite: quem entra assim controla o servidor inteiro."
                .formatted(i.getSourceIp(), login != null ? " às " + t(login.getOccurredAt()) + " usando " + login.meta("method") : "");
        b.impact = "Logins diretos de root não deixam rastro de qual pessoa entrou e, se a senha ou chave de root vazar, não há uma segunda barreira. "
                + "A boa prática é entrar com um usuário comum e usar sudo.";
        b.fact("IP", i.getSourceIp() + (c.ip() != null ? " · " + c.ip().kindLabel() : ""));
        if (login != null) {
            b.fact("Método", String.valueOf(login.meta("method")));
        }
        b.step("Confirmar quem estava logado", "Mostra as últimas sessões com IP de origem.", "last -i -n 20 root");
        b.step("Criar um usuário administrador", "Entre com ele e use sudo no lugar de root.",
                "sudo adduser admin && sudo usermod -aG sudo admin && sudo rsync -a /root/.ssh/ /home/admin/.ssh/ && sudo chown -R admin: /home/admin/.ssh");
        b.step("Desligar login direto de root", "Teste antes o login com o novo usuário em outra janela.",
                "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-vps-soc.conf && sudo sshd -t && sudo systemctl reload ssh");
        b.falsePositive = "Normal se foi você entrando como root desse IP. Se o acesso vem do terminal do painel da Hostinger (169.254.0.1) ou de um IP fixo seu, "
                + "adicione-o em SOC_TRUSTED_SSH_SOURCES no .env do SOC e esse alerta deixa de aparecer.";
    }

    private void newSource(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        SecurityEvent login = s.latest(EventType.SSH_LOGIN_SUCCESS);
        b.summary = "A conta '%s' fez login via SSH a partir de %s pela primeira vez%s. O SOC não tinha visto essa combinação de usuário e IP antes."
                .formatted(i.getUsername(), i.getSourceIp(), login != null ? " (" + t(login.getOccurredAt()) + ", método " + login.meta("method") + ")" : "");
        b.impact = "Um IP novo pode ser só você em outra rede (4G, viagem). Mas também é o primeiro sinal de uma credencial roubada sendo usada por outra pessoa.";
        b.fact("Usuário", i.getUsername());
        b.fact("IP", i.getSourceIp() + (c.ip() != null ? " · " + c.ip().kindLabel() : ""));
        b.step("Confirmar a sessão", "Veja se o horário e o IP batem com um acesso seu.", "last -i -n 20 " + i.getUsername());
        b.step("Se não foi você", "Derrube a sessão, troque a senha e revise as chaves SSH da conta.",
                "sudo pkill -KILL -u %s; sudo passwd %s; sudo cat /home/%s/.ssh/authorized_keys".formatted(i.getUsername(), i.getUsername(), i.getUsername()));
        b.falsePositive = "Comum quando você acessa de uma rede nova. Se for um IP fixo seu, inclua-o em SOC_TRUSTED_SSH_SOURCES.";
    }

    private void sudoFailure(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        SecurityEvent e = s.latest(EventType.SUDO_DENIED, EventType.SUDO_AUTH_FAILURE);
        boolean denied = s.count(EventType.SUDO_DENIED) > 0;
        b.summary = denied
                ? "O usuário '%s', que não tem permissão de administrador, tentou executar '%s' como %s. O sudo recusou e registrou a tentativa."
                .formatted(i.getUsername(), e == null ? "?" : e.meta("command"), e == null ? "root" : e.meta("runAs"))
                : "O usuário '%s' errou a senha do sudo %d vez(es) ao tentar executar '%s'."
                .formatted(i.getUsername(), s.count(EventType.SUDO_AUTH_FAILURE), e == null ? "?" : e.meta("command"));
        b.impact = denied
                ? "Uma conta sem privilégios tentando virar root é típico de um invasor que entrou por uma conta comum (ou por uma aplicação web, ex.: www-data) e está tentando escalar privilégio."
                : "Pode ser só um erro de digitação. Mas várias falhas seguidas podem ser alguém com acesso à conta tentando adivinhar a senha para virar root.";
        b.fact("Usuário", i.getUsername());
        b.fact("Tentativas", String.valueOf(s.count(EventType.SUDO_DENIED, EventType.SUDO_AUTH_FAILURE)));
        if (e != null) {
            b.fact("Comando", String.valueOf(e.meta("command")));
            b.fact("Terminal", String.valueOf(e.meta("tty")));
        }
        b.step("Ver o histórico de sudo dessa conta", null, "sudo journalctl _COMM=sudo --since '-24h' | grep '%s'".formatted(i.getUsername()));
        b.step("Ver de onde a conta está logada", "Se for www-data ou outra conta de serviço, a origem é a aplicação web: confira os logs dela.",
                "who; sudo ps -u %s -o pid,ppid,etime,cmd".formatted(i.getUsername()));
        b.falsePositive = "Normal se foi você esquecendo de que a conta não tem sudo ou errando a senha.";
    }

    // ---------------------------------------------------------------- network / files / processes

    private void newPort(Context c, Stats s, Builder b) {
        SecurityEvent e = s.latest(EventType.PORT_OPENED);
        Object port = e == null ? "?" : e.meta("port");
        String address = e == null ? "?" : String.valueOf(e.meta("address"));
        String exe = e == null ? "" : Objects.toString(e.meta("exe"), "");
        boolean exposed = "0.0.0.0".equals(address) || "::".equals(address);
        boolean temp = exe.startsWith("/tmp/") || exe.startsWith("/dev/shm/") || exe.startsWith("/var/tmp/") || exe.endsWith("(deleted)");
        b.summary = "O processo %s (pid %s, executável %s) começou a escutar na porta %s em %s, %s."
                .formatted(e == null ? "?" : e.meta("process"), e == null ? "?" : e.meta("pid"), exe.isEmpty() ? "?" : exe, port, address,
                        exposed ? "ou seja, aberta para a internet (se o firewall do provedor permitir)" : "acessível só localmente");
        b.impact = temp
                ? "O executável roda de um diretório temporário ou foi apagado do disco. Isso quase sempre é um payload de invasor, como um backdoor (bind shell), um proxy ou um minerador."
                : exposed
                ? "Todo serviço exposto é uma porta de entrada. Se for algo que você instalou, confira se precisa mesmo estar público (bancos de dados e painéis quase nunca precisam)."
                : "Serviços só locais têm risco baixo, mas um processo inesperado escutando ainda merece uma olhada.";
        b.fact("Porta", port + "/" + (e == null ? "tcp" : e.meta("proto")));
        b.fact("Endereço", address + (exposed ? " (todas as interfaces)" : ""));
        b.fact("Processo", e == null ? "?" : e.meta("process") + " · pid " + e.meta("pid") + " · usuário " + e.getUsername());
        b.fact("Executável", exe.isEmpty() ? "?" : exe);
        b.step("Ver quem está escutando e conectado", null, "sudo ss -tlnp 'sport = :%s'; sudo ss -tnp | grep 'pid=%s,'".formatted(port, e == null ? "" : e.meta("pid")));
        b.step("Inspecionar o processo", null, e == null ? null : "sudo ls -l /proc/%s/exe; sudo cat /proc/%s/cmdline | tr '\\0' ' '; echo".formatted(e.meta("pid"), e.meta("pid")));
        if (exposed && !temp) {
            b.step("Se o serviço deve ser só local", "Configure-o para escutar em 127.0.0.1, ou feche a porta no firewall da Hostinger (hPanel → VPS → Firewall).", null);
        }
        b.falsePositive = "Normal logo depois de você instalar ou subir um serviço (um container Docker, um app Node...). Nesse caso resolva o incidente com uma nota.";
    }

    private void fileChange(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        SecurityEvent e = s.latest(EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED);
        String path = e == null ? i.getDedupKey() : String.valueOf(e.meta("path"));
        String verb = e == null ? "alterado" : switch (e.getType()) {
            case FILE_CREATED -> "criado";
            case FILE_DELETED -> "apagado";
            default -> "alterado";
        };
        List<String> added = e == null ? List.of() : strings(e.meta("addedLines"));
        List<String> removed = e == null ? List.of() : strings(e.meta("removedLines"));
        b.summary = "O arquivo %s foi %s%s.%s%s".formatted(path, verb, e == null ? "" : " às " + t(e.getOccurredAt()),
                added.isEmpty() ? "" : " Linhas novas: " + String.join(" | ", added.stream().limit(5).toList()) + ".",
                removed.isEmpty() ? "" : " Linhas removidas: " + String.join(" | ", removed.stream().limit(5).toList()) + ".");
        String rule = i.getRuleId();
        b.impact = switch (rule) {
            case RuleIds.FIM_AUTHORIZED_KEYS -> "Uma chave em authorized_keys deixa quem tem a chave privada entrar sem senha, e continua valendo mesmo se a senha for trocada. "
                    + "É a forma de persistência mais comum depois de uma invasão.";
            case RuleIds.FIM_SSHD_CONFIG -> "A configuração do SSH define quem pode entrar e como. Ligar login por senha ou root, ou apontar para outro arquivo de chaves, abre caminho para invasão.";
            case RuleIds.FIM_SUDOERS -> "O sudoers decide quem pode virar root. Uma linha nova como 'usuario ALL=(ALL) NOPASSWD:ALL' dá root sem senha.";
            case RuleIds.FIM_CRON -> "Cron executa comandos sozinho em horários definidos. Invasores usam cron para baixar e rodar malware de novo a cada minuto, mesmo depois de você limpar.";
            default -> "passwd/group/shadow definem as contas do sistema. Uma conta nova (pior ainda com UID 0) é um backdoor permanente.";
        };
        boolean uidZero = added.stream().anyMatch(l -> l.matches("^[^:]+:[^:]*:0:.*") && !l.startsWith("root:"));
        if (uidZero) {
            b.impact += " ATENÇÃO: uma das linhas novas cria uma conta com UID 0, que equivale a root.";
            b.risk("Conta nova com UID 0 (equivale a root)");
        }
        b.fact("Arquivo", path);
        if (e != null) {
            b.fact("Dono / permissões", e.meta("owner") + " · " + e.meta("mode"));
            b.fact("Hash anterior → atual", shortHash(e.meta("oldHash")) + " → " + shortHash(e.meta("newHash")));
            List<?> keys = e.meta("addedKeys") instanceof List<?> l ? l : List.of();
            if (!keys.isEmpty()) {
                b.fact("Chaves adicionadas", keys.stream().map(k -> k instanceof Map<?, ?> m ? m.get("type") + " " + m.get("fingerprint")
                        + (m.get("comment") != null ? " \"" + m.get("comment") + "\"" : "") : String.valueOf(k)).collect(Collectors.joining("; ")));
            }
        }
        switch (rule) {
            case RuleIds.FIM_AUTHORIZED_KEYS -> {
                b.step("Listar as chaves e suas impressões digitais", "Compare com as chaves que você reconhece (ssh-keygen -lf ~/.ssh/id_ed25519.pub no seu PC).",
                        "sudo ssh-keygen -lf " + path);
                b.step("Remover uma chave desconhecida", "Apague a linha correspondente e salve.", "sudo nano " + path);
            }
            case RuleIds.FIM_SSHD_CONFIG -> {
                b.step("Ver a configuração efetiva", null, "sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|authorizedkeysfile|port '");
                b.step("Desfazer e recarregar", "Corrija as linhas e valide antes de recarregar para não se trancar fora.", "sudo nano %s && sudo sshd -t && sudo systemctl reload ssh".formatted(path));
            }
            case RuleIds.FIM_SUDOERS -> {
                b.step("Revisar o arquivo", null, "sudo cat " + path);
                b.step("Editar com segurança", "visudo valida a sintaxe antes de salvar.", "sudo visudo" + (path.equals("/etc/sudoers") ? "" : " -f " + path));
            }
            case RuleIds.FIM_CRON -> {
                b.step("Ver o conteúdo", "Desconfie de curl/wget, base64, /tmp e /dev/shm.", "sudo cat " + path);
                b.step("Listar todos os agendamentos", null, "sudo ls -la /etc/cron.* /var/spool/cron/crontabs; for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u $u 2>/dev/null | sed \"s/^/$u: /\"; done");
            }
            default -> {
                b.step("Contas com privilégio de root", "Só 'root' deveria aparecer.", "awk -F: '$3==0' /etc/passwd");
                b.step("Contas que podem logar", null, "grep -vE 'nologin|false$' /etc/passwd; sudo lastlog | grep -v Never");
            }
        }
        b.falsePositive = "Normal se foi você (ou uma atualização de pacote) que mexeu no arquivo agora há pouco. Nesse caso resolva com uma nota dizendo o que mudou.";
    }

    private void process(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        SecurityEvent e = s.latest(EventType.PROCESS_SUSPICIOUS);
        if (e == null) {
            b.summary = Objects.toString(i.getDescription(), i.getTitle());
            return;
        }
        String reason = String.valueOf(e.meta("reason"));
        b.summary = "%s (pid %s, usuário %s) está rodando com o executável %s, iniciado por %s (pid %s). Linha de comando: %s"
                .formatted(e.meta("comm"), e.meta("pid"), e.getUsername(), e.meta("exe"), e.meta("parentComm"), e.meta("ppid"), e.meta("cmdline"));
        b.impact = switch (reason) {
            case "WEB_SHELL" -> "Um shell rodando debaixo do servidor web ou da aplicação significa que alguém está executando comandos através do site, "
                    + "por upload de arquivo malicioso, falha de RCE ou plugin vulnerável. O invasor já executa comandos no servidor.";
            case "TEMP_EXE" -> "Programas legítimos não rodam de /tmp, /var/tmp ou /dev/shm. São diretórios onde qualquer usuário escreve, e é onde invasores "
                    + "colocam mineradores, bots de DDoS e backdoors baixados com curl/wget.";
            default -> i.getSeverity() == Severity.LOW
                    ? "O binário foi substituído no disco enquanto o processo rodava, o que normalmente acontece quando um pacote é atualizado e o serviço não é reiniciado. "
                    + "Ele continua rodando a versão antiga, possivelmente sem as correções."
                    : "O executável não existe mais no disco (apagado ou carregado só em memória). Malware faz isso para não deixar arquivo para análise.";
        };
        b.fact("Motivo", switch (reason) {
            case "WEB_SHELL" -> "shell filho de serviço web";
            case "TEMP_EXE" -> "executável em diretório temporário";
            default -> "executável apagado do disco";
        });
        b.fact("Processo", e.meta("comm") + " · pid " + e.meta("pid") + " · usuário " + e.getUsername());
        b.fact("Pai", e.meta("parentComm") + " · pid " + e.meta("ppid") + " · " + e.meta("parentExe"));
        b.fact("Comando", String.valueOf(e.meta("cmdline")));
        if (i.getSeverity() == Severity.LOW) {
            b.step("Reiniciar o serviço afetado", "Carrega o binário atualizado.", "sudo needrestart -r l || sudo systemctl restart " + e.meta("comm"));
            b.falsePositive = "Quase sempre é benigno: atualização de pacote sem reinício.";
            return;
        }
        b.step("Ver conexões do processo", "Conexões para fora (portas 4444, 1337, pools de mineração) confirmam o malware.",
                "sudo ss -tnp | grep 'pid=%s,'".formatted(e.meta("pid")));
        b.step("Guardar e encerrar", "Se o agente ainda não encerrou: copie o binário para análise e mate o processo.",
                "sudo cp /proc/%s/exe /root/evidencia-%s.bin; sudo kill -9 %s".formatted(e.meta("pid"), e.meta("pid"), e.meta("pid")));
        b.step("Evidência guardada pelo agente", "Ao encerrar, o agente salva uma cópia do binário (só leitura) com o hash SHA-256. Pesquise o hash no VirusTotal.",
                "sudo ls -la /var/lib/vps-soc-agent/quarantine/");
        if ("WEB_SHELL".equals(reason)) {
            b.step("Achar a porta de entrada no site", "Procure requisições POST estranhas e arquivos .php recém-criados na pasta do site.",
                    "sudo tail -n 300 /var/log/nginx/access.log | grep -E 'POST|cmd=|eval|base64'; sudo find /var/www -newermt '-2 hours' -type f");
        } else {
            b.step("Achar como chegou", "Procure downloads recentes e persistência.", "sudo grep -rE 'curl|wget' /etc/cron* /var/spool/cron 2>/dev/null; sudo ls -la /tmp /var/tmp /dev/shm");
        }
        b.falsePositive = "Raro. Alguns instaladores rodam de /tmp por alguns segundos, e scripts de deploy podem abrir shells sob o usuário do app. "
                + "Se você reconhece o comando acima, marque como falso positivo.";
    }

    // ---------------------------------------------------------------- host state

    private void agentOffline(Context c, Builder b) {
        Host h = c.host();
        b.summary = "O agente de %s parou de mandar sinais de vida. Último contato: %s."
                .formatted(c.incident().getHostId(), h == null ? t(c.incident().getFirstSeen()) : t(h.getLastSeen()));
        b.impact = "Sem o agente o SOC fica cego para esse servidor. Um invasor com root costuma parar o monitoramento primeiro. "
                + "Também acontece por motivos simples: VPS reiniciando, queda de rede ou do Tailscale.";
        b.step("Ver o estado do agente na VPS", null, "sudo systemctl status vps-soc-agent --no-pager; sudo journalctl -u vps-soc-agent -n 50 --no-pager");
        b.step("Conferir o Tailscale", "O agente envia os dados por ele até o seu PC.", "tailscale status");
        b.step("Religar o agente", null, "sudo systemctl restart vps-soc-agent");
        b.falsePositive = "Se o seu PC (onde o SOC roda) ficou desligado, este alerta aparece logo que ele volta e se resolve sozinho no próximo heartbeat (até 30 s). "
                + "O agente guarda os eventos enquanto o SOC está fora e manda tudo depois.";
    }

    private void disk(Context c, Builder b) {
        Map<String, Object> m = c.host() == null ? null : c.host().getMetrics();
        Object pct = m == null ? null : m.get("diskPercent");
        b.summary = "A partição raiz (/) está com %s%% de uso.".formatted(pct == null ? "?" : pct);
        b.impact = "Com o disco cheio, logs param de ser gravados (inclusive os de segurança), bancos de dados corrompem e serviços caem. "
                + "Atacantes às vezes enchem o disco de propósito para apagar rastros.";
        b.fact("Uso atual", pct == null ? "?" : pct + "%");
        b.step("Ver o que ocupa espaço", null, "sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -20");
        b.step("Docker e logs", "Imagens antigas e logs de container costumam ser os maiores culpados.", "sudo docker system df; sudo journalctl --disk-usage");
        b.step("Liberar espaço do Docker (com cuidado)", "Remove imagens e containers parados.", "sudo docker system prune");
        b.falsePositive = "Não é um ataque: é um alerta de saúde. Resolve sozinho quando o uso cair 2 pontos abaixo do limite.";
    }

    private void serviceFailed(Context c, Builder b) {
        String unit = c.incident().getDedupKey();
        b.summary = "O serviço %s está em estado 'failed': o processo terminou com erro e o systemd não está mais rodando ele.".formatted(unit);
        b.impact = "Se for o site, a API ou o banco, o sistema está fora do ar. Se for um serviço de segurança (firewall, fail2ban, backup), a proteção está desligada.";
        b.step("Ver o motivo da falha", null, "sudo systemctl status %s --no-pager; sudo journalctl -u %s -n 100 --no-pager".formatted(unit, unit));
        b.step("Reiniciar", null, "sudo systemctl restart " + unit);
        b.step("Se não for mais usado", "Desative para parar o alerta.", "sudo systemctl disable --now %s && sudo systemctl reset-failed %s".formatted(unit, unit));
        b.falsePositive = "Serviços que rodam uma vez e terminam com erro esperado aparecem aqui. Use reset-failed ou marque como falso positivo (risco aceito).";
    }

    private void updates(Context c, Builder b) {
        Map<String, Object> p = c.host() == null ? null : c.host().getPosture();
        Object sec = p == null ? "?" : p.get("securityUpdates");
        Object all = p == null ? "?" : p.get("pendingUpdates");
        b.summary = "%s pacote(s) com correções de segurança aguardam instalação (%s atualizações no total).".formatted(sec, all);
        b.impact = "Falhas públicas (CVEs) em pacotes como openssh, openssl, sudo e no kernel são exploradas por robôs dias depois de divulgadas. "
                + "Manter o sistema atualizado é a defesa mais barata que existe.";
        b.step("Ver o que será atualizado", null, "apt list --upgradable 2>/dev/null | head -40");
        b.step("Atualizar", null, "sudo apt update && sudo apt upgrade -y");
        b.step("Atualizações automáticas de segurança", "Instala correções de segurança sozinho todo dia.", "sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades");
        b.falsePositive = "Não é um ataque: é postura. Marcar como falso positivo aceita o risco até a contagem mudar.";
    }

    private void reboot(Context c, Builder b) {
        b.summary = "O servidor precisa ser reiniciado para aplicar atualizações já instaladas (normalmente kernel, libc ou systemd).";
        b.impact = "Até reiniciar, o sistema continua rodando as versões antigas, com as falhas que as atualizações corrigem.";
        b.step("Ver quais pacotes pedem reinício", null, "cat /var/run/reboot-required.pkgs");
        b.step("Reiniciar num horário tranquilo", "O agente volta sozinho e reaplica os bloqueios de IP ativos.", "sudo reboot");
        b.falsePositive = "Não é um ataque: é postura.";
    }

    private void sshWeak(Context c, Builder b) {
        Map<String, Object> p = c.host() == null ? null : c.host().getPosture();
        Object ssh = p == null ? null : p.get("ssh");
        b.summary = "A configuração efetiva do SSH (sshd -T) está mais aberta do que o recomendado: " + Objects.toString(c.incident().getDescription(), "") ;
        b.impact = "Com login por senha ligado, cada robô na internet pode tentar adivinhar senhas para sempre. Com chave SSH, força bruta não funciona.";
        if (ssh instanceof Map<?, ?> m) {
            b.fact("PasswordAuthentication", String.valueOf(m.get("passwordAuthentication")));
            b.fact("PermitRootLogin", String.valueOf(m.get("permitRootLogin")));
            b.fact("MaxAuthTries", String.valueOf(m.get("maxAuthTries")));
        }
        b.step("1. Garanta que o login por chave funciona", "Em outra janela, entre com a chave antes de mudar qualquer coisa.", "ssh -i ~/.ssh/id_ed25519 usuario@IP_DA_VPS");
        b.step("2. Procure overrides", "No Ubuntu 24.04 o arquivo 50-cloud-init.conf costuma ligar PasswordAuthentication yes e vence o sshd_config.",
                "grep -ri 'passwordauthentication\\|permitrootlogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/");
        b.step("3. Endureça e recarregue", null,
                "printf 'PasswordAuthentication no\\nPermitRootLogin prohibit-password\\nMaxAuthTries 3\\n' | sudo tee /etc/ssh/sshd_config.d/00-vps-soc.conf && sudo sshd -t && sudo systemctl reload ssh");
        b.falsePositive = "O terminal web do hPanel usa chave temporária, então continua funcionando com login por senha desligado. "
                + "Se você precisa mesmo de senha, marque como falso positivo (risco aceito).";
    }

    // ---------------------------------------------------------------- shared pieces

    private void sshHardeningSteps(Host host, Builder b) {
        Map<String, Object> p = host == null ? null : host.getPosture();
        Object ssh = p == null ? null : p.get("ssh");
        boolean passwordOn = !(ssh instanceof Map<?, ?> m) || !"no".equals(String.valueOf(m.get("passwordAuthentication")));
        if (passwordOn) {
            b.step("Desligar login por senha (resolve a causa)", "Com só chave SSH, força bruta não tem como funcionar. Teste o login com chave antes.",
                    "echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/00-vps-soc.conf && sudo sshd -t && sudo systemctl reload ssh");
        }
    }

    private String sshPasswordNote(Host host) {
        Map<String, Object> p = host == null ? null : host.getPosture();
        if (p != null && p.get("ssh") instanceof Map<?, ?> m) {
            return "no".equals(String.valueOf(m.get("passwordAuthentication")))
                    ? ". Boa notícia: o servidor já recusa login por senha (PasswordAuthentication no), então essas tentativas não têm como funcionar"
                    : ". Hoje o servidor ACEITA login por senha (PasswordAuthentication " + m.get("passwordAuthentication") + ")";
        }
        return "";
    }

    private void commonRisk(Context c, Stats s, Builder b) {
        Incident i = c.incident();
        b.risk("Severidade %s, risco %d/100".formatted(i.getSeverity(), i.getRiskScore()));
        if (c.ip() != null) {
            IpProfile ip = c.ip();
            if ("PUBLIC".equals(ip.kind())) {
                b.risk("Origem na internet pública (" + ip.ip() + ")");
            } else {
                b.risk("Origem em rede interna/confiável: " + ip.kindLabel());
            }
            if (ip.everLoggedIn() && RuleIds.SSH_BRUTE_FORCE.equals(i.getRuleId())) {
                b.risk("Esse IP já fez login com sucesso antes (reduz a chance de ser ataque)");
            }
            if (ip.incidents() > 1) {
                b.risk("Reincidente: %d incidentes com esse IP no histórico".formatted(ip.incidents()));
            }
        }
        if (s.count(EventType.SUDO_COMMAND) > 0 && RuleIds.SSH_COMPROMISE.equals(i.getRuleId())) {
            b.risk("Usou sudo depois do login: provável acesso root");
        }
        if (i.getTechniques().size() > 2) {
            b.risk("%d técnicas MITRE ATT&CK correlacionadas: o ataque avançou por várias etapas".formatted(i.getTechniques().size()));
        }
        if (i.getContainedAt() != null) {
            b.risk("Contido em " + t(i.getContainedAt()) + " (risco atual menor)");
        }
    }

    private String describeResponse(Context c) {
        Incident i = c.incident();
        List<ResponseAction> acts = c.actions();
        List<String> parts = new ArrayList<>();
        for (ResponseAction a : acts) {
            String what = actionLabel(a);
            String when = t(a.getCompletedAt() != null ? a.getCompletedAt() : a.getCreatedAt());
            String who = a.getOrigin() == ResponseAction.Origin.AGENT ? "pelo agente sozinho" : a.getMode() == ResponseAction.Mode.AUTO ? "automaticamente" : "com aprovação manual";
            parts.add(switch (a.getStatus()) {
                case SUCCEEDED -> "%s: %s %s. %s".formatted(when, what, who, Objects.toString(a.getResult(), ""));
                case PROPOSED -> "Aguardando sua aprovação: %s. %s".formatted(what, Objects.toString(a.getReason(), ""));
                case PENDING, SENT -> "Em execução: %s (o agente busca a cada poucos segundos).".formatted(what);
                case FAILED -> "%s: falhou ao %s. %s".formatted(when, what.toLowerCase(Locale.ROOT), Objects.toString(a.getResult(), ""));
                case REJECTED -> "%s: o agente recusou %s por segurança. %s".formatted(when, what.toLowerCase(Locale.ROOT), Objects.toString(a.getResult(), ""));
                case DISMISSED -> "%s: %s descartado por você.".formatted(when, what);
                case EXPIRED -> "%s: %s expirou sem execução.".formatted(when, what);
            });
        }
        if (parts.isEmpty() && i.getContainedAt() != null && i.getContainmentNote() != null) {
            return i.getContainmentNote();
        }
        if (parts.isEmpty()) {
            if (i.getSourceIp() != null && c.ip() != null && c.ip().protectedBy() != null
                    && (RuleIds.SSH_BRUTE_FORCE.equals(i.getRuleId()) || RuleIds.SSH_COMPROMISE.equals(i.getRuleId()))) {
                return "Nenhum bloqueio: %s está numa faixa protegida (%s), que nunca é bloqueada para você não se trancar fora.".formatted(i.getSourceIp(), c.ip().protectedBy());
            }
            if (c.policy() != null && !c.policy().enabled()) {
                return "Resposta ativa desligada (SOC_RESPONSE_ENABLED=false): o SOC só detecta e avisa.";
            }
            return "Nenhuma ação automática para este tipo de incidente. Siga os próximos passos abaixo.";
        }
        if (i.getContainedAt() != null) {
            parts.add(0, "Contido em %s.".formatted(t(i.getContainedAt())));
        }
        return String.join("\n", parts);
    }

    public static String actionLabel(ResponseAction a) {
        return switch (a.getType()) {
            case BLOCK_IP -> "Bloquear IP " + a.getTarget();
            case UNBLOCK_IP -> "Desbloquear IP " + a.getTarget();
            case KILL_PROCESS -> "Encerrar processo " + a.getParams().getOrDefault("exe", a.getTarget());
            case DISK_CLEANUP -> "Limpar disco (journald + cache do apt)";
            case RESTART_SERVICE -> "Reiniciar " + a.getTarget();
        };
    }

    private static List<String> strings(Object v) {
        return v instanceof List<?> l ? l.stream().map(String::valueOf).toList() : List.of();
    }

    private static String shortHash(Object h) {
        String s = Objects.toString(h, "-");
        return s.length() > 12 ? s.substring(0, 12) : s;
    }

    static String t(Instant i) {
        return i == null ? "?" : TIME.format(i);
    }

    private static String isoLocal(Instant i) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZONE).format(i);
    }

    static String human(Duration d) {
        long s = d.toSeconds();
        if (s < 60) return s + " s";
        if (s < 3600) return (s / 60) + " min";
        if (s < 86400) return "%d h %02d min".formatted(s / 3600, (s % 3600) / 60);
        return (s / 86400) + " dia(s)";
    }

    private static String list(List<String> items, int max) {
        if (items.isEmpty()) {
            return "-";
        }
        String shown = items.stream().limit(max).map(u -> u.isEmpty() ? "(vazio)" : u).collect(Collectors.joining(", "));
        return items.size() > max ? shown + " e mais " + (items.size() - max) : shown;
    }

    /** Counts and lookups over the incident's evidence. */
    static final class Stats {
        final List<SecurityEvent> events;
        final Instant first;
        final Instant last;

        Stats(List<SecurityEvent> events) {
            this.events = events;
            this.first = events.stream().map(SecurityEvent::getOccurredAt).min(Comparator.naturalOrder()).orElse(null);
            this.last = events.stream().map(SecurityEvent::getOccurredAt).max(Comparator.naturalOrder()).orElse(null);
        }

        long count(EventType... types) {
            Set<EventType> set = Set.of(types);
            return events.stream().filter(e -> set.contains(e.getType())).count();
        }

        List<SecurityEvent> of(EventType type) {
            return events.stream().filter(e -> e.getType() == type).toList();
        }

        List<SecurityEvent> ofAny(EventType... types) {
            Set<EventType> set = Set.of(types);
            return events.stream().filter(e -> set.contains(e.getType())).toList();
        }

        SecurityEvent latest(EventType... types) {
            Set<EventType> set = Set.of(types);
            SecurityEvent out = null;
            for (SecurityEvent e : events) {
                if (set.contains(e.getType())) {
                    out = e; // events come ordered by time
                }
            }
            return out;
        }

        /** Usernames ordered by attempts. */
        List<String> usernames(EventType... types) {
            Set<EventType> set = Set.of(types);
            Predicate<SecurityEvent> p = e -> set.contains(e.getType()) && e.getUsername() != null;
            return events.stream().filter(p)
                    .collect(Collectors.groupingBy(SecurityEvent::getUsername, LinkedHashMap::new, Collectors.counting()))
                    .entrySet().stream().sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                    .map(Map.Entry::getKey).toList();
        }

        Duration span() {
            return first == null ? Duration.ZERO : Duration.between(first, last);
        }

        double perMinute(long n) {
            double mins = Math.max(span().toSeconds() / 60.0, 1.0);
            return n / mins;
        }
    }

    static final class Builder {
        String summary;
        String impact;
        String response;
        String falsePositive;
        final List<String> risks = new ArrayList<>();
        final List<Fact> facts = new ArrayList<>();
        final List<Step> steps = new ArrayList<>();

        void fact(String label, String value) {
            facts.add(new Fact(label, value));
        }

        void step(String title, String detail, String command) {
            steps.add(new Step(title, detail, command));
        }

        void risk(String r) {
            risks.add(r);
        }

        Explanation build() {
            return new Explanation(summary, impact, risks, facts, response, steps, falsePositive);
        }
    }
}
