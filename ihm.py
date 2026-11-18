# IHM

import ast
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCADA_HOST = "127.0.0.1"
SCADA_PORT = 5000
IHM_HOST = "0.0.0.0"
IHM_PORT = 8000

# Limites de operação e faixa normal
TEMP_MIN_NORMAL, TEMP_MAX_NORMAL = 25.0, 45.0
TEMP_MIN_ALARME, TEMP_MAX_ALARME = 23.0, 47.0
UMID_MIN_NORMAL, UMID_MAX_NORMAL = 40.0, 70.0
UMID_MIN_ALARME, UMID_MAX_ALARME = 35.0, 75.0

lock = threading.RLock()

estado = {
    "temperatura": None,
    "umidade": None,
    "nome_estado": "NORMAL",
    "ligado": False,
    "emergencia": False,
    "emergencia_seguranca": False,
    "bloqueio_seguranca": False,
    "ultima_atualizacao": None,
    "comunicacao_scada": False,
    "alarme_operacional": []
}

def alarmes_operacionais(d):
    a = []
    t = d.get("temperatura")
    h = d.get("umidade")

    if t is not None:
        if t < TEMP_MIN_ALARME:
            a.append("Temperatura abaixo do limite operacional")
        elif t > TEMP_MAX_ALARME:
            a.append("Temperatura acima do limite operacional")
        elif t < TEMP_MIN_NORMAL:
            a.append("Temperatura abaixo da faixa normal")
        elif t > TEMP_MAX_NORMAL:
            a.append("Temperatura acima da faixa normal")

    if h is not None:
        if h < UMID_MIN_ALARME:
            a.append("Umidade abaixo do limite operacional")
        elif h > UMID_MAX_ALARME:
            a.append("Umidade acima do limite operacional")
        elif h < UMID_MIN_NORMAL:
            a.append("Umidade abaixo da faixa normal")
        elif h > UMID_MAX_NORMAL:
            a.append("Umidade acima da faixa normal")

    return a

def receber_scada():
    # A conexão com o SCADA permanece ativa e os dados são recebidos continuamente.
    # ON, OFF e EMERGÊNCIA controlam somente a interface da IHM.
    while True:
        try:
            with socket.create_connection(
                (SCADA_HOST, SCADA_PORT),
                timeout=5
            ) as sock:
                sock.settimeout(1.0)
                buffer = ""

                with lock:
                    estado["comunicacao_scada"] = True

                while True:
                    try:
                        chunk = sock.recv(8192)
                    except socket.timeout:
                        continue

                    if not chunk:
                        raise ConnectionError(
                            "Conexão encerrada pelo SCADA"
                        )

                    buffer += chunk.decode(
                        "utf-8",
                        errors="replace"
                    )

                    while "\n" in buffer:
                        linha, buffer = buffer.split("\n", 1)
                        linha = linha.strip()

                        if not linha:
                            continue

                        try:
                            item = ast.literal_eval(linha)

                            if not isinstance(item, dict):
                                continue

                            nome_estado = item.get(
                                "nome_estado",
                                "NORMAL"
                            )

                            with lock:
                                estado["comunicacao_scada"] = True
                                estado["nome_estado"] = nome_estado

                                if nome_estado == "BLOQUEADO":
                                    # O bloqueio aciona a emergência automaticamente.
                                    # A última leitura e seu horário são preservados.
                                    estado["bloqueio_seguranca"] = True
                                    estado["emergencia_seguranca"] = True
                                    estado["emergencia"] = True
                                    estado["ligado"] = True
                                else:
                                    estado["bloqueio_seguranca"] = False

                                    # Enquanto a emergência automática estiver ativa,
                                    # os valores recebidos não substituem a última leitura.
                                    if not estado["emergencia_seguranca"]:
                                        estado["temperatura"] = item.get(
                                            "temperatura"
                                        )
                                        estado["umidade"] = item.get(
                                            "umidade"
                                        )
                                        estado["ultima_atualizacao"] = time.time()
                                        estado["alarme_operacional"] = (
                                            alarmes_operacionais(estado)
                                        )

                        except (
                            ValueError,
                            SyntaxError,
                            TypeError
                        ):
                            continue

        except Exception:
            with lock:
                estado["comunicacao_scada"] = False

            time.sleep(1)

def snapshot():
    with lock:
        d = dict(estado)
        d["alarme_operacional"] = list(
            estado["alarme_operacional"]
        )

        # Durante o bloqueio a última leitura continua visível.
        if (
            not d["emergencia_seguranca"]
            and (
                not d["ligado"]
                or d["emergencia"]
            )
        ):
            d["temperatura"] = None
            d["umidade"] = None
            d["ultima_atualizacao"] = None

        return d

def set_command(c):
    with lock:
        if c == "on":
            if estado["emergencia"]:
                return (
                    False,
                    "Emergência ativa. Execute o RESET."
                )

            estado["ligado"] = True

            return (
                True,
                "Exibição dos dados habilitada."
            )

        if c == "off":
            if estado["emergencia"]:
                return (
                    False,
                    "OFF bloqueado durante a emergência."
                )

            estado["ligado"] = False

            return (
                True,
                "Exibição dos dados desabilitada."
            )

        if c == "emergency":
            estado["emergencia"] = True
            estado["emergencia_seguranca"] = False
            estado["ligado"] = False

            return (
                True,
                "EMERGÊNCIA acionada. Dados ocultados. ON e OFF bloqueados."
            )

        if c == "reset":
            if not estado["emergencia"]:
                return (
                    False,
                    "Não há emergência ativa."
                )

            if estado["bloqueio_seguranca"]:
                return (
                    False,
                    "RESET bloqueado. Aguarde a liberação do alarme de segurança."
                )

            estado["emergencia"] = False
            estado["emergencia_seguranca"] = False
            estado["ligado"] = False

            return (
                True,
                "RESET concluído. Pressione ON para exibir os dados novamente."
            )

    return (
        False,
        "Comando inválido."
    )

# Conteúdo HTML da interface
HTML = r'''
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IHM - Câmara de Armazenamento</title>
<style>
:root{--bg:#eef1f4;--panel:#fff;--border:#d7dce1;--text:#1d252c;--muted:#68737d;--normal:#16834b;--attention:#c88700;--alarm:#c62828;--dark:#26323b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
.header{background:var(--dark);color:#fff;padding:18px 28px;display:flex;align-items:center;justify-content:space-between;border-bottom:4px solid #46545e}
.header-title{font-size:24px;font-weight:700;letter-spacing:.5px}
.header-subtitle{margin-top:5px;color:#cbd3d9;font-size:13px}
.clock{text-align:right;font-size:14px;color:#e7ebee}
.container{max-width:1450px;margin:20px auto;padding:0 20px 30px}
.status-bar{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.status-title{font-size:14px;color:var(--muted);text-transform:uppercase;font-weight:700}
.process-status{font-size:18px;font-weight:700}
.grid-main{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:22px}
.variable-title{color:var(--muted);text-transform:uppercase;font-size:13px;font-weight:700;letter-spacing:.5px}
.variable-value{font-size:48px;font-weight:700;margin:12px 0 8px}
.variable-unit{font-size:20px;color:var(--muted);font-weight:400}
.range{font-size:13px;color:var(--muted);margin-top:10px}
.badge{display:inline-block;padding:6px 12px;border-radius:5px;font-size:12px;font-weight:700}
.normal{color:var(--normal);background:#e5f4ec}
.attention{color:var(--attention);background:#fff4d6}
.alarm{color:var(--alarm);background:#fde7e7}
.waiting{color:var(--muted);background:#edf0f2}
.section{margin-top:18px}
.section-title{font-size:15px;font-weight:700;text-transform:uppercase;margin-bottom:10px}
.condition-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.condition{border:1px solid var(--border);border-radius:7px;padding:15px;background:#fafbfc}
.condition-label{font-size:12px;color:var(--muted);text-transform:uppercase}
.condition-value{margin-top:7px;font-size:16px;font-weight:700}
.alarm-panel{border:1px solid var(--border);border-radius:8px;background:var(--panel);padding:18px}
.alarm-item{padding:12px 14px;margin-bottom:8px;border-left:5px solid var(--alarm);background:#fff6f6;font-size:14px;font-weight:700}
.no-alarm{color:var(--normal);background:#edf8f2;border-left:5px solid var(--normal);padding:12px 14px;font-weight:700}
.info-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.info{border:1px solid var(--border);border-radius:7px;padding:14px;background:var(--panel)}
.info-label{color:var(--muted);font-size:12px;text-transform:uppercase}
.info-value{margin-top:5px;font-weight:700}
.controls{display:flex;flex-wrap:wrap;gap:12px;background:#fff;border:1px solid var(--border);border-radius:8px;padding:18px}
button{border:0;border-radius:6px;padding:13px 24px;font-size:14px;font-weight:700;cursor:pointer;min-width:125px;color:#fff;box-shadow:0 2px 4px #0002}
button:disabled{opacity:.4;cursor:not-allowed;box-shadow:none}
.btn-on{background:#16834b}
.btn-off{background:#59636b}
.btn-emergency{background:#bd2525;min-width:190px}
.btn-emergency.active{animation:flash .7s steps(2,start) infinite;background:#ff1010;box-shadow:0 0 0 4px #ffc5c5,0 0 22px #ff0000}
.btn-reset{background:#2467a5;min-width:190px;touch-action:none;user-select:none}
@keyframes flash{to{visibility:hidden}}
.control-message{width:100%;font-size:13px;color:var(--muted);padding-top:4px}
.reset-progress{height:7px;background:#e4e8eb;border-radius:5px;overflow:hidden;margin-top:7px;display:none}
.reset-progress>div{height:100%;width:0;background:#2467a5;transition:width .05s linear}
.footer{margin-top:20px;text-align:center;color:var(--muted);font-size:12px}
@media(max-width:900px){
.grid-main,.condition-grid,.info-grid{grid-template-columns:1fr}
.header{flex-direction:column;align-items:flex-start;gap:10px}
.clock{text-align:left}
}
</style>
</head>
<body>
<header class="header">
<div>
<div class="header-title">CÂMARA DE ARMAZENAMENTO</div>
<div class="header-subtitle">SISTEMA DE SUPERVISÃO — PRODUÇÃO 01</div>
</div>
<div class="clock">
<div id="data">--/--/----</div>
<div id="hora">--:--:--</div>
</div>
</header>

<main class="container">

<div class="status-bar">
<div>
<div class="status-title">Condição da câmara</div>
<div id="processStatus" class="process-status">EXIBIÇÃO DESLIGADA</div>
</div>
<div id="processBadge" class="badge waiting">DESLIGADO</div>
</div>

<section class="grid-main">

<div class="card">
<div class="variable-title">Temperatura</div>
<div class="variable-value">
<span id="temperatura">--.--</span>
<span class="variable-unit">°C</span>
</div>
<div id="tempBadge" class="badge waiting">SEM DADO</div>
<div class="range">Faixa normal: 25 °C a 45 °C</div>
</div>

<div class="card">
<div class="variable-title">Umidade relativa</div>
<div class="variable-value">
<span id="umidade">--.--</span>
<span class="variable-unit">%</span>
</div>
<div id="umidBadge" class="badge waiting">SEM DADO</div>
<div class="range">Faixa normal: 40% a 70%</div>
</div>

</section>

<section class="section">
<div class="section-title">Comandos do operador</div>
<div class="controls">

<button id="onBtn" class="btn-on" onclick="comando('on')">ON</button>

<button id="offBtn" class="btn-off" onclick="comando('off')">OFF</button>

<button id="emergencyBtn" class="btn-emergency" onclick="comando('emergency')">EMERGÊNCIA</button>

<button id="resetBtn" class="btn-reset">RESET (SEGURE 3s)</button>

<div class="control-message" id="controlMessage">
Pressione ON para exibir os dados recebidos do SCADA.
</div>

<div class="reset-progress" id="resetProgress">
<div id="resetProgressBar"></div>
</div>

</div>
</section>

<section class="section">
<div class="section-title">Condições operacionais</div>
<div class="condition-grid">

<div class="condition">
<div class="condition-label">Temperatura</div>
<div id="conditionTemp" class="condition-value">--</div>
</div>

<div class="condition">
<div class="condition-label">Umidade</div>
<div id="conditionUmid" class="condition-value">--</div>
</div>

<div class="condition">
<div class="condition-label">Recepção de dados</div>
<div id="conditionComm" class="condition-value">AGUARDANDO SISTEMA</div>
</div>

</div>
</section>

<section class="section">
<div class="section-title">Alarmes</div>
<div class="alarm-panel">
<div id="alarms">
<div class="no-alarm">Nenhum alarme ativo</div>
</div>
</div>
</section>

<section class="section">
<div class="section-title">Informações operacionais</div>
<div class="info-grid">

<div class="info">
<div class="info-label">Última atualização</div>
<div id="ultimaAtualizacao" class="info-value">--</div>
</div>

<div class="info">
<div class="info-label">Estado da interface</div>
<div id="estadoSistema" class="info-value">EXIBIÇÃO DESLIGADA</div>
</div>

</div>
</section>

<div class="footer">
Interface Homem-Máquina — Supervisão da Câmara de Armazenamento
</div>

</main>

<script>
let emergencia = false;
let ligado = false;
let bloqueioSeguranca = false;
let resetInterval = null;
let resetStart = 0;

const $ = id => document.getElementById(id);

function classe(s) {
    return s === "NORMAL"
        ? "normal"
        : s === "ATENÇÃO"
            ? "attention"
            : s === "ALARME"
                ? "alarm"
                : "waiting";
}

function badge(id, s) {
    $(id).textContent = s;
    $(id).className = "badge " + classe(s);
}

function relogio() {
    const d = new Date();
    $("data").textContent = d.toLocaleDateString("pt-BR");
    $("hora").textContent = d.toLocaleTimeString("pt-BR");
}

function render(d) {
    ligado = !!d.ligado;
    emergencia = !!d.emergencia;
    bloqueioSeguranca = !!d.bloqueio_seguranca;

    $("onBtn").disabled = emergencia || ligado;
    $("offBtn").disabled = emergencia || !ligado;
    $("resetBtn").disabled = !emergencia || bloqueioSeguranca;

    $("emergencyBtn").classList.toggle(
        "active",
        emergencia
    );

    $("emergencyBtn").textContent =
        emergencia
            ? "EMERGÊNCIA ATIVA"
            : "EMERGÊNCIA";

    $("processStatus").textContent =
        emergencia
            ? "EMERGÊNCIA ATIVA"
            : ligado
                ? "EXIBIÇÃO DE DADOS ATIVA"
                : "EXIBIÇÃO DESLIGADA";

    badge(
        "processBadge",
        emergencia
            ? "ALARME"
            : ligado
                ? "NORMAL"
                : "DESLIGADO"
    );

    $("estadoSistema").textContent =
        emergencia
            ? "EMERGÊNCIA ATIVA"
            : ligado
                ? "EXIBIÇÃO ATIVA"
                : "EXIBIÇÃO DESLIGADA";

    $("conditionComm").textContent =
        d.comunicacao_scada
            ? "ATIVA"
            : "AGUARDANDO SISTEMA";

    $("conditionComm").className =
        "condition-value " +
        (
            d.comunicacao_scada
                ? "normal"
                : "waiting"
        );

    const t =
        d.temperatura == null
            ? null
            : Number(d.temperatura);

    const h =
        d.umidade == null
            ? null
            : Number(d.umidade);

    $("temperatura").textContent =
        t == null
            ? "--.--"
            : t.toFixed(2).replace(".", ",");

    $("umidade").textContent =
        h == null
            ? "--.--"
            : h.toFixed(2).replace(".", ",");

    const st =
        t == null
            ? "SEM DADO"
            : (
                t < 23 || t > 47
                    ? "ALARME"
                    : (
                        t < 25 || t > 45
                            ? "ATENÇÃO"
                            : "NORMAL"
                    )
            );

    const sh =
        h == null
            ? "SEM DADO"
            : (
                h < 35 || h > 75
                    ? "ALARME"
                    : (
                        h < 40 || h > 70
                            ? "ATENÇÃO"
                            : "NORMAL"
                    )
            );

    badge("tempBadge", st);
    badge("umidBadge", sh);

    $("conditionTemp").textContent = st;
    $("conditionTemp").className =
        "condition-value " + classe(st);

    $("conditionUmid").textContent = sh;
    $("conditionUmid").className =
        "condition-value " + classe(sh);

    $("ultimaAtualizacao").textContent =
        d.ultima_atualizacao
            ? new Date(
                d.ultima_atualizacao * 1000
            ).toLocaleTimeString("pt-BR")
            : "--";

    const alarms = [];

    if (d.nome_estado === "BLOQUEADO") {
        alarms.push(
            "Sistema de segurança bloqueado — intervenção do ADMINISTRADOR necessária - SISTEMA OFFLINE"
        );
    } else if (
        emergencia &&
        !d.emergencia_seguranca
    ) {
        alarms.push(
            "Parada de emergência acionada pelo operador"
        );
    }

    if (ligado && t !== null) {
        if (t < 23) {
            alarms.push(
                "Temperatura abaixo do limite operacional"
            );
        } else if (t > 47) {
            alarms.push(
                "Temperatura acima do limite operacional"
            );
        } else if (t < 25) {
            alarms.push(
                "Temperatura abaixo da faixa normal"
            );
        } else if (t > 45) {
            alarms.push(
                "Temperatura acima da faixa normal"
            );
        }
    }

    if (ligado && h !== null) {
        if (h < 35) {
            alarms.push(
                "Umidade abaixo do limite operacional"
            );
        } else if (h > 75) {
            alarms.push(
                "Umidade acima do limite operacional"
            );
        } else if (h < 40) {
            alarms.push(
                "Umidade abaixo da faixa normal"
            );
        } else if (h > 70) {
            alarms.push(
                "Umidade acima da faixa normal"
            );
        }
    }

    if (
        ligado &&
        d.nome_estado === "ALERTA"
    ) {
        alarms.push(
            "Alerta de segurança do sistema — verifique as condições operacionais"
        );
    }

    $("alarms").innerHTML =
        alarms.length
            ? alarms
                .map(
                    x =>
                        '<div class="alarm-item">⚠ ' +
                        x +
                        '</div>'
                )
                .join("")
            : '<div class="no-alarm">Nenhum alarme ativo</div>';

    if (bloqueioSeguranca) {
        $("controlMessage").textContent =
            "Bloqueio ativo. A leitura foi congelada; aguarde a liberação do alarme para executar RESET.";
    }
}

async function refresh() {
    try {
        const r = await fetch(
            "/api/estado",
            {
                cache: "no-store"
            }
        );

        render(await r.json());

    } catch (e) {
        $("conditionComm").textContent =
            "SEM COMUNICAÇÃO";
    }
}

async function comando(c) {
    try {
        const r = await fetch(
            "/api/comando",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    comando: c
                })
            }
        );

        const d = await r.json();

        $("controlMessage").textContent =
            d.mensagem;

        await refresh();

    } catch (e) {
        $("controlMessage").textContent =
            "Não foi possível executar o comando.";
    }
}

function resetStartHold(ev) {
    ev.preventDefault();

    if (
        !emergencia ||
        bloqueioSeguranca
    ) {
        return;
    }

    resetStart = Date.now();

    $("resetProgress").style.display =
        "block";

    $("resetProgressBar").style.width =
        "0%";

    resetInterval = setInterval(
        () => {
            const p =
                Math.min(
                    100,
                    (
                        Date.now() -
                        resetStart
                    ) /
                    3000 *
                    100
                );

            $("resetProgressBar").style.width =
                p + "%";

            const restante =
                Math.max(
                    0,
                    3 -
                    (
                        Date.now() -
                        resetStart
                    ) /
                    1000
                );

            $("controlMessage").textContent =
                "Mantenha RESET pressionado: " +
                restante.toFixed(1) +
                " s";

            if (p >= 100) {
                clearInterval(
                    resetInterval
                );

                resetInterval = null;

                $("resetProgress").style.display =
                    "none";

                comando("reset");
            }
        },
        40
    );
}

function resetEnd() {
    if (resetInterval) {
        clearInterval(resetInterval);

        resetInterval = null;

        $("resetProgress").style.display =
            "none";

        $("controlMessage").textContent =
            "RESET cancelado. Mantenha pressionado por 3 segundos.";
    }
}

$("resetBtn").addEventListener(
    "pointerdown",
    resetStartHold
);

$("resetBtn").addEventListener(
    "pointerup",
    resetEnd
);

$("resetBtn").addEventListener(
    "pointerleave",
    resetEnd
);

$("resetBtn").addEventListener(
    "pointercancel",
    resetEnd
);

setInterval(
    relogio,
    1000
);

setInterval(
    refresh,
    500
);

relogio();
refresh();
</script>
</body>
</html>
'''

# Manipulação das requisições HTTP
class Handler(BaseHTTPRequestHandler):

    def send(self, code, payload, ctype):
        b = payload.encode("utf-8")

        self.send_response(code)
        self.send_header(
            "Content-Type",
            ctype
        )
        self.send_header(
            "Content-Length",
            str(len(b))
        )
        self.send_header(
            "Cache-Control",
            "no-store"
        )
        self.end_headers()

        self.wfile.write(b)

    def do_GET(self):

        if self.path == "/":
            self.send(
                200,
                HTML,
                "text/html; charset=utf-8"
            )

        elif self.path == "/api/estado":
            self.send(
                200,
                json.dumps(
                    snapshot(),
                    ensure_ascii=False
                ),
                "application/json; charset=utf-8"
            )

        else:
            self.send(
                404,
                "Not found",
                "text/plain; charset=utf-8"
            )

    def do_POST(self):

        if self.path != "/api/comando":
            return self.send(
                404,
                "Not found",
                "text/plain; charset=utf-8"
            )

        try:
            n = int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )

            body = json.loads(
                self.rfile.read(n).decode(
                    "utf-8"
                )
            )

            ok, msg = set_command(
                body.get(
                    "comando",
                    ""
                )
            )

            self.send(
                200 if ok else 409,
                json.dumps(
                    {
                        "ok": ok,
                        "mensagem": msg
                    },
                    ensure_ascii=False
                ),
                "application/json; charset=utf-8"
            )

        except Exception:
            self.send(
                400,
                json.dumps(
                    {
                        "ok": False,
                        "mensagem":
                            "Requisição inválida."
                    }
                ),
                "application/json; charset=utf-8"
            )

    def log_message(self, *args):
        pass

def main():
    threading.Thread(
        target=receber_scada,
        daemon=True
    ).start()

    server = ThreadingHTTPServer(
        (IHM_HOST, IHM_PORT),
        Handler
    )

    print(
        f"IHM disponível em http://127.0.0.1:{IHM_PORT}"
    )

    print(
        f"Recepção contínua do SCADA: "
        f"{SCADA_HOST}:{SCADA_PORT}"
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print(
            "\nIHM encerrada."
        )

    finally:
        server.server_close()

if __name__ == "__main__":
    main()