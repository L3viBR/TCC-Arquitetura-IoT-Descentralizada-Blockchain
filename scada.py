# Implementação de um Algoritmo de Defesa Cibernética em
# Sistemas SCADA Utilizando IoT Descentralizada

import time
import socket
import threading

from pyModbusTCP.client import ModbusClient

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature
)

from blockchain import (
    registrar_bloco_com_leituras,
    obter_leitura,
    verificar_integridade,
    obter_estado_seguranca,
    registrar_evento_seguranca,
    scada_esta_autorizado,
)

# CONFIGURAÇÕES

ESP32_IP = "192.168.0.24"
MODBUS_PORT = 502
MODBUS_UNIT_ID = 1

INTERVALO_LEITURA = 5
TAMANHO_BLOCO = 5

# IHM

IHM_HOST = "0.0.0.0"
IHM_PORT = 5000

# DETECTORES

LIMITE_FALHAS_COMUNICACAO = 3
LIMITE_FALHAS_ASSINATURA = 1

# ESTADOS DO SMART CONTRACT

ESTADO_NORMAL = 0
ESTADO_ALERTA = 1
ESTADO_BLOQUEADO = 2

NOME_ESTADO = {
    ESTADO_NORMAL: "NORMAL",
    ESTADO_ALERTA: "ALERTA",
    ESTADO_BLOQUEADO: "BLOQUEADO",
}

# TIPOS DE EVENTO

EVENTO_OUTRO = 0
EVENTO_COMUNICACAO = 1
EVENTO_INTEGRIDADE = 2
EVENTO_AUTENTICACAO = 3
EVENTO_AUTORIZACAO = 4
EVENTO_DADO_INVALIDO = 5

NOME_EVENTO = {
    EVENTO_OUTRO: "OUTRO",
    EVENTO_COMUNICACAO: "EVENTO_COMUNICACAO",
    EVENTO_INTEGRIDADE: "EVENTO_INTEGRIDADE",
    EVENTO_AUTENTICACAO: "EVENTO_AUTENTICACAO",
    EVENTO_AUTORIZACAO: "EVENTO_AUTORIZACAO",
    EVENTO_DADO_INVALIDO: "DADO_INVALIDO",
}

# MAPA DOS REGISTRADORES MODBUS

REG_TEMP = 0
REG_UMIDADE = 1
REG_SEQ_HIGH = 2
REG_SEQ_LOW = 3
REG_TIMESTAMP_HIGH = 4
REG_TIMESTAMP_LOW = 5

REG_ASSINATURA_TAMANHO = 6
REG_ASSINATURA_INICIO = 7
REG_ASSINATURA_FIM = 38

REG_CHAVE_PUBLICA_INICIO = 39
REG_CHAVE_PUBLICA_FIM = 71

TOTAL_REGISTRADORES = 72

# CLIENTE MODBUS

cliente_modbus = ModbusClient(
    host=ESP32_IP,
    port=MODBUS_PORT,
    unit_id=MODBUS_UNIT_ID,
    auto_open=True,
    auto_close=False,
    timeout=5,
)

# BUFFER

leituras_pendentes = []
buffer_lock = threading.Lock()

# CLIENTES DA IHM

clientes_ihm = []
clientes_ihm_lock = threading.Lock()

# CONTROLE DOS EVENTOS

falhas_modbus_consecutivas = 0
assinaturas_invalidas_consecutivas = 0

controle_evento_lock = threading.Lock()

# ESTADO DISPONIBILIZADO À IHM

ultima_leitura_valida = {
    "temperatura": None,
    "umidade": None,
    "timestamp": None,
    "sequencia": None,
    "index": None,
    "hash": None,
    "tx_hash": None,
    "integridade": False,
    "assinatura_valida": False,
    "estado_seguranca": ESTADO_NORMAL,
    "nome_estado": "NORMAL",
    "ultimo_ataque": None,
    "nome_ataque": None,
    "descricao_ataque": None,
}

estado_lock = threading.Lock()

# FUNÇÕES AUXILIARES

def uint32_from_regs(high, low):
    return (
        ((int(high) & 0xFFFF) << 16)
        | (int(low) & 0xFFFF)
    )


def regs_to_bytes(regs):
    resultado = bytearray()

    for reg in regs:
        resultado.append((int(reg) >> 8) & 0xFF)
        resultado.append(int(reg) & 0xFF)

    return bytes(resultado)

# ASSINATURA

def extrair_assinatura(regs):
    tamanho = int(
        regs[REG_ASSINATURA_TAMANHO]
    )

    if tamanho <= 0:
        return None

    assinatura_regs = regs[
        REG_ASSINATURA_INICIO:
        REG_ASSINATURA_FIM + 1
    ]

    assinatura = regs_to_bytes(
        assinatura_regs
    )

    return assinatura[:tamanho]

# CHAVE PÚBLICA

def extrair_chave_publica(regs):
    chave_regs = regs[
        REG_CHAVE_PUBLICA_INICIO:
        REG_CHAVE_PUBLICA_FIM + 1
    ]

    chave = regs_to_bytes(
        chave_regs
    )

    return chave[:65]

# VERIFICAÇÃO ECDSA

def verificar_assinatura(
    temperatura_raw,
    umidade_raw,
    sequencia,
    timestamp,
    assinatura_raw,
    chave_publica_raw,
):
    try:
        # Deve ser exatamente o payload assinado pelo ESP32.
        payload = (
            f"{temperatura_raw}|"
            f"{umidade_raw}|"
            f"{sequencia}|"
            f"{timestamp}"
        ).encode()

        if assinatura_raw is None:
            return False

        if len(assinatura_raw) != 64:
            print(
                "Assinatura com tamanho inválido: "
                f"{len(assinatura_raw)} bytes"
            )
            return False

        if len(chave_publica_raw) != 65:
            print(
                "Chave pública com tamanho inválido: "
                f"{len(chave_publica_raw)} bytes"
            )
            return False

        chave_publica = (
            ec.EllipticCurvePublicKey
            .from_encoded_point(
                ec.SECP256R1(),
                chave_publica_raw,
            )
        )

        r = int.from_bytes(
            assinatura_raw[:32],
            byteorder="big",
        )

        s = int.from_bytes(
            assinatura_raw[32:64],
            byteorder="big",
        )

        assinatura_der = encode_dss_signature(
            r,
            s,
        )

        chave_publica.verify(
            assinatura_der,
            payload,
            ec.ECDSA(
                hashes.SHA256()
            ),
        )

        return True

    except Exception:
        return False

# IHM - ENVIO

def enviar_para_ihm(dados):
    mensagem = str(dados) + "\n"
    clientes_remover = []

    with clientes_ihm_lock:
        for cliente in clientes_ihm:
            try:
                cliente.sendall(
                    mensagem.encode()
                )
            except Exception:
                clientes_remover.append(
                    cliente
                )

        for cliente in clientes_remover:
            try:
                cliente.close()
            except Exception:
                pass

            if cliente in clientes_ihm:
                clientes_ihm.remove(
                    cliente
                )

# IHM - SERVIDOR

def servidor_ihm():
    servidor = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    servidor.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    servidor.bind(
        (
            IHM_HOST,
            IHM_PORT,
        )
    )

    servidor.listen(10)

    print(
        f"IHM disponível em "
        f"{IHM_HOST}:{IHM_PORT}"
    )

    while True:
        try:
            cliente, endereco = (
                servidor.accept()
            )

            print(
                f"IHM conectada: "
                f"{endereco}"
            )

            with clientes_ihm_lock:
                clientes_ihm.append(
                    cliente
                )

            with estado_lock:
                estado = dict(
                    ultima_leitura_valida
                )

            try:
                cliente.sendall(
                    (
                        str(estado) + "\n"
                    ).encode()
                )
            except Exception:
                pass

        except Exception as erro:
            print(
                f"Erro no servidor IHM: "
                f"{erro}"
            )
            time.sleep(1)

# ATUALIZA ESTADO DA IHM

def atualizar_estado_ihm(
    temperatura=None,
    umidade=None,
    timestamp=None,
    sequencia=None,
    index=None,
    hash_bloco=None,
    tx_hash=None,
    integridade=None,
    assinatura_valida=None,
    estado_seguranca=None,
    ultimo_ataque=None,
    descricao_ataque=None,
):
    with estado_lock:

        if temperatura is not None:
            ultima_leitura_valida[
                "temperatura"
            ] = temperatura

        if umidade is not None:
            ultima_leitura_valida[
                "umidade"
            ] = umidade

        if timestamp is not None:
            ultima_leitura_valida[
                "timestamp"
            ] = timestamp

        if sequencia is not None:
            ultima_leitura_valida[
                "sequencia"
            ] = sequencia

        if index is not None:
            ultima_leitura_valida[
                "index"
            ] = index

        if hash_bloco is not None:
            ultima_leitura_valida[
                "hash"
            ] = hash_bloco

        if tx_hash is not None:
            ultima_leitura_valida[
                "tx_hash"
            ] = tx_hash

        if integridade is not None:
            ultima_leitura_valida[
                "integridade"
            ] = integridade

        if assinatura_valida is not None:
            ultima_leitura_valida[
                "assinatura_valida"
            ] = assinatura_valida

        if estado_seguranca is not None:
            ultima_leitura_valida[
                "estado_seguranca"
            ] = estado_seguranca

            ultima_leitura_valida[
                "nome_estado"
            ] = NOME_ESTADO.get(
                estado_seguranca,
                "DESCONHECIDO",
            )

        if ultimo_ataque is not None:
            ultima_leitura_valida[
                "ultimo_ataque"
            ] = ultimo_ataque

            ultima_leitura_valida[
                "nome_ataque"
            ] = NOME_EVENTO.get(
                ultimo_ataque,
                "DESCONHECIDO",
            )

        if descricao_ataque is not None:
            ultima_leitura_valida[
                "descricao_ataque"
            ] = descricao_ataque

        dados = dict(
            ultima_leitura_valida
        )

    enviar_para_ihm(dados)

# CONSULTA ESTADO DA BLOCKCHAIN

def consultar_estado_seguranca():
    try:
        estado = int(
            obter_estado_seguranca()
        )

        atualizar_estado_ihm(
            estado_seguranca=estado
        )

        return estado

    except Exception as erro:
        print(
            "Não foi possível consultar "
            f"estado de segurança: {erro}"
        )
        return None

# VERIFICA AUTORIZAÇÃO DO SCADA

def verificar_autorizacao_scada():
    try:
        autorizado = bool(
            scada_esta_autorizado()
        )

        if autorizado:
            print(
                "Identidade SCADA autorizada."
            )
            return True

        print(
            "IDENTIDADE SCADA NÃO AUTORIZADA!"
        )

        return False

    except Exception as erro:
        print(
            "Falha ao verificar "
            f"identidade SCADA: {erro}"
        )

        return False

# REGISTRA EVENTO DE SEGURANÇA

def registrar_evento(
    tipo_ataque,
    descricao="",
):
    print()
    print("EVENTO DE SEGURANÇA")
    print(
        f"   Tipo: "
        f"{NOME_EVENTO.get(tipo_ataque, 'DESCONHECIDO')}"
    )
    print(
        f"   Descrição: {descricao}"
    )

    atualizar_estado_ihm(
        ultimo_ataque=tipo_ataque,
        descricao_ataque=descricao,
    )

    try:
        tx_hash = registrar_evento_seguranca(
            tipo_ataque
        )

        print(
            "Evento registrado na blockchain."
        )

        print(
            f"   TX: {tx_hash}"
        )

        estado = int(
            obter_estado_seguranca()
        )

        atualizar_estado_ihm(
            estado_seguranca=estado
        )

        return tx_hash

    except Exception as erro:
        print(
            "Não foi possível registrar "
            f"evento na blockchain: {erro}"
        )
        return None

# DETECÇÃO DE FALHA DE COMUNICAÇÃO

def detectar_falha_comunicacao():
    global falhas_modbus_consecutivas

    with controle_evento_lock:
        falhas_modbus_consecutivas += 1
        contador = (
            falhas_modbus_consecutivas
        )

    print(
        f"Falha de comunicação "
        f"{contador}/{LIMITE_FALHAS_COMUNICACAO}"
    )

    if contador == LIMITE_FALHAS_COMUNICACAO:
        registrar_evento(
            EVENTO_COMUNICACAO,
            (
                "Múltiplas falhas consecutivas "
                "na comunicação SCADA/ESP32."
            ),
        )

def resetar_contador_comunicacao():
    global falhas_modbus_consecutivas

    with controle_evento_lock:
        falhas_modbus_consecutivas = 0

# DETECÇÃO DE FALHA DE ASSINATURA

def detectar_falha_assinatura():
    global assinaturas_invalidas_consecutivas

    with controle_evento_lock:
        assinaturas_invalidas_consecutivas += 1
        contador = (
            assinaturas_invalidas_consecutivas
        )

    print(
        f"Assinatura inválida "
        f"{contador}/{LIMITE_FALHAS_ASSINATURA}"
    )

    if contador == LIMITE_FALHAS_ASSINATURA:
        registrar_evento(
            EVENTO_INTEGRIDADE,
            (
                "Assinatura ECDSA inválida. "
                "Possível alteração do conteúdo "
                "durante a comunicação."
            ),
        )


def resetar_contador_assinatura():
    global assinaturas_invalidas_consecutivas

    with controle_evento_lock:
        assinaturas_invalidas_consecutivas = 0

# VERIFICAÇÃO DE IDENTIDADE SCADA

def verificar_identidade_scada():
    autorizado = (
        verificar_autorizacao_scada()
    )

    if not autorizado:
        registrar_evento(
            EVENTO_AUTENTICACAO,
            (
                "Identidade utilizada pelo SCADA "
                "não está autorizada no smart contract."
            ),
        )

        return False

    return True

# LEITURA MODBUS

def ler_esp32():
    try:
        regs = (
            cliente_modbus
            .read_holding_registers(
                0,
                TOTAL_REGISTRADORES,
            )
        )

        # Falha de comunicação

        if regs is None:
            detectar_falha_comunicacao()
            return None

        if len(regs) != TOTAL_REGISTRADORES:
            detectar_falha_comunicacao()

            print(
                "Quantidade inesperada "
                f"de registradores: {len(regs)}"
            )

            return None

        # Comunicação normal

        resetar_contador_comunicacao()

        # Temperatura

        temperatura_raw = int(
            regs[REG_TEMP]
        )

        if temperatura_raw & 0x8000:
            temperatura_raw -= 0x10000

        temperatura = (
            temperatura_raw / 100.0
        )

        # Umidade

        umidade_raw = int(
            regs[REG_UMIDADE]
        )

        umidade = (
            umidade_raw / 100.0
        )

        # Sequência

        sequencia = uint32_from_regs(
            regs[REG_SEQ_HIGH],
            regs[REG_SEQ_LOW],
        )

        # Timestamp

        timestamp = uint32_from_regs(
            regs[REG_TIMESTAMP_HIGH],
            regs[REG_TIMESTAMP_LOW],
        )

        # Assinatura

        assinatura = extrair_assinatura(
            regs
        )

        # Chave pública

        chave_publica = extrair_chave_publica(
            regs
        )

        # ECDSA

        assinatura_valida = (
            verificar_assinatura(
                temperatura_raw,
                umidade_raw,
                sequencia,
                timestamp,
                assinatura,
                chave_publica,
            )
        )

        # VERIFICAÇÃO DE ASSINATURA E INTEGRIDADE

        if not assinatura_valida:

            print()
            print(
                "ASSINATURA ECDSA INVÁLIDA"
            )

            print(
                f"   Sequência: {sequencia}"
            )

            detectar_falha_assinatura()

            atualizar_estado_ihm(
                assinatura_valida=False,
                integridade=False,
            )

            return None

        # Assinatura válida

        resetar_contador_assinatura()

        print()
        print(
            "LEITURA VÁLIDA"
        )

        print(
            f"   Temperatura: "
            f"{temperatura:.2f} °C"
        )

        print(
            f"   Umidade: "
            f"{umidade:.2f} %"
        )

        print(
            f"   Sequência: "
            f"{sequencia}"
        )

        print(
            f"   Timestamp: "
            f"{timestamp}"
        )

        print(
            "   ECDSA: válida"
        )

        # Estrutura utilizada pelo blockchain.py

        return {
            "temperatura": temperatura,
            "umidade": umidade,
            "temperatura_raw": temperatura_raw,
            "umidade_raw": umidade_raw,
            "sequencia": sequencia,
            "timestamp": timestamp,
            "assinatura_valida": True,
            "index": 0,
        }

    except Exception as erro:

        print()
        print(
            "Exceção na comunicação "
            f"com ESP32: {erro}"
        )

        detectar_falha_comunicacao()

        return None

# PROCESSAMENTO DO BLOCO

def processar_bloco():

    global leituras_pendentes

    # Copia as cinco leituras sem removê-las.

    with buffer_lock:

        if len(leituras_pendentes) < TAMANHO_BLOCO:
            return

        bloco_leituras = list(
            leituras_pendentes[
                :TAMANHO_BLOCO
            ]
        )

    print()
    print("PROCESSANDO BLOCO")
    print(
        f"   Leituras: {len(bloco_leituras)}"
    )

    # 1. ESTADO DE SEGURANÇA

    estado = consultar_estado_seguranca()

    if estado is None:
        print(
            "Estado de segurança desconhecido."
        )

        print(
            "Bloco não será enviado."
        )

        return

    print(
        f"Estado: "
        f"{NOME_ESTADO.get(estado, 'DESCONHECIDO')}"
    )

    # 2. BLOQUEADO

    if estado == ESTADO_BLOQUEADO:

        print()
        print(
            "SISTEMA BLOQUEADO"
        )

        print(
            "Registro do bloco impedido."
        )

        return

    # 3. VERIFICAÇÃO DE IDENTIDADE

    if not verificar_identidade_scada():

        print()
        print(
            "FALHA DE AUTENTICAÇÃO DETECTADA"
        )

        print(
            "Bloco não será enviado."
        )

        return

    # 4. REGISTRO BLOCKCHAIN

    try:

        resultado = (
            registrar_bloco_com_leituras(
                bloco_leituras
            )
        )

    except Exception as erro:

        print()
        print(
            "Erro no registro blockchain:"
        )

        print(
            f"   {erro}"
        )

        print(
            "As leituras permanecem no buffer."
        )

        return

    if not resultado:

        print(
            "Blockchain não confirmou "
            "o bloco."
        )

        print(
            "As leituras permanecem no buffer."
        )

        return

    # 5. DADOS DO BLOCO

    index = resultado.get(
        "index"
    )

    hash_bloco = resultado.get(
        "hash"
    )

    tx_hash = resultado.get(
        "tx_hash"
    )

    print()
    print(
        "BLOCO REGISTRADO"
    )

    print(
        f"   Índice: {index}"
    )

    print(
        f"   Hash: {hash_bloco}"
    )

    print(
        f"   TX: {tx_hash}"
    )

    # Transacao confirmada: evita reenviar as mesmas leituras.
    with buffer_lock:
        if (
            len(leituras_pendentes) >= TAMANHO_BLOCO
            and leituras_pendentes[:TAMANHO_BLOCO] == bloco_leituras
        ):
            del leituras_pendentes[:TAMANHO_BLOCO]
            print("5 leituras confirmadas removidas do buffer.")
        else:
            print("AVISO: buffer mudou; nenhuma leitura foi removida.")

    # 6. VERIFICA CADA LEITURA

    leituras_validas = True

    print()
    print(
        "Verificando leituras..."
    )

    for posicao, leitura in enumerate(
        bloco_leituras
    ):

        try:

            leitura_bc = obter_leitura(
                index,
                posicao,
            )

            if leitura_bc is None:

                print(
                    f"Leitura {posicao} "
                    "não encontrada."
                )

                leituras_validas = False
                continue

            # Compara os valores RAW.
            # Isso evita erro de comparação entre:
            # 36.72 e 3672

            temperatura_scada = int(
                leitura[
                    "temperatura_raw"
                ]
            )

            umidade_scada = int(
                leitura[
                    "umidade_raw"
                ]
            )

            sequencia_scada = int(
                leitura[
                    "sequencia"
                ]
            )

            timestamp_scada = int(
                leitura[
                    "timestamp"
                ]
            )

            temperatura_bc = int(
                leitura_bc[
                    "temperatura_raw"
                ]
            )

            umidade_bc = int(
                leitura_bc[
                    "umidade_raw"
                ]
            )

            sequencia_bc = int(
                leitura_bc[
                    "sequencia"
                ]
            )

            timestamp_bc = int(
                leitura_bc[
                    "timestamp"
                ]
            )

            # Comparação

            if (
                temperatura_scada
                != temperatura_bc
            ):

                print(
                    f"Temperatura divergente "
                    f"na leitura {posicao}"
                )

                leituras_validas = False

            if (
                umidade_scada
                != umidade_bc
            ):

                print(
                    f"Umidade divergente "
                    f"na leitura {posicao}"
                )

                leituras_validas = False

            if (
                sequencia_scada
                != sequencia_bc
            ):

                print(
                    f"Sequência divergente "
                    f"na leitura {posicao}"
                )

                leituras_validas = False

            if (
                timestamp_scada
                != timestamp_bc
            ):

                print(
                    f"Timestamp divergente "
                    f"na leitura {posicao}"
                )

                leituras_validas = False

            if (
                temperatura_scada == temperatura_bc
                and
                umidade_scada == umidade_bc
                and
                sequencia_scada == sequencia_bc
                and
                timestamp_scada == timestamp_bc
            ):

                print(
                    f"Leitura {posicao} íntegra."
                )

        except Exception as erro:

            print(
                f"Erro verificando "
                f"leitura {posicao}: {erro}"
            )

            leituras_validas = False

    # 7. VERIFICA HASH DO BLOCO

    hash_valido = False

    try:

        hash_valido = bool(
            verificar_integridade(
                index
            )
        )

    except Exception as erro:

        print(
            "Erro verificando "
            f"hash: {erro}"
        )

    # 8. RESULTADO

    if (
        leituras_validas
        and
        hash_valido
    ):

        print()
        print(
            "BLOCO ÍNTEGRO"
        )

        print(
            "5 leituras verificadas."
        )

        print(
            "Hash válido."
        )

        print(
            "Cadeia íntegra."
        )

        atualizar_estado_ihm(
            index=index,
            hash_bloco=hash_bloco,
            tx_hash=tx_hash,
            integridade=True,
            assinatura_valida=True,
        )

    else:

        print()
        print(
            "FALHA DE INTEGRIDADE"
        )

        print(
            f"   Leituras válidas: "
            f"{leituras_validas}"
        )

        print(
            f"   Hash válido: "
            f"{hash_valido}"
        )

        print(
            "Bloco registrado; verificacao posterior falhou."
        )

        atualizar_estado_ihm(
            index=index,
            hash_bloco=hash_bloco,
            tx_hash=tx_hash,
            integridade=False,
        )

        # Não classifica automaticamente a causa da inconsistência.
        # Uma inconsistência pós-registro pode ter outras causas.

        registrar_evento(
            EVENTO_DADO_INVALIDO,
            (
                "Falha na validação de integridade "
                "após registro do bloco."
            ),
        )

# LOOP PRINCIPAL

def main():

    print()
    print(
        "       SCADA - DEFESA CIBERNÉTICA"
    )

    print(
        f"ESP32: {ESP32_IP}:{MODBUS_PORT}"
    )

    print(
        f"IHM: {IHM_HOST}:{IHM_PORT}"
    )

    print(
        f"Bloco: {TAMANHO_BLOCO} leituras"
    )

    print(
        f"Intervalo: {INTERVALO_LEITURA} s"
    )

    #print(
    #    f"Limite de falhas de comunicação: {LIMITE_FALHAS_COMUNICACAO}"
    #)

    # SERVIDOR IHM

    thread_ihm = threading.Thread(
        target=servidor_ihm,
        daemon=True,
    )

    thread_ihm.start()

    # IDENTIDADE SCADA

    print()
    print(
        "Verificando identidade SCADA..."
    )

    if not verificar_autorizacao_scada():

        print()
        print(
            "SCADA NÃO AUTORIZADO"
        )

        print(
            "Encerrando aplicação."
        )

        return

    # ESTADO INICIAL

    estado = consultar_estado_seguranca()

    if estado is not None:

        print()
        print(
            f"Estado inicial: "
            f"{NOME_ESTADO.get(estado)}"
        )

    # LOOP

    while True:

        inicio = time.time()

        try:

            # Estado atual

            estado = (
                consultar_estado_seguranca()
            )

            # Leitura do ESP32

            leitura = ler_esp32()

            if leitura is not None:

                # Atualiza IHM

                atualizar_estado_ihm(

                    temperatura=
                    leitura["temperatura"],

                    umidade=
                    leitura["umidade"],

                    timestamp=
                    leitura["timestamp"],

                    sequencia=
                    leitura["sequencia"],

                    assinatura_valida=True,
                )

                # Não acumula se estiver bloqueado

                if estado != ESTADO_BLOQUEADO:

                    with buffer_lock:

                        # O index é apenas local ao buffer.
                        # Não representa o índice do bloco blockchain.

                        leitura["index"] = len(
                            leituras_pendentes
                        )

                        leituras_pendentes.append(
                            leitura
                        )

                        quantidade = len(
                            leituras_pendentes
                        )

                    print()
                    print(
                        f"Buffer: "
                        f"{quantidade}/"
                        f"{TAMANHO_BLOCO}"
                    )

                    # Bloco completo

                    if quantidade >= TAMANHO_BLOCO:

                        processar_bloco()

            # Mantém o intervalo de 5 segundos

            tempo_execucao = (
                time.time() - inicio
            )

            espera = max(
                0,
                INTERVALO_LEITURA
                - tempo_execucao,
            )

            time.sleep(
                espera
            )

        except KeyboardInterrupt:

            print()
            print(
                "SCADA encerrado."
            )

            break

        except Exception as erro:

            print()
            print(
                "Erro no loop:"
            )

            print(
                f"   {erro}"
            )

            time.sleep(
                INTERVALO_LEITURA
            )

    # ENCERRAMENTO

    try:
        cliente_modbus.close()
    except Exception:
        pass

    with clientes_ihm_lock:

        for cliente in clientes_ihm:

            try:
                cliente.close()
            except Exception:
                pass

        clientes_ihm.clear()

    print(
        "Conexões encerradas."
    )

# EXECUÇÃO

if __name__ == "__main__":
    main()
