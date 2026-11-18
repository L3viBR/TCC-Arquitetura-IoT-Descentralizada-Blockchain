# Implementação de um Algoritmo de Defesa Cibernética em Sistemas SCADA Utilizando IoT Descentralizada

from web3 import Web3
from eth_abi import encode
from hashlib import sha256
import os
import time

# CONFIGURAÇÕES

RPC_URL = "http://127.0.0.1:8545"

# Arquivo local de controle de transacoes com confirmacao pendente.
from pathlib import Path
ARQUIVO_TRANSACAO_PENDENTE = Path(__file__).resolve().parent / "transacao_pendente_scada.json"

CHAIN_ID = 1337

# Insira um contrato
CONTRACT_ADDRESS = Web3.to_checksum_address(
    "0x00000000000000000000000000000000000000000"
)

# Insira a conta Ethereum utilizada pelo SCADA
SCADA_ACCOUNT = Web3.to_checksum_address(
    "0x0000000000000000000000000000000000000000"
)

# CHAVE PRIVADA

#SCADA_PRIVATE_KEY = os.getenv("SCADA_PRIVATE_KEY", "")
def carregar_chave_scada():
    import json
    from pathlib import Path

# Defina o caminho correto para o arquivo JSON da conta SCADA
    caminho = Path(
        "//wsl.localhost/Ubuntu/home/l3vi/TCC-Besu/"
        "besu-test-network/smart_contracts/contas_tcc/scada.json"
    )

    with caminho.open("r", encoding="utf-8") as arquivo:
        conta = json.load(arquivo)

    if conta["address"].lower() != SCADA_ACCOUNT.lower():
        raise ValueError("Endereco da conta SCADA nao corresponde ao autorizado.")

    from eth_account import Account
    endereco_derivado = Account.from_key(conta["privateKey"]).address

    if endereco_derivado.lower() != SCADA_ACCOUNT.lower():
        raise ValueError("Chave privada nao corresponde a conta SCADA.")

    return conta["privateKey"]

SCADA_PRIVATE_KEY = carregar_chave_scada()
# CONFIGURAÇÃO DO PoW
# Na prática, aproximadamente quatro zeros hexadecimais
# no início do hash.

POW_TARGET = 2 ** 240

# Tamanho dos blocos definidos no Smart Contract
TAMANHO_BLOCO = 5

# ABI DO SMART CONTRACT

ABI = [

    # Construtor / estado

    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },

    # quantidadeBlocos

    {
        "inputs": [],
        "name": "quantidadeBlocos",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # quantidadeLeituras

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_bloco",
                "type": "uint256"
            }
        ],
        "name": "quantidadeLeituras",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # administrador

    {
        "inputs": [],
        "name": "administrador",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # scadasAutorizados

    {
        "inputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "name": "scadasAutorizados",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # obterEstadoSeguranca

    {
        "inputs": [],
        "name": "obterEstadoSeguranca",
        "outputs": [
            {
                "internalType": "enum SCADACyberDefense.EstadoSeguranca",
                "name": "",
                "type": "uint8"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # quantidadeEventosSeguranca

    {
        "inputs": [],
        "name": "quantidadeEventosSeguranca",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # registrarEventoSeguranca

    {
        "inputs": [
            {
                "internalType": "enum SCADACyberDefense.CategoriaEvento",
                "name": "_categoria",
                "type": "uint8"
            }
        ],
        "name": "registrarEventoSeguranca",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },

    # obterEventoSeguranca

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_indice",
                "type": "uint256"
            }
        ],
        "name": "obterEventoSeguranca",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            },
            {
                "internalType": "enum SCADACyberDefense.CategoriaEvento",
                "name": "categoria",
                "type": "uint8"
            },
            {
                "internalType": "address",
                "name": "origem",
                "type": "address"
            },
            {
                "internalType": "enum SCADACyberDefense.EstadoSeguranca",
                "name": "estadoGerado",
                "type": "uint8"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # resetarSeguranca

    {
        "inputs": [],
        "name": "resetarSeguranca",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },

    # calcularDadosHash

    {
        "inputs": [
            {
                "components": [
                    {
                        "internalType": "uint256",
                        "name": "temperatura",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "umidade",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "sequencia",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "timestamp",
                        "type": "uint256"
                    }
                ],
                "internalType": "struct SCADACyberDefense.Leitura[]",
                "name": "_leituras",
                "type": "tuple[]"
            }
        ],
        "name": "calcularDadosHash",
        "outputs": [
            {
                "internalType": "bytes32",
                "name": "",
                "type": "bytes32"
            }
        ],
        "stateMutability": "pure",
        "type": "function"
    },

    # calcularHashBloco

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_index",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "_timestamp",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "_previousHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "_nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "_dadosHash",
                "type": "bytes32"
            }
        ],
        "name": "calcularHashBloco",
        "outputs": [
            {
                "internalType": "bytes32",
                "name": "",
                "type": "bytes32"
            }
        ],
        "stateMutability": "pure",
        "type": "function"
    },

    # adicionarBlocoCompleto
    # O contrato atual possui 6 argumentos.
    # Não enviar dadosHash como argumento.
    # O contrato calcula dadosHash internamente.

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_index",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "_timestamp",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "_previousHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "_nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "_hash",
                "type": "bytes32"
            },
            {
                "components": [
                    {
                        "internalType": "uint256",
                        "name": "temperatura",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "umidade",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "sequencia",
                        "type": "uint256"
                    },
                    {
                        "internalType": "uint256",
                        "name": "timestamp",
                        "type": "uint256"
                    }
                ],
                "internalType": "struct SCADACyberDefense.Leitura[]",
                "name": "_leituras",
                "type": "tuple[]"
            }
        ],
        "name": "adicionarBlocoCompleto",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },

    # obterUltimoBloco

    {
        "inputs": [],
        "name": "obterUltimoBloco",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "index",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "previousHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "hash",
                "type": "bytes32"
            },
            {
                "internalType": "bytes32",
                "name": "dadosHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "totalLeituras",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # obterBloco

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_index",
                "type": "uint256"
            }
        ],
        "name": "obterBloco",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "index",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "previousHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "hash",
                "type": "bytes32"
            },
            {
                "internalType": "bytes32",
                "name": "dadosHash",
                "type": "bytes32"
            },
            {
                "internalType": "uint256",
                "name": "totalLeituras",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # obterLeitura

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_bloco",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "_posicao",
                "type": "uint256"
            }
        ],
        "name": "obterLeitura",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "temperatura",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "umidade",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "sequencia",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # verificarHash

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_index",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "_hash",
                "type": "bytes32"
            }
        ],
        "name": "verificarHash",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # verificarBloco

    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_index",
                "type": "uint256"
            }
        ],
        "name": "verificarBloco",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },

    # verificarCadeia

    {
        "inputs": [],
        "name": "verificarCadeia",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# CONEXÃO

w3 = Web3(Web3.HTTPProvider(RPC_URL))

contract = w3.eth.contract(
    address=CONTRACT_ADDRESS,
    abi=ABI
)

# FUNÇÕES AUXILIARES

def bytes32_para_hex(valor):
    """
    Converte bytes32 retornado pelo Web3 para string hexadecimal.
    """
    if isinstance(valor, bytes):
        return "0x" + valor.hex()

    if isinstance(valor, str):
        return valor

    return Web3.to_hex(valor)

def hex_para_bytes32(valor):
    """
    Converte string hexadecimal para bytes32.
    """
    if isinstance(valor, bytes):
        return valor

    if isinstance(valor, str):
        return Web3.to_bytes(hexstr=valor)

    return Web3.to_bytes(hexstr=Web3.to_hex(valor))

def normalizar_leitura(leitura):
    """
    Converte uma leitura do SCADA para o formato:

    (
        temperatura,
        umidade,
        sequencia,
        timestamp
    )

    O SCADA atual trabalha com dicionários.
    Aceita tuplas/listas para facilitar testes.
    """

    # Caso seja dicionário

    if isinstance(leitura, dict):

        # Prefira os valores RAW, pois são exatamente os
        # valores utilizados na assinatura e armazenados
        # na blockchain.

        if "temperatura_raw" in leitura:
            temperatura = int(leitura["temperatura_raw"])
        else:
            temperatura = int(leitura["temperatura"])

        if "umidade_raw" in leitura:
            umidade = int(leitura["umidade_raw"])
        else:
            umidade = int(leitura["umidade"])

        sequencia = int(leitura["sequencia"])
        timestamp = int(leitura["timestamp"])

    # Caso seja tupla/lista

    elif isinstance(leitura, (tuple, list)):

        if len(leitura) < 4:
            raise ValueError(
                "Leitura deve possuir pelo menos 4 campos."
            )

        temperatura = int(leitura[0])
        umidade = int(leitura[1])
        sequencia = int(leitura[2])
        timestamp = int(leitura[3])

    else:

        raise TypeError(
            "Formato de leitura não suportado. "
            "Use dict, tuple ou list."
        )

    # O Solidity utiliza uint256.
    # Portanto, não podemos enviar números negativos.

    if temperatura < 0:
        raise ValueError(
            f"Temperatura inválida para uint256: {temperatura}"
        )

    if umidade < 0:
        raise ValueError(
            f"Umidade inválida para uint256: {umidade}"
        )

    if sequencia < 0:
        raise ValueError(
            f"Sequência inválida: {sequencia}"
        )

    if timestamp < 0:
        raise ValueError(
            f"Timestamp inválido: {timestamp}"
        )

    return (
        temperatura,
        umidade,
        sequencia,
        timestamp
    )


def normalizar_leituras(leituras):
    """
    Normaliza uma lista completa de leituras.
    """

    return [
        normalizar_leitura(leitura)
        for leitura in leituras
    ]

# HASH DOS DADOS

def calcular_dados_hash(leituras):
    """
    Reproduz exatamente:

        sha256(abi.encode(_leituras))

    do Smart Contract.

    Solidity:

        sha256(abi.encode(_leituras))
    """

    leituras_normalizadas = normalizar_leituras(leituras)

    dados_codificados = encode(
        ["(uint256,uint256,uint256,uint256)[]"],
        [leituras_normalizadas]
    )

    return sha256(dados_codificados).digest()

# HASH DO BLOCO

def calcular_hash_bloco(
    index,
    timestamp,
    previous_hash,
    nonce,
    dados_hash
):
    """
    Reproduz exatamente:

        sha256(
            abi.encode(
                index,
                timestamp,
                previousHash,
                nonce,
                dadosHash
            )
        )

    do Smart Contract.
    """

    previous_hash = hex_para_bytes32(previous_hash)
    dados_hash = hex_para_bytes32(dados_hash)

    dados_codificados = encode(
        [
            "uint256",
            "uint256",
            "bytes32",
            "uint256",
            "bytes32"
        ],
        [
            int(index),
            int(timestamp),
            previous_hash,
            int(nonce),
            dados_hash
        ]
    )

    return sha256(dados_codificados).digest()

# MINERAÇÃO

def minerar_bloco(
    index,
    timestamp,
    previous_hash,
    leituras
):
    """
    Executa o Proof of Work do bloco.

    O nonce é incrementado até encontrar:

        hash < 2**240

    equivalente ao alvo utilizado no contrato.
    """

    leituras_normalizadas = normalizar_leituras(leituras)

    dados_hash = calcular_dados_hash(
        leituras_normalizadas
    )

    previous_hash = hex_para_bytes32(previous_hash)

    print()
    print("MINERAÇÃO DO BLOCO")
    print(
        "dadosHash:",
        bytes32_para_hex(dados_hash)
    )

    inicio = time.time()

    nonce = 0

    while True:

        hash_bloco = calcular_hash_bloco(
            index=index,
            timestamp=timestamp,
            previous_hash=previous_hash,
            nonce=nonce,
            dados_hash=dados_hash
        )

        valor_hash = int.from_bytes(
            hash_bloco,
            byteorder="big"
        )

        if valor_hash < POW_TARGET:
            break

        nonce += 1

    fim = time.time()

    print(
        "nonce:",
        nonce
    )

    print(
        "hash:",
        bytes32_para_hex(hash_bloco)
    )

    print(
        "tempo de mineração:",
        f"{fim - inicio:.4f} s"
    )

    return {
        "index": int(index),
        "timestamp": int(timestamp),
        "previousHash": previous_hash,
        "nonce": int(nonce),
        "hash": hash_bloco,
        "dadosHash": dados_hash,
        "leituras": leituras_normalizadas
    }

# ENVIO DE TRANSAÇÃO

def enviar_transacao(funcao):

    """
    Envia uma função do Smart Contract como transação.

    Antes de assinar, executa CALL para descobrir
    possíveis revert do contrato.
    """

    if (
        not SCADA_PRIVATE_KEY
        or SCADA_PRIVATE_KEY
        == "COLOQUE_AQUI_A_CHAVE_PRIVADA_DA_CONTA_SCADA"
    ):
        raise RuntimeError(
            "A chave privada da conta SCADA ainda não foi "
            "configurada em SCADA_PRIVATE_KEY."
        )

    # Verificação da conexão

    if not w3.is_connected():
        raise ConnectionError(
            "Não foi possível conectar ao Hyperledger Besu."
        )

    # CALL

    print()
    print("CALL...")

    try:

        funcao.call({
            "from": SCADA_ACCOUNT
        })

        print("CALL ACEITA PELO CONTRATO")

    except Exception as erro:

        print("CALL REJEITADA PELO CONTRATO")
        print("Motivo:", erro)

        raise

    # Nonce

    nonce = w3.eth.get_transaction_count(
        SCADA_ACCOUNT,
        "pending"
    )

    # Estimativa de gás

    try:

        gas_estimado = funcao.estimate_gas({
            "from": SCADA_ACCOUNT
        })

        gas = int(gas_estimado * 1.20)

    except Exception as erro:

        print(
            "Falha ao estimar gás:",
            erro
        )

        gas = 500000

    # Gas price

    gas_price = w3.eth.gas_price

    # Construção da transação

    transacao = funcao.build_transaction({

        "from": SCADA_ACCOUNT,

        "nonce": nonce,

        "chainId": CHAIN_ID,

        "gas": gas,

        "gasPrice": gas_price
    })

    # Assinatura

    signed = w3.eth.account.sign_transaction(
        transacao,
        private_key=SCADA_PRIVATE_KEY
    )

    if ARQUIVO_TRANSACAO_PENDENTE.exists():
        raise RuntimeError(
            "Transacao pendente: consulte o Besu antes de reenviar."
        )

    # Envio

    # Calcula o hash antes de transmitir ao Besu.
    tx_hash_esperado = Web3.keccak(signed.raw_transaction)

    # Registra a transacao antes da transmissao.
    import json
    import os
    pendencia = {
        "tx_hash": tx_hash_esperado.hex(),
        "nonce": transacao["nonce"],
        "estado": "confirmacao_pendente"
    }
    temporario = ARQUIVO_TRANSACAO_PENDENTE.with_suffix(".json.tmp")
    with temporario.open("x", encoding="utf-8") as arquivo:
        json.dump(pendencia, arquivo, indent=2)
        arquivo.flush()
        os.fsync(arquivo.fileno())
    os.replace(temporario, ARQUIVO_TRANSACAO_PENDENTE)

    tx_hash = w3.eth.send_raw_transaction(
        signed.raw_transaction
    )

    if tx_hash != tx_hash_esperado:
        raise RuntimeError(
            "Hash retornado difere da transacao assinada."
        )

    print()
    print(
        "Transação enviada:"
    )

    print(
        "TX:",
        tx_hash.hex()
    )

    # Aguarda mineração

    receipt = w3.eth.wait_for_transaction_receipt(
        tx_hash
    )

    print(
        "Bloco Ethereum:",
        receipt.blockNumber
    )

    print(
        "Status:",
        receipt.status
    )

    if receipt.status != 1:

        raise RuntimeError(
            "A transação foi minerada, mas falhou."
        )

    # Confirmacao bem-sucedida: libera o proximo envio.
    ARQUIVO_TRANSACAO_PENDENTE.unlink()

    return tx_hash.hex()

# REGISTRAR BLOCO

def registrar_bloco(bloco):

    """
    Registra um bloco já minerado na blockchain.
    O contrato atual possui:
        adicionarBlocoCompleto(
            index,
            timestamp,
            previousHash,
            nonce,
            hash,
            leituras
        )

    6 argumentos.
    """

    leituras = normalizar_leituras(
        bloco["leituras"]
    )

    index = int(bloco["index"])

    timestamp = int(bloco["timestamp"])

    previous_hash = hex_para_bytes32(
        bloco["previousHash"]
    )

    nonce = int(bloco["nonce"])

    hash_bloco = hex_para_bytes32(
        bloco["hash"]
    )

    # Confere novamente o hash localmente

    dados_hash = calcular_dados_hash(
        leituras
    )

    hash_calculado = calcular_hash_bloco(
        index=index,
        timestamp=timestamp,
        previous_hash=previous_hash,
        nonce=nonce,
        dados_hash=dados_hash
    )

    if hash_calculado != hash_bloco:

        raise ValueError(
            "Hash do bloco não corresponde aos dados."
        )

    # Confere Proof of Work

    valor_hash = int.from_bytes(
        hash_bloco,
        byteorder="big"
    )

    if valor_hash >= POW_TARGET:

        raise ValueError(
            "Bloco não satisfaz o Proof of Work."
        )

    # Função do contrato

    funcao = contract.functions.adicionarBlocoCompleto(

        index,

        timestamp,

        previous_hash,

        nonce,

        hash_bloco,

        leituras
    )

    # Envia

    tx_hash = enviar_transacao(
        funcao
    )

    return {
        "sucesso": True,
        "tx_hash": tx_hash,
        "index": index,
        "hash": bytes32_para_hex(hash_bloco),
        "dadosHash": bytes32_para_hex(dados_hash),
        "nonce": nonce
    }

# REGISTRAR BLOCO COM LEITURAS

def registrar_bloco_com_leituras(leituras):

    """
    Função principal utilizada pelo SCADA.

    Recebe diretamente as leituras coletadas pelo SCADA:

        [
            {
                "temperatura": ...,
                "umidade": ...,
                "temperatura_raw": ...,
                "umidade_raw": ...,
                "sequencia": ...,
                "timestamp": ...
            },
            ...
        ]

    """

    if not w3.is_connected():

        raise ConnectionError(
            "Hyperledger Besu não está conectado."
        )

    # Normalização

    leituras_normalizadas = normalizar_leituras(
        leituras
    )

    # Verifica quantidade

    if len(leituras_normalizadas) != TAMANHO_BLOCO:

        raise ValueError(
            f"O bloco deve possuir exatamente "
            f"{TAMANHO_BLOCO} leituras. "
            f"Recebido: {len(leituras_normalizadas)}"
        )

    # Verifica estado de segurança

    estado = obter_estado_seguranca()

    if estado == 2:

        raise RuntimeError(
            "Blockchain está em estado BLOQUEADO. "
            "Registro de bloco impedido."
        )

    # Verifica se a conta SCADA está autorizada

    if not scada_esta_autorizado():

        raise PermissionError(
            "A conta do SCADA não está autorizada "
            "no Smart Contract."
        )

    # Obtém último bloco

    ultimo = contract.functions.obterUltimoBloco().call()

    ultimo_index = int(ultimo[0])

    ultimo_hash = ultimo[4]

    # O próximo bloco terá índice:
    # último índice + 1

    index = ultimo_index + 1

    # Timestamp do novo bloco

    timestamp = int(time.time())

    # Mineração

    bloco = minerar_bloco(

        index=index,

        timestamp=timestamp,

        previous_hash=ultimo_hash,

        leituras=leituras_normalizadas
    )

    print()
    print("Bloco minerado:")

    print(
        "index:",
        bloco["index"]
    )

    print(
        "timestamp:",
        bloco["timestamp"]
    )

    print(
        "previousHash:",
        bytes32_para_hex(
            bloco["previousHash"]
        )
    )

    print(
        "nonce:",
        bloco["nonce"]
    )

    print(
        "hash:",
        bytes32_para_hex(
            bloco["hash"]
        )
    )

    print(
        "dadosHash:",
        bytes32_para_hex(
            bloco["dadosHash"]
        )
    )

    # Registro na blockchain

    resultado = registrar_bloco(
        bloco
    )

    print()
    print("BLOCO REGISTRADO NA BLOCKCHAIN")

    print(
        "TX:",
        resultado["tx_hash"]
    )

    return resultado

# ESTADO DE SEGURANÇA

def obter_estado_seguranca():

    """
    Retorna:
        0 = NORMAL
        1 = ALERTA
        2 = BLOQUEADO
    """

    estado = contract.functions.obterEstadoSeguranca().call()

    return int(estado)

def nome_estado_seguranca(estado):

    estados = {
        0: "NORMAL",
        1: "ALERTA",
        2: "BLOQUEADO"
    }

    return estados.get(
        int(estado),
        "DESCONHECIDO"
    )

# VERIFICAR AUTORIZAÇÃO DO SCADA

def scada_esta_autorizado():

    autorizado = contract.functions.scadasAutorizados(
        SCADA_ACCOUNT
    ).call()

    return bool(autorizado)

# REGISTRAR EVENTO DE SEGURANÇA

def registrar_evento_seguranca(tipo_ataque):

    """
    Converte o identificador de ocorrência usado pelo SCADA
    para a categoria genérica armazenada no contrato.

    0 = CONSISTENCIA
    1 = COMUNICACAO
    2 = INTEGRIDADE
    3 = AUTENTICACAO
    4 = AUTORIZACAO
    5 = INCONSISTENCIA

    O detalhe da ocorrência continua sendo apresentado no
    terminal e na IHM. Na blockchain é registrada a categoria.
    """

    categorias = {
        0: 4,
        1: 3,
        2: 0,
        3: 1,
        4: 2,
        5: 4
    }

    tipo_ataque = int(tipo_ataque)

    if tipo_ataque not in categorias:

        raise ValueError(
            "Identificador de ocorrência inválido."
        )

    if not scada_esta_autorizado():

        raise PermissionError(
            "SCADA não autorizado para registrar "
            "evento de segurança."
        )

    categoria = categorias[tipo_ataque]

    funcao = contract.functions.registrarEventoSeguranca(
        categoria
    )

    return enviar_transacao(
        funcao
    )

# RESETAR SEGURANÇA

def resetar_seguranca():

    """
    Reseta o estado para NORMAL.
    Esta função só funciona se a conta SCADA
    também for o administrador do contrato.
    Caso contrário, o contrato fará revert.
    """

    funcao = contract.functions.resetarSeguranca()

    return enviar_transacao(
        funcao
    )

# CONSULTAR LEITURA

def obter_leitura(
    bloco_index,
    posicao
):

    """
    Obtém uma leitura diretamente da blockchain.
    """

    leitura = contract.functions.obterLeitura(
        int(bloco_index),
        int(posicao)
    ).call()

    return {
        "temperatura_raw": int(leitura[0]),
        "umidade_raw": int(leitura[1]),
        "sequencia": int(leitura[2]),
        "timestamp": int(leitura[3]),

        "temperatura": int(leitura[0]) / 100.0,
        "umidade": int(leitura[1]) / 100.0
    }

# CONSULTAR BLOCO

def obter_bloco(index):

    bloco = contract.functions.obterBloco(
        int(index)
    ).call()

    return {
        "index": int(bloco[0]),
        "timestamp": int(bloco[1]),
        "previousHash": bytes32_para_hex(bloco[2]),
        "nonce": int(bloco[3]),
        "hash": bytes32_para_hex(bloco[4]),
        "dadosHash": bytes32_para_hex(bloco[5]),
        "totalLeituras": int(bloco[6])
    }

# CONSULTAR ÚLTIMO BLOCO

def obter_ultimo_bloco():

    bloco = contract.functions.obterUltimoBloco().call()

    return {
        "index": int(bloco[0]),
        "timestamp": int(bloco[1]),
        "previousHash": bytes32_para_hex(bloco[2]),
        "nonce": int(bloco[3]),
        "hash": bytes32_para_hex(bloco[4]),
        "dadosHash": bytes32_para_hex(bloco[5]),
        "totalLeituras": int(bloco[6])
    }

# QUANTIDADE DE BLOCOS

def quantidade_blocos():

    return int(
        contract.functions.quantidadeBlocos().call()
    )

# QUANTIDADE DE LEITURAS

def quantidade_leituras():

    total = 0
    total_blocos = quantidade_blocos()

    for index in range(total_blocos):
        total += int(
            contract.functions.quantidadeLeituras(index).call()
        )

    return total

# VERIFICAR INTEGRIDADE DE UM BLOCO

def verificar_integridade(index):

    """
    Utiliza a função verificarBloco() do contrato.
    """

    resultado = contract.functions.verificarBloco(
        int(index)
    ).call()

    return bool(resultado)

# VERIFICAR HASH

def verificar_hash(index, hash_bloco):

    """
    Utiliza:

        verificarHash(uint256, bytes32)
    """

    hash_bloco = hex_para_bytes32(
        hash_bloco
    )

    resultado = contract.functions.verificarHash(
        int(index),
        hash_bloco
    ).call()

    return bool(resultado)

# VERIFICAR CADEIA COMPLETA

def verificar_cadeia():

    resultado = contract.functions.verificarCadeia().call()

    return bool(resultado)

# DIAGNÓSTICO

def diagnostico():

    print()
    print("=" * 50)
    print("DIAGNÓSTICO BLOCKCHAIN")
    print("=" * 50)

    # Ganache (teste)

    conectado = w3.is_connected()

    print(
        "Ganache conectado:",
        conectado
    )

    if not conectado:

        print()
        print(
            "ERRO: Ganache não está disponível."
        )

        return

    # RPC

    print(
        "RPC:",
        RPC_URL
    )

    # Chain ID

    try:

        print(
            "Chain ID:",
            w3.eth.chain_id
        )

    except Exception as erro:

        print(
            "Erro ao consultar Chain ID:",
            erro
        )

    # Contrato

    print(
        "Contrato:",
        CONTRACT_ADDRESS
    )

    # SCADA

    print(
        "SCADA:",
        SCADA_ACCOUNT
    )

    # Saldo

    try:

        saldo = w3.eth.get_balance(
            SCADA_ACCOUNT
        )

        saldo_eth = w3.from_wei(
            saldo,
            "ether"
        )

        print(
            "Saldo:",
            saldo_eth,
            "ETH"
        )

    except Exception as erro:

        print(
            "Erro ao consultar saldo:",
            erro
        )

    # Autorização

    try:

        autorizado = scada_esta_autorizado()

        print(
            "SCADA autorizado:",
            autorizado
        )

    except Exception as erro:

        print(
            "Erro ao verificar autorização:",
            erro
        )

    # Estado de segurança

    try:

        estado = obter_estado_seguranca()

        print(
            "Estado de segurança:",
            estado,
            "-",
            nome_estado_seguranca(estado)
        )

    except Exception as erro:

        print(
            "Erro ao consultar estado:",
            erro
        )

    # Quantidade de blocos

    try:

        qtd_blocos = quantidade_blocos()

        print(
            "Quantidade de blocos:",
            qtd_blocos
        )

    except Exception as erro:

        print(
            "Erro ao consultar blocos:",
            erro
        )

    # Quantidade de leituras

    try:

        qtd_leituras = quantidade_leituras()

        print(
            "Quantidade de leituras:",
            qtd_leituras
        )

    except Exception as erro:

        print(
            "Erro ao consultar leituras:",
            erro
        )

    # Integridade da cadeia

    try:

        cadeia = verificar_cadeia()

        print(
            "Cadeia íntegra:",
            cadeia
        )

    except Exception as erro:

        print(
            "Erro ao verificar cadeia:",
            erro
        )

    # Último bloco

    try:

        bloco = obter_ultimo_bloco()

        print()
        print("ÚLTIMO BLOCO")

        print(
            "Index:",
            bloco["index"]
        )

        print(
            "Timestamp:",
            bloco["timestamp"]
        )

        print(
            "Previous hash:",
            bloco["previousHash"]
        )

        print(
            "Nonce:",
            bloco["nonce"]
        )

        print(
            "Hash:",
            bloco["hash"]
        )

        print(
            "Dados hash:",
            bloco["dadosHash"]
        )

        print(
            "Total leituras:",
            bloco["totalLeituras"]
        )

    except Exception as erro:

        print(
            "Erro ao consultar último bloco:",
            erro
        )

# TESTE DE COMPATIBILIDADE DO HASH

def teste_hash():

    """
    Testa se o Python consegue reproduzir o hash dos dados
    usando exatamente o mesmo ABI do Solidity.
    """

    print()
    print("TESTE DE HASH")

    leituras = [

        {
            "temperatura_raw": 3672,
            "umidade_raw": 4822,
            "sequencia": 1000,
            "timestamp": 1788292369
        },

        {
            "temperatura_raw": 3675,
            "umidade_raw": 4772,
            "sequencia": 1001,
            "timestamp": 1788292373
        },

        {
            "temperatura_raw": 3672,
            "umidade_raw": 4765,
            "sequencia": 1002,
            "timestamp": 1788292379
        },

        {
            "temperatura_raw": 3672,
            "umidade_raw": 4777,
            "sequencia": 1003,
            "timestamp": 1788292383
        },

        {
            "temperatura_raw": 3674,
            "umidade_raw": 4774,
            "sequencia": 1004,
            "timestamp": 1788292389
        }
    ]

    dados_hash = calcular_dados_hash(
        leituras
    )

    print(
        "dadosHash calculado pelo Python:"
    )

    print(
        bytes32_para_hex(dados_hash)
    )

    # Se estiver conectado, compara com Solidity

    if w3.is_connected():

        try:

            leituras_tuplas = normalizar_leituras(
                leituras
            )

            dados_hash_solidity = (
                contract
                .functions
                .calcularDadosHash(
                    leituras_tuplas
                )
                .call()
            )

            print()
            print(
                "dadosHash calculado pelo Solidity:"
            )

            print(
                bytes32_para_hex(
                    dados_hash_solidity
                )
            )

            if dados_hash == dados_hash_solidity:

                print()
                print(
                    "HASH PYTHON = HASH SOLIDITY"
                )

            else:

                print()
                print(
                    "HASH PYTHON != HASH SOLIDITY"
                )

        except Exception as erro:

            print(
                "Erro no teste Solidity:",
                erro
            )

# TESTE DE MINERAÇÃO

def teste_mineracao():

    """
    Executa uma mineração local sem enviar transação.
    """

    print()
    print("TESTE DIRETO DE MINERAÇÃO")

    if not w3.is_connected():

        print(
            "Ganache não conectado."
        )

        return

    ultimo = (
        contract
        .functions
        .obterUltimoBloco()
        .call()
    )

    print()
    print(
        "Retorno obterUltimoBloco:"
    )

    print(
        ultimo
    )

    print()
    print(
        "Quantidade de campos:",
        len(ultimo)
    )

    ultimo_index = int(
        ultimo[0]
    )

    index = ultimo_index + 1

    previous_hash = ultimo[4]

    timestamp = int(
        time.time()
    )

    # Cinco leituras de teste

    leituras = [

        (
            3672,
            4822,
            1000,
            int(time.time()) - 120
        ),

        (
            3675,
            4772,
            1001,
            int(time.time()) - 116
        ),

        (
            3672,
            4765,
            1002,
            int(time.time()) - 110
        ),

        (
            3672,
            4777,
            1003,
            int(time.time()) - 106
        ),

        (
            3674,
            4774,
            1004,
            int(time.time()) - 100
        )
    ]

    print()
    print(
        "Index:",
        index
    )

    print(
        "Previous hash:",
        bytes32_para_hex(previous_hash)
    )

    print(
        "Timestamp:",
        timestamp
    )

    print()
    print(
        "Calculando dadosHash..."
    )

    dados_hash = calcular_dados_hash(
        leituras
    )

    print(
        "dadosHash:",
        bytes32_para_hex(dados_hash)
    )

    bloco = minerar_bloco(

        index=index,

        timestamp=timestamp,

        previous_hash=previous_hash,

        leituras=leituras
    )

    print()
    print(
        "Bloco minerado:"
    )

    print(
        bloco
    )

# EXECUÇÃO DIRETA

if __name__ == "__main__":

    diagnostico()

    print()

    teste_hash()

    print()

    print(
        "Blockchain.py carregado."
    )