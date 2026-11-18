# Função para desbloquear o contrato inteligente em uma rede Besu local usando Web3.py e a biblioteca eth_account.

import re
from pathlib import Path
from eth_account import Account

# Defina o caminho para o arquivo de configuração do Hardhat
arquivo = Path(r"\\wsl.localhost\Ubuntu\home\l3vi\TCC-Besu\besu-test-network\smart_contracts\hardhat.config.ts")
conteudo = arquivo.read_text(encoding="utf-8")
resultado = re.search(r"0x[0-9a-fA-F]{64}", conteudo)

if not resultado:
    raise RuntimeError("Chave administrativa nao encontrada.")

conta = Account.from_key(resultado.group(0))

# Defina o endereço do administrador
administrador = "0x00000000000000000000000000000000000000000"  # Substitua pelo endereço real do administrador

if conta.address.lower() != administrador.lower():
    raise RuntimeError("A conta configurada nao corresponde ao administrador.")

print("Conta administrativa validada:", conta.address)
print("Pronto para preparar o desbloqueio.")
from web3 import Web3

RPC = "http://127.0.0.1:8545"
CONTRATO = "0x0000000000000000000000000000000000000000"  # Substitua pelo endereço real do contrato

w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 10}))

if not w3.is_connected():
    raise RuntimeError("Nao foi possivel conectar ao Besu.")

contrato = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRATO),
    abi=[
        {
            "inputs": [],
            "name": "obterEstadoSeguranca",
            "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
)

estado = contrato.functions.obterEstadoSeguranca().call()

print("Conexao com Besu: OK")
print("Chain ID:", w3.eth.chain_id)
print("Estado de seguranca:", estado)

def desbloquear():
    if w3.eth.chain_id != 1337:
        raise RuntimeError("Rede incorreta.")

    estado_atual = contrato.functions.obterEstadoSeguranca().call()
    print("Estado antes do desbloqueio:", estado_atual)

    if estado_atual == 0:
        print("O contrato ja esta em estado NORMAL. Nenhuma transacao enviada.")
        return

    funcao_reset = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRATO),
        abi=[
            {
                "inputs": [],
                "name": "resetarSeguranca",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
    )

    transacao = funcao_reset.functions.resetarSeguranca().build_transaction({
        "from": conta.address,
        "chainId": 1337,
        "nonce": w3.eth.get_transaction_count(conta.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price
    })

    assinada = conta.sign_transaction(transacao)
    hash_tx = w3.eth.send_raw_transaction(assinada.raw_transaction)
    recibo = w3.eth.wait_for_transaction_receipt(hash_tx, timeout=60)

    print("Hash da transacao:", hash_tx.hex())
    print("Status da transacao:", recibo.status)
    print("Estado apos recuperacao:", contrato.functions.obterEstadoSeguranca().call())

if __name__ == "__main__":
    desbloquear()
