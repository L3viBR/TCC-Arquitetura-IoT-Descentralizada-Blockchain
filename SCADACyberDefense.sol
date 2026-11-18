// SPDX-License-Identifier: MIT
// Smart Contract
pragma solidity ^0.8.20;

contract SCADACyberDefense {

    // CONFIGURAÇÕES DA BLOCKCHAIN

    uint256 public constant TAMANHO_BLOCO = 5;

    // O hash precisa começar com: 0000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    uint256 public constant POW_TARGET =
        0x0001000000000000000000000000000000000000000000000000000000000000;

    // ADMINISTRADOR

    address public administrador;

    // IDENTIDADE / AUTORIZAÇÃO DO SCADA

    mapping(address => bool) public scadasAutorizados;

    // ESTADO DE SEGURANÇA

    enum EstadoSeguranca {
        NORMAL,
        ALERTA,
        BLOQUEADO
    }

    EstadoSeguranca public estadoSeguranca;

    // CATEGORIAS DE EVENTOS DE SEGURANÇA

    enum CategoriaEvento {
        INTEGRIDADE,
        AUTENTICACAO,
        AUTORIZACAO,
        COMUNICACAO,
        CONSISTENCIA
    }

    // ESTRUTURA DE LEITURA

    struct Leitura {

        uint256 temperatura;

        uint256 umidade;

        uint256 sequencia;

        uint256 timestamp;
    }

    // ESTRUTURA DE BLOCO

    struct Bloco {

        uint256 index;

        uint256 timestamp;

        bytes32 previousHash;

        uint256 nonce;

        bytes32 hash;

        bytes32 dadosHash;

        Leitura[] leituras;
    }

    // ESTRUTURA DE EVENTO DE SEGURANÇA

    struct EventoSeguranca {

        uint256 timestamp;

        CategoriaEvento categoria;

        address origem;

        EstadoSeguranca estadoGerado;
    }

    // BLOCKCHAIN

    Bloco[] private blockchain;

    // EVENTOS BLOCKCHAIN

    event BlocoAdicionado(
        uint256 indexed index,
        bytes32 hash,
        bytes32 previousHash,
        uint256 nonce,
        uint256 timestamp,
        uint256 quantidadeLeituras
    );

    // EVENTOS DE SEGURANÇA

    event ScadaAutorizado(
        address indexed scada
    );


    event ScadaRevogado(
        address indexed scada
    );


    event EstadoSegurancaAlterado(
        EstadoSeguranca estado,
        string motivo,
        address indexed origem
    );


    event EventoSegurancaRegistrado(
        uint256 indexed id,
        CategoriaEvento categoria,
        address indexed origem,
        uint256 timestamp,
        EstadoSeguranca estadoGerado
    );

    // MODIFICADORES

    modifier onlyAdmin() {

        require(
            msg.sender == administrador,
            "Apenas administrador"
        );

        _;
    }


    modifier onlyScada() {

        require(
            scadasAutorizados[msg.sender],
            "SCADA nao autorizado"
        );

        _;
    }


    modifier sistemaOperacional() {

        require(
            estadoSeguranca != EstadoSeguranca.BLOQUEADO,
            "Sistema bloqueado"
        );

        _;
    }

    // CONSTRUTOR

    constructor() {

        administrador = msg.sender;

        estadoSeguranca = EstadoSeguranca.NORMAL;

        // BLOCO GENESIS (PRIMEIRO BLOCO/NÃO POSSUI PREVIUS HASH)

        uint256 timestampGenesis = block.timestamp;

        bytes32 dadosHashGenesis = bytes32(0);

        bytes32 hashGenesis = calcularHashBloco(
            0,
            timestampGenesis,
            bytes32(0),
            0,
            dadosHashGenesis
        );


        Bloco storage genesis = blockchain.push();

        genesis.index = 0;

        genesis.timestamp = timestampGenesis;

        genesis.previousHash = bytes32(0);

        genesis.nonce = 0;

        genesis.hash = hashGenesis;

        genesis.dadosHash = dadosHashGenesis;


        emit BlocoAdicionado(
            0,
            hashGenesis,
            bytes32(0),
            0,
            timestampGenesis,
            0
        );
    }

    // ADMINISTRAÇÃO DO SCADA

    function autorizarScada(
        address _scada
    )
        external
        onlyAdmin
    {

        require(
            _scada != address(0),
            "Endereco invalido"
        );

        scadasAutorizados[_scada] = true;

        emit ScadaAutorizado(_scada);
    }


    function revogarScada(
        address _scada
    )
        external
        onlyAdmin
    {

        scadasAutorizados[_scada] = false;

        emit ScadaRevogado(_scada);
    }


    function scadaAutorizado(
        address _scada
    )
        external
        view
        returns (bool)
    {

        return scadasAutorizados[_scada];
    }

    // ESTADO DE SEGURANÇA

    function obterEstadoSeguranca()
        external
        view
        returns (EstadoSeguranca)
    {

        return estadoSeguranca;
    }

    // Apenas a conta administrador pode recuperar o sistema.

    function resetarSeguranca()
        external
        onlyAdmin
    {

        estadoSeguranca = EstadoSeguranca.NORMAL;

        emit EstadoSegurancaAlterado(
            EstadoSeguranca.NORMAL,
            "Sistema recuperado pelo administrador",
            msg.sender
        );
    }

    // REGISTRO DE EVENTO DE SEGURANÇA

    EventoSeguranca[] private eventosSeguranca;


    function registrarEventoSeguranca(
        CategoriaEvento _categoria
    )
        external
        onlyScada
    {

        EstadoSeguranca novoEstado;

        // Define o estado de segurança conforme a categoria recebida.

        if (
            _categoria == CategoriaEvento.COMUNICACAO
        ) {

            novoEstado = EstadoSeguranca.ALERTA;

        }

        else {

            novoEstado = EstadoSeguranca.BLOQUEADO;
        }


        estadoSeguranca = novoEstado;


        uint256 id = eventosSeguranca.length;


        eventosSeguranca.push(
            EventoSeguranca({
                timestamp: block.timestamp,
                categoria: _categoria,
                origem: msg.sender,
                estadoGerado: novoEstado
            })
        );


        emit EventoSegurancaRegistrado(
            id,
            _categoria,
            msg.sender,
            block.timestamp,
            novoEstado
        );


        emit EstadoSegurancaAlterado(
            novoEstado,
            "Evento de seguranca registrado",
            msg.sender
        );
    }

    // CONSULTA DOS EVENTOS

    function quantidadeEventosSeguranca()
        external
        view
        returns (uint256)
    {

        return eventosSeguranca.length;
    }


    function obterEventoSeguranca(
        uint256 _id
    )
        external
        view
        returns (
            uint256 timestamp,
            CategoriaEvento categoria,
            address origem,
            EstadoSeguranca estadoGerado
        )
    {

        require(
            _id < eventosSeguranca.length,
            "Evento inexistente"
        );


        EventoSeguranca storage evento =
            eventosSeguranca[_id];


        return (
            evento.timestamp,
            evento.categoria,
            evento.origem,
            evento.estadoGerado
        );
    }

    // HASH DOS DADOS

    function calcularDadosHash(
        Leitura[] calldata _leituras
    )
        public
        pure
        returns (bytes32)
    {

        return sha256(
            abi.encode(_leituras)
        );
    }

    // HASH DO BLOCO

    function calcularHashBloco(
        uint256 _index,
        uint256 _timestamp,
        bytes32 _previousHash,
        uint256 _nonce,
        bytes32 _dadosHash
    )
        public
        pure
        returns (bytes32)
    {

        return sha256(
            abi.encode(
                _index,
                _timestamp,
                _previousHash,
                _nonce,
                _dadosHash
            )
        );
    }

    // ADICIONAR BLOCO COMPLETO

    function adicionarBlocoCompleto(
        uint256 _index,
        uint256 _timestamp,
        bytes32 _previousHash,
        uint256 _nonce,
        bytes32 _hash,
        Leitura[] calldata _leituras
    )
        external
        onlyScada
        sistemaOperacional
    {

        // 1. VERIFICA INDEX

        require(
            _index == blockchain.length,
            "Index invalido"
        );

        // 2. VERIFICA TAMANHO DO BLOCO

        require(
            _leituras.length == TAMANHO_BLOCO,
            "Quantidade de leituras invalida"
        );

        // 3. VERIFICA PREVIOUS HASH

        bytes32 ultimoHash =
            blockchain[blockchain.length - 1].hash;


        require(
            _previousHash == ultimoHash,
            "Previous hash invalido"
        );

        // 4. CALCULA HASH DOS DADOS

        bytes32 dadosHash =
            calcularDadosHash(_leituras);

        // 5. RECONSTRÓI O HASH DO BLOCO

        bytes32 hashCalculado =
            calcularHashBloco(
                _index,
                _timestamp,
                _previousHash,
                _nonce,
                dadosHash
            );


        require(
            hashCalculado == _hash,
            "Hash do bloco invalido"
        );

        // 6. VERIFICA PROOF OF WORK

        require(
            uint256(_hash) < POW_TARGET,
            "Hash nao atende dificuldade"
        );

        // 7. CRIA O BLOCO

        Bloco storage novoBloco =
            blockchain.push();


        novoBloco.index = _index;

        novoBloco.timestamp = _timestamp;

        novoBloco.previousHash = _previousHash;

        novoBloco.nonce = _nonce;

        novoBloco.hash = _hash;

        novoBloco.dadosHash = dadosHash;

        // 8. ARMAZENA AS LEITURAS

        for (
            uint256 i = 0;
            i < _leituras.length;
            i++
        ) {

            novoBloco.leituras.push(
                _leituras[i]
            );
        }

        // 9. EVENTO

        emit BlocoAdicionado(
            _index,
            _hash,
            _previousHash,
            _nonce,
            _timestamp,
            _leituras.length
        );
    }

    // QUANTIDADE DE BLOCOS

    function quantidadeBlocos()
        public
        view
        returns (uint256)
    {

        return blockchain.length;
    }

    // ÚLTIMO BLOCO

    function obterUltimoBloco()
        public
        view
        returns (
            uint256 index,
            uint256 timestamp,
            bytes32 previousHash,
            uint256 nonce,
            bytes32 hash,
            bytes32 dadosHash,
            uint256 totalLeituras
        )
    {

        Bloco storage bloco =
            blockchain[blockchain.length - 1];


        return (
            bloco.index,
            bloco.timestamp,
            bloco.previousHash,
            bloco.nonce,
            bloco.hash,
            bloco.dadosHash,
            bloco.leituras.length
        );
    }

    // OBTER BLOCO

    function obterBloco(
        uint256 _index
    )
        public
        view
        returns (
            uint256 index,
            uint256 timestamp,
            bytes32 previousHash,
            uint256 nonce,
            bytes32 hash,
            bytes32 dadosHash,
            uint256 totalLeituras
        )
    {

        require(
            _index < blockchain.length,
            "Bloco inexistente"
        );


        Bloco storage bloco =
            blockchain[_index];


        return (
            bloco.index,
            bloco.timestamp,
            bloco.previousHash,
            bloco.nonce,
            bloco.hash,
            bloco.dadosHash,
            bloco.leituras.length
        );
    }

    // OBTER LEITURA

    function obterLeitura(
        uint256 _bloco,
        uint256 _leitura
    )
        public
        view
        returns (
            uint256 temperatura,
            uint256 umidade,
            uint256 sequencia,
            uint256 timestamp
        )
    {

        require(
            _bloco < blockchain.length,
            "Bloco inexistente"
        );


        require(
            _leitura <
            blockchain[_bloco].leituras.length,
            "Leitura inexistente"
        );


        Leitura storage leitura =
            blockchain[_bloco].leituras[_leitura];


        return (
            leitura.temperatura,
            leitura.umidade,
            leitura.sequencia,
            leitura.timestamp
        );
    }

    // QUANTIDADE DE LEITURAS

    function quantidadeLeituras(
        uint256 _bloco
    )
        public
        view
        returns (uint256)
    {

        require(
            _bloco < blockchain.length,
            "Bloco inexistente"
        );


        return blockchain[_bloco].leituras.length;
    }

    // VERIFICAR HASH

    function verificarHash(
        uint256 _index,
        bytes32 _hash
    )
        public
        view
        returns (bool)
    {

        require(
            _index < blockchain.length,
            "Bloco inexistente"
        );


        return blockchain[_index].hash == _hash;
    }

    // VERIFICAR BLOCO COMPLETO

    function verificarBloco(
        uint256 _index
    )
        public
        view
        returns (bool)
    {

        require(
            _index < blockchain.length,
            "Bloco inexistente"
        );


        Bloco storage bloco =
            blockchain[_index];

        // Index correto

        if (
            bloco.index != _index
        ) {
            return false;
        }

        // Previous hash correto

        if (
            _index > 0 &&
            bloco.previousHash !=
            blockchain[_index - 1].hash
        ) {
            return false;
        }

        // Proof of Work

        if (
            uint256(bloco.hash) >= POW_TARGET
        ) {
            return false;
        }

        // Recalcula o hash

        bytes32 hashCalculado =
            calcularHashBloco(
                bloco.index,
                bloco.timestamp,
                bloco.previousHash,
                bloco.nonce,
                bloco.dadosHash
            );


        if (
            hashCalculado != bloco.hash
        ) {
            return false;
        }


        return true;
    }

    // VERIFICAR CADEIA COMPLETA

    function verificarCadeia()
        public
        view
        returns (bool)
    {

        if (
            blockchain.length <= 1
        ) {
            return true;
        }


        for (
            uint256 i = 1;
            i < blockchain.length;
            i++
        ) {

            // Index

            if (
                blockchain[i].index != i
            ) {
                return false;
            }

            // Previous hash

            if (
                blockchain[i].previousHash !=
                blockchain[i - 1].hash
            ) {
                return false;
            }

            // Proof of Work

            if (
                uint256(blockchain[i].hash) >=
                POW_TARGET
            ) {
                return false;
            }

            // Integridade do hash

            bytes32 hashCalculado =
                calcularHashBloco(
                    blockchain[i].index,
                    blockchain[i].timestamp,
                    blockchain[i].previousHash,
                    blockchain[i].nonce,
                    blockchain[i].dadosHash
                );


            if (
                hashCalculado != blockchain[i].hash
            ) {
                return false;
            }
        }


        return true;
    }
}
