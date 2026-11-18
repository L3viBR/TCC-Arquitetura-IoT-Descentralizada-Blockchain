
# Sistema de Defesa Cibernética baseado em uma Arquitetura IoT Descentralizada

Repositório destinado à disponibilização dos códigos-fonte desenvolvidos para o Trabalho de Conclusão de Curso, que propõe uma arquitetura de defesa cibernética para ambientes industriais integrando dispositivos IoT, sistemas SCADA e tecnologia blockchain.

## Arquitetura do projeto

A solução integra:
- ESP32 com sensor SHT31;
- Comunicação Modbus TCP/IP;
- Sistema SCADA desenvolvido em Python;
- Assinaturas digitais ECDSA;
- Rede privada Hyperledger Besu com consenso QBFT;
- Contratos inteligentes para registro de eventos de segurança.

## Organização dos arquivos

- COD_ESP_REV01-TCC.ino: código-fonte do dispositivo IoT.
- scada.py: código-fonte da implementação do sistema de supervisão e validação criptográfica.
- SCADACyberDefense.sol: código-fonte do contrato inteligente.
- blockchain.py: código-fonte da blockchain.
- ihm.py: código-fonte da ihm.

## Observações

- Não foram disponibilizados os códigos referente às simulações de ataque e de configuração da blockchain no ubuntu devido a sensibilidade dos dados.
