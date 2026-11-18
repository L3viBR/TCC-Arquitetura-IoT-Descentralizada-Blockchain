#include <WiFi.h>
#include <Wire.h>
#include <Adafruit_SHT31.h>
#include <ModbusIP_ESP8266.h>
#include <Preferences.h>
#include <psa/crypto.h>

// WIFI

const char* ssid = "User";
const char* password = "Senha";

// SENSOR

Adafruit_SHT31 sht31 = Adafruit_SHT31();

// MODBUS TCP

ModbusIP mb;

const int REG_TEMPERATURA = 0;
const int REG_UMIDADE     = 1;

// sequência 32 bits -> registradores 2 e 3
const int REG_SEQUENCIA_H = 2;
const int REG_SEQUENCIA_L = 3;

// timestamp 32 bits -> registradores 4 e 5
const int REG_TIMESTAMP_H = 4;
const int REG_TIMESTAMP_L = 5;

// tamanho da assinatura
const int REG_ASSINATURA_LEN = 6;

// assinatura ECDSA 64 bytes = 32 registradores
const int REG_ASSINATURA = 7;

// chave pública ECDSA P-256
// 65 bytes = 33 registradores
const int REG_CHAVE_PUBLICA = 39;

// PSA / ECDSA

psa_key_id_t chaveESP = 0;
Preferences preferences;
uint8_t chavePrivada[32];
uint8_t chavePublica[65];
size_t tamanhoChavePublica = 0;

// ASSINATURA

uint8_t assinatura[64];
size_t tamanhoAssinatura = 0;

// CONTADOR

uint32_t sequencia = 0;

// INTERVALO

unsigned long ultimaLeitura = 0;
const unsigned long INTERVALO_LEITURA = 2000;

// FUNÇÃO PARA MOSTRAR ERRO PSA

void mostrarErroPSA(
  const char* mensagem,
  psa_status_t status
) {

  Serial.print(mensagem);

  Serial.print(" | PSA status = ");
  Serial.println((int)status);
}

// INICIALIZAR PSA

bool inicializarPSA() {

  psa_status_t status;

  status = psa_crypto_init();

  if (status != PSA_SUCCESS) {

    mostrarErroPSA(
      "Falha ao inicializar PSA Crypto",
      status
    );

    return false;
  }

  Serial.println(
    "PSA Crypto inicializado."
  );

  return true;
}

// CONFIGURAR ATRIBUTOS DA CHAVE

void configurarAtributos(
  psa_key_attributes_t* atributos,
  bool exportavel
) {

  *atributos = PSA_KEY_ATTRIBUTES_INIT;

  psa_set_key_type(
    atributos,
    PSA_KEY_TYPE_ECC_KEY_PAIR(
      PSA_ECC_FAMILY_SECP_R1
    )
  );

  psa_set_key_bits(
    atributos,
    256
  );

  psa_set_key_usage_flags(
    atributos,
    PSA_KEY_USAGE_SIGN_HASH |
    (exportavel ? PSA_KEY_USAGE_EXPORT : 0)
  );

  psa_set_key_algorithm(
    atributos,
    PSA_ALG_ECDSA(
      PSA_ALG_SHA_256
    )
  );
}

// CRIAR OU CARREGAR CHAVE PRIVADA

bool inicializarChaveECDSA() {

  psa_status_t status;

  preferences.begin(
    "espcrypto",
    false
  );

  // VERIFICAR SE JÁ EXISTE CHAVE

  size_t tamanhoSalvo =
    preferences.getBytesLength(
      "privkey"
    );


  if (tamanhoSalvo == 32) {

    Serial.println(
      "Chave privada encontrada na memória."
    );

    preferences.getBytes(
      "privkey",
      chavePrivada,
      32
    );

    // Importar chave existente

    psa_key_attributes_t atributos =
      PSA_KEY_ATTRIBUTES_INIT;

    configurarAtributos(
      &atributos,
      false
    );


    status = psa_import_key(
      &atributos,
      chavePrivada,
      32,
      &chaveESP
    );


    psa_reset_key_attributes(
      &atributos
    );


    if (status != PSA_SUCCESS) {

      mostrarErroPSA(
        "Falha ao importar chave privada",
        status
      );

      preferences.end();

      return false;
    }


    Serial.println(
      "Chave privada importada."
    );
  }

  // PRIMEIRA EXECUÇÃO

  else {

    Serial.println(
      "Nenhuma chave encontrada."
    );

    Serial.println(
      "Gerando nova chave ECDSA P-256..."
    );


    psa_key_attributes_t atributos =
      PSA_KEY_ATTRIBUTES_INIT;

    configurarAtributos(
      &atributos,
      true
    );


    status = psa_generate_key(
      &atributos,
      &chaveESP
    );


    if (status != PSA_SUCCESS) {

      mostrarErroPSA(
        "Falha ao gerar chave ECDSA",
        status
      );

      psa_reset_key_attributes(
        &atributos
      );

      preferences.end();

      return false;
    }

    // Exportar chave privada UMA VEZ

    size_t tamanhoPrivada = 0;


    status = psa_export_key(
      chaveESP,
      chavePrivada,
      sizeof(chavePrivada),
      &tamanhoPrivada
    );


    if (
      status != PSA_SUCCESS ||
      tamanhoPrivada != 32
    ) {

      mostrarErroPSA(
        "Falha ao exportar chave privada",
        status
      );

      psa_destroy_key(
        chaveESP
      );

      psa_reset_key_attributes(
        &atributos
      );

      preferences.end();

      return false;
    }

    // Salvar chave privada

    size_t gravados =
      preferences.putBytes(
        "privkey",
        chavePrivada,
        32
      );


    if (gravados != 32) {

      Serial.println(
        "Não foi possível salvar chave privada."
      );

      psa_destroy_key(
        chaveESP
      );

      psa_reset_key_attributes(
        &atributos
      );

      preferences.end();

      return false;
    }


    Serial.println(
      "Chave privada armazenada."
    );


    psa_reset_key_attributes(
      &atributos
    );
  }


  preferences.end();

  // EXPORTAR CHAVE PÚBLICA

  status = psa_export_public_key(
    chaveESP,
    chavePublica,
    sizeof(chavePublica),
    &tamanhoChavePublica
  );


  if (status != PSA_SUCCESS) {

    mostrarErroPSA(
      "Falha ao exportar chave pública",
      status
    );

    return false;
  }


  Serial.println();

  Serial.println(
    "CHAVE PÚBLICA DO ESP32"
  );

  Serial.print(
    "Tamanho: "
  );

  Serial.print(
    tamanhoChavePublica
  );

  Serial.println(
    " bytes"
  );


  Serial.print(
    "Public Key HEX: "
  );


  for (
    size_t i = 0;
    i < tamanhoChavePublica;
    i++
  ) {

    if (
      chavePublica[i] < 0x10
    ) {

      Serial.print("0");
    }

    Serial.print(
      chavePublica[i],
      HEX
    );
  }

  Serial.println();

  Serial.println();

  return true;
}

// SHA-256

bool calcularSHA256(
  const uint8_t* dados,
  size_t tamanho,
  uint8_t* hash
) {

  psa_status_t status;

  size_t tamanhoHash = 0;


  status = psa_hash_compute(
    PSA_ALG_SHA_256,
    dados,
    tamanho,
    hash,
    32,
    &tamanhoHash
  );


  if (
    status != PSA_SUCCESS ||
    tamanhoHash != 32
  ) {

    mostrarErroPSA(
      "Falha ao calcular SHA-256",
      status
    );

    return false;
  }


  return true;
}

// ASSINAR DADOS

bool assinarDados(
  const char* dados
) {

  uint8_t hash[32];

  // SHA-256

  if (
    !calcularSHA256(
      (const uint8_t*)dados,
      strlen(dados),
      hash
    )
  ) {

    return false;
  }

  // ECDSA

  psa_status_t status;
  tamanhoAssinatura = 0;
  status = psa_sign_hash(

    chaveESP,

    PSA_ALG_ECDSA(
      PSA_ALG_SHA_256
    ),

    hash,

    sizeof(hash),

    assinatura,

    sizeof(assinatura),

    &tamanhoAssinatura
  );


  if (status != PSA_SUCCESS) {

    mostrarErroPSA(
      "Falha ao gerar assinatura ECDSA",
      status
    );

    return false;
  }


  return true;
}

// COLOCAR UINT32 EM DOIS REGISTRADORES

void escreverUInt32(
  int regHigh,
  int regLow,
  uint32_t valor
) {

  uint16_t high =
    (uint16_t)(
      (valor >> 16) & 0xFFFF
    );

  uint16_t low =
    (uint16_t)(
      valor & 0xFFFF
    );


  mb.Hreg(
    regHigh,
    high
  );

  mb.Hreg(
    regLow,
    low
  );
}

// COLOCAR BYTES NOS REGISTRADORES

void escreverBytesRegistradores(
  int registradorInicial,
  const uint8_t* dados,
  size_t tamanho
) {

  size_t quantidadeRegistradores =
    (tamanho + 1) / 2;


  for (
    size_t i = 0;
    i < quantidadeRegistradores;
    i++
  ) {

    uint16_t valor = 0;


    size_t pos =
      i * 2;


    valor =
      ((uint16_t)dados[pos]) << 8;


    if (
      pos + 1 < tamanho
    ) {

      valor |=
        dados[pos + 1];
    }


    mb.Hreg(
      registradorInicial + i,
      valor
    );
  }
}

// CONFIGURAR REGISTRADORES MODBUS

void configurarModbus() {

  // Registradores simples

  for (
    int i = 0;
    i < 73;
    i++
  ) {

    mb.addHreg(
      i,
      0
    );
  }

  Serial.println(
    "Registradores Modbus configurados."
  );

  Serial.println();
  Serial.println(
    "MAPA MODBUS:"
  );

  Serial.println(
    "REG 0  = Temperatura"
  );

  Serial.println(
    "REG 1  = Umidade"
  );

  Serial.println(
    "REG 2  = Sequência HIGH"
  );

  Serial.println(
    "REG 3  = Sequência LOW"
  );

  Serial.println(
    "REG 4  = Timestamp HIGH"
  );

  Serial.println(
    "REG 5  = Timestamp LOW"
  );

  Serial.println(
    "REG 6  = Tamanho assinatura"
  );

  Serial.println(
    "REG 7-38 = Assinatura ECDSA"
  );

  Serial.println(
    "REG 39-71 = Chave pública"
  );

  Serial.println();
}

// ATUALIZAR REGISTRADORES

void atualizarRegistradores(
  int temperaturaRaw,
  int umidadeRaw,
  uint32_t timestamp
) {

  // Sensor

  mb.Hreg(
    REG_TEMPERATURA,
    temperaturaRaw
  );

  mb.Hreg(
    REG_UMIDADE,
    umidadeRaw
  );

  // Sequência

  escreverUInt32(
    REG_SEQUENCIA_H,
    REG_SEQUENCIA_L,
    sequencia
  );

  // Timestamp

  escreverUInt32(
    REG_TIMESTAMP_H,
    REG_TIMESTAMP_L,
    timestamp
  );

  // Assinatura

  mb.Hreg(
    REG_ASSINATURA_LEN,
    tamanhoAssinatura
  );

  escreverBytesRegistradores(
    REG_ASSINATURA,
    assinatura,
    tamanhoAssinatura
  );

  // Chave pública

  escreverBytesRegistradores(
    REG_CHAVE_PUBLICA,
    chavePublica,
    tamanhoChavePublica
  );
}

// SETUP

void setup() {

  Serial.begin(
    115200
  );

  delay(
    2000
  );

  Serial.println();
  Serial.println(
    " ESP32 - SENSOR + MODBUS + ECDSA"
  );

  Serial.println();

  // I2C

  Wire.begin(
    21,
    22
  );

  // SENSOR

  if (
    !sht31.begin(
      0x44
    )
  ) {

    Serial.println(
      "Falha ao inicializar o SHT31."
    );

    while (true) {

      delay(1000);
    }
  }

  Serial.println(
    "Sensor SHT31 encontrado!"
  );

  // WIFI

  WiFi.begin(
    ssid,
    password
  );

  Serial.print(
    "Conectando ao Wi-Fi"
  );

  while (
    WiFi.status()
    != WL_CONNECTED
  ) {

    delay(500);

    Serial.print(
      "."
    );
  }

  Serial.println();
  Serial.println(
    "Wi-Fi conectado!"
  );

  Serial.print(
    "IP do ESP32: "
  );

  Serial.println(
    WiFi.localIP()
  );

  // NTP

  configTime(
    0,
    0,
    "pool.ntp.org",
    "time.nist.gov"
  );

  Serial.println(
    "Sincronizando horário..."
  );

  time_t agora = time(nullptr);
  int tentativas = 0;

  while (
    agora < 100000 &&
    tentativas < 20
  ) {

    delay(500);

    agora =
      time(nullptr);

    tentativas++;
  }

  if (
    agora >= 100000
  ) {

    Serial.println(
      "Horário NTP sincronizado."
    );
  }

  else {

    Serial.println(
      "NTP não sincronizado."
    );
  }

  // PSA

  if (
    !inicializarPSA()
  ) {

    Serial.println(
      "Sistema criptográfico não inicializado."
    );

    while (true) {

      delay(1000);
    }
  }

  // CHAVE ECDSA

  if (
    !inicializarChaveECDSA()
  ) {

    Serial.println(
      "Não foi possível inicializar ECDSA."
    );

    while (true) {

      delay(1000);
    }
  }

  Serial.println(
    "ECDSA pronto."
  );

  // MODBUS TCP

  mb.server();
  configurarModbus();

  Serial.println(
    "Servidor Modbus TCP iniciado."
  );

  Serial.println();
  Serial.println(
    "              ESP32 PRONTO"
  );

  Serial.println();
}

// LOOP

void loop() {

  mb.task();


  unsigned long agoraMillis =
    millis();


  if (
    agoraMillis -
    ultimaLeitura
    < INTERVALO_LEITURA
  ) {

    return;
  }


  ultimaLeitura =
    agoraMillis;

  // LEITURA SENSOR
  float temperatura =
    sht31.readTemperature();

  float umidade =
    sht31.readHumidity();

  if (
    isnan(temperatura) ||
    isnan(umidade)
  ) {

    Serial.println(
      "Falha na leitura do SHT31."
    );

    return;
  }

  // RAW
  int temperaturaRaw =
    (int)(
      temperatura * 100.0
    );

  int umidadeRaw =
    (int)(
      umidade * 100.0
    );

  // SEQUÊNCIA
  sequencia++;

  // TIMESTAMP
  time_t timestamp =
    time(nullptr);

  if (
    timestamp < 100000
  ) {

    timestamp =
      millis() / 1000;
  }

  // PAYLOAD

  char payload[128];

  snprintf(

    payload,

    sizeof(payload),

    "%d|%d|%lu|%lu",

    temperaturaRaw,

    umidadeRaw,

    (unsigned long)sequencia,

    (unsigned long)timestamp
  );

  // ASSINAR

  if (
    !assinarDados(
      payload
    )
  ) {

    Serial.println(
      "Leitura não assinada."
    );

    return;
  }

  // MODBUS

  atualizarRegistradores(

    temperaturaRaw,

    umidadeRaw,

    (uint32_t)timestamp
  );

  // SERIAL

  Serial.println();

  Serial.print(
    "Temperatura: "
  );

  Serial.print(
    temperatura,
    2
  );

  Serial.println(
    " °C"
  );

  Serial.print(
    "Umidade: "
  );

  Serial.print(
    umidade,
    2
  );

  Serial.println(
    " %"
  );

  Serial.print(
    "Sequência: "
  );

  Serial.println(
    sequencia
  );

  Serial.print(
    "Timestamp: "
  );

  Serial.println(
    (unsigned long)timestamp
  );


  Serial.print(
    "Payload: "
  );

  Serial.println(
    payload
  );

  Serial.print(
    "Assinatura ECDSA: "
  );

  for (
    size_t i = 0;
    i < tamanhoAssinatura;
    i++
  ) {

    if (
      assinatura[i] < 0x10
    ) {

      Serial.print(
        "0"
      );
    }

    Serial.print(
      assinatura[i],
      HEX
    );
  }

  Serial.println();
  Serial.print(
    "Modbus TCP: "
  );

  Serial.println(
    "dados atualizados"
  );
}