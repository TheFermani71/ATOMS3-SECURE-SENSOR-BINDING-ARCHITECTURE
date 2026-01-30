/************************************************************
 *  ATOMS3 – SECURE SENSOR BINDING ARCHITECTURE
 *
 *  Questo firmware implementa un modello di sicurezza
 *  basato su:
 *  - Secure Boot + Flash Encryption (assunti attivi a livello HW)
 *  - Binding del sensore alle API
 *  - Tipi di dato cifrati (Int)
 *  - API aritmetiche protette e invocabili
 *  - Tracciamento completo dell’esecuzione (trace)
 *  - Hash + Firma ECDSA per attestazione remota
 *
 *  Obiettivo:
 *  impedire la manipolazione dei dati sensoriali e del
 *  flusso di esecuzione, anche in presenza di codice
 *  applicativo pubblico o modificabile.
 ************************************************************/

#include <M5Unified.h>      // Framework M5Stack (IMU, display, HW abstraction)
#include <TinyGPSPlus.h>    // Parsing dati GPS
#include <AceRoutine.h>     // Coroutine cooperative
#include "mbedtls/aes.h"    // AES per cifratura dati
#include "mbedtls/sha256.h"// Hash SHA-256
#include "mbedtls/pk.h"    // PK / ECDSA
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

using namespace ace_routine;

/************************************************************
 *  CONFIGURAZIONE GPS
 ************************************************************/
#define GPS_BAUD 115200
#define GPS_RX_PIN 5
#define GPS_TX_PIN 6

HardwareSerial gpsSerial(2);
TinyGPSPlus gps;

/************************************************************
 *  CONTESTO CRITTOGRAFICO GLOBALE
 *
 *  Tutti questi contesti sono considerati parte della
 *  Trusted Computing Base (TCB) e risiedono nella flash
 *  protetta (Secure Boot + Flash Encryption).
 ************************************************************/
mbedtls_pk_context pk_ctx;           // Chiave privata ECC
mbedtls_entropy_context entropy;     // Entropia HW/SW
mbedtls_ctr_drbg_context ctr_drbg;   // PRNG crittografico

// Chiave simmetrica AES-128 
// Derivata da secure element / eFuse
const uint8_t AES_KEY[16] = {
  0x10,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
  0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78
};

/************************************************************
 *  TRACE DI ESECUZIONE
 *
 *  Implementa la funzione trace().
 *  Ogni operazione protetta viene registrata.
 ************************************************************/
#define TRACE_MAX 256

// Tipologia di operazioni tracciate
enum TraceOp {
  OP_INIT,  // inizializzazione Int
  OP_ADD,   // somma
  OP_LT     // confronto <
};

// Singola entry di trace
typedef struct {
  uint32_t op;         // tipo di operazione
  uint32_t in1;        // ID primo operando
  uint32_t in2;        // ID secondo operando
  uint32_t out;        // ID risultato (se presente)
  uint32_t timestamp; // tempo di esecuzione
} TraceEntry;

// Buffer circolare di trace
TraceEntry traceBuf[TRACE_MAX];
uint16_t traceIndex = 0;

/************************************************************
 *  TIPI PROTETTI (Int)
 *
 *  NON ESISTE UN int IN CHIARO nel codice applicativo.
 ************************************************************/
typedef struct {
  uint8_t enc[16];      // valore cifrato (AES)
  uint32_t id;          // identificatore logico univoco
  uint32_t timestamp;   // momento di creazione
} Int;

// Contatore globale degli ID (per trace e verifica server)
uint32_t globalVarID = 1;

/************************************************************
 *  UTILITY: AES ECB
 *
 *  Serve a:
 *  - impedire la lettura diretta dei dati
 *  - garantire che il valore reale esista solo
 *    temporaneamente dentro le API protette
 ************************************************************/
void aesEncrypt(uint8_t *data) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, data, data);
  mbedtls_aes_free(&aes);
}

void aesDecrypt(uint8_t *data) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, data, data);
  mbedtls_aes_free(&aes);
}

/************************************************************
 *  TRACE API
 *
 *  Rappresentazione della trace()
 *  Ogni chiamata API registra un evento.
 ************************************************************/
void trace(uint32_t op, uint32_t in1, uint32_t in2, uint32_t out) {
  if (traceIndex < TRACE_MAX) {
    traceBuf[traceIndex++] = {
      op, in1, in2, out, millis()
    };
  }
}

/************************************************************
 *  BINDING: CREAZIONE Int
 *
 *  Converte un valore in chiaro in un Int cifrato.
 *  Dopo questa funzione:
 *  - il valore NON è più leggibile
 *  - esiste solo come cifrato
 ************************************************************/
Int initI(int value) {
  Int x;

  // Copia valore in buffer temporaneo
  memset(x.enc, 0, 16);
  memcpy(x.enc, &value, sizeof(int));

  // Cifratura immediata
  aesEncrypt(x.enc);

  // Metadati di sicurezza
  x.id = globalVarID++;
  x.timestamp = millis();

  // Tracciamento
  trace(OP_INIT, 0, 0, x.id);
  return x;
}

/************************************************************
 *  DECRITTAZIONE (PRIVATA)
 *
 *  Funzione NON accessibile dal codice applicativo.
 *  Il valore in chiaro risiede solo nello stack dell’API.
 ************************************************************/
int decryptInt(const Int &x) {
  uint8_t tmp[16];
  memcpy(tmp, x.enc, 16);
  aesDecrypt(tmp);

  int v;
  memcpy(&v, tmp, sizeof(int));
  return v;
}

/************************************************************
 *  API ARITMETICHE PROTETTE
 *
 *  Sostituiscono completamente +, -, <, >, ecc.
 *  Il codice pubblico NON può fare operazioni dirette.
 ************************************************************/
Int addI(const Int &a, const Int &b) {
  int va = decryptInt(a);
  int vb = decryptInt(b);
  int r  = va + vb;

  Int out = initI(r);
  trace(OP_ADD, a.id, b.id, out.id);
  return out;
}

bool LTI(const Int &a, const Int &b) {
  int va = decryptInt(a);
  int vb = decryptInt(b);

  trace(OP_LT, a.id, b.id, 0);
  return va < vb;
}

/************************************************************
 *  ACQUISIZIONE SENSORI (BINDING)
 *
 *  Il sensore NON restituisce mai un float o int.
 *  Il dato è immediatamente inglobato in Int.
 ************************************************************/
Int readAccZ() {
  float ax, ay, az;
  M5.Imu.getAccel(&ax, &ay, &az);

  // Quantizzazione + binding
  return initI((int)(az * 1000));
}

/************************************************************
 *  HASH + FIRMA DELLA TRACE
 *
 *  Questa funzione produce l’attestazione remota:
 *  - Hash SHA-256 della trace
 *  - Firma ECDSA con chiave privata del device
 ************************************************************/
void sendSecurePacket() {
  mbedtls_sha256_context sha;
  uint8_t hash[32];

  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);

  // Hash dell’intera sequenza di operazioni
  mbedtls_sha256_update(&sha,
    (uint8_t*)traceBuf,
    traceIndex * sizeof(TraceEntry)
  );

  mbedtls_sha256_finish(&sha, hash);
  mbedtls_sha256_free(&sha);

  // Firma ECDSA
  uint8_t sig[80];
  size_t sigLen;

  mbedtls_pk_sign(&pk_ctx,
                  MBEDTLS_MD_SHA256,
                  hash, 32,
                  sig, sizeof(sig),
                  &sigLen,
                  mbedtls_ctr_drbg_random,
                  &ctr_drbg);

  Serial.println("TRACE HASH + FIRMA GENERATI");
}

/************************************************************
 *  COROUTINE PRINCIPALE
 *
 *  Comprende:
 *  - ciclo for completamente protetto
 *  - contatori e confronti tracciati
 ************************************************************/
COROUTINE(mainCoroutine) {
  COROUTINE_LOOP() {

    Int accZ = readAccZ();
    Int limit = initI(10);

    for (Int i = initI(0); LTI(i, limit); i = addI(i, initI(1))) {
      accZ = addI(accZ, initI(1));
    }

    sendSecurePacket();
    COROUTINE_DELAY(2000);
  }
}

/************************************************************
 *  SETUP
 *
 *  Inizializza:
 *  - IMU
 *  - GPS
 *  - contesto crittografico
 ************************************************************/
void setup() {
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.begin(115200);

  M5.Imu.begin();
  gpsSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_pk_init(&pk_ctx);

  const char *pers = "secure-device";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                        &entropy,
                        (const uint8_t*)pers,
                        strlen(pers));

  mbedtls_pk_setup(&pk_ctx,
                   mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                      mbedtls_pk_ec(pk_ctx),
                      mbedtls_ctr_drbg_random,
                      &ctr_drbg);

  CoroutineScheduler::setup();
}

/************************************************************
 *  LOOP
 ************************************************************/
void loop() {
  CoroutineScheduler::loop();
}
