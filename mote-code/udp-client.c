/*
 * udp-client.c — Cooja mote firmware
 * ====================================
 * IoT Data Integrity + Backend Data Sharing model
 *
 * Changes vs. previous version (Step 13):
 *   - The mote now reports one of three sensor types — temperature,
 *     humidity, or pressure — chosen at boot from the node-id, so a
 *     single firmware image can populate a heterogeneous network.
 *   - The AAD now includes  ";type=<temp|hum|press>"   so the
 *     authenticated cleartext header carries the sensor type to the
 *     gateway. The CCM tag is computed over the new AAD; the gateway
 *     must reconstruct the same AAD byte-for-byte.
 *   - The plaintext body now uses a generic  "v=XX.YY;batt=ZZ"   field
 *     name instead of "temp=...", because the value can be temperature,
 *     humidity, or pressure depending on the device.
 *
 * Node-id → sensor-type mapping (block-range, see docs/allocation.md):
 *      1  –   9    border routers (BR firmware — never reach this code)
 *      10 –  89     temperature   (18.00 – 28.00 °C)    DODAG aaaa::/64
 *      90 – 169     humidity      (40.00 – 70.00 %)     DODAG bbbb::/64
 *      170 – 249     pressure      (990.00 – 1020.00 hPa) DODAG cccc::/64
 *      250 – 255     reserved for future sensor types
 *      other       UNKNOWN → fail-loud, no transmissions
 *
 * The encryption layer (AES-CCM-8 over tinyAES, HKDF-derived key) is
 * unchanged. Wire format on the air remains ASCII:
 *
 *    id=N;seq=M;type=T;nonce=<hex>;ct=<hex>;tag=<hex>
 *    └────────── AAD (authenticated cleartext) ──────────┘└─ MAC ─┘
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/linkaddr.h"
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include "sys/log.h"
#include "key_derivation.h"        /* HKDF + self-contained SHA-256/HMAC      */
#include "ccm.h"                   /* AES-CCM-8 built on tinyAES (aes.c/.h)   */

#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define UDP_CLIENT_PORT   8765
#define UDP_SERVER_PORT   3000
#define SEND_INTERVAL    (10 * CLOCK_SECOND)

#define CCM_TAG_BYTES     CCM_TAG_LEN           /* 8                          */
#define CCM_TAG_HEX       (CCM_TAG_BYTES * 2)
#define CCM_NONCE_BYTES   CCM_NONCE_LEN         /* 13                         */
#define CCM_NONCE_HEX     (CCM_NONCE_BYTES * 2)

static struct simple_udp_connection udp_conn;
static const uint8_t MASTER_KEY[32] = {
    0x3a, 0x56, 0x86, 0xf2, 0xb2, 0xc3, 0x62, 0x31,
    0x34, 0xa5, 0x2b, 0x69, 0x4c, 0xa9, 0xd2, 0x54,
    0x3a, 0x18, 0xfa, 0x4a, 0x01, 0xc7, 0xbd, 0xe4,
    0x40, 0x70, 0x4a, 0x8b, 0x6e, 0x6f, 0x11, 0xf5
};
static char    MY_DEVICE_ID[16];
static uint8_t MY_ENC_KEY[16];

/* --- profile struct: extended for multi-DODAG routing --- */
typedef struct {
  const char *type_name;       /* "temp" | "hum" | "press" | "UNKNOWN"           */
  long  v_min;                 /* 32-bit — needed for pressure (~99000)          */
  long  v_range;               /* random offset added on top of v_min            */
  uint16_t dest_prefix0;       /* first 16-bit word of dest IPv6 prefix:         */
                               /*   0xaaaa → aaaa::1, 0xbbbb → bbbb::1, …        */
                               /*   0x0000 → invalid (fail-loud sentinel)        */
} sensor_profile_t;

PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);

/* -------------------------------------------------------------------------- */
/*  Profile selection from node-id — single firmware, multiple sensor types.  */
/* -------------------------------------------------------------------------- */
  /* --- block-range profile selector ---
 * Node-id allocation (see docs/allocation.md):
 *      1 –   9   border routers (BR firmware — never reach this code)
 *     10 –  89   temp   sensors → DODAG aaaa::/64
 *     90 – 169   hum    sensors → DODAG bbbb::/64
 *    170 – 249   press  sensors → DODAG cccc::/64
 *    250 – 255   reserved for future types
 *  All other ids → UNKNOWN (fail-loud, no transmissions)                 */
static void
choose_profile(uint8_t dev_id, sensor_profile_t *out)
{
  if(dev_id >= 10 && dev_id <= 89) {
    out->type_name    = "temp";
    out->v_min        = 1800;       /* 18.00 °C            */
    out->v_range      = 1000;       /* up to 28.00 °C      */
    out->dest_prefix0 = 0xaaaa;
  } else if(dev_id >= 90 && dev_id <= 169) {
    out->type_name    = "hum";
    out->v_min        = 4000;       /* 40.00 %             */
    out->v_range      = 3000;       /* up to 70.00 %       */
    out->dest_prefix0 = 0xbbbb;
  } else if(dev_id >= 170 && dev_id <= 249) {
    out->type_name    = "press";
    out->v_min        = 99000;      /* 990.00 hPa          */
    out->v_range      = 3000;       /* up to 1020.00 hPa   */
    out->dest_prefix0 = 0xcccc;
  } else {
    /* Defensive default — sentinel values, visible in boot log */
    out->type_name    = "UNKNOWN";
    out->v_min        = 0;
    out->v_range      = 0;
    out->dest_prefix0 = 0x0000;
  }
}

/* HKDF — derive AES-128 key with domain-separated info "device:<id>|enc". */
static void
derive_enc_key(const uint8_t *master_key, const char *device_id,
               uint8_t *out_key_16)
{
  uint8_t prk[32], expand_input[80], full[32];
  int info_len;
  hmac_sha256_raw(HKDF_SALT, HKDF_SALT_LEN, master_key, 32, prk);
  info_len = snprintf((char *)expand_input, sizeof(expand_input),
                      "device:%s|enc", device_id);
  expand_input[info_len] = 0x01;
  hmac_sha256_raw(prk, 32, expand_input, info_len + 1, full);
  memcpy(out_key_16, full, 16);    /* AES-128 = first 16 bytes of HKDF output */
}

/* Build 13-byte nonce: [device_id (2B BE) || seq (8B BE) || 3B 0x00].       */
static void
build_nonce(uint16_t device_num, uint32_t seq, uint8_t nonce_out[CCM_NONCE_BYTES])
{
  nonce_out[0]  = (device_num >> 8) & 0xff;
  nonce_out[1]  =  device_num       & 0xff;
  nonce_out[2]  = nonce_out[3] = nonce_out[4] = nonce_out[5] = 0x00;
  nonce_out[6]  = (seq >> 24) & 0xff;
  nonce_out[7]  = (seq >> 16) & 0xff;
  nonce_out[8]  = (seq >>  8) & 0xff;
  nonce_out[9]  =  seq        & 0xff;
  nonce_out[10] = nonce_out[11] = nonce_out[12] = 0x00;
}

/* Lower-case hex encoder. */
static void
to_hex(const uint8_t *in, size_t len, char *out)
{
  static const char H[] = "0123456789abcdef";
  size_t i;
  for(i = 0; i < len; i++) {
    out[2*i]     = H[(in[i] >> 4) & 0x0f];
    out[2*i + 1] = H[ in[i]       & 0x0f];
  }
  out[2 * len] = '\0';
}

PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  uip_ipaddr_t dest_ipaddr;
  static uint32_t tx_count;
  static sensor_profile_t profile;          /* (1) survives protothread yields */
  static uint8_t boot_dev_id;
  PROCESS_BEGIN();

  /* ---------- (2) Identity + profile resolution at boot ---------- */
  boot_dev_id = linkaddr_node_addr.u8[LINKADDR_SIZE - 1];
  snprintf(MY_DEVICE_ID, sizeof(MY_DEVICE_ID), "mote-%u", boot_dev_id);
  choose_profile(boot_dev_id, &profile);
  derive_enc_key(MASTER_KEY, MY_DEVICE_ID, MY_ENC_KEY);

  /* ---------- (3) Boot log — single line of truth for verification ---------- */
  LOG_INFO("Device %s — type=%s dest=%04x::1 — AES-128-CCM-8 key derived\n",
           MY_DEVICE_ID,
           profile.type_name ? profile.type_name : "UNKNOWN",
           (unsigned int)profile.dest_prefix0);

  /* ---------- (4) Fail-loud halt for unknown profile ---------- */
  if(profile.dest_prefix0 == 0x0000) {
    LOG_WARN("Device %s has UNKNOWN profile (node-id outside any block) "
             "— refusing to transmit\n", MY_DEVICE_ID);
    /* Stay alive in the simulation so the LOG_WARN remains visible,
     * but never enter the send loop.                                  */
    while(1) {
      etimer_set(&periodic_timer, CLOCK_SECOND * 60);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    }
  }

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, NULL);
  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    if(NETSTACK_ROUTING.node_is_reachable()) {

      /* ---------- (5) Dynamic destination from profile ---------- */
      uip_ip6addr(&dest_ipaddr,
                  profile.dest_prefix0, 0,0,0, 0,0,0, 0x0001);

      /* ---------- (6) Profile-driven synthetic value ---------- */
      long value_centi = profile.v_min + (long)(random_rand() % profile.v_range);
      int  batt        = 50 + (random_rand() % 51);
      const char *type_name = profile.type_name ? profile.type_name : "UNKNOWN";

      char    ad[64], body[64], full_msg[256];
      uint8_t ct[64], nonce[CCM_NONCE_BYTES], tag[CCM_TAG_BYTES];
      char    nonce_hex[CCM_NONCE_HEX + 1];
      char    ct_hex[129], tag_hex[CCM_TAG_HEX + 1];
      int     ad_len, body_len;

      /* Step 1 — Associated Data (cleartext, authenticated).
       *          Includes the sensor type so the gateway can route /
       *          tag the reading without decrypting first.
       *          MUST be reconstructed byte-identically on the gateway.                   */
      ad_len = snprintf(ad, sizeof(ad),
                        "id=%u;seq=%" PRIu32 ";type=%s",
                        boot_dev_id, tx_count, type_name);
      /* Step 2 — Plaintext body: generic "v=XX.YY;batt=ZZ" so the same
       *          field name works for temperature / humidity / pressure.
       *    Body uses generic v= so the wire format is type-agnostic.        */
      body_len = snprintf(body, sizeof(body),
                          "v=%lu.%02lu;batt=%d",
                          (unsigned long)(value_centi / 100),
                          (unsigned long)(value_centi % 100),
                          batt);
                          
      
      /* Step 3 — Build the per-packet 13-byte nonce.                      */                   
      build_nonce((uint16_t)boot_dev_id, tx_count, nonce);

      /* Step 4 — Encrypt + authenticate (custom CCM-8 over tinyAES).      */
      aes_ccm8_encrypt(MY_ENC_KEY, nonce,
                       (const uint8_t *)ad,   (uint16_t)ad_len,
                       (const uint8_t *)body, (uint16_t)body_len,
                       ct, tag);

      /* Step 5 — Hex-encode binary fields for the ASCII wire format.      */
      to_hex(nonce, CCM_NONCE_BYTES, nonce_hex);
      to_hex(ct,    body_len,        ct_hex);
      to_hex(tag,   CCM_TAG_BYTES,   tag_hex);

      /* Step 6 — Assemble the wire message:
       *          id=N;seq=M;type=T;nonce=<hex>;ct=<hex>;tag=<hex>          */
      snprintf(full_msg, sizeof(full_msg),
               "%s;nonce=%s;ct=%s;tag=%s", ad, nonce_hex, ct_hex, tag_hex);

      simple_udp_sendto(&udp_conn, full_msg, strlen(full_msg), &dest_ipaddr);

      LOG_INFO("tx [%s] seq=%" PRIu32 " %s=%lu.%02lu batt=%d\n",
               MY_DEVICE_ID, tx_count,
               type_name,
               (unsigned long)(value_centi / 100),
               (unsigned long)(value_centi % 100),
               batt);
               
      tx_count++;
    }
    etimer_set(&periodic_timer,
      SEND_INTERVAL - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }
  PROCESS_END();
}