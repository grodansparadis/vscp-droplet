/**
 * @brief           VSCP droplet over esp-now code
 * @file            vscp_dropplet.h
 * @author          Ake Hedman, The VSCP Project, www.vscp.org
 *
 *********************************************************************/

/* ******************************************************************************
 * VSCP (Very Simple Control Protocol)
 * http://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright (C) 2000-2022 Ake Hedman,
 * The VSCP Project <info@grodansparadis.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *  This file is part of VSCP - Very Simple Control Protocol
 *  http://www.vscp.org
 *
 * ******************************************************************************
 */

#include "vscp-projdefs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include <freertos/FreeRTOS.h>
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <esp_check.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_crc.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_timer.h>
#include <esp_random.h>

#include <cJSON.h>

#include <vscp.h>
#include <vscp-firmware-helper.h>

#include "vscp-droplet.h"

#define DROPLET_VERSION              1
#define DROPLET_MSG_CACHE_SIZE       32
#define DROPLET_DISCOVERY_CACHE_SIZE 64



static const char *TAG                   = "vscp_droplet_alpha";
static bool g_set_channel_flag           = true;
static droplet_config_t g_droplet_config = { 0 };

static wifi_country_t g_self_country = { 0 };

#define DROPLET_MAX_BUFFERED_NUM                                                                                       \
  (CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM / 2) /* Not more than CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM */

// This mutex protects the espnow_send as it is NOT thread safe
static SemaphoreHandle_t s_droplet_send_lock;

// Free running counter that is updated for every send
static uint8_t g_droplet_sendSequence = 0;

static EventGroupHandle_t g_droplet_event_group = NULL;

// Number of send events in transit
static uint32_t g_droplet_buffered_num = 0;

static QueueHandle_t g_droplet_queue = NULL;

#define DROPLET_SEND_CB_OK   BIT0
#define DROPLET_SEND_CB_FAIL BIT1

static struct {
  uint16_t magic;
} __attribute__((packed)) g_droplet_magic_cache[DROPLET_MSG_CACHE_SIZE] = { 0 };

static uint8_t g_droplet_magic_cache_next = 0;

/*!
  The discovery cache holds all nodes this node has discovered by there
  heartbeats.
*/
static struct {
  uint8_t mac[6];
} __attribute__((packed)) g_droplet_discovery_cache[DROPLET_DISCOVERY_CACHE_SIZE] = { 0 };

/**
 * @brief Receive data packet temporarily store in queue
 */
typedef struct {
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  uint8_t dest_addr[6];
  uint8_t src_addr[6];
  uint8_t size;
  uint8_t payload[0];
} droplet_rxpkt_t;

/**
 * @brief Send and receive statistics
 *
 */
typedef struct {
  uint32_t nSend;            // # sent frames
  uint32_t nSendFailures;    // Number of send failures
  uint32_t nSendLock;        // Number of send lock give ups
  uint32_t nSendAck;         // # of failed send confirms
  uint32_t nRecv;            // # received frames
  uint32_t nRecvOverruns;    // Number of receive overruns
  uint32_t nRecvFrameFault;  // Frame to big or to small
  uint32_t nRecvAdjChFilter; // Adjacent channel filter
  uint32_t nRecvŔssiFilter;  // RSSI filter stats
  uint32_t nForw;            // # Number of forwarded frames
} droplet_stats_t;

static droplet_stats_t g_droppletStats = { 0 };

static uint8_t DROPLET_ADDR_SELF[6] = { 0 };

const uint8_t DROPLET_ADDR_NONE[6]       = { 0 };
const uint8_t DROPLET_ADDR_BROADCAST[6]  = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0XFF };
const uint8_t DROPLET_ADDR_GROUP_VSCP[6] = { 'V', 'S', 'C', 'P', 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_PROV[6] = { 'P', 'R', 'O', 'V', 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_SEC[6]  = { 'S', 'E', 'C', 0x0, 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_OTA[6]  = { 'O', 'T', 'A', 0x0, 0x0, 0x0 };

static uint8_t s_vscp_zero_guid[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

vscp_event_handler_cb_t g_vscp_event_handler_cb = NULL;
// Forward declarations

static void
droplet_task(void *arg);
static void
droplet_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status);
static void
droplet_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len);

//-----------------------------------------------------------------------------
//                                Droplet
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// droplet_init
//

// void read_discovery_cache()
// {
//   size_t length  = nvs_get_blob(g_nvsHandle, "discovery-cache", g_droplet_discovery_cache, &length);
// }

///////////////////////////////////////////////////////////////////////////////
// droplet_init
//

esp_err_t
droplet_init(const droplet_config_t *config)
{
  // esp_err_t ret = ESP_FAIL;

  // ESP_ERROR_CHECK(config);
  memcpy(&g_droplet_config, config, sizeof(droplet_config_t));

  g_droplet_queue = xQueueCreate(g_droplet_config.sizeQueue, sizeof(droplet_rxpkt_t *));
  if (!g_droplet_queue) {
    ESP_LOGD(TAG, "Create droplet event queue fail");
    return ESP_FAIL;
  }

  // Event group for droplet sent cb
  g_droplet_event_group = xEventGroupCreate();
  ESP_RETURN_ON_ERROR(!g_droplet_event_group, TAG, "Create event group fail");

  s_droplet_send_lock = xSemaphoreCreateMutex();
  ESP_RETURN_ON_ERROR(!s_droplet_send_lock, TAG, "Create send semaphore mutex fail");

  // Initialize DROPLET function
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_send_cb(droplet_send_cb));
  ESP_ERROR_CHECK(esp_now_register_recv_cb(droplet_recv_cb));
  ESP_ERROR_CHECK(esp_now_set_wake_window(65535));
  ESP_ERROR_CHECK(esp_now_set_pmk(config->pmk));

  // ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL));

  esp_wifi_get_country(&g_self_country);
  esp_wifi_get_mac(ESP_IF_WIFI_STA, DROPLET_ADDR_SELF);
  ESP_LOGD(TAG, "mac: " MACSTR ", version: %d", MAC2STR(DROPLET_ADDR_SELF), DROPLET_VERSION);

  // Add broadcast peer information to peer list.
  esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
  if (NULL == peer) {
    ESP_LOGE(TAG, "Malloc peer information fail");
    // vSemaphoreDelete(s_vscp_droplet_event_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memset(peer, 0, sizeof(esp_now_peer_info_t));
  peer->channel = DROPLET_CHANNEL;
  peer->ifidx   = DROPLET_WIFI_IF;
  peer->encrypt = false;
  memcpy(peer->peer_addr, DROPLET_ADDR_BROADCAST, ESP_NOW_ETH_ALEN);
  ESP_ERROR_CHECK(esp_now_add_peer(peer));
  free(peer);

  // Init droplet system
  droplet_sec_init();

  xTaskCreate(droplet_task, "droplet tast", 4096, NULL, 5, NULL);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_task
//

static void
droplet_task(void *arg)
{
  esp_err_t ret            = ESP_FAIL;
  droplet_rxpkt_t *prxdata = NULL;
  bool bRun                = true;
  size_t size              = 0;

  ESP_LOGI(TAG, "droplet task entry");

  while (bRun) {

    if (xQueueReceive(g_droplet_queue, &(prxdata), portMAX_DELAY) != pdTRUE) {
      ESP_LOGE(TAG, "Failed to get receive data from queue");
      continue;
    }

    g_droppletStats.nRecv++; // Update receive frame statistics

    // uint32_t hf = esp_get_free_heap_size();
    // heap_caps_check_integrity_all(true);
    // ESP_LOGI(TAG, "Event received heap=%X", (unsigned int) hf);

    size = prxdata->size;

    if (prxdata == NULL) {
      ESP_LOGE(TAG, "Receive event data is NULL");
      continue;
    }

    // Allocate space for data
    uint8_t *pdata = malloc(prxdata->size);

    // * * * Decrypt frame if needed * * *

    if (prxdata->payload[DROPLET_POS_PKTID] == VSCP_ENCRYPTION_AES128) {

      if (VSCP_ERROR_SUCCESS != vscp_fwhlp_decryptFrame(pdata,
                                                        prxdata->payload,
                                                        prxdata->size,
                                                        g_droplet_config.pmk, // key
                                                        NULL,                 // IV  - use embedded
                                                        VSCP_ENCRYPTION_FROM_TYPE_BYTE)) {
        ESP_LOGE(TAG, "Failed to decrypt frame");
        free(pdata);
        free(prxdata);
        continue;
      }

      size -= 16; // no need to send the old IV
      memcpy(prxdata->payload, pdata, size);
    }

    free(pdata);

    // Check if we have already received this frame
    for (size_t i = 0, index = g_droplet_magic_cache_next; i < DROPLET_MSG_CACHE_SIZE;
         i++, index          = (g_droplet_magic_cache_next + i) % DROPLET_MSG_CACHE_SIZE) {
      if (g_droplet_magic_cache[index].magic == prxdata->payload[DROPLET_POS_MAGIC]) {
        ESP_LOGI(TAG, "Frame is already in cache");
        free(prxdata);
        continue;
      }
    }

    // Store magic in cache
    g_droplet_magic_cache[g_droplet_magic_cache_next].magic =
      (prxdata->payload[DROPLET_POS_MAGIC] << 8) + prxdata->payload[DROPLET_POS_MAGIC + 1];
    g_droplet_magic_cache_next = (g_droplet_magic_cache_next + 1) % DROPLET_MSG_CACHE_SIZE;

    uint8_t ttl                       = --prxdata->payload[DROPLET_POS_TTL];
    prxdata->payload[DROPLET_POS_TTL] = ttl;

    // Destination address can't be a pointer as it will be encrypted if
    // encryption is enabled in frame
    uint8_t dest_addr[6];
    memcpy(dest_addr, prxdata->payload + DROPLET_POS_DEST_ADDR, 6);

    // if ttl is zero or frame is addressed to us don't forward
    if (g_droplet_config.bForwardEnable && ttl /*&& DROPLET_ADDR_IS_SELF(prxdata->payload[DROPLET_POS_DEST_ADDR])*/) {
      if (ESP_OK == (ret = droplet_send(dest_addr, true, false, 0, prxdata->payload, size, 20))) {
        g_droppletStats.nForw++; // Update forward frame statistics
      }
      else {
        ESP_LOGE(TAG, "Failed to forward event ret=%X", ret);
        g_droppletStats.nSendFailures++; // Update send failures
      }
    }

    // Handle event callback
    if (NULL != g_vscp_event_handler_cb) {
      vscpEventEx ex;
      g_vscp_event_handler_cb(&ex, NULL);
    }

    free(prxdata);
  } // while

  // Empty queue
  while (xQueueReceive(g_droplet_queue, &(prxdata), 0)) {
    free(prxdata);
  }

  vQueueDelete(g_droplet_queue);
  g_droplet_queue = NULL;

  ESP_LOGI(TAG, "main task exit");
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// droplet_send_cb
//
// DROPLET sending or receiving callback function is called in WiFi task.
// Users should not do lengthy operations from this task. Instead, post
// necessary data to a queue and handle it from a lower priority task.
//

static void
droplet_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  // Must be an address
  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  // There is room for more data
  if (g_droplet_buffered_num) {
    g_droplet_buffered_num--;
  }

  if (status == ESP_NOW_SEND_SUCCESS) {
    xEventGroupSetBits(g_droplet_event_group, DROPLET_SEND_CB_OK);
  }
  else {
    xEventGroupSetBits(g_droplet_event_group, DROPLET_SEND_CB_FAIL);
  }
}

///////////////////////////////////////////////////////////////////////////////
// droplet_recv_cb
//

static void
droplet_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
{
  if (mac_addr == NULL || data == NULL || len <= 0) {
    ESP_LOGE(TAG, "Receive cb arg error");
    return;
  }

  // Check that frame length is within limits
  if ((len < DROPLET_MIN_FRAME) || (len > DROPLET_MAX_FRAME) || (data[0] > VSCP_ENCRYPTION_AES256)) {
    ESP_LOGE(TAG, "Frame length is invalid len=%d", len);
    g_droppletStats.nRecvFrameFault++; // Increase receive frame faults
    return;
  }

  // uint8_t *droplet_data = (uint8_t *) data;
  wifi_promiscuous_pkt_t *promiscuous_pkt = (wifi_promiscuous_pkt_t *) (data - sizeof(wifi_pkt_rx_ctrl_t));
  wifi_pkt_rx_ctrl_t *rx_ctrl             = &promiscuous_pkt->rx_ctrl;

  // ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_INFO);

  // Channel filtering
  if (g_droplet_config.bFilterAdjacentChannel && g_droplet_config.channel != rx_ctrl->channel) {
    ESP_LOGD(TAG, "Filter adjacent channels, %d != %d", g_droplet_config.channel, rx_ctrl->channel);
    g_droppletStats.nRecvAdjChFilter++; // Incrice adjacent channel filter stats
    return;
  }

  // RSSI filtering
  if (g_droplet_config.filterWeakSignal && g_droplet_config.filterWeakSignal > rx_ctrl->rssi) {
    ESP_LOGD(TAG, "Filter weak signal strength, %d > %d", g_droplet_config.filterWeakSignal, rx_ctrl->rssi);
    g_droppletStats.nRecvŔssiFilter++; // Increas RSSI filter stats
    return;
  }

  droplet_rxpkt_t *q_data = malloc(sizeof(droplet_rxpkt_t) + len);
  if (NULL == q_data) {
    ESP_LOGD(TAG, "Failed to allocate data.");
    return;
  }
  // memcpy(&q_data->dest_addr, droplet_data->dest_addr, 6);
  // memcpy(&q_data->src_addr, droplet_data->src_addr, 6);
  memcpy(&q_data->rx_ctrl, rx_ctrl, sizeof(wifi_pkt_rx_ctrl_t));
  memcpy(&q_data->payload, data, len);
  q_data->size = len;
  memcpy(q_data->src_addr, mac_addr, 6);

  // If a specific channel set, make rx data using it
  if (g_droplet_config.channel && g_droplet_config.channel != DROPLET_CHANNEL_ALL) {
    q_data->rx_ctrl.channel = g_droplet_config.channel;
  }

  if (xQueueSend(g_droplet_queue, &q_data, 0) != pdPASS) {
    ESP_LOGW(TAG, "[%s, %d] Send event queue failed. errQUEUE_FULL", __func__, __LINE__);
    free(q_data);
    g_droppletStats.nRecvOverruns++; // Receive overrrun
    return;
  }
}

///////////////////////////////////////////////////////////////////////////////
// droplet_send
//

esp_err_t
droplet_send(const uint8_t *dest_addr,
             bool bPreserveHeader,
             bool bEncrypt,
             uint8_t ttl,
             uint8_t *payload,
             size_t size,
             TickType_t wait_ticks)
{
  if (NULL == dest_addr) {
    ESP_LOGE(TAG, "destination address pointer invalid");
    return ESP_ERR_INVALID_ARG;
  }

  if (NULL == payload) {
    ESP_LOGE(TAG, "data pointer invalid");
    return ESP_ERR_INVALID_ARG;
  }

  if (size > DROPLET_MAX_FRAME) {
    ESP_LOGE(TAG, "frame size is invalid");
    return ESP_ERR_INVALID_ARG;
  }

  static uint8_t seq     = 0;
  esp_err_t ret          = ESP_FAIL;
  TickType_t write_ticks = 0;
  uint32_t start_ticks   = xTaskGetTickCount();
  uint8_t *outbuf        = NULL;
  bool bBroadcast        = (0 == memcmp(dest_addr, DROPLET_ADDR_BROADCAST, ESP_NOW_ETH_ALEN));
  size_t frame_len       = size;

  if (bPreserveHeader) {
    // Let pktid byte decide if we should encrypt or not
    bEncrypt = payload[DROPLET_POS_PKTID] ? true : false;
  }
  else {

    // ttl
    payload[DROPLET_POS_TTL] = ttl;

    // Magic word
    esp_fill_random((payload + DROPLET_POS_MAGIC), 2);

    // Set destination address
    memcpy(payload + DROPLET_POS_DEST_ADDR, dest_addr, ESP_NOW_ETH_ALEN);

    // Add frame sequency to VSCP header
    payload[DROPLET_POS_HEAD + 1] = (payload[DROPLET_POS_HEAD + 1] & 0xf8) + seq++;
  }

  // Encrypt data if needed. IV will be placed at end of data
  // | id | encrypted-data | IV |
  if (bEncrypt) {

    // Fill in iv at end of send frame
    uint8_t *iv = malloc(16);
    esp_fill_random(iv, DROPLET_IV_LEN);

    // Encrypt send frame
    outbuf = malloc(size + (16 - (size % 16) + 16) + 1); // size + padding + iv + coding byte

    payload[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_AES128;

    // uint64_t start = esp_timer_get_time();
    if (0 == (frame_len = vscp_fwhlp_encryptFrame(outbuf,
                                                  payload,
                                                  size,
                                                  g_droplet_config.pmk, // key
                                                  iv,                   // IV
                                                  VSCP_ENCRYPTION_AES128))) {
      ESP_LOGE(TAG, "Failed to encrypt frame");
      free(iv);
      free(outbuf);
      return ESP_FAIL;
    }
    // printf("Encrypt %d %lld\n", size, esp_timer_get_time() - start);

    // Decryption test printout
    if (0) {
      uint8_t yyy[frame_len + 16];
      if (VSCP_ERROR_SUCCESS != vscp_fwhlp_decryptFrame(yyy,
                                                        outbuf,
                                                        frame_len,
                                                        g_droplet_config.pmk, // key
                                                        NULL,                 // IV  - use embedded
                                                        VSCP_ENCRYPTION_FROM_TYPE_BYTE)) {
        ESP_LOGE(TAG, "Failed to decrypt frame");
        free(outbuf);
        free(iv);
        return ESP_FAIL;
      }

      ESP_LOG_BUFFER_HEX("DEC", yyy, frame_len);
    }
  }
  // If not encrypted
  else {
    outbuf = malloc(size);
    memcpy(outbuf, payload, size);
    outbuf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_NONE;
  }

  /**< Wait for other tasks to be sent before send ESP-NOW data */
  if (xSemaphoreTake(s_droplet_send_lock, pdMS_TO_TICKS(wait_ticks)) != pdPASS) {
    ESP_LOGE(TAG, "Timeout trying to get send lock.");
    free(outbuf);
    g_droppletStats.nSendLock++; // Increase send lock failure counter
    return ESP_ERR_TIMEOUT;
  }

  xEventGroupClearBits(g_droplet_event_group, DROPLET_SEND_CB_OK | DROPLET_SEND_CB_FAIL);

  ret = esp_now_send(dest_addr, outbuf, frame_len);
  if (ret == ESP_OK) {

    write_ticks = (wait_ticks == portMAX_DELAY)                    ? portMAX_DELAY
                  : xTaskGetTickCount() - start_ticks < wait_ticks ? wait_ticks - (xTaskGetTickCount() - start_ticks)
                                                                   : 0;
    g_droplet_buffered_num++;

    // Wait send cb if no room for frames
    if (g_droplet_buffered_num >= DROPLET_MAX_BUFFERED_NUM) {
      EventBits_t uxBits = xEventGroupWaitBits(g_droplet_event_group,
                                               DROPLET_SEND_CB_OK | DROPLET_SEND_CB_FAIL,
                                               pdTRUE,
                                               pdFALSE,
                                               wait_ticks);
      if ((uxBits & DROPLET_SEND_CB_OK) == DROPLET_SEND_CB_OK) {
        ret = ESP_OK;
      }
      else {
        ESP_LOGE(TAG, "Timeout waiting for send status.");
        g_droppletStats.nSendAck++; // Increase sendack failures
        ret = ESP_FAIL;
      }
    }
  }
  else {
    ESP_LOGE(TAG, "Failed to send frame err=%X", (int) ret);
  }

  xSemaphoreGive(s_droplet_send_lock);
  free(outbuf);

  return ret;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_set_vscp_handler_cb
//

void
droplet_set_vscp_handler_cb(vscp_event_handler_cb_t *cb)
{
  g_vscp_event_handler_cb = cb;
}

//-----------------------------------------------------------------------------
//                                Security
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// droplet_sec_init
//

esp_err_t
droplet_sec_init(void)
{
  // memset(&s_vscp_espnow_sec, 0, sizeof(vscp_espnow_sec_t));
  // s_vscp_espnow_sec.cipher_ctx = (mbedtls_ccm_context *) calloc(1, sizeof(mbedtls_ccm_context));

  // mbedtls_ccm_init((mbedtls_ccm_context *) &s_vscp_espnow_sec.cipher_ctx);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sec_deinit
//

esp_err_t
droplet_sec_deinit(void)
{
  // if (s_vscp_espnow_sec.cipher_ctx) {
  //   mbedtls_ccm_free((mbedtls_ccm_context *) s_vscp_espnow_sec.cipher_ctx);
  //   free(s_vscp_espnow_sec.cipher_ctx);
  // }
  // memset(&s_vscp_espnow_sec, 0, sizeof(vscp_espnow_sec_t));

  vEventGroupDelete(g_droplet_event_group);
  g_droplet_event_group = NULL;

  esp_now_deinit();

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sec_setkey
//

esp_err_t
droplet_sec_setkey(void)
{
  // ESP_ERROR_CHECK(app_key);
  // ESP_ERROR_CHECK(s_vscp_espnow_sec.cipher_ctx);

  // int ret = mbedtls_ccm_setkey((mbedtls_ccm_context *) s_vscp_espnow_sec.cipher_ctx,
  //                              MBEDTLS_CIPHER_ID_AES,
  //                              app_key,
  //                              8 * s_vscp_espnow_sec.key_len);
  // ESP_RETURN_ON_ERROR(ret != ESP_OK, TAG, "mbedtls_ccm_setkey %x", ret);

  // memcpy(s_vscp_espnow_sec.key, app_key, s_vscp_espnow_sec.key_len);
  // memcpy(s_vscp_espnow_sec.iv, app_key + s_vscp_espnow_sec.key_len, s_vscp_espnow_sec.iv_len);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sec_auth_encrypt
//

esp_err_t
droplet_sec_auth_encrypt(const uint8_t *input,
                         size_t ilen,
                         uint8_t *output,
                         size_t output_len,
                         size_t *olen,
                         size_t tag_len)
{
  // ESP_ERROR_CHECK(input);
  // ESP_ERROR_CHECK(ilen);
  // ESP_ERROR_CHECK(output);
  // ESP_ERROR_CHECK(olen);
  // ESP_ERROR_CHECK(output_len >= ilen + tag_len);
  // ESP_ERROR_CHECK(tag_len);

  int ret = ESP_OK;
  // ret     = mbedtls_ccm_encrypt_and_tag((mbedtls_ccm_context *) s_vscp_espnow_sec.cipher_ctx,
  //                                   ilen,
  //                                   s_vscp_espnow_sec.iv,
  //                                   s_vscp_espnow_sec.iv_len,
  //                                   NULL,
  //                                   0,
  //                                   input,
  //                                   output,
  //                                   output + ilen,
  //                                   tag_len);
  // *olen   = ilen + tag_len;

  if (ret != 0) {
    ESP_LOGE(TAG, "Failed at mbedtls_ccm_encrypt_and_tag with error code : %d", ret);
    return ESP_FAIL;
  }

  return ret;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sec_auth_decrypt
//

esp_err_t
droplet_sec_auth_decrypt(const uint8_t *input,
                         size_t ilen,
                         uint8_t *output,
                         size_t output_len,
                         size_t *olen,
                         size_t tag_len)
{
  // ESP_ERROR_CHECK(input);
  // ESP_ERROR_CHECK(ilen);
  // ESP_ERROR_CHECK(output);
  // ESP_ERROR_CHECK(olen);
  // ESP_ERROR_CHECK(ilen > tag_len);
  // ESP_ERROR_CHECK(output_len >= ilen - tag_len);
  // ESP_ERROR_CHECK(tag_len);

  int ret = ESP_OK;
  ilen -= tag_len;
  // ret   = mbedtls_ccm_auth_decrypt((mbedtls_ccm_context *) s_vscp_espnow_sec.cipher_ctx,
  //                                ilen-16,   // iv not part of data
  //                                input-16,  // iv is at end of frame
  //                                16,        // iv is always sixteen bytes
  //                                NULL,
  //                                0,
  //                                input,
  //                                output,
  //                                input + ilen,
  //                                tag_len);
  *olen = ilen;

  if (ret != 0) {
    ESP_LOGE(TAG, "Failed at mbedtls_ccm_auth_decrypt with error code : %d", ret);
    return ESP_FAIL;
  }

  return ret;
}

// ----------------------------------------------------------------------------
//                                  VSCP
// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// droplet_build_guid_from_mac
//

int
droplet_build_guid_from_mac(uint8_t *pguid, const uint8_t *pmac, uint16_t nickname)
{
  uint8_t prebytes[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };

  // Need a GUID pointer
  if (NULL == pguid) {
    ESP_LOGE(TAG, "Pointer to GUID is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Need a mac pointer
  if (NULL == pmac) {
    ESP_LOGE(TAG, "Pointer to mac address is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  memcpy(pguid, prebytes, 8);
  memcpy(pguid + 8, pmac, 6);
  pguid[14] = (nickname << 8) & 0xff;
  pguid[15] = nickname & 0xff;

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_build_l1_heartbeat
//

int
droplet_build_l1_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (DROPLET_MIN_FRAME + 3)) {
    ESP_LOGE(TAG, "Size of byffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Construct VSCP heart beat event

  // Unencrypted packet id
  buf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_NONE;

  // VSCP Head
  buf[DROPLET_POS_HEAD]     = 0x00;
  buf[DROPLET_POS_HEAD + 1] = 0x00;

  // Nickname
  if (NULL != pguid) {
    buf[DROPLET_POS_NICKNAME]     = (PROJDEF_NODE_NICKNAME >> 8) & 0xff;
    buf[DROPLET_POS_NICKNAME + 1] = PROJDEF_NODE_NICKNAME & 0xff;
  }

  // VSCP Class
  buf[DROPLET_POS_CLASS]     = (VSCP_CLASS1_INFORMATION >> 8) & 0xff;
  buf[DROPLET_POS_CLASS + 1] = VSCP_CLASS1_INFORMATION & 0xff;

  // VSCP Type
  buf[DROPLET_POS_TYPE]     = (VSCP_TYPE_INFORMATION_NODE_HEARTBEAT >> 8) & 0xff;
  buf[DROPLET_POS_TYPE + 1] = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT & 0xff;

  buf[DROPLET_POS_SIZE] = 3;

  // Data
  buf[DROPLET_POS_DATA]     = 0;    // User specific
  buf[DROPLET_POS_DATA + 1] = 0xff; // All zones
  buf[DROPLET_POS_DATA + 2] = 0xff; // All subzones

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_build_l2_heartbeat
//

int
droplet_build_l2_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid, const char *name)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (DROPLET_MIN_FRAME + 3)) {
    ESP_LOGE(TAG, "Size of byffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Construct VSCP heart beat event

  // Packet id VSCP
  buf[0] = (VSCP_DEFAULT_TCP_PORT >> 8) & 0xff;
  buf[1] = VSCP_DEFAULT_TCP_PORT & 0xff;

  // Head
  buf[2] = 0;
  buf[3] = 0;

  // Nickname
  if (NULL != pguid) {
    buf[4] = pguid[14]; // (g_node_nickname >> 8) & 0xff;
    buf[5] = pguid[15]; // g_node_nickname & 0xff;
  }

  // VSCP Class
  buf[6] = (VSCP_CLASS1_INFORMATION >> 8) & 0xff;
  buf[7] = VSCP_CLASS1_INFORMATION & 0xff;

  // VSCP Type
  buf[8] = (VSCP_TYPE_INFORMATION_NODE_HEARTBEAT >> 8) & 0xff;
  buf[9] = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT & 0xff;

  // Data
  buf[10] = 0;    // User specific
  buf[11] = 0xff; // All zones
  buf[12] = 0xff; // All subzones

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_exToFrame
//

int
droplet_exToFrame(uint8_t *buf, uint8_t len, const vscpEventEx *pex)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Need event
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (DROPLET_MIN_FRAME + pex->sizeData)) {
    ESP_LOGE(TAG, "Size of buffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Packet id VSCP
  buf[0] = (VSCP_DEFAULT_TCP_PORT >> 8) & 0xff;
  buf[1] = VSCP_DEFAULT_TCP_PORT & 0xff;

  // head
  buf[2] = (pex->head >> 8) & 0xff;
  buf[3] = pex->head & 0xff;

  // nickname
  buf[4] = pex->GUID[14];
  buf[5] = pex->GUID[15];

  // vscp-class
  buf[6] = (pex->vscp_class >> 8) & 0xff;
  buf[7] = pex->vscp_class & 0xff;

  // vscp-type
  buf[8] = (pex->vscp_type >> 8) & 0xff;
  buf[9] = pex->vscp_type & 0xff;

  // data
  memcpy((buf + 10), pex->data, pex->sizeData);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_frameToEx
//

int
droplet_frameToEx(vscpEventEx *pex, const uint8_t *buf, uint8_t len, uint32_t timestamp)
{
  // Need event
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must at least have min size
  if (len < DROPLET_MIN_FRAME) {
    ESP_LOGE(TAG, "esp-now data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  // First two bytes of buffer must be VSCP magic bytes, if not
  // this is not a VSCP frame
  if (!(buf[0] == ((VSCP_DEFAULT_TCP_PORT >> 8) & 0xff)) || !(buf[1] == (VSCP_DEFAULT_TCP_PORT & 0xff))) {
    ESP_LOGE(TAG, "esp-now data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  memset(pex, 0, sizeof(vscpEventEx));

  // Set VSCP size
  pex->sizeData = len - DROPLET_MIN_FRAME;

  // Copy in VSCP data
  memcpy(pex->data, buf + DROPLET_MIN_FRAME, pex->sizeData);

  // Set timestamp if not set
  if (!timestamp) {
    pex->timestamp = esp_timer_get_time();
  }

  // Head
  pex->head = (buf[2] << 8) + buf[3];

  // Nickname
  pex->GUID[14] = buf[4];
  pex->GUID[15] = buf[5];

  // VSCP class
  pex->vscp_class = (buf[6] << 8) + buf[7];

  // VSCP type
  pex->vscp_type = (buf[8] << 8) + buf[9];

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_parse_vscp_json
//
// // https://github.com/nopnop2002/esp-idf-json
/*
{
  "vscpHead":3,
  "vscpClass":10,
  "vscpType":6,
  "vscpGuid":"FF:FF:FF:FF:FF:FF:FF:FE:B8:27:EB:CF:3A:15:00:01",
  "vscpObId":11,
  "vscpTimeStamp":467530633,
  "vscpDateTime":"2022-12-16T16:41:02.000Z",
  "vscpData":[72,51,57,46,55,48,52],
  "measurement": {
    "value":39.704,
    "unit":1,
    "sensorindex":0,
    "index":0,
    "zone":0,
    "subzone":0
  }
}
*/

int
droplet_parse_vscp_json(const char *jsonVscpEventObj, vscpEventEx *pex)
{
  int rv;
  cJSON *root = cJSON_Parse(jsonVscpEventObj);

  if (cJSON_GetObjectItem(root, "vscpHead")) {
    pex->head = (uint16_t) cJSON_GetObjectItem(root, "vscpHead")->valueint;
    ESP_LOGD(TAG, "vscpHead=%u", pex->head);
  }

  if (cJSON_GetObjectItem(root, "vscpObId")) {
    pex->obid = (uint32_t) cJSON_GetObjectItem(root, "vscpObId")->valuedouble;
    ESP_LOGD(TAG, "pex->obid=%lu", pex->obid);
  }

  // "2017-01-13T10:16:02",
  if (cJSON_GetObjectItem(root, "vscpDateTime")) {
    int year, month, day, hour, minute, second;
    const char *str = cJSON_GetObjectItem(root, "vscpDateTime")->valuestring;
    ESP_LOGD(TAG, "vscpDateTime=%s", str);
    sscanf(str, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
    pex->year   = year;
    pex->month  = month;
    pex->day    = day;
    pex->hour   = hour;
    pex->minute = minute;
    pex->second = second;
    ESP_LOGD(TAG, "%d-%02d-%02dT%02d:%02d:%02d", pex->year, pex->month, pex->day, pex->hour, pex->minute, pex->second);
  }

  if (cJSON_GetObjectItem(root, "vscpTimeStamp")) {
    pex->timestamp = (uint32_t) cJSON_GetObjectItem(root, "vscpTimeStamp")->valuedouble;
    ESP_LOGD(TAG, "vscpTimeStamp=%lu", pex->timestamp);
  }

  if (cJSON_GetObjectItem(root, "vscpClass")) {
    pex->vscp_class = (uint16_t) cJSON_GetObjectItem(root, "vscpClass")->valueint;
    ESP_LOGD(TAG, "vscpClass=%u", pex->vscp_class);
  }

  if (cJSON_GetObjectItem(root, "vscpType")) {
    pex->vscp_type = (uint16_t) cJSON_GetObjectItem(root, "vscpType")->valueint;
    ESP_LOGD(TAG, "vscpType=%u", pex->vscp_type);
  }

  if (cJSON_GetObjectItem(root, "vscpGuid")) {
    const char *str = cJSON_GetObjectItem(root, "vscpGuid")->valuestring;
    if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseGuid(pex->GUID, str, NULL))) {
      ESP_LOGD(TAG, "Failed to parse GUID");
      return rv;
    }
    ESP_LOGD(TAG, "vscpGuid=%s", str);
  }

  if (cJSON_GetObjectItem(root, "vscpData")) {

    cJSON *pdata = cJSON_GetObjectItem(root, "vscpData");
    pex->sizeData     = cJSON_GetArraySize(pdata);
    ESP_LOGD(TAG, "VSCP data size=%d", pex->sizeData);
    for (int i = 0; i < pex->sizeData; i++) {
      cJSON *pitem = cJSON_GetArrayItem(pdata, i);
      if (pitem->type == cJSON_Number && i < 512) {
        pex->data[i] = pitem->valueint;
        ESP_LOGD(TAG, "data%d=%u", i, pitem->valueint);
      }
    }

  }

  cJSON_Delete(root);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_parse_vscp_json
//
// https://github.com/nopnop2002/esp-idf-json
//

int
droplet_create_vscp_json(char *strObj, vscpEventEx *pex)
{
  int rv;
  char str[80];
  cJSON *root = cJSON_CreateObject();

  cJSON_AddNumberToObject(root, "vscpHead", pex->head);
  cJSON_AddNumberToObject(root, "vscpClass", pex->vscp_class);
  cJSON_AddNumberToObject(root, "vscpType", pex->vscp_type);
  cJSON_AddNumberToObject(root, "vscpObid", pex->obid);
  cJSON_AddNumberToObject(root, "vscpTimeStamp", pex->timestamp);
  vscp_fwhlp_writeGuidToString(str, pex->GUID);
  cJSON_AddStringToObject(root, "vscpGUID", str);
  sprintf(str, "%04d-%02d-%02dT%02d:%02d:%02d", pex->year, pex->month, pex->day, pex->hour, pex->minute, pex->second);
  cJSON_AddStringToObject(root, "vscpDateTime", str);
  cJSON *array;
  array = cJSON_AddArrayToObject(root, "vscpData");
  cJSON *element;
  for (int i = 0; i < pex->sizeData; i++) {
    element = cJSON_CreateNumber(pex->data[i]);
    cJSON_AddItemToArray(array, element);
  }
  char *json_string = cJSON_Print(root);
  if (NULL != json_string) {
    ESP_LOGD(TAG, "%s", json_string);
    strcpy(strObj, json_string);   
  }
  cJSON_free(json_string);
  cJSON_Delete(root);
  
  return VSCP_ERROR_SUCCESS;
}