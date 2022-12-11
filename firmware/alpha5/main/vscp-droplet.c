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

// #include <mbedtls/aes.h>
// #include <mbedtls/ccm.h>

#include <vscp.h>
#include <vscp-firmware-helper.h>
#include "vscp-droplet.h"

#define DROPLET_VERSION               1
#define DROPLET_MSG_CACHE             32
#define DROPLET_SEND_DELAY_UNIT_MSECS 2

static const char *TAG                   = "vscp_droplet_alpha";
static bool g_set_channel_flag           = true;
static droplet_config_t g_droplet_config = { 0 };

static wifi_country_t g_self_country = { 0 };

#define DROPLET_SEND_DELAY_UNIT_MSECS 2
#define DROPLET_MAX_BUFFERED_NUM                                                                                       \
  (CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM / 2) /* Not more than CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM */

typedef struct droplet_recv_handle {
  uint8_t type;
  bool enable;
  type_handle_t handle;
} droplet_recv_handle_t;

// Receive handle
static droplet_recv_handle_t g_droplet_recv_handle;

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
} __attribute__((packed)) g_droplet_magic_cache[DROPLET_MSG_CACHE] = { 0 };

/**
 * @brief Receive data packet temporarily store in queue
 */
typedef struct {
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  // uint8_t dest_addr[6];
  // uint8_t src_addr[6];
  uint8_t size;
  uint8_t payload[0];
} droplet_rxpkt_t;

typedef struct {
  uint8_t size;
  // uint8_t dest_addr[6];
  // uint8_t src_addr[6];
  uint8_t payload[0];
} __attribute__((packed)) droplet_data_t;

/*
  frames received are handle by the main task which work
  on it's event queue
*/
typedef enum {
  DROPLET_EVENT_FORWARD,
  DROPLET_EVENT_RECEIVE,
  DROPLET_EVENT_STOP,
} droplet_msg_id_t;

typedef struct {
  droplet_msg_id_t id;
  size_t size;
  void *data;
  void *handle;
} droplet_event_ctx_t;

static uint8_t DROPLET_ADDR_SELF[6] = { 0 };

const uint8_t DROPLET_ADDR_NONE[6]       = { 0 };
const uint8_t DROPLET_ADDR_BROADCAST[6]  = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0XFF };
const uint8_t DROPLET_ADDR_GROUP_VSCP[6] = { 'V', 'S', 'C', 'P', 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_PROV[6] = { 'P', 'R', 'O', 'V', 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_SEC[6]  = { 'S', 'E', 'C', 0x0, 0x0, 0x0 };
const uint8_t DROPLET_ADDR_GROUP_OTA[6]  = { 'O', 'T', 'A', 0x0, 0x0, 0x0 };

static uint8_t g_droplet_magic_cache_next = 0;

static uint8_t s_vscp_zero_guid[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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

esp_err_t
droplet_init(const droplet_config_t *config)
{
  esp_err_t ret = ESP_FAIL;

  // ESP_ERROR_CHECK(config);
  memcpy(&g_droplet_config, config, sizeof(droplet_config_t));

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
  ESP_LOGI(TAG, "mac: " MACSTR ", version: %d", MAC2STR(DROPLET_ADDR_SELF), DROPLET_VERSION);

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

  if (g_droplet_config.sizeQueue) {
    g_droplet_queue = xQueueCreate(g_droplet_config.sizeQueue, sizeof(droplet_event_ctx_t));
    ESP_GOTO_ON_ERROR(!g_droplet_queue, EXIT, TAG, "Create droplet event queue fail");
  }

  g_droplet_recv_handle.enable = true;

EXIT:

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_task
//

static void
droplet_task(void *arg)
{
  droplet_event_ctx_t evt_data = { 0 };
  bool bRun                    = true;

  ESP_LOGI(TAG, "main task entry");

  // if (g_droplet_config->qsize) {
  //   g_droplet_queue = xQueueCreate(g_droplet_config->qsize, sizeof(droplet_event_ctx_t));
  //   ESP_ERROR_GOTO(!g_droplet_queue, EXIT, "Create droplet event queue fail");
  // }

  while (bRun) {

    if (xQueueReceive(g_droplet_queue, &evt_data, portMAX_DELAY) != pdTRUE) {
      continue;
    }

    if (evt_data.id == DROPLET_EVENT_STOP) {
      bRun = false;
      continue;
    }

    if (evt_data.id == DROPLET_EVENT_FORWARD) {
      if (droplet_send(DROPLET_ADDR_BROADCAST,
                       true,
                       g_droplet_config.ttl,
                       (droplet_data_t *) (evt_data.data),
                       evt_data.size,
                       100) != ESP_OK) {
        ESP_LOGD(TAG, "droplet_send_forward failed");
      }
      continue;
    }

    // if (evt_data.id == DROPLET_EVENT_RECEIVE) {
    //   ret = droplet_sec_auth_decrypt(g_droplet_sec, droplet_data->payload, droplet_data->size, data,
    //   DROPLET_PAYLOAD_LEN, &size, g_droplet_sec->tag_len);

    //   if (droplet_recv_process((droplet_pkt_t *) (evt_data.data)) != ESP_OK) {
    //     ESP_LOGD(TAG, "droplet_recv_process");
    //   }
    //   continue;
    // }
  }

  // EXIT:
  //  if (g_droplet_queue) {
  //    while (xQueueReceive(g_droplet_queue, &evt_data, 0)) {
  //      free(evt_data.data);
  //    }

  //   vQueueDelete(g_droplet_queue);
  //   g_droplet_queue = NULL;
  // }

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
// droplet_queue_over_write
//

static bool
droplet_queue_over_write(const void *const data, size_t data_len, void *arg, TickType_t xTicksToWait)
{
  droplet_event_ctx_t droplet_event = { .size = data_len, .data = (void *) data, .handle = arg };

  return xQueueSend(g_droplet_queue, &droplet_event, xTicksToWait);
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
  if ((len < DROPLET_MIN_FRAME) || (len > DROPLET_MAX_FRAME)) {
    ESP_LOGE(TAG, "Frame length is invalid len=%d", len);
    return;
  }

  // uint8_t *droplet_data = (uint8_t *) data;
  wifi_promiscuous_pkt_t *promiscuous_pkt =
    (wifi_promiscuous_pkt_t *) (data - sizeof(wifi_pkt_rx_ctrl_t) /*- sizeof(droplet_frame_format_t)*/);
  wifi_pkt_rx_ctrl_t *rx_ctrl = &promiscuous_pkt->rx_ctrl;

  ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_DEBUG);
  // ESP_LOGD(TAG,
  //          "[%s, %d], " MACSTR ", rssi: %d, size: %d, total: %d - %d, type: %d, addr: %02x,
  //          g_vscp_msg_magic_cache_next: %d",
  //          __func__,
  //          __LINE__,
  //          MAC2STR(mac_addr),
  //          rx_ctrl->rssi,
  //          size,
  //          len,
  //          sizeof(droplet_data_t),
  //          droplet_data->type,
  //          addr[5],
  //          g_vscp_msg_magic_cache_next);

  // Filter ESP-NOW packets not generated by this project
  if (0x25 != data[DROPLET_POS_PKTID] || 0x7e != data[DROPLET_POS_PKTID + 1]) {
    ESP_LOGD(TAG, "This frame is not for us");
    return;
    // DROPLET_ADDR_IS_SELF(droplet_data->src_addr))
    // {
    //   ESP_LOGD(TAG,
    //            "Receive cb args error, recv_addr: " MACSTR ", src_addr: " MACSTR ", data: %p, size: %d",
    //            MAC2STR(addr),
    //            MAC2STR(droplet_data->src_addr),
    //            data,
    //            (int) len);
    //   return;
    // }
  }

  // Data may not be needed to be forwarded
  //  - No data handle enable
  //  - No forward enabled
  //  - ttl is over
  if (!g_droplet_recv_handle.enable && (!g_droplet_config.bForwardEnable || !data[DROPLET_POS_TTL])) {
    return;
  }

  // Channel filtering
  if (g_droplet_config.bFilterAdjacentChannel && g_droplet_config.channel != rx_ctrl->channel) {
    ESP_LOGD(TAG, "Filter adjacent channels, %d != %d", g_droplet_config.channel, rx_ctrl->channel);
    return;
  }

  // Rssi filtering
  if (g_droplet_config.filterWeakSignal && g_droplet_config.filterWeakSignal > rx_ctrl->rssi) {
    ESP_LOGD(TAG, "Filter weak signal strength, %d > %d", g_droplet_config.filterWeakSignal, rx_ctrl->rssi);
    return;
  }

  // Check if we have already received this frame
  for (size_t i = 0, index = g_droplet_magic_cache_next; i < DROPLET_MSG_CACHE;
       i++, index          = (g_droplet_magic_cache_next + i) % DROPLET_MSG_CACHE) {
    if (g_droplet_magic_cache[index].magic == data[DROPLET_POS_MAGIC]) {
      return;
    }
  }

  // ESP_LOGD(TAG,
  //          "[%s, %d]: " MACSTR ", rssi: %d, channel: %d/%d, size: %d, %s, magic: 0x%x, ack: %d",
  //          __func__,
  //          __LINE__,
  //          MAC2STR(droplet_data->dest_addr),
  //          rx_ctrl->rssi,
  //          rx_ctrl->channel,
  //          rx_ctrl->secondary_channel,
  //          droplet_data->size,
  //          droplet_data->payload,
  //          data[VSCP_DROPLET_POS_MAGIC],
  //          droplet_data->frame_head.ack);

  // if (!g_recv_handle.enable) {
  //   goto FORWARD_DATA;
  // }

  // if (!DROPLET_ADDR_IS_BROADCAST(espnow_data->dest_addr) && !DROPLET_ADDR_IS_SELF(mac_addr)) {
  //   goto FORWARD_DATA;
  // }

  droplet_rxpkt_t *q_data = malloc(sizeof(droplet_rxpkt_t) + len);
  // memcpy(&q_data->dest_addr, droplet_data->dest_addr, 6);
  // memcpy(&q_data->src_addr, droplet_data->src_addr, 6);
  memcpy(&q_data->rx_ctrl, rx_ctrl, sizeof(wifi_pkt_rx_ctrl_t));
  memcpy(&q_data->payload, data, len);
  q_data->size = len;

  // If a specific channel set, make rx data using it
  if (g_droplet_config.channel && g_droplet_config.channel != DROPLET_CHANNEL_ALL) {
    q_data->rx_ctrl.channel = g_droplet_config.channel;
  }

  if (droplet_queue_over_write(q_data, len, NULL, 0) != pdPASS) {
    ESP_LOGW(TAG, "[%s, %d] Send event queue failed", __func__, __LINE__);
    free(q_data);
    return;
  }

  // FORWARD_DATA:

  if (g_droplet_config.bForwardEnable && g_droplet_config.filterWeakSignal > 0 &&
      g_droplet_config.filterWeakSignal <= rx_ctrl->rssi && !DROPLET_ADDR_IS_SELF(mac_addr)) {
    droplet_data_t *q_data = malloc(len);

    if (!q_data) {
      return;
    }

    memcpy(q_data, data, len);
    q_data->size = len;

    if (data[DROPLET_POS_TTL] && (data[DROPLET_POS_TTL] != DROPLET_FORWARD_MAX_COUNT)) {
      q_data->payload[DROPLET_POS_TTL] -= 1;
    }

    if (droplet_queue_over_write(q_data, q_data->size, NULL, 0) != pdPASS) {
      ESP_LOGW(TAG, "[%s, %d] Send event queue failed", __func__, __LINE__);
      free(q_data);
      return;
    }
  }

  // EXIT:
  g_droplet_magic_cache_next = (g_droplet_magic_cache_next + 1) % DROPLET_MSG_CACHE;
  memcpy(g_droplet_magic_cache[g_droplet_magic_cache_next].magic, data[DROPLET_POS_MAGIC], 2);
}

///////////////////////////////////////////////////////////////////////////////
// droplet_send
//

esp_err_t
droplet_send(const uint8_t *dest_addr, bool bEncrypt, uint8_t ttl, uint8_t *data, size_t size, TickType_t wait_ticks)
{
  if (NULL == dest_addr) {
    ESP_LOGE(TAG, "destination address pointer invalid");
    return ESP_ERR_INVALID_ARG;
  }

  if (NULL == data) {
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
  bool bBroadcast        = (0 == memcmp(dest_addr, DROPLET_ADDR_BROADCAST, 6));
  size_t frame_len       = size;

  // ttl
  data[DROPLET_POS_TTL] = ttl;

  // Magic word
  esp_fill_random((data + DROPLET_POS_MAGIC), 2);

  // Add frame sequency to VSCP header
  data[DROPLET_POS_HEAD + 1] = (data[DROPLET_POS_HEAD + 1] & 0xf8) + seq++;

  // Encrypt data if needed. IV will be placed at end of data
  // | id | encrypted-data | IV |
  if (bEncrypt) {

    // Fill in iv at end of send frame
    uint8_t *iv = malloc(16);
    esp_fill_random(iv, DROPLET_IV_LEN);
    // ESP_LOG_BUFFER_HEX("IV", iv, 16);

    // printf("size: %d\n", size);
    // printf("fame-len: %d\n", frame_len);
    // ESP_LOG_BUFFER_HEX("ORIG", send_data, size);

    // Encrypt send frame
    // uint8_t ttt[frame_len + 16];
    outbuf = malloc(size + (16 - (size % 16) + 16)); // size + paddding + iv

    data[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_AES128;

    if (0 == (frame_len = vscp_fwhlp_encryptFrame(outbuf,
                                                  data,
                                                  size,
                                                  g_droplet_config.pmk, // key
                                                  iv,                   // IV
                                                  VSCP_ENCRYPTION_AES128))) {
      ESP_LOGE(TAG, "Failed to encrypt frame");
      free(iv);
      free(outbuf);
      return ESP_FAIL;
    }

    free(iv);

    if (0) {
      printf("fame-len: %d\n", frame_len);
      ESP_LOG_BUFFER_HEX("ENC", outbuf, frame_len);

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
    memcpy(outbuf, data, size);
    outbuf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_NONE;
  }

  /**< Wait for other tasks to be sent before send ESP-NOW data */
  if (xSemaphoreTake(s_droplet_send_lock, pdMS_TO_TICKS(wait_ticks)) != pdPASS) {
    free(outbuf);
    return ESP_ERR_TIMEOUT;
  }

  xEventGroupClearBits(g_droplet_event_group, DROPLET_SEND_CB_OK | DROPLET_SEND_CB_FAIL);

  ret = esp_now_send(dest_addr, outbuf, frame_len);
  if (ret == ESP_OK) {
    ESP_LOGI(TAG,
             "Sent %dth broadcast data to: " MACSTR " \n len: %d "
             "pktid = %02X%02X "
             "ttl = %d "
             "magic = %02X%02X "
             "head = %02X%02X "
             "nickname = %02X%02X "
             "class = %02X%02X "
             "type = %02X%02X ",
             seq++,
             MAC2STR(dest_addr),
             DROPLET_MIN_FRAME + 3,
             outbuf[0],
             outbuf[1], // pktid
             outbuf[2], // ttl
             outbuf[3],
             outbuf[4], // magic
             outbuf[5],
             outbuf[6], // head
             outbuf[7],
             outbuf[8], // nickname
             outbuf[9],
             outbuf[10], // class
             outbuf[11],
             outbuf[12] // type
    );

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
        ret = ESP_FAIL;
      }
    }
  }
  else {
    ESP_LOGE(TAG, "Failed to send frame err=%d", (int) ret);
  }

  xSemaphoreGive(s_droplet_send_lock);
  free(outbuf);

  return ret;
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