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
 * Copyright © 2000-2023 Ake Hedman, the VSCP project <info@vscp.org>
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

#include "vscp-compiler.h"
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
#include <esp_wifi_types.h>
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

static const char *TAG = "droplet";

typedef struct {
  uint16_t frame_head;
  uint16_t duration;
  uint8_t destination_address[6];
  uint8_t source_address[6];
  uint8_t broadcast_address[6];
  uint16_t sequence_control;

  uint8_t category_code;
  uint8_t organization_identifier[3]; // 0x18fe34
  uint8_t random_values[4];
  struct {
    uint8_t element_id;                 // 0xdd
    uint8_t lenght;                     //
    uint8_t organization_identifier[3]; // 0x18fe34
    uint8_t type;                       // 4
    uint8_t version;
    uint8_t body[0];
  } vendor_specific_content;
} __attribute__((packed)) espnow_frame_format_t;

// ------------------------------------------------

typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

bool g_set_channel_flag           = true;
droplet_config_t g_droplet_config = { 0 };

wifi_country_t g_self_country = { 0 };

#define DROPLET_MAX_BUFFERED_NUM                                                                                       \
  (CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM / 2) /* Not more than CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM */

// Free running counter that is updated for every send
uint8_t g_droplet_sendSequence = 0;

static EventGroupHandle_t droplet_event_group = NULL;

// Number of send events in transit
uint32_t g_droplet_buffered_num = 0;

QueueHandle_t g_droplet_rcvqueue = NULL;

#define DROPLET_SEND_CB_OK   BIT0
#define DROPLET_SEND_CB_FAIL BIT1

static struct {
  uint16_t magic;
} __attribute__((packed)) g_droplet_magic_cache[DROPLET_MSG_CACHE_SIZE] = { 0 };

static uint8_t g_droplet_magic_cache_next = 0;

// This mutex protects the espnow_send as it is NOT thread safe
static SemaphoreHandle_t droplet_send_lock;

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
typedef struct __droplet_rxpkt {
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  uint8_t src_addr[6];
  // dest_addr is vailable in payload
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

const uint8_t DROPLET_ADDR_NONE[6]      = { 0 };
const uint8_t DROPLET_ADDR_BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0XFF };
// const uint8_t DROPLET_ADDR_GROUP_VSCP[6] = { 'V', 'S', 'C', 'P', 0x0, 0x0 };
// const uint8_t DROPLET_ADDR_GROUP_PROV[6] = { 'P', 'R', 'O', 'V', 0x0, 0x0 };
// const uint8_t DROPLET_ADDR_GROUP_SEC[6]  = { 'S', 'E', 'C', 0x0, 0x0, 0x0 };
// const uint8_t DROPLET_ADDR_GROUP_OTA[6]  = { 'O', 'T', 'A', 0x0, 0x0, 0x0 };

static uint8_t s_vscp_zero_guid[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// User handler for received droplet frames/events
static vscp_event_handler_cb_t s_vscp_event_handler_cb = NULL;

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
// read_discovery_cache
//

// void read_discovery_cache()
// {
//   size_t length  = nvs_get_blob(g_nvsHandle, "discovery-cache", g_droplet_discovery_cache, &length);
// }

///////////////////////////////////////////////////////////////////////////////
// wifi_sniffer_packet_type2str
//

const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch (type) {
    case WIFI_PKT_MGMT:
      return "MGMT";
    case WIFI_PKT_DATA:
      return "DATA";
    default:
    case WIFI_PKT_MISC:
      return "MISC";
  }
}

///////////////////////////////////////////////////////////////////////////////
// promiscuous_rx_cb
//

void
promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{

  /*! All espnow traffic uses action frames which are a subtype of the
    mgmnt frames so filter out everything else.
  */
  if (type != WIFI_PKT_MGMT) {
    return;
  }

  static const uint8_t ACTION_SUBTYPE  = 0xd0;
  static const uint8_t ESPRESSIF_OUI[] = { 0x18, 0xfe, 0x34 };

  const wifi_promiscuous_pkt_t *ppkt  = (wifi_promiscuous_pkt_t *) buf;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *) ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
  //        " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
  //        " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
  //        " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
  //        wifi_sniffer_packet_type2str(type),
  //        ppkt->rx_ctrl.channel,
  //        ppkt->rx_ctrl.rssi,
  //        /* ADDR1 */
  //        hdr->addr1[0],
  //        hdr->addr1[1],
  //        hdr->addr1[2],
  //        hdr->addr1[3],
  //        hdr->addr1[4],
  //        hdr->addr1[5],
  //        /* ADDR2 */
  //        hdr->addr2[0],
  //        hdr->addr2[1],
  //        hdr->addr2[2],
  //        hdr->addr2[3],
  //        hdr->addr2[4],
  //        hdr->addr2[5],
  //        /* ADDR3 */
  //        hdr->addr3[0],
  //        hdr->addr3[1],
  //        hdr->addr3[2],
  //        hdr->addr3[3],
  //        hdr->addr3[4],
  //        hdr->addr3[5]);

  // Only continue processing if this is an action frame containing the Espressif OUI.
  if ((ACTION_SUBTYPE == (hdr->frame_ctrl & 0xFF)) && (memcmp(hdr->addr4, ESPRESSIF_OUI, 3) == 0)) {
    int rssi = ppkt->rx_ctrl.rssi;
    printf("-------------------------------> %d", rssi);
  }
}

///////////////////////////////////////////////////////////////////////////////
// droplet_init
//

esp_err_t
droplet_init(const droplet_config_t *config)
{
  void *p;
  // esp_err_t ret = ESP_FAIL;

  // ESP_ERROR_CHECK(config);
  memcpy(&g_droplet_config, config, sizeof(droplet_config_t));

  ESP_LOGI(TAG, "Ptr size %d", sizeof(void *));
  g_droplet_rcvqueue = xQueueCreate(g_droplet_config.sizeQueue, sizeof(void *));
  if (NULL == g_droplet_rcvqueue) {
    ESP_LOGD(TAG, "Create droplet event queue fail");
    return ESP_FAIL;
  }

  // Event group for droplet sent cb
  droplet_event_group = xEventGroupCreate();
  ESP_RETURN_ON_ERROR(!droplet_event_group, TAG, "Create event group fail");

  droplet_send_lock = xSemaphoreCreateMutex();
  ESP_RETURN_ON_ERROR(!droplet_send_lock, TAG, "Create send semaphore mutex fail");

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);

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
  esp_now_peer_info_t *peer = VSCP_MALLOC(sizeof(esp_now_peer_info_t));
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
  VSCP_FREE(peer);

  // Init droplet system
  droplet_sec_init();

  xTaskCreate(droplet_task, "droplet task", 1024*8, NULL, 5, NULL);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_task
//

static void
droplet_task(void *arg)
{
  int rv;
  esp_err_t ret            = ESP_FAIL;
  droplet_rxpkt_t *prxdata = NULL;
  bool bRun                = true;
  size_t size              = 0;

  ESP_LOGI(TAG, "droplet task entry");

  while (bRun) {

  NEXT_FRAME:

    // Get receive frame (if any)
    if ((ret = xQueueReceive(g_droplet_rcvqueue, &prxdata, portMAX_DELAY)) != pdTRUE) {
      ESP_LOGE(TAG, "Failed to get receive data from queue. ret=%d", ret);
      continue;
    }

    if (prxdata == NULL) {
      ESP_LOGE(TAG, "Receive event data is NULL");
      continue;
    }

    g_droppletStats.nRecv++; // Update receive frame statistics

    // uint32_t hf = esp_get_free_heap_size();
    // heap_caps_check_integrity_all(true);
    // ESP_LOGI(TAG, "Event received heap=%X", (unsigned int) hf);

    size = prxdata->size;

    // * * * Decrypt frame if needed * * *

    if (prxdata->payload[DROPLET_POS_PKTID] & 0x0f) {

      ESP_LOGI(TAG, "<------ Decryption -------->");

      uint8_t nEncryption = prxdata->payload[DROPLET_POS_PKTID] & 0x0f;

      // Allocate space for data
      uint8_t *pdata = VSCP_MALLOC(prxdata->size);
      if (NULL == pdata) {
        VSCP_FREE(prxdata);
        ESP_LOGE(TAG, "Unable to allocate data. Terminating");
        return;
      }

      if (VSCP_ERROR_SUCCESS != vscp_fwhlp_decryptFrame(pdata,
                                                        prxdata->payload,
                                                        prxdata->size,
                                                        g_droplet_config.pmk, // key
                                                        NULL,                 // IV  - use embedded
                                                        nEncryption)) {
        ESP_LOGE(TAG, "Failed to decrypt frame");
        VSCP_FREE(pdata);
        VSCP_FREE(prxdata);
        continue;
      }

      size -= 16; // no need to send the old IV

      // Copy back decrypted payload data
      memcpy(prxdata->payload, pdata, size);

      VSCP_FREE(*pdata);
    }

    // Check if we have already received this frame
    for (size_t i = 0, index = g_droplet_magic_cache_next; i < DROPLET_MSG_CACHE_SIZE;
         i++, index          = (g_droplet_magic_cache_next + i) % DROPLET_MSG_CACHE_SIZE) {
      if (g_droplet_magic_cache[index].magic ==
          ((prxdata->payload[DROPLET_POS_MAGIC] << 8) + prxdata->payload[DROPLET_POS_MAGIC + 1])) {
        ESP_LOGI(TAG,
                 "Frame %X is skipped - already in cache, ",
                 ((prxdata->payload[DROPLET_POS_MAGIC] << 8) + prxdata->payload[DROPLET_POS_MAGIC + 1]));
        VSCP_FREE(prxdata);
        goto NEXT_FRAME;
      }
    }

    // Store magic in cache
    g_droplet_magic_cache[g_droplet_magic_cache_next].magic =
      (prxdata->payload[DROPLET_POS_MAGIC] << 8) + prxdata->payload[DROPLET_POS_MAGIC + 1];
    g_droplet_magic_cache_next = (g_droplet_magic_cache_next + 1) % DROPLET_MSG_CACHE_SIZE;

    // Decrease ttl as we have seen this frame
    uint8_t ttl                       = --prxdata->payload[DROPLET_POS_TTL];
    prxdata->payload[DROPLET_POS_TTL] = ttl;

    // Destination address can't be a pointer as it will be encrypted if
    // encryption is enabled in frame
    uint8_t dest_addr[6];
    memcpy(dest_addr, prxdata->payload + DROPLET_POS_DEST_ADDR, 6);

    // if ttl is zero or frame is addressed to us don't forward
    if (g_droplet_config.bForwardEnable && ttl && DROPLET_ADDR_IS_SELF(prxdata->payload + DROPLET_POS_DEST_ADDR)) {
      ESP_LOGI(TAG,
               "Forward frame %X",
               ((prxdata->payload[DROPLET_POS_MAGIC] << 8) + prxdata->payload[DROPLET_POS_MAGIC + 1]));
      if (ESP_OK == (ret = droplet_send(dest_addr, true, VSCP_ENCRYPTION_NONE, 0, prxdata->payload, size, 20))) {
        ESP_LOGD(TAG, "Frame forwarded successfully");
        g_droppletStats.nForw++; // Update forward frame statistics
      }
      else {
        ESP_LOGE(TAG, "Failed to forward frame ret=%X", ret);
        g_droppletStats.nSendFailures++; // Update send failures
      }
    }

    // Handle event callback
    if (NULL != s_vscp_event_handler_cb) {
      vscpEvent *pev = vscp_fwhlp_newEvent();
      if (NULL == pev) {
        ESP_LOGE(TAG, "Failed to allocate new event-");
        goto CONTINUE;
      }
      if (VSCP_ERROR_SUCCESS !=
          (rv = droplet_frameToEv(pev, prxdata->payload, prxdata->size, prxdata->rx_ctrl.timestamp))) {
        ESP_LOGE(TAG, "Failed to convert frame to event. rv=%d", rv);
        if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_deleteEvent(&pev))) {
          ESP_LOGE(TAG, "Failed to delete event. rv=%d", rv);
        }
        goto CONTINUE;
      }
      // Call event callback and let it do it's
      // work
      s_vscp_event_handler_cb(pev, NULL);
    }

  CONTINUE:

    VSCP_FREE(prxdata); // Deallocate structure data

  } // while

  // Empty queue
  while (xQueueReceive(g_droplet_rcvqueue, &prxdata, 0)) {
    VSCP_FREE((prxdata));       // Deallocate receive frame data
  }

  vQueueDelete(g_droplet_rcvqueue);
  g_droplet_rcvqueue = NULL;

  ESP_LOGI(TAG, "droplet task exit");
  vTaskDelete(NULL);
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
  if ((len < DROPLET_MIN_FRAME) || (len > DROPLET_MAX_FRAME) || ((data[0] & 0xff) > VSCP_ENCRYPTION_AES256)) {
    ESP_LOGE(TAG, "Frame length/type is invalid len=%d", len);
    g_droppletStats.nRecvFrameFault++; // Increase receive frame faults
    return;
  }

  wifi_promiscuous_pkt_t *promiscuous_pkt =
    (wifi_promiscuous_pkt_t *) (data - sizeof(wifi_pkt_rx_ctrl_t) - sizeof(espnow_frame_format_t));
  wifi_pkt_rx_ctrl_t *prx_ctrl = &promiscuous_pkt->rx_ctrl;

  ESP_LOGI(TAG,
           "Receive event from " MACSTR " frame %04X, RSSI %d Channel %d",
           MAC2STR(mac_addr),
           ((data[DROPLET_POS_MAGIC] << 8) + data[DROPLET_POS_MAGIC + 1]),
           prx_ctrl->rssi,
           prx_ctrl->channel);
  ESP_LOG_BUFFER_HEXDUMP(TAG, data, len, ESP_LOG_DEBUG);

  // Channel filtering
  if (g_droplet_config.bFilterAdjacentChannel && (g_droplet_config.channel != prx_ctrl->channel)) {
    ESP_LOGI(TAG, "Filter adjacent channels, %d != %d", g_droplet_config.channel, prx_ctrl->channel);
    g_droppletStats.nRecvAdjChFilter++; // Increase adjacent channel filter statistics
    return;
  }

  // RSSI filtering
  if (g_droplet_config.filterWeakSignal && (g_droplet_config.filterWeakSignal > prx_ctrl->rssi)) {
    ESP_LOGI(TAG, "Filter weak signal strength, %d > %d", g_droplet_config.filterWeakSignal, prx_ctrl->rssi);
    g_droppletStats.nRecvŔssiFilter++; // Increase RSSI filter statistics
    return;
  }

  droplet_rxpkt_t *prxdata = VSCP_MALLOC(sizeof(droplet_rxpkt_t) + len);
  if (NULL == prxdata) {
    ESP_LOGD(TAG, "Failed to allocate data.");
    return;
  }

  memcpy(&prxdata->rx_ctrl, prx_ctrl, sizeof(wifi_pkt_rx_ctrl_t));
  memcpy(&prxdata->payload, data, len);
  prxdata->size = len;
  memcpy(prxdata->src_addr, mac_addr, 6);

  // If a specific channel set, make rx data using it
  if (g_droplet_config.channel && g_droplet_config.channel != DROPLET_CHANNEL_ALL) {
    prxdata->rx_ctrl.channel = g_droplet_config.channel;
  }

  if (xQueueSend(g_droplet_rcvqueue, &(prxdata), 0) != pdPASS) {
    ESP_LOGW(TAG, "[%s, %d] Send event queue failed. errQUEUE_FULL", __func__, __LINE__);
    VSCP_FREE(prxdata);
    g_droppletStats.nRecvOverruns++; // Receive overrun
    return;
  }
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
    xEventGroupSetBits(droplet_event_group, DROPLET_SEND_CB_OK);
  }
  else {
    xEventGroupSetBits(droplet_event_group, DROPLET_SEND_CB_FAIL);
  }
}

///////////////////////////////////////////////////////////////////////////////
// droplet_send
//

esp_err_t
droplet_send(const uint8_t *dest_addr,
             bool bPreserveHeader,
             uint8_t nEncrypt,
             uint8_t ttl,
             uint8_t *payload,
             size_t size,
             uint16_t wait_ms)
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

  static uint8_t seq = 0;
  esp_err_t ret      = ESP_FAIL;
  // TickType_t write_ticks = 0;
  uint32_t start_ticks = xTaskGetTickCount();
  uint8_t *outbuf      = NULL;
  bool bBroadcast      = (0 == memcmp(dest_addr, DROPLET_ADDR_BROADCAST, ESP_NOW_ETH_ALEN));
  size_t frame_len     = size;

  if (bPreserveHeader) {
    // Let pktid byte decide if we should encrypt or not
    nEncrypt = payload[DROPLET_POS_PKTID] & 0x0f;
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
  if (nEncrypt) {

    // Fill in iv at end of send frame
    uint8_t *iv = VSCP_MALLOC(16);
    esp_fill_random(iv, DROPLET_IV_LEN);

    // Encrypt send frame
    outbuf = VSCP_MALLOC(size + (16 - (size % 16) + 16) + 1); // size + padding + iv + coding byte

    payload[DROPLET_POS_PKTID] = nEncrypt;

    // uint64_t start = esp_timer_get_time();
    if (0 == (frame_len = vscp_fwhlp_encryptFrame(outbuf,
                                                  payload,
                                                  size,
                                                  g_droplet_config.pmk, // key
                                                  iv,                   // IV
                                                  nEncrypt))) {
      ESP_LOGE(TAG, "Failed to encrypt frame");
      VSCP_FREE(iv);
      VSCP_FREE(outbuf);
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
        VSCP_FREE(outbuf);
        VSCP_FREE(iv);
        return ESP_FAIL;
      }

      ESP_LOG_BUFFER_HEX("DEC", yyy, frame_len);
    }
  }
  // If not encrypted
  else {
    outbuf = VSCP_MALLOC(size);
    if (NULL == outbuf) {
      return ESP_ERR_NO_MEM;
    }
    memcpy(outbuf, payload, size);
    outbuf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_NONE;
  }

  // Wait for other tasks to be sent before send ESP-NOW data
  if (xSemaphoreTake(droplet_send_lock, pdMS_TO_TICKS(wait_ms)) != pdPASS) {
    ESP_LOGE(TAG, "Timeout trying to get send lock.");
    VSCP_FREE(outbuf);
    g_droppletStats.nSendLock++; // Increase send lock failure counter
    return ESP_ERR_TIMEOUT;
  }

  xEventGroupClearBits(droplet_event_group, DROPLET_SEND_CB_OK | DROPLET_SEND_CB_FAIL);

  ret = esp_now_send(dest_addr, outbuf, frame_len);
  if (ret == ESP_OK) {

    // write_ticks = (wait_ticks == portMAX_DELAY)                    ? portMAX_DELAY
    //               : xTaskGetTickCount() - start_ticks < wait_ticks ? wait_ticks - (xTaskGetTickCount() - start_ticks)
    //                                                                : 0;
    g_droplet_buffered_num++;

    // Wait send cb if no room for frames
    if (g_droplet_buffered_num >= DROPLET_MAX_BUFFERED_NUM) {
      EventBits_t uxBits =
        xEventGroupWaitBits(droplet_event_group, DROPLET_SEND_CB_OK | DROPLET_SEND_CB_FAIL, pdTRUE, pdFALSE, wait_ms);
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

  xSemaphoreGive(droplet_send_lock);
  VSCP_FREE(outbuf);

  return ret;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_set_vscp_user_handler_cb
//

void
droplet_set_vscp_user_handler_cb(vscp_event_handler_cb_t *cb)
{
  s_vscp_event_handler_cb = cb;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_clear_vscp_handler_cb
//

void
droplet_clear_vscp_handler_cb(void)
{
  s_vscp_event_handler_cb = NULL;
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
  //   mbedtls_ccm_VSCP_FREE((mbedtls_ccm_context *) s_vscp_espnow_sec.cipher_ctx);
  //   VSCP_FREE(s_vscp_espnow_sec.cipher_ctx);
  // }
  // memset(&s_vscp_espnow_sec, 0, sizeof(vscp_espnow_sec_t));

  vEventGroupDelete(droplet_event_group);
  droplet_event_group = NULL;

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
    ESP_LOGE(TAG, "Size of buffer is to small to fit event, len:%d", len);
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

  // Unencrypted packet id
  buf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_NONE;

  // Head
  buf[DROPLET_POS_HEAD]     = 0;
  buf[DROPLET_POS_HEAD + 1] = 0;

  // Nickname
  if (NULL != pguid) {
    buf[DROPLET_POS_NICKNAME]     = pguid[14]; // (g_node_nickname >> 8) & 0xff;
    buf[DROPLET_POS_NICKNAME + 1] = pguid[15]; // g_node_nickname & 0xff;
  }

  // VSCP Class
  buf[DROPLET_POS_CLASS]     = (VSCP_CLASS1_INFORMATION >> 8) & 0xff;
  buf[DROPLET_POS_CLASS + 1] = VSCP_CLASS1_INFORMATION & 0xff;

  // VSCP Type
  buf[DROPLET_POS_TYPE]     = (VSCP_TYPE_INFORMATION_NODE_HEARTBEAT >> 8) & 0xff;
  buf[DROPLET_POS_TYPE + 1] = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT & 0xff;

  // Data
  buf[DROPLET_POS_DATA]     = 0;    // User specific
  buf[DROPLET_POS_DATA + 1] = 0xff; // All zones
  buf[DROPLET_POS_DATA + 2] = 0xff; // All subzones

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_getMinBufSizeEv
//

size_t
droplet_getMinBufSizeEv(vscpEvent *pev)
{
  // Need event pointer
  if (NULL == pev) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return 0;
  }

  return (DROPLET_MIN_FRAME + pev->sizeData);
}

///////////////////////////////////////////////////////////////////////////////
// droplet_getMinBufSizeEx
//

size_t
droplet_getMinBufSizeEx(vscpEventEx *pex)
{
  // Need event ex pointer
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event ex is NULL");
    return 0;
  }

  return (DROPLET_MIN_FRAME + pex->sizeData);
}

///////////////////////////////////////////////////////////////////////////////
// droplet_evToFrame
//

int
droplet_evToFrame(uint8_t *buf, uint8_t len, const vscpEvent *pev)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Need event
  if (NULL == pev) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (DROPLET_MIN_FRAME + pev->sizeData)) {
    ESP_LOGE(TAG, "Size of buffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  buf[DROPLET_POS_PKTID] = VSCP_ENCRYPTION_AES128;

  // head
  buf[DROPLET_POS_HEAD] = (pev->head >> 8) & 0xff;
  buf[DROPLET_POS_HEAD] = pev->head & 0xff;

  // nickname
  buf[DROPLET_POS_NICKNAME]     = pev->GUID[14];
  buf[DROPLET_POS_NICKNAME + 1] = pev->GUID[15];

  // vscp-class
  buf[DROPLET_POS_CLASS]        = (pev->vscp_class >> 8) & 0xff;
  buf[DROPLET_POS_NICKNAME + 1] = pev->vscp_class & 0xff;

  // vscp-type
  buf[DROPLET_POS_TYPE]     = (pev->vscp_type >> 8) & 0xff;
  buf[DROPLET_POS_TYPE + 1] = pev->vscp_type & 0xff;

  // data
  if (pev->sizeData) {
    memcpy((buf + DROPLET_POS_DATA), pev->pdata, pev->sizeData);
  }

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

  // head
  buf[DROPLET_POS_HEAD]     = (pex->head >> 8) & 0xff;
  buf[DROPLET_POS_HEAD + 1] = pex->head & 0xff;

  // nickname
  buf[DROPLET_POS_NICKNAME]     = pex->GUID[14];
  buf[DROPLET_POS_NICKNAME + 1] = pex->GUID[15];

  // vscp-class
  buf[DROPLET_POS_CLASS]     = (pex->vscp_class >> 8) & 0xff;
  buf[DROPLET_POS_CLASS + 1] = pex->vscp_class & 0xff;

  // vscp-type
  buf[DROPLET_POS_TYPE]     = (pex->vscp_type >> 8) & 0xff;
  buf[DROPLET_POS_TYPE + 1] = pex->vscp_type & 0xff;

  // data
  if (pex->sizeData) {
    memcpy((buf + DROPLET_POS_DATA), pex->data, pex->sizeData);
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_frameToEv
//

int
droplet_frameToEv(vscpEvent *pev, const uint8_t *buf, uint8_t len, uint32_t timestamp)
{
  // Need event
  if (NULL == pev) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must be at least have min size
  if (len < DROPLET_MIN_FRAME) {
    ESP_LOGE(TAG, "esp-now data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  // Must have valid first byte
  if ((buf[DROPLET_POS_PKTID] & 0xff) > VSCP_ENCRYPTION_AES256) {
    ESP_LOGE(TAG, "esp-now data is an invalid frame");
    return VSCP_ERROR_MTU;
  }

  memset(pev, 0, sizeof(vscpEvent));
  if (NULL != pev->pdata) {
    VSCP_FREE(pev);
    pev->pdata = NULL;
  }

  // Set VSCP size
  pev->sizeData = len - DROPLET_MIN_FRAME;
  pev->pdata    = VSCP_MALLOC(pev->sizeData);
  if (NULL == pev->pdata) {
    return VSCP_ERROR_MEMORY;
  }

  // Copy in VSCP data
  memcpy(pev->pdata, buf + DROPLET_MIN_FRAME, pev->sizeData);

  // Set timestamp if not set
  if (!timestamp) {
    pev->timestamp = esp_timer_get_time();
  }
  else {
    pev->timestamp = timestamp;
  }

  // Head
  pev->head = (buf[DROPLET_POS_HEAD] << 8) + buf[DROPLET_POS_HEAD + 1];

  // Nickname
  pev->GUID[14] = buf[DROPLET_POS_NICKNAME];
  pev->GUID[15] = buf[DROPLET_POS_NICKNAME + 1];

  // VSCP class
  pev->vscp_class = (buf[DROPLET_POS_CLASS] << 8) + buf[DROPLET_POS_CLASS + 1];

  // VSCP type
  pev->vscp_type = (buf[DROPLET_POS_TYPE] << 8) + buf[DROPLET_POS_TYPE + 1];

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

  // Must have valid first byte
  if ((buf[0] & 0xff) > VSCP_ENCRYPTION_AES256) {
    ESP_LOGE(TAG, "esp-now data is an invalid frame");
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
  else {
    pex->timestamp = timestamp;
  }

  // Head
  pex->head = (buf[DROPLET_POS_HEAD] << 8) + buf[DROPLET_POS_HEAD + 1];

  // Nickname
  pex->GUID[14] = buf[DROPLET_POS_NICKNAME];
  pex->GUID[15] = buf[DROPLET_POS_NICKNAME + 1];

  // VSCP class
  pex->vscp_class = (buf[DROPLET_POS_CLASS] << 8) + buf[DROPLET_POS_CLASS + 1];

  // VSCP type
  pex->vscp_type = (buf[DROPLET_POS_TYPE] << 8) + buf[DROPLET_POS_TYPE + 1];

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sendEvent
//

esp_err_t
droplet_sendEvent(vscpEvent *pev, uint32_t wait_ms)
{
  esp_err_t rv;
  uint8_t *pbuf;

  // Need event
  if (NULL == pev) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return ESP_ERR_INVALID_ARG;
  }

  pbuf = VSCP_MALLOC(DROPLET_MIN_FRAME + pev->sizeData);
  if (NULL == pbuf) {
    return ESP_ERR_NO_MEM;
  }

  if (VSCP_ERROR_SUCCESS != (rv = droplet_evToFrame(pbuf, DROPLET_MIN_FRAME + pev->sizeData, pev))) {
    VSCP_FREE(pbuf);
    ESP_LOGE(TAG, "Failed to convert event to frame. rv=%d", rv);
    return rv;
  }

  if (ESP_OK != (rv = droplet_send(DROPLET_ADDR_BROADCAST,
                                   false,
                                   g_droplet_config.nEncryption,
                                   g_droplet_config.ttl,
                                   pbuf,
                                   DROPLET_MIN_FRAME + pev->sizeData,
                                   wait_ms))) {
    ESP_LOGE(TAG, "Failed to send event. rv=%X", rv);
    VSCP_FREE(pbuf);
    return rv;
  }

  ESP_LOGI(TAG, "Event sent OK");

  VSCP_FREE(pbuf);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_sendEventEx
//

esp_err_t
droplet_sendEventEx(vscpEventEx *pex, uint32_t wait_ms)
{
  esp_err_t rv;
  uint8_t *pbuf;

  ESP_LOGI(TAG, "Send Event");

  // Need event
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event ex is NULL");
    return ESP_ERR_INVALID_ARG;
  }

  pbuf = VSCP_MALLOC(DROPLET_MIN_FRAME + pex->sizeData);
  if (NULL == pbuf) {
    return ESP_ERR_NO_MEM;
  }

  if (VSCP_ERROR_SUCCESS != (rv = droplet_evToFrame(pbuf, DROPLET_MIN_FRAME + pex->sizeData, pex))) {
    VSCP_FREE(pbuf);
    ESP_LOGE(TAG, "Failed to convert event to frame. rv=%d", rv);
    return ESP_ERR_INVALID_ARG;
  }

  if (ESP_OK != (rv = droplet_send(DROPLET_ADDR_BROADCAST,
                                   false,
                                   g_droplet_config.nEncryption,
                                   g_droplet_config.ttl,
                                   pbuf,
                                   DROPLET_MIN_FRAME + pex->sizeData,
                                   wait_ms))) {
    ESP_LOGE(TAG, "Failed to send event. rv=%X", rv);
    VSCP_FREE(pbuf);
    return rv;
  }

  ESP_LOGI(TAG, "Event sent OK");

  VSCP_FREE(pbuf);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_parse_vscp_json
//
// Uses JSON lib. https://github.com/nopnop2002/esp-idf-json
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
droplet_parse_vscp_json(vscpEvent *pev, const char *jsonVscpEventObj)
{
  int rv;
  cJSON *root = cJSON_Parse(jsonVscpEventObj);

  if (cJSON_GetObjectItem(root, "vscpHead")) {
    pev->head = (uint16_t) cJSON_GetObjectItem(root, "vscpHead")->valueint;
    ESP_LOGD(TAG, "vscpHead=%X", pev->head);
  }

  if (cJSON_GetObjectItem(root, "vscpObId")) {
    pev->obid = (uint32_t) cJSON_GetObjectItem(root, "vscpObId")->valuedouble;
    ESP_LOGD(TAG, "pex->obid=%lu", pev->obid);
  }

  // "2017-01-13T10:16:02",
  if (cJSON_GetObjectItem(root, "vscpDateTime")) {
    int year, month, day, hour, minute, second;
    const char *str = cJSON_GetObjectItem(root, "vscpDateTime")->valuestring;
    ESP_LOGD(TAG, "vscpDateTime=%s", str);
    sscanf(str, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
    pev->year   = year;
    pev->month  = month;
    pev->day    = day;
    pev->hour   = hour;
    pev->minute = minute;
    pev->second = second;
    ESP_LOGD(TAG, "%d-%02d-%02dT%02d:%02d:%02d", pev->year, pev->month, pev->day, pev->hour, pev->minute, pev->second);
  }

  if (cJSON_GetObjectItem(root, "vscpTimeStamp")) {
    pev->timestamp = (uint32_t) cJSON_GetObjectItem(root, "vscpTimeStamp")->valuedouble;
    ESP_LOGD(TAG, "vscpTimeStamp=%lu", pev->timestamp);
  }

  if (cJSON_GetObjectItem(root, "vscpClass")) {
    pev->vscp_class = (uint16_t) cJSON_GetObjectItem(root, "vscpClass")->valueint;
    ESP_LOGD(TAG, "vscpClass=%u", pev->vscp_class);
  }

  if (cJSON_GetObjectItem(root, "vscpType")) {
    pev->vscp_type = (uint16_t) cJSON_GetObjectItem(root, "vscpType")->valueint;
    ESP_LOGD(TAG, "vscpType=%u", pev->vscp_type);
  }

  if (cJSON_GetObjectItem(root, "vscpGuid")) {
    const char *str = cJSON_GetObjectItem(root, "vscpGuid")->valuestring;
    if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseGuid(pev->GUID, str, NULL))) {
      ESP_LOGD(TAG, "Failed to parse GUID");
      return rv;
    }
    ESP_LOGD(TAG, "vscpGuid=%s", str);
  }

  if (cJSON_GetObjectItem(root, "vscpData")) {

    cJSON *pdata  = cJSON_GetObjectItem(root, "vscpData");
    pev->sizeData = cJSON_GetArraySize(pdata);
    ESP_LOGD(TAG, "VSCP data size=%d", pev->sizeData);
    for (int i = 0; i < pev->sizeData; i++) {
      cJSON *pitem = cJSON_GetArrayItem(pdata, i);
      if (pitem->type == cJSON_Number && i < 512) {
        pev->pdata[i] = pitem->valueint;
        ESP_LOGD(TAG, "data%d=%u", i, pitem->valueint);
      }
    }
  }

  cJSON_Delete(root);
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// droplet_create_vscp_json
//
// https://github.com/nopnop2002/esp-idf-json
//

int
droplet_create_vscp_json(char *strObj, size_t len, vscpEvent *pev)
{
  cJSON *root;
  char str[80];

  if ( (NULL == strObj) || (NULL == pev)) {
    return VSCP_ERROR_INVALID_POINTER;
  }
  
  root = cJSON_CreateObject();

  cJSON_AddNumberToObject(root, "vscpHead", pev->head);
  cJSON_AddNumberToObject(root, "vscpClass", pev->vscp_class);
  cJSON_AddNumberToObject(root, "vscpType", pev->vscp_type);
  cJSON_AddNumberToObject(root, "vscpObid", pev->obid);
  cJSON_AddNumberToObject(root, "vscpTimeStamp", pev->timestamp);
  vscp_fwhlp_writeGuidToString(str, pev->GUID);
  cJSON_AddStringToObject(root, "vscpGUID", str);
  sprintf(str, "%04d-%02d-%02dT%02d:%02d:%02d", pev->year, pev->month, pev->day, pev->hour, pev->minute, pev->second);
  cJSON_AddStringToObject(root, "vscpDateTime", str);
  cJSON *array;
  array = cJSON_AddArrayToObject(root, "vscpData");
  cJSON *element;
  for (int i = 0; i < pev->sizeData; i++) {
    element = cJSON_CreateNumber(pev->pdata[i]);
    cJSON_AddItemToArray(array, element);
  }
  char *json_string = cJSON_Print(root);
  if (NULL == json_string) {
    cJSON_Delete(root);
    return VSCP_ERROR_PARSING;
  }

  ESP_LOGD(TAG, "%s", json_string);

  if (strlen(json_string) > (len-1)) {
    cJSON_free(json_string);
    cJSON_Delete(root);
    return VSCP_ERROR_BUFFER_TO_SMALL;
  }

  strcpy(strObj, json_string);
      
  cJSON_free(json_string);
  cJSON_Delete(root);

  return VSCP_ERROR_SUCCESS;
}