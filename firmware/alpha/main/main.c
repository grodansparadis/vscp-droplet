/*
  File: main.c

  VSCP Droplet alfa node

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022 Ake Hedman, the VSCP project <info@vscp.org>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#include <stdio.h>
#include <string.h>

#include "freertos/semphr.h"
#include "freertos/timers.h"
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include "driver/ledc.h"
#include "iot_button.h"
#include <driver/gpio.h>

#include <esp_event.h>

#include <esp_task_wdt.h>

#include "esp_crc.h"
#include "esp_now.h"
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_timer.h>
#include <esp_tls_crypto.h>
#include <esp_wifi.h>
#include <nvs_flash.h>

#include <esp_storage.h>
#include <esp_utils.h>

#include <espnow.h>
#include <espnow_ctrl.h>
#include <espnow_security.h>

#ifdef CONFIG_PROV_TRANSPORT_BLE
#include <wifi_provisioning/scheme_ble.h>
#endif /* CONFIG_PROV_TRANSPORT_BLE */

#ifdef CONFIG_PROV_TRANSPORT_SOFTAP
#include <wifi_provisioning/scheme_softap.h>
#endif /* CONFIG_PROV_TRANSPORT_SOFTAP */

#include "qrcode.h"

#include "websrv.h"

#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>

#include "vscp_espnow.h"

#include "main.h"
#include "wifiprov.h"

const char *pop_data   = "ESPNOW_VSCP_ALPHA";
static const char *TAG = "espnow_alpha";

// Handle for nvs storage
nvs_handle_t g_nvsHandle;

// GUID for unit
uint8_t g_device_guid[16];

// ESP-NOW

SemaphoreHandle_t g_ctrl_task_sem;

// Message queues for espnow messages
QueueHandle_t g_tx_msg_queue;
QueueHandle_t g_rx_msg_queue;

#ifdef CONFIG_IDF_TARGET_ESP32C3
#define BOOT_KEY_GPIIO  GPIO_NUM_9
#define CONFIG_LED_GPIO GPIO_NUM_2
#elif CONFIG_IDF_TARGET_ESP32S3
#define BOOT_KEY_GPIIO  GPIO_NUM_0
#define CONFIG_LED_GPIO GPIO_NUM_2
#else
#define BOOT_KEY_GPIIO  GPIO_NUM_0
#define CONFIG_LED_GPIO GPIO_NUM_2
#endif

static xQueueHandle s_vscp_espnow_queue; // espnow send queue

static QueueHandle_t s_espnow_queue;

static uint16_t s_espnow_seq[ESPNOW_DATA_MAX] = { 0, 0 };

static uint8_t s_vscp_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// Provisioning state
static espnow_ctrl_status_t s_espnow_ctrl_state = ESPNOW_CTRL_INIT;

espnow_sec_t *g_sec; // espnow security structure

// Forward declarations

static void
vscp_espnow_deinit(void *param);

// Signal Wi-Fi events on this event-group
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

///////////////////////////////////////////////////////////////////////////////
// vscp_wifi_init
//
// WiFi should start before using espnow
//

static void
vscp_wifi_init(void)
{
  ESP_ERROR_CHECK(esp_netif_init());

  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(ESPNOW_WIFI_MODE));
  // esp_wifi_set_mode(WIFI_MODE_APSTA);
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  ESP_ERROR_CHECK(esp_wifi_start());

#if CONFIG_ESPNOW_ENABLE_LONG_RANGE
  ESP_ERROR_CHECK(esp_wifi_set_protocol(ESPNOW_WIFI_IF,
                                        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
#endif
}

///////////////////////////////////////////////////////////////////////////////
// espnow_send_cb
//
// ESPNOW sending or receiving callback function is called in WiFi task.
// Users should not do lengthy operations from this task. Instead, post
// necessary data to a queue and handle it from a lower priority task.
//

static void
espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  espnow_event_t evt;
  espnow_event_send_cb_t *send_cb = &evt.info.send_cb;

  ESP_LOGI(TAG, "espnow Send cb");

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = ESPNOW_SEND_CB;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;

  // Report message as sent
  if (xQueueSend(s_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send send queue fail");
  }
}

///////////////////////////////////////////////////////////////////////////////
// espnow_recv_cb
//

static void
espnow_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
{
  espnow_event_t evt;
  espnow_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

  ESP_LOGI(TAG, "espnow recv cb");

  if (mac_addr == NULL || data == NULL || len <= 0) {
    ESP_LOGE(TAG, "Receive cb arg error");
    return;
  }

  evt.id = ESPNOW_RECV_CB;
  memcpy(recv_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  recv_cb->data = malloc(len);
  if (recv_cb->data == NULL) {
    ESP_LOGE(TAG, "Malloc receive data fail");
    return;
  }
  memcpy(recv_cb->data, data, len);
  recv_cb->data_len = len;
  if (xQueueSend(s_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send receive queue fail");
    free(recv_cb->data);
  }
}

///////////////////////////////////////////////////////////////////////////////
// espnow_data_parse
//
// Parse received ESPNOW data.
//

int
espnow_data_parse(uint8_t *data, uint16_t data_len, uint8_t *state, uint16_t *seq, int *magic)
{
  espnow_data_t *buf = (espnow_data_t *) data;
  uint16_t crc, crc_cal = 0;

  if (data_len < sizeof(espnow_data_t)) {
    ESP_LOGE(TAG, "Receive ESPNOW data too short, len:%d", data_len);
    return -1;
  }

  *state   = buf->state;
  *seq     = buf->seq_num;
  *magic   = buf->magic;
  crc      = buf->crc;
  buf->crc = 0;
  crc_cal  = esp_crc16_le(UINT16_MAX, (uint8_t const *) buf, data_len);

  if (crc_cal == crc) {
    return buf->type;
  }

  return -1;
}

///////////////////////////////////////////////////////////////////////////////
// espnow_data_prepare
//
// Prepare ESPNOW data to be sent.
//

void
espnow_data_prepare(espnow_send_param_t *send_param)
{
  espnow_data_t *buf = (espnow_data_t *) send_param->buffer;

  assert(send_param->len >= sizeof(espnow_data_t));

  buf->type    = IS_BROADCAST_ADDR(send_param->dest_mac) ? ESPNOW_DATA_BROADCAST : ESPNOW_DATA_UNICAST;
  buf->state   = send_param->state;
  buf->seq_num = s_espnow_seq[buf->type]++;
  buf->crc     = 0;
  buf->magic   = send_param->magic;
  /* Fill all remaining bytes after the data with random values */
  esp_fill_random(buf->payload, send_param->len - sizeof(espnow_data_t));
  buf->crc = esp_crc16_le(UINT16_MAX, (uint8_t const *) buf, send_param->len);
}

///////////////////////////////////////////////////////////////////////////////
// espnow_task
//

static void
espnow_task(void *pvParameter)
{
  espnow_event_t evt;
  uint8_t recv_state = 0;
  uint16_t recv_seq  = 0;
  int recv_magic     = 0;
  bool is_broadcast  = false;
  int ret;
  static int cnt = 0;

  vTaskDelay(5000 / portTICK_PERIOD_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  // Start sending broadcast ESPNOW data.
  espnow_send_param_t *send_param = (espnow_send_param_t *) pvParameter;
  if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
    ESP_LOGE(TAG, "Send error");
    espnow_deinit();
    vTaskDelete(NULL);
  }

  ESP_LOGI(TAG, "Waiting for broadcast response");

  while (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {

      case ESPNOW_SEND_CB: {
        espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        is_broadcast                    = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG,
                 "Send frame %d to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00, status1: %d",
                 cnt++,
                 MAC2STR(send_cb->mac_addr),
                 send_cb->status);

        if (is_broadcast && (send_param->broadcast == false)) {
          break;
        }

        if (!is_broadcast) {
          // send_param->count--;
          if (send_param->count == 0) {
            ESP_LOGI(TAG, "Send done");
            espnow_deinit();
            vTaskDelete(NULL);
          }
        }

        /* Delay a while before sending the next data. */
        if (send_param->delay > 0) {
          vTaskDelay(send_param->delay / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "send frame %d to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", cnt++, MAC2STR(send_cb->mac_addr));

        memcpy(send_param->dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        espnow_data_prepare(send_param);

        // Send the next data after the previous data is sent.
        if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
          ESP_LOGE(TAG, "Send error");
          espnow_deinit();
          vTaskDelete(NULL);
        }
        break;
      }

      case ESPNOW_RECV_CB: {

        ESP_LOGE(TAG, "ESPNOW_RECV_CB");

        espnow_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

        // Parse event data
        ret = espnow_data_parse(recv_cb->data, recv_cb->data_len, &recv_state, &recv_seq, &recv_magic);
        free(recv_cb->data);

        // If event is heartbeat check if we have seen it before
        if (ret == ESPNOW_DATA_BROADCAST) {

          ESP_LOGI(TAG,
                   "Receive %dth broadcast data from: ff:ff:ff:ff:ff:fe:" MACSTR ":00:00, len: %d",
                   recv_seq,
                   MAC2STR(recv_cb->mac_addr),
                   recv_cb->data_len);

          /* If MAC address does not exist in peer list, add it to peer list. */
          if (esp_now_is_peer_exist(recv_cb->mac_addr) == false) {
            esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
            if (peer == NULL) {
              ESP_LOGE(TAG, "Malloc peer information fail");
              espnow_deinit();
              vTaskDelete(NULL);
            }
            memset(peer, 0, sizeof(esp_now_peer_info_t));
            peer->channel = CONFIG_ESPNOW_CHANNEL;
            peer->ifidx   = ESPNOW_WIFI_IF;
            peer->encrypt = true;
            memcpy(peer->lmk, CONFIG_ESPNOW_LMK, ESP_NOW_KEY_LEN);
            memcpy(peer->peer_addr, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
            ESP_ERROR_CHECK(esp_now_add_peer(peer));
            free(peer);
          }

          // Indicates that the device has received broadcast ESPNOW data.
          if (send_param->state == 0) {
            send_param->state = 1;
          }

          /* If receive broadcast ESPNOW data which indicates that the other
           * device has received broadcast ESPNOW data and the local magic number
           * is bigger than that in the received broadcast ESPNOW data, stop
           * sending broadcast ESPNOW data and start sending unicast ESPNOW data.
           */
          if (recv_state == 1) {
            /* The device which has the bigger magic number sends ESPNOW data, the
             * other one receives ESPNOW data.
             */
            if (send_param->unicast == false && send_param->magic >= recv_magic) {
              ESP_LOGI(TAG, "Start sending unicast data");
              ESP_LOGI(TAG, "send frame to %d ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", cnt++, MAC2STR(recv_cb->mac_addr));

              /* Start sending unicast ESPNOW data. */
              memcpy(send_param->dest_mac, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
              espnow_data_prepare(send_param);
              if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
                ESP_LOGE(TAG, "Send error");
                espnow_deinit();
                vTaskDelete(NULL);
              }
              else {
                send_param->broadcast = false;
                send_param->unicast   = true;
              }
            }
          }
        }
        else if (ret == ESPNOW_DATA_UNICAST) {
          ESP_LOGI(TAG,
                   "Receive %dth unicast data from: ff:ff:ff:ff:ff:fe:" MACSTR ":00:00, len: %d",
                   recv_seq,
                   MAC2STR(recv_cb->mac_addr),
                   recv_cb->data_len);

          /* If receive unicast ESPNOW data, also stop sending broadcast ESPNOW
           * data. */
          send_param->broadcast = false;
        }
        else {
          ESP_LOGI(TAG, "Receive error data from: ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", MAC2STR(recv_cb->mac_addr));
        }
        break;
      }
      default:
        ESP_LOGE(TAG, "Callback type error: %d", evt.id);
        break;
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_send_cb
//
// ESPNOW sending or receiving callback function is called in WiFi task.
// Users should not do lengthy operations from this task. Instead, post
// necessary data to a queue and handle it from a lower priority task.
//

static void
vscp_espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  vscp_espnow_event_post_t evt;
  vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;

  ESP_LOGI(TAG, "vscp_espnow_send_cb ");

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = VSCP_ESPNOW_SEND_EVT;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;
  // Put status on event queue
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Add to event queue failed");
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_recv_cb
//

static void
vscp_espnow_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
{

  vscp_espnow_event_post_t evt;
  vscp_espnow_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

  if (mac_addr == NULL || data == NULL || len <= 0) {
    ESP_LOGE(TAG, "Receive cb arg error");
    return;
  }

  evt.id = VSCP_ESPNOW_RECV_EVT;
  memcpy(recv_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  memcpy(recv_cb->buf, data, len);
  recv_cb->len = len;
  // Put message + status on event queue
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send receive queue fail");
  }
}



///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_heartbeat_prepare
//
// Prepare ESPNOW data to be sent.
//

// void vscp_espnow_heartbeat_prepare(vscp_espnow_send_param_t *send_param)
//{
//  vscp_espnow_data_t *buf = (vscp_espnow_data_t *)send_param->buffer;

// assert(send_param->len >= sizeof(vscp_espnow_data_t));

// buf->type = IS_BROADCAST_ADDR(send_param->dest_mac)
//                 ? VSCP_ESPNOW_DATA_BROADCAST
//                 : VSCP_ESPNOW_DATA_UNICAST;
// buf->state = send_param->state;
// buf->seq_num = s_vscp_espnow_seq[buf->type]++;
// buf->crc = 0;
// buf->magic = send_param->magic;
// /* Fill all remaining bytes after the data with random values */
// esp_fill_random(buf->payload, send_param->len - sizeof(vscp_espnow_data_t));
// buf->crc = esp_crc16_le(UINT16_MAX, (uint8_t const *)buf, send_param->len);
//}

static int
vscpEventToEspNowBuf(uint8_t *buf, uint8_t len, vscp_espnow_event_t *pvscpEspNowEvent)
{
  if (len < VSCP_ESPNOW_PACKET_MAX_SIZE) {
    return -1;
  }
  // pvscpEspNowEvent->ttl = 7;
  //  pvscpEspNowEvent->seq = seq++;
  // pvscpEspNowEvent->magic = esp_random();
  //  pvscpEspNowEvent.crc = 0;
  //   https://grodansparadis.github.io/vscp-doc-spec/#/./class1.information?id=type9
  pvscpEspNowEvent->head = 0;
  // pvscpEspNowEvent->timestamp  = 0;
  pvscpEspNowEvent->nickname   = 0;
  pvscpEspNowEvent->vscp_class = VSCP_CLASS1_INFORMATION;
  pvscpEspNowEvent->vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
  pvscpEspNowEvent->len        = 3;
  pvscpEspNowEvent->data[0]    = 0;
  pvscpEspNowEvent->data[1]    = 0xff; // All zones
  pvscpEspNowEvent->data[2]    = 0xff; // All subzones

  // seq
  // buf[0] = (pvscpEspNowEvent->seq >> 8) & 0xff;
  // buf[1] = pvscpEspNowEvent->seq & 0xff;
  // magic
  // buf[2] = (pvscpEspNowEvent->magic >> 24) & 0xff;
  // buf[3] = (pvscpEspNowEvent->magic >> 16) & 0xff;
  // buf[4] = (pvscpEspNowEvent->magic >> 8) & 0xff;
  // buf[5] = pvscpEspNowEvent->magic & 0xff;
  // ttl
  // buf[6] = pvscpEspNowEvent->ttl;
  // head
  buf[7] = (pvscpEspNowEvent->head >> 8) & 0xff;
  buf[8] = pvscpEspNowEvent->head & 0xff;
  // timestamp
  // buf[9]  = (pvscpEspNowEvent->timestamp >> 24) & 0xff;
  // buf[10] = (pvscpEspNowEvent->timestamp >> 16) & 0xff;
  // buf[11] = (pvscpEspNowEvent->timestamp >> 8) & 0xff;
  // buf[12] = pvscpEspNowEvent->timestamp & 0xff;
  // nickname
  buf[13] = (pvscpEspNowEvent->nickname >> 8) & 0xff;
  buf[14] = pvscpEspNowEvent->nickname & 0xff;
  // vscp_class
  buf[15] = pvscpEspNowEvent->vscp_class;
  // vscp_type
  buf[16] = pvscpEspNowEvent->vscp_type;
  // Payload data
  for (uint8_t i = 0; i < pvscpEspNowEvent->len; i++) {
    buf[17 + i] = pvscpEspNowEvent->data[i];
  }
  // CRC
  pvscpEspNowEvent->crc               = esp_crc16_le(UINT16_MAX, (uint8_t const *) buf, 17 + pvscpEspNowEvent->len);
  buf[17 + pvscpEspNowEvent->len]     = (pvscpEspNowEvent->crc >> 8) & 0xff;
  buf[17 + pvscpEspNowEvent->len + 1] = pvscpEspNowEvent->crc & 0xff;

  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_heartbeat_task
//

static void
vscp_espnow_heartbeat_task(void *pvParameter)
{
  ESP_LOGI(TAG, "Start sending VSCP heartbeats");
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_task
//

static void
vscp_espnow_send_task(void *pvParameter)
{
  vscp_espnow_event_post_t evt;
  // uint16_t seq      = 0;
  // uint16_t recv_seq = 0;
  //  int recv_magic = 0;
  uint8_t dest_mac[ESP_NOW_ETH_ALEN]; // MAC address of destination device.
  vscp_espnow_event_t vscpEspNowEvent;
  uint8_t buf[VSCP_ESPNOW_PACKET_MAX_SIZE];
  // int ret;
  static int cnt = 0;

  memcpy(dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);

  vTaskDelay(5000 / portTICK_RATE_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

  ESP_LOGI(TAG, "Before broadcast send");

  espnow_frame_head_t frame_head = {
    .retransmit_count = 0,
    .broadcast        = true,
    .forward_ttl      = 7,
  };

  ESP_LOGI(TAG, "Before broadcast send 2");

  espnow_send(ESPNOW_TYPE_DATA,
              dest_mac,
              buf,
              VSCP_ESPNOW_PACKET_MIN_SIZE + vscpEspNowEvent.len,
              &frame_head,
              portMAX_DELAY);

  ESP_LOGI(TAG, "First broadcast sent");

  while (xQueueReceive(s_vscp_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {

      case VSCP_ESPNOW_SEND_EVT: {

        vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        // is_broadcast = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG,
                 "--> Send frame %d to " MACSTR ", status1: %d",
                 cnt++,
                 MAC2STR(send_cb->mac_addr),
                 send_cb->status);

        // if (is_broadcast && (send_param->broadcast == false)) {
        //   break;
        // }

        // if (!is_broadcast) {
        //   send_param->count--;
        //   if (send_param->count == 0) {
        //     ESP_LOGI(TAG, "Send done");
        //     vscp_espnow_deinit(NULL);
        //     vTaskDelete(NULL);
        //   }
        // }

        /* Delay a while before sending the next data. */
        // if (CONFIG_ESPNOW_SEND_DELAY > 0) {
        // vTaskDelay(1000 / portTICK_RATE_MS);
        //}

        ESP_LOGI(TAG, "send frame %d to " MACSTR "", cnt++, MAC2STR(send_cb->mac_addr));

        memcpy(dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        // scp_espnow_heart_beat_prepare(send_param);

        // vscpEspNowEvent.ttl   = 7;
        // vscpEspNowEvent.seq   = seq++;
        // vscpEspNowEvent.magic = esp_random();
        vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

        /* Send the next data after the previous data is sent. */
        // if (esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MAX_SIZE) != ESP_OK) {
        //   ESP_LOGE(TAG, "Send error");
        //   vscp_espnow_deinit(NULL);
        //   vTaskDelete(NULL);
        // }
        espnow_frame_head_t frame_head = {
          .retransmit_count = 0,
          .broadcast        = true,
          .forward_ttl      = 7,
        };
        vscpEspNowEvent.len = 0;
        espnow_send(ESPNOW_TYPE_DATA,
                    dest_mac,
                    buf,
                    VSCP_ESPNOW_PACKET_MIN_SIZE + vscpEspNowEvent.len,
                    &frame_head,
                    portMAX_DELAY);

        break;
      }
      case VSCP_ESPNOW_RECV_EVT: {
        break;
      } // receive

      default:
        ESP_LOGE(TAG, "Callback type error: %d", evt.id);
        break;
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_init
//

static esp_err_t
vscp_espnow_init(void)
{
  // vscp_espnow_send_param_t *send_param;

  // Create the event queue
  s_vscp_espnow_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(vscp_espnow_event_post_t));
  if (s_vscp_espnow_queue == NULL) {
    ESP_LOGE(TAG, "Create mutex fail");
    return ESP_FAIL;
  }

  // g_send_lock = xSemaphoreCreateMutex();
  // ESP_ERROR_RETURN(!g_send_lock, ESP_FAIL, "Create send semaphore mutex fail");
  espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  espnow_init(&espnow_config);

  // Initialize ESPNOW and register sending and receiving callback function.
  // ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_send_cb(vscp_espnow_send_cb));
  ESP_ERROR_CHECK(esp_now_register_recv_cb(vscp_espnow_recv_cb));

  // Set primary master key.
  ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

  // Add broadcast peer information to peer list.
  esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
  if (NULL == peer) {
    ESP_LOGE(TAG, "Malloc peer information fail");
    vSemaphoreDelete(s_vscp_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memset(peer, 0, sizeof(esp_now_peer_info_t));
  peer->channel = CONFIG_ESPNOW_CHANNEL;
  peer->ifidx   = ESPNOW_WIFI_IF;
  peer->encrypt = false;
  memcpy(peer->peer_addr, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);
  // ESP_ERROR_CHECK(esp_now_add_peer(peer));
  esp_now_add_peer(peer);
  free(peer);

  // Initialize sending parameters.
  /* send_param = malloc(sizeof(vscp_espnow_send_param_t));
  if (NULL == send_param) {
    ESP_LOGE(TAG, "Malloc send parameter fail");
    vSemaphoreDelete(s_vscp_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  } */

  /* memset(send_param, 0, sizeof(vscp_espnow_send_param_t));
  send_param->unicast = false;
  send_param->broadcast = true;
  send_param->state = 0;
  send_param->magic = esp_random();
  send_param->count = CONFIG_ESPNOW_SEND_COUNT;
  send_param->delay = CONFIG_ESPNOW_SEND_DELAY;
  send_param->len = CONFIG_ESPNOW_SEND_LEN;
  send_param->buffer = malloc(CONFIG_ESPNOW_SEND_LEN);
  if (send_param->buffer == NULL) {
    ESP_LOGE(TAG, "Malloc send buffer fail");
    free(send_param);
    vSemaphoreDelete(s_vscp_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memcpy(send_param->dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);
  vscp_espnow_heart_beat_prepare(send_param); */

  xTaskCreate(vscp_espnow_send_task, "vscp_espnow_send_task", 4096, NULL, 4, NULL);
  // xTaskCreate(vscp_espnow_recv_task, "vscp_espnow_recv_task", 2048, NULL, 4, NULL);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_deinit
//

static void
vscp_espnow_deinit(void *param)
{
  // free(send_param->buffer);
  // free(send_param);
  vSemaphoreDelete(s_vscp_espnow_queue);

  esp_now_deinit();
}

///////////////////////////////////////////////////////////////////////////////
// security
//

void
security(void)
{
  uint32_t start_time1                  = xTaskGetTickCount();
  espnow_sec_result_t espnow_sec_result = { 0 };
  espnow_sec_responder_t *info_list     = NULL;
  size_t num                            = 0;
  espnow_sec_initiator_scan(&info_list, &num, pdMS_TO_TICKS(3000));
  ESP_LOGW(TAG, "espnow wait security num: %d", num);

  if (num == 0) {
    ESP_FREE(info_list);
    return;
  }

  espnow_addr_t *dest_addr_list = ESP_MALLOC(num * ESPNOW_ADDR_LEN);

  for (size_t i = 0; i < num; i++) {
    memcpy(dest_addr_list[i], info_list[i].mac, ESPNOW_ADDR_LEN);
  }

  ESP_FREE(info_list);
  uint32_t start_time2 = xTaskGetTickCount();
  esp_err_t ret        = espnow_sec_initiator_start(g_sec, pop_data, dest_addr_list, num, &espnow_sec_result);
  ESP_ERROR_GOTO(ret != ESP_OK, EXIT, "<%s> espnow_sec_initator_start", esp_err_to_name(ret));

  ESP_LOGI(TAG,
           "App key is sent to the device to complete, Spend time: %dms, Scan time: %dms",
           (xTaskGetTickCount() - start_time1) * portTICK_RATE_MS,
           (start_time2 - start_time1) * portTICK_RATE_MS);
  ESP_LOGI(TAG,
           "Devices security completed, successed_num: %d, unfinished_num: %d",
           espnow_sec_result.successed_num,
           espnow_sec_result.unfinished_num);

EXIT:
  ESP_FREE(dest_addr_list);
  espnow_sec_initator_result_free(&espnow_sec_result);
}

///////////////////////////////////////////////////////////////////////////////
// read_onboard_temperature
//

float
read_onboard_temperature(void)
{
  // TODO
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// getMilliSeconds
//

uint32_t
getMilliSeconds(void)
{
  return (esp_timer_get_time() / 1000);
};

///////////////////////////////////////////////////////////////////////////////
// get_device_guid
//

bool
get_device_guid(uint8_t *pguid)
{
  esp_err_t rv;
  size_t length = 16;

  // Ceck pointer
  if (NULL == pguid) {
    return false;
  }

  rv = nvs_get_blob(g_nvsHandle, "guid", pguid, &length);
  switch (rv) {

    case ESP_OK:
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      printf("Username not found in nvs\n");
      return false;

    default:
      printf("Error (%s) reading username f900rom nvs!\n", esp_err_to_name(rv));
      return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// event_handler
//
// Event handler for catching system events
//

static void
event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{

#ifdef CONFIG_RESET_PROV_MGR_ON_FAILURE
  static int retries;
#endif

  if (event_base == WIFI_PROV_EVENT) {

    switch (event_id) {

      case WIFI_PROV_START:
        ESP_LOGI(TAG, "Provisioning started");
        break;

      case WIFI_PROV_CRED_RECV: {
        wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *) event_data;
        ESP_LOGI(TAG,
                 "Received Wi-Fi credentials"
                 "\n\tSSID     : %s\n\tPassword : %s",
                 (const char *) wifi_sta_cfg->ssid,
                 (const char *) wifi_sta_cfg->password);
        break;
      }

      case WIFI_PROV_CRED_FAIL: {
        wifi_prov_sta_fail_reason_t *reason = (wifi_prov_sta_fail_reason_t *) event_data;
        ESP_LOGE(TAG,
                 "Provisioning failed!\n\tReason : %s"
                 "\n\tPlease reset to factory and retry provisioning",
                 (*reason == WIFI_PROV_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed"
                                                       : "Wi-Fi access-point not found");
#ifdef CONFIG_RESET_PROV_MGR_ON_FAILURE
        retries++;
        if (retries >= CONFIG_PROV_MGR_MAX_RETRY_CNT) {
          ESP_LOGI(TAG,
                   "Failed to connect with provisioned AP, reseting "
                   "provisioned credentials");
          wifi_prov_mgr_reset_sm_state_on_failure();
          retries = 0;
        }
#endif
        break;
      }

      case WIFI_PROV_CRED_SUCCESS:
        ESP_LOGI(TAG, "Provisioning successful");
#ifdef CONFIG_RESET_PROV_MGR_ON_FAILURE
        retries = 0;
#endif
        break;

      case WIFI_PROV_END:
        /* De-initialize manager once provisioning is finished */
        wifi_prov_mgr_deinit();
        break;

      default:
        break;
    }
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_WIFI_READY) {
    // Set channel
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE));
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    ESP_LOGI(TAG, "Connecting.......................................");
    esp_wifi_connect();
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "Connected with IP Address:" IPSTR, IP2STR(&event->ip_info.ip));
    /* Signal main application to continue execution */
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_EVENT);
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
    esp_wifi_connect();
  }
}

static void
wifi_init_sta(void)
{
  /* Start Wi-Fi in station mode */
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA)); // WIFI_MODE_APSTA
  ESP_ERROR_CHECK(esp_wifi_start());
}

///////////////////////////////////////////////////////////////////////////////
// get_device_service_name
//

void
get_device_service_name(char *service_name, size_t max)
{
  uint8_t eth_mac[6];
  const char *ssid_prefix = "PROV_";
  esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
  snprintf(service_name, max, "%s%02X%02X%02X", ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
}

///////////////////////////////////////////////////////////////////////////////
// custom_prov_data_handler
//
// Handler for the optional provisioning endpoint registered by the application.
// The data format can be chosen by applications. Here, we are using plain ascii
// text. Applications can choose to use other formats like protobuf, JSON, XML,
// etc.
//

esp_err_t
custom_prov_data_handler(uint32_t session_id,
                         const uint8_t *inbuf,
                         ssize_t inlen,
                         uint8_t **outbuf,
                         ssize_t *outlen,
                         void *priv_data)
{
  if (inbuf) {
    ESP_LOGI(TAG, "Received data: %.*s", inlen, (char *) inbuf);
  }

  char response[] = "SUCCESS";
  *outbuf         = (uint8_t *) strdup(response);

  if (*outbuf == NULL) {
    ESP_LOGE(TAG, "System out of memory");
    return ESP_ERR_NO_MEM;
  }

  *outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// wifi_prov_print_qr
//

void
wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport)
{
  if (!name || !transport) {
    ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
    return;
  }
  char payload[150] = { 0 };
  if (pop) {
#if CONFIG_PROV_SECURITY_VERSION_1
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             pop,
             transport);
#elif CONFIG_PROV_SECURITY_VERSION_2
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"username\":\"%s\",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             username,
             pop,
             transport);
#endif
  }
  else {
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             transport);
  }
#ifdef CONFIG_PROV_SHOW_QR
  ESP_LOGI(TAG, "Scan this QR code from the provisioning application for Provisioning.");
  esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
  esp_qrcode_generate(&cfg, payload);
#endif /* CONFIG_APP_WIFI_PROV_SHOW_QR */
  ESP_LOGI(TAG,
           "If QR code is not visible, copy paste the below URL in a "
           "browser.\n%s?data=%s",
           QRCODE_BASE_URL,
           payload);
}

///////////////////////////////////////////////////////////////////////////////
// LED status task
//

void
led_task(void *pvParameter)
{
  // GPIO_NUM_16 is G16 on board
  gpio_set_direction(GPIO_NUM_2, GPIO_MODE_OUTPUT);
  printf("Blinking LED on GPIO 16\n");
  int cnt = 0;
  while (1) {
    gpio_set_level(GPIO_NUM_2, cnt % 2);
    cnt++;
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  // static uint8_t uid[33];
  ESP_LOGI(TAG, "App Main");

  // Initialize NVS partition
  esp_err_t rv = nvs_flash_init();
  if (rv == ESP_ERR_NVS_NO_FREE_PAGES || rv == ESP_ERR_NVS_NEW_VERSION_FOUND) {

    // NVS partition was truncated
    // and needs to be erased
    ESP_ERROR_CHECK(nvs_flash_erase());

    // Retry nvs_flash_init
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  // Create microsecond timer
  // ESP_ERROR_CHECK(esp_timer_create());

  // Start timer
  // esp_timer_start_periodic();

  // Initialize TCP/IP
  ESP_ERROR_CHECK(esp_netif_init());

  // Initialize the event loop
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_event_group = xEventGroupCreate();

  gpio_config_t io_conf = {};

  // Disable interrupt
  io_conf.intr_type = GPIO_INTR_DISABLE;

  // Set as output mode
  io_conf.mode = GPIO_MODE_OUTPUT;

  // Bit mask of the pins that you want to be able to set
  io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;

  // Disable pull-down mode
  io_conf.pull_down_en = 0;

  // Disable pull-up mode
  io_conf.pull_up_en = 0;

  // Configure GPIO with the given settings
  gpio_config(&io_conf);

  gpio_set_level(CONNECTED_LED_GPIO_NUM, 1);
  gpio_set_level(ACTIVE_LED_GPIO_NUM, 1);

  // Create message queues  QueueHandle_t tx_msg_queue
  g_tx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Outgoing esp-now messages */
  g_rx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Incoming esp-now messages */

  // **************************************************************************
  //                        NVS - Persistent storage
  // **************************************************************************

  // Init persistent storage
  ESP_LOGE(TAG, "Persistent storage ... ");

  rv = nvs_open("config", NVS_READWRITE, &g_nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Error (%s) opening NVS handle!\n", esp_err_to_name(rv));
  }
  else {

    // Read
    ESP_LOGI(TAG, "Reading restart counter from NVS ... ");
    int32_t restart_counter = 0; // value will default to 0, if not set yet in NVS

    rv = nvs_get_i32(g_nvsHandle, "restart_counter", &restart_counter);
    switch (rv) {

      case ESP_OK:
        ESP_LOGI(TAG, "Restart counter = %d\n", (int) restart_counter);
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        ESP_LOGE(TAG, "The value is not initialized yet!\n");
        break;

      default:
        ESP_LOGE(TAG, "Error (%s) reading!\n", esp_err_to_name(rv));
    }

    // Write
    ESP_LOGI(TAG, "Updating restart counter in NVS ... ");
    restart_counter++;
    rv = nvs_set_i32(g_nvsHandle, "restart_counter", restart_counter);
    if (rv != ESP_OK) {
      ESP_LOGI(TAG, "Failed!\n");
    }
    else {
      ESP_LOGI(TAG, "Done\n");
    }

    // Commit written value.
    // After setting any values, nvs_commit() must be called to ensure changes
    // are written to flash storage. Implementations may write to storage at
    // other times, but this is not guaranteed.
    ESP_LOGI(TAG, "Committing updates in NVS ... ");
    rv = nvs_commit(g_nvsHandle);
    if (rv != ESP_OK) {
      ESP_LOGI(TAG, "Failed!\n");
    }
    else {
      ESP_LOGI(TAG, "Done\n");
    }

    // TODO remove !!!!
    char username[32];
    size_t length = sizeof(username);
    rv            = nvs_get_str(g_nvsHandle, "username", username, &length);
    ESP_LOGI(TAG, "Username_: %s", username);
    length = sizeof(username);
    rv     = nvs_get_str(g_nvsHandle, "password", username, &length);
    ESP_LOGI(TAG, "Password: %s", username);
    length = 16;
    rv     = nvs_get_blob(g_nvsHandle, "guid", g_device_guid, &length);
    // ESP_LOGI(TAG,
    //          "GUID:
    //          %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
    //          device_guid[0],
    //          device_guid[1],
    //          device_guid[2],
    //          device_guid[3],
    //          device_guid[4],
    //          device_guid[5],
    //          device_guid[6],
    //          device_guid[7],
    //          device_guid[8],
    //          device_guid[9],
    //          device_guid[10],
    //          device_guid[11],
    //          device_guid[12],
    //          device_guid[13],
    //          device_guid[14],
    //          device_guid[15]);
    // If GUID is all zero construct GUID
    if (!(g_device_guid[0] | g_device_guid[1] | g_device_guid[2] | g_device_guid[3] | g_device_guid[4] |
          g_device_guid[5] | g_device_guid[6] | g_device_guid[7] | g_device_guid[8] | g_device_guid[9] |
          g_device_guid[10] | g_device_guid[11] | g_device_guid[12] | g_device_guid[13] | g_device_guid[14] |
          g_device_guid[15])) {
      g_device_guid[0] = 0xff;
      g_device_guid[1] = 0xff;
      g_device_guid[2] = 0xff;
      g_device_guid[3] = 0xff;
      g_device_guid[4] = 0xff;
      g_device_guid[5] = 0xff;
      g_device_guid[6] = 0xff;
      g_device_guid[7] = 0xfe;
      rv               = esp_efuse_mac_get_default(g_device_guid + 8);
      // ESP_LOGI(TAG,
      //          "Constructed GUID:
      //          %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
      //          g_device_guid[0],
      //          g_device_guid[1],
      //          g_device_guid[2],
      //          g_device_guid[3],
      //          g_device_guid[4],
      //          g_device_guid[5],
      //          g_device_guid[6],
      //          g_device_guid[7],
      //          g_device_guid[8],
      //          g_device_guid[9],
      //          g_device_guid[10],
      //          g_device_guid[11],
      //          g_device_guid[12],
      //          g_device_guid[13],
      //          g_device_guid[14],
      //          g_device_guid[15]);
    }
  }

  g_ctrl_task_sem = xSemaphoreCreateBinary();

  // Register our event handler for Wi-Fi, IP and Provisioning related events
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

  ESP_LOGI(TAG, "default wifi sta");

  // ESP_ERROR_CHECK(esp_netif_init());
  // ESP_ERROR_CHECK(esp_event_loop_create_default());

  // Start up with default
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  esp_netif_create_default_wifi_sta();

  ESP_LOGI(TAG, "wifi initializated");

  // Do wifi provisioning if needed

#ifdef CONFIG_PROV_TRANSPORT_SOFTAP
  esp_netif_create_default_wifi_ap();
#endif // CONFIG_PROV_TRANSPORT_SOFTAP

  if (!wifi_provisioning()) {

    ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

    /*
     * We don't need the manager as device is already provisioned,
     * so let's release it's resources
     */
    wifi_prov_mgr_deinit();

    ESP_LOGI(TAG, "wifi_prov_mgr_deinit");

    // vscp_wifi_init();
    wifi_init_sta();
    ESP_LOGI(TAG, "wifi init");
  }

  /* Wait for Wi-Fi connection */
  xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);

  // Start LED controlling tast
  xTaskCreate(&led_task, "led_task", 1024, NULL, 5, NULL);

  // espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  // espnow_init(&espnow_config);
  vscp_espnow_init();

  espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  espnow_init(&espnow_config);

  // Start web server
  httpd_handle_t server = start_webserver();

  ESP_LOGI(TAG, "Going to work now!");

  /*
    Start main application loop now
  */

  while (1) {
    // esp_task_wdt_reset();
    ESP_LOGI(TAG, "Loop");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // Clean up

  // Close
  nvs_close(g_nvsHandle);
}
