/*
  File: main.c

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG, Frankfurt-WiFi)

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

#include <freertos/FreeRTOS.h>
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <driver/gpio.h>
#include <driver/temperature_sensor.h>
#include <esp_event.h>

#include <esp_task_wdt.h>

#include <esp_http_server.h>
#include "esp_crc.h"
#include "esp_now.h"
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_timer.h>
#include <esp_tls_crypto.h>
#include <esp_wifi.h>
#include <nvs_flash.h>

#include <wifi_provisioning/manager.h>

#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
#include <wifi_provisioning/scheme_ble.h>
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */

#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
#include <wifi_provisioning/scheme_softap.h>
#endif /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
#include "qrcode.h"

#include <vscp.h>
#include "websrv.h"

#include "main.h"

static const char *TAG = "main";

/**!
 * Configure temperature sensor
 */
temperature_sensor_config_t cfgTempSensor = {
  .range_min = 20,
  .range_max = 50,
};

// Handle for nvs storage
nvs_handle_t nvsHandle;

// GUID for unit
uint8_t device_guid[16];

SemaphoreHandle_t ctrl_task_sem;

// ESP-NOW

#define ESPNOW_MAXDELAY 512 // Delat for send queue

static QueueHandle_t s_espnow_queue;

static uint8_t s_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint16_t s_espnow_seq[ESPNOW_DATA_MAX]    = { 0, 0 };

// Forward declarations

static void
espnow_deinit(espnow_send_param_t *send_param);

// Provisioning

#if CONFIG_WCANG_PROV_SECURITY_VERSION_2

#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
#define WCANG_PROV_SEC2_USERNAME "testuser"
#define WCANG_PROV_SEC2_PWD      "testpassword"

/* This salt,verifier has been generated for username = "testuser" and password
 * = "testpassword" IMPORTANT NOTE: For production cases, this must be unique to
 * every device and should come from device manufacturing partition.*/
static const char sec2_salt[] = { 0x2f, 0x3d, 0x3c, 0xf8, 0x0d, 0xbd, 0x0c, 0xa9,
                                  0x6f, 0x30, 0xb4, 0x4d, 0x89, 0xd5, 0x2f, 0x0e };

// 24*16 = 384 * 8 = 3072
static const char sec2_verifier[] = {
  0xf2, 0x9f, 0xc1, 0xf5, 0x28, 0x4a, 0x11, 0x74, 0xb4, 0x24, 0x09, 0x23, 0xd8, 0x27, 0xb7, 0x5a, 0x95, 0x3a, 0x99,
  0xed, 0xf4, 0x6e, 0xe9, 0x8c, 0x4f, 0x07, 0xf2, 0xf5, 0x43, 0x3d, 0x7f, 0x9a, 0x11, 0x60, 0x66, 0xaf, 0xcd, 0xa5,
  0xf6, 0xfa, 0xcb, 0x06, 0xe9, 0xc5, 0x3f, 0x4d, 0x77, 0x16, 0x4c, 0x68, 0x6d, 0x7f, 0x7c, 0xd7, 0xc7, 0x5a, 0x83,
  0xc0, 0xfb, 0x94, 0x2d, 0xa9, 0x60, 0xf0, 0x09, 0x11, 0xa0, 0xe1, 0x95, 0x33, 0xd1, 0x30, 0x7f, 0x82, 0x1b, 0x1b,
  0x0f, 0x6d, 0xf1, 0xdc, 0x93, 0x1c, 0x20, 0xa7, 0xc0, 0x8d, 0x48, 0x38, 0xff, 0x46, 0xb9, 0xaf, 0xf7, 0x93, 0x78,
  0xae, 0xff, 0xb8, 0x3b, 0xdf, 0x99, 0x7b, 0x64, 0x47, 0x02, 0xba, 0x01, 0x39, 0x0f, 0x5c, 0xd8, 0x4e, 0x6f, 0xc8,
  0xd0, 0x82, 0x7f, 0x2d, 0x33, 0x1a, 0x09, 0x65, 0x77, 0x85, 0xbc, 0x8a, 0x84, 0xe0, 0x46, 0x7e, 0x3b, 0x0e, 0x6e,
  0x3b, 0xdf, 0x70, 0x17, 0x70, 0x0a, 0xbc, 0x84, 0x67, 0xfa, 0xf9, 0x84, 0x53, 0xda, 0xb4, 0xca, 0x38, 0x71, 0xe4,
  0x06, 0xf6, 0x7d, 0xc8, 0x32, 0xbb, 0x91, 0x0c, 0xe7, 0xd3, 0x59, 0xb6, 0x03, 0xed, 0x8e, 0x0d, 0x91, 0x9c, 0x09,
  0xd7, 0x6f, 0xd5, 0xca, 0x55, 0xc5, 0x58, 0x0f, 0x95, 0xb5, 0x83, 0x65, 0x6f, 0x2d, 0xbc, 0x94, 0x0f, 0xbb, 0x0f,
  0xd3, 0x42, 0xa5, 0xfe, 0x15, 0x7f, 0xf9, 0xa8, 0x16, 0xe6, 0x58, 0x9b, 0x4c, 0x0f, 0xd3, 0x83, 0x2c, 0xac, 0xe4,
  0xbf, 0xa3, 0x96, 0x1e, 0xb6, 0x6f, 0x59, 0xe6, 0xd1, 0x0e, 0xd4, 0x27, 0xb6, 0x05, 0x34, 0xec, 0x8c, 0xf8, 0x72,
  0xbb, 0x04, 0x7b, 0xa4, 0x49, 0x3d, 0x6d, 0xa9, 0x99, 0xfc, 0x0a, 0x2b, 0xd8, 0x46, 0xa8, 0xd1, 0x46, 0x61, 0x5c,
  0x96, 0xd2, 0x43, 0xcd, 0xea, 0x7f, 0x6a, 0x50, 0x59, 0x0d, 0x0e, 0xa1, 0xb3, 0x94, 0x5a, 0x34, 0xe0, 0x1e, 0x95,
  0x56, 0x68, 0xb4, 0xbc, 0xf1, 0x08, 0x54, 0xcb, 0x42, 0x41, 0xc6, 0x78, 0xad, 0x71, 0x84, 0x1c, 0x29, 0xb8, 0x33,
  0x79, 0x1c, 0x10, 0xdd, 0x07, 0xc8, 0x91, 0x21, 0x85, 0x89, 0x76, 0xd7, 0x37, 0xdf, 0x5b, 0x19, 0x33, 0x4e, 0x17,
  0x67, 0x02, 0x0f, 0x1b, 0xb9, 0x2f, 0xa4, 0xdc, 0xdd, 0x75, 0x32, 0x96, 0x87, 0xdd, 0x66, 0xc3, 0x33, 0xc1, 0xfc,
  0x4c, 0x27, 0x63, 0xb9, 0x14, 0x72, 0x76, 0x65, 0xb8, 0x90, 0x2b, 0xeb, 0x7a, 0xde, 0x71, 0x97, 0xf3, 0x6b, 0xc9,
  0x8e, 0xdf, 0xfc, 0x6e, 0x13, 0xcc, 0x1b, 0x2b, 0x54, 0x1a, 0x6e, 0x3d, 0xe6, 0x1c, 0xec, 0x5d, 0xa1, 0xf1, 0xd4,
  0x86, 0x9d, 0xcd, 0xb9, 0xe8, 0x98, 0xf1, 0xe5, 0x16, 0xa5, 0x48, 0xe5, 0xec, 0x12, 0xe8, 0x17, 0xe2, 0x55, 0xb5,
  0xb3, 0x7c, 0xce, 0xfd
};
#endif

///////////////////////////////////////////////////////////////////////////////
// wcang_get_sec2_salt
//

static esp_err_t
wcang_get_sec2_salt(const char **salt, uint16_t *salt_len)
{
#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded salt");
  *salt     = sec2_salt;
  *salt_len = sizeof(sec2_salt);
  return ESP_OK;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}

///////////////////////////////////////////////////////////////////////////////
// wcang_get_sec2_verifier
//

static esp_err_t
wcang_get_sec2_verifier(const char **verifier, uint16_t *verifier_len)
{
#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded verifier");
  *verifier     = sec2_verifier;
  *verifier_len = sizeof(sec2_verifier);
  return ESP_OK;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
  /* This code needs to be updated with appropriate implementation to provide
   * verifier */
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}
#endif

/* Signal Wi-Fi events on this event-group */
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

#define PROV_QR_VERSION       "v1"
#define PROV_TRANSPORT_SOFTAP "softap"
#define PROV_TRANSPORT_BLE    "ble"
#define QRCODE_BASE_URL       "https://espressif.github.io/esp-jumpstart/qrcode.html"

///////////////////////////////////////////////////////////////////////////////
// wifi_init_sta
//

// static void
// wifi_init_sta(void)
// {
//   /* Start Wi-Fi in station mode */
//   ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
//   ESP_ERROR_CHECK(esp_wifi_start());
// }

///////////////////////////////////////////////////////////////////////////////
// wifi_init
//
// WiFi should start before using ESPNOW
//

static void
wifi_init(void)
{
  // ESP_ERROR_CHECK(esp_netif_init());
  // ESP_ERROR_CHECK(esp_event_loop_create_default());
  // wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  // ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  // ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
  ESP_ERROR_CHECK(esp_wifi_start());

  
  EventBits_t uxBits = xEventGroupWaitBits(
            wifi_event_group,             // The event group being tested. 
            WIFI_CONNECTED_EVENT,         // The bits within the event group to wait for. 
            pdFALSE,                      // BIT_0 & BIT_4 should be cleared before returning. 
            pdFALSE,                      // Don't wait for both bits, either bit will do. 
            1000 / portTICK_PERIOD_MS );  // Wait a maximum of 100ms for either bit to be set. 

  if (uxBits & WIFI_CONNECTED_EVENT) {    
    ESP_LOGI(TAG,"CONNECTED");
    //vTaskDelay(5000 / portTICK_PERIOD_MS);
    //ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    //ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE));
    //ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
  }

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

  ESP_LOGI(TAG, "Send cb");

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = ESPNOW_SEND_CB;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;
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

  ESP_LOGI(TAG, "Recv cb");

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

  vTaskDelay(5000 / portTICK_PERIOD_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  /* Start sending broadcast ESPNOW data. */
  espnow_send_param_t *send_param = (espnow_send_param_t *) pvParameter;
  if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
    ESP_LOGE(TAG, "Send error");
    espnow_deinit(send_param);
    vTaskDelete(NULL);
  }

  ESP_LOGI(TAG, "Waiting for broadcast response");

  while (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {
    
      case ESPNOW_SEND_CB: {
        espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        is_broadcast                    = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG, "Send data to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00, status1: %d", MAC2STR(send_cb->mac_addr), send_cb->status);

        if (is_broadcast && (send_param->broadcast == false)) {
          break;
        }

        if (!is_broadcast) {
          //send_param->count--;
          if (send_param->count == 0) {
            ESP_LOGI(TAG, "Send done");
            espnow_deinit(send_param);
            vTaskDelete(NULL);
          }
        }

        /* Delay a while before sending the next data. */
        if (send_param->delay > 0) {
          vTaskDelay(send_param->delay / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "send data to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", MAC2STR(send_cb->mac_addr));

        memcpy(send_param->dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        espnow_data_prepare(send_param);

        // Send the next data after the previous data is sent. 
        if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
          ESP_LOGE(TAG, "Send error");
          espnow_deinit(send_param);
          vTaskDelete(NULL);
        }
        break;
      }

      case ESPNOW_RECV_CB: {

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
              espnow_deinit(send_param);
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
              ESP_LOGI(TAG, "send data to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", MAC2STR(recv_cb->mac_addr));

              /* Start sending unicast ESPNOW data. */
              memcpy(send_param->dest_mac, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
              espnow_data_prepare(send_param);
              if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
                ESP_LOGE(TAG, "Send error");
                espnow_deinit(send_param);
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
// espnow_init
//

static esp_err_t
espnow_init(void)
{
  espnow_send_param_t *send_param;

  s_espnow_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(espnow_event_t));
  if (s_espnow_queue == NULL) {
    ESP_LOGE(TAG, "Create mutex fail");
    return ESP_FAIL;
  }

  /* Initialize ESPNOW and register sending and receiving callback function. */
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));
  ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
#if CONFIG_ESP_WIFI_STA_DISCONNECTED_PM_ENABLE
  ESP_ERROR_CHECK(esp_now_set_wake_window(65535));
#endif
  /* Set primary master key. */
  ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

  /* Add broadcast peer information to peer list. */
  esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
  if (peer == NULL) {
    ESP_LOGE(TAG, "Malloc peer information fail");
    vSemaphoreDelete(s_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }

  // Get wifi channel
  uint8_t primary_channel;
  wifi_second_chan_t secondary_channel;
  esp_wifi_get_channel(&primary_channel, &secondary_channel);

  memset(peer, 0, sizeof(esp_now_peer_info_t));
  peer->channel = primary_channel; //CONFIG_ESPNOW_CHANNEL;
  peer->ifidx   = ESPNOW_WIFI_IF;
  peer->encrypt = false;
  memcpy(peer->peer_addr, s_broadcast_mac, ESP_NOW_ETH_ALEN);
  ESP_ERROR_CHECK(esp_now_add_peer(peer));
  free(peer);

  /* Initialize sending parameters. */
  send_param = malloc(sizeof(espnow_send_param_t));
  if (send_param == NULL) {
    ESP_LOGE(TAG, "Malloc send parameter fail");
    vSemaphoreDelete(s_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memset(send_param, 0, sizeof(espnow_send_param_t));
  send_param->unicast   = false;
  send_param->broadcast = true;
  send_param->state     = 0;
  send_param->magic     = esp_random();
  send_param->count     = CONFIG_ESPNOW_SEND_COUNT;
  send_param->delay     = CONFIG_ESPNOW_SEND_DELAY;
  send_param->len       = CONFIG_ESPNOW_SEND_LEN;
  send_param->buffer    = malloc(CONFIG_ESPNOW_SEND_LEN);
  if (send_param->buffer == NULL) {
    ESP_LOGE(TAG, "Malloc send buffer fail");
    free(send_param);
    vSemaphoreDelete(s_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memcpy(send_param->dest_mac, s_broadcast_mac, ESP_NOW_ETH_ALEN);
  espnow_data_prepare(send_param);

  xTaskCreate(espnow_task, "espnow_task", 2048, send_param, 4, NULL);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// espnow_deinit
//

static void
espnow_deinit(espnow_send_param_t *send_param)
{
  free(send_param->buffer);
  free(send_param);
  vSemaphoreDelete(s_espnow_queue);
  esp_now_deinit();
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

  rv = nvs_get_blob(nvsHandle, "guid", pguid, &length);
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

#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
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
#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
        retries++;
        if (retries >= CONFIG_WCANG_PROV_MGR_MAX_RETRY_CNT) {
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
#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
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

///////////////////////////////////////////////////////////////////////////////
// get_device_service_name
//

static void
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

static void
wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport)
{
  if (!name || !transport) {
    ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
    return;
  }
  char payload[150] = { 0 };
  if (pop) {
#if CONFIG_WCANG_PROV_SECURITY_VERSION_1
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             pop,
             transport);
#elif CONFIG_WCANG_PROV_SECURITY_VERSION_2
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
#ifdef CONFIG_WCANG_PROV_SHOW_QR
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

  // QueueHandle_t test = xQueueCreate(10, sizeof( twai_message_t) );

  // **************************************************************************
  //                        NVS - Persistent storage
  // **************************************************************************

  // Init persistent storage
  ESP_LOGE(TAG, "Persistent storage ... ");

  rv = nvs_open("config", NVS_READWRITE, &nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Error (%s) opening NVS handle!\n", esp_err_to_name(rv));
  }
  else {

    // Read
    ESP_LOGI(TAG, "Reading restart counter from NVS ... ");
    int32_t restart_counter = 0; // value will default to 0, if not set yet in NVS

    rv = nvs_get_i32(nvsHandle, "restart_counter", &restart_counter);
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
    rv = nvs_set_i32(nvsHandle, "restart_counter", restart_counter);
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
    rv = nvs_commit(nvsHandle);
    if (rv != ESP_OK) {
      ESP_LOGI(TAG, "Failed!\n");
    }
    else {
      ESP_LOGI(TAG, "Done\n");
    }

    // TODO remove !!!!
    char username[32];
    size_t length = sizeof(username);
    rv            = nvs_get_str(nvsHandle, "username", username, &length);
    ESP_LOGI(TAG, "Username_: %s", username);
    length = sizeof(username);
    rv     = nvs_get_str(nvsHandle, "password", username, &length);
    ESP_LOGI(TAG, "Password: %s", username);
    length = 16;
    rv     = nvs_get_blob(nvsHandle, "guid", device_guid, &length);
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
    if (!(device_guid[0] | device_guid[1] | device_guid[2] | device_guid[3] | device_guid[4] | device_guid[5] |
          device_guid[6] | device_guid[7] | device_guid[8] | device_guid[9] | device_guid[10] | device_guid[11] |
          device_guid[12] | device_guid[13] | device_guid[14] | device_guid[15])) {
      device_guid[0] = 0xff;
      device_guid[1] = 0xff;
      device_guid[2] = 0xff;
      device_guid[3] = 0xff;
      device_guid[4] = 0xff;
      device_guid[5] = 0xff;
      device_guid[6] = 0xff;
      device_guid[7] = 0xfe;
      rv             = esp_efuse_mac_get_default(device_guid + 8);
      // ESP_LOGI(TAG,
      //          "Constructed GUID:
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
    }
  }

  ctrl_task_sem = xSemaphoreCreateBinary();

  // Register our event handler for Wi-Fi, IP and Provisioning related events
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

  // Initialize Wi-Fi including netif with default config
  esp_netif_create_default_wifi_sta();

#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
  esp_netif_create_default_wifi_ap();
#endif // CONFIG_WCANG_PROV_TRANSPORT_SOFTAP

  // ESP_ERROR_CHECK(esp_netif_init());
  // ESP_ERROR_CHECK(esp_event_loop_create_default());

  // Start up with default
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  // --------------------------------------------------------
  //                      Provisioning
  // --------------------------------------------------------

  // Configuration for the provisioning manager
  wifi_prov_mgr_config_t config = {
  // What is the Provisioning Scheme that we want ?
  // wifi_prov_scheme_softap or wifi_prov_scheme_ble
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    .scheme = wifi_prov_scheme_ble,
#endif // CONFIG_WCANG_PROV_TRANSPORT_BLE
#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
    .scheme = wifi_prov_scheme_softap,
#endif // CONFIG_WCANG_PROV_TRANSPORT_SOFTAP

  /*
   * Any default scheme specific event handler that you would
   * like to choose. Since our example application requires
   * neither BT nor BLE, we can choose to release the associated
   * memory once provisioning is complete, or not needed
   * (in case when device is already provisioned). Choosing
   * appropriate scheme specific event handler allows the manager
   * to take care of this automatically. This can be set to
   * WIFI_PROV_EVENT_HANDLER_NONE when using wifi_prov_scheme_softap
   */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
    .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE
#endif /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
  };

  /*
   * Initialize provisioning manager with the
   * configuration parameters set above
   */
  ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

  bool provisioned = false;
#ifdef CONFIG_WCANG_RESET_PROVISIONED
  wifi_prov_mgr_reset_provisioning();
#else
  /* Let's find out if the device is provisioned */
  ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));

#endif

  /* If device is not yet provisioned start provisioning service */
  if (!provisioned) {

    ESP_LOGI(TAG, "Starting provisioning");

    /*
     * What is the Device Service Name that we want
     *
     * This translates to :
     *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
     *     - device name when scheme is wifi_prov_scheme_ble
     */
    char service_name[12];
    get_device_service_name(service_name, sizeof(service_name));

#ifdef CONFIG_WCANG_PROV_SECURITY_VERSION_1
    /*
     * What is the security level that we want (0, 1, 2):
     *
     *   - WIFI_PROV_SECURITY_0 is simply plain text communication.
     *   - WIFI_PROV_SECURITY_1 is secure communication which consists of secure
     * handshake using X25519 key exchange and proof of possession (pop) and
     * AES-CTR for encryption/decryption of messages.
     *   - WIFI_PROV_SECURITY_2 SRP6a based authentication and key exchange
     *      + AES-GCM encryption/decryption of messages
     */
    wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

    /*
     * Do we want a proof-of-possession (ignored if Security 0 is selected):
     *   - this should be a string with length > 0
     *   - NULL if not used
     */
    const char *pop = "VSCP-Dropplet-Alpha";
    /*
     * If the pop is allocated dynamically, then it should be valid till
     * the provisioning process is running.
     * it can be only freed when the WIFI_PROV_END event is triggered
     */

    /*
     * This is the structure for passing security parameters
     * for the protocomm security 1.
     * This does not need not be static i.e. could be dynamically allocated
     */
    wifi_prov_security1_params_t *sec_params = pop;

    const char *username = NULL;

#elif CONFIG_WCANG_PROV_SECURITY_VERSION_2
    wifi_prov_security_t security = WIFI_PROV_SECURITY_2;
    // The username must be the same one, which has been used in the generation
    // of salt and verifier

#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
    /*
     * This pop field represents the password that will be used to generate salt
     * and verifier. The field is present here in order to generate the QR code
     * containing password. In production this password field shall not be
     * stored on the device
     */
    const char *username = WCANG_PROV_SEC2_USERNAME;
    const char *pop = WCANG_PROV_SEC2_PWD;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
    /*
     * The username and password shall not be embedded in the firmware,
     * they should be provided to the user by other means.
     * e.g. QR code sticker
     */
    const char *username = NULL;
    const char *pop      = NULL;
#endif
    /*
     * This is the structure for passing security parameters
     * for the protocomm security 2.
     * This does not need not be static i.e. could be dynamically allocated
     */
    wifi_prov_security2_params_t sec2_params = {};

    ESP_ERROR_CHECK(wcang_get_sec2_salt(&sec2_params.salt, &sec2_params.salt_len));
    ESP_ERROR_CHECK(wcang_get_sec2_verifier(&sec2_params.verifier, &sec2_params.verifier_len));

    wifi_prov_security2_params_t *sec_params = &sec2_params;
#endif

    /*
     * What is the service key (could be NULL)
     * This translates to :
     *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
     *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
     *     - simply ignored when scheme is wifi_prov_scheme_ble
     */
    const char *service_key = NULL;

#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    /*
     * This step is only useful when scheme is wifi_prov_scheme_ble. This will
     * set a custom 128 bit UUID which will be included in the BLE advertisement
     * and will correspond to the primary GATT service that provides
     * provisioning endpoints as GATT characteristics. Each GATT characteristic
     * will be formed using the primary service UUID as base, with different
     * auto assigned 12th and 13th bytes (assume counting starts from 0th byte).
     * The client side applications must identify the endpoints by reading the
     * User Characteristic Description descriptor (0x2901) for each
     * characteristic, which contains the endpoint name of the characteristic
     */
    uint8_t custom_service_uuid[] = {
      /*
       * LSB <---------------------------------------
       * ---------------------------------------> MSB
       */
      0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04, 0x90, 0x1a, 0x02,
    };

    /*
     * If your build fails with linker errors at this point, then you may have
     * forgotten to enable the BT stack or BTDM BLE settings in the SDK (e.g.
     * see the sdkconfig.defaults in the example project)
     */
    wifi_prov_scheme_ble_set_service_uuid(custom_service_uuid);
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */

    /*
     * An optional endpoint that applications can create if they expect to
     * get some additional custom data during provisioning workflow.
     * The endpoint name can be anything of your choice.
     * This call must be made before starting the provisioning.
     */
    wifi_prov_mgr_endpoint_create("VSCP-WCANG");

    /* Start provisioning service */
    ESP_ERROR_CHECK(wifi_prov_mgr_start_provisioning(security, (const void *) sec_params, service_name, service_key));

    /*
     * The handler for the optional endpoint created above.
     * This call must be made after starting the provisioning, and only if the
     * endpoint has already been created above.
     */
    wifi_prov_mgr_endpoint_register("VSCP-WCANG", custom_prov_data_handler, NULL);

    /*
     * Uncomment the following to wait for the provisioning to finish and then
     * release the resources of the manager. Since in this case
     * de-initialization is triggered by the default event loop handler, we
     * don't need to call the following
     */
    // wifi_prov_mgr_wait();
    // wifi_prov_mgr_deinit();

    /* Print QR code for provisioning */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_BLE);
#else  /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_SOFTAP);
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */
  }
  else {
    ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

    /*
     * We don't need the manager as device is already provisioned,
     * so let's release it's resources
     */
    wifi_prov_mgr_deinit();

    /* Start Wi-Fi station */
    //wifi_init_sta();
    // esp_wifi_deinit();
    wifi_init();
  }

  /* Wait for Wi-Fi connection */
  xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);

  // wifi_init();
  espnow_init();

  // First start of web server
  int server = start_webserver();

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
  nvs_close(nvsHandle);
}
