/* ESPNOW Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
   This example shows how to use ESPNOW.
   Prepare two device, one for sending ESPNOW data and another for receiving
   ESPNOW data.
*/
#include "esp_crc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "espnow_logger.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "nvs_flash.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vscp-droplet.h>

#define ESPNOW_MAXDELAY 512

static const char *TAG = "espnow_logger";

static QueueHandle_t s_logger_queue;

static uint8_t s_example_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint16_t s_logger_seq[LOGGER_DATA_MAX]            = { 0, 0 };

static void
logger_deinit(logger_send_param_t *send_param);

///////////////////////////////////////////////////////////////////////////////
// example_wifi_init
//
/* WiFi should start before using ESPNOW */
static void
example_wifi_init(void)
{
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(ESPNOW_WIFI_MODE));
  ESP_ERROR_CHECK(esp_wifi_start());

#if CONFIG_ESPNOW_ENABLE_LONG_RANGE
  ESP_ERROR_CHECK(esp_wifi_set_protocol(ESPNOW_WIFI_IF,
                                        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
#endif
}

///////////////////////////////////////////////////////////////////////////////
// logger_send_cb
//
/* ESPNOW sending or receiving callback function is called in WiFi task.
 * Users should not do lengthy operations from this task. Instead, post
 * necessary data to a queue and handle it from a lower priority task. */
static void
logger_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  logger_event_t evt;
  logger_event_send_cb_t *send_cb = &evt.info.send_cb;

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = LOGGER_SEND_CB;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;
  if (xQueueSend(s_logger_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send send queue fail");
  }
}

///////////////////////////////////////////////////////////////////////////////
// logger_recv_cb
//

static void
logger_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
{
  logger_event_t evt;
  logger_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

  if (mac_addr == NULL || data == NULL || len <= 0) {
    ESP_LOGE(TAG, "Receive cb arg error");
    return;
  }

  evt.id = LOGGER_RECV_CB;
  memcpy(recv_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  recv_cb->data = malloc(len);
  if (recv_cb->data == NULL) {
    ESP_LOGE(TAG, "Malloc receive data fail");
    return;
  }
  memcpy(recv_cb->data, data, len);
  recv_cb->data_len = len;
  if (xQueueSend(s_logger_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send receive queue fail");
    free(recv_cb->data);
  }
}

///////////////////////////////////////////////////////////////////////////////
// logger_task
//

static void
logger_task(void *pvParameter)
{
  logger_event_t evt;
  uint16_t recv_seq = 0;
  bool is_broadcast = false;
  int ret           = 0;

  while (xQueueReceive(s_logger_queue, &evt, portMAX_DELAY) == pdTRUE) {
    switch (evt.id) {
      case LOGGER_SEND_CB: {
        logger_event_send_cb_t *send_cb = &evt.info.send_cb;
        is_broadcast                    = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG, "Send data to " MACSTR ", status1: %d", MAC2STR(send_cb->mac_addr), send_cb->status);
        break;
      }
      case LOGGER_RECV_CB: {
        logger_event_recv_cb_t *recv_cb = &evt.info.recv_cb;
        printf("-------------------------------------------------------------------------------------------\n");
        printf("Receive %dth broadcast data from: " MACSTR " \n" 
                "To " MACSTR "\n" 
               "len: %d "
               "pktid = %d "
               "ttl = %d, "
               "magic = %02X%02X, "
               "head = %02X%02X, "
               "nickname = %02X%02X, "
               "class = %02X%02X, "
               "type = %02X%02X data-len = %d\n",
               recv_seq,
               MAC2STR(recv_cb->mac_addr),
               MAC2STR(recv_cb->data + DROPLET_POS_DEST_ADDR),
               recv_cb->data_len,
               recv_cb->data[DROPLET_POS_PKTID],      // pktid
               recv_cb->data[DROPLET_POS_TTL],       // ttl
               recv_cb->data[DROPLET_POS_MAGIC],
               recv_cb->data[DROPLET_POS_MAGIC + 1], // magic
               recv_cb->data[DROPLET_POS_HEAD],
               recv_cb->data[DROPLET_POS_HEAD + 1], // head
               recv_cb->data[DROPLET_POS_NICKNAME],
               recv_cb->data[DROPLET_POS_NICKNAME + 1], // nickname
               recv_cb->data[DROPLET_POS_CLASS],
               recv_cb->data[DROPLET_POS_CLASS + 1], // class
               recv_cb->data[DROPLET_POS_TYPE],
               recv_cb->data[DROPLET_POS_TYPE + 1], // type
               (int) recv_cb->data_len - DROPLET_MIN_FRAME);
        ESP_LOG_BUFFER_HEX(TAG, recv_cb->data, recv_cb->data_len);
        recv_seq++;
        // ret = logger_data_parse(recv_cb->data, recv_cb->data_len,
        // &recv_state, &recv_seq, &recv_magic);
        free(recv_cb->data);

        if (ret == LOGGER_DATA_BROADCAST) {}
        else if (ret == LOGGER_DATA_UNICAST) {
          ESP_LOGI(TAG,
                   "Receive %dth unicast data from: " MACSTR ", len: %d",
                   recv_seq,
                   MAC2STR(recv_cb->mac_addr),
                   recv_cb->data_len);
        }
        else {
          ESP_LOGI(TAG, "Receive error data from: " MACSTR "", MAC2STR(recv_cb->mac_addr));
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
// logger_init
//

static esp_err_t
logger_init(void)
{
  logger_send_param_t *send_param;

  s_logger_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(logger_event_t));
  if (s_logger_queue == NULL) {
    ESP_LOGE(TAG, "Create mutex fail");
    return ESP_FAIL;
  }

  /* Initialize ESPNOW and register sending and receiving callback function. */
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_send_cb(logger_send_cb));
  ESP_ERROR_CHECK(esp_now_register_recv_cb(logger_recv_cb));
#if CONFIG_ESP_WIFI_STA_DISCONNECTED_PM_ENABLE
  ESP_ERROR_CHECK(esp_now_set_wake_window(65535));
#endif
  /* Set primary master key. */
  ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

  /* Add broadcast peer information to peer list. */
  esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
  if (peer == NULL) {
    ESP_LOGE(TAG, "Malloc peer information fail");
    vSemaphoreDelete(s_logger_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memset(peer, 0, sizeof(esp_now_peer_info_t));
  peer->channel = CONFIG_ESPNOW_CHANNEL;
  peer->ifidx   = ESPNOW_WIFI_IF;
  peer->encrypt = false;
  memcpy(peer->peer_addr, s_example_broadcast_mac, ESP_NOW_ETH_ALEN);
  ESP_ERROR_CHECK(esp_now_add_peer(peer));
  free(peer);

  /* Initialize sending parameters. */
  send_param = malloc(sizeof(logger_send_param_t));
  if (send_param == NULL) {
    ESP_LOGE(TAG, "Malloc send parameter fail");
    vSemaphoreDelete(s_logger_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memset(send_param, 0, sizeof(logger_send_param_t));
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
    vSemaphoreDelete(s_logger_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }
  memcpy(send_param->dest_mac, s_example_broadcast_mac, ESP_NOW_ETH_ALEN);

  xTaskCreate(logger_task, "logger_task", 4048, send_param, 4, NULL);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// logger_deinit
//

static void
logger_deinit(logger_send_param_t *send_param)
{
  free(send_param->buffer);
  free(send_param);
  vSemaphoreDelete(s_logger_queue);
  esp_now_deinit();
}

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  example_wifi_init();
  logger_init();
}
