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

#include <freertos/FreeRTOS.h>
#include "freertos/semphr.h"
#include "freertos/timers.h"
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
#include <esp_task_wdt.h>
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

#include "tcpsrv.h"
#include "vscp_espnow.h"

#include "main.h"
#include "wifiprov.h"

const char *pop_data   = "ESPNOW_VSCP_ALPHA";
static const char *TAG = "espnow_alpha";

// Handle for nvs storage
nvs_handle_t g_nvsHandle;

// Transports
transport_t g_tr_tcpsrv[MAX_TCP_CONNECTIONS] = {};
transport_t g_tr_mqtt      = {}; // MQTT

///////////////////////////////////////////////////////////
//                      V S C P
///////////////////////////////////////////////////////////

// GUID for unit
uint8_t g_node_guid[16]; // Ful GUID for node


// ESP-NOW
SemaphoreHandle_t g_ctrl_task_sem;

// Message queues for espnow messages
// QueueHandle_t g_tx_msg_queue;
// QueueHandle_t g_rx_msg_queue;

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

//static uint16_t s_espnow_seq[ESPNOW_DATA_MAX] = { 0, 0 };

static uint8_t s_vscp_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t s_vscp_own_mac[ESP_NOW_ETH_ALEN]       = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// Provisioning state
static espnow_ctrl_status_t s_espnow_ctrl_prov_state = ESPNOW_CTRL_INIT;

espnow_sec_t *g_sec; // espnow security structure

// Forward declarations
static void
vscp_espnow_deinit(void *param);

// Signal Wi-Fi events on this event-group
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

///////////////////////////////////////////////////////////////////////////////
// vscp_heartbeat_task
//
// Sent periodically as a broadcast to all zones/subzones
//

static void
vscp_heartbeat_task(void *pvParameter)
{
  esp_err_t ret = 0;
  uint8_t dest_mac[ESP_NOW_ETH_ALEN];
  uint8_t buf[VSCP_ESPNOW_PACKET_MIN_SIZE + 3];
  size_t size = sizeof(buf);

  ESP_LOGI(TAG, "Start sending VSCP heartbeats");

  espnow_frame_head_t frame_head = {
    .retransmit_count = 1,
    .broadcast        = true,
    .forward_ttl      = 7,
  };

  ESP_LOGI(TAG, "magic=0x%X", ret);

  

  while (1) {

    vTaskDelay(VSCP_HEART_BEAT_INTERVAL / portTICK_RATE_MS);

    ret = espnow_send(ESPNOW_TYPE_DATA, dest_mac, buf, size, &frame_head, portMAX_DELAY);

    ESP_LOGI(TAG, "VSCP heartbeat sent - ret=0x%X", ret);
    ESP_ERROR_CONTINUE(ret != ESP_OK, "<%s>", esp_err_to_name(ret));
  }

  ESP_LOGW(TAG, "Heartbeat task exit %d", ret);
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_send_task
//

static void
vscp_espnow_send_task(void *pvParameter)
{
  vscp_espnow_event_post_t evt;
  esp_err_t ret;
  uint8_t dest_mac[ESP_NOW_ETH_ALEN]; // MAC address of destination device.
  vscp_espnow_event_t vscpEspNowEvent;
  uint8_t buf[VSCP_ESPNOW_PACKET_MAX_SIZE];
  static int cnt = 0;

  memcpy(dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);

  // vTaskDelay(5000 / portTICK_RATE_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  // vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

  ESP_LOGI(TAG, "Before broadcast send");

  // espnow_frame_head_t frame_head = {
  //   .channel = 11,
  //   .retransmit_count = 0,
  //   .broadcast        = true,
  //   .forward_ttl      = 1,
  //   .ack = 0,
  // };

  // ESPNOW_FRAME_CONFIG_DEFAULT();
  espnow_frame_head_t frame_head = {
    .retransmit_count = 2,
    .broadcast        = true,
    .forward_ttl      = 7,
  };

  while (1) {

    ret = espnow_send(ESPNOW_TYPE_DATA,
                      dest_mac,
                      buf,
                      VSCP_ESPNOW_PACKET_MIN_SIZE, //+ vscpEspNowEvent.len,
                      &frame_head,
                      portMAX_DELAY);

    vTaskDelay(5000 / portTICK_RATE_MS);
    ESP_LOGI(TAG, "Broadcast sent - ret=0x%X", ret);
    ESP_ERROR_CONTINUE(ret != ESP_OK, "<%s>", esp_err_to_name(ret));
  }

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

        // vTaskDelay(2000 / portTICK_RATE_MS);
        //  if (is_broadcast && (send_param->broadcast == false)) {
        //    break;
        //  }

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

        memcpy(dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        // scp_espnow_heart_beat_prepare(send_param);

        // vscpEspNowEvent.ttl   = 7;
        // vscpEspNowEvent.seq   = seq++;
        // vscpEspNowEvent.magic = esp_random();
        // vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

        /* Send the next data after the previous data is sent. */
        // if (esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MAX_SIZE) != ESP_OK) {
        //   ESP_LOGE(TAG, "Send error");
        //   vscp_espnow_deinit(NULL);
        //   vTaskDelete(NULL);
        // }
        espnow_frame_head_t frame_head = {
          .channel                 = 11,
          .retransmit_count        = 0,
          .broadcast               = true,
          .forward_ttl             = 0,
          .magic                   = esp_random(),
          .forward_rssi            = 0,
          .filter_adjacent_channel = 0,
          .filter_weak_signal      = 0,
          .group                   = 0,
        };

        memset(buf, 0, sizeof(buf));
        buf[0]              = 11;
        buf[1]              = 22;
        buf[2]              = 33;
        buf[3]              = 44;
        buf[4]              = 55;
        vscpEspNowEvent.len = 5;

        // espnow_data->size + sizeof(espnow_data_t)

        ret = espnow_send(ESPNOW_TYPE_DATA,
                          dest_mac,
                          buf,
                          VSCP_ESPNOW_PACKET_MIN_SIZE + vscpEspNowEvent.len,
                          &frame_head,
                          portMAX_DELAY);

        ESP_LOGI(TAG,
                 "send frame %d to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00 - ret=%d ch=%d",
                 cnt++,
                 MAC2STR(send_cb->mac_addr),
                 (int) ret,
                 (int) frame_head.channel);

        break;
      }

      case VSCP_ESPNOW_RECV_EVT: {
        ESP_LOGI(TAG, "Receive: %d", evt.id);
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
  espnow_config.qsize.data      = 64;
  espnow_config.send_retry_num  = 5;
  //strcpy(espnow_config.pmk, "pmk1234567890123");
  espnow_init(&espnow_config);

  // Initialize ESPNOW and register sending and receiving callback function.
  // ESP_ERROR_CHECK(esp_now_init());
  // ESP_ERROR_CHECK(esp_now_register_send_cb(vscp_espnow_send_cb));
  // ESP_ERROR_CHECK(esp_now_register_recv_cb(vscp_espnow_recv_cb));

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
  esp_wifi_set_channel(11, 0);
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
    vTaskDelay(100 / portTICK_PERIOD_MS);
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
  //ESP_ERROR_CHECK(esp_timer_create());

  // Start timer
  //esp_timer_start_periodic();

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
  // g_tx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Outgoing esp-now messages */
  // g_rx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Incoming esp-now messages */

  // Initiate message queues
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    g_tr_tcpsrv[i].msg_queue = xQueueCreate(10, VSCP_ESPNOW_PACKET_MAX_SIZE); // tcp/ip link channel i
  } 
  g_tr_mqtt.msg_queue      = xQueueCreate(10, VSCP_ESPNOW_PACKET_MAX_SIZE); // MQTT empties

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
    rv     = nvs_get_blob(g_nvsHandle, "guid", g_node_guid, &length);

    // If GUID is all zero construct GUID
    if (!(g_node_guid[0] | g_node_guid[1] | g_node_guid[2] | g_node_guid[3] | g_node_guid[4] | g_node_guid[5] |
          g_node_guid[6] | g_node_guid[7] | g_node_guid[8] | g_node_guid[9] | g_node_guid[10] | g_node_guid[11] |
          g_node_guid[12] | g_node_guid[13] | g_node_guid[14] | g_node_guid[15])) {
      g_node_guid[0] = 0xff;
      g_node_guid[1] = 0xff;
      g_node_guid[2] = 0xff;
      g_node_guid[3] = 0xff;
      g_node_guid[4] = 0xff;
      g_node_guid[5] = 0xff;
      g_node_guid[6] = 0xff;
      g_node_guid[7] = 0xfe;
      rv             = esp_efuse_mac_get_default(g_node_guid + 8);
      ESP_LOGD(TAG,
               "Constructed GUID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               g_node_guid[0],
               g_node_guid[1],
               g_node_guid[2],
               g_node_guid[3],
               g_node_guid[4],
               g_node_guid[5],
               g_node_guid[6],
               g_node_guid[7],
               g_node_guid[8],
               g_node_guid[9],
               g_node_guid[10],
               g_node_guid[11],
               g_node_guid[12],
               g_node_guid[13],
               g_node_guid[14],
               g_node_guid[15]);
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

    wifi_init_sta();
    ESP_LOGI(TAG, "wifi init");
  }

  /* Wait for Wi-Fi connection */
  xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);

  // Start LED controlling tast
  xTaskCreate(&led_task, "led_task", 1024, NULL, 5, NULL);

  // Start heartbeat task vscp_heartbeat_task
  xTaskCreate(&vscp_heartbeat_task, "vscp_heartbeat_task", 2024, NULL, 5, NULL);

  // Initialize espnow
  vscp_espnow_init();

  // Start web server
  httpd_handle_t server = start_webserver();

  xTaskCreate(&tcpsrv_task, "vscp_tcpsrv_task", 2024, NULL, 5, NULL);

  ESP_LOGI(TAG, "Going to work now!");

  /*
    Start main application loop now
  */

  while (1) {
    // esp_task_wdt_reset();
    ESP_LOGI(TAG, "Ctrl - Loop");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // Clean up

  // Close
  nvs_close(g_nvsHandle);
}
