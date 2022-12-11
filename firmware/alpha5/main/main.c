/*
  File: main.c

  VSCP alpha node

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
#include <freertos/semphr.h>
#include <freertos/timers.h>
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <driver/ledc.h>
#include <driver/gpio.h>

#include <esp_check.h>
#include <esp_crc.h>
#include <esp_http_client.h>
#include <esp_https_ota.h>
#include <esp_now.h>
#include <esp_event_base.h>
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <esp_tls_crypto.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <esp_spiffs.h>
#include <lwip/sockets.h>

#include "websrv.h"

#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>

#include "tcpsrv.h"
#include "vscp-droplet.h"

#include "main.h"
#include "wifiprov.h"

#include <wifi_provisioning/manager.h>

#include "button.h"
#include "led_indicator.h"

// #ifdef CONFIG_PROV_TRANSPORT_BLE
// #include <wifi_provisioning/scheme_ble.h>
// #endif /* CONFIG_PROV_TRANSPORT_BLE */

// #ifdef CONFIG_PROV_TRANSPORT_SOFTAP
// #include <wifi_provisioning/scheme_softap.h>
// #endif /* CONFIG_PROV_TRANSPORT_SOFTAP */

const char *pop_data   = "VSCP ALPHA";
static const char *TAG = "alpha";

#define HASH_LEN   32
#define BUTTON_CNT 1

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

// Holds alpha node states
alpha_node_states_t g_state = MAIN_STATE_INIT;

// Event source task related definitions
ESP_EVENT_DEFINE_BASE(ALPHA_EVENT);

// Handle for status led
led_indicator_handle_t g_led_handle;

// Handle for nvs storage
nvs_handle_t g_nvsHandle = 0;

static QueueHandle_t s_espnow_queue;

// If init button is held for  > 10 seconds defaults are stored and the
// node is restarted. Wifi creadentials need to be restored
uint32_t g_restore_defaults_timer = 0;

// Initiating provisioning is done with a button click
// the provisioning state is active for 30 seconds
uint32_t g_provisioning_state_timer = 0;

// Button defines
static button_handle_t g_btns[BUTTON_CNT] = { 0 };

// Transports
transport_t g_tr_tcpsrv[MAX_TCP_CONNECTIONS] = {};
transport_t g_tr_mqtt                        = {}; // MQTT

static void
vscp_heartbeat_task(void *pvParameter);
static void
vscp_espnow_send_task(void *pvParameter);

enum {
  VSCP_SEND_STATE_NONE,
  VSCP_SEND_STATE_SENT,        // Event has been sent, no other events can be sent
  VSCP_SEND_STATE_SEND_CONFIRM // Event send has been confirmed
};

typedef struct __state__ {
  uint8_t state;      // State of send
  uint64_t timestamp; // Time when state was set
} vscp_send_state_t;

static vscp_send_state_t g_send_state = { VSCP_SEND_STATE_NONE, 0 };

//----------------------------------------------------------
typedef enum {
  EXAMPLE_ESPNOW_SEND_CB,
  EXAMPLE_ESPNOW_RECV_CB,
} example_espnow_event_id_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];
  esp_now_send_status_t status;
} example_espnow_event_send_cb_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];
  uint8_t *data;
  int data_len;
} example_espnow_event_recv_cb_t;

typedef union {
  example_espnow_event_send_cb_t send_cb;
  example_espnow_event_recv_cb_t recv_cb;
} example_espnow_event_info_t;

/* When ESPNOW sending or receiving callback function is called, post event to ESPNOW task. */
typedef struct {
  example_espnow_event_id_t id;
  example_espnow_event_info_t info;
} example_espnow_event_t;

enum {
  EXAMPLE_ESPNOW_DATA_BROADCAST,
  EXAMPLE_ESPNOW_DATA_UNICAST,
  EXAMPLE_ESPNOW_DATA_MAX,
};

const blink_step_t test_blink[] = {
  { LED_BLINK_HOLD, LED_STATE_ON, 50 },   // step1: turn on LED 50 ms
  { LED_BLINK_HOLD, LED_STATE_OFF, 100 }, // step2: turn off LED 100 ms
  { LED_BLINK_HOLD, LED_STATE_ON, 150 },  // step3: turn on LED 150 ms
  { LED_BLINK_HOLD, LED_STATE_OFF, 100 }, // step4: turn off LED 100 ms
  { LED_BLINK_STOP, 0, 0 },               // step5: stop blink (off)
};

//----------------------------------------------------------

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

// Forward declarations
static void
vscp_espnow_deinit(void *param);

// Signal Wi-Fi events on this event-group
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t g_wifi_event_group;

#define SEND_CB_OK   BIT0
#define SEND_CB_FAIL BIT1

//-----------------------------------------------------------------------------
//                                    OTA
//-----------------------------------------------------------------------------

#define OTA_URL_SIZE 256

///////////////////////////////////////////////////////////////////////////////
// _http_event_handler
//

esp_err_t
_http_event_handler(esp_http_client_event_t *evt)
{
  switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
      ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
      break;
    case HTTP_EVENT_ON_CONNECTED:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
      break;
    case HTTP_EVENT_HEADER_SENT:
      ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
      break;
    case HTTP_EVENT_ON_HEADER:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
      break;
    case HTTP_EVENT_ON_DATA:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
      break;
    case HTTP_EVENT_ON_FINISH:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
      break;
    case HTTP_EVENT_DISCONNECTED:
      ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
      break;
    case HTTP_EVENT_REDIRECT:
      ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
      break;
  }
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// ota_task
//

void
ota_task(void *pvParameter)
{
  ESP_LOGI(TAG, "Starting OTA ");
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
  esp_netif_t *netif = get_example_netif_from_desc(bind_interface_name);
  if (netif == NULL) {
    ESP_LOGE(TAG, "Can't find netif from interface description");
    abort();
  }
  struct ifreq ifr;
  esp_netif_get_netif_impl_name(netif, ifr.ifr_name);
  ESP_LOGI(TAG, "Bind interface name is %s", ifr.ifr_name);
#endif
  esp_http_client_config_t config_http = {
    //.url               = "http://192.168.1.7:80/hello_world.bin", //
    //"https://eurosource.se:443/download/alpha/hello-world.bin", // CONFIG_FIRMWARE_UPGRADE_URL,
    .url = "http://185.144.156.45:80/hello_world.bin", // vscp2
    //.url               = "https://185.144.156.54:443/hello_world.bin", // vscp2
    .cert_pem          = (char *) server_cert_pem_start,
    .event_handler     = _http_event_handler,
    .keep_alive_enable = true,
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
    .if_name = &ifr,
#endif
  };

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
  config.skip_cert_common_name_check = true;
#endif

  esp_https_ota_config_t config = {
    .http_config           = &config_http,
    .bulk_flash_erase      = true,
    .partial_http_download = true,
    //.max_http_request_size
  };

  esp_err_t ret = esp_https_ota(&config);
  if (ret == ESP_OK) {
    esp_restart();
  }
  else {
    ESP_LOGE(TAG, "Firmware upgrade failed");
  }
  while (1) {
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

///////////////////////////////////////////////////////////////////////////////
// print_sha256
//

static void
print_sha256(const uint8_t *image_hash, const char *label)
{
  char hash_print[HASH_LEN * 2 + 1];
  hash_print[HASH_LEN * 2] = 0;
  for (int i = 0; i < HASH_LEN; ++i) {
    sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
  }
  ESP_LOGI(TAG, "%s %s", label, hash_print);
}

///////////////////////////////////////////////////////////////////////////////
// get_sha256_of_partitions
//

static void
get_sha256_of_partitions(void)
{
  uint8_t sha_256[HASH_LEN] = { 0 };
  esp_partition_t partition;

  // get sha256 digest for bootloader
  partition.address = ESP_BOOTLOADER_OFFSET;
  partition.size    = ESP_PARTITION_TABLE_OFFSET;
  partition.type    = ESP_PARTITION_TYPE_APP;
  esp_partition_get_sha256(&partition, sha_256);
  print_sha256(sha_256, "SHA-256 for bootloader: ");

  // get sha256 digest for running partition
  esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
  print_sha256(sha_256, "SHA-256 for current firmware: ");
}

//-----------------------------------------------------------------------------
//                              Button handlers
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// get_btn_index
//

static int
get_btn_index(button_handle_t btn)
{
  for (size_t i = 0; i < BUTTON_CNT; i++) {
    if (btn == g_btns[i]) {
      return i;
    }
  }
  return -1;
}

///////////////////////////////////////////////////////////////////////////////
// button_single_click_cb
//

static void
button_single_click_cb(void *arg, void *data)
{
  // Initiate provisioning
  ESP_LOGI(TAG, "BTN%d: BUTTON_SINGLE_CLICK", get_btn_index((button_handle_t) arg));

  if (led_indicator_start(g_led_handle, BLINK_PROVISIONING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator lite");
  }
}

///////////////////////////////////////////////////////////////////////////////
// button_double_click_cb
//

static void
button_double_click_cb(void *arg, void *data)
{
  // Restart
  ESP_LOGI(TAG, "Will reboot device in two seconds");
  vTaskDelay(2000 / portTICK_PERIOD_MS);
  esp_restart();
}

///////////////////////////////////////////////////////////////////////////////
// button_long_press_start_cb
//

static void
button_long_press_start_cb(void *arg, void *data)
{
  // > 10 seconds Restore defaults
  ESP_LOGI(TAG, "BTN%d: BUTTON_LONG_PRESS_START", get_btn_index((button_handle_t) arg));
  g_restore_defaults_timer = getMilliSeconds();
}

///////////////////////////////////////////////////////////////////////////////
// button_long_press_hold_cb
//

static void
button_long_press_hold_cb(void *arg, void *data)
{
  ESP_LOGI(TAG,
           "Will restore defaults in %u seconds",
           (int) (10 - ((getMilliSeconds() - g_restore_defaults_timer) / 1000)));
  if ((getMilliSeconds() - g_restore_defaults_timer) > 10000) {
    wifi_prov_mgr_reset_provisioning();
    esp_restart();
  }
}

//-----------------------------------------------------------------------------
//                                 espnow OTA
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// startOTA
//

void
startOTA()
{
  xTaskCreate(&ota_task, "ota_task", 8192, NULL, 5, NULL);
}

///////////////////////////////////////////////////////////////////////////////
// firmware_download
//

static size_t
firmware_download(const char *url)
{
#define OTA_DATA_PAYLOAD_LEN 1024

  esp_err_t ret               = ESP_OK;
  esp_ota_handle_t ota_handle = 0;
  uint8_t *data               = malloc(OTA_DATA_PAYLOAD_LEN); // TODO ESP MALLOC
  size_t total_size           = 0;
  uint32_t start_time         = xTaskGetTickCount();

  esp_http_client_config_t config = {
    .url            = url,
    .transport_type = HTTP_TRANSPORT_UNKNOWN,
  };

  /**
   * @brief 1. Connect to the server
   */
  esp_http_client_handle_t client = esp_http_client_init(&config);
  ESP_GOTO_ON_ERROR(!client, EXIT, TAG, "Initialise HTTP connection");

  ESP_LOGI(TAG, "Open HTTP connection: %s", url);

  /**
   * @brief First, the firmware is obtained from the http server and stored
   */
  do {
    ret = esp_http_client_open(client, 0);

    if (ret != ESP_OK) {
      vTaskDelay(pdMS_TO_TICKS(1000));
      ESP_LOGW(TAG, "<%s> Connection service failed", esp_err_to_name(ret));
    }
  } while (ret != ESP_OK);

  total_size = esp_http_client_fetch_headers(client);

  if (total_size <= 0) {
    ESP_LOGW(TAG, "Please check the address of the server");
    ret = esp_http_client_read(client, (char *) data, OTA_DATA_PAYLOAD_LEN);
    ESP_GOTO_ON_ERROR(ret < 0, EXIT, TAG, "<%s> Read data from http stream", esp_err_to_name(ret));

    ESP_LOGW(TAG, "Recv data: %.*s", ret, data);
    goto EXIT;
  }

  /**
   * @brief 2. Read firmware from the server and write it to the flash of the root node
   */

  const esp_partition_t *updata_partition = esp_ota_get_next_update_partition(NULL);
  /**< Commence an OTA update writing to the specified partition. */
  ret = esp_ota_begin(updata_partition, total_size, &ota_handle);
  ESP_GOTO_ON_ERROR(ret != ESP_OK, EXIT, TAG, "<%s> esp_ota_begin failed, total_size", esp_err_to_name(ret));

  for (ssize_t size = 0, recv_size = 0; recv_size < total_size; recv_size += size) {
    size = esp_http_client_read(client, (char *) data, OTA_DATA_PAYLOAD_LEN);
    ESP_GOTO_ON_ERROR(size < 0, EXIT, TAG, "<%s> Read data from http stream", esp_err_to_name(ret));

    if (size > 0) {
      /**< Write OTA update data to partition */
      ret = esp_ota_write(ota_handle, data, OTA_DATA_PAYLOAD_LEN);
      ESP_GOTO_ON_ERROR(ret != ESP_OK,
                        EXIT,
                        TAG,
                        "<%s> Write firmware to flash, size: %d, data: %.*s",
                        esp_err_to_name(ret),
                        size,
                        size,
                        data);
    }
    else {
      ESP_LOGW(TAG, "<%s> esp_http_client_read", esp_err_to_name((int) ret));
      goto EXIT;
    }
  }

  ESP_LOGI(TAG,
           "The service download firmware is complete, Spend time: %ds",
           (int) ((xTaskGetTickCount() - start_time) * portTICK_PERIOD_MS / 1000));

  ret = esp_ota_end(ota_handle);
  ESP_GOTO_ON_ERROR(ret != ESP_OK, EXIT, TAG, "<%s> esp_ota_end", esp_err_to_name(ret));

EXIT:
  free(data);
  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  return total_size;
}

///////////////////////////////////////////////////////////////////////////////
// ota_initator_data_cb
//

esp_err_t
ota_initator_data_cb(size_t src_offset, void *dst, size_t size)
{
  static const esp_partition_t *data_partition = NULL;

  if (!data_partition) {
    data_partition = esp_ota_get_next_update_partition(NULL);
  }

  return esp_partition_read(data_partition, src_offset, dst, size);
}

///////////////////////////////////////////////////////////////////////////////
// firmware_send
//

// static void
// firmware_send(size_t firmware_size, uint8_t sha[ESPNOW_OTA_HASH_LEN])
// {
//   esp_err_t ret                         = ESP_OK;
//   uint32_t start_time                   = xTaskGetTickCount();
//   espnow_ota_result_t espnow_ota_result = { 0 };
//   espnow_ota_responder_t *info_list     = NULL;
//   size_t num                            = 0;

//   espnow_ota_initator_scan(&info_list, &num, pdMS_TO_TICKS(3000));
//   ESP_LOGW(TAG, "espnow wait ota num: %d", num);

//   espnow_addr_t *dest_addr_list = ESP_MALLOC(num * ESPNOW_ADDR_LEN);

//   for (size_t i = 0; i < num; i++) {
//     memcpy(dest_addr_list[i], info_list[i].mac, ESPNOW_ADDR_LEN);
//   }

//   ESP_FREE(info_list);

//   ret = espnow_ota_initator_send(dest_addr_list, num, sha, firmware_size, ota_initator_data_cb, &espnow_ota_result);
//   ESP_GOTO_ON_ERROR(ret != ESP_OK, EXIT, TAG, "<%s> espnow_ota_initator_send", esp_err_to_name(ret));

//   if (espnow_ota_result.successed_num == 0) {
//     ESP_LOGW(TAG, "Devices upgrade failed, unfinished_num: %d", espnow_ota_result.unfinished_num);
//     goto EXIT;
//   }

//   ESP_LOGI(TAG,
//            "Firmware is sent to the device to complete, Spend time: %ds",
//            (xTaskGetTickCount() - start_time) * portTICK_PERIOD_MS / 1000);
//   ESP_LOGI(TAG,
//            "Devices upgrade completed, successed_num: %d, unfinished_num: %d",
//            espnow_ota_result.successed_num,
//            espnow_ota_result.unfinished_num);

// EXIT:
//   espnow_ota_initator_result_free(&espnow_ota_result);
// }

// ///////////////////////////////////////////////////////////////////////////////
// // initiateFirmwareUpload
// //

// int
// initiateFirmwareUpload(void)
// {
//   uint8_t sha_256[32]                   = { 0 };
//   const esp_partition_t *data_partition = esp_ota_get_next_update_partition(NULL);

//   size_t firmware_size = firmware_download(CONFIG_FIRMWARE_UPGRADE_URL);
//   esp_partition_get_sha256(data_partition, sha_256);

//   // Send new firmware to clients
//   firmware_send(firmware_size, sha_256);

//   return VSCP_ERROR_SUCCESS;
// }

// ///////////////////////////////////////////////////////////////////////////////
// // respondToFirmwareUpload
// //

// int
// respondToFirmwareUpload(void)
// {
//   espnow_ota_config_t ota_config = {
//     .skip_version_check       = true,
//     .progress_report_interval = 10,
//   };

//   // Take care of firmware update of out node
//   espnow_ota_responder_start(&ota_config);

//   return VSCP_ERROR_SUCCESS;
// }

// ----------------------------------------------------------------------------
//                              espnow key exchange
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// security
//

// void
// Initiate_security_key_transfer(void)
// {
//   uint32_t start_time1                  = xTaskGetTickCount();
//   espnow_sec_result_t espnow_sec_result = { 0 };
//   espnow_sec_responder_t *info_list     = NULL;
//   size_t num                            = 0;
//   espnow_sec_initiator_scan(&info_list, &num, pdMS_TO_TICKS(3000));
//   ESP_LOGW(TAG, "espnow wait security num: %d", num);

//   if (num == 0) {
//     ESP_FREE(info_list);
//     return;
//   }

//   espnow_addr_t *dest_addr_list = ESP_MALLOC(num * ESPNOW_ADDR_LEN);

//   for (size_t i = 0; i < num; i++) {
//     memcpy(dest_addr_list[i], info_list[i].mac, ESPNOW_ADDR_LEN);
//   }

//   ESP_FREE(info_list);
//   uint32_t start_time2 = xTaskGetTickCount();
//   esp_err_t ret        = espnow_sec_initiator_start(g_sec, pop_data, dest_addr_list, num, &espnow_sec_result);
//   ESP_GOTO_ON_ERROR(ret != ESP_OK, EXIT, TAG, "<%s> espnow_sec_initator_start", esp_err_to_name(ret));

//   ESP_LOGI(TAG,
//            "App key is sent to the device to complete, Spend time: %dms, Scan time: %dms",
//            (xTaskGetTickCount() - start_time1) * portTICK_PERIOD_MS,
//            (start_time2 - start_time1) * portTICK_PERIOD_MS);
//   ESP_LOGI(TAG,
//            "Devices security completed, successed_num: %d, unfinished_num: %d",
//            espnow_sec_result.successed_num,
//            espnow_sec_result.unfinished_num);

// EXIT:
//   ESP_FREE(dest_addr_list);
//   espnow_sec_initator_result_free(&espnow_sec_result);
// }

// void
// respond_to_security_key_transfer(void)
// {
//   espnow_sec_responder_start(g_sec, pop_data);
//   ESP_LOGI(TAG, "<===============================>");
// }

// ----------------------------------------------------------------------------

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

  // Check pointer
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
// alpha_event_handler
//
// Event handler for catching system events
//

static void
alpha_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  if (event_base == ALPHA_EVENT) {
    if (event_id == ALPHA_START_CLIENT_PROVISIONING) {
      ESP_LOGI(TAG, "Start client provisioning");
    }
    else if (event_id == ALPHA_STOP_CLIENT_PROVISIONING) {
      ESP_LOGI(TAG, "Stop client provisioning");
    }
    else if (event_id == ALPHA_GET_IP_ADDRESS_START) {
      ESP_LOGI(TAG, "Waiting for IP-address");
    }
    else if (event_id == ALPHA_GET_IP_ADDRESS_STOP) {
      ESP_LOGI(TAG, "IP-address received");
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// system_event_handler
//
// Event handler for catching system events
//

static void
system_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  static bool s_ap_staconnected_flag = false;
  static bool s_sta_connected_flag   = false;

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
        // De-initialize manager once provisioning is finished
        wifi_prov_mgr_deinit();
        break;

      default:
        break;
    }
  }
  else if (event_base == WIFI_EVENT) {

    switch (event_id) {

      case WIFI_EVENT_WIFI_READY: {
        // Set channel
        ESP_ERROR_CHECK(esp_wifi_set_channel(DROPLET_CHANNEL, WIFI_SECOND_CHAN_NONE));
      } break;

      case WIFI_EVENT_STA_START: {
        ESP_LOGI(TAG, "Connecting........");
        esp_wifi_connect();
      }

      case WIFI_EVENT_AP_STACONNECTED: {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *) event_data;
        // ESP_LOGI(TAG, "station " MACSTR " join, AID=%d", MAC2STR(event->mac), (int)event->aid);
        s_ap_staconnected_flag = true;
        break;
      }

      case WIFI_EVENT_AP_STADISCONNECTED: {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *) event_data;
        // ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d", MAC2STR(event->mac), ((int)event->aid);
        s_ap_staconnected_flag = false;
        break;
      }

      case WIFI_EVENT_STA_CONNECTED: {
        wifi_event_sta_connected_t *event = (wifi_event_sta_connected_t *) event_data;
        char *ttt                         = MACSTR;
        // ESP_LOGI(TAG,
        //          "Connected to %s (BSSID: " MACSTR ", Channel: %d)",
        //          event->ssid,
        //          MAC2STR(event->bssid),
        //          event->channel);
        s_sta_connected_flag = true;
        break;
      }

      case WIFI_EVENT_STA_DISCONNECTED: {
        ESP_LOGI(TAG, "sta disconnect");
        s_sta_connected_flag = false;
        ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
        g_state = MAIN_STATE_INIT;
        esp_wifi_connect();
        break;
      }
    }
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "Connected with IP Address: " IPSTR, IP2STR(&event->ip_info.ip));
    g_state = MAIN_STATE_WORK;
    /* Signal main application to continue execution */
    xEventGroupSetBits(g_wifi_event_group, WIFI_CONNECTED_EVENT);
  }
  else if (event_base == ALPHA_EVENT) {
    ESP_LOGI(TAG, "----------------------------------------------------------->");
  }
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
// vscp_heartbeat_task
//
// Sent periodically as a broadcast to all zones/subzones
//

static void
vscp_heartbeat_task(void *pvParameter)
{
  esp_err_t ret = 0;
  uint8_t dest_addr[ESP_NOW_ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t buf[DROPLET_MIN_FRAME + 3];  // Three byte data
  size_t size = sizeof(buf);
  int recv_seq = 0;

  // Create Heartbeat event
  if ( VSCP_ERROR_SUCCESS != (ret = droplet_build_l1_heartbeat(buf, size, g_node_guid))) {
    ESP_LOGE(TAG, "Could not create heartbeat event, will exit task. VSCP rv %d", ret);
    goto ERROR;
  }

  ESP_LOGI(TAG, "Start sending VSCP heartbeats");

  while (1) {

  //   // if (pthread_mutex_lock(&g_espnow_send_mutex) == 0){
  //   if (xSemaphoreTake(g_send_lock, (TickType_t)100)) {
  //     ret = espnow_send(ESPNOW_TYPE_DATA, dest_mac, buf, size, &frame_head, portMAX_DELAY);
  //     ret = esp_now_send(dest_mac, buf, size);
  //     xSemaphoreGive(g_send_lock);
    ret = droplet_send(dest_addr, false, 4, buf, DROPLET_MIN_FRAME + 3, 1000/portTICK_PERIOD_MS);
    ESP_LOGI(TAG, "VSCP heartbeat sent - ret=0x%X", ret);

    uint32_t hf = esp_get_free_heap_size();
    heap_caps_check_integrity_all(true);
    ESP_LOGI(TAG, "---------> VSCP heartbeat sent - ret=0x%X heap=%X", (unsigned int)ret, (unsigned int)hf);

    ESP_LOGI(TAG, "VSCP heartbeat sent - ret=0x%X", ret);
    vTaskDelay(VSCP_HEART_BEAT_INTERVAL / portTICK_PERIOD_MS);
  }

  
  //ESP_ERROR_CONTINUE(ret != ESP_OK, "<%s>", esp_err_to_name(ret));

ERROR:
  ESP_LOGW(TAG, "Heartbeat task exit %d", ret);
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_send_task
//

static void
vscp_espnow_send_task(void *pvParameter)
{
  // vscp_espnow_event_post_t evt;
  // esp_err_t ret = 0;
  // uint8_t dest_mac[ESP_NOW_ETH_ALEN]; // MAC address of destination device.
  // vscp_espnow_event_t vscpEspNowEvent;
  // uint8_t buf[VSCP_ESPNOW_PACKET_MAX_SIZE];
  // static int cnt = 0;

  // // vTaskDelay(5000 / portTICK_PERIOD_MS);
  // ESP_LOGI(TAG, "Start sending broadcast data");

  // // vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

  // // ESP_LOGI(TAG, "Before broadcast send");

  // espnow_frame_head_t frame_head = {
  //   .channel          = 11,
  //   .retransmit_count = 1,
  //   .broadcast        = true,
  //   .forward_ttl      = 7,
  //   .ack              = 0,
  // };

  // while (1) {

  //   // esp_task_wdt_reset();

  //   // if (pthread_mutex_lock(&g_espnow_send_mutex) == 0){
  //   if (xSemaphoreTake(g_send_lock, (TickType_t) 200)) {
  //     // if (g_send_state.state == VSCP_SEND_STATE_NONE) {
  //     memcpy(dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);
  //     // ret = esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MIN_SIZE);
  //     ret = espnow_send(ESPNOW_TYPE_DATA,
  //                       dest_mac,
  //                       buf,
  //                       VSCP_ESPNOW_PACKET_MIN_SIZE, //+ vscpEspNowEvent.len,
  //                       &frame_head,
  //                       portMAX_DELAY);
  //     // g_send_state.state = VSCP_SEND_STATE_SENT;
  //     // g_send_state.timestamp = esp_timer_get_time();
  //     uint32_t hf = esp_get_free_heap_size();
  //     // heap_caps_check_integrity_all(true);
  //     ESP_LOGI(TAG, "Broadcast sent - ret=0x%X heap=%X", ret, hf);
  //     // g_send_state.state = VSCP_SEND_STATE_NONE;
  //     // g_send_state.timestamp = esp_timer_get_time();
  //     //}
  //     // Check for timeout
  //     // else if ((g_send_state.state ==VSCP_SEND_STATE_SENT) && ((esp_timer_get_time() - g_send_state.timestamp) >
  //     // 5000000L) ){
  //     //   ESP_LOGI(TAG, "Send timout");
  //     //   g_send_state.state = VSCP_SEND_STATE_NONE;
  //     //   g_send_state.timestamp = esp_timer_get_time();
  //     // }
  //     // else if (g_send_state.state ==VSCP_SEND_STATE_SEND_CONFIRM ){
  //     //   ESP_LOGI(TAG, "Send Confirm reset");
  //     //   g_send_state.state = VSCP_SEND_STATE_NONE;
  //     //   g_send_state.timestamp = esp_timer_get_time();
  //     // }

  //     // pthread_mutex_unlock(&g_espnow_send_mutex);
  //     xSemaphoreGive(g_send_lock);

  //     // ESP_ERROR_BREAK(ret != ESP_OK, "<%s>", esp_err_to_name(ret));
  //   }

  //   vTaskDelay(10 / portTICK_PERIOD_MS);
  //   vTaskDelay(5000 / portTICK_PERIOD_MS);
  // }

  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_receive_task
//

void
vscp_espnow_recv_task(void *pvParameter)
{
  esp_err_t ret = 0;
  // char *data                    = ESP_MALLOC(ESPNOW_DATA_LEN);
  // size_t size                   = ESPNOW_DATA_LEN;
  // uint8_t addr[ESPNOW_ADDR_LEN] = { 0 };
  // wifi_pkt_rx_ctrl_t rx_ctrl    = { 0 };

  // ESP_LOGI(TAG, "Receive task started --->");

  // // vTaskDelay(4000 / portTICK_PERIOD_MS);

  // for (;;) {
  //   esp_task_wdt_reset();
  //   ret = espnow_recv(ESPNOW_TYPE_DATA, addr, data, &size, &rx_ctrl, 5000 / portTICK_PERIOD_MS); //
  //   ESP_ERROR_CONTINUE(ret != ESP_OK, MACSTR ",  error: <%s>", MAC2STR(addr), esp_err_to_name(ret));
  //   ESP_LOGI(TAG, "Data from " MACSTR " Data size=%d", MAC2STR(addr), size);
  // }

  ESP_LOGW(TAG, "Receive task exit %d", ret);
  // ESP_FREE(data);
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  uint8_t dest_addr[ESP_NOW_ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t buf[DROPLET_MIN_FRAME + 3];  // Three byte data
  size_t size = sizeof(buf);

  // Initialize NVS partition
  esp_err_t rv = nvs_flash_init();
  if (rv == ESP_ERR_NVS_NO_FREE_PAGES || rv == ESP_ERR_NVS_NEW_VERSION_FOUND) {

    // NVS partition was truncated
    // and needs to be erased
    ESP_ERROR_CHECK(nvs_flash_erase());

    // Retry nvs_flash_init
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  

  // Create message queues  QueueHandle_t tx_msg_queue
  // g_tx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Outgoing esp-now messages */
  // g_rx_msg_queue = xQueueCreate(ESPNOW_SIZE_TX_BUF, sizeof(vscp_espnow_event_t)); /*< Incoming esp-now messages */

  // Initialize LED indicator
  led_indicator_config_t indicator_config = {

    .off_level = 0, // if zero, attach led positive side to esp32 gpio pin
    .mode      = LED_GPIO_MODE,
  };
  led_indicator_handle_t g_led_handle = led_indicator_create(INDICATOR_LED_PIN, &indicator_config);
  if (NULL == g_led_handle) {
    ESP_LOGE(TAG, "Failed to create LED indicator");
  }

  // Initialize Buttons

  button_config_t btncfg = {
        .type = BUTTON_TYPE_GPIO,
        //.long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        //.short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
        .gpio_button_config = {
            .gpio_num = 0,
            .active_level = 0,
        },
    };
  g_btns[0] = iot_button_create(&btncfg);
  iot_button_register_cb(g_btns[0], BUTTON_SINGLE_CLICK, button_single_click_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_DOUBLE_CLICK, button_double_click_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_LONG_PRESS_START, button_long_press_start_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_LONG_PRESS_HOLD, button_long_press_hold_cb, NULL);

  if (led_indicator_start(g_led_handle, BLINK_CONNECTING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator lite");
  }

  // Initiate message queues
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    g_tr_tcpsrv[i].msg_queue = xQueueCreate(10, DROPLET_MAX_FRAME); // tcp/ip link channel i
  }
  g_tr_mqtt.msg_queue = xQueueCreate(10, DROPLET_MAX_FRAME); // MQTT empties

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

    // If GUID is all zero construct VSCP GUID
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

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  g_wifi_event_group = xEventGroupCreate();

  // Register our event handler for Wi-Fi, IP and Provisioning related events
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &system_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(ALPHA_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));

  /* esp_event_loop_args_t alpha_loop_config = {
    .queue_size = 10,
    .task_name = "alpha loop",
    .task_priority = uxTaskPriorityGet(NULL),
    .task_stack_size = 2048,
    .task_core_id = tskNO_AFFINITY
  };

  esp_event_loop_handle_t alpha_loop_handle;
  ESP_ERROR_CHECK(esp_event_loop_create(&alpha_loop_config, &alpha_loop_handle));

  ESP_ERROR_CHECK(esp_event_handler_register_with(alpha_loop_handle,
                                                           ALPHA_EVENT,
                                                           ESP_EVENT_ANY_ID,
                                                           alpha_event_handler,
                                                           NULL)); */

  // Initialize Wi-Fi including netif with default config
  esp_netif_create_default_wifi_sta();

#ifdef CONFIG_PROV_TRANSPORT_SOFTAP
  esp_netif_create_default_wifi_ap();
#endif // CONFIG_PROV_TRANSPORT_SOFTAP

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  if (led_indicator_start(g_led_handle, BLINK_PROVISIONING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  if (!wifi_provisioning()) {

    ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi");

    /*
     * We don't need the manager as device is already provisioned,
     * so let's release it's resources
     */
    wifi_prov_mgr_deinit();

    // Start Wi-Fi soft ap & station
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_start());

#if CONFIG_ESPNOW_ENABLE_LONG_RANGE
    ESP_ERROR_CHECK(
      esp_wifi_set_protocol(ESP_IF_WIFI_STA,
                            WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
#endif
  }

  if (led_indicator_start(g_led_handle, BLINK_CONNECTING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator lite");
  }

  // Wait for Wi-Fi connection
  ESP_LOGI(TAG, "Wait for wifi connection...");
  esp_event_post( /*_to(alpha_loop_handle,*/ ALPHA_EVENT, ALPHA_GET_IP_ADDRESS_START, NULL, 0, portMAX_DELAY);
  xEventGroupWaitBits(g_wifi_event_group, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);
  esp_event_post(/*_to(alpha_loop_handle,*/ ALPHA_EVENT, ALPHA_GET_IP_ADDRESS_STOP, NULL, 0, portMAX_DELAY);

  if (led_indicator_start(g_led_handle, BLINK_CONNECTED) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  // Initialize droplet
  droplet_config_t droplet_config = {
    .channel = 1,
    .ttl = 32,
    .bForwardEnable = true,
    .bForwardSwitchChannel = false,
    .sizeQueue = 32,
    .bFilterAdjacentChannel = false,
    .filterWeakSignal = false,
    .pmk = {"01234567890012345678900123456789001"}
  };

  if (ESP_OK != droplet_init(&droplet_config)) {
    ESP_LOGI(TAG, "Failed to initialize espnow");
  }
  ESP_LOGI(TAG, "espnow initializated");

  // Initialize Spiffs for web pages
  ESP_LOGI(TAG, "Initializing SPIFFS");

  esp_vfs_spiffs_conf_t spiffsconf = { .base_path              = "/spiffs",
                                       .partition_label        = "web",
                                       .max_files              = 50,
                                       .format_if_mount_failed = true };

  // Initialize and mount SPIFFS filesystem.
  esp_err_t ret = esp_vfs_spiffs_register(&spiffsconf);

  if (ret != ESP_OK) {
    if (ret == ESP_FAIL) {
      ESP_LOGE(TAG, "Failed to mount or format web filesystem");
    }
    else if (ret == ESP_ERR_NOT_FOUND) {
      ESP_LOGE(TAG, "Failed to find SPIFFS partition for web ");
    }
    else {
      ESP_LOGE(TAG, "Failed to initialize SPIFFS for web (%s)", esp_err_to_name(ret));
    }
    return;
  }

  ESP_LOGI(TAG, "SPIFFS for web initialized");

  // Start LED controlling tast
  // xTaskCreate(&led_task, "led_task", 1024, NULL, 5, NULL);

  // Start heartbeat task vscp_heartbeat_task
  xTaskCreate(&vscp_heartbeat_task, "vscp_heartbeat_task", 2024, NULL, 5, NULL);

  // startOTA();

  xTaskCreate(vscp_espnow_send_task, "vscp_espnow_send_task", 4096, NULL, 4, NULL);
  xTaskCreate(vscp_espnow_recv_task, "vscp_espnow_recv_task", 2048, NULL, 4, NULL);

  // Start the VSCP Link Protocol Server
#ifdef CONFIG_EXAMPLE_IPV6
  xTaskCreate(&tcpsrv_task, "vscp_tcpsrv_task", 4096, (void *) AF_INET6, 5, NULL);
#else
  xTaskCreate(&tcpsrv_task, "vscp_tcpsrv_task", 4096, (void *) AF_INET, 5, NULL);
#endif

  // Start web server
  httpd_handle_t server = start_webserver();

  ESP_LOGI(TAG, "Going to work now!");

  /*
    Start main application loop now
  */

 if ( VSCP_ERROR_SUCCESS != (ret = droplet_build_l1_heartbeat(buf, size, g_node_guid))) {
    ESP_LOGE(TAG, "Could not create heartbeat event, will exit task. VSCP rv %d", ret);
  }

    ret = droplet_send(dest_addr, true, 4, buf, DROPLET_MIN_FRAME + 3, 1000/portTICK_PERIOD_MS);

  while (1) {
    // esp_task_wdt_reset();
    ESP_LOGI(TAG, "Ctrl - Loop");    
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // Unmount web spiffs partition and disable SPIFFS
  esp_vfs_spiffs_unregister(spiffsconf.partition_label);
  ESP_LOGI(TAG, "web SPIFFS unmounted");

  // Clean up
  iot_button_delete(g_btns[0]);

  // Close
  nvs_close(g_nvsHandle);
}
