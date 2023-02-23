/*
  File: main.c

  VSCP alpha node

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022-2023 Ake Hedman, the VSCP project <info@vscp.org>

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
#include <dirent.h>

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
#include <esp_event.h>

#include <esp_crt_bundle.h>

#include <cJSON.h>

#include "websrv.h"
#include "mqtt.h"

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

#include "net_logging.h"

extern vprintf_like_t g_stdLogFunc; // net logging

const char *pop_data   = "VSCP ALPHA";
static const char *TAG = "ALPHA";

#define HASH_LEN   32
#define BUTTON_CNT 1

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

// The net interface
esp_netif_t *g_netif = NULL;

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
// node is restarted. Wifi credentials need to be restored
uint32_t g_restore_defaults_timer = 0;

// Initiating provisioning is done with a button click
// the provisioning state is active for 30 seconds
uint32_t g_provisioning_state_timer = 0;

// Button defines
static button_handle_t g_btns[BUTTON_CNT] = { 0 };

// Transports
transport_t g_tr_tcpsrv[MAX_TCP_CONNECTIONS] = {}; // VSCP tcp/ip link server
transport_t g_tr_mqtt                        = {}; // MQTT

// Logging
// int16_t g_write2Stdout = 0;     // Enable write to standard out

// static void
// vscp_heartbeat_task(void *pvParameter);
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

///////////////////////////////////////////////////////////
//                   P E R S I S T A N T
///////////////////////////////////////////////////////////

// Set default configuration

node_persistent_config_t g_persistent = {

  // General
  .nodeName   = "Alpha Node",
  .lkey       = { 0 },
  .pmk        = { 0 },
  .nodeGuid   = { 0 }, // GUID for unit
  .startDelay = 2,
  .bootCnt    = 0,

  // Logging
  .logwrite2Stdout = 1,
  .logLevel        = ESP_LOG_INFO,
  .logType         = ALPHA_LOG_UDP,
  .logRetries      = 5,
  .logUrl          = "255.255.255.255",
  .logPort         = 6789,
  .logMqttTopic    = "%guid/log",

  // Web server
  .webEnable   = true,
  .webPort     = 80,
  .webUsername = "vscp",
  .webPassword = "secret",

  // VSCP tcp/ip Link
  .vscplinkEnable   = true,
  .vscplinkUrl      = { 0 },
  .vscplinkPort     = VSCP_DEFAULT_TCP_PORT,
  .vscplinkUsername = "vscp",
  .vscplinkPassword = "secret",
  .vscpLinkKey      = { 0 }, // VSCP_DEFAULT_KEY32,

  // MQTT
  .mqttEnable       = true,
  .mqttUrl          = { 0 },
  .mqttPort         = 1883,
  .mqttClientid     = "{{node}}-{{guid}}",
  .mqttUsername     = "vscp",
  .mqttPassword     = "secret",
  .mqttQos          = 0,
  .mqttRetain       = 0,
  .mqttSub          = "vscp/{{guid}}/pub/#",
  .mqttPub          = "vscp/{{guid}}/{{class}}/{{type}}/{{index}}",
  .mqttVerification = { 0 },
  .mqttLwTopic      = { 0 },
  .mqttLwMessage    = { 0 },
  .mqttLwQos        = 0,
  .mqttLwRetain     = false,

  // Droplet
  .dropletEnable                = true,
  .dropletLongRange             = false,
  .dropletChannel               = 0, // Use wifi channel
  .dropletTtl                   = 32,
  .dropletSizeQueue             = 32,                     // Size fo input queue
  .dropletForwardEnable         = true,                   // Forward when packets are received
  .dropletEncryption            = VSCP_ENCRYPTION_AES128, // 0=no encryption, 1=AES-128, 2=AES-192, 3=AES-256
  .dropletFilterAdjacentChannel = true,                   // Don't receive if from other channel
  .dropletForwardSwitchChannel  = false,                  // Allow switchin gchannel on forward
  .dropletFilterWeakSignal      = -100,                   // Filter onm RSSI (zero is no rssi filtering)
};

//----------------------------------------------------------

///////////////////////////////////////////////////////////
//                      V S C P
///////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
// droplet_receive_cb
//

void
droplet_receive_cb(const vscpEvent *pev, void *userdata)
{
  int rv;

  if (NULL == pev) {
    ESP_LOGE(TAG, "Invalid pointer for droplet rx cb");
    return;
  }

  // Disable if no broker URL defined
  if (g_persistent.mqttEnable && (g_persistent.mqttUrl)) {
    // Send event to MQTT broker
    if (VSCP_ERROR_SUCCESS != (rv = mqtt_send_vscp_event(NULL, pev))) {
      ESP_LOGE(TAG, "Failed to send event to MQTT broker rv=%d", rv);
    }
  }

  // If VSCP Link protocol is enabled and a client is connected send event
  // to client
  if (g_persistent.vscplinkEnable && strlen(g_persistent.vscplinkUrl)) {
    // Send event to active VSCP link clients
    ESP_LOGV(TAG, "Sending event to VSCP Link client\n");
    if (VSCP_ERROR_SUCCESS != (rv = tcpsrv_sendEventExToAllClients(pev))) {
      if (VSCP_ERROR_TRM_FULL == rv) {
        ESP_LOGI(TAG, "Failed to send event to tcpipsrv (queue is full for client)");
      }
      else if (VSCP_ERROR_TIMEOUT == rv) {
        ESP_LOGI(TAG, "Failed to send event to tcpipsrv (Unable to get mutex)");
      }
      else {
        ESP_LOGE(TAG, "Failed to send event to tcpipsrv rv=%d", rv);
      }
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// setAccessPointParameters
//

esp_err_t
setAccessPointParameters(void)
{
  wifi_config_t wifi_cfg = { .ap = {
                               .channel = PRJDEF_AP_CHANNEL,
                               .max_connection  = PRJDEF_AP_MAX_CONNECTIONS,
                               .beacon_interval = PRJDEF_AP_BEACON_INTERVAL,
                               .ssid_hidden = 1,
                             } };
  memcpy(wifi_cfg.ap.ssid, g_persistent.nodeName, strlen(g_persistent.nodeName));
  memcpy(wifi_cfg.ap.password, PRJDEF_AP_PASSWORD, strlen(PRJDEF_AP_PASSWORD));
  return esp_wifi_set_config(WIFI_IF_AP, &wifi_cfg);
}

///////////////////////////////////////////////////////////////////////////////
// readPersistentConfigs
//

esp_err_t
readPersistentConfigs(void)
{
  esp_err_t rv;
  char buf[80];
  size_t length = sizeof(buf);
  uint8_t val;

  // Set default primary key
  vscp_fwhlp_hex2bin(g_persistent.vscpLinkKey, 32, VSCP_DEFAULT_KEY32);

  // boot counter
  rv = nvs_get_u32(g_nvsHandle, "boot_counter", &g_persistent.bootCnt);
  switch (rv) {

    case ESP_OK:
      ESP_LOGI(TAG, "Boot counter = %d", (int) g_persistent.bootCnt);
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGE(TAG, "The boot counter is not initialized yet!");
      break;

    default:
      ESP_LOGE(TAG, "Error (%s) reading boot counter!", esp_err_to_name(rv));
      break;
  }

  // Update and write back boot counter
  g_persistent.bootCnt++;
  rv = nvs_set_u32(g_nvsHandle, "boot_counter", g_persistent.bootCnt);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to update boot counter");
  }

  // Node name
  rv = nvs_get_str(g_nvsHandle, "node_name", buf, &length);
  switch (rv) {
    case ESP_OK:
      strncpy(g_persistent.nodeName, buf, sizeof(g_persistent.nodeName));
      ESP_LOGI(TAG, "Node Name = %s", g_persistent.nodeName);
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      rv = nvs_set_str(g_nvsHandle, "node_name", "Alpha Node");
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update node name");
      }
      break;

    default:
      ESP_LOGE(TAG, "Error (%s) reading 'node_name'!", esp_err_to_name(rv));
      break;
  }

  // Start Delay (seconds)
  rv = nvs_get_u8(g_nvsHandle, "start_delay", &g_persistent.startDelay);
  switch (rv) {

    case ESP_OK:
      ESP_LOGI(TAG, "Start delay = %d", g_persistent.startDelay);
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      rv = nvs_set_u8(g_nvsHandle, "start_delay", 2);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update start delay");
      }
      break;

    default:
      ESP_LOGE(TAG, "Error (%s) reading!", esp_err_to_name(rv));
      break;
  }

  // Logging ------------------------------------------------------------------

  // logwrite2Stdout
  rv = nvs_get_u8(g_nvsHandle, "log_stdout", &g_persistent.logwrite2Stdout);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "log_stdout", g_persistent.logwrite2Stdout);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update log-stdout");
    }
  }

  // logLevel
  esp_log_level_set("*", ESP_LOG_INFO);
  rv = nvs_get_u8(g_nvsHandle, "log_level", &g_persistent.logLevel);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "log_level", g_persistent.logLevel);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update log-level");
    }
  }

  // logType
  rv = nvs_get_u8(g_nvsHandle, "log_type", &g_persistent.logType);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "log_type", g_persistent.logType);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update log-type");
    }
  }

  // logRetries
  rv = nvs_get_u8(g_nvsHandle, "log_retries", &g_persistent.logRetries);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "log:retries", g_persistent.logRetries);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update log-retries");
    }
  }

  // logUrl
  length = sizeof(g_persistent.logUrl);
  rv     = nvs_get_str(g_nvsHandle, "log_url", g_persistent.logUrl, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'log URL' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "log_url", g_persistent.logUrl);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save log URL");
    }
  }

  // logPort
  rv = nvs_get_u16(g_nvsHandle, "log_port", &g_persistent.logPort);
  if (ESP_OK != rv) {
    rv = nvs_set_u16(g_nvsHandle, "log_port", g_persistent.logPort);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update log_port");
    }
  }

  // logMqttTopic
  length = sizeof(g_persistent.logMqttTopic);
  rv     = nvs_get_str(g_nvsHandle, "log_mqtt_topic", g_persistent.logMqttTopic, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'log MQTT topic' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "log_mqtt_topic", g_persistent.logMqttTopic);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save log MQTT topic");
    }
  }

  // VSCP Link ----------------------------------------------------------------

  // VSCP Link enable
  rv = nvs_get_u8(g_nvsHandle, "vscp_enable", &val);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'VSCP link enable' will be set to default. ret=%d", rv);
    val = (uint8_t) g_persistent.vscplinkEnable;
    rv  = nvs_set_u8(g_nvsHandle, "vscp_enable", g_persistent.vscplinkEnable);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCP link enable");
    }
  }
  else {
    g_persistent.vscplinkEnable = (bool) val;
  }

  // VSCP Link host
  length = sizeof(g_persistent.vscplinkUrl);
  rv     = nvs_get_str(g_nvsHandle, "vscp_url", g_persistent.vscplinkUrl, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'VSCP link host' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "vscp_url", DEFAULT_TCPIP_USER);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCP link host");
    }
  }

  // VSCP link port
  rv = nvs_get_u16(g_nvsHandle, "vscp_port", &g_persistent.vscplinkPort);
  if (ESP_OK != rv) {
    rv = nvs_set_u16(g_nvsHandle, "vscp_port", g_persistent.vscplinkPort);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update VSCP link port");
    }
  }

  // VSCP Link key
  length = sizeof(g_persistent.vscpLinkKey);
  rv     = nvs_get_blob(g_nvsHandle, "vscp_key", (char *) g_persistent.vscpLinkKey, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'VSCP link_key' will be set to default. ret=%d", rv);
    rv = nvs_set_blob(g_nvsHandle, "vscp_key", g_persistent.vscpLinkKey, sizeof(g_persistent.vscpLinkKey));
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCL link key");
    }
  }

  // VSCP Link Username
  length = sizeof(g_persistent.vscplinkUsername);
  rv     = nvs_get_str(g_nvsHandle, "vscp_user", g_persistent.vscplinkUsername, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'VSCP Username' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "vscp_user", DEFAULT_TCPIP_USER);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCP username");
    }
  }

  // VSCP Link password
  length = sizeof(g_persistent.vscplinkPassword);
  rv     = nvs_get_str(g_nvsHandle, "vscp_password", g_persistent.vscplinkPassword, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'VSCP password' will be set to default. ret=%d", rv);
    nvs_set_str(g_nvsHandle, "vscp_password", DEFAULT_TCPIP_PASSWORD);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCP password");
    }
  }
  // ESP_LOGI(TAG, "VSCP Password: %s", buf);

  // lkey (Local key)
  length = 32;
  rv     = nvs_get_blob(g_nvsHandle, "lkey", g_persistent.lkey, &length);
  if (rv != ESP_OK) {

    // We need to generate a new lkey
    esp_fill_random(g_persistent.lkey, sizeof(g_persistent.lkey));
    ESP_LOGW(TAG, "----------> New lkey generated <----------");

    rv = nvs_set_blob(g_nvsHandle, "lkey", g_persistent.lkey, 32);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write node lkey to nvs. rv=%d", rv);
    }
  }

  // pmk (Primary key)
  length = 32;
  rv     = nvs_get_blob(g_nvsHandle, "pmk", g_persistent.pmk, &length);
  if (rv != ESP_OK) {
    const char key[] = VSCP_DEFAULT_KEY32;
    const char *pos  = key;
    for (int i = 0; i < 32; i++) {
      sscanf(pos, "%2hhx", &g_persistent.pmk[i]);
      pos += 2;
    }
    rv = nvs_set_blob(g_nvsHandle, "pmk", g_persistent.pmk, 32);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write node pmk to nvs. rv=%d", rv);
    }
  }

  // GUID
  length = 16;
  rv     = nvs_get_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, &length);

  if (rv != ESP_OK) {
    // FF:FF:FF:FF:FF:FF:FF:FE:MAC1:MAC2:MAC3:MAC4:MAC5:MAC6:NICKNAME1:NICKNAME2
    memset(g_persistent.nodeGuid + 6, 0xff, 7);
    g_persistent.nodeGuid[7] = 0xfe;
    // rv                       = esp_efuse_mac_get_default(g_persistent.nodeGuid + 8);
    //  ESP_MAC_WIFI_STA
    //  ESP_MAC_WIFI_SOFTAP
    rv = esp_read_mac(g_persistent.nodeGuid + 8, ESP_MAC_WIFI_SOFTAP);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "esp_efuse_mac_get_default failed to get GUID. rv=%d", rv);
    }

    rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
    }
  }
  ESP_LOGI(TAG,
           "GUID for node: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
           g_persistent.nodeGuid[0],
           g_persistent.nodeGuid[1],
           g_persistent.nodeGuid[2],
           g_persistent.nodeGuid[3],
           g_persistent.nodeGuid[4],
           g_persistent.nodeGuid[5],
           g_persistent.nodeGuid[6],
           g_persistent.nodeGuid[7],
           g_persistent.nodeGuid[8],
           g_persistent.nodeGuid[9],
           g_persistent.nodeGuid[10],
           g_persistent.nodeGuid[11],
           g_persistent.nodeGuid[12],
           g_persistent.nodeGuid[13],
           g_persistent.nodeGuid[14],
           g_persistent.nodeGuid[15]);

  // MQTT ----------------------------------------------------------------

  // VSCP Link enable
  rv = nvs_get_u8(g_nvsHandle, "mqtt_enable", &val);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT enable' will be set to default. ret=%d", rv);
    val = (uint8_t) g_persistent.mqttEnable;
    rv  = nvs_set_u8(g_nvsHandle, "mwtt_enable", g_persistent.mqttEnable);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT enable");
    }
  }
  else {
    g_persistent.mqttEnable = (bool) val;
  }

  // MQTT host
  length = sizeof(g_persistent.mqttUrl);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_url", g_persistent.mqttUrl, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT host' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "mqtt_url", g_persistent.mqttUrl);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT host");
    }
  }

  // MQTT port
  rv = nvs_get_u16(g_nvsHandle, "mqtt_port", &g_persistent.mqttPort);
  if (ESP_OK != rv) {
    rv = nvs_set_u16(g_nvsHandle, "mqtt_port", g_persistent.mqttPort);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update MQTT port");
    }
  }

  // MQTT client
  length = sizeof(g_persistent.mqttClientid);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_cid", g_persistent.mqttClientid, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT clientid' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "mqtt_cid", g_persistent.mqttClientid);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT clientid");
    }
  }

  // MQTT Link Username
  length = sizeof(g_persistent.mqttUsername);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_user", g_persistent.mqttUsername, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT user' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "mqtt_user", DEFAULT_TCPIP_USER);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT username");
    }
  }

  // MQTT password
  length = sizeof(g_persistent.mqttPassword);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_password", g_persistent.mqttPassword, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT password' will be set to default. ret=%d", rv);
    nvs_set_str(g_nvsHandle, "mqtt_password", DEFAULT_TCPIP_PASSWORD);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT password");
    }
  }

  // MQTT subscribe
  length = sizeof(g_persistent.mqttSub);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_sub", g_persistent.mqttSub, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT sub' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "mqtt_sub", g_persistent.mqttSub);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT sub");
    }
  }

  // MQTT publish
  length = sizeof(g_persistent.mqttPub);
  rv     = nvs_get_str(g_nvsHandle, "mqtt_pub", g_persistent.mqttPub, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'MQTT pub' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "mqtt_pub", g_persistent.mqttPub);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save MQTT pub");
    }
  }

  // WEB server ----------------------------------------------------------------

  // WEB enable
  rv = nvs_get_u8(g_nvsHandle, "web_enable", &val);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'web enable' will be set to default. ret=%d", rv);
    val = (uint8_t) g_persistent.webEnable;
    rv  = nvs_set_u8(g_nvsHandle, "web_enable", g_persistent.webEnable);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save web enable");
    }
  }
  else {
    g_persistent.webEnable = (bool) val;
  }

  // WEB port
  rv = nvs_get_u16(g_nvsHandle, "web_port", &g_persistent.webPort);
  if (ESP_OK != rv) {
    rv = nvs_set_u16(g_nvsHandle, "web_port", g_persistent.webPort);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update Web server port");
    }
  }

  // WEB Username
  length = sizeof(g_persistent.webUsername);
  rv     = nvs_get_str(g_nvsHandle, "web_user", g_persistent.webUsername, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'Web server user' will be set to default. ret=%d", rv);
    rv = nvs_set_str(g_nvsHandle, "web_user", DEFAULT_TCPIP_USER);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save Web Server username");
    }
  }

  // WEB password
  length = sizeof(g_persistent.webPassword);
  rv     = nvs_get_str(g_nvsHandle, "web_password", g_persistent.webPassword, &length);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'Web server password' will be set to default. ret=%d", rv);
    nvs_set_str(g_nvsHandle, "web_password", DEFAULT_TCPIP_PASSWORD);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save Web server password");
    }
  }

  // Droplet ----------------------------------------------------------------

  // VSCP Link enable
  rv = nvs_get_u8(g_nvsHandle, "drop_enable", &val);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read 'Droplet enable' will be set to default. ret=%d", rv);
    val = (uint8_t) g_persistent.dropletEnable;
    rv  = nvs_set_u8(g_nvsHandle, "drop_enable", g_persistent.dropletEnable);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to save VSCP link enable");
    }
  }
  else {
    g_persistent.dropletEnable = (bool) val;
  }

  // Long Range
  rv = nvs_get_u8(g_nvsHandle, "drop_lr", &val);
  if (ESP_OK != rv) {
    val = (uint8_t) g_persistent.dropletLongRange;
    rv  = nvs_set_u8(g_nvsHandle, "drop_lr", g_persistent.dropletLongRange);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet long range");
    }
  }
  else {
    g_persistent.dropletLongRange = (bool) val;
  }

  // Channel
  rv = nvs_get_u8(g_nvsHandle, "drop_ch", &g_persistent.dropletChannel);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "drop_ch", g_persistent.dropletChannel);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet channel");
    }
  }

  // Default queue size
  rv = nvs_get_u8(g_nvsHandle, "drop_qsize", &g_persistent.dropletSizeQueue);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "drop_qsize", g_persistent.dropletSizeQueue);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet queue size");
    }
  }

  // Default ttl
  rv = nvs_get_u8(g_nvsHandle, "drop_ttl", &g_persistent.dropletTtl);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "drop_ttl", g_persistent.dropletTtl);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet ttl");
    }
  }

  // Forward
  rv = nvs_get_u8(g_nvsHandle, "drop_fw", &val);
  if (ESP_OK != rv) {
    val = (uint8_t) g_persistent.dropletForwardEnable;
    rv  = nvs_set_u8(g_nvsHandle, "drop_fw", g_persistent.dropletForwardEnable);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet forward");
    }
  }
  else {
    g_persistent.dropletForwardEnable = (bool) val;
  }

  // Encryption
  rv = nvs_get_u8(g_nvsHandle, "drop_enc", &g_persistent.dropletEncryption);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "drop_enc", g_persistent.dropletEncryption);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet encryption");
    }
  }

  // Adj filter channel
  rv = nvs_get_u8(g_nvsHandle, "drop_filt", &val);
  if (ESP_OK != rv) {
    val = (uint8_t) g_persistent.dropletFilterAdjacentChannel;
    rv  = nvs_set_u8(g_nvsHandle, "drop_filt", g_persistent.dropletFilterAdjacentChannel);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet adj channel filter");
    }
  }
  else {
    g_persistent.dropletFilterAdjacentChannel = (bool) val;
  }

  // Allow switching channel on forward
  rv = nvs_get_u8(g_nvsHandle, "drop_swchf", &val);
  if (ESP_OK != rv) {
    val = (uint8_t) g_persistent.dropletForwardSwitchChannel;
    rv  = nvs_set_u8(g_nvsHandle, "drop_swchf", g_persistent.dropletForwardSwitchChannel);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet shitch channel on forward");
    }
  }
  else {
    g_persistent.dropletFilterAdjacentChannel = (bool) val;
  }

  // RSSI limit
  rv = nvs_get_i8(g_nvsHandle, "drop_rssi", &g_persistent.dropletFilterWeakSignal);
  if (ESP_OK != rv) {
    rv = nvs_set_u8(g_nvsHandle, "drop_rssi", g_persistent.dropletFilterWeakSignal);
    if (rv != ESP_OK) {
      ESP_LOGE(TAG, "Failed to update droplet RSSI");
    }
  }

  rv = nvs_commit(g_nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGI(TAG, "Failed to commit updates to nvs\n");
  }

  return ESP_OK;
}

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
    //.url = "http://185.144.156.45:80/hello_world.bin", // vscp1
    .url = "http://185.144.156.45:80/vscp_espnow_alpha.bin",
    //.url               = "https://185.144.156.54:443/hello_world.bin", // vscp2
    //.cert_pem          = (char *) server_cert_pem_start,
    .crt_bundle_attach = esp_crt_bundle_attach,
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
    .partial_http_download = false,
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
    ESP_LOGE(TAG, "Failed to start indicator light");
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
    vprintf_like_t logFunc = esp_log_set_vprintf(g_stdLogFunc);
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
startOTA(void)
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
      printf("GUID not found in nvs\n");
      return false;

    default:
      printf("Error (%s) reading GUID from nvs!\n", esp_err_to_name(rv));
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
  static int retries;

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
        retries++;
        if (retries >= PROV_MGR_MAX_RETRY_CNT) {
          ESP_LOGI(TAG,
                   "Failed to connect with provisioned AP, reseting "
                   "provisioned credentials");
          wifi_prov_mgr_reset_sm_state_on_failure();
          retries = 0;
        }
        break;
      }

      case WIFI_PROV_CRED_SUCCESS:
        ESP_LOGI(TAG, "Provisioning successful");
        retries = 0;
        break;

      case WIFI_PROV_END:
        // De-initialize manager once provisioning is finished
        wifi_prov_mgr_deinit();
        ESP_LOGI(TAG, "Provisioning manager released");
        break;

      default:
        break;
    }
  }
  else if (event_base == WIFI_EVENT) {

    switch (event_id) {

      case WIFI_EVENT_WIFI_READY: {
        // Set channel
        ESP_ERROR_CHECK(esp_wifi_set_channel(PRJDEF_DROPLET_CHANNEL, WIFI_SECOND_CHAN_NONE));
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
        ESP_LOGI(TAG,
                 "Connected to %s (BSSID: " MACSTR ", Channel: %d)",
                 event->ssid,
                 MAC2STR(event->bssid),
                 event->channel);
        s_sta_connected_flag = true;
        break;
      }

      case WIFI_EVENT_STA_DISCONNECTED: {
        ESP_LOGI(TAG, "sta disconnect");
        if (!s_sta_connected_flag) {
          s_sta_connected_flag = false;
          ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
          g_state = MAIN_STATE_INIT;
          esp_wifi_connect();
        }
        break;
      }
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
      case WIFI_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "SoftAP transport: Connected!");
        break;
      case WIFI_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "SoftAP transport: Disconnected!");
        break;
#endif
      default:
        break;
    }
  }
  // Post 5.0 stable
  // ---------------
  // else if (event_base == ESP_HTTPS_OTA_EVENT) {
  //   switch (event_id) {

  //     case ESP_HTTPS_OTA_START: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_CONNECTED: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_GET_IMG_DESC: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_VERIFY_CHIP_ID: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_DECRYPT_CB: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_WRITE_FLASH: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_UPDATE_BOOT_PARTITION: {
  //       ;
  //     } break;

  //     case ESP_HTTPS_OTA_FINISH: {
  //       ;
  //     } break;

  //   case ESP_HTTPS_OTA_ABORT: {
  //       ;
  //     } break;
  // }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "Connected with IP Address: " IPSTR, IP2STR(&event->ip_info.ip));
    g_state = MAIN_STATE_WORK;
    // Signal main application to continue execution
    xEventGroupSetBits(g_wifi_event_group, WIFI_CONNECTED_EVENT);
  }
  else if (event_base == ALPHA_EVENT) {
    ESP_LOGI(TAG, "Alpha event -----------------------------------------------------------> id=%ld", event_id);
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

// ///////////////////////////////////////////////////////////////////////////////
// // vscp_heartbeat_task
// //
// // Sent periodically as a broadcast to all zones/subzones
// //

// static void
// vscp_heartbeat_task(void *pvParameter)
// {
//   esp_err_t ret                       = 0;
//   uint8_t dest_addr[ESP_NOW_ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
//   uint8_t buf[DROPLET_MIN_FRAME + 3]; // Three byte data
//   size_t size  = sizeof(buf);
//   int recv_seq = 0;

//   // Create Heartbeat event
//   if (VSCP_ERROR_SUCCESS != (ret = droplet_build_l1_heartbeat(buf, size, g_persistent.nodeGuid))) {
//     ESP_LOGE(TAG, "Could not create heartbeat event, will exit task. VSCP rv %d", ret);
//     goto ERROR;
//   }

//   ESP_LOGI(TAG, "Start sending VSCP heartbeats");

//   while (true) {

//     ESP_LOGI(TAG, "Sending heartbeat.");
//     ret =
//       droplet_send(dest_addr, false, VSCP_ENCRYPTION_NONE, g_persistent.pmk, 4, buf, DROPLET_MIN_FRAME + 3, 1000 /
//       portTICK_PERIOD_MS);
//     if (ret != ESP_OK) {
//       ESP_LOGE(TAG, "Failed to send heartbeat. ret = %d", ret);
//     }
//     // uint32_t hf = esp_get_free_heap_size();
//     // heap_caps_check_integrity_all(true);
//     // ESP_LOGI(TAG, "VSCP heartbeat sent - ret=0x%X heap=%X", (unsigned int) ret, (unsigned int) hf);

//     vTaskDelay(VSCP_HEART_BEAT_INTERVAL / portTICK_PERIOD_MS);
//   }

//   // ESP_ERROR_CONTINUE(ret != ESP_OK, "<%s>", esp_err_to_name(ret));

// ERROR:
//   ESP_LOGW(TAG, "Heartbeat task exit %d", ret);
//   vTaskDelete(NULL);
// }

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  esp_err_t ret;
  uint8_t dest_addr[ESP_NOW_ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t buf[DROPLET_MIN_FRAME + 3]; // Three byte data
  size_t size = sizeof(buf);

  cJSON *root = cJSON_CreateObject();

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
  led_indicator_handle_t g_led_handle = led_indicator_create(PRJDEF_INDICATOR_LED_PIN, &indicator_config);
  if (NULL == g_led_handle) {
    ESP_LOGE(TAG, "Failed to create LED indicator");
  }

  // Initialize Buttons

  button_config_t btncfg = {
        .type = BUTTON_TYPE_GPIO,
        //.long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        //.short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
        .gpio_button_config = {
            .gpio_num = PRJDEF_INIT_BUTTON_GPIO_PIN,
            .active_level = PRJDEF_INIT_BUTTON_ACTIVE_LEVEL,
        },
    };
  g_btns[0] = iot_button_create(&btncfg);
  iot_button_register_cb(g_btns[0], BUTTON_SINGLE_CLICK, button_single_click_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_DOUBLE_CLICK, button_double_click_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_LONG_PRESS_START, button_long_press_start_cb, NULL);
  iot_button_register_cb(g_btns[0], BUTTON_LONG_PRESS_HOLD, button_long_press_hold_cb, NULL);

  if (led_indicator_start(g_led_handle, BLINK_CONNECTING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  // Initiate message queues
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    g_tr_tcpsrv[i].msg_queue = xQueueCreate(10, DROPLET_MAX_FRAME); // tcp/ip link channel i
  }
  g_tr_mqtt.msg_queue = xQueueCreate(10, DROPLET_MAX_FRAME); // MQTT empties

  // ----------------------------------------------------------------------------
  //                        NVS - Persistent storage
  // ----------------------------------------------------------------------------

  // Init persistent storage
  ESP_LOGI(TAG, "Persistent storage ... ");

  rv = nvs_open("config", NVS_READWRITE, &g_nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Error (%s) opening NVS handle!\n", esp_err_to_name(rv));
  }
  else {
    // Read (or set to defaults) persistent values
    readPersistentConfigs();
  }

  g_ctrl_task_sem = xSemaphoreCreateBinary();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  g_wifi_event_group = xEventGroupCreate();

  // Register our event handler for Wi-Fi, IP and Provisioning related events
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));

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
  g_netif = esp_netif_create_default_wifi_sta();

  // #ifdef CONFIG_PROV_TRANSPORT_SOFTAP
  //   g_netif = esp_netif_create_default_wifi_ap();
  // #endif // CONFIG_PROV_TRANSPORT_SOFTAP

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  if (led_indicator_start(g_led_handle, BLINK_PROVISIONING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  // ----------------------------------------------------------------------------
  //                           WiFi Provisioning
  // ----------------------------------------------------------------------------

  if (!wifi_provisioning()) {

    ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi");

    /*
     * We don't need the manager as device is already provisioned,
     * so let's release it's resources
     */
    ESP_LOGI(TAG, "Deinit wifi manager");
    wifi_prov_mgr_deinit();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &system_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ALPHA_EVENT, ESP_EVENT_ANY_ID, &system_event_handler, NULL));

    // Start Wi-Fi soft ap & station
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA)); // Only APSTA is possible with esp-now working!!!
    ESP_ERROR_CHECK(esp_wifi_start());

    // Configure AP paramters
    if (ESP_OK != (ret = setAccessPointParameters())) {
      ESP_LOGE(TAG, "Unable top set AP parameters. rv =%X",ret); 
    }

    if (g_persistent.dropletLongRange) {
      ESP_ERROR_CHECK(
        esp_wifi_set_protocol(ESP_IF_WIFI_STA,
                              WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
    }
  } // !provisioning

  if (led_indicator_start(g_led_handle, BLINK_CONNECTING) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  // Wait for Wi-Fi connection
  ESP_LOGI(TAG, "Wait for wifi connection...");
  esp_event_post(/*_to(alpha_loop_handle,*/ ALPHA_EVENT, ALPHA_GET_IP_ADDRESS_START, NULL, 0, portMAX_DELAY);
  {
    EventBits_t ret;
    uint8_t cnt = 20; // 20 seconds until reboot due to no IP address
    while (!xEventGroupWaitBits(g_wifi_event_group, WIFI_CONNECTED_EVENT, false, true, 1000 / portTICK_PERIOD_MS)) {
      if (--cnt == 0) {
        // esp_wifi_disconnect();
        // esp_restart();
        vTaskDelay(2000 / portTICK_PERIOD_MS);
      }
      // ESP_LOGI(TAG, "Waiting for IP address. %d", cnt);
    }
  }
  esp_event_post(/*_to(alpha_loop_handle,*/ ALPHA_EVENT, ALPHA_GET_IP_ADDRESS_STOP, NULL, 0, portMAX_DELAY);

  if (led_indicator_start(g_led_handle, BLINK_CONNECTED) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start indicator light");
  }

  // Start web server
  httpd_handle_t server;
  if (g_persistent.webEnable) {
    server = start_webserver();
  }

  // Start MQTT client
  if (g_persistent.mqttEnable) {
    mqtt_start();
  }

  // ----------------------------------------------------------------------------
  //                                  Logging
  // ----------------------------------------------------------------------------

  switch (g_persistent.logType) {

    case ALPHA_LOG_NONE:
      break;

    case ALPHA_LOG_UDP:
      // ESP_ERROR_CHECK(udp_logging_init(g_persistent.logUrl, g_persistent.logPort, g_persistent.logwrite2Stdout));
      break;

    case ALPHA_LOG_TCP:
      ESP_ERROR_CHECK(tcp_logging_init(g_persistent.logUrl, g_persistent.logPort, g_persistent.logwrite2Stdout));
      break;

    case ALPHA_LOG_HTTP:
      ESP_ERROR_CHECK(http_logging_init(g_persistent.logUrl, g_persistent.logwrite2Stdout));
      break;

    case ALPHA_LOG_MQTT:
      ESP_ERROR_CHECK(mqtt_logging_init(g_persistent.logUrl, g_persistent.logMqttTopic, g_persistent.logwrite2Stdout));
      break;

    case ALPHA_LOG_VSCP:
      // ESP_ERROR_CHECK(mqtt_logging_init( CONFIG_LOG_MQTT_SERVER_URL, CONFIG_LOG_MQTT_PUB_TOPIC,
      // g_persistent.logwrite2Stdout ));
      break;

    case ALPHA_LOG_STD:
    default:
      break;
  }

  // ----------------------------------------------------------------------------
  //                                   Spiffs
  // ----------------------------------------------------------------------------

  // Initialize Spiffs for web pages
  ESP_LOGI(TAG, "Initializing SPIFFS");

  esp_vfs_spiffs_conf_t spiffsconf = { .base_path              = "/spiffs",
                                       .partition_label        = "web",
                                       .max_files              = 50,
                                       .format_if_mount_failed = true };

  // Initialize and mount SPIFFS filesystem.
  ret = esp_vfs_spiffs_register(&spiffsconf);

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

  ESP_LOGI(TAG, "Performing SPIFFS_check().");
  ret = esp_spiffs_check(spiffsconf.partition_label);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
    return;
  }
  else {
    ESP_LOGI(TAG, "SPIFFS_check() successful");
  }

  ESP_LOGI(TAG, "SPIFFS for web initialized");

  size_t total = 0, used = 0;
  ret = esp_spiffs_info(spiffsconf.partition_label, &total, &used);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s). Formatting...", esp_err_to_name(ret));
    esp_spiffs_format(spiffsconf.partition_label);
    return;
  }
  else {
    ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
  }

  DIR *dir = opendir("/spiffs");
  if (dir == NULL) {
    return;
  }

  while (true) {

    struct dirent *de = readdir(dir);
    if (!de) {
      break;
    }

    printf("Found file: %s\n", de->d_name);
  }

  closedir(dir);

  // Start LED controlling tast
  // xTaskCreate(&led_task, "led_task", 1024, NULL, 5, NULL);

  // ----------------------------------------------------------------------------
  //                              Droplet
  // ----------------------------------------------------------------------------

  // Initialize droplet
  droplet_config_t droplet_config = { .channel                = g_persistent.dropletChannel,
                                      .ttl                    = g_persistent.dropletTtl,
                                      .bForwardEnable         = g_persistent.dropletForwardEnable,
                                      .sizeQueue              = g_persistent.dropletSizeQueue,
                                      .bFilterAdjacentChannel = g_persistent.dropletFilterAdjacentChannel,
                                      .bForwardSwitchChannel  = g_persistent.dropletForwardSwitchChannel,
                                      .filterWeakSignal       = g_persistent.dropletFilterWeakSignal };

  // Set local key
  droplet_config.lkey = g_persistent.lkey;

  // Set primary key
  droplet_config.pmk = g_persistent.pmk;

  // Set GUID
  droplet_config.nodeGuid = g_persistent.nodeGuid;

  if (g_persistent.dropletEnable) {
    // Set callback for droplet receive events
    droplet_set_vscp_user_handler_cb(droplet_receive_cb);

    if (ESP_OK != droplet_init(&droplet_config)) {
      ESP_LOGE(TAG, "Failed to initialize espnow");
    }

    // Start heartbeat task vscp_heartbeat_task
    // xTaskCreate(&vscp_heartbeat_task, "vscp_heartbeat_task", 4096, NULL, 5, NULL);
  }

  ESP_LOGI(TAG, "espnow initializated");

  // startOTA();

  // xTaskCreate(vscp_espnow_send_task, "vscp_espnow_send_task", 4096, NULL, 4, NULL);
  // xTaskCreate(vscp_espnow_recv_task, "vscp_espnow_recv_task", 2048, NULL, 4, NULL);

  // Start the VSCP Link Protocol Server
  if (g_persistent.vscplinkEnable) {
#ifdef CONFIG_EXAMPLE_IPV6
    xTaskCreate(&tcpsrv_task, "vscp_tcpsrv_task", 4096, (void *) AF_INET6, 5, NULL);
#else
    xTaskCreate(&tcpsrv_task, "vscp_tcpsrv_task", 4096, (void *) AF_INET, 5, NULL);
#endif
  }

  ESP_LOGI(TAG, "Going to work now!");

  // vTaskDelay(5000 / portTICK_PERIOD_MS);

  /*
    Start main application loop now
  */

  if (VSCP_ERROR_SUCCESS != (ret = droplet_build_l1_heartbeat(buf, size, g_persistent.nodeGuid))) {
    ESP_LOGE(TAG, "Could not create heartbeat event, will exit task. VSCP rv %d", ret);
  }

  ret = droplet_send(dest_addr,
                     false,
                     VSCP_ENCRYPTION_NONE,
                     g_persistent.pmk,
                     4,
                     buf,
                     DROPLET_MIN_FRAME + 3,
                     1000 / portTICK_PERIOD_MS);
  if (ESP_OK != ret) {
    ESP_LOGE(TAG, "Could not send droplet start event. rv %d", ret);
  }

  /* const char *obj = "{"
     "\"vscpHead\": 2,"
     "\"vscpObId\": 123,"
     "\"vscpDateTime\": \"2017-01-13T10:16:02\","
     "\"vscpTimeStamp\":50817,"
     "\"vscpClass\": 10,"
     "\"vscpType\": 8,"
     "\"vscpGuid\": \"00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:02\","
     "\"vscpData\": [1,2,3,4,5,6,7],"
     "\"note\": \"This is some text\""
  "}";

vscpEventEx ex;
droplet_parse_vscp_json(obj, &ex);
char str[512];
droplet_create_vscp_json(str, &ex); */

  // test();

  while (1) {
    // esp_task_wdt_reset();
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
