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


  ESP Now + web server
  https://randomnerdtutorials.com/esp32-esp-now-wi-fi-web-server/#:~:text=Using%20ESP%2DNOW%20and%20Wi%2DFi%20Simultaneously&text=The%20ESP32%20sender%20boards%20must,channel%20of%20the%20receiver%20board.&text=You%20can%20set%20up%20the,same%20of%20the%20receiver%20board.
*/

#include "sdkconfig.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#if CONFIG_EXAMPLE_CONNECT_ETHERNET
#include "esp_eth.h"
#endif
#include "esp_crc.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_now.h"
#include "esp_tls_crypto.h"
#include "espnow_example.h"
#include <esp_http_server.h>

#define ESPNOW_MAXDELAY 512

#define CONFIG_BASIC_AUTH           1
#define CONFIG_BASIC_AUTH_USERNAME  "vscp"
#define CONFIG_BASIC_AUTH_PASSWORD  "secret"

// #define EXAMPLE_CONNECT_WIFI        1
// #define CONFIG_CONNECT_ETHERNET    0
// #define CONFIG_CONNECT_IPV6        0
// #define CONFIG_WIFI_CONN_MAX_RETRY 6

#define CONFIG_WIFI_AUTH_WPA_PSK         1
#define CONFIG_WIFI_SCAN_METHOD          WIFI_ALL_CHANNEL_SCAN
#define CONFIG_WIFI_CONNECT_AP_BY_SIGNAL 1

#if CONFIG_WIFI_CONNECT_AP_BY_SIGNAL
#define WIFI_CONNECT_AP_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#elif CONFIG_WIFI_CONNECT_AP_BY_SECURITY
#define WIFI_CONNECT_AP_SORT_METHOD WIFI_CONNECT_AP_BY_SECURITY
#endif
#define CONFIG_WIFI_SCAN_RSSI_THRESHOLD (-127)

#if CONFIG_WIFI_AUTH_OPEN
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_WIFI_AUTH_WEP
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_WIFI_AUTH_WPA_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_WIFI_AUTH_WPA2_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_WIFI_AUTH_WPA_WPA2_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_WIFI_AUTH_WPA2_ENTERPRISE
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_ENTERPRISE
#elif CONFIG_WIFI_AUTH_WPA3_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_WIFI_AUTH_WPA2_WPA3_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_WIFI_AUTH_WAPI_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#endif

#define NETIF_DESC_STA "netif_sta"

static const char *TAG                        = "espnow_http";

static esp_netif_t *s_apsta_netif               = NULL;
static SemaphoreHandle_t s_semph_get_ip_addrs = NULL;
#if CONFIG_EXAMPLE_CONNECT_IPV6
static SemaphoreHandle_t s_semph_get_ip6_addrs = NULL;
#endif

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/*
 * The event group allows multiple bits for each event, but we only care about
 * two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries
 */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static QueueHandle_t s_espnow_queue;

static uint8_t s_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint16_t s_espnow_seq[ESPNOW_DATA_MAX]    = { 0, 0 };

static void
espnow_deinit(espnow_send_param_t *send_param);

///////////////////////////////////////////////////////////////////////////////
// wifi_init
//
// WiFi should start before using ESPNOW
//

static void
wifi_init(void)
{
  s_wifi_event_group = xEventGroupCreate();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
  // Warning: the interface desc is used in tests to capture actual connection
  // details (IP, gw, mask)
  esp_netif_config.if_desc    = NETIF_DESC_STA;
  esp_netif_config.route_prio = 128;
  s_apsta_netif                 = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
  esp_wifi_set_default_wifi_sta_handlers();

  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
  ESP_ERROR_CHECK(esp_wifi_start());

  // Wait for wifi to connect

  ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE));

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

  // Start sending broadcast ESPNOW data. 
  espnow_send_param_t *send_param = (espnow_send_param_t *) pvParameter;
  if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
    ESP_LOGE(TAG, "Send error");
    espnow_deinit(send_param);
    vTaskDelete(NULL);
  }

  while (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {
    
      case ESPNOW_SEND_CB: {
        espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        is_broadcast                    = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG, "Send data to " MACSTR ", status1: %d", MAC2STR(send_cb->mac_addr), send_cb->status);

        if (is_broadcast && (send_param->broadcast == false)) {
          break;
        }

        if (!is_broadcast) {
          // send_param->count--;
          if (send_param->count == 0) {
            ESP_LOGI(TAG, "Send done");
            espnow_deinit(send_param);
            vTaskDelete(NULL);
          }
        }

        // Delay a while before sending the next data. 
        if (send_param->delay > 0) {
          vTaskDelay(send_param->delay / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "send data to " MACSTR "", MAC2STR(send_cb->mac_addr));

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

        ret = espnow_data_parse(recv_cb->data, recv_cb->data_len, &recv_state, &recv_seq, &recv_magic);
        free(recv_cb->data);
        if (ret == ESPNOW_DATA_BROADCAST) {
          ESP_LOGI(TAG,
                   "Receive %dth broadcast data from: " MACSTR ", len: %d",
                   recv_seq,
                   MAC2STR(recv_cb->mac_addr),
                   recv_cb->data_len);

          // If MAC address does not exist in peer list, add it to peer list. 
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
              ESP_LOGI(TAG, "send data to " MACSTR "", MAC2STR(recv_cb->mac_addr));

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
                   "Receive %dth unicast data from: " MACSTR ", len: %d",
                   recv_seq,
                   MAC2STR(recv_cb->mac_addr),
                   recv_cb->data_len);

          // If receive unicast ESPNOW data, also stop sending broadcast ESPNOW
          // data. 
          send_param->broadcast = false;
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
  // modem will be put to sleep if rf modue is not in used anymore
  ESP_ERROR_CHECK(esp_now_set_wake_window(65535));
#endif
  // Set primary master key. 
  ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

  // Add broadcast peer information to peer list. 
  esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
  if (peer == NULL) {
    ESP_LOGE(TAG, "Malloc peer information fail");
    vSemaphoreDelete(s_espnow_queue);
    esp_now_deinit();
    return ESP_FAIL;
  }

  memset(peer, 0, sizeof(esp_now_peer_info_t));
  peer->channel = CONFIG_ESPNOW_CHANNEL;
  peer->ifidx   = ESPNOW_WIFI_IF;
  peer->encrypt = false;
  memcpy(peer->peer_addr, s_broadcast_mac, ESP_NOW_ETH_ALEN);
  ESP_ERROR_CHECK(esp_now_add_peer(peer));
  free(peer);

  // Initialize sending parameters. 
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

// * * * WEB Server * * *

typedef struct {
  char *username;
  char *password;
} basic_auth_info_t;

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

///////////////////////////////////////////////////////////////////////////////
// http_auth_basic
//

static char *
http_auth_basic(const char *username, const char *password)
{
  int out;
  char *user_info = NULL;
  char *digest    = NULL;
  size_t n        = 0;
  asprintf(&user_info, "%s:%s", username, password);
  if (!user_info) {
    ESP_LOGE(TAG, "No enough memory for user information");
    return NULL;
  }
  esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *) user_info, strlen(user_info));

  /* 6: The length of the "Basic " string
   * n: Number of bytes for a base64 encode format
   * 1: Number of bytes for a reserved which be used to fill zero
   */
  digest = calloc(1, 6 + n + 1);
  if (digest) {
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *) digest + 6,
                             n,
                             (size_t *) &out,
                             (const unsigned char *) user_info,
                             strlen(user_info));
  }
  free(user_info);
  return digest;
}

///////////////////////////////////////////////////////////////////////////////
// basic_auth_get_handler
//
// An HTTP GET handler
//

static esp_err_t
basic_auth_get_handler(httpd_req_t *req)
{
  char *buf                          = NULL;
  size_t buf_len                     = 0;
  basic_auth_info_t *basic_auth_info = req->user_ctx;

  buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
  if (buf_len > 1) {
    buf = calloc(1, buf_len);
    if (!buf) {
      ESP_LOGE(TAG, "No enough memory for basic authorization");
      return ESP_ERR_NO_MEM;
    }

    if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
    }
    else {
      ESP_LOGE(TAG, "No auth value received");
    }

    char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
    if (!auth_credentials) {
      ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
      free(buf);
      return ESP_ERR_NO_MEM;
    }

    if (strncmp(auth_credentials, buf, buf_len)) {
      ESP_LOGE(TAG, "Not authenticated");
      httpd_resp_set_status(req, HTTPD_401);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
      httpd_resp_send(req, NULL, 0);
    }
    else {
      ESP_LOGI(TAG, "Authenticated!");
      char *basic_auth_resp = NULL;
      httpd_resp_set_status(req, HTTPD_200);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
      if (!basic_auth_resp) {
        ESP_LOGE(TAG, "No enough memory for basic authorization response");
        free(auth_credentials);
        free(buf);
        return ESP_ERR_NO_MEM;
      }
      httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
      free(basic_auth_resp);
    }
    free(auth_credentials);
    free(buf);
  }
  else {
    ESP_LOGE(TAG, "No auth header received");
    httpd_resp_set_status(req, HTTPD_401);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
    httpd_resp_send(req, NULL, 0);
  }

  return ESP_OK;
}

static httpd_uri_t basic_auth = {
  .uri     = "/basic_auth",
  .method  = HTTP_GET,
  .handler = basic_auth_get_handler,
};

///////////////////////////////////////////////////////////////////////////////
// httpd_register_basic_auth
//

static void
httpd_register_basic_auth(httpd_handle_t server)
{
  basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
  if (basic_auth_info) {
    basic_auth_info->username = CONFIG_BASIC_AUTH_USERNAME;
    basic_auth_info->password = CONFIG_BASIC_AUTH_PASSWORD;

    basic_auth.user_ctx = basic_auth_info;
    httpd_register_uri_handler(server, &basic_auth);
  }
}

///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// An HTTP GET handler
//

static esp_err_t
hello_get_handler(httpd_req_t *req)
{
  char *buf;
  size_t buf_len;

  /* Get header value string length and allocate memory for length + 1,
   * extra byte for null termination */
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    /* Copy null terminated value string into buffer */
    if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
    }
    free(buf);
  }

  /* Read URL query string length and allocate memory for length + 1,
   * extra byte for null termination */
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char param[32];
      /* Get value of expected key from query string */
      if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
      }
      if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
      }
      if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
      }
    }
    free(buf);
  }

  /* Set some custom headers */
  httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
  httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

  /* Send response with custom headers and body set as the
   * string passed in user context*/
  const char *resp_str = (const char *) req->user_ctx;

  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  /* After sending the HTTP response the old HTTP request
   * headers are lost. Check if HTTP request headers can be read now. */
  if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
    ESP_LOGI(TAG, "Request headers lost");
  }
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// httpd_uri_t
//

static const httpd_uri_t hello = { .uri     = "/hello",
                                   .method  = HTTP_GET,
                                   .handler = hello_get_handler,
                                   /* Let's pass response string in user
                                    * context to demonstrate it's usage */
                                   .user_ctx = "Hello World!" };

///////////////////////////////////////////////////////////////////////////////
// esp_err_t
//
/* An HTTP POST handler */

static esp_err_t
echo_post_handler(httpd_req_t *req)
{
  char buf[100];
  int ret, remaining = req->content_len;

  while (remaining > 0) {
    /* Read the data for the request */
    if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
        /* Retry receiving if timeout occurred */
        continue;
      }
      return ESP_FAIL;
    }

    /* Send back the same data */
    httpd_resp_send_chunk(req, buf, ret);
    remaining -= ret;

    /* Log data received */
    ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TAG, "%.*s", ret, buf);
    ESP_LOGI(TAG, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// httpd_uri_t
//

static const httpd_uri_t echo = { .uri = "/echo", .method = HTTP_POST, .handler = echo_post_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// http_404_error_handler
//
/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t
http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
  if (strcmp("/hello", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
    /* Return ESP_OK to keep underlying socket open */
    return ESP_OK;
  }
  else if (strcmp("/echo", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
    /* Return ESP_FAIL to close underlying socket */
    return ESP_FAIL;
  }
  /* For any other URI send 404 and close socket */
  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
  return ESP_FAIL;
}

///////////////////////////////////////////////////////////////////////////////
// ctrl_put_handler
//
/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t
ctrl_put_handler(httpd_req_t *req)
{
  char buf;
  int ret;

  if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }

  if (buf == '0') {
    /* URI handlers can be unregistered using the uri string */
    ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
    httpd_unregister_uri(req->handle, "/hello");
    httpd_unregister_uri(req->handle, "/echo");
    /* Register the custom error handler */
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
  }
  else {
    ESP_LOGI(TAG, "Registering /hello and /echo URIs");
    httpd_register_uri_handler(req->handle, &hello);
    httpd_register_uri_handler(req->handle, &echo);
    /* Unregister custom error handler */
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
  }

  /* Respond with empty body */
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// httpd_uri_t
//

static const httpd_uri_t ctrl = { .uri = "/ctrl", .method = HTTP_PUT, .handler = ctrl_put_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// start_webserver
//

static httpd_handle_t
start_webserver(void)
{
  httpd_handle_t server   = NULL;
  httpd_config_t config   = HTTPD_DEFAULT_CONFIG();
  config.lru_purge_enable = true;

  // Start the httpd server
  ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
  if (httpd_start(&server, &config) == ESP_OK) {
    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &hello);
    httpd_register_uri_handler(server, &echo);
    httpd_register_uri_handler(server, &ctrl);
#if CONFIG_BASIC_AUTH
    httpd_register_basic_auth(server);
#endif
    return server;
  }

  ESP_LOGI(TAG, "Error starting server!");
  return NULL;
}

static int s_retry_num = 0;

///////////////////////////////////////////////////////////////////////////////
// is_our_netif
//
// @brief Checks the netif description if it contains specified prefix.
// All netifs created withing common connect component are prefixed with the
// module TAG, so it returns true if the specified netif is owned by this module
//

bool
is_our_netif(const char *prefix, esp_netif_t *netif)
{
  return strncmp(prefix, esp_netif_get_desc(netif), strlen(prefix) - 1) == 0;
}

///////////////////////////////////////////////////////////////////////////////
// get_netif_from_desc
//

esp_netif_t *
get_netif_from_desc(const char *desc)
{
  esp_netif_t *netif = NULL;
  while ((netif = esp_netif_next(netif)) != NULL) {
    if (strcmp(esp_netif_get_desc(netif), desc) == 0) {
      return netif;
    }
  }
  return netif;
}

///////////////////////////////////////////////////////////////////////////////
// handler_on_wifi_disconnect
//

static void
handler_on_wifi_disconnect(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  s_retry_num++;
  if (s_retry_num > CONFIG_EXAMPLE_WIFI_CONN_MAX_RETRY) {
    ESP_LOGI(TAG, "WiFi Connect failed %d times, stop reconnect.", s_retry_num);
    /* let example_wifi_sta_do_connect() return */
    if (s_semph_get_ip_addrs) {
      xSemaphoreGive(s_semph_get_ip_addrs);
    }
#if CONFIG_CONNECT_IPV6
    if (s_semph_get_ip6_addrs) {
      xSemaphoreGive(s_semph_get_ip6_addrs);
    }
#endif
    return;
  }
  ESP_LOGI(TAG, "Wi-Fi disconnected, trying to reconnect...");
  esp_err_t err = esp_wifi_connect();
  if (err == ESP_ERR_WIFI_NOT_STARTED) {
    return;
  }
  ESP_ERROR_CHECK(err);
}

///////////////////////////////////////////////////////////////////////////////
// handler_on_wifi_connect
//

static void
handler_on_wifi_connect(void *esp_netif, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
#if CONFIG_CONNECT_IPV6
  esp_netif_create_ip6_linklocal(esp_netif);
#endif // CONFIG_CONNECT_IPV6
}

///////////////////////////////////////////////////////////////////////////////
// handler_on_sta_got_ip
//

static void
handler_on_sta_got_ip(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  s_retry_num              = 0;
  
  ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
  if (!is_our_netif(NETIF_DESC_STA, event->esp_netif)) {
    return;
  }

  ESP_LOGI(TAG,
           "Got IPv4 event: Interface \"%s\" address: " IPSTR,
           esp_netif_get_desc(event->esp_netif),
           IP2STR(&event->ip_info.ip));

  if (s_semph_get_ip_addrs) {
    // Release the semaphore
    xSemaphoreGive(s_semph_get_ip_addrs);
  }
  else {
    ESP_LOGI(TAG, "- IPv4 address: " IPSTR ",", IP2STR(&event->ip_info.ip));
  }
}

///////////////////////////////////////////////////////////////////////////////
// handler_on_sta_got_ipv6
//

#if CONFIG_EXAMPLE_CONNECT_IPV6
static void
handler_on_sta_got_ipv6(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  ip_event_got_ip6_t *event = (ip_event_got_ip6_t *) event_data;
  if (!is_our_netif(NETIF_DESC_STA, event->esp_netif)) {
    return;
  }
  esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&event->ip6_info.ip);
  ESP_LOGI(TAG,
           "Got IPv6 event: Interface \"%s\" address: " IPV6STR ", type: %s",
           esp_netif_get_desc(event->esp_netif),
           IPV62STR(event->ip6_info.ip),
           ipv6_addr_types_to_str[ipv6_type]);

  if (ipv6_type == CONNECT_PREFERRED_IPV6_TYPE) {
    if (s_semph_get_ip6_addrs) {
      xSemaphoreGive(s_semph_get_ip6_addrs);
    }
    else {
      ESP_LOGI(TAG,
               "- IPv6 address: " IPV6STR ", type: %s",
               IPV62STR(event->ip6_info.ip),
               example_ipv6_addr_types_to_str[ipv6_type]);
    }
  }
}
#endif // CONFIG_EXAMPLE_CONNECT_IPV6

///////////////////////////////////////////////////////////////////////////////
// wifi_start
//

// void
// wifi_start(void)
// {
//   wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//   ESP_ERROR_CHECK(esp_wifi_init(&cfg));

//   esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
//   // Warning: the interface desc is used in tests to capture actual connection
//   // details (IP, gw, mask)
//   esp_netif_config.if_desc    = NETIF_DESC_STA;
//   esp_netif_config.route_prio = 128;
//   s_apsta_netif                 = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
//   esp_wifi_set_default_wifi_sta_handlers();

//   ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
//   ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
//   ESP_ERROR_CHECK(esp_wifi_start());
// }

///////////////////////////////////////////////////////////////////////////////
// stop_webserver
//

static esp_err_t
stop_webserver(httpd_handle_t server)
{
  // Stop the httpd server
  return httpd_stop(server);
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// wifi_stop
//

void
wifi_stop(void)
{
  esp_err_t err = esp_wifi_stop();
  if (err == ESP_ERR_WIFI_NOT_INIT) {
    return;
  }
  ESP_ERROR_CHECK(err);
  ESP_ERROR_CHECK(esp_wifi_deinit());
  ESP_ERROR_CHECK(esp_wifi_clear_default_wifi_driver_and_handlers(s_apsta_netif));
  esp_netif_destroy(s_apsta_netif);
  s_apsta_netif = NULL;
}

///////////////////////////////////////////////////////////////////////////////
// wifi_sta_do_connect
//

esp_err_t
wifi_sta_do_connect(wifi_config_t wifi_config, bool wait)
{
  if (wait) {
    // Create semaphore for IPv4 address
    s_semph_get_ip_addrs = xSemaphoreCreateBinary();
    if (s_semph_get_ip_addrs == NULL) {
      return ESP_ERR_NO_MEM;
    }
#if CONFIG_EXAMPLE_CONNECT_IPV6
    // Create semaphore for IPv6 address
    s_semph_get_ip6_addrs = xSemaphoreCreateBinary();
    if (s_semph_get_ip6_addrs == NULL) {
      vSemaphoreDelete(s_semph_get_ip_addrs);
      return ESP_ERR_NO_MEM;
    }
#endif
  }

  s_retry_num = 0;
  ESP_ERROR_CHECK(
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &handler_on_wifi_disconnect, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler_on_sta_got_ip, NULL));
  ESP_ERROR_CHECK(
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &handler_on_wifi_connect, s_apsta_netif));
#if CONFIG_EXAMPLE_CONNECT_IPV6
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &handler_on_sta_got_ipv6, NULL));
#endif

  ESP_LOGI(TAG, "Connecting to %s...", wifi_config.sta.ssid);
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));  // WIFI_IF_AP
  esp_err_t ret = esp_wifi_connect();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "WiFi connect failed! ret:%x", ret);
    return ret;
  }
  if (wait) {
    ESP_LOGI(TAG, "Waiting for IP(s)");
    xSemaphoreTake(s_semph_get_ip_addrs, portMAX_DELAY);
#if CONFIG_EXAMPLE_CONNECT_IPV6
    xSemaphoreTake(s_semph_get_ip6_addrs, portMAX_DELAY);
#endif
    if (s_retry_num > CONFIG_EXAMPLE_WIFI_CONN_MAX_RETRY) {
      ESP_LOGI(TAG, "Waiting for IP(s) - Timeout");
      return ESP_FAIL;
    }
  }
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// wifi_sta_do_disconnect
//

esp_err_t
wifi_sta_do_disconnect(void)
{
  ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &handler_on_wifi_disconnect));
  ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler_on_sta_got_ip));
  ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &handler_on_wifi_connect));
#if CONFIG_EXAMPLE_CONNECT_IPV6
  ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_GOT_IP6, &handler_on_sta_got_ipv6));
#endif
  if (s_semph_get_ip_addrs) {
    vSemaphoreDelete(s_semph_get_ip_addrs);
  }
#if CONFIG_EXAMPLE_CONNECT_IPV6
  if (s_semph_get_ip6_addrs) {
    vSemaphoreDelete(s_semph_get_ip6_addrs);
  }
#endif
  return esp_wifi_disconnect();
}

///////////////////////////////////////////////////////////////////////////////
// wifi_shutdown
//

void
wifi_shutdown(void)
{
  wifi_sta_do_disconnect();
  wifi_stop();
}

///////////////////////////////////////////////////////////////////////////////
// wifi_connect
//

esp_err_t
wifi_connect(void)
{
  ESP_LOGI(TAG, "Start wifi_connect.");

  // wifi_start();
  wifi_config_t wifi_config = {
    .sta =
      {
        .ssid = CONFIG_EXAMPLE_WIFI_SSID,
        .password = CONFIG_EXAMPLE_WIFI_PASSWORD,
        .scan_method = CONFIG_WIFI_SCAN_METHOD,
        .sort_method = WIFI_CONNECT_AP_SORT_METHOD,
        .threshold.rssi = CONFIG_WIFI_SCAN_RSSI_THRESHOLD,
        .threshold.authmode = WIFI_SCAN_AUTH_MODE_THRESHOLD,
      },
  };

  return wifi_sta_do_connect(wifi_config, true);
}

///////////////////////////////////////////////////////////////////////////////
// print_all_netif_ips
//

void
print_all_netif_ips(const char *prefix)
{
  // iterate over active interfaces, and print out IPs of "our" netifs
  esp_netif_t *netif = NULL;
  esp_netif_ip_info_t ip;
  
  for (int i = 0; i < esp_netif_get_nr_of_ifs(); ++i) {
    netif = esp_netif_next(netif);
    if (is_our_netif(prefix, netif)) {
      ESP_LOGI(TAG, "Connected to %s", esp_netif_get_desc(netif));
      ESP_ERROR_CHECK(esp_netif_get_ip_info(netif, &ip));

      ESP_LOGI(TAG, "- IPv4 address: " IPSTR ",", IP2STR(&ip.ip));
#if CONFIG_CONNECT_IPV6
      esp_ip6_addr_t ip6[MAX_IP6_ADDRS_PER_NETIF];
      int ip6_addrs = esp_netif_get_all_ip6(netif, ip6);
      for (int j = 0; j < ip6_addrs; ++j) {
        esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&(ip6[j]));
        ESP_LOGI(TAG, "- IPv6 address: " IPV6STR ", type: %s", IPV62STR(ip6[j]), ipv6_addr_types_to_str[ipv6_type]);
      }
#endif
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// station_connect
//

esp_err_t
station_connect(void)
{

#if CONFIG_CONNECT_ETHERNET
  if (ethernet_connect() != ESP_OK) {
    return ESP_FAIL;
  }
  ESP_ERROR_CHECK(esp_register_shutdown_handler(&ethernet_shutdown));
#endif

#if CONFIG_CONNECT_WIFI
  if (wifi_connect() != ESP_OK) { 
    return ESP_FAIL;
  }
  ESP_ERROR_CHECK(esp_register_shutdown_handler(&wifi_shutdown));
#endif

#if CONFIG_CONNECT_ETHERNET
  print_all_netif_ips(NETIF_DESC_ETH);
#endif

#if CONFIG_CONNECT_WIFI
  print_all_netif_ips(NETIF_DESC_STA);
#endif

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// station_disconnect
//

esp_err_t
station_disconnect(void)
{
#if CONFIG_CONNECT_ETHERNET
  ethernet_shutdown();
  ESP_ERROR_CHECK(esp_unregister_shutdown_handler(&ethernet_shutdown));
#endif
#if CONFIG_CONNECT_WIFI
  wifi_shutdown();
  ESP_ERROR_CHECK(esp_unregister_shutdown_handler(&wifi_shutdown));
#endif
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// disconnect_handler
//

static void
disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server) {
    ESP_LOGI(TAG, "Stopping webserver");
    if (stop_webserver(*server) == ESP_OK) {
      *server = NULL;
    }
    else {
      ESP_LOGE(TAG, "Failed to stop http server");
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// connect_handler
//

static void
connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server == NULL) {
    ESP_LOGI(TAG, "Starting webserver");
    *server = start_webserver();
  }
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
// app_main
//

void
app_main(void)
{
  static httpd_handle_t server = NULL;

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  wifi_init();    

  /*
   * This helper function configures Wi-Fi or Ethernet, as selected in
   * menuconfig. Read "Establishing Wi-Fi or Ethernet Connection" section in
   * examples/protocols/README.md for more information about this function.
   */
  wifi_connect();

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));

  // Start the web server 
  server = start_webserver();

  espnow_init();
}
