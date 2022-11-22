/* ESPNOW alpha

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
   This example act as an VSCP alpha device and send out messages
   periodically
*/
#include "esp_crc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include <esp_timer.h>

#include "iot_button.h"
#include "driver/gpio.h"

// Components
#include "esp_utils.h"
#include "esp_storage.h"
#include "espnow.h"
#include "espnow_security.h"
#include "espnow_ctrl.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "freertos/timers.h"
#include "nvs_flash.h"

#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>

#include "vscp_espnow.h"
#include "espnow_alpha.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ESPNOW_MAXDELAY 512

#ifdef CONFIG_IDF_TARGET_ESP32C3
#define BOOT_KEY_GPIIO        GPIO_NUM_9
#define CONFIG_LED_GPIO GPIO_NUM_2
#elif CONFIG_IDF_TARGET_ESP32S3
#define BOOT_KEY_GPIIO        GPIO_NUM_0
#define CONFIG_LED_GPIO GPIO_NUM_2
#else
#define BOOT_KEY_GPIIO        GPIO_NUM_0
#define CONFIG_LED_GPIO GPIO_NUM_2
#endif

const char *pop_data = "ESPNOW_POP";
static const char *TAG = "espnow_alpha";

static xQueueHandle s_vscp_espnow_queue;

static uint8_t s_vscp_broadcast_mac[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Every message sent get seq updated
// static uint16_t s_vscp_espnow_seq = 0;

typedef enum {
    ESPNOW_CTRL_INIT,
    ESPNOW_CTRL_BOUND,
    ESPNOW_CTRL_MAX
} espnow_ctrl_status_t;

void security(void);

static espnow_ctrl_status_t s_espnow_ctrl_status = ESPNOW_CTRL_INIT;

espnow_sec_t *g_sec;

///////////////////////////////////////////////////////////////////////////////
// getMilliSeconds
//

uint32_t
getMilliSeconds(void)
{
  return (esp_timer_get_time() / 1000);
};

static void
vscp_espnow_deinit(void *param);

///////////////////////////////////////////////////////////////////////////////
// initiator_send_press_cb
//

static void 
initiator_send_press_cb(void *arg, void *usr_data)
{
  ESP_ERROR_CHECK(!(BUTTON_SINGLE_CLICK == iot_button_get_event(arg)));
  ESP_LOGI(TAG, "initiator send press");
  static bool status = 0;
  if (s_espnow_ctrl_status == ESPNOW_CTRL_BOUND) {
      espnow_ctrl_initiator_send(ESPNOW_ATTRIBUTE_KEY_1, ESPNOW_ATTRIBUTE_POWER, status);
      status = !status;
  }
}

///////////////////////////////////////////////////////////////////////////////
// initiator_bind_press_cb
//

static void 
initiator_bind_press_cb(void *arg, void *usr_data)
{
  ESP_ERROR_CHECK(!(BUTTON_DOUBLE_CLICK == iot_button_get_event(arg)));
  ESP_LOGI(TAG, "initiator bind press");
  if (s_espnow_ctrl_status == ESPNOW_CTRL_INIT) {
      espnow_ctrl_initiator_bind(ESPNOW_ATTRIBUTE_KEY_1, true);
      s_espnow_ctrl_status = ESPNOW_CTRL_BOUND;      
  }
}

///////////////////////////////////////////////////////////////////////////////
// initiator_unbind_press_cb
//

static void 
initiator_unbind_press_cb(void *arg, void *usr_data)
{
  ESP_ERROR_CHECK(!(BUTTON_LONG_PRESS_START == iot_button_get_event(arg)));
  ESP_LOGI(TAG, "long press");
  if (s_espnow_ctrl_status == ESPNOW_CTRL_BOUND) {
    ESP_LOGI(TAG, "Unbound");
    espnow_ctrl_initiator_bind(ESPNOW_ATTRIBUTE_KEY_1, false);
    s_espnow_ctrl_status = ESPNOW_CTRL_INIT;
  }
  else if (s_espnow_ctrl_status == ESPNOW_CTRL_INIT) {
    ESP_LOGI(TAG, "Bound");
    espnow_ctrl_initiator_bind(ESPNOW_ATTRIBUTE_KEY_1, true);
    s_espnow_ctrl_status = ESPNOW_CTRL_BOUND;
    security();
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_wifi_init
//
// WiFi should start before using ESPNOW
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
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  ESP_ERROR_CHECK(esp_wifi_start());

#if CONFIG_ESPNOW_ENABLE_LONG_RANGE
  ESP_ERROR_CHECK(esp_wifi_set_protocol(ESPNOW_WIFI_IF,
                                        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
#endif
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_send_cb
//
/* ESPNOW sending or receiving callback function is called in WiFi task.
 * Users should not do lengthy operations from this task. Instead, post
 * necessary data to a queue and handle it from a lower priority task. */
static void
vscp_espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  vscp_espnow_event_post_t evt;
  vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = VSCP_ESPNOW_SEND_EVT;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send send queue fail");
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
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send receive queue fail");
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_data_parse
//
// Parse received ESPNOW data.
//

int
vscp_espnow_data_parse(uint8_t *buf, uint8_t len, vscp_espnow_event_t *pvscpData)
{
  uint16_t crc = 0, crc_cal = 0;

  if (len < VSCP_ESPNOW_PACKET_MIN_SIZE) {
    ESP_LOGE(TAG, "Receive ESPNOW data too short, len:%d", len);
    return -1;
  }

  if (len > VSCP_ESPNOW_PACKET_MAX_SIZE) {
    ESP_LOGE(TAG, "Receive ESPNOW data too long, len:%d", len);
    return -1;
  }

  // crc = buf->crc;
  // buf->crc = 0;
  crc_cal = esp_crc16_le(UINT16_MAX, (uint8_t const *) buf, len);

  if (crc_cal == crc) {
    return 0;
  }

  return -1;
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
  pvscpEspNowEvent->ttl = 7;
  // pvscpEspNowEvent->seq = seq++;
  //pvscpEspNowEvent->magic = esp_random();
  // pvscpEspNowEvent.crc = 0;
  //  https://grodansparadis.github.io/vscp-doc-spec/#/./class1.information?id=type9
  pvscpEspNowEvent->head       = 0;
  //pvscpEspNowEvent->timestamp  = 0;
  pvscpEspNowEvent->nickname   = 0;
  pvscpEspNowEvent->vscp_class = VSCP_CLASS1_INFORMATION;
  pvscpEspNowEvent->vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
  pvscpEspNowEvent->len        = 3;
  pvscpEspNowEvent->data[0] = 0;
  pvscpEspNowEvent->data[1] = 0xff; // All zones
  pvscpEspNowEvent->data[2] = 0xff; // All subzones

  // seq
  buf[0] = (pvscpEspNowEvent->seq >> 8) & 0xff;
  buf[1] = pvscpEspNowEvent->seq & 0xff;
  // magic
  // buf[2] = (pvscpEspNowEvent->magic >> 24) & 0xff;
  // buf[3] = (pvscpEspNowEvent->magic >> 16) & 0xff;
  // buf[4] = (pvscpEspNowEvent->magic >> 8) & 0xff;
  // buf[5] = pvscpEspNowEvent->magic & 0xff;
  // ttl
  buf[6] = pvscpEspNowEvent->ttl;
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
  uint16_t seq      = 0;
  uint16_t recv_seq = 0;
  // int recv_magic = 0;
  uint8_t dest_mac[ESP_NOW_ETH_ALEN]; // MAC address of destination device.
  vscp_espnow_event_t vscpEspNowEvent;
  uint8_t buf[VSCP_ESPNOW_PACKET_MAX_SIZE];
  int ret;

  memcpy(dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);

  vTaskDelay(5000 / portTICK_RATE_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  /* vscpEspNowEvent.ttl = 7;
  vscpEspNowEvent.seq = seq++;
  vscpEspNowEvent.magic = esp_random();
  vscpEspNowEvent.crc = 0;
  // https://grodansparadis.github.io/vscp-doc-spec/#/./class1.information?id=type9
  vscpEspNowEvent.head = 0;
  vscpEspNowEvent.timestamp = 0;
  vscpEspNowEvent.nickname = 0;
  vscpEspNowEvent.vscp_class = VSCP_CLASS1_INFORMATION;
  vscpEspNowEvent.vscp_type = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
  vscpEspNowEvent.len = 3;
  vscpEspNowEvent.payload[0] = 0;
  vscpEspNowEvent.payload[1] = 0xff; // All zones
  vscpEspNowEvent.payload[2] = 0xff; // All subzones

  // seq
  buf[0] = (vscpEspNowEvent.seq >> 8) & 0xff;
  buf[1] = vscpEspNowEvent.seq & 0xff;
  // magic
  buf[2] = (vscpEspNowEvent.magic >> 24) & 0xff;
  buf[3] = (vscpEspNowEvent.magic >> 16) & 0xff;
  buf[4] = (vscpEspNowEvent.magic >> 8) & 0xff;
  buf[5] = vscpEspNowEvent.magic & 0xff;
  // ttl
  buf[6] = vscpEspNowEvent.ttl;
  // head
  buf[7] = (vscpEspNowEvent.head >> 8) & 0xff;
  buf[8] = vscpEspNowEvent.head & 0xff;
  // timestamp
  buf[9] = (vscpEspNowEvent.timestamp >> 24) & 0xff;
  buf[10] = (vscpEspNowEvent.timestamp >> 16) & 0xff;
  buf[11] = (vscpEspNowEvent.timestamp >> 8) & 0xff;
  buf[12] = vscpEspNowEvent.timestamp & 0xff;
  // nickname
  buf[13] = (vscpEspNowEvent.nickname >> 8) & 0xff;
  buf[14] = vscpEspNowEvent.nickname & 0xff;
  // vscp_class
  buf[15] = vscpEspNowEvent.vscp_class;
  // vscp_type
  buf[16] = vscpEspNowEvent.vscp_type;
  // Payload data
  for ( uint8_t i=0; i<vscpEspNowEvent.len; i++) {
    buf[17 + i] = vscpEspNowEvent.payload[i];
  }
  // CRC
  vscpEspNowEvent.crc = esp_crc16_le(UINT16_MAX, (uint8_t const *)buf, 17 + vscpEspNowEvent.len);
  buf[17 + vscpEspNowEvent.len] = (vscpEspNowEvent.crc >> 8) & 0xff;
  buf[17 + vscpEspNowEvent.len + 1] = vscpEspNowEvent.crc & 0xff; */

  vscpEspNowEvent.ttl   = 7;              // Hops this event should survive
  vscpEspNowEvent.seq   = seq++;          // seq is increased for every frame sent
  //vscpEspNowEvent.magic = esp_random();   // 
  //vscpEspNowEvent.timestamp = esp_timer_get_time();
  //memcpy(vscpEspNowEvent.dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);
  vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

  /**< Wait for other tasks to be sent before send ESP-NOW data */
  // TickType_t wait_ticks;
  // if (xSemaphoreTake(g_send_lock, pdMS_TO_TICKS(wait_ticks)) != pdPASS) {
  //     //ESP_FREE(espnow_data);
  //     return ESP_ERR_TIMEOUT;
  // }


  // Start sending broadcast ESPNOW data.
  // vscp_espnow_send_param_t *send_param = (vscp_espnow_send_param_t *)pvParameter;
  vscpEspNowEvent.len = 0;
  if (esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MIN_SIZE + vscpEspNowEvent.len) != ESP_OK) {
    ESP_LOGE(TAG, "Send error");
    vscp_espnow_deinit(NULL);
    vTaskDelete(NULL);
  }

  while (xQueueReceive(s_vscp_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {

      case VSCP_ESPNOW_SEND_EVT: {

        vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        // is_broadcast = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG, "--> Send data to " MACSTR ", status1: %d", MAC2STR(send_cb->mac_addr), send_cb->status);

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
        if (CONFIG_ESPNOW_SEND_DELAY > 0) {
          vTaskDelay(CONFIG_ESPNOW_SEND_DELAY / portTICK_RATE_MS);
        }

        ESP_LOGI(TAG, "send data to " MACSTR "", MAC2STR(send_cb->mac_addr));

        memcpy(dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        // scp_espnow_heart_beat_prepare(send_param);

        vscpEspNowEvent.ttl   = 7;
        vscpEspNowEvent.seq   = seq++;
        //vscpEspNowEvent.magic = esp_random();
        vscpEventToEspNowBuf(buf, sizeof(buf), &vscpEspNowEvent);

        /* Send the next data after the previous data is sent. */
        if (esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MAX_SIZE) != ESP_OK) {
          ESP_LOGE(TAG, "Send error");
          vscp_espnow_deinit(NULL);
          vTaskDelete(NULL);
        }
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
  //vscp_espnow_send_param_t *send_param;

  // Create the event queue
  s_vscp_espnow_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(vscp_espnow_event_post_t));
  if (s_vscp_espnow_queue == NULL) {
    ESP_LOGE(TAG, "Create mutex fail");
    return ESP_FAIL;
  }

  // g_send_lock = xSemaphoreCreateMutex();
  // ESP_ERROR_RETURN(!g_send_lock, ESP_FAIL, "Create send semaphore mutex fail");

  // Initialize ESPNOW and register sending and receiving callback function.
  ESP_ERROR_CHECK(esp_now_init());
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
  ESP_ERROR_CHECK(esp_now_add_peer(peer));
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

  xTaskCreate(vscp_espnow_send_task, "vscp_espnow_send_task", 4048, NULL, 4, NULL);
  //xTaskCreate(vscp_espnow_recv_task, "vscp_espnow_recv_task", 4048, NULL, 4, NULL);

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

void security(void) 
{
  uint32_t start_time1 = xTaskGetTickCount();
  espnow_sec_result_t espnow_sec_result = {0};
  espnow_sec_responder_t *info_list = NULL;
  size_t num = 0;
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
  esp_err_t ret = espnow_sec_initiator_start(g_sec, pop_data, dest_addr_list, num, &espnow_sec_result);
  ESP_ERROR_GOTO(ret != ESP_OK, EXIT, "<%s> espnow_sec_initator_start", esp_err_to_name(ret));

  ESP_LOGI(TAG, "App key is sent to the device to complete, Spend time: %dms, Scan time: %dms",
          (xTaskGetTickCount() - start_time1) * portTICK_RATE_MS, 
          (start_time2 - start_time1) * portTICK_RATE_MS);
  ESP_LOGI(TAG, "Devices security completed, successed_num: %d, unfinished_num: %d", 
          espnow_sec_result.successed_num, espnow_sec_result.unfinished_num);

EXIT:
  ESP_FREE(dest_addr_list);
  espnow_sec_initator_result_free(&espnow_sec_result);
}


///////////////////////////////////////////////////////////////////////////////
// espnow_event_handler
//

static void 
espnow_event_handler(void* handler_args, esp_event_base_t base, int32_t id, void* event_data)
{
    if (base != ESP_EVENT_ESPNOW) {
        return;
    }

    switch (id) {

        // case ESP_EVENT_ESPNOW_CTRL_BIND: {

        //   ESP_LOGI(TAG,"Start!");

        //   espnow_ctrl_bind_info_t *info = (espnow_ctrl_bind_info_t *)event_data;
        //   ESP_LOGI(TAG, "bind, uuid: " MACSTR ", initiator_type: %d", MAC2STR(info->mac), info->initiator_attribute);
          
        //   //g_strip_handle->set_pixel(g_strip_handle, 0, 0x0, 255, 0x0);
        //   //ESP_ERROR_CHECK(g_strip_handle->refresh(g_strip_handle, 100));
        //   break;
        // }

        // case ESP_EVENT_ESPNOW_CTRL_UNBIND: {
        //   espnow_ctrl_bind_info_t *info = (espnow_ctrl_bind_info_t *)event_data;
        //   ESP_LOGI(TAG, "unbind, uuid: " MACSTR ", initiator_type: %d", MAC2STR(info->mac), info->initiator_attribute);
          
        //   //g_strip_handle->set_pixel(g_strip_handle, 0, 255, 0x0, 0x00);
        //   //ESP_ERROR_CHECK(g_strip_handle->refresh(g_strip_handle, 100));
        //   break;
        // }

        default:
        break;
    }
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

  vscp_wifi_init();
  vscp_espnow_init();
  espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  espnow_init(&espnow_config);

  g_sec = ESP_MALLOC(sizeof(espnow_sec_t));
  espnow_sec_init(g_sec);

  esp_event_handler_register(ESP_EVENT_ESPNOW, ESP_EVENT_ANY_ID, espnow_event_handler, NULL);

  button_config_t button_config = {
    .type = BUTTON_TYPE_GPIO,
    .gpio_button_config = {
        .gpio_num = BOOT_KEY_GPIIO,
        .active_level = 0,
    },
  };

  button_handle_t button_handle = iot_button_create(&button_config);
  iot_button_register_cb(button_handle, BUTTON_SINGLE_CLICK, initiator_send_press_cb, NULL);
  iot_button_register_cb(button_handle, BUTTON_DOUBLE_CLICK, initiator_bind_press_cb, NULL);
  iot_button_register_cb(button_handle, BUTTON_LONG_PRESS_START, initiator_unbind_press_cb, NULL);
}
