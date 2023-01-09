/*
  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

  VSCP Alpha Droplet node

  MQTT SSL Client

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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_system.h"
#include "esp_partition.h"
#include "spi_flash_mmap.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "main.h"

#include "esp_log.h"
#include "mqtt_client.h"
#include "esp_tls.h"
#include "esp_ota_ops.h"
#include <sys/param.h>

#include <vscp.h>

#include "mqtt.h"

static const char *TAG = "ALPHA MQTT";

static esp_mqtt_client_handle_t g_mqtt_client;

// #if CONFIG_BROKER_CERTIFICATE_OVERRIDDEN == 1
// static const uint8_t mqtt_eclipseprojects_io_pem_start[] =
//   "-----BEGIN CERTIFICATE-----\n" CONFIG_BROKER_CERTIFICATE_OVERRIDE "\n-----END CERTIFICATE-----";
// #else
extern const uint8_t mqtt_eclipse_io_pem_start[] asm("_binary_mqtt_eclipse_io_pem_start");
// #endif
extern const uint8_t mqtt_eclipse_io_pem_end[] asm("_binary_mqtt_eclipse_io_pem_end");

///////////////////////////////////////////////////////////////////////////////
// send_binary
//
//
// Note: this function is for testing purposes only publishing part of the active partition
//       (to be checked against the original binary)
//

// static void
// send_binary(esp_mqtt_client_handle_t client)
// {
//   spi_flash_mmap_handle_t out_handle;
//   const void *binary_address;
//   const esp_partition_t *partition = esp_ota_get_running_partition();
//   esp_partition_mmap(partition, 0, partition->size, SPI_FLASH_MMAP_DATA, &binary_address, &out_handle);
//   // sending only the configured portion of the partition (if it's less than the partition size)
//   int binary_size = MIN(4096, partition->size);
//   int msg_id      = esp_mqtt_client_publish(client, "/topic/binary", binary_address, binary_size, 0, 0);
//   ESP_LOGI(TAG, "binary sent with msg_id=%d", msg_id);
// }

///////////////////////////////////////////////////////////////////////////////
// mqtt_send_vscp_event
//

void
mqtt_send_vscp_event(const char *topic, vscpEventEx *pex)
{
  int msg_id      = esp_mqtt_client_publish(g_mqtt_client, "/topic/binary", "hello", 5, 0, 0);
  ESP_LOGI(TAG, "binary sent with msg_id=%d", msg_id);
}

///////////////////////////////////////////////////////////////////////////////
// mqtt_event_handler
//
/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
 */
static void
mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
  ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, (int) event_id);
  esp_mqtt_event_handle_t event   = event_data;
  esp_mqtt_client_handle_t client = event->client;
  int msg_id;
  switch ((esp_mqtt_event_id_t) event_id) {
    case MQTT_EVENT_CONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
      msg_id =
        esp_mqtt_client_subscribe(client,
                                  /*"/topic/qos0"*/ "vscp/FF:FF:FF:FF:FF:FF:FF:FE:B8:27:EB:CF:3A:15:00:01/10/6/1/0",
                                  0);
      ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

      msg_id = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
      ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

      msg_id = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
      ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);
      break;

    case MQTT_EVENT_DISCONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
      break;

    case MQTT_EVENT_SUBSCRIBED:
      ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
      msg_id = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
      ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
      break;

    case MQTT_EVENT_UNSUBSCRIBED:
      ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
      break;

    case MQTT_EVENT_PUBLISHED:
      ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
      break;

    case MQTT_EVENT_DATA:
      ESP_LOGI(TAG, "MQTT_EVENT_DATA");
      printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
      printf("DATA=%.*s\r\n", event->data_len, event->data);
      if (strncmp(event->data, "send binary please", event->data_len) == 0) {
        ESP_LOGI(TAG, "Sending the binary");
        //send_binary(client);
      }
      break;

    case MQTT_EVENT_ERROR:
      ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
      if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
        ESP_LOGI(TAG, "Last error code reported from esp-tls: 0x%x", event->error_handle->esp_tls_last_esp_err);
        ESP_LOGI(TAG, "Last tls stack error number: 0x%x", event->error_handle->esp_tls_stack_err);
        ESP_LOGI(TAG,
                 "Last captured errno : %d (%s)",
                 event->error_handle->esp_transport_sock_errno,
                 strerror(event->error_handle->esp_transport_sock_errno));
      }
      else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
        ESP_LOGI(TAG, "Connection refused error: 0x%x", event->error_handle->connect_return_code);
      }
      else {
        ESP_LOGW(TAG, "Unknown error type: 0x%x", event->error_handle->error_type);
      }
      break;

    default:
      ESP_LOGI(TAG, "Other event id:%d", event->event_id);
      break;
  }
}

///////////////////////////////////////////////////////////////////////////////
// mqtt_start
//

void
mqtt_start(void)
{
  esp_log_level_set("*", ESP_LOG_INFO);
  esp_log_level_set("esp-tls", ESP_LOG_VERBOSE);
  esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
  esp_log_level_set("MQTT_EXAMPLE", ESP_LOG_VERBOSE);
  esp_log_level_set("TRANSPORT_BASE", ESP_LOG_VERBOSE);
  esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
  esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);

  // test.mosquitto.org
  const esp_mqtt_client_config_t mqtt_cfg = {
    .broker                              = { .address.uri = "mqtt://192.168.1.7:1883", .address.port = 1883,
                                             /*.verification.certificate = (const char *) mqtt_eclipse_io_pem_start*/ },
    .credentials.username                = "vscp",
    .credentials.client_id               = "ESP32 Alpha",
    .credentials.authentication.password = "secret",
  };

  ESP_LOGI(TAG, "[APP] Free memory: %lu bytes", esp_get_free_heap_size());
  g_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
  // The last argument may be used to pass data to the event handler, in this example mqtt_event_handler
  esp_mqtt_client_register_event(g_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
  esp_mqtt_client_start(g_mqtt_client);
}

///////////////////////////////////////////////////////////////////////////////
// mqtt_stop
//

void
mqtt_stop(void)
{
  esp_mqtt_client_stop(g_mqtt_client);
}
