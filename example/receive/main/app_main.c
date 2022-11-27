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
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "nvs_flash.h"
#include <assert.h>
#include <esp_utils.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "esp_task_wdt.h"

#include <espnow.h>
#include <espnow_ctrl.h>
#include <espnow_security.h>

#include "app_main.h"

#define ESPNOW_MAXDELAY 512

static const char *TAG = "espnow_recv";


static void
example_espnow_deinit(void);

///////////////////////////////////////////////////////////////////////////////
// example_wifi_init
//
// WiFi should start before using ESPNOW
//

static void
example_wifi_init(void)
{
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
  ESP_ERROR_CHECK(esp_wifi_start());

  esp_wifi_set_channel(11, 0);

#if CONFIG_ESPNOW_ENABLE_LONG_RANGE
  ESP_ERROR_CHECK(esp_wifi_set_protocol(ESPNOW_WIFI_IF,
                                        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
#endif
}

///////////////////////////////////////////////////////////////////////////////
// example_receive_task
//

static void
example_receive_task(void *pvParameter)
{
  esp_err_t ret;
  char *data                    = ESP_MALLOC(ESPNOW_DATA_LEN);
  size_t size                   = ESPNOW_DATA_LEN;
  uint8_t addr[ESPNOW_ADDR_LEN] = { 0 };
  wifi_pkt_rx_ctrl_t rx_ctrl    = { 0 };

  ESP_LOGI(TAG, "Receive task started --->");

  // vTaskDelay(4000 / portTICK_PERIOD_MS);

  for (;;) {
    esp_task_wdt_reset();
    ret = espnow_recv(ESPNOW_TYPE_DATA, addr, data, &size, &rx_ctrl, 1000 / portTICK_RATE_MS); // 
    ESP_ERROR_CONTINUE(ret != ESP_OK, MACSTR ",  error: <%s>", MAC2STR(addr), esp_err_to_name(ret));
    ESP_LOGI(TAG, "Data from " MACSTR " Data size=%d", MAC2STR(addr), size);
  }

  ESP_LOGW(TAG, "Receive task exit %d", ret);
  ESP_FREE(data);
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// example_espnow_init
//

static esp_err_t
example_espnow_init(void)
{
  espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  espnow_config.qsize.data      = 64;
  espnow_init(&espnow_config);

  ESP_LOGI(TAG, "Configured");

  // Set primary master key.
  ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

  //xTaskCreate(example_receive_task, "example_receive_task", 8048, NULL, 4, NULL);

  return ESP_OK;
}

static void
example_espnow_deinit(void)
{
  esp_now_deinit();
}

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
  example_espnow_init();
  ESP_LOGI(TAG, "Running");

  char *data                    = ESP_MALLOC(ESPNOW_DATA_LEN);
  size_t size                   = ESPNOW_DATA_LEN;
  uint8_t addr[ESPNOW_ADDR_LEN] = { 0 };
  wifi_pkt_rx_ctrl_t rx_ctrl    = { 0 };

  ESP_LOGI(TAG, "Receive task started --->");

  for (;;) {
    esp_task_wdt_reset();
    ret = espnow_recv(ESPNOW_TYPE_DATA, addr, data, &size, &rx_ctrl, portMAX_DELAY); // 
    ESP_ERROR_CONTINUE(ret != ESP_OK, MACSTR ", error: <%s>", MAC2STR(addr), esp_err_to_name(ret));
    ESP_LOGI(TAG, "Data from " MACSTR " Data size=%d", MAC2STR(addr), size);
  }

  ESP_LOGW(TAG, "Receive task exit %d", ret);
  ESP_FREE(data);
  vTaskDelete(NULL);

  example_espnow_deinit();
}
