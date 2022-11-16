///////////////////////////////////////////////////////////////////////////////
// wifi_init
//
// WiFi should start before using ESPNOW
//

// static void
// wifi_init(void)
// {
//   // ESP_ERROR_CHECK(esp_netif_init());
//   // ESP_ERROR_CHECK(esp_event_loop_create_default());
//   // wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//   // ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
//   // ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

//   ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
//   ESP_ERROR_CHECK(esp_wifi_start());

//   EventBits_t uxBits =
//     xEventGroupWaitBits(wifi_event_group,           // The event group being tested.
//                         WIFI_CONNECTED_EVENT,       // The bits within the event group to wait for.
//                         pdFALSE,                    // BIT_0 & BIT_4 should be cleared before returning.
//                         pdFALSE,                    // Don't wait for both bits, either bit will do.
//                         1000 / portTICK_PERIOD_MS); // Wait a maximum of 100ms for either bit to be set.

//   if (uxBits & WIFI_CONNECTED_EVENT) {
//     ESP_LOGI(TAG, "CONNECTED");
//     // vTaskDelay(5000 / portTICK_PERIOD_MS);
//     // ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
//     // ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE));
//     // ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
//   }

// #if CONFIG_ESPNOW_ENABLE_LONG_RANGE
//   ESP_ERROR_CHECK(esp_wifi_set_protocol(ESPNOW_WIFI_IF,
//                                         WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
// #endif
// }

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

  //vscpEspNowEvent.ttl   = 7;              // Hops this event should survive
  //vscpEspNowEvent.seq   = seq++;          // seq is increased for every frame sent
  //vscpEspNowEvent.magic = esp_random();   // 
  //vscpEspNowEvent.timestamp = esp_timer_get_time();
  //memcpy(vscpEspNowEvent.dest_mac, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN);

  // ///////////////////////////////////////////////////////////////////////////////
// // espnow_init
// //

// static esp_err_t
// espnow_init(void)
// {
//   espnow_send_param_t *send_param;

//   s_espnow_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(espnow_event_t));
//   if (s_espnow_queue == NULL) {
//     ESP_LOGE(TAG, "Create mutex fail");
//     return ESP_FAIL;
//   }

//   // Initialize ESPNOW and register sending and receiving callback function. 
//   ESP_ERROR_CHECK(esp_now_init());
//   ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));
//   ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
// #if CONFIG_ESP_WIFI_STA_DISCONNECTED_PM_ENABLE
//   ESP_ERROR_CHECK(esp_now_set_wake_window(65535));
// #endif
//   // Set primary master key. 
//   ESP_ERROR_CHECK(esp_now_set_pmk((uint8_t *) CONFIG_ESPNOW_PMK));

//   // Add broadcast peer information to peer list. 
//   esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
//   if (peer == NULL) {
//     ESP_LOGE(TAG, "Malloc peer information fail");
//     vSemaphoreDelete(s_espnow_queue);
//     esp_now_deinit();
//     return ESP_FAIL;
//   }

//   // Get wifi channel
//   uint8_t primary_channel;
//   wifi_second_chan_t secondary_channel;
//   esp_wifi_get_channel(&primary_channel, &secondary_channel);

//   memset(peer, 0, sizeof(esp_now_peer_info_t));
//   peer->channel = primary_channel; // CONFIG_ESPNOW_CHANNEL;
//   peer->ifidx   = ESPNOW_WIFI_IF;
//   peer->encrypt = false;
//   memcpy(peer->peer_addr, s_broadcast_mac, ESP_NOW_ETH_ALEN);
//   ESP_ERROR_CHECK(esp_now_add_peer(peer));
//   free(peer);

//   // Initialize sending parameters. 
//   send_param = malloc(sizeof(espnow_send_param_t));
//   if (send_param == NULL) {
//     ESP_LOGE(TAG, "Malloc send parameter fail");
//     vSemaphoreDelete(s_espnow_queue);
//     esp_now_deinit();
//     return ESP_FAIL;
//   }
//   memset(send_param, 0, sizeof(espnow_send_param_t));
//   send_param->unicast   = false;
//   send_param->broadcast = true;
//   send_param->state     = 0;
//   send_param->magic     = esp_random();
//   send_param->count     = CONFIG_ESPNOW_SEND_COUNT;
//   send_param->delay     = CONFIG_ESPNOW_SEND_DELAY;
//   send_param->len       = CONFIG_ESPNOW_SEND_LEN;
//   send_param->buffer    = malloc(CONFIG_ESPNOW_SEND_LEN);
//   if (send_param->buffer == NULL) {
//     ESP_LOGE(TAG, "Malloc send buffer fail");
//     free(send_param);
//     vSemaphoreDelete(s_espnow_queue);
//     esp_now_deinit();
//     return ESP_FAIL;
//   }
//   memcpy(send_param->dest_mac, s_broadcast_mac, ESP_NOW_ETH_ALEN);
//   espnow_data_prepare(send_param);

//   xTaskCreate(espnow_task, "espnow_task", 2048, send_param, 4, NULL);

//   return ESP_OK;
// }

///////////////////////////////////////////////////////////////////////////////
// espnow_deinit
//

// static void
// espnow_deinit(espnow_send_param_t *send_param)
// {
//   free(send_param->buffer);
//   free(send_param);
//   vSemaphoreDelete(s_espnow_queue);
//   esp_now_deinit();
// }


/**< Wait for other tasks to be sent before send ESP-NOW data */
  // TickType_t wait_ticks;
  // if (xSemaphoreTake(g_send_lock, pdMS_TO_TICKS(wait_ticks)) != pdPASS) {
  //     //ESP_FREE(espnow_data);
  //     return ESP_ERR_TIMEOUT;
  // }


  // Start sending broadcast ESPNOW data.
  // vscp_espnow_send_param_t *send_param = (vscp_espnow_send_param_t *)pvParameter;
  vscpEspNowEvent.len = 0;
  // if ((ret = esp_now_send(dest_mac, buf, VSCP_ESPNOW_PACKET_MIN_SIZE + vscpEspNowEvent.len)) != ESP_OK) {
  //   ESP_LOGE(TAG, "vscp_espnow_send_task - Send error %d err=%d", vscpEspNowEvent.len, ret);
  //   vscp_espnow_deinit(NULL);
  //   vTaskDelete(NULL);
  // }


  ///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_data_parse
//
// Parse received ESPNOW data and try to build VSCP event.
//

int
vscp_espnow_data_parse(vscp_espnow_event_t *pvscpData, uint8_t *buf, uint8_t len)
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