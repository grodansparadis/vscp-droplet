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
  static int cnt = 0;

  vTaskDelay(5000 / portTICK_PERIOD_MS);
  ESP_LOGI(TAG, "Start sending broadcast data");

  // Start sending broadcast ESPNOW data.
  espnow_send_param_t *send_param = (espnow_send_param_t *) pvParameter;
  if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
    ESP_LOGE(TAG, "Send error");
    espnow_deinit();
    vTaskDelete(NULL);
  }

  ESP_LOGI(TAG, "Waiting for broadcast response");

  while (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

    switch (evt.id) {

      case ESPNOW_SEND_CB: {
        espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
        is_broadcast                    = IS_BROADCAST_ADDR(send_cb->mac_addr);

        ESP_LOGD(TAG,
                 "Send frame %d to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00, status1: %d",
                 cnt++,
                 MAC2STR(send_cb->mac_addr),
                 send_cb->status);

        if (is_broadcast && (send_param->broadcast == false)) {
          break;
        }

        if (!is_broadcast) {
          // send_param->count--;
          if (send_param->count == 0) {
            ESP_LOGI(TAG, "Send done");
            espnow_deinit();
            vTaskDelete(NULL);
          }
        }

        /* Delay a while before sending the next data. */
        if (send_param->delay > 0) {
          vTaskDelay(send_param->delay / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "send frame %d to ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", cnt++, MAC2STR(send_cb->mac_addr));

        memcpy(send_param->dest_mac, send_cb->mac_addr, ESP_NOW_ETH_ALEN);
        espnow_data_prepare(send_param);

        // Send the next data after the previous data is sent.
        if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
          ESP_LOGE(TAG, "Send error");
          espnow_deinit();
          vTaskDelete(NULL);
        }
        break;
      }

      case ESPNOW_RECV_CB: {

        ESP_LOGE(TAG, "ESPNOW_RECV_CB");

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
              espnow_deinit();
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
              ESP_LOGI(TAG, "send frame to %d ff:ff:ff:ff:ff:fe:" MACSTR ":00:00", cnt++, MAC2STR(recv_cb->mac_addr));

              /* Start sending unicast ESPNOW data. */
              memcpy(send_param->dest_mac, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
              espnow_data_prepare(send_param);
              if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
                ESP_LOGE(TAG, "Send error");
                espnow_deinit();
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


static void example_espnow_task(void *pvParameter)
{
    example_espnow_event_t evt;
    uint8_t recv_state = 0;
    uint16_t recv_seq = 0;
    int recv_magic = 0;
    int ret;

    while (xQueueReceive(s_example_espnow_queue, &evt, portMAX_DELAY) == pdTRUE) {

        ESP_LOGI(TAG, "Waiting for events...");

        switch (evt.id) {
                        
            case EXAMPLE_ESPNOW_RECV_CB:
            {
                example_espnow_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

                ret = example_espnow_data_parse(recv_cb->data, recv_cb->data_len, &recv_state, &recv_seq, &recv_magic);
                free(recv_cb->data);
                
                if (1 /*ret == EXAMPLE_ESPNOW_DATA_BROADCAST*/) {

                    ESP_LOGI(TAG, "Receive %dth broadcast data from: "MACSTR", len: %d", recv_seq, MAC2STR(recv_cb->mac_addr), recv_cb->data_len);

                    /* If MAC address does not exist in peer list, add it to peer list. */
                    // if (esp_now_is_peer_exist(recv_cb->mac_addr) == false) {
                    //     esp_now_peer_info_t *peer = malloc(sizeof(esp_now_peer_info_t));
                    //     if (peer == NULL) {
                    //         ESP_LOGE(TAG, "Malloc peer information fail");
                    //         example_espnow_deinit();
                    //         vTaskDelete(NULL);
                    //     }
                    //     memset(peer, 0, sizeof(esp_now_peer_info_t));
                    //     peer->channel = CONFIG_ESPNOW_CHANNEL;
                    //     peer->ifidx = ESPNOW_WIFI_IF;
                    //     peer->encrypt = true;
                    //     memcpy(peer->lmk, CONFIG_ESPNOW_LMK, ESP_NOW_KEY_LEN);
                    //     memcpy(peer->peer_addr, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
                    //     ESP_ERROR_CHECK( esp_now_add_peer(peer) );
                    //     free(peer);
                    // }

                    /* If receive broadcast ESPNOW data which indicates that the other device has received
                     * broadcast ESPNOW data and the local magic number is bigger than that in the received
                     * broadcast ESPNOW data, stop sending broadcast ESPNOW data and start sending unicast
                     * ESPNOW data.
                     */
                    if (recv_state == 1) {
                        /* The device which has the bigger magic number sends ESPNOW data, the other one
                         * receives ESPNOW data.
                         */
                        // if (send_param->unicast == false && send_param->magic >= recv_magic) {
                    	  //   ESP_LOGI(TAG, "Start sending unicast data");
                    	  //   ESP_LOGI(TAG, "send data to "MACSTR"", MAC2STR(recv_cb->mac_addr));

                    	  //   /* Start sending unicast ESPNOW data. */
                        //     memcpy(send_param->dest_mac, recv_cb->mac_addr, ESP_NOW_ETH_ALEN);
                        //     example_espnow_data_prepare(send_param);
                        //     if (esp_now_send(send_param->dest_mac, send_param->buffer, send_param->len) != ESP_OK) {
                        //         ESP_LOGE(TAG, "Send error");
                        //         example_espnow_deinit(send_param);
                        //         vTaskDelete(NULL);
                        //     }
                        //     else {
                        //         //send_param->broadcast = false;
                        //         //send_param->unicast = true;
                        //     }
                        // }
                    }
                }
                else if (ret == EXAMPLE_ESPNOW_DATA_UNICAST) {
                    ESP_LOGI(TAG, "Receive %dth unicast data from: "MACSTR", len: %d", recv_seq, MAC2STR(recv_cb->mac_addr), recv_cb->data_len);

                    /* If receive unicast ESPNOW data, also stop sending broadcast ESPNOW data. */
                    //send_param->broadcast = false;
                }
                else {
                    ESP_LOGI(TAG, "Receive error data from: "MACSTR"", MAC2STR(recv_cb->mac_addr));
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
// vscp_wifi_init
//
// WiFi should start before using espnow
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
// ESPNOW sending or receiving callback function is called in WiFi task.
// Users should not do lengthy operations from this task. Instead, post
// necessary data to a queue and handle it from a lower priority task.
//

static void
vscp_espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
  vscp_espnow_event_post_t evt;
  vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;

  ESP_LOGI(TAG, "vscp_espnow_send_cb ");

  if (mac_addr == NULL) {
    ESP_LOGE(TAG, "Send cb arg error");
    return;
  }

  evt.id = VSCP_ESPNOW_SEND_EVT;
  memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  send_cb->status = status;
  // Put status on event queue
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Add to event queue failed");
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

  ESP_LOGI(TAG, "                         --------> espnow-x recv cb");

  if (mac_addr == NULL || data == NULL || len <= 0) {
    ESP_LOGE(TAG, "Receive cb arg error");
    return;
  }

  evt.id = VSCP_ESPNOW_RECV_EVT;
  memcpy(recv_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
  memcpy(recv_cb->buf, data, len);
  recv_cb->len = len;
  // Put message + status on event queue
  if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
    ESP_LOGW(TAG, "Send receive queue fail");
  }
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
  // pvscpEspNowEvent->ttl = 7;
  //  pvscpEspNowEvent->seq = seq++;
  // pvscpEspNowEvent->magic = esp_random();
  //  pvscpEspNowEvent.crc = 0;
  //   https://grodansparadis.github.io/vscp-doc-spec/#/./class1.information?id=type9
  pvscpEspNowEvent->head = 0;
  // pvscpEspNowEvent->timestamp  = 0;
  pvscpEspNowEvent->nickname   = 0;
  pvscpEspNowEvent->vscp_class = VSCP_CLASS1_INFORMATION;
  pvscpEspNowEvent->vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
  pvscpEspNowEvent->len        = 3;
  pvscpEspNowEvent->data[0]    = 0;
  pvscpEspNowEvent->data[1]    = 0xff; // All zones
  pvscpEspNowEvent->data[2]    = 0xff; // All subzones

  // seq
  // buf[0] = (pvscpEspNowEvent->seq >> 8) & 0xff;
  // buf[1] = pvscpEspNowEvent->seq & 0xff;
  // magic
  // buf[2] = (pvscpEspNowEvent->magic >> 24) & 0xff;
  // buf[3] = (pvscpEspNowEvent->magic >> 16) & 0xff;
  // buf[4] = (pvscpEspNowEvent->magic >> 8) & 0xff;
  // buf[5] = pvscpEspNowEvent->magic & 0xff;
  // ttl
  // buf[6] = pvscpEspNowEvent->ttl;
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

  // crc        - 
  //crc = esp_crc16_le(UINT16_MAX, (uint8_t const *)buf, VSCP_ESPNOW_PACKET_MIN_SIZE - 2 + pex->sizeData);
  //buf[VSCP_ESPNOW_PACKET_MIN_SIZE - 2] = (crc >> 8) & 0xff;
  //buf[VSCP_ESPNOW_PACKET_MIN_SIZE + 1 - 2] = crc & 0xff;


  ///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_send_cb
//
// ESPNOW sending or receiving callback function is called in WiFi task.
// Users should not do lengthy operations from this task. Instead, post
// necessary data to a queue and handle it from a lower priority task.
//

// static void
// vscp_espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
// {
//   vscp_espnow_event_post_t evt;
//   vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;

//   //ESP_LOGI(TAG, "---------------------> vscp_espnow_send_cb ");

//   if (mac_addr == NULL) {
//     ESP_LOGE(TAG, "Send cb arg error");
//     return;
//   }

//   g_send_state.state = VSCP_SEND_STATE_SEND_CONFIRM;
//   g_send_state.timestamp = esp_timer_get_time();

//   evt.id = VSCP_ESPNOW_SEND_EVT;
//   memcpy(send_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
//   send_cb->status = status;
//   //Put status on event queue
//   if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
//     ESP_LOGW(TAG, "Add to event queue failed");
//   }
// }

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_recv_cb
//

// static void
// vscp_espnow_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
// {

//   vscp_espnow_event_post_t evt;
//   vscp_espnow_event_recv_cb_t *recv_cb = &evt.info.recv_cb;

//   //ESP_LOGI(TAG, "                         --------> espnow-x recv cb");

//   if (mac_addr == NULL || data == NULL || len <= 0) {
//     ESP_LOGE(TAG, "Receive cb arg error");
//     return;
//   }

//   evt.id = VSCP_ESPNOW_RECV_EVT;
//   memcpy(recv_cb->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);
//   memcpy(recv_cb->buf, data, len);
//   recv_cb->len = len;
//   // Put message + status on event queue
//   if (xQueueSend(s_vscp_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE) {
//     ESP_LOGW(TAG, "Send receive queue fail");
//   }
// }

///////////////////////////////////////////////////////////////////////////////
// vscp_work_task
//

// static void
// vscp_work_task(void *pvParameter)
// {
//   vscp_espnow_event_post_t evt;
//   esp_err_t ret;
//   uint8_t dest_mac[ESP_NOW_ETH_ALEN]; // MAC address of destination device.
//   vscp_espnow_event_t vscpEspNowEvent;
//   int cnt = 0;

//   for (;;) { 

//     ret = xQueueReceive(s_vscp_espnow_queue, &evt, (1000 / portTICK_RATE_MS));

//     esp_task_wdt_reset();
//     //ESP_LOGI(TAG,"HoHo");
//     if (ret != pdTRUE) continue;

//     //ESP_LOGI(TAG,"==============================> Event: %d", evt.id);

//     switch (evt.id) {

//       case VSCP_ESPNOW_SEND_EVT: {

//         g_send_state.state = VSCP_SEND_STATE_NONE;
//         g_send_state.timestamp = esp_timer_get_time();

//         vscp_espnow_event_send_cb_t *send_cb = &evt.info.send_cb;
//         bool is_broadcast = IS_BROADCAST_ADDR(send_cb->mac_addr);

//         ESP_LOGI(TAG,
//                  "-->> %d to " MACSTR ", status: %d",
//                  cnt++,
//                  MAC2STR(send_cb->mac_addr),
//                  send_cb->status);

//         break;
//       }

//       case VSCP_ESPNOW_RECV_EVT: {
//         ESP_LOGI(TAG, "Receive: %d", evt.id);
//         break;
//       } // receive

//       default:
//         ESP_LOGE(TAG, "Callback type error: %d", evt.id);
//         break;
//     }
//   }

//   ESP_LOGE(TAG, "The end");
// }
