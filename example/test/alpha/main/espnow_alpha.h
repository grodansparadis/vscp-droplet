/* ESPNOW Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef ESPNOW_vscp_H
#define ESPNOW_vscp_H

/* ESPNOW can work in both station and softap mode. It is configured in menuconfig. */
#if CONFIG_ESPNOW_WIFI_MODE_STATION
#define ESPNOW_WIFI_MODE WIFI_MODE_STA
#define ESPNOW_WIFI_IF   ESP_IF_WIFI_STA
#else
#define ESPNOW_WIFI_MODE WIFI_MODE_AP
#define ESPNOW_WIFI_IF   ESP_IF_WIFI_AP
#endif

#define ESPNOW_QUEUE_SIZE           60

#define IS_BROADCAST_ADDR(addr) (memcmp(addr, s_vscp_broadcast_mac, ESP_NOW_ETH_ALEN) == 0)

/**!
 * Context object 
 */
typedef struct {
  uint16_t seq;
} vscp_espnow_context_t;


typedef enum {
  VSCP_ESPNOW_SEND_EVT,
  VSCP_ESPNOW_RECV_EVT,
} vscp_espnow_event_id_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];         // Destination address
  esp_now_send_status_t status;               // Status of send
} vscp_espnow_event_send_cb_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];         // Originating address
  uint8_t buf[VSCP_ESPNOW_PACKET_MAX_SIZE];   // Incoming frame
  uint8_t len;                                // Real length of incoming frame
} vscp_espnow_event_recv_cb_t;

typedef union {
  vscp_espnow_event_send_cb_t send_cb;
  vscp_espnow_event_recv_cb_t recv_cb;
} vscp_espnow_event_info_t;

/* When ESPNOW sending or receiving callback function is called, post event to ESPNOW task. */
typedef struct {
  vscp_espnow_event_id_t id;
  vscp_espnow_event_info_t info;
} vscp_espnow_event_post_t;

enum {
  VSCP_ESPNOW_DATA_BROADCAST,
  VSCP_ESPNOW_DATA_UNICAST,
  VSCP_ESPNOW_DATA_MAX,
};

/* Parameters of sending ESPNOW data. */
// typedef struct {
//   //int len;                              // Length of ESPNOW data to be sent, unit: byte.
//   //uint8_t *buffer;                      // Buffer pointing to ESPNOW data.
//   uint8_t dest_mac[ESP_NOW_ETH_ALEN];   // MAC address of destination device.
// } vscp_espnow_send_param_t;

#endif
