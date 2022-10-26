/*
  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

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

#ifndef __VSCP_WCANG_H__
#define __VSCP_WCANG_H__

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include <vscp.h>

#define CONNECTED_LED_GPIO_NUM		2
#define ACTIVE_LED_GPIO_NUM			  3
#define GPIO_OUTPUT_PIN_SEL       ((1ULL<<CONNECTED_LED_GPIO_NUM) | (1ULL<<ACTIVE_LED_GPIO_NUM) )

#define DEV_BUFFER_LENGTH	        64

typedef enum
{	
  CH_LINK = 0,    // tcp/ip link protocol
  CH_CAN,         // CAN
  CH_WS,          // websocket I & II
  CH_UDP,         // UDP 
  CH_MULTI,       // Multicast
  CH_MQTT,        // MQTT
	CH_BLE,         // BLE
	CH_UART         // UART  
} dev_channel_t;

// All transports use this structure for state 

typedef struct {
  union {
    struct {
      uint32_t active: 1;       /**< Transport active if set to one */
      uint32_t open: 1;         /**< Transport open if set to one */
      uint32_t reserved: 30;    /**< Reserved bits */
    };
    uint32_t flags;             /**< Don't use */ 
  };
  QueueHandle_t msg_queue;      /**< Message queue for transport */
  uint32_t overruns;            /**< Queue overrun counter */

} transport_t;



/*!
  Default values stored in non volatile memory
  on start up.
*/

#define DEFAULT_GUID              ""      // Empty constructs from MAC, "-" all nills, "xx:yy:..." set GUID

// BLE
#define DEFAULT_BLE_ENABLE        true
#define DEFAULT_ADVERTISE_ENABLE  true

// Web server
#define DEFAULT_WEB_ENABLE        true
#define DEFAULT_WEB_PORT          80

// MQTT
#define DEAFULT_MQTT_ENABLE       true   // Enabled

// tcp/ip interface
#define DEFAULT_TCPIP_ENABLE      true   // Enabled
#define DEFAULT_TCPIPPORT         9598
#define DEFAULT_TCPIP_USER        "vscp"
#define DEFAULT_TCPIP_PASSWORD    "secret"
#define DEFAULT_TCPIP_VER         4       // Ipv6 = 6 or Ipv4 = 4
#define TCPSRV_WELCOME_MSG        "Welcome to the Wireless CAN4VSCP Gateway\r\n"                    \
                                  "Copyright (C) 2000-2022 Grodans Paradis AB\r\n"                  \
                                  "https://www.grodansparadis.com\r\n"                              \
                                  "+OK\r\n"

// UDP interface
#define DEFAULT_UDP_ENABLE        true   // Enabled
#define DEFAULT_UDP_RX_ENABLE     true   // Enable UDP server
#define DEFAULT_UDP_TX_ENABLE     true   // Enable UDP client

// Multicast
#define DEFAULT_MULTICAST_ENABLE  false   // Disable

// MQTT broker
#define DEFAULT_MQTT_ENABLE       true
#define DEFAULT_MQTT_ADDRESS      "192.168.1.7"
#define DEFAULT_MQTT_PORT         1883
#define DEFAULT_MQTT_USER         "vscp"
#define DEFAULT_MQTT_PASSWORD     "secret"
#define DEFAULT_TOPIC_SUBSCRIBE   "VSCP"
#define DEFAULT_TOPIC_PUBLISH     "VSCP/PUB"


// ----------------------------------------------------------------------------


/* ESPNOW can work in both station and softap mode. It is configured in menuconfig. */
#if CONFIG_ESPNOW_WIFI_MODE_STATION
#define ESPNOW_WIFI_MODE WIFI_MODE_STA
#define ESPNOW_WIFI_IF   ESP_IF_WIFI_STA
#else
#define ESPNOW_WIFI_MODE WIFI_MODE_AP
#define ESPNOW_WIFI_IF   ESP_IF_WIFI_AP
#endif

#define ESPNOW_QUEUE_SIZE           6

#define IS_BROADCAST_ADDR(addr) (memcmp(addr, s_broadcast_mac, ESP_NOW_ETH_ALEN) == 0)

typedef enum {
  ESPNOW_SEND_CB,
  ESPNOW_RECV_CB,
} espnow_event_id_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];
  esp_now_send_status_t status;
} espnow_event_send_cb_t;

typedef struct {
  uint8_t mac_addr[ESP_NOW_ETH_ALEN];
  uint8_t *data;
  int data_len;
} espnow_event_recv_cb_t;

typedef union {
  espnow_event_send_cb_t send_cb;
  espnow_event_recv_cb_t recv_cb;
} espnow_event_info_t;

/* When ESPNOW sending or receiving callback function is called, post event to ESPNOW task. */
typedef struct {
  espnow_event_id_t id;
  espnow_event_info_t info;
} espnow_event_t;

enum {
  ESPNOW_DATA_BROADCAST,
  ESPNOW_DATA_UNICAST,
  ESPNOW_DATA_MAX,
};

/* User defined field of ESPNOW data in this example. */
typedef struct {
    uint8_t type;                         //Broadcast or unicast ESPNOW data.
    uint8_t state;                        //Indicate that if has received broadcast ESPNOW data or not.
    uint16_t seq_num;                     //Sequence number of ESPNOW data.
    uint16_t crc;                         //CRC16 value of ESPNOW data.
    uint32_t magic;                       //Magic number which is used to determine which device to send unicast ESPNOW data.
    uint8_t payload[0];                   //Real payload of ESPNOW data.
} __attribute__((packed)) espnow_data_t;

/* Parameters of sending ESPNOW data. */
typedef struct {
    bool unicast;                         //Send unicast ESPNOW data.
    bool broadcast;                       //Send broadcast ESPNOW data.
    uint8_t state;                        //Indicate that if has received broadcast ESPNOW data or not.
    uint32_t magic;                       //Magic number which is used to determine which device to send unicast ESPNOW data.
    uint16_t count;                       //Total count of unicast ESPNOW data to be sent.
    uint16_t delay;                       //Delay between sending two ESPNOW data, unit: ms.
    int len;                              //Length of ESPNOW data to be sent, unit: byte.
    uint8_t *buffer;                      //Buffer pointing to ESPNOW data.
    uint8_t dest_mac[ESP_NOW_ETH_ALEN];   //MAC address of destination device.
} espnow_send_param_t;


// ----------------------------------------------------------------------------


/**
 * @brief Read preocessor on chip temperature
 * @return Temperature as floating point value
 */
float read_onboard_temperature(void);


/**
 * @fn getMilliSeconds
 * @brief Get system time in Milliseconds 
 * 
 * @return Systemtime in milliseconds
 */
uint32_t getMilliSeconds(void);

/**
 * @fn validate_user
 * @brief Validate user
 * 
 * @param user Username to check
 * @param password Password to check
 * @return True if user is valid, False if not.
 */
bool
validate_user(const char *user, const char *password);

#endif