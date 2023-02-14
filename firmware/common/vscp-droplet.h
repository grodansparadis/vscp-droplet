/**
 * @brief           VSCP droplet over esp-now code
 * @file            vscp_droplet.h
 * @author          Ake Hedman, The VSCP Project, www.vscp.org
 *
 *********************************************************************/

/* ******************************************************************************
 * VSCP (Very Simple Control Protocol)
 * http://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright © 2000-2023 Ake Hedman, the VSCP project <info@vscp.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *  This file is part of VSCP - Very Simple Control Protocol
 *  http://www.vscp.org
 *
 * ******************************************************************************
 */

#ifndef DROPLET_H
#define DROPLET_H

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <esp_wifi_types.h>

#include <vscp.h>

#ifdef __cplusplus
extern "C" {
#endif

// Security

#define DROPLET_KEY_LEN 32 // Secret key length (AES-128 use the first 16)
#define DROPLET_IV_LEN  16 // The initialization vector (nonce) length

/**
 * @brief Frame positions for data in the VSCP droplet frame
 */
#define DROPLET_POS_PKTID 0 // Frame id (1)
#define DROPLET_POS_TTL   1 // Time to live
// magic and crc form unique number that identify a frame
// in the frame cache. id/ttl is not part of crc as ttl can
// vary for the same frame (if forwarded)
#define DROPLET_POS_MAGIC 2 // Frame random number (2)

#define DROPLET_POS_DEST_ADDR 4 // Destination address for frame

// VSCP content
#define DROPLET_POS_HEAD     10 // VSCP head bytes (2)
#define DROPLET_POS_NICKNAME 12 // Node nickname (2)
#define DROPLET_POS_CLASS    14 // VSCP class (2)
#define DROPLET_POS_TYPE     16 // VSCP Type (2)
#define DROPLET_POS_SIZE     18 // Data size (needed because of encryption padding)
#define DROPLET_POS_DATA     19 // VSCP data (max 128 bytes)

#define DROPLET_MIN_FRAME DROPLET_POS_DATA // Number of bytes in minimum frame
#define DROPLET_MAX_DATA  128              // Max VSCP data (of possible 512 bytes) that a frame can hold
#define DROPLET_MAX_FRAME DROPLET_MIN_FRAME + DROPLET_MAX_DATA

typedef enum {
  DROPLET_ALPHA_NODE = 0,
  DROPLET_BETA_NODE,
  DROPLET_GAMMA_NODE,
} droplet_node_type_t;

/*
  The idel state is the normal state a node is in. This is where it does all it's
  work if it has been initialized.

  Alpha nodes can only be in the idle or one of the SRV states.
  Beta nodes can be both in one of the SRV states and in one of the CLIENT states and in idle.
  Gamma nodes can only be in CLIENT state and idle.
*/
typedef enum {
  DROPLET_STATE_IDLE,        // Normal state for all nodes, but may be uninitialized.
  DROPLET_STATE_CLIENT_INIT, // Initialization state for Beta/Gamma nodes.
  DROPLET_STATE_SRV_INIT1,   // Server initialization state 1 (Alpha/Beta nodes)  Waiting for heartbeat.
  DROPLET_STATE_SRV_INIT2,   // Server initialization state 2 (Alpha/Beta nodes). Waiting for new node on-line
  DROPLET_STATE_CLIENT_OTA,  // OTA state for all nodes being updated.
  DROPLET_STATE_SRV_OTA      // OTA state for Alpha/Beta/Gamma nodes that serve firmware.
} droplet_state_t;

/**
 * @brief Initialize the configuration of droplet
 */
typedef struct {
  droplet_node_type_t nodeType; // Alpha/Gamma/Beta
  uint8_t channel;              // Channel to use (zero is current)
  uint8_t ttl;                  // Default ttl
  bool bForwardEnable;          // Forward when packets are received
  bool bForwardSwitchChannel;   // Forward data packet with exchange channel
  uint8_t sizeQueue;            // Size of receive queue
  uint8_t nEncryption;          // 0=no encryption, 1=AES-128, 2=AES-192, 3=AES-256
  bool bFilterAdjacentChannel;  // Don't receive if from other channel
  int filterWeakSignal;         // Filter onm RSSI (zero is no rssi filtering)
  const uint8_t pmk[32];        // Primary master key (16 (EAS128)/24(AES192)/32(AES256))
  const uint8_t nodeGuid[16];   // GUID for node.
} droplet_config_t;

/*
  Structure that holds data for node that should
  be provisioned.
*/
typedef struct {
  uint8_t mac[6];                    // MAC address for node to provision
  uint8_t keyLocal[DROPLET_KEY_LEN]; // Local key for node
} droplet_provisioning_t;

/**
 * @brief   Droplet type data receive callback function
 *
 * @param[in]  src_addr  peer MAC address
 * @param[in]  data  received data
 * @param[in]  size  length of received data
 * @param[in]  rx_ctrl  received packet radio metadata header
 *
 * @return
 *    - ESP_OK
 *    - ESP_ERR_INVALID_ARG
 */
typedef esp_err_t (*type_handle_t)(uint8_t *src_addr, void *data, size_t size, wifi_pkt_rx_ctrl_t *rx_ctrl);

#define VSCP_HEART_BEAT_INTERVAL      30000 // Milliseconds between heartbeat events
#define VSCP_INIT_HEART_BEAT_INTERVAL 500   // Milliseconds between heartbeat probe events
#define VSCP_SET_KEY_INTERVAL         100   // Provisioning interval between set key events

// Control states for droplet provisioning
typedef enum { DROPLET_CTRL_INIT, DROPLET_CTRL_BOUND, DEOPLET_CTRL_MAX } droplet_ctrl_status_t;

/**
 * @brief The channel on which the device sends packets
 */
#define DROPLET_CHANNEL_CURRENT 0x0  // Only in the current channel
#define DROPLET_CHANNEL_ALL     0x0f // All supported channels

#define DROPLET_FORWARD_MAX_COUNT 0xff // Maximum number of forwards

#define DROPLET_ADDR_LEN                  (6)
#define DROPLET_DECLARE_COMMON_ADDR(addr) extern const uint8_t addr[6];
#define DROPLET_ADDR_IS_EMPTY(addr)       (((addr)[0] | (addr)[1] | (addr)[2] | (addr)[3] | (addr)[4] | (addr)[5]) == 0x0)
#define DROPLET_ADDR_IS_BROADCAST(addr)                                                                                \
  (((addr)[0] & (addr)[1] & (addr)[2] & (addr)[3] & (addr)[4] & (addr)[5]) == 0xFF)
#define DROPLET_ADDR_IS_SELF(addr)          !memcmp(addr, DROPLET_ADDR_SELF, 6)
#define DROPLET_ADDR_IS_EQUAL(addr1, addr2) !memcmp(addr1, addr2, 6)

// Callback functions

// Callback for droplet received events
typedef void (*vscp_event_handler_cb_t)(const vscpEvent *pev, void *userdata);

// ----------------------------------------------------------------------------

/**
 * @brief Set droplet configuration
 *
 * @param config Pointer to droplet configuration
 * @return esp_err_t
 */
esp_err_t
droplet_init(const droplet_config_t *config);

/**
 * @brief Send droplet frame
 *
 * @param dest_addr Pointer to destination mac address. Normally broadcast 0xff,0xff,0xff,0xff,0xff,0xff
 * @param bPreserveHeader Set to true if header is already set in payload and need to be preserved. If false
 *                        ttl , magic etc will be set by the routine.
 * @param nEncrypt  Encryption type. Frame size will increase by 16 as the iv is appended to
 *                  the end of it. Valid values is
 *                  VSCP_ENCRYPTION_NONE           0
 *                  VSCP_ENCRYPTION_AES128         1
 *                  VSCP_ENCRYPTION_AES192         2
 *                  VSCP_ENCRYPTION_AES256         3
 * @param pkey Pointer to 32 bit key used for encryption.
 * @param ttl   Time to live for frame. Will be decrease by one for every hop.
 * @param payload The frame data.
 * @param size  The size of the payload.
 * @param wait_ms Milliseconds to wait for the frame to get sent.
 * @return esp_err_t ESP_OK is returned if all is OK
 */
esp_err_t
droplet_send(const uint8_t *dest_addr,
             bool bPreserveHeader,
             uint8_t nEncrypt,
             uint8_t *pkey,
             uint8_t ttl,
             uint8_t *data,
             size_t size,
             uint16_t wait_ms);

/**
 * @brief Build full GUID from mac address
 *
 * @param pguid Pointer to GUID that will get data
 * @param pmac Pointer to six byte mac
 * @param nickname Nickname for node. Set to zero if not used.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */
int
droplet_build_guid_from_mac(uint8_t *pguid, const uint8_t *pmac, uint16_t nickname);

/**
 * @brief Construct VSCP level I heartbeat frame
 *
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of the buffer. Must be at least DROPLET_PACKET_MIN_SIZE + 3
 * @param pguid Pointer to node GUID. Can be NULL in which case the node id will be set to zero.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 *
 * The user defined first byte and zone/subzone is predefined in this call. Zone information is set to 0xff
 * for all zones/subzones and the user defined byte is set to zero.
 */

int
droplet_build_l1_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid);

/**
 * @brief Construct VSCP level II heartbeat frame
 *
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of the buffer. Must be at least DROPLET_PACKET_MIN_SIZE + 3
 * @param pguid Pointer to node GUID. Can be NULL in which case the node id will be set to zero.
 * @param pname Pointer to node name or NULL in which case no name is set.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 *
 */

int
droplet_build_l2_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid, const char *pname);

/**
 * @fn droplet_sendEvent
 * @brief  Send event on droplet network
 *
 * @param pev Event to send
 * @param wait_ms Time in milliseconds to wait for send
 * @return esp_err_t Error code. ESP_OK if all is OK.
 */

esp_err_t
droplet_sendEvent(vscpEvent *pev, uint8_t *pkey, uint32_t wait_ms);

/**
 * @fn droplet_sendEventEx
 * @brief Send event ex on droplet network
 *
 * @param pex Pointer to event ex to send.
 * @param pkey Pointer to 32 bit key used for encryption.
 * @param wait_ms Time in milliseconds to wait for send
 * @return esp_err_t Error code. ESP_OK if all is OK.
 */
esp_err_t
droplet_sendEventEx(vscpEventEx *pex, uint8_t *pkey, uint32_t wait_ms);

/**
 * @fn droplet_getMinBufSizeEv
 * @brief Get minimum buffer size for a VSCP event
 *
 * @param pev Pointer to event
 * @param pkey Pointer to 32 bit key used for encryption.
 * @return size_t Needed buffer size or zero for error (invalid event pointer).
 */
size_t
droplet_getMinBufSizeEv(vscpEvent *pev);

/**
 * @fn droplet_getMinBufSizeEx
 * @brief Get minimum buffer size for a VSCP ex event
 *
 * @param pex Pointer to event ex
 * @return size_t Needed buffer size or zero for error (invalid event pointer).
 */
size_t
droplet_getMinBufSizeEx(vscpEventEx *pex);

/**
 * @brief Construct VSCP ESP-NOW frame form event structure
 *
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of buffer. The buffer should have room for the frame plus VSCP data so it
 * should have a length that exceeds DROPLET_PACKET_MIN_SIZE + VSCP event data length.
 * @param pev Pointer to VSCP event which will have its content written to the buffer.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */

int
droplet_evToFrame(uint8_t *buf, uint8_t len, const vscpEvent *pev);

/**
 * @brief Construct VSCP ESP-NOW frame form event ex structure
 *
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of buffer. The buffer should have room for the frame plus VSCP data so it
 * should have a length that exceeds DROPLET_PACKET_MIN_SIZE + VSCP event data length.
 * @param pex Pointer to VSCP event ex which will have its content written to the buffer.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */

int
droplet_exToFrame(uint8_t *buf, uint8_t len, const vscpEventEx *pex);

/**
 * @brief Fill in Data of VSCP ex event from esp-now frame
 *
 * @param pev Pointer to VSCP event
 * @param buf  Buffer holding esp-now frame data
 * @param len  Len of buffer
 * @param timestamp The event timestamp normally comes from wifi_pkt_rx_ctrl_t in the wifi frame. If
 * set to zero  it will be set from tickcount
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */
int
droplet_frameToEv(vscpEvent *pev, const uint8_t *buf, uint8_t len, uint32_t timestamp);

/**
 * @brief Fill in Data of VSCP ex event from esp-now frame
 *
 * @param pex Pointer to VSCP ex event
 * @param buf  Buffer holding esp-now frame data
 * @param len  Len of buffer
 * @param timestamp The event timestamp normally comes from wifi_pkt_rx_ctrl_t in the wifi frame. If
 * set to zero  it will be set from tickcount
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */
int
droplet_frameToEx(vscpEventEx *pex, const uint8_t *buf, uint8_t len, uint32_t timestamp);

/**
 * @brief Set the VSCP event receive handler callback
 *
 * @param cb Callback
 *
 * Set the VSCP event receive handler callback
 *
 */
void
droplet_set_vscp_user_handler_cb(vscp_event_handler_cb_t *cb);

/**
 * @brief Clear VSCP handler event recive handler callback
 *
 */
void
droplet_clear_vscp_handler_cb(void);

/**
 * @fn droplet_parse_vscp_json
 * @brief Convert JSON string to VSCP event
 *
 * @param jsonVscpEventObj1
 * @param pev
 * @return int
 */
int
droplet_parse_vscp_json(vscpEvent *pev, const char *jsonVscpEventObj);

/**
 * @fn droplet_create_vscp_json
 * @brief Convert pointer to VSCP event to VSCP JSON string
 *
 * @param strObj String buffer that will get result
 * @param len Size of string buffer
 * @param pev Pointer to event
 * @return int Returns VSCP_ERROR_SUCCESS on OK, error code else.
 */
int
droplet_create_vscp_json(char *strObj, size_t len, vscpEvent *pev);

#ifdef __cplusplus
}
#endif /**< _cplusplus */

#endif