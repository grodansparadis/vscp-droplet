/**
 * @brief           VSCP ESP-Now code
 * @file            vscp_espnow.h
 * @author          Ake Hedman, The VSCP Project, www.vscp.org
 *
 *********************************************************************/

/* ******************************************************************************
 * VSCP (Very Simple Control Protocol)
 * http://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright (C) 2000-2022 Ake Hedman, 
 * The VSCP Project <info@grodansparadis.com>
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

#ifndef VSCP_ESPNOW_H
#define VSCP_ESPNOW_H

#define VSCP_ESPNOW_MAX_DATA    128     // Max VSCP data (of possible 512 bytes) that a frame can hold

/**
 * @brief VSCP ESP-NOW event frame
 * 
 * // Frame format
 * head       - 16 bytes
 * timestamp  - 32 bytes 
 * nickname   - 16 bytes
 * vscp-class - 16 bytes
 * vscp-data  - 16 bytes
 * data       - 0-128 bytes
 * crc        - 16 bytes
 */

typedef struct {
  // Start of VSCP frame
  // First two bytes 0x257E (9598)
  union {
    struct {
      uint16_t seq: 6;                    // Sequence number, increased for every frame sent
      uint16_t reserved: 10;              // Reserved bits */
    };
    uint16_t head;                        // Don't use
  };
  // Timestamp in  <wifi_pkt_rx_ctrl_t> on receive
  //uint32_t timestamp;                     // Microsecond timestamp is in espnow header
  uint16_t nickname;                      // #FF:FF:FF:FF:FF:FF:FF:FE:" + MAC + nickname forms VSCP GUID
  uint16_t vscp_class;                    // VSCP Level I class (ninth bit in head)
  uint16_t vscp_type;                     // VSCP level I type  
  uint8_t data[VSCP_ESPNOW_MAX_DATA];     // Real payload of ESPNOW data. On wire: 0-128 bytes
  // CRC is calculated on frame
  //uint16_t crc;                         // CRC16 value of ESPNOW data. seq -> data, len not included
  uint8_t len;                            // Payload data len !!!!! Not sent on the wire !!!!! 
} vscp_espnow_event_t;  // 14 + 128 = 142

#define VSCP_ESPNOW_PACKET_MIN_SIZE   (8 + 2)   // VSCP id bytes + structure
#define VSCP_ESPNOW_PACKET_MAX_SIZE   (VSCP_ESPNOW_PACKET_MIN_SIZE + VSCP_ESPNOW_MAX_DATA)

#define VSCP_HEART_BEAT_INTERVAL      30000   // Milliseconds between heartbeat events

// Control states for espnow provisioning
typedef enum {
    ESPNOW_CTRL_INIT,
    ESPNOW_CTRL_BOUND,
    ESPNOW_CTRL_MAX
} espnow_ctrl_status_t;

// ----------------------------------------------------------------------------

/**
 * @brief Build full GUID from mac address
 * 
 * @param pguid Pointer to GUID that will get data
 * @param pmac Pointer to six byte mac 
 * @param nickname Nickname for node. Set to zero if not used.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned. 
 */
int
vscp_espnow_build_guid_from_mac(uint8_t *pguid, const uint8_t *pmac, uint16_t nickname);

/**
 * @brief Construct VSCP level I heartbeat frame
 * 
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of the buffer. Must be at least VSCP_ESPNOW_PACKET_MIN_SIZE + 3
 * @param pguid Pointer to node GUID. Can be NULL in which case the node id will be set to zero.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 * 
 * The user defined first byte and zone/subzone is predefined in this call. Zone information is set to 0xff
 * for all zones/subzones and the user defined byte is set to zero.
 */

int
vscp_espnow_build_l1_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid);

/**
 * @brief Construct VSCP level II heartbeat frame
 * 
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of the buffer. Must be at least VSCP_ESPNOW_PACKET_MIN_SIZE + 3
 * @param pguid Pointer to node GUID. Can be NULL in which case the node id will be set to zero.
 * @param pname Pointer to node name or NULL in which case no name is set.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 * 
 */

int
vscp_espnow_build_l2_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid, const char *pname);

/**
 * @brief Construct VSCP ESP-NOW frame form event structure
 * 
 * @param buf Pointer to buffer that will get the frame data
 * @param len Size of buffer. The buffer should have room for the frame plus VSCP data so it
 * should have a length that exceeds VSCP_ESPNOW_PACKET_MIN_SIZE + VSCP event data length. 
 * @param pex Pointer to VSCP event ex which will have its content written to the buffer.
 * @return int VSCP_ERROR_SUCCES is returned if all goes well. Otherwise VSCP error code is returned.
 */

int
vscp_espnow_exToFrame(uint8_t *buf, uint8_t len, const vscpEventEx *pex);

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
vscp_espnow_frameToex(vscpEventEx *pex, const uint8_t *buf, uint8_t len, uint32_t timestamp);


#endif