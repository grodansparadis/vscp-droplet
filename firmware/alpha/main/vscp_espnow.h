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
  //uint8_t dest_mac[ESP_NOW_ETH_ALEN];   // Destination mac address
  //uint16_t seq;                         // Sequence number, increased for every frame sent


  // Start of VSCP data
  union {
    struct {
      uint16_t seq: 6;                    // Sequence number, increased for every frame sent
      uint16_t reserved: 10;              // Reserved bits */
    };
    uint16_t head;                        // Don't use
  };
  uint32_t timestamp;                     // Microsecond timestamp is in espnow header
  uint16_t nickname;                      // #FF:FF:FF:FF:FF:FF:FF:FE:" + MAC + nickname forms VSCP GUID
  uint16_t vscp_class;                    // VSCP Level I class (ninth bit in head)
  uint16_t vscp_type;                     // VSCP level I type  
  uint8_t data[VSCP_ESPNOW_MAX_DATA];     // Real payload of ESPNOW data. On wire: 0-128 bytes
  // End of VSCP data
  uint16_t crc;                           // CRC16 value of ESPNOW data. seq -> data, len not included
  uint8_t len;                            // Payload data len !!!!! Not sent on the wire !!!!! 
} vscp_espnow_event_t;  // 14 + 128 = 142

#define VSCP_ESPNOW_PACKET_MIN_SIZE   14
#define VSCP_ESPNOW_PACKET_MAX_SIZE   (VSCP_ESPNOW_PACKET_MIN_SIZE + VSCP_ESPNOW_MAX_DATA)

#define VSCP_HEART_BEAT_INTERVAL      20000   // Milliseconds between heartbeat events

// Control states for espnow provisioning
typedef enum {
    ESPNOW_CTRL_INIT,
    ESPNOW_CTRL_BOUND,
    ESPNOW_CTRL_MAX
} espnow_ctrl_status_t;

// ----------------------------------------------------------------------------



/**
 * @brief Construct VSCP ESP-NOW frame form event structure
 * 
 * @param buf This buffer will get frame written
 * @param len Size of buffer
 * @param pex Pointer to VSCP ex event
 * @return int VSCP_ERROR_SUCCESS is returned on success, error code otherwise.
 */

int
vscp_espnow_exToFrame(uint8_t *buf, size_t len, vscpEventEx *pex);

/**
 * @brief Fill in Data of VSCP ex event from esp-now frame
 * 
 * @param pex Pointer to VSCP ex event
 * @param buf  Buffer holding esp-now frame data
 * @param len  Len of buffer
 * @return int VSCP_ERROR_SUCCESS is returned on success, error code otherwise.
 */
int
vscp_espnow_frameToex(vscpEventEx *pex, uint8_t *buf, size_t len);


#endif