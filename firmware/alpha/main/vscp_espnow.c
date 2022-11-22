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

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <esp_now.h>
#include <esp_log.h>
#include <esp_crc.h>

#include <espnow.h>

#include <vscp.h>
#include "vscp_espnow.h"

static const char *TAG = "vscp_espnow_alpha";


///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_build_guid_from_mac
//

int
vscp_espnow_build_guid_from_mac(uint8_t *pguid, const uint8_t *pmac, uint16_t nickname)
{
  uint8_t prebytes[8] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe};

  // Need a GUID pointer
  if (NULL == pguid) {
    ESP_LOGE(TAG, "Pointer to GUID is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  } 

  // Need a mac pointer
  if (NULL == pmac) {
    ESP_LOGE(TAG, "Pointer to mac address is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  } 

  memcpy( pguid, prebytes, 8);
  memcpy( pguid+8, pmac, 6);
  pguid[14] = (nickname << 8) & 0xff;
  pguid[15] =  nickname & 0xff;

  return VSCP_ERROR_SUCCESS;
}



///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_build_heartbeat
//

int
vscp_espnow_build_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (VSCP_ESPNOW_PACKET_MIN_SIZE + 3)) {
    ESP_LOGE(TAG, "Size of byffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Construct VSCP heart beat event

  // Packet id VSCP
  buf[0] = (VSCP_DEFAULT_TCP_PORT >> 8) & 0xff;
  buf[1] = VSCP_DEFAULT_TCP_PORT & 0xff;

  // Head
  buf[2] = 0;
  buf[3] = 0;

  // Nickname
  if (NULL != pguid) {
    buf[4] = pguid[14]; // (g_node_nickname >> 8) & 0xff;
    buf[5] = pguid[15]; // g_node_nickname & 0xff;
  }

  // VSCP Class
  buf[6] = (VSCP_CLASS1_INFORMATION >> 8) & 0xff;
  buf[7] = VSCP_CLASS1_INFORMATION & 0xff;

  // VSCP Type
  buf[8] = (VSCP_TYPE_INFORMATION_NODE_HEARTBEAT >> 8) & 0xff;
  buf[9] = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT & 0xff;

  // Data
  buf[10] = 0;    // User specific
  buf[11] = 0xff; // All zones
  buf[12] = 0xff; // All subzones

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_build_l2_heartbeat
//

int
vscp_espnow_build_l2_heartbeat(uint8_t *buf, uint8_t len, const uint8_t *pguid, const char *name)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (VSCP_ESPNOW_PACKET_MIN_SIZE + 3)) {
    ESP_LOGE(TAG, "Size of byffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Construct VSCP heart beat event

  // Packet id VSCP
  buf[0] = (VSCP_DEFAULT_TCP_PORT >> 8) & 0xff;
  buf[1] = VSCP_DEFAULT_TCP_PORT & 0xff;

  // Head
  buf[2] = 0;
  buf[3] = 0;

  // Nickname
  if (NULL != pguid) {
    buf[4] = pguid[14]; // (g_node_nickname >> 8) & 0xff;
    buf[5] = pguid[15]; // g_node_nickname & 0xff;
  }

  // VSCP Class
  buf[6] = (VSCP_CLASS1_INFORMATION >> 8) & 0xff;
  buf[7] = VSCP_CLASS1_INFORMATION & 0xff;

  // VSCP Type
  buf[8] = (VSCP_TYPE_INFORMATION_NODE_HEARTBEAT >> 8) & 0xff;
  buf[9] = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT & 0xff;

  // Data
  buf[10] = 0;    // User specific
  buf[11] = 0xff; // All zones
  buf[12] = 0xff; // All subzones

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_exToFrame
//

int
vscp_espnow_exToFrame(uint8_t *buf, uint8_t len, const vscpEventEx *pex)
{
  // Need a buffer
  if (NULL == buf) {
    ESP_LOGE(TAG, "Pointer to buffer is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Need event
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must have room for frame
  if (len < (VSCP_ESPNOW_PACKET_MIN_SIZE + pex->sizeData)) {
    ESP_LOGE(TAG, "Size of buffer is to small to fit event, len:%d", len);
    return VSCP_ERROR_PARAMETER;
  }

  memset(buf, 0, len);

  // Packet id VSCP
  buf[0] = (VSCP_DEFAULT_TCP_PORT >> 8) & 0xff;
  buf[1] = VSCP_DEFAULT_TCP_PORT & 0xff;

  // head
  buf[2] = (pex->head >> 8) & 0xff;
  buf[3] = pex->head & 0xff;
  
  // nickname   
  buf[4] = pex->GUID[14];
  buf[5] = pex->GUID[15];

  // vscp-class 
  buf[6] = (pex->vscp_class >> 8) & 0xff;
  buf[7] = pex->vscp_class & 0xff;

  // vscp-type
  buf[8] = (pex->vscp_type >> 8) & 0xff;
  buf[9] = pex->vscp_type & 0xff;

  // data    
  memcpy((buf + 10), pex->data, pex->sizeData);
  
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_frameToEx
//

int vscp_espnow_frameToEx(vscpEventEx *pex, const uint8_t *buf, uint8_t len, uint32_t timestamp) 
{
  // Need event
  if (NULL == pex) {
    ESP_LOGE(TAG, "Pointer to event is NULL");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must at least have min size
  if (len < VSCP_ESPNOW_PACKET_MIN_SIZE) {
    ESP_LOGE(TAG, "esp-now data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  // First two bytes of buffer must be VSCP magic bytes, if not
  // this is not a VSCP frame
  if (!(buf[0] == ((VSCP_DEFAULT_TCP_PORT >> 8) & 0xff)) || !(buf[1] == (VSCP_DEFAULT_TCP_PORT & 0xff))) {
    ESP_LOGE(TAG, "esp-now data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  memset(pex, 0, sizeof(vscpEventEx));

  // Set VSCP size
  pex->sizeData = len - VSCP_ESPNOW_PACKET_MIN_SIZE;

  // Copy in VSCP data
  memcpy(pex->data, buf+VSCP_ESPNOW_PACKET_MIN_SIZE, pex->sizeData);

  // Set timestamp if not set
  if (!timestamp) {
    pex->timestamp =  esp_timer_get_time();
  }

  // Head
  pex->head = (buf[2] << 8) + buf[3];

  // Nickname
  pex->GUID[14] = buf[4];
  pex->GUID[15] = buf[5];

  // VSCP class
  pex->vscp_class = (buf[6] << 8) + buf[7];

  // VSCP type
  pex->vscp_type = (buf[8] << 8) + buf[9];

  return VSCP_ERROR_SUCCESS;
}