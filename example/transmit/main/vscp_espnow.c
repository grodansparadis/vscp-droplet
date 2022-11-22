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
// vscp_espnow_exToFrame
//

int
vscp_espnow_exToFrame(uint8_t *buf, uint8_t len, const vscpEventEx *pex)
{
  uint16_t crc = 0;

  if (len < VSCP_ESPNOW_PACKET_MIN_SIZE) {
    ESP_LOGE(TAG, "event does not fit in buf, len:%d", len);
    return VSCP_ERROR_INVALID_SYNTAX;
  }

  if (len < (VSCP_ESPNOW_PACKET_MIN_SIZE + pex->sizeData + 2 /*crc*/)) {
    ESP_LOGE(TAG, "event + data does not fit in buf, len:%d", len);
    return VSCP_ERROR_BUFFER_TO_SMALL;
  }

  if (pex->sizeData > VSCP_ESPNOW_MAX_DATA) {
    ESP_LOGE(TAG, "Size of VSCP event data os to large, len:%d", pex->sizeData);
    return VSCP_ERROR_INVALID_SYNTAX;
  }

  // head
  buf[0] = (pex->head >> 8) & 0xff;
  buf[1] = pex->head & 0xff;
  
  // timestamp
  buf[2] = (pex->timestamp >> 24) & 0xff;
  buf[3] = (pex->timestamp >> 16) & 0xff;
  buf[4] = (pex->timestamp >> 8) & 0xff;
  buf[5] = pex->timestamp & 0xff;

  // nickname   
  buf[6] = pex->GUID[14];
  buf[7] = pex->GUID[15];

  // vscp-class 
  buf[8] = (pex->vscp_class >> 8) & 0xff;
  buf[9] = pex->vscp_class & 0xff;

  // vscp-type
  buf[10] = (pex->vscp_type >> 8) & 0xff;
  buf[11] = pex->vscp_type & 0xff;

  // data    
  memcpy((buf + 12), pex->data, pex->sizeData);
  
  // crc        - 
  crc = esp_crc16_le(UINT16_MAX, (uint8_t const *)buf, VSCP_ESPNOW_PACKET_MIN_SIZE - 2 + pex->sizeData);
  buf[VSCP_ESPNOW_PACKET_MIN_SIZE - 2] = (crc >> 8) & 0xff;
  buf[VSCP_ESPNOW_PACKET_MIN_SIZE + 1 - 2] = crc & 0xff;

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_frameToEx
//

int vscp_espnow_frameToEx(vscpEventEx *pex, const uint8_t *buf, uint8_t len) 
{
  uint16_t crc = 0, crc_cal = 0;

  if (len < VSCP_ESPNOW_PACKET_MIN_SIZE) {
    ESP_LOGE(TAG, "Receive espnow data is too short, len:%d", len);
    return VSCP_ERROR_MTU;
  }

  if (len > VSCP_ESPNOW_PACKET_MAX_SIZE) {
    ESP_LOGI(TAG, "Receive espnow data is too long (will try anyway), len:%d", len);
  }

  // crc = buf->crc;
  // buf->crc = 0;
  crc_cal = esp_crc16_le(UINT16_MAX, (uint8_t const *) buf, len);

  if (crc_cal == crc) {
    return VSCP_ERROR_SUCCESS;
  }

  return VSCP_ERROR_SUCCESS;
}