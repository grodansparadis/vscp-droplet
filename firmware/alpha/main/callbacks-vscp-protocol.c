// FILE: callbacks-vscp-protocol.c

// This file holds callbacks for the VSCP protocol

/* ******************************************************************************
 * 	VSCP (Very Simple Control Protocol)
 * 	https://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2000-2022 Ake Hedman, Grodans Paradis AB <info@grodansparadis.com>
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
 *	This file is part of VSCP - Very Simple Control Protocol
 *	https://www.vscp.org
 *
 * ******************************************************************************
 */


#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vscp-compiler.h"
#include "vscp-projdefs.h"

#include <vscp-firmware-helper.h>
#include <vscp-link-protocol.h>
#include <vscp-firmware-level2.h>
#include "tcpsrv.h"
#include "main.h"



// Defines from demo.c

//extern wiz_NetInfo net_info;
extern uint8_t device_guid[16];
//extern vscp_fifo_t fifoEventsIn;
extern vscpctx_t ctx[MAX_TCP_CONNECTIONS];
extern struct _eeprom_ eeprom;



// ****************************************************************************
//                        VSCP protocol callbacks
// ****************************************************************************



/*!
  @fn vscp2_callback_get_ms
  @brief Get the time in milliseconds.
  @param pdata Pointer to user data.
  @param ptime Pointer to unsigned integer that will get the time in milliseconds.
  @return True if handled.
*/
int vscp2_callback_get_ms(const void* pdata, uint32_t *ptime)
{
  if ((NULL == pdata) || (NULL == ptime)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  *ptime = getMilliSeconds();
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Get a pointer to the 16-bit device GUID.
 *
 * @param pdata Pointer to user data.
 * @return 0 on success.
 */

const uint8_t* 
vscp2_callback_get_guid(const void* pdata)
{
  return device_guid;
}

#ifdef THIS_FIRMWARE_ENABLE_WRITE_2PROTECTED_LOCATIONS

int
vscp2_callback_write_manufacturer_id(const void* pdata, uint8_t pos, uint8_t val)
{
  if (pos < 4) {
    //eeprom_write(&eeprom, VSCP2_STD_REG_MANUFACTURER_ID0 + pos, val);
  }
  else if (pos < 8) {
    //eeprom_write(&eeprom, VSCP2_STD_REG_MANUFACTURER_SUBID0 + pos - 4, val);
  }

  // Commit changes to 'eeprom'
  //eeprom_commit(&eeprom);

  return VSCP_ERROR_SUCCESS;
}

int
vscp2_callback_write_guid(const void *pdata, uint8_t pos, uint8_t val)
{
  //eeprom_write(&eeprom, VSCP2_STD_REG_GUID0 + pos, val);
  
  // Commit changes to 'eeprom'
  //eeprom_commit(&eeprom);

  return VSCP_ERROR_SUCCESS;
}

#endif

/**
 * @fn vscp2_callback_read_user_reg
 * @brief Read user register callback
 * 
 * @param pdata Pointer to context. 
 * @param reg 
 * @param pval 
 * @return VSCP_ERROR_SUCCESS on success, error code on failure 
 */

int
vscp2_callback_read_user_reg(const void* pdata, uint32_t reg, uint8_t* pval)
{
  // Check pointers (pdata allowed to be NULL)
  if (NULL == pval) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  // if ( REG_DEVICE_ZONE == reg) {
  //   *pval = eeprom_read(&eeprom, REG_DEVICE_ZONE);
  // }
  // else if ( REG_DEVICE_SUBZONE == reg) {
  //   *pval = eeprom_read(&eeprom, REG_DEVICE_SUBZONE);
  // }
  // else if ( REG_LED_CTRL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_LED_CTRL);
  // }
  // else if ( REG_LED_STATUS == reg) {
  //   *pval = gpio_get(LED_PIN);
  // }
  // else if ( REG_LED_BLINK_INTERVAL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_LED_BLINK_INTERVAL);
  // }
  // else if ( REG_IO_CTRL1 == reg) {
  //   *pval = eeprom_read(&eeprom, REG_IO_CTRL1);
  // }
  // else if ( REG_IO_CTRL2 == reg) {
  //   *pval = eeprom_read(&eeprom, REG_IO_CTRL2);
  // }
  // else if ( REG_IO_STATUS == reg) {
  //   uint32_t all = gpio_get_all();
  //   *pval = (all >> 2) & 0xff;
  // }
  // else if ( REG_TEMP_CTRL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_TEMP_CTRL);
  // }
  // else if ( REG_TEMP_RAW_MSB == reg) {
  //   float temp = read_onboard_temperature();
  //   *pval = (((uint16_t)(100* temp)) >> 8) & 0xff;
  // }
  // else if ( REG_TEMP_RAW_LSB == reg) {
  //   float temp = read_onboard_temperature();
  //   *pval = ((uint16_t)(100* temp)) & 0xff;
  // }
  // else if ( REG_TEMP_CORR_MSB == reg) {
  //   *pval = eeprom_read(&eeprom, REG_TEMP_CORR_MSB);
  // }
  // else if ( REG_TEMP_CORR_LSB == reg) {
  //   *pval = eeprom_read(&eeprom, REG_TEMP_CORR_LSB);
  // }
  // else if ( REG_TEMP_INTERVAL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_TEMP_INTERVAL);
  // }
  // else if ( REG_ADC0_CTRL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_ADC0_CTRL);
  // }
  // else if ( REG_ADC0_MSB == reg) {
  //   float adc = read_adc(0);
  //   *pval = (((uint16_t)(100* adc)) >> 8) & 0xff;
  // }
  // else if ( REG_ADC0_LSB == reg) {
  //   float adc = read_adc(0);
  //   *pval = ((uint16_t)(100* adc)) & 0xff;
  // }
  // else if ( REG_ADC1_CTRL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_ADC0_CTRL);
  // }
  // else if ( REG_ADC1_MSB == reg) {
  //   float adc = read_adc(1);
  //   *pval = (((uint16_t)(100* adc)) >> 8) & 0xff;
  // }
  // else if ( REG_ADC1_LSB == reg) {
  //   float adc = read_adc(1);
  //   *pval = ((uint16_t)(100* adc)) & 0xff;
  // }
  // else if ( REG_ADC2_CTRL == reg) {
  //   *pval = eeprom_read(&eeprom, REG_ADC0_CTRL);
  // }
  // else if ( REG_ADC2_MSB == reg) {
  //   float adc = read_adc(2);
  //   *pval = (((uint16_t)(100* adc)) >> 8) & 0xff;
  // }
  // else if ( REG_ADC2_LSB == reg) {
  //   float adc = read_adc(2);
  //   *pval = ((uint16_t)(100* adc)) & 0xff;
  // }
  // else if ((REG_BOARD_ID0 >= reg) && (REG_BOARD_ID8 <= reg)) {
  //   pico_unique_board_id_t boardid;
  //   pico_get_unique_board_id(&boardid);
  //   *pval = boardid.id[reg - REG_BOARD_ID0];
  // }
  // else {
  //   // Invalid register
  //   return VSCP_ERROR_PARAMETER;
  // }

  return VSCP_ERROR_SUCCESS;
}

/**
 * @fn vscp2_callback_write_user_reg
 * @brief Write application register
 * 
 * @param pdata Pointer to context. 
 * @param reg Register to write.
 * @param val Value to write.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_write_user_reg(const void* pdata, uint32_t reg, uint8_t val)
{
  // if ( REG_DEVICE_ZONE == reg) {
  //   eeprom_write(&eeprom, REG_DEVICE_ZONE, val);
  // }
  // else if ( REG_DEVICE_SUBZONE == reg) {
  //   eeprom_write(&eeprom, REG_DEVICE_SUBZONE, val);
  // }
  // else if ( REG_LED_CTRL == reg) { 
  //   eeprom_write(&eeprom, REG_LED_CTRL, val);
    
  // }
  // else if ( REG_LED_STATUS == reg) {
  //   if (val) {
  //     gpio_put(LED_PIN, 1);
  //   }
  //   else {
  //     gpio_put(LED_PIN, 0);
  //   }
  // }
  // else if ( REG_LED_BLINK_INTERVAL == reg) {
  //   eeprom_write(&eeprom, REG_LED_BLINK_INTERVAL, val);
  // }
  // else if ( REG_IO_CTRL1 == reg) {
  //   eeprom_write(&eeprom, REG_IO_CTRL1, val);
  // }
  // else if ( REG_IO_CTRL2 == reg) {
  //   eeprom_write(&eeprom, REG_IO_CTRL2, val);
  // }
  // else if ( REG_IO_STATUS == reg) {
    
  // }
  // else if ( REG_TEMP_CTRL == reg) {
  //   eeprom_write(&eeprom, REG_TEMP_CTRL, val);
  // }
  // else if ( REG_TEMP_CORR_MSB == reg) {
  //   eeprom_write(&eeprom, REG_TEMP_CORR_MSB, val);
  // }
  // else if ( REG_TEMP_CORR_LSB == reg) {
  //   eeprom_write(&eeprom, REG_TEMP_CORR_LSB, val);
  // }
  // else if ( REG_TEMP_INTERVAL == reg) {
  //   eeprom_write(&eeprom, REG_TEMP_INTERVAL, val);
  // }
  // else if ( REG_ADC0_CTRL == reg) {
  //   eeprom_write(&eeprom, REG_ADC0_CTRL, val);
  // }
  // else if ( REG_ADC1_CTRL == reg) {
  //   eeprom_write(&eeprom, REG_ADC1_CTRL, val);
  // }
  // else if ( REG_ADC2_CTRL == reg) {
  //   eeprom_write(&eeprom, REG_ADC2_CTRL, val);
  // }
  // else {
  //   return VSCP_ERROR_PARAMETER;
  // }

  // Commit changes to 'eeprom'
  //eeprom_commit(&eeprom);

  return VSCP_ERROR_SUCCESS;
}


/**
 * @brief Enter bootloader
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_enter_bootloader(const void* pdata)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Respons to DM info request
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_report_dmatrix(const void* pdata)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Response on embedded MDF request.
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_report_mdf(const void* pdata)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Response on event interest request.
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_report_events_of_interest(const void* pdata)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Get timestamp in microseconds
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

uint32_t
vscp2_callback_get_timestamp(const void* pdata)
{
  return 0; //time_us_32();
}

/**
 * @brief  Set VSCP event time
 * @param pdata Pointer to context.
 * @param pex Pointer to event.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_get_time(const void* pdata, const vscpEventEx *pex)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Get timestamp in milliseconds
 * @param pdata Pointer to context.
 * @param pex Event to send
 * @return VSCP_ERROR_SUCCESS on success, error code on failure
 */

int
vscp2_callback_send_eventEx(const void* pdata, vscpEventEx* pex)
{
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {

    // Only if user is validated
    if (ctx[i].bValidated) {  
      // vscpEvent *pnew = vscp_fwhlp_mkEventCopy(pex);
      // if (NULL == pnew) {
      //   return VSCP_ERROR_MEMORY;
      // }
      // else {
      //   pnew->obid = 0xffffffff; // The device
      //   if (vscp_fifo_write(&ctx[i].fifoEventsOut, pnew)) {
      //     printf("Written to fifo\n");
      //   }
      //   else {
      //     printf("Failed to write to fifo\n");
      //     vscp_fwhlp_deleteEvent(&pnew);      
      //   }
      // }
    }
  }

  // Remove original event
  //vscp_fwhlp_deleteEvent(&pex);
  
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief 
 * 
 * @param pdata Pointer to context.
 * @return VSCP_ERROR_SUCCESS on success, error code on failure 
 */

int
vscp2_callback_restore_defaults(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief 
 * 
 * @param pdata Pointer to context. 
 * @param pos 
 * @param val 
 * @return VSCP_ERROR_SUCCESS on success, error code on failure 
 */

int
vscp2_callback_write_user_id(const void *pdata, uint8_t pos, uint8_t val)
{
  //eeprom_write(&eeprom, VSCP2_STD_REG_USER_ID0 + pos, val);

  // Commit changes to 'eeprom'
  //eeprom_commit(&eeprom);
  
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief Return ipv6 or ipv4 address
 * 
 * Return the ipv6 or ipv4 address of the interface. If the
 * interface is not tcp/ip based just return a positive
 * response or a valid address for the underlying transport protocol.
 * 
 * The address is always sixteen bytes long.
 * 
 * @param pdata Pointer to context. 
 * @param pipaddr Pointer to 16 byte address space for (ipv6 or ipv4) address
 *                return value. 
 * @return VSCP_ERROR_SUCCESS on success, error code on failure 
 */

int
vscp2_callback_get_ip_addr(const void *pUserData, uint8_t *pipaddr)
{
  if (NULL == pipaddr) {
    return VSCP_ERROR_PARAMETER;
  }
  else {
    //memcpy(pipaddr, net_info.ip, 4);
  }
  
  return VSCP_ERROR_SUCCESS;
}

/**
 * @brief High end server response
 * 
 * Event received after a high end server request. This
 * request can have been sent from this device or some 
 * other device.
 * 
 * @param pdata Pointer to context. 
 * @return VSCP_ERROR_SUCCESS on success, error code on failure 
 */

#ifdef THIS_FIRMWARE_VSCP_DISCOVER_SERVER
int
vscp2_callback_high_end_server_response(const void *pUserData)
{
  return VSCP_ERROR_SUCCESS;
}
#endif