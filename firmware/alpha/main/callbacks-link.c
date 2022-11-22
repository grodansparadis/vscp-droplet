// FILE: callbacks-link.c

// This file holds callbacks for the VSCP tcp/ip link protocol

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

#include "tcpsrv.h"
#include "main.h"


// Defines from demo.c

extern uint8_t g_node_guid[16];
//extern vscp_fifo_t fifoEventsIn;
extern vscpctx_t g_ctx[MAX_TCP_CONNECTIONS];




// ****************************************************************************
//                       VSCP Link protocol callbacks
// ****************************************************************************




///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_write_client
//

int
vscp_link_callback_welcome(const void* pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;  

  ////writeSocket(pctx->sn, DEMO_WELCOME_MSG, strlen(DEMO_WELCOME_MSG));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_write_client
//

int
vscp_link_callback_write_client(const void* pdata, const char* msg)
{
  if ((NULL == pdata) && (NULL == msg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  //writeSocket(pctx->sn, (uint8_t*)msg, strlen(msg));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_quit
//

int
vscp_link_callback_quit(const void* pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // Confirm quit
  //writeSocket(pctx->sn, VSCP_LINK_MSG_GOODBY, strlen(VSCP_LINK_MSG_GOODBY));

  // Disconnect from client
  //disconnect(pctx->sn);

  // Set context defaults
  setContextDefaults(pctx);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_help
//

int
vscp_link_callback_help(const void* pdata, const char* arg)
{
  if ((NULL == pdata) && (NULL == arg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  //writeSocket(pctx->sn, VSCP_LINK_MSG_OK, strlen(VSCP_LINK_MSG_OK));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_interface_count
//

uint16_t
vscp_link_callback_get_interface_count(const void* pdata)
{
  /* Return number of interfaces we support */
  return 1;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_interface
//

int
vscp_link_callback_get_interface(const void* pdata, uint16_t index, struct vscp_interface_info *pif)
{
  if ((NULL == pdata) && (NULL == pif)) {
    return VSCP_ERROR_UNKNOWN_ITEM;
  }

  if (index != 0) {
    return VSCP_ERROR_UNKNOWN_ITEM;
  }

  // interface-id-n, type, interface-GUID-n, interface_real-name-n
  // interface types in vscp.h

  pif->idx = index;
  pif->type = VSCP_INTERFACE_TYPE_INTERNAL;
  memcpy(pif->guid, g_node_guid, 16);
  strncpy(pif->description, "Interface for the device itself", sizeof(pif->description));

  // We have no interfaces
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_check_user
//

int
vscp_link_callback_check_user(const void* pdata, const char* arg)
{
  if ((NULL == pdata) && (NULL == arg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  // trim
  const char* p = arg;
  while (*p && isspace(*p)) {
    p++;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  strncpy(pctx->user, p, VSCP_LINK_MAX_USER_NAME_LENGTH);
  //writeSocket(pctx->sn, VSCP_LINK_MSG_USENAME_OK, strlen(VSCP_LINK_MSG_USENAME_OK));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_check_password
//

int
vscp_link_callback_check_password(const void* pdata, const char* arg)
{
  if ((NULL == pdata) && (NULL == arg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // Must have a username before a password
  if (*(pctx->user) == '\0') {
    //writeSocket(pctx->sn, VSCP_LINK_MSG_NEED_USERNAME, strlen(VSCP_LINK_MSG_NEED_USERNAME));
    return VSCP_ERROR_SUCCESS;
  }

  const char* p = arg;
  while (*p && isspace(*p)) {
    p++;
  }

  // if (!pctx->bValidated) {

  // }
  if (0 == strcmp(pctx->user, "admin") && 0 == strcmp(p, "secret")) {
    pctx->bValidated = true;
    pctx->privLevel = 15;

    // Send out early to identify ourself
    // no need to send earlier as bValidate must be true
    // for events to get delivered
    
    //vscp2_send_heartbeat();
    //vscp2_send_caps();
  }
  else {
    pctx->user[0]    = '\0';
    pctx->bValidated = false;
    pctx->privLevel = 0;
    //writeSocket(pctx->sn, VSCP_LINK_MSG_PASSWORD_ERROR, strlen(VSCP_LINK_MSG_PASSWORD_ERROR));
    return VSCP_ERROR_SUCCESS;
  }

  //writeSocket(pctx->sn, VSCP_LINK_MSG_PASSWORD_OK, strlen(VSCP_LINK_MSG_PASSWORD_OK));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_challenge
//

int
vscp_link_callback_challenge(const void* pdata, const char* arg)
{
  uint8_t buf[80];
  uint8_t random_data[32];
  if ((NULL == pdata) && (NULL == arg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  const char* p = arg;
  while (*p && isspace(*p)) {
    p++;
  }

  strcpy((char *)buf, "+OK - ");
  p = (const char *)buf + strlen((const char *)buf);

  for (int i = 0; i < 32; i++) {
    random_data[i] = rand() >> 16;
    if (i < sizeof(p)) {
      random_data[i] += (uint8_t)p[i];
    }
    vscp_fwhlp_dec2hex(random_data[i], (char*)p, 2);
    p++;
  }

  strcat((char *)buf, "\r\n");
  //writeSocket(pctx->sn, buf, strlen(buf));
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_check_authenticated
//

int
vscp_link_callback_check_authenticated(const void* pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  if (pctx->bValidated) {
    return VSCP_ERROR_SUCCESS;
  }

  return VSCP_ERROR_INVALID_PERMISSION;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_check_privilege
//

int
vscp_link_callback_check_privilege(const void* pdata, uint8_t priv)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  if (pctx->privLevel >= priv) {
    return VSCP_ERROR_SUCCESS;
  }

  return VSCP_ERROR_INVALID_PERMISSION;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_challenge
//

int
vscp_link_callback_test(const void* pdata, const char* arg)
{
  if ((NULL == pdata) && (NULL == arg)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  //writeSocket(pctx->sn, VSCP_LINK_MSG_OK, strlen(VSCP_LINK_MSG_OK));
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_send
//

int
vscp_link_callback_send(const void* pdata, vscpEventEx* pex)
{
  if ((NULL == pdata) && (NULL == pex)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // Filter
  if (!vscp_fwhlp_doLevel2FilterEx(pex, &pctx->filter)) {
    return VSCP_ERROR_SUCCESS;  // Filter out == OK
  }

  // Update send statistics
  pctx->statistics.cntTransmitFrames++;
  pctx->statistics.cntTransmitData += pex->sizeData;

  // Write event to receive fifo
  pex->obid = pctx->sock;
  // vscpEvent *pnew = vscp_fwhlp_mkEventCopy(pex);
  // if (NULL == pnew) {
  //   return VSCP_ERROR_MEMORY;
  // }
  // else {
  //   if (!vscp_fifo_write(&fifoEventsIn, pnew)) {
  //     vscp_fwhlp_deleteEvent(&pnew);
  //     vscp_fwhlp_deleteEvent(&pex);
  //     pctx->statistics.cntOverruns++;
  //     return VSCP_ERROR_TRM_FULL;
  //   }
  // }

  // // Write to send buffer of other interfaces
  // for (int i = 0; i < MAX_CONNECTIONS; i++) {
  //   if (pctx->sn != i) {
  //     vscpEvent *pnew = vscp_fwhlp_mkEventCopy(pev);
  //     if (NULL == pnew) {
  //       vscp_fwhlp_deleteEvent(&pnew);
  //       vscp_fwhlp_deleteEvent(&pev);
  //       return VSCP_ERROR_MEMORY;
  //     }
  //     else {
  //       if (!vscp_fifo_write(&ctx[i].fifoEventsOut, pnew)) {
  //         vscp_fwhlp_deleteEvent(&pnew);
  //         vscp_fwhlp_deleteEvent(&pev);
  //         ctx[i].statistics.cntOverruns++;
  //         return VSCP_ERROR_TRM_FULL;
  //       }  
  //     }
  //   }  
  // }

  // Event is not needed anymore
  //vscp_fwhlp_deleteEvent(&pev);

  // We own the event from now on and must
  // delete it and it's data when we are done
  // with it

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_retr
//

int
vscp_link_callback_retr(const void* pdata, vscpEventEx* pex)
{
  if ((NULL == pdata) && (NULL == pex)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // if (!vscp_fifo_read(&pctx->fifoEventsOut, pex)) {
  //   return VSCP_ERROR_RCV_EMPTY;
  // }

  // Update receive statistics
  pctx->statistics.cntReceiveFrames++;
  pctx->statistics.cntReceiveData += pex->sizeData;

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_enable_rcvloop
//

int
vscp_link_callback_enable_rcvloop(const void* pdata, int bEnable)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  pctx->bRcvLoop = bEnable;
  //pctx->last_rcvloop_time = time_us_32();

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_rcvloop_status
//

int
vscp_link_callback_get_rcvloop_status(const void* pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  return pctx->bRcvLoop; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_chkData
//

int
vscp_link_callback_chkData(const void* pdata, uint16_t* pcount)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  //*pcount = TRANSMIT_FIFO_SIZE - vscp_fifo_getFree(&pctx->fifoEventsOut);
  
  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_clrAll
//

int
vscp_link_callback_clrAll(const void* pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  //vscp_fifo_clear(&pctx->fifoEventsOut);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_channel_id
//

int
vscp_link_callback_get_channel_id(const void* pdata, uint16_t *pchid)
{
  if ((NULL == pdata) && (NULL == pchid)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  *pchid = pctx->sock;
  
  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_guid
//

int
vscp_link_callback_get_guid(const void* pdata, uint8_t *pguid)
{
  if ((NULL == pdata) || (NULL == pguid)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  memcpy(pguid, g_node_guid, 16);
  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_set_guid
//

int
vscp_link_callback_set_guid(const void* pdata, uint8_t *pguid)
{
  if ((NULL == pdata) || (NULL == pguid)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  memcpy(g_node_guid, pguid, 16);
  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_get_version
//

int
vscp_link_callback_get_version(const void* pdata, uint8_t *pversion)
{
  if ((NULL == pdata) || (NULL == pversion)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  pversion[0] = THIS_FIRMWARE_MAJOR_VERSION;
  pversion[1] = THIS_FIRMWARE_MINOR_VERSION;
  pversion[2] = THIS_FIRMWARE_RELEASE_VERSION;
  pversion[3] = THIS_FIRMWARE_BUILD_VERSION;
  
  return VSCP_ERROR_SUCCESS; 
}


///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_setFilter
//

int
vscp_link_callback_setFilter(const void* pdata, vscpEventFilter *pfilter)
{
  if ((NULL == pdata) || (NULL == pfilter)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  pctx->filter.filter_class = pfilter->filter_class;
  pctx->filter.filter_type = pfilter->filter_type;
  pctx->filter.filter_priority = pfilter->filter_priority;
  memcpy(pctx->filter.filter_GUID, pfilter->filter_GUID, 16);

  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_setMask
//

int
vscp_link_callback_setMask(const void* pdata, vscpEventFilter *pfilter)
{
  if ((NULL == pdata) || (NULL == pfilter)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  pctx->filter.mask_class = pfilter->mask_class;
  pctx->filter.mask_type = pfilter->mask_type;
  pctx->filter.mask_priority = pfilter->mask_priority;
  memcpy(pctx->filter.mask_GUID, pfilter->mask_GUID, 16);

  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_statistics
//

int
vscp_link_callback_statistics(const void* pdata, VSCPStatistics *pStatistics)
{
  if ((NULL == pdata) || (NULL == pStatistics)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  memcpy(pStatistics, &pctx->statistics, sizeof(VSCPStatistics));

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_info
//

int
vscp_link_callback_info(const void* pdata, VSCPStatus *pstatus)
{
  if ((NULL == pdata) || (NULL == pstatus)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;
  memcpy(pstatus, &pctx->status, sizeof(VSCPStatus));  

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_rcvloop
//

int
vscp_link_callback_rcvloop(const void* pdata, vscpEventEx *pex)
{
  // Check pointer
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // Every second output '+OK\r\n' in rcvloop mode
  // if ((time_us_32() - pctx->last_rcvloop_time) > 1000000) {
  //   pctx->last_rcvloop_time = time_us_32();
  //   return VSCP_ERROR_TIMEOUT;
  // }

  // if (!vscp_fifo_read(&pctx->fifoEventsOut, pev)) {
  //   return VSCP_ERROR_RCV_EMPTY;
  // }

  // Update receive statistics
  pctx->statistics.cntReceiveFrames++;
  pctx->statistics.cntReceiveData += pex->sizeData;

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_wcyd
//

int
vscp_link_callback_wcyd(const void* pdata, uint64_t *pwcyd)
{
  // Check pointers
  if ((NULL == pdata) || (NULL == pwcyd)) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  *pwcyd = VSCP_SERVER_CAPABILITY_TCPIP | 
              VSCP_SERVER_CAPABILITY_DECISION_MATRIX | 
              VSCP_SERVER_CAPABILITY_IP4 | 
              /*VSCP_SERVER_CAPABILITY_SSL |*/
              VSCP_SERVER_CAPABILITY_TWO_CONNECTIONS;

  return VSCP_ERROR_SUCCESS;            
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_shutdown
//

int
vscp_link_callback_shutdown(const void* pdata)
{
  // Check pointers
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  // At this point
  // Shutdown the system
  // Set everything in a safe and inactive state

  // Stay here until someone presses the reset button
  // or power cycles the board
  while(1) {
    //watchdog_update();
  }

  return VSCP_ERROR_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// vscp_link_callback_restart
//

int
vscp_link_callback_restart(const void* pdata)
{
  // Check pointers
  if (NULL == pdata) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  vscpctx_t* pctx = (vscpctx_t*)pdata;

  while(1); // Restart

  return VSCP_ERROR_SUCCESS; 
}
