/* 
  projdefs.h

  This file contains project definitions for the VSCP TCP/IP link protocol code.
*/



#ifndef _VSCP_PROJDEFS_H_
#define _VSCP_PROJDEFS_H_

/*
  Demo related projdefs
*/
#define IDLE_OTHER_CORE       idle_other_core
#define RESUME_OTHER_CORE     resume_other_core

/*!
  Max buffer for level II events. The buffer size is needed to
  convert an event to string. To handle all level II events
  512*5 + 110 = 2670 bytes is needed. In reality this is
  seldom needed so the value can be set to a lower value. In this
  case one should check the max data size for events that are of
  interest and set the max size accordingly 
*/
#define VSCP_LINK_MAX_BUF         (2680)

/*!
  Define to show custom help. The callback is called so you can respond 
  with your custom help text.  This can be used to save memory if you work 
  on a constraint environment.
  
  If zero standard help is shown.
*/
//#define VSCP_LINK_CUSTOM_HELP_TEXT 

/**
 * Undefine to send incoming events to all clients (default).
 */
#define VSCP_LINK_SEND_TO_ALL

/*!
  Size for inout buffer and outputbuffer.
  Must be at least one for each fifo
*/
#define VSCP_LINK_MAX_IN_FIFO_SIZE    (10)
#define VSCP_LINK_MAX_OUT_FIFO_SIZE   (10)

/**
 * Enable command also when rcvloop is active
 * Only 'quit' and 'quitloop' will work if
 * set to zero.
 */
#define VSCP_LINK_ENABLE_RCVLOOP_CMD  (1)


/**
  ----------------------------------------------------------------------------
                              VSCP TCP/IP Link
  ----------------------------------------------------------------------------
  Defines for firmware level II
*/

/*!
  Name of device for level II capabilities announcement event.
*/
#define THIS_FIRMWARE_DEVICE_NAME "VSCP Wireless CAN Gateway"


/**
 * If defined an UDP heartbeat is broadcasted every minute.
 */
#define THIS_FIRMWARE_USE_UDP_ANNOUNCE

/**
 * If defined a multicast heartbeat is broadcasted every minute.
 */
#define THIS_FIRMWARE_USE_MULTICAST_ANNOUNCE

/**
 * Firmware version 
 */

#define THIS_FIRMWARE_MAJOR_VERSION             (0)
#define THIS_FIRMWARE_MINOR_VERSION             (0)
#define THIS_FIRMWARE_RELEASE_VERSION           (1)
#define THIS_FIRMWARE_BUILD_VERSION             (0)

/**
 * User id (this is only defaults)
 */
#define THIS_FIRMWARE_USER_ID0                  (0)
#define THIS_FIRMWARE_USER_ID1                  (0)
#define THIS_FIRMWARE_USER_ID2                  (0)
#define THIS_FIRMWARE_USER_ID3                  (0)
#define THIS_FIRMWARE_USER_ID4                  (0)

/**
 * Manufacturer id
 */
#define THIS_FIRMWARE_MANUFACTURER_ID0          (0)
#define THIS_FIRMWARE_MANUFACTURER_ID1          (0)
#define THIS_FIRMWARE_MANUFACTURER_ID2          (0)
#define THIS_FIRMWARE_MANUFACTURER_ID3          (0)

/**
 * Manufacturer subid
 */
#define THIS_FIRMWARE_MANUFACTURER_SUBID0       (0)
#define THIS_FIRMWARE_MANUFACTURER_SUBID1       (0)
#define THIS_FIRMWARE_MANUFACTURER_SUBID2       (0)
#define THIS_FIRMWARE_MANUFACTURER_SUBID3       (0)

/**
 * Set bootloader algorithm
 */
#define THIS_FIRMWARE_BOOTLOADER_ALGORITHM      (0) 

/**
 * Device family code 32-bit
 */
#define THIS_FIRMWARE_DEVICE_FAMILY_CODE        (0ul)

/**
 * Device type code 32-bit
 */
#define THIS_FIRMWARE_DEVICE_TYPE_CODE          (0ul)    

/**
  Interval for heartbeats in seconds
*/
#define THIS_FIRMWARE_INTERVAL_HEARTBEATS       (60)

/**
 * Interval for capabilities report in seconds
 */
#define THIS_FIRMWARE_INTERVAL_CAPS             (60)

/**
 * Buffer size
 */
#define THIS_FIRMWARE_BUFFER_SIZE               VSCP_MAX (vscp.h)

/**
 * Enable logging
 */
#define THIS_FIRMWARE_ENABLE_LOGGING

/**
 * Enable error reporting
 */
#define THIS_FIRMWARE_ENABLE_ERROR_REPORTING

/**
 * @brief Uncomment to enable writing to write protected areas
 *
 * Writing manufacturer data and GUID
 */
#define THIS_FIRMWARE_ENABLE_WRITE_2PROTECTED_LOCATIONS

/**
 * @brief Send server probe
 * 
 */
#define THIS_FIRMWARE_VSCP_DISCOVER_SERVER

/**
 * GUID for this node (no spaces)
 */
#define THIS_FIRMWARE_GUID                    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0x00,0x08,0xdc,0x12,0x34,0x56,0x00,0x01}

/**
 * URL to MDF file
 */
#define THIS_FIRMWARE_MDF_URL                 "eurosource.se/wcang0.mdf"

/**
 * 16-bit firmware code for this device
 */
#define THIS_FIRMWARE_CODE                    (0)

/**
 * 16-bit firmware code for this device
 */
#define THIS_FIRMWARE_FAMILY_CODE             (0)

/**
 * 16-bit firmware code for this device
 */
#define THIS_FIRMWARE_FAMILY_TYPE             (0)


/**
 * @brief Maximum number of simultanonus TCP/IP connections
 * This is the maximum simultaneous number
 * of connections to the server
 */
#define MAX_TCP_CONNECTIONS                 2

#endif // _VSCP_PROJDEFS_H_