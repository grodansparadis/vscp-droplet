/*
  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

  VSCP Alpha Droplet node

  MQTT SSL Client

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

#ifndef  __DROPLET_MQTT__
#define __DROPLET_MQTT__

#define DROPLET_MQTT_STATISTIC_PUBLISH_INTERVAL   60000

// Topics for send and receive statistics
#define DROPLET_MQTT_TOPIC_STATS_RECV_CNT   "droplet/alpha/statistics/rcvcnt"
#define DROPLET_MQTT_TOPIC_STATS_TX_CNT   "droplet/alpha/statistics/txcnt"


/**
 * @brief 
 * 
 */

void
mqtt_start(void);

/**
 * @brief 
 * 
 */

void
mqtt_stop(void);

#endif