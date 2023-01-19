/*
  VSCP Alpha Droplet node

  Web Server

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022-2023 Ake Hedman, the VSCP project <info@vscp.org>

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

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include <esp_system.h>
#include <esp_chip_info.h>
#include <esp_flash_spi_init.h>
#include <esp_flash.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>
#include <esp_timer.h>
#include <esp_err.h>
#include <esp_log.h>
#include <nvs_flash.h>

#include <esp_event_base.h>
#include <esp_tls_crypto.h>
#include <esp_vfs.h>
#include <esp_spiffs.h>
#include <esp_http_server.h>

#include <vscp.h>
#include <vscp-firmware-helper.h>

#include "urldecode.h"

#include "websrv.h"
#include "main.h"

// #define MIN(a, b) (((a) < (b)) ? (a) : (b))
// #define MAX(a, b) (((a) > (b)) ? (a) : (b))

// External from main
extern nvs_handle_t g_nvsHandle;
extern node_persistent_config_t g_persistent;
extern esp_netif_t *g_netif;

#define TAG __func__

// Max length a file path can have on storage
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)

// Chunk buffer size
#define CHUNK_BUFSIZE 8192

#define IS_FILE_EXT(filename, ext) (strcasecmp(&filename[strlen(filename) - sizeof(ext) + 1], ext) == 0)

//-----------------------------------------------------------------------------
//                               Start Basic Auth
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// http_auth_basic
//

static char *
http_auth_basic(const char *username, const char *password)
{
  int out;
  char *user_info = NULL;
  char *digest    = NULL;
  size_t n        = 0;
  asprintf(&user_info, "%s:%s", username, password);
  if (!user_info) {
    ESP_LOGE(TAG, "No enough memory for user information");
    return NULL;
  }
  esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *) user_info, strlen(user_info));

  /* 6: The length of the "Basic " string
   * n: Number of bytes for a base64 encode format
   * 1: Number of bytes for a reserved which be used to fill zero
   */
  digest = calloc(1, 6 + n + 1);
  if (digest) {
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *) digest + 6,
                             n,
                             (size_t *) &out,
                             (const unsigned char *) user_info,
                             strlen(user_info));
  }
  free(user_info);
  return digest;
}

///////////////////////////////////////////////////////////////////////////////
// basic_auth_get_handler
//
// An HTTP GET handler
//

// static esp_err_t
// basic_auth_get_handler(httpd_req_t *req)
// {
//   char *buf                          = NULL;
//   size_t buf_len                     = 0;
//   basic_auth_info_t *basic_auth_info = req->user_ctx;

//   ESP_LOGI(TAG, "basic_auth_get_handler");

//   buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
//   if (buf_len > 1) {
//     buf = calloc(1, buf_len);
//     if (!buf) {
//       ESP_LOGE(TAG, "No enough memory for basic authorization");
//       return ESP_ERR_NO_MEM;
//     }

//     if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
//       ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
//     }
//     else {
//       ESP_LOGE(TAG, "No auth value received");
//     }

//     char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
//     if (!auth_credentials) {
//       ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
//       free(buf);
//       return ESP_ERR_NO_MEM;
//     }

//     if (strncmp(auth_credentials, buf, buf_len)) {
//       ESP_LOGE(TAG, "Not authenticated");
//       httpd_resp_set_status(req, HTTPD_401);
//       httpd_resp_set_type(req, "application/json");
//       httpd_resp_set_hdr(req, "Connection", "keep-alive");
//       httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
//       httpd_resp_send(req, NULL, 0);
//     }
//     else {
//       ESP_LOGI(TAG, "Authenticated!");
//       char *basic_auth_resp = NULL;
//       httpd_resp_set_status(req, HTTPD_200);
//       httpd_resp_set_type(req, "application/json");
//       httpd_resp_set_hdr(req, "Connection", "keep-alive");
//       asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
//       if (!basic_auth_resp) {
//         ESP_LOGE(TAG, "No enough memory for basic authorization response");
//         free(auth_credentials);
//         free(buf);
//         return ESP_ERR_NO_MEM;
//       }
//       httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
//       free(basic_auth_resp);
//     }
//     free(auth_credentials);
//     free(buf);
//   }
//   else {
//     ESP_LOGE(TAG, "No auth header received");
//     httpd_resp_set_status(req, HTTPD_401);
//     httpd_resp_set_type(req, "application/json");
//     httpd_resp_set_hdr(req, "Connection", "keep-alive");
//     httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
//     httpd_resp_send(req, NULL, 0);
//   }

//   return ESP_OK;
// }

// static httpd_uri_t basic_auth = {
//   .uri     = "/basic_auth",
//   .method  = HTTP_GET,
//   .handler = basic_auth_get_handler,
// };

// ///////////////////////////////////////////////////////////////////////////////
// // httpd_register_basic_auth
// //

// static void
// httpd_register_basic_auth(httpd_handle_t server)
// {
//   esp_err_t ret;
//   basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
//   if (basic_auth_info) {
//     basic_auth_info->username = DEFAULT_TCPIP_USER;
//     basic_auth_info->password = DEFAULT_TCPIP_PASSWORD;

//     basic_auth.user_ctx = basic_auth_info;
//     if (ESP_OK != (ret = httpd_register_uri_handler(server, &basic_auth)) ) {
//       ESP_LOGE(TAG,"Failed to register aut hri handler %d", ret);
//     }
//   }
// }

//-----------------------------------------------------------------------------
//                               End Basic Auth
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// escape_buf
//
// Replace escape expressions in buffer
//
// MODULE
// ======
// %a0    - Module Version
// %aq    - Current date
// %a2    - Current time
// %a3    - Time server 1 (disabled if blank)
// %a4    - Time server 2
// %a5    - Capacitor charge time (s) before wifi startup.
//
// WIFI
// ====
// %b0    - ssid1
// %b1    - password1
// %b2    - ssid2
// %b3    - password2
//
// MQTT
// ====
// %c0    - MQTT host
// %c1    - MQTT port
// %c2    - MQTT Client
// %c3    - MQTT user
// %c4    - MQTT password
// %c5    - MQTT Subscribe (multiple)
// %c6    - MQTT Publish (multiple)
//
// DROPLET
// =======
// %d0    - Droplet master key (32 + zero termination)
// %d1    - Time to live (0-255)
// %d2    - Packet forward enable("true")/disable("false")
// %d3    - Long range ("true"/"false").
// %d4    - RSSI threshold
//

static void
str_replace(char *target, const char *needle, const char *replacement)
{
  char buf[1024]     = { 0 };
  char *insert_point = &buf[0];
  const char *tmp    = target;
  size_t needle_len  = strlen(needle);
  size_t repl_len    = strlen(replacement);

  while (1) {
    const char *p = strstr(tmp, needle);

    // walked past last occurrence of needle; copy remaining part
    if (p == NULL) {
      strcpy(insert_point, tmp);
      break;
    }

    // copy part before needle
    memcpy(insert_point, tmp, p - tmp);
    insert_point += p - tmp;

    // copy replacement string
    memcpy(insert_point, replacement, repl_len);
    insert_point += repl_len;

    // adjust pointers, move on
    tmp = p + needle_len;
  }

  // write altered string back to target
  strcpy(target, buf);
}

static esp_err_t
esapeBuf(const char buf, size_t len)
{

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// info_get_handler
//
// HTTP GET handler for info page
//

static esp_err_t
info_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  temp = (char *) calloc(80, 1);
  if (NULL == temp) {
    return ESP_ERR_NO_MEM;
  }

  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Technical Info");
  // sprintf(buf,WEBPAGE_START_TEMPLATE);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<table>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // * * * system * * *
  // sprintf(buf, "<tr><td>System</td><td></td></tr>");
  sprintf(buf, "<tr><td class='infoheader'>System</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Chip type:</td>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  switch (chip_info.model) {

    case CHIP_ESP32:
      // printf("ESP32\n");
      sprintf(buf, "<td class=\"prop\">ESP32</td><tr>");
      break;

    case CHIP_ESP32S2:
      // printf("ESP32-S2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S2</td><tr>");
      break;

    case CHIP_ESP32S3:
      // printf("ESP32-S3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S3</td><tr>");
      break;

    case CHIP_ESP32C3:
      // printf("ESP32-C3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C3</td><tr>");
      break;

    case CHIP_ESP32H2:
      // printf("ESP32-H2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-H2</td><tr>");
      break;

    case CHIP_ESP32C2:
      // printf("ESP32-C2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C2</td><tr>");
      break;

    default:
      // printf("Unknown\n");
      sprintf(buf, "<td class=\"prop\">Unknown</td></tr>");
      break;
  }
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Number of cores:</td><td class=\"prop\">%d</td></tr>", chip_info.cores);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Number of cores: %d \n", chip_info.cores);

  // Chip comm features
  sprintf(temp,
          "%s%s%s%s",
          (chip_info.features & CHIP_FEATURE_WIFI_BGN) ? "WiFi " : "",
          (chip_info.features & CHIP_FEATURE_BT) ? "BT " : "",
          (chip_info.features & CHIP_FEATURE_BLE) ? "BLE " : "",
          (chip_info.features & CHIP_FEATURE_IEEE802154) ? "802.15.4 " : "");
  sprintf(buf, "<tr><td class=\"name\">Chip comm features:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_country_t country;
  esp_wifi_get_country(&country);
  // printf("Wifi country code: %c%c%c\n", country.cc[0],country.cc[1],country.cc[2]);
  sprintf(buf,
          "<tr><td class=\"name\">Wifi country code:</td><td class=\"prop\">%c%c%c</td></tr>",
          country.cc[0],
          country.cc[1],
          country.cc[2]);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded flash:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_PSRAM) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded psram:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // sprintf(temp, "%d", chip_info.revision);
  sprintf(buf, "<tr><td class=\"name\">Silicon revision:</td><td class=\"prop\">%d</td></tr>", chip_info.revision);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t chipId;
  rv = esp_flash_read_id(NULL, &chipId);
  // printf("Flash chip id: %04lX\n", chipId);
  sprintf(buf, "<tr><td class=\"name\">Flash chip id:</td><td class=\"prop\">%04lX</td></tr>", chipId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint64_t uniqueId;
  rv = esp_flash_read_unique_chip_id(NULL, &uniqueId);
  // printf("Unique flash chip id: %08llX\n", uniqueId);
  sprintf(buf, "<tr><td class=\"name\">Unique flash chip id:</td><td class=\"prop\">%08llX</td></tr>", uniqueId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t sizeFlash;
  esp_flash_get_size(NULL, &sizeFlash);
  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "(embedded)" : "(external)");
  // printf("%luMB %s flash\n",
  //        sizeFlash / (1024 * 1024),
  //        (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
  sprintf(buf,
          "<tr><td class=\"name\">Flash size:</td><td class=\"prop\">%s %lu MB</td></tr>",
          temp,
          sizeFlash / (1024 * 1024));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // get chip id
  // chipId = String((uint32_t) ESP.getEfuseMac(), HEX);
  // chipId.toUpperCase();
  // printf("Chip id: %s\n", chipId.c_str());

  // printf("esp-idf version: %s\n", esp_get_idf_version());
  sprintf(buf, "<tr><td class=\"name\">esp-idf version:</td><td class=\"prop\">%s</td></tr>", esp_get_idf_version());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Free heap size: %lu\n", esp_get_free_heap_size());
  sprintf(buf,
          "<tr><td class=\"name\">Free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>",
          esp_get_free_heap_size() / 1024,
          esp_get_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Min free heap size: %lu\n", esp_get_minimum_free_heap_size());
  sprintf(buf,
          "<tr><td class=\"name\">Min free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>",
          esp_get_minimum_free_heap_size() / 1024,
          esp_get_minimum_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Last reset reson: ");
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:
      sprintf(temp, "Reset due to power-on event.\n");
      break;
    case ESP_RST_EXT:
      sprintf(temp, "Reset by external pin (not applicable for ESP32.\n");
      break;
    case ESP_RST_SW:
      sprintf(temp, "Software reset via esp_restart.\n");
      break;
    case ESP_RST_PANIC:
      sprintf(temp, "Software reset due to exception/panic.\n");
      break;
    case ESP_RST_INT_WDT:
      sprintf(temp, "Reset (software or hardware) due to interrupt watchdog.\n");
      break;
    case ESP_RST_TASK_WDT:
      sprintf(temp, "Reset due to task watchdog.\n");
      break;
    case ESP_RST_WDT:
      sprintf(temp, "Reset due to other watchdogs.\n");
      break;
    case ESP_RST_DEEPSLEEP:
      sprintf(temp, "Reset after exiting deep sleep mode.\n");
      break;
    case ESP_RST_BROWNOUT:
      sprintf(temp, "Brownout reset (software or hardware.\n");
      break;
    case ESP_RST_SDIO:
      sprintf(temp, "Reset over SDIO.\n");
      break;
    case ESP_RST_UNKNOWN:
    default:
      sprintf(temp, "Reset reason can not be determined.\n");
      break;
  }
  sprintf(buf, "<tr><td class=\"name\">Last reset reson:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Number of reboots: %lu\n",g_boot_counter);
  sprintf(buf, "<tr><td class=\"name\">Number of reboots:</td><td class=\"prop\">%lu</td></tr>", g_persistent.bootCnt);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  vscp_fwhlp_writeGuidToString(temp, g_persistent.nodeGuid);
  sprintf(buf, "<tr><td class=\"name\">GUID:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // -------------------------------------------------------------------------

  // * * *  Application * * *
  // sprintf(buf, "<tr><td>Application</td><td></td></tr>");
  sprintf(buf, "<tr><td class='infoheader'>Application</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  int time = esp_timer_get_time();
  sprintf(buf,
          "<tr><td class=\"name\">Uptime:</td><td class=\"prop\">%dT%02d:%02d:%02d</td></tr>",
          ((time / 1000000) / (3600 * 24)),
          ((time / 1000000) / 3600),
          ((time / 1000000) / 60),
          (time / 1000000));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Firmware version: %d\n", DROPLET_VERSION);
  const esp_app_desc_t *appDescr = esp_app_get_description();

  if (NULL != appDescr) {
    // sprintf(temp,"%s",appDescr->project_name);
    sprintf(buf, "<tr><td class=\"name\">Application:</td><td class=\"prop\">%s</td></tr>", appDescr->project_name);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"Application ver: %s\n",appDescr->version);
    sprintf(buf, "<tr><td class=\"name\">Application ver:</td><td class=\"prop\">%s</td></tr>", appDescr->version);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"Application ver: %s %s\n",appDescr->date,appDescr->time);
    sprintf(buf,
            "<tr><td class=\"name\">Compile time:</td><td class=\"prop\">%s %s</td></tr>",
            appDescr->date,
            appDescr->time);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"idf ver: %s\n",appDescr->idf_ver);
    sprintf(buf, "<tr><td class=\"name\">Compiled w/ idf ver:</td><td class=\"prop\">%s</td></tr>", appDescr->idf_ver);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  }

  // * * *  Connection * * *
  sprintf(buf, "<tr><td class='infoheader'>Connection</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_mode_t mode;
  rv = esp_wifi_get_mode(&mode);
  switch (mode) {

    case WIFI_MODE_STA:
      sprintf(temp, "STA\n");
      break;

    case WIFI_MODE_AP:
      sprintf(temp, "AP\n");
      break;

    case WIFI_MODE_APSTA:
      sprintf(temp, "APSTA\n");
      break;

    case WIFI_MODE_NULL:
    default:
      sprintf(temp, "unknown\n");
      break;
  };
  // sprintf(temp,"Wifi mode: ");
  sprintf(buf, "<tr><td class=\"name\">Wifi mode:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_sta_list_t sta;
  rv = esp_wifi_ap_get_sta_list(&sta);
  // printf("Stations: %d\n",sta.num);
  sprintf(buf, "<tr><td class=\"name\">Stations:</td><td class=\"prop\">%d</td></tr>", sta.num);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_ap_record_t ap_info;
  rv = esp_wifi_sta_get_ap_info(&ap_info);
  // printf("bssid: " MACSTR "\n", MAC2STR(ap_info.bssid));
  sprintf(buf, "<tr><td class=\"name\">bssid:</td><td class=\"prop\">" MACSTR "</td></tr>", MAC2STR(ap_info.bssid));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("ssid: %s\n", ap_info.ssid);
  sprintf(buf, "<tr><td class=\"name\">ssid:</td><td class=\"prop\">%s</td></tr>", ap_info.ssid);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("channel: %d (%d)\n", ap_info.primary, ap_info.second);
  sprintf(buf,
          "<tr><td class=\"name\">channel:</td><td class=\"prop\">%d (%d)</td></tr>",
          ap_info.primary,
          ap_info.second);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("signal strength: %d\n", ap_info.rssi);
  if (ap_info.rssi > -30) {
    sprintf(temp, "Perfect");
  }
  else if (ap_info.rssi > -50) {
    sprintf(temp, "Excellent");
  }
  else if (ap_info.rssi > -60) {
    sprintf(temp, "Good");
  }
  else if (ap_info.rssi > -67) {
    sprintf(temp, "Limited");
  }
  else if (ap_info.rssi > -70) {
    sprintf(temp, "Poor");
  }
  else if (ap_info.rssi > -80) {
    sprintf(temp, "Unstable");
  }
  else {
    sprintf(temp, "Unusable");
  }

  sprintf(buf,
          "<tr><td class=\"name\">signal strength:</td><td class=\"prop\">%d dBm ( %d%% = %s)</td></tr>",
          ap_info.rssi,
          (2 * (ap_info.rssi + 100)),
          temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Mode: 11%s%s%s %s %s",
  //           ap_info.phy_11b ? "b" : "",
  //           ap_info.phy_11g ? "g" : "",
  //           ap_info.phy_11n ? "n" : "",
  //           ap_info.phy_lr ? "lr" : "",
  //           ap_info.wps ? "wps" : "");
  // printf("\nAuth mode of AP: ");
  switch (ap_info.authmode) {

    case WIFI_AUTH_OPEN:
      sprintf(temp, "open\n");
      break;

    case WIFI_AUTH_WEP:
      sprintf(temp, "wep\n");
      break;

    case WIFI_AUTH_WPA_PSK:
      sprintf(temp, "wpa-psk\n");
      break;

    case WIFI_AUTH_WPA2_PSK:
      sprintf(temp, "wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA_WPA2_PSK:
      sprintf(temp, "wpa-wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA2_ENTERPRISE:
      sprintf(temp, "wpa2-enterprise\n");
      break;

    case WIFI_AUTH_WPA3_PSK:
      sprintf(temp, "wpa3-psk\n");
      break;

    case WIFI_AUTH_WPA2_WPA3_PSK:
      sprintf(temp, "wpa2-wpa3-psk\n");
      break;

    case WIFI_AUTH_WAPI_PSK:
      sprintf(temp, "wpa2-wapi-psk\n");
      break;

    case WIFI_AUTH_OWE:
      sprintf(temp, "wpa2-wapi-psk\n");
      break;

    default:
      sprintf(temp, "unknown\n");
      break;
  }

  sprintf(buf, "<tr><td class=\"name\">Auth mode of AP:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint8_t mac[6];
  esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
  // printf("Wifi STA MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf,
          "<tr><td class=\"name\">Wifi STA MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>",
          MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_wifi_get_mac(ESP_MAC_WIFI_SOFTAP, mac);
  // printf("Wifi SOFTAP MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf,
          "<tr><td class=\"name\">Wifi SOFTAP MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>",
          MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_netif_ip_info_t ifinfo;
  esp_netif_get_ip_info(g_netif, &ifinfo);
  // printf("IP address (wifi): " IPSTR "\n", IP2STR(&ifinfo.ip));
  sprintf(buf,
          "<tr><td class=\"name\">IP address (wifi):</td><td class=\"prop\">" IPSTR "</td></tr>",
          IP2STR(&ifinfo.ip));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Subnet Mask: " IPSTR "\n", IP2STR(&ifinfo.netmask));
  sprintf(buf,
          "<tr><td class=\"name\">Subnet Mask:</td><td class=\"prop\">" IPSTR "</td></tr>",
          IP2STR(&ifinfo.netmask));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Gateway: " IPSTR "\n", IP2STR(&ifinfo.gw));
  sprintf(buf, "<tr><td class=\"name\">Gateway:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&ifinfo.gw));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_netif_dns_info_t dns;
  rv = esp_netif_get_dns_info(g_netif, ESP_NETIF_DNS_MAIN, &dns);
  // printf("DNS DNS Server1: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));
  sprintf(buf,
          "<tr><td class=\"name\">DNS Server1:</td><td class=\"prop\">" IPSTR "</td></tr>",
          IP2STR(&dns.ip.u_addr.ip4));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  rv = esp_netif_get_dns_info(g_netif, ESP_NETIF_DNS_BACKUP, &dns);

  // printf("DNS Server2: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));
  sprintf(buf,
          "<tr><td class=\"name\">DNS Server2:</td><td class=\"prop\">" IPSTR "</td></tr>",
          IP2STR(&dns.ip.u_addr.ip4));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</table>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);
  free(temp);

  return ESP_OK;
}

// URI handler for getting uploaded files
httpd_uri_t info = { .uri = "/info", .method = HTTP_GET, .handler = info_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// reset_get_handler
//
// HTTP GET handler for reset of machine
//

static esp_err_t
reset_get_handler(httpd_req_t *req)
{
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=index.html\" "
                         "/></head><body><h1>The system is restarting...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  // esp_wifi_disconnect();
  // vTaskDelay(2000 / portTICK_PERIOD_MS);
  esp_restart();
  return ESP_OK;
}

httpd_uri_t reset = { .uri = "/reset", .method = HTTP_GET, .handler = reset_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// upgrade_get_handler
//
// HTTP GET handler for update of firmware
//

static esp_err_t
upgrade_get_handler(httpd_req_t *req)
{
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta name=\"viewport\" "
    "content=\"width=device-width,initial-scale=1,user-scalable=no\" /><link rel=\"icon\" "
    "href=\"favicon-32x32.png\"><title>Droplet Alpha node - Update</title><link rel=\"stylesheet\" href=\"style.css\" "
    "/><meta http-equiv=\"refresh\" content=\"5;url=index.html\" /></head><body><div "
    "style='text-align:left;display:inline-block;color:#eaeaea;min-width:340px;'><div "
    "style='text-align:center;color:#eaeaea;'><h1>Upgrade from secure server...</h1></div></div></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  startOTA();

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  // esp_restart();
  return ESP_OK;
}

httpd_uri_t upgrade = { .uri = "/upgrade", .method = HTTP_GET, .handler = upgrade_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// upgrdlocal_get_handler
//
// HTTP GET handler for update of firmware
//

static esp_err_t
upgrdlocal_get_handler(httpd_req_t *req)
{
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta name=\"viewport\" "
    "content=\"width=device-width,initial-scale=1,user-scalable=no\" /><link rel=\"icon\" "
    "href=\"favicon-32x32.png\"><title>Droplet Alpha node - Update</title><link rel=\"stylesheet\" href=\"style.css\" "
    "/><meta http-equiv=\"refresh\" content=\"5;url=index.html\" /></head><body><div "
    "style='text-align:left;display:inline-block;color:#eaeaea;min-width:340px;'><div "
    "style='text-align:center;color:#eaeaea;'><h1>Upgrade local...</h1></div></div></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  // esp_restart();
  return ESP_OK;
}

httpd_uri_t upgrade_local = { .uri      = "/upgrade-local",
                              .method   = HTTP_GET,
                              .handler  = upgrdlocal_get_handler,
                              .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// Copies the full path into destination buffer and returns
// pointer to path (skipping the preceding base path)
//

static const char *
get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{
  const size_t base_pathlen = strlen(base_path);
  size_t pathlen            = strlen(uri);

  const char *quest = strchr(uri, '?');
  if (quest) {
    pathlen = MIN(pathlen, quest - uri);
  }
  const char *hash = strchr(uri, '#');
  if (hash) {
    pathlen = MIN(pathlen, hash - uri);
  }

  if (base_pathlen + pathlen + 1 > destsize) {
    // Full path string won't fit into destination buffer
    return NULL;
  }

  // Construct full path (base + path)
  strcpy(dest, base_path);
  strlcpy(dest + base_pathlen, uri, pathlen + 1);

  // Return pointer to path, skipping the base
  return dest + base_pathlen;
}

///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// An HTTP GET handler
//

static esp_err_t
hello_get_handler(httpd_req_t *req)
{
  char *buf;
  size_t buf_len;

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
    }
    free(buf);
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char param[32];
      // Get value of expected key from query string
      if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
      }
      if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
      }
      if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
      }
    }
    free(buf);
  }

  // Set some custom headers
  httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
  httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

  // Send response with custom headers and body set as the
  // string passed in user context
  const char *resp_str = "Hi there mister mongo!"; //(const char *) req->user_ctx;
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // After sending the HTTP response the old HTTP request
  // headers are lost. Check if HTTP request headers can be read now.
  if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
    ESP_LOGI(TAG, "Request headers lost");
  }

  return ESP_OK;
}

static const httpd_uri_t hello = { .uri     = "/hello",
                                   .method  = HTTP_GET,
                                   .handler = hello_get_handler,
                                   // Let's pass response string in user
                                   // context to demonstrate it's usage
                                   .user_ctx = "Hello World!" };

///////////////////////////////////////////////////////////////////////////////
// mainpg_get_handler
//
// Mainpage for web interface
//

static esp_err_t
mainpg_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Main Page");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but1 class=\"button\" action='config' method='get'><button>Configuration</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<p><form id=but2 class=\"button\" action='info' method='get'><button>Information</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(
    buf,
    "<p><form id=but3 class=\"button\" action='upgrade' method='get'><button>Firmware Upgrade</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but4 class=\"button\" action='reset' method='get'><button name='rst' class='button "
          "bred'>Restart</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE_NO_RETURN, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t mainpg = { .uri     = "/index.html",
//                                    .method  = HTTP_GET,
//                                    .handler = mainpg_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// config_get_handler
//

static esp_err_t
config_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but1 class=\"button\" action='cfgmodule' method='get'><button>Module</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<p><form id=but2 class=\"button\" action='cfgwifi' method='get'><button>WiFi</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgdroplet' method='get'><button>Droplet</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgvscplink' method='get'><button>VSCP Link</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfgmqtt' method='get'><button>MQTT</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfglog' method='get'><button>Logging</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<hr /><p><form id=but4 class=\"button\" action='cfgreset' method='get'><button name='rst' class='button "
          "bgrn'>Reset</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgbackup' method='get'><button class='button "
          "bgrn'>Backup</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgrestore' method='get'><button class='button "
          "bgrn'>Restore</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t config = { .uri     = "/config",
//                                    .method  = HTTP_GET,
//                                    .handler = config_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// config_module_get_handler
//

static esp_err_t
config_module_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Module Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgmodule' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  const char *pmkstr = malloc(65);
  for (int i = 0; i < 32; i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(buf,
          "Primay key (32 bytes hex):<input type=\"text\" name=\"pmk\" maxlength=\"64\" size=\"20\" value=\"%s\" >",
          pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf,
          "Startup delay:<input type=\"text\" name=\"strtdly\" value=\"%d\" maxlength=\"2\" size=\"4\">",
          g_persistent.startDelay);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  char *guidstr = malloc(48);
  vscp_fwhlp_writeGuidToString(guidstr, g_persistent.nodeGuid);

  sprintf(buf,
          "GUID (FF:FF:00...):<input type=\"text\" name=\"guid\" value=\"%s\" maxlength=\"50\" size=\"20\">",
          guidstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(guidstr);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t cfgModule = { .uri     = "/cfgmodule",
//                                    .method  = HTTP_GET,
//                                    .handler = config_module_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// do_config_module_get_handler
//

static esp_err_t
do_config_module_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// config_wifi_get_handler
//

static esp_err_t
config_wifi_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Wifi Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgwifi' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  const char *pmkstr = malloc(65);
  for (int i = 0; i < 32; i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(buf,
          "Primay key (32 bytes hex):<input type=\"text\" name=\"pmk\" maxlength=\"64\" size=\"20\" value=\"%s\" >",
          pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_wifi_get_handler
//

static esp_err_t
do_config_wifi_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_droplet_get_handler
//

static esp_err_t
config_droplet_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Droplet Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgdroplet' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  const char *pmkstr = malloc(65);
  for (int i = 0; i < 32; i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(buf,
          "Primay key (32 bytes hex):<input type=\"text\" name=\"pmk\" maxlength=\"64\" size=\"20\" value=\"%s\" >",
          pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_droplet_get_handler
//

static esp_err_t
do_config_droplet_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_vscplink_get_handler
//

static esp_err_t
config_vscplink_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "VSCP Link Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgdroplet' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  const char *pmkstr = malloc(65);
  for (int i = 0; i < 32; i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(buf,
          "Primay key (32 bytes hex):<input type=\"text\" name=\"pmk\" maxlength=\"64\" size=\"20\" value=\"%s\" >",
          pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_vscplink_get_handler
//

static esp_err_t
do_config_vscplink_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_mqtt_get_handler
//

static esp_err_t
config_mqtt_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "MQTT Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgdroplet' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  const char *pmkstr = malloc(65);
  for (int i = 0; i < 32; i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(buf,
          "Primay key (32 bytes hex):<input type=\"text\" name=\"pmk\" maxlength=\"64\" size=\"20\" value=\"%s\" >",
          pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_mqtt_get_handler
//

static esp_err_t
do_config_mqtt_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_log_get_handler
//

static esp_err_t
config_log_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Logging Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgdroplet' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<input type=\"checkbox\" id=\"stdout\"name=\"stdout\" value=\"%s\"><label for=\"stdout\"> Log to stdout</label>",
          g_persistent.logwrite2Stdout ? "true" : "false");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,"<br /><br />Log to:<select type=\"checkbox\" name=\"dest\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);  
  sprintf(buf,"<option value=\"0\" %s>none</option>", (ALPHA_LOG_NONE == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"<option value=\"1\" %s>stdout</option>", (ALPHA_LOG_STD == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"<option value=\"2\" %s>UDP</option>", (ALPHA_LOG_UDP == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"<option value=\"3\" %s>TCP</option>", (ALPHA_LOG_TCP == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"<option value=\"4\" %s>MQTT</option>", (ALPHA_LOG_MQTT == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"<option value=\"5\" %s>VSCP</option>", (ALPHA_LOG_VSCP == g_persistent.logOutput) ? "selected":"");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,"></select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Log level:<select type=\"checkbox\" name=\"level\" "
          "<option value=\"0\">error</option>"
          "<option value=\"1\">warning</option>"
          "<option value=\"2\">info</option>"
          "<option value=\"3\">debug</option>"
          "<option value=\"4\">verbose</option>"
          "></select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Max retries:<input type=\"text\" name=\"retries\" value=\"%d\" >",
          g_persistent.logRetries);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Destination (IP Addr):<input type=\"text\" name=\"address\" value=\"%s\" >",
          g_persistent.logDestination);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Port:<input type=\"text\" name=\"port\" value=\"%d\" >",
          g_persistent.logPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "MQTT Topic:<input type=\"text\" name=\"topic\" value=\"%s\" >",
          g_persistent.logMqttTopic);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_log_get_handler
//

static esp_err_t
do_config_log_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_ESPNOW_NO_MEM;
        free(buf);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_ESPNOW_NO_MEM;
        }
        ESP_LOGI(TAG, "Found name query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "node_name", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // strtdly
      if (ESP_OK == (rv = httpd_query_key_value(buf, "strtdly", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => strtdly=%s", param);
        g_persistent.startDelay = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "start_delay", g_persistent.startDelay);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update start delay");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting strtdly => rv=%d", rv);
      }

      // GUID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "guid", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGI(TAG, "Found name query parameter => guid=%s", param);

        char *p = urlDecode(param);
        ESP_LOGI(TAG, "URL Decode => guid=%s", p);
        if (VSCP_ERROR_SUCCESS != vscp_fwhlp_parseGuid(g_persistent.nodeGuid, p, NULL)) {
          ESP_LOGE(TAG, "Failed to read GUID");
        }

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "guid", g_persistent.nodeGuid, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write node GUID to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting guid => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// upd_droplet_get_handler
//
// Update droplet configuration settings
//

static esp_err_t
upd_droplet_get_handler(httpd_req_t *req)
{
  char *buf;
  size_t buf_len;

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination

  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char param[33];
      // Get value of expected key from query string
      if (httpd_query_key_value(buf, "key", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => key=%s", param);
      }
      if (httpd_query_key_value(buf, "ttl", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => ttl=%s", param);
      }
      // Enable packet forward functionality
      if (httpd_query_key_value(buf, "bforward", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => bforward=%s", param);
      }
      else {
        // Key 'bforward' is not found
      }
      // Enable Long Range
      if (httpd_query_key_value(buf, "blr", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => blr=%s", param);
      }
      else {
        // Key 'blr' is not found
      }
    }
    free(buf);
  }

  // httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");

  // Send response with custom headers and body set as the
  // string passed in user context
  const char *resp_str =
    "<html><head><meta http-equiv=\"refresh\" content=\"0; url='index.html'\" /></head><body>Save<body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// echo_post_handler
//
// An HTTP POST handler
//

static esp_err_t
echo_post_handler(httpd_req_t *req)
{
  char buf[100];
  int ret, remaining = req->content_len;

  while (remaining > 0) {
    // Read the data for the request
    if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
        // Retry receiving if timeout occurred
        continue;
      }
      return ESP_FAIL;
    }

    // Send back the same data
    httpd_resp_send_chunk(req, buf, ret);
    remaining -= ret;

    // Log data received
    ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TAG, "%.*s", ret, buf);
    ESP_LOGI(TAG, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

static const httpd_uri_t echo = { .uri = "/echo", .method = HTTP_POST, .handler = echo_post_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// http_404_error_handler
//
// This handler allows the custom error handling functionality to be
// tested from client side. For that, when a PUT request 0 is sent to
// URI /ctrl, the /hello and /echo URIs are unregistered and following
// custom error handler http_404_error_handler() is registered.
// Afterwards, when /hello or /echo is requested, this custom error
// handler is invoked which, after sending an error message to client,
// either closes the underlying socket (when requested URI is /echo)
// or keeps it open (when requested URI is /hello). This allows the
// client to infer if the custom error handler is functioning as expected
// by observing the socket state.
//

esp_err_t
http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
  if (strcmp("/hello", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
    // Return ESP_OK to keep underlying socket open
    return ESP_OK;
  }
  else if (strcmp("/echo", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
    // Return ESP_FAIL to close underlying socket
    return ESP_FAIL;
  }
  // For any other URI send 404 and close socket
  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
  return ESP_FAIL;
}

///////////////////////////////////////////////////////////////////////////////
// ctrl_put_handler
//
// An HTTP PUT handler. This demonstrates realtime
// registration and deregistration of URI handlers
//

static esp_err_t
ctrl_put_handler(httpd_req_t *req)
{
  char buf;
  int ret;

  if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }

  if (buf == '0') {
    // URI handlers can be unregistered using the uri string
    ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
    httpd_unregister_uri(req->handle, "/hello");
    httpd_unregister_uri(req->handle, "/echo");
    // Register the custom error handler
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
  }
  else {
    ESP_LOGI(TAG, "Registering /hello and /echo URIs");
    httpd_register_uri_handler(req->handle, &hello);
    httpd_register_uri_handler(req->handle, &echo);
    // Unregister custom error handler
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
  }

  // Respond with empty body
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

// static const httpd_uri_t ctrl = { .uri = "/ctrl", .method = HTTP_PUT, .handler = ctrl_put_handler, .user_ctx = NULL
// };

///////////////////////////////////////////////////////////////////////////////
// set_content_type_from_file
//
// Set HTTP response content type according to file extension
//

static esp_err_t
set_content_type_from_file(httpd_req_t *req, const char *filename)
{
  if (IS_FILE_EXT(filename, ".gz")) {
    return httpd_resp_set_type(req, "application/gzip");
  }
  else if (IS_FILE_EXT(filename, ".html")) {
    return httpd_resp_set_type(req, "text/html");
  }
  else if (IS_FILE_EXT(filename, ".css")) {
    return httpd_resp_set_type(req, "text/css");
  }
  else if (IS_FILE_EXT(filename, ".jpeg")) {
    return httpd_resp_set_type(req, "image/jpeg");
  }
  else if (IS_FILE_EXT(filename, ".png")) {
    return httpd_resp_set_type(req, "image/png");
  }
  else if (IS_FILE_EXT(filename, ".ico")) {
    return httpd_resp_set_type(req, "image/x-icon");
  }
  else if (IS_FILE_EXT(filename, ".js")) {
    return httpd_resp_set_type(req, "text/javascript");
  }
  // For any other type always set as plain text
  return httpd_resp_set_type(req, "text/plain");
}

///////////////////////////////////////////////////////////////////////////////
// default_get_handler
//
// Handler to download a file kept on the server
//

static esp_err_t
default_get_handler(httpd_req_t *req)
{
  char filepath[FILE_PATH_MAX];
  FILE *fd = NULL;
  struct stat file_stat;
  char *buf      = NULL;
  size_t buf_len = 0;

  ESP_LOGI(TAG, "uri : [%s]", req->uri);

  //---------------------------------------------------------------------------

  ESP_LOGI(TAG, "default_get_handler");

  buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
  if (buf_len > 1) {
    buf = calloc(1, buf_len);
    if (!buf) {
      ESP_LOGE(TAG, "No enough memory for basic authorization");
      return ESP_ERR_NO_MEM;
    }

    if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
    }
    else {
      ESP_LOGE(TAG, "No auth value received");
    }

    char *auth_credentials = http_auth_basic(DEFAULT_TCPIP_USER, DEFAULT_TCPIP_PASSWORD);
    if (!auth_credentials) {
      ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
      free(buf);
      return ESP_ERR_NO_MEM;
    }

    if (strncmp(auth_credentials, buf, buf_len)) {
      ESP_LOGE(TAG, "Not authenticated");
      httpd_resp_set_status(req, HTTPD_401);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Alpha\"");
      httpd_resp_send(req, NULL, 0);
    }
    else {
      ESP_LOGI(TAG, "------> Authenticated!");
      /* char *basic_auth_resp = NULL;
      httpd_resp_set_status(req, HTTPD_200);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
      if (!basic_auth_resp) {
        ESP_LOGE(TAG, "No enough memory for basic authorization response");
        free(auth_credentials);
        free(buf);
        return ESP_ERR_NO_MEM;
      }
      httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
      free(basic_auth_resp); */
    }
    free(auth_credentials);
    free(buf);
  }
  else {
    ESP_LOGE(TAG, "No auth header received.");
    httpd_resp_set_status(req, HTTPD_401);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Alpha\"");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
  }

  // -----------------------------------------------------------------------------

  if (0 == strncmp(req->uri, "/hello", 6)) {
    ESP_LOGV(TAG, "--------- HELLO ---------\n");
    return hello_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/echo", 5)) {
    ESP_LOGV(TAG, "--------- ECHO ---------\n");
    return echo_post_handler(req);
  }

  if (0 == strncmp(req->uri, "/ctrl", 5)) {
    ESP_LOGV(TAG, "--------- CTRL ---------\n");
    return ctrl_put_handler(req);
  }

  if (0 == strncmp(req->uri, "/index.html", 11)) {
    ESP_LOGV(TAG, "--------- index ---------\n");
    return mainpg_get_handler(req);
  }

  if ((0 == strncmp(req->uri, "/", 1)) && (1 == strlen(req->uri))) {
    ESP_LOGV(TAG, "--------- index /---------\n");
    return mainpg_get_handler(req);
  }

  // ---------------------------------------------------------------

  if (0 == strncmp(req->uri, "/config", 7)) {
    ESP_LOGV(TAG, "--------- config ---------\n");
    return config_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgmodule", 10)) {
    ESP_LOGV(TAG, "--------- cfgmodule ---------\n");
    return config_module_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgmodule", 12)) {
    ESP_LOGV(TAG, "--------- docfgmodule ---------\n");
    return do_config_module_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgwifi", 8)) {
    ESP_LOGV(TAG, "--------- cfgwifi ---------\n");
    return config_wifi_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgwifi", 10)) {
    ESP_LOGV(TAG, "--------- docfgwifi ---------\n");
    return do_config_wifi_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgdroplet", 11)) {
    ESP_LOGV(TAG, "--------- cfgdroplet ---------\n");
    return config_droplet_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgdroplet", 13)) {
    ESP_LOGV(TAG, "--------- docfgdroplet ---------\n");
    return do_config_droplet_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgvscplink", 11)) {
    ESP_LOGV(TAG, "--------- cfgvscplink ---------\n");
    return config_vscplink_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgvscplink", 13)) {
    ESP_LOGV(TAG, "--------- docfgvscplink ---------\n");
    return do_config_vscplink_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgmqtt", 8)) {
    ESP_LOGV(TAG, "--------- cfgmqtt ---------\n");
    return config_mqtt_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgmqtt", 10)) {
    ESP_LOGV(TAG, "--------- docfgmqtt ---------\n");
    return do_config_mqtt_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfglog", 7)) {
    ESP_LOGV(TAG, "--------- cfglog ---------\n");
    return config_log_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfglog", 9)) {
    ESP_LOGV(TAG, "--------- docfglog ---------\n");
    return do_config_log_get_handler(req);
  }

  // ---------------------------------------------------------------

  if (0 == strncmp(req->uri, "/info", 5)) {
    ESP_LOGV(TAG, "--------- info ---------\n");
    return info_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/reset", 6)) {
    ESP_LOGV(TAG, "--------- reset ---------\n");
    return reset_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdsrv", 9)) {
    ESP_LOGV(TAG, "--------- Upgrade server ---------\n");
    return upgrade_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdlocal", 10)) {
    ESP_LOGV(TAG, "--------- Upgrade local ---------\n");
    return upgrdlocal_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upd-droplet", 12)) {
    ESP_LOGV(TAG, "--------- Upgrade droplet settings ---------\n");
    return upd_droplet_get_handler(req);
  }

  return ESP_OK;

  // ------------------------------------------------------------------------------------------

  // If name has trailing '/', respond with directory contents
  if (0 == strcmp(req->uri, "/")) {
    ESP_LOGI(TAG, "Set default uri");
    strcpy(req->uri, "/index.html");
  }

  const char *filename = get_path_from_uri(filepath, "/spiffs", req->uri, sizeof(filepath));
  if (!filename) {
    ESP_LOGE(TAG, "Filename is too long");
    // Respond with 500 Internal Server Error
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
    return ESP_FAIL;
  }

  if (stat(filepath, &file_stat) == -1) {
    // If file not present on SPIFFS check if URI
    // corresponds to one of the hardcoded paths
    if (strcmp(filename, "/index.html") == 0) {
      // return index_html_get_handler(req);
    }
    else if (strcmp(filename, "/favicon.ico") == 0) {
      // return favicon_get_handler(req);
    }
    ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
    // Respond with 404 Not Found
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
    return ESP_FAIL;
  }

  fd = fopen(filepath, "r");
  if (!fd) {
    ESP_LOGE(TAG, "Failed to read existing file : %s", filepath);
    // Respond with 500 Internal Server Error
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Sending file : %s (%ld bytes)...", filename, file_stat.st_size);
  set_content_type_from_file(req, filename);

  // Retrieve the pointer to chunk buffer for temporary storage
  char *chunk = (char *) req->user_ctx;
  size_t chunksize;
  do {
    // Read file in chunks into the chund buffer
    memset(chunk, 0, sizeof(req->user_ctx));
    chunksize = fread(chunk, 1, CHUNK_BUFSIZE, fd);

    if (chunksize > 0) {
      // Send the buffer contents as HTTP response chunk
      if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
        fclose(fd);
        ESP_LOGE(TAG, "File sending failed!");
        // Abort sending file
        httpd_resp_sendstr_chunk(req, NULL);
        // Respond with 500 Internal Server Error
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
        return ESP_FAIL;
      }
    }

    // Keep looping till the whole file is sent
  } while (chunksize != 0);

  // Close file after sending complete
  fclose(fd);
  ESP_LOGI(TAG, "File sending complete");

  /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
  httpd_resp_set_hdr(req, "Connection", "close");
#endif
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// start_webserver
//

httpd_handle_t
start_webserver(void)
{
  httpd_handle_t srv        = NULL;
  httpd_config_t dfltconfig = HTTPD_DEFAULT_CONFIG();

  dfltconfig.lru_purge_enable = true;
  // Use the URI wildcard matching function in order to
  // allow the same handler to respond to multiple different
  // target URIs which match the wildcard scheme
  dfltconfig.uri_match_fn = httpd_uri_match_wildcard;

  dfltconfig.max_uri_handlers = 20;

  // Start the httpd server
  ESP_LOGI(TAG, "Starting server on port: '%d'", dfltconfig.server_port);
  if (httpd_start(&srv, &dfltconfig) == ESP_OK) {

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");

    // URI handler for getting uploaded files
    // httpd_uri_t file_spiffs = { .uri      = "/*", // Match all URIs of type /path/to/file
    //                             .method   = HTTP_GET,
    //                             .handler  = spiffs_get_handler,
    //                             .user_ctx = NULL };

    httpd_uri_t dflt = { .uri      = "/*", // Match all URIs of type /path/to/file
                         .method   = HTTP_GET,
                         .handler  = default_get_handler,
                         .user_ctx = NULL };

    // httpd_register_uri_handler(srv, &hello);
    // httpd_register_uri_handler(srv, &echo);
    // httpd_register_uri_handler(srv, &ctrl);
    // httpd_register_uri_handler(srv, &mainpg);
    httpd_register_uri_handler(srv, &dflt);

    // httpd_register_uri_handler(srv, &config);
    //  httpd_register_uri_handler(srv, &cfgModule);

    // httpd_register_uri_handler(srv, &info);
    // httpd_register_uri_handler(srv, &reset);

    // httpd_register_uri_handler(srv, &upgrade);
    // httpd_register_uri_handler(srv, &upgrade_local);

    // httpd_register_basic_auth(srv);
    // httpd_register_uri_handler(srv, &file_spiffs);

    return srv;
  }

  ESP_LOGI(TAG, "Error starting server!");
  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// stop_webserver
//

esp_err_t
stop_webserver(httpd_handle_t server)
{

  // Stop the httpd server
  return httpd_stop(server);
}

///////////////////////////////////////////////////////////////////////////////
// disconnect_handler
//

static void
disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server) {
    ESP_LOGI(TAG, "Stopping webserver");
    if (stop_webserver(*server) == ESP_OK) {
      *server = NULL;
    }
    else {
      ESP_LOGE(TAG, "Failed to stop http server");
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// connect_handler
//

static void
connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server == NULL) {
    ESP_LOGI(TAG, "Starting webserver");
    *server = start_webserver();
  }
}
