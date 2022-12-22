/*
  VSCP Alpha Droplet node

  Web Server

  This file is part of the VSCP (https://www.vscp.org)

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

#include <esp_event_base.h>
#include <esp_tls_crypto.h>
#include <esp_vfs.h>
#include <esp_spiffs.h>
#include <esp_http_server.h>

#include "websrv.h"

// #define MIN(a, b) (((a) < (b)) ? (a) : (b))
// #define MAX(a, b) (((a) > (b)) ? (a) : (b))

// External from main
extern uint32_t g_boot_counter;
extern esp_netif_t *g_netif;

#define TAG __func__

// Max length a file path can have on storage
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)

// Chunk buffer size
#define CHUNK_BUFSIZE 8192
static char g_chunkbuf[CHUNK_BUFSIZE];

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

static esp_err_t
basic_auth_get_handler(httpd_req_t *req)
{
  char *buf                          = NULL;
  size_t buf_len                     = 0;
  basic_auth_info_t *basic_auth_info = req->user_ctx;

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

    char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
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
      httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
      httpd_resp_send(req, NULL, 0);
    }
    else {
      ESP_LOGI(TAG, "Authenticated!");
      char *basic_auth_resp = NULL;
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
      free(basic_auth_resp);
    }
    free(auth_credentials);
    free(buf);
  }
  else {
    ESP_LOGE(TAG, "No auth header received");
    httpd_resp_set_status(req, HTTPD_401);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
    httpd_resp_send(req, NULL, 0);
  }

  return ESP_OK;
}

static httpd_uri_t basic_auth = {
  .uri     = "/basic_auth",
  .method  = HTTP_GET,
  .handler = basic_auth_get_handler,
};

///////////////////////////////////////////////////////////////////////////////
// httpd_register_basic_auth
//

static void
httpd_register_basic_auth(httpd_handle_t server)
{
  basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
  if (basic_auth_info) {
    basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
    basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

    basic_auth.user_ctx = basic_auth_info;
    httpd_register_uri_handler(server, &basic_auth);
  }
}

//-----------------------------------------------------------------------------
//                               End Basic Auth
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// info_get_handler
//
// HTTP GET handler for info page
//

static esp_err_t
  info_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char buf[250];
  char temp[80];
  //size_t buf_len;

  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  sprintf(buf, "<!DOCTYPE html><html lang=\"en\" class=\"\"><head><meta charset='utf-8'>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,user-scalable=no\" /><title>Droplet Alpha node - Main Menu</title><link rel=\"icon\" href=\"favicon-32x32.png\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<link rel=\"stylesheet\" href=\"style.css\" /></head><body><div style='text-align:left;display:inline-block;color:#eaeaea;min-width:340px;'>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div style='text-align:center;color:#eaeaea;'><noscript>To use Droplet admin interface, please enable JavaScript<br></noscript><h3>Droplet Alpha</h3></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div style='text-align:center;color:#f7f1a6;'><h4>Technical Info</h4></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<table>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // * * * system * * *
  //sprintf(buf, "<tr><td>System</td><td></td></tr>");
  sprintf(buf, "<tr><td class='infoheader'>System</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Chip type:</td>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  switch (chip_info.model) {

    case CHIP_ESP32:
      printf("ESP32\n");
      sprintf(buf, "<td class=\"prop\">ESP32</td><tr>");
      break;

    case CHIP_ESP32S2:
      printf("ESP32-S2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S2</td><tr>");
      break;

    case CHIP_ESP32S3:
      printf("ESP32-S3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S3</td><tr>");
      break;

    case CHIP_ESP32C3:
      printf("ESP32-C3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C3</td><tr>");
      break;

    case CHIP_ESP32H2:
      printf("ESP32-H2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-H2</td><tr>");
      break;

    case CHIP_ESP32C2:
      printf("ESP32-C2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C2</td><tr>");
      break;

    default:
      printf("Unknown\n");
      sprintf(buf, "<td class=\"prop\">Unknown</td></tr>");
      break;
  }
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Number of cores:</td><td class=\"prop\">%d</td></tr>", chip_info.cores);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //printf("Number of cores: %d \n", chip_info.cores);

  // Chip comm features
  sprintf(temp,"%s%s%s%s",
         (chip_info.features & CHIP_FEATURE_WIFI_BGN) ? "WiFi " : "",
         (chip_info.features & CHIP_FEATURE_BT) ? "BT " : "",
         (chip_info.features & CHIP_FEATURE_BLE) ? "BLE " : "",
         (chip_info.features & CHIP_FEATURE_IEEE802154) ? "802.15.4 " : "");
  sprintf(buf, "<tr><td class=\"name\">Chip comm features:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);   

  wifi_country_t country;
  esp_wifi_get_country(&country);
  //printf("Wifi country code: %c%c%c\n", country.cc[0],country.cc[1],country.cc[2]);
  sprintf(buf, "<tr><td class=\"name\">Wifi country code:</td><td class=\"prop\">%c%c%c</td></tr>", country.cc[0],country.cc[1],country.cc[2]);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);    

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded flash:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_PSRAM) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded psram:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //sprintf(temp, "%d", chip_info.revision);
  sprintf(buf, "<tr><td class=\"name\">Silicon revision:</td><td class=\"prop\">%d</td></tr>", chip_info.revision);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t chipId;
  rv = esp_flash_read_id(NULL, &chipId);
  //printf("Flash chip id: %04lX\n", chipId);
  sprintf(buf, "<tr><td class=\"name\">Flash chip id:</td><td class=\"prop\">%04lX</td></tr>", chipId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint64_t uniqueId;
  rv = esp_flash_read_unique_chip_id(NULL, &uniqueId);
  //printf("Unique flash chip id: %08llX\n", uniqueId);
  sprintf(buf, "<tr><td class=\"name\">Unique flash chip id:</td><td class=\"prop\">%08llX</td></tr>", uniqueId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t sizeFlash;
  esp_flash_get_size(NULL, &sizeFlash);
  sprintf(temp,"%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "(embedded)" : "(external)");
  // printf("%luMB %s flash\n",
  //        sizeFlash / (1024 * 1024),
  //        (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
  sprintf(buf, "<tr><td class=\"name\">Flash size:</td><td class=\"prop\">%s %lu MB</td></tr>", temp, sizeFlash / (1024 * 1024));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // get chip id
  // chipId = String((uint32_t) ESP.getEfuseMac(), HEX);
  // chipId.toUpperCase();
  // printf("Chip id: %s\n", chipId.c_str());

  //printf("esp-idf version: %s\n", esp_get_idf_version());
  sprintf(buf, "<tr><td class=\"name\">esp-idf version:</td><td class=\"prop\">%s</td></tr>", esp_get_idf_version());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //printf("Free heap size: %lu\n", esp_get_free_heap_size());
  sprintf(buf, "<tr><td class=\"name\">Free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>", esp_get_free_heap_size()/1024, esp_get_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //printf("Min free heap size: %lu\n", esp_get_minimum_free_heap_size());
  sprintf(buf, "<tr><td class=\"name\">Min free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>", esp_get_minimum_free_heap_size()/1024, esp_get_minimum_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //printf("Last reset reson: ");
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

  //printf("Number of reboots: %lu\n",g_boot_counter);
  sprintf(buf, "<tr><td class=\"name\">Number of reboots:</td><td class=\"prop\">%lu</td></tr>", g_boot_counter);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // * * *  Application * * *
  //sprintf(buf, "<tr><td>Application</td><td></td></tr>");
  sprintf(buf, "<tr><td class='infoheader'>Application</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);


  int time = esp_timer_get_time();
  sprintf(buf, "<tr><td class=\"name\">Uptime:</td><td class=\"prop\">%dT%02d:%02d:%02d</td></tr>", ((time/1000000)/(3600*24)),((time/1000000)/3600),((time/1000000)/60),(time/1000000));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  //printf("Firmware version: %d\n", DROPLET_VERSION);
  const esp_app_desc_t *appDescr = esp_ota_get_app_description();

  if ( NULL != appDescr) {
    //sprintf(temp,"%s",appDescr->project_name);
    sprintf(buf, "<tr><td class=\"name\">Application:</td><td class=\"prop\">%s</td></tr>", appDescr->project_name);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    
    //sprintf(temp,"Application ver: %s\n",appDescr->version);
    sprintf(buf, "<tr><td class=\"name\">Application ver:</td><td class=\"prop\">%s</td></tr>", appDescr->version);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    
    //sprintf(temp,"Application ver: %s %s\n",appDescr->date,appDescr->time);
    sprintf(buf, "<tr><td class=\"name\">Compile time:</td><td class=\"prop\">%s %s</td></tr>", appDescr->date,appDescr->time);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    
    //sprintf(temp,"idf ver: %s\n",appDescr->idf_ver);
    sprintf(buf, "<tr><td class=\"name\">Compiled w/ idf ver:</td><td class=\"prop\">%s</td></tr>", appDescr->idf_ver);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  }

  // * * *  Connection * * *
  sprintf(buf, "<tr><td class='infoheader'>Connection</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_mode_t mode;
  rv = esp_wifi_get_mode(&mode);  
  switch(mode) {

    case WIFI_MODE_STA:
      sprintf(temp,"STA\n");
      break;

    case WIFI_MODE_AP:
      sprintf(temp,"AP\n");
      break;

    case WIFI_MODE_APSTA:
      sprintf(temp,"APSTA\n");
      break;

    case WIFI_MODE_NULL:
    default:
      sprintf(temp,"unknown\n");
      break;
  };
  //sprintf(temp,"Wifi mode: ");
  sprintf(buf, "<tr><td class=\"name\">Wifi mode:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_sta_list_t sta;
  rv =  esp_wifi_ap_get_sta_list(&sta);
  //printf("Stations: %d\n",sta.num);
  sprintf(buf, "<tr><td class=\"name\">Stations:</td><td class=\"prop\">%d</td></tr>", sta.num);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_ap_record_t ap_info;
  rv = esp_wifi_sta_get_ap_info(&ap_info);
  printf("bssid: " MACSTR "\n", MAC2STR(ap_info.bssid));
  sprintf(buf, "<tr><td class=\"name\">bssid:</td><td class=\"prop\">" MACSTR "</td></tr>", MAC2STR(ap_info.bssid));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  printf("ssid: %s\n", ap_info.ssid);
  sprintf(buf, "<tr><td class=\"name\">ssid:</td><td class=\"prop\">%s</td></tr>", ap_info.ssid);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  printf("channel: %d (%d)\n", ap_info.primary, ap_info.second);
  sprintf(buf, "<tr><td class=\"name\">channel:</td><td class=\"prop\">%d (%d)</td></tr>", ap_info.primary, ap_info.second);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  printf("signal strength: %d\n", ap_info.rssi);
  if ( ap_info.rssi > -30 ) {
    sprintf(temp,"Perfect");
  }
  else if ( ap_info.rssi > -50 ) { 
    sprintf(temp,"Excellent");
  }
  else if ( ap_info.rssi > -60 ) { 
    sprintf(temp,"Good");
  }
  else if ( ap_info.rssi > -67 ) { 
    sprintf(temp,"Limited");
  }
  else if ( ap_info.rssi > -70 ) { 
    sprintf(temp,"Poor");
  }
  else if ( ap_info.rssi > -80 ) { 
    sprintf(temp,"Unstable");
  }
  else { 
    sprintf(temp,"Unusable");
  }
  
  sprintf(buf, "<tr><td class=\"name\">signal strength:</td><td class=\"prop\">%d dBm ( %d%% = %s)</td></tr>", ap_info.rssi, (2 * (ap_info.rssi + 100) ), temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  printf("Mode: 11%s%s%s %s %s",
            ap_info.phy_11b ? "b" : "",
            ap_info.phy_11g ? "g" : "",
            ap_info.phy_11n ? "n" : "",
            ap_info.phy_lr ? "lr" : "",
            ap_info.wps ? "wps" : "");
  //printf("\nAuth mode of AP: ");
  switch (ap_info.authmode) {
    
    case WIFI_AUTH_OPEN:
      sprintf(temp,"open\n");
      break;

    case WIFI_AUTH_WEP:
      sprintf(temp,"wep\n");
      break;

    case WIFI_AUTH_WPA_PSK:
      sprintf(temp,"wpa-psk\n");
      break;

    case WIFI_AUTH_WPA2_PSK:
      sprintf(temp,"wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA_WPA2_PSK:
      sprintf(temp,"wpa-wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA2_ENTERPRISE:
      sprintf(temp,"wpa2-enterprise\n");
      break;

    case WIFI_AUTH_WPA3_PSK:
      sprintf(temp,"wpa3-psk\n");
      break;  

    case WIFI_AUTH_WPA2_WPA3_PSK:
      sprintf(temp,"wpa2-wpa3-psk\n");
      break;    

    case WIFI_AUTH_WAPI_PSK:
      sprintf(temp,"wpa2-wapi-psk\n");
      break;

    case WIFI_AUTH_OWE:
      sprintf(temp,"wpa2-wapi-psk\n");
      break;

    default:
      sprintf(temp,"unknown\n");
      break;      
  }

  sprintf(buf, "<tr><td class=\"name\">Auth mode of AP:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  
  uint8_t mac[6];
  esp_wifi_get_mac(ESP_IF_WIFI_STA, &mac);
  //printf("Wifi STA MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf, "<tr><td class=\"name\">Wifi STA MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>", MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_wifi_get_mac(ESP_MAC_WIFI_SOFTAP, &mac);
  //printf("Wifi SOFTAP MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf, "<tr><td class=\"name\">Wifi SOFTAP MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>", MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_netif_ip_info_t ifinfo;
  esp_netif_get_ip_info(g_netif, &ifinfo);
  printf("IP address (wifi): " IPSTR "\n", IP2STR(&ifinfo.ip));
  sprintf(buf, "<tr><td class=\"name\">IP address (wifi):</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&ifinfo.ip));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  printf("Subnet Mask: " IPSTR "\n", IP2STR(&ifinfo.netmask));
  sprintf(buf, "<tr><td class=\"name\">Subnet Mask:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&ifinfo.netmask));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  
  printf("Gateway: " IPSTR "\n", IP2STR(&ifinfo.gw));
  sprintf(buf, "<tr><td class=\"name\">Gateway:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&ifinfo.gw));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_netif_dns_info_t dns;
  rv = esp_netif_get_dns_info(g_netif, ESP_NETIF_DNS_MAIN, &dns);
  //printf("DNS DNS Server1: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4)); 
  sprintf(buf, "<tr><td class=\"name\">DNS Server1:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&dns.ip.u_addr.ip4));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  rv = esp_netif_get_dns_info(g_netif, ESP_NETIF_DNS_BACKUP, &dns);

  //printf("DNS Server2: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));  
  sprintf(buf, "<tr><td class=\"name\">DNS Server2:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&dns.ip.u_addr.ip4));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</table>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but14 style=\"display: block;\" action='index.html' method='get'><button>Main Menu</button></form></p><p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  
  sprintf(buf, "<div style='text-align:right;font-size:11px;'><hr /><a href='https://vscp.org' target='_blank' style='color:#aaa;'>Alpha Droplet 13.1 -- vscp.org</a></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</div></body></html>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// reset_get_handler
//
// HTTP GET handler for reset of machine
//

static esp_err_t
  reset_get_handler(httpd_req_t *req)
{
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=index.html\" /></head><body><h1>The system is restarting...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  esp_restart();
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// update_get_handler
//
// HTTP GET handler for update of firmware
//

static esp_err_t
  update_get_handler(httpd_req_t *req)
{
  const char *resp_str = "<html><head><meta charset='utf-8'><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,user-scalable=no\" /><link rel=\"icon\" href=\"favicon-32x32.png\"><title>Droplet Alpha node - Update</title><link rel=\"stylesheet\" href=\"style.css\" /><meta http-equiv=\"refresh\" content=\"5;url=index.html\" /></head><body><div style='text-align:left;display:inline-block;color:#eaeaea;min-width:340px;'><div style='text-align:center;color:#eaeaea;'><h1>The system is restarting...</h1></div></div></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  esp_restart();
  return ESP_OK;
}

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
  const char *resp_str = "Hi there mister mongo!";//(const char *) req->user_ctx;
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
// spiffs_get_handler
//
// Handler to download a file kept on the server
//

static esp_err_t
spiffs_get_handler(httpd_req_t *req)
{
  char filepath[FILE_PATH_MAX];
  FILE *fd = NULL;
  struct stat file_stat;

  ESP_LOGI(TAG, "uri : [%s]", req->uri);

  if (0 == strncmp(req->uri, "/hello", 6)) {
    printf("--------- HELLO ---------\n");
    return hello_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/info", 5)) {
    printf("--------- info ---------\n");
    return info_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/reset", 5)) {
    printf("--------- reset ---------\n");
    return reset_get_handler(req);
  }

  const char *filename = get_path_from_uri(filepath, "/spiffs", req->uri, sizeof(filepath));
  if (!filename) {
    ESP_LOGE(TAG, "Filename is too long");
    // Respond with 500 Internal Server Error
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
    return ESP_FAIL;
  }

  // If name has trailing '/', respond with directory contents
  if (0 == strcmp(filename, "/spiffs/'")) {
    strcpy(req->uri, "/index.html");
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
  httpd_handle_t server = NULL;
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();

  config.lru_purge_enable = true;
  // Use the URI wildcard matching function in order to
  // allow the same handler to respond to multiple different
  // target URIs which match the wildcard scheme
  config.uri_match_fn = httpd_uri_match_wildcard;

  // Start the httpd server
  ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
  if (httpd_start(&server, &config) == ESP_OK) {

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");

    // URI handler for getting uploaded files
    httpd_uri_t file_spiffs = { .uri      = "/*", // Match all URIs of type /path/to/file
                                .method   = HTTP_GET,
                                .handler  = spiffs_get_handler,
                                .user_ctx = g_chunkbuf };

    // httpd_register_uri_handler(server, &hello);
    // httpd_register_uri_handler(server, &echo);
    // httpd_register_uri_handler(server, &ctrl);
    httpd_register_uri_handler(server, &file_spiffs);

    httpd_register_basic_auth(server);

    return server;
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
