  /*
  File: wifiprov.c

  Wifi provisioning

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

#include "esp_now.h"
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_wifi.h>

#ifdef CONFIG_PROV_TRANSPORT_BLE 
#include <wifi_provisioning/scheme_ble.h> 
#endif /* CONFIG_PROV_TRANSPORT_BLE */

#ifdef CONFIG_PROV_TRANSPORT_SOFTAP
#include <wifi_provisioning/scheme_softap.h>
#endif /* CONFIG_PROV_TRANSPORT_SOFTAP */

#include "qrcode.h"

#include <vscp.h>
#include "vscp_espnow.h"

#include "main.h"
#include "wifiprov.h"

static const char *TAG = "espnow_alpha wifiprov";

///////////////////////////////////////////////////////////////////////////////
// wifi_prov_print_qr
//

void
wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport)
{
  if (!name || !transport) {
    ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
    return;
  }
  char payload[150] = { 0 };
  if (pop) {
#if CONFIG_PROV_SECURITY_VERSION_1
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             pop,
             transport);
#elif CONFIG_PROV_SECURITY_VERSION_2
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"username\":\"%s\",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             username,
             pop,
             transport);
#endif
  }
  else {
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             transport);
  }
#ifdef CONFIG_PROV_SHOW_QR
  ESP_LOGI(TAG, "Scan this QR code from the provisioning application for Provisioning.");
  esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
  esp_qrcode_generate(&cfg, payload);
#endif /* CONFIG_APP_WIFI_PROV_SHOW_QR */
  ESP_LOGI(TAG,
           "If QR code is not visible, copy paste the below URL in a "
           "browser.\n%s?data=%s",
           QRCODE_BASE_URL,
           payload);
}

///////////////////////////////////////////////////////////////////////////////
// custom_prov_data_handler
//
// Handler for the optional provisioning endpoint registered by the application.
// The data format can be chosen by applications. Here, we are using plain ascii
// text. Applications can choose to use other formats like protobuf, JSON, XML,
// etc.
//



esp_err_t
custom_prov_data_handler(uint32_t session_id,
                         const uint8_t *inbuf,
                         ssize_t inlen,
                         uint8_t **outbuf,
                         ssize_t *outlen,
                         void *priv_data)
{
  if (inbuf) {
    ESP_LOGI(TAG, "Received data: %.*s", inlen, (char *) inbuf);
  }

  char response[] = "SUCCESS";
  *outbuf         = (uint8_t *) strdup(response);

  if (*outbuf == NULL) {
    ESP_LOGE(TAG, "System out of memory");
    return ESP_ERR_NO_MEM;
  }

  *outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_espnow_data_prepare
//
// Prepare ESPNOW data to be sent. 
//

// void vscp_espnow_data_prepare(vscp_espnow_data_t *send_param)
// {
//     vscp_espnow_send_param_t *buf = (vscp_espnow_send_param_t *)send_param->buffer;
//     assert(send_param->len >= sizeof(vscp_espnow_send_param_t));

//     buf->type = IS_BROADCAST_ADDR(send_param->dest_mac) ? EXAMPLE_ESPNOW_DATA_BROADCAST : EXAMPLE_ESPNOW_DATA_UNICAST;
//     buf->state = send_param->state;
//     buf->seq_num = s_vscp_espnow_seq[buf->type]++;
//     buf->crc = 0;
//     buf->magic = send_param->magic;
//     // Fill all remaining bytes after the data with random values 
//     esp_fill_random(buf->payload, send_param->len - sizeof(vscp_espnow_send_param_t));
//     buf->crc = esp_crc16_le(UINT16_MAX, (uint8_t const *)buf, send_param->len);
// }

///////////////////////////////////////////////////////////////////////////////
// get_device_service_name
//

void
get_device_service_name(char *service_name, size_t max)
{
  uint8_t eth_mac[6];
  const char *ssid_prefix = "PROV_";
  esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
  snprintf(service_name, max, "%s%02X%02X%02X", ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
}

// --------------------------------------------------------
//                      Provisioning
// --------------------------------------------------------

#if CONFIG_PROV_SECURITY_VERSION_2

#if CONFIG_PROV_SEC2_DEV_MODE
#define WCANG_PROV_SEC2_USERNAME    "testuser"
#define WCANG_PROV_SEC2_PWD         "testpassword"

/* This salt,verifier has been generated for username = "testuser" and password
 * = "testpassword" IMPORTANT NOTE: For production cases, this must be unique to
 * every device and should come from device manufacturing partition.*/
static const char sec2_salt[] = { 0x2f, 0x3d, 0x3c, 0xf8, 0x0d, 0xbd, 0x0c, 0xa9,
                                  0x6f, 0x30, 0xb4, 0x4d, 0x89, 0xd5, 0x2f, 0x0e };

// 24*16 = 384 * 8 = 3072
static const char sec2_verifier[] = {
  0xf2, 0x9f, 0xc1, 0xf5, 0x28, 0x4a, 0x11, 0x74, 0xb4, 0x24, 0x09, 0x23, 0xd8, 0x27, 0xb7, 0x5a, 0x95, 0x3a, 0x99,
  0xed, 0xf4, 0x6e, 0xe9, 0x8c, 0x4f, 0x07, 0xf2, 0xf5, 0x43, 0x3d, 0x7f, 0x9a, 0x11, 0x60, 0x66, 0xaf, 0xcd, 0xa5,
  0xf6, 0xfa, 0xcb, 0x06, 0xe9, 0xc5, 0x3f, 0x4d, 0x77, 0x16, 0x4c, 0x68, 0x6d, 0x7f, 0x7c, 0xd7, 0xc7, 0x5a, 0x83,
  0xc0, 0xfb, 0x94, 0x2d, 0xa9, 0x60, 0xf0, 0x09, 0x11, 0xa0, 0xe1, 0x95, 0x33, 0xd1, 0x30, 0x7f, 0x82, 0x1b, 0x1b,
  0x0f, 0x6d, 0xf1, 0xdc, 0x93, 0x1c, 0x20, 0xa7, 0xc0, 0x8d, 0x48, 0x38, 0xff, 0x46, 0xb9, 0xaf, 0xf7, 0x93, 0x78,
  0xae, 0xff, 0xb8, 0x3b, 0xdf, 0x99, 0x7b, 0x64, 0x47, 0x02, 0xba, 0x01, 0x39, 0x0f, 0x5c, 0xd8, 0x4e, 0x6f, 0xc8,
  0xd0, 0x82, 0x7f, 0x2d, 0x33, 0x1a, 0x09, 0x65, 0x77, 0x85, 0xbc, 0x8a, 0x84, 0xe0, 0x46, 0x7e, 0x3b, 0x0e, 0x6e,
  0x3b, 0xdf, 0x70, 0x17, 0x70, 0x0a, 0xbc, 0x84, 0x67, 0xfa, 0xf9, 0x84, 0x53, 0xda, 0xb4, 0xca, 0x38, 0x71, 0xe4,
  0x06, 0xf6, 0x7d, 0xc8, 0x32, 0xbb, 0x91, 0x0c, 0xe7, 0xd3, 0x59, 0xb6, 0x03, 0xed, 0x8e, 0x0d, 0x91, 0x9c, 0x09,
  0xd7, 0x6f, 0xd5, 0xca, 0x55, 0xc5, 0x58, 0x0f, 0x95, 0xb5, 0x83, 0x65, 0x6f, 0x2d, 0xbc, 0x94, 0x0f, 0xbb, 0x0f,
  0xd3, 0x42, 0xa5, 0xfe, 0x15, 0x7f, 0xf9, 0xa8, 0x16, 0xe6, 0x58, 0x9b, 0x4c, 0x0f, 0xd3, 0x83, 0x2c, 0xac, 0xe4,
  0xbf, 0xa3, 0x96, 0x1e, 0xb6, 0x6f, 0x59, 0xe6, 0xd1, 0x0e, 0xd4, 0x27, 0xb6, 0x05, 0x34, 0xec, 0x8c, 0xf8, 0x72,
  0xbb, 0x04, 0x7b, 0xa4, 0x49, 0x3d, 0x6d, 0xa9, 0x99, 0xfc, 0x0a, 0x2b, 0xd8, 0x46, 0xa8, 0xd1, 0x46, 0x61, 0x5c,
  0x96, 0xd2, 0x43, 0xcd, 0xea, 0x7f, 0x6a, 0x50, 0x59, 0x0d, 0x0e, 0xa1, 0xb3, 0x94, 0x5a, 0x34, 0xe0, 0x1e, 0x95,
  0x56, 0x68, 0xb4, 0xbc, 0xf1, 0x08, 0x54, 0xcb, 0x42, 0x41, 0xc6, 0x78, 0xad, 0x71, 0x84, 0x1c, 0x29, 0xb8, 0x33,
  0x79, 0x1c, 0x10, 0xdd, 0x07, 0xc8, 0x91, 0x21, 0x85, 0x89, 0x76, 0xd7, 0x37, 0xdf, 0x5b, 0x19, 0x33, 0x4e, 0x17,
  0x67, 0x02, 0x0f, 0x1b, 0xb9, 0x2f, 0xa4, 0xdc, 0xdd, 0x75, 0x32, 0x96, 0x87, 0xdd, 0x66, 0xc3, 0x33, 0xc1, 0xfc,
  0x4c, 0x27, 0x63, 0xb9, 0x14, 0x72, 0x76, 0x65, 0xb8, 0x90, 0x2b, 0xeb, 0x7a, 0xde, 0x71, 0x97, 0xf3, 0x6b, 0xc9,
  0x8e, 0xdf, 0xfc, 0x6e, 0x13, 0xcc, 0x1b, 0x2b, 0x54, 0x1a, 0x6e, 0x3d, 0xe6, 0x1c, 0xec, 0x5d, 0xa1, 0xf1, 0xd4,
  0x86, 0x9d, 0xcd, 0xb9, 0xe8, 0x98, 0xf1, 0xe5, 0x16, 0xa5, 0x48, 0xe5, 0xec, 0x12, 0xe8, 0x17, 0xe2, 0x55, 0xb5,
  0xb3, 0x7c, 0xce, 0xfd
};
#endif

///////////////////////////////////////////////////////////////////////////////
// get_sec2_salt
//

static esp_err_t
get_sec2_salt(const char **salt, uint16_t *salt_len)
{
#if CONFIG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded salt");
  *salt     = sec2_salt;
  *salt_len = sizeof(sec2_salt);
  return ESP_OK;
#elif CONFIG_PROV_SEC2_PROD_MODE
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}

///////////////////////////////////////////////////////////////////////////////
// get_sec2_verifier
//

static esp_err_t
get_sec2_verifier(const char **verifier, uint16_t *verifier_len)
{
#if CONFIG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded verifier");
  *verifier     = sec2_verifier;
  *verifier_len = sizeof(sec2_verifier);
  return ESP_OK;
#elif CONFIG_PROV_SEC2_PROD_MODE
  /* This code needs to be updated with appropriate implementation to provide
   * verifier */
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}
#endif

///////////////////////////////////////////////////////////////////////////////
// wifi_provisioning
//

bool wifi_provisioning(void)
{
  ESP_LOGI(TAG, "wifi provisioning started");

  // Configuration for the provisioning manager
  wifi_prov_mgr_config_t config = {

  // What is the Provisioning Scheme that we want ?
  // wifi_prov_scheme_softap or wifi_prov_scheme_ble
#ifdef CONFIG_PROV_TRANSPORT_BLE
  .scheme = wifi_prov_scheme_ble,
#endif // CONFIG_PROV_TRANSPORT_BLE

#ifdef CONFIG_PROV_TRANSPORT_SOFTAP
  .scheme = wifi_prov_scheme_softap,
#endif // CONFIG_PROV_TRANSPORT_SOFTAP

  /*
   * Any default scheme specific event handler that you would
   * like to choose. Since our example application requires
   * neither BT nor BLE, we can choose to release the associated
   * memory once provisioning is complete, or not needed
   * (in case when device is already provisioned). Choosing
   * appropriate scheme specific event handler allows the manager
   * to take care of this automatically. This can be set to
   * WIFI_PROV_EVENT_HANDLER_NONE when using wifi_prov_scheme_softap
   */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE  
    .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */    
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
        .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */

  };

  /*
   * Initialize provisioning manager with the
   * configuration parameters set above
   */
  ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

  ESP_LOGI(TAG, "Provision initiated");

  bool provisioned = false;

#ifdef CONFIG_RESET_PROVISIONED
  wifi_prov_mgr_reset_provisioning();
#else
  // Let's find out if the device is provisioned 
  ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));
#endif

  // If device is not yet provisioned start provisioning service 
  if (provisioned) {
    
    ESP_LOGI(TAG, "Already provisioned");
    
    /* We don't need the manager as device is already provisioned,
     * so let's release it's resources 
     */
    wifi_prov_mgr_deinit();

    return false;
  }
  else {

    ESP_LOGI(TAG, "Provisioning process...");

    /*
     * What is the Device Service Name that we want
     *
     * This translates to :
     *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
     *     - device name when scheme is wifi_prov_scheme_ble
     */
    char service_name[12];
    get_device_service_name(service_name, sizeof(service_name));

#ifdef CONFIG_PROV_SECURITY_VERSION_1
    /*
     * What is the security level that we want (0, 1, 2):
     *
     *   - WIFI_PROV_SECURITY_0 is simply plain text communication.
     *   - WIFI_PROV_SECURITY_1 is secure communication which consists of secure
     * handshake using X25519 key exchange and proof of possession (pop) and
     * AES-CTR for encryption/decryption of messages.
     *   - WIFI_PROV_SECURITY_2 SRP6a based authentication and key exchange
     *      + AES-GCM encryption/decryption of messages
     */
    wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

    /*
     * Do we want a proof-of-possession (ignored if Security 0 is selected):
     *   - this should be a string with length > 0
     *   - NULL if not used
     */
    const char *pop = "CONFIG_ESPNOW_SESSION_POP; // espnow_pop";
    /*
     * If the pop is allocated dynamically, then it should be valid till
     * the provisioning process is running.
     * it can be only freed when the WIFI_PROV_END event is triggered
     */

    /*
     * This is the structure for passing security parameters
     * for the protocomm security 1.
     * This does not need not be static i.e. could be dynamically allocated
     */
    //wifi_prov_security1_params_t *sec_params = pop;
    void *sec_params = (void *)pop;

    const char *username = NULL;

#elif CONFIG_PROV_SECURITY_VERSION_2
    wifi_prov_security_t security = WIFI_PROV_SECURITY_2;
    // The username must be the same one, which has been used in the generation
    // of salt and verifier

#if CONFIG_PROV_SEC2_DEV_MODE
    /*
     * This pop field represents the password that will be used to generate salt
     * and verifier. The field is present here in order to generate the QR code
     * containing password. In production this password field shall not be
     * stored on the device
     */
    const char *username = WCANG_PROV_SEC2_USERNAME;
    const char *pop = WCANG_PROV_SEC2_PWD;
#elif CONFIG_PROV_SEC2_PROD_MODE
    /*
     * The username and password shall not be embedded in the firmware,
     * they should be provided to the user by other means.
     * e.g. QR code sticker
     */
    const char *username = NULL;
    const char *pop      = NULL;
#endif
    /*
     * This is the structure for passing security parameters
     * for the protocomm security 2.
     * This does not need not be static i.e. could be dynamically allocated
     */
    wifi_prov_security2_params_t sec2_params = {};

    ESP_ERROR_CHECK(wcang_get_sec2_salt(&sec2_params.salt, &sec2_params.salt_len));
    ESP_ERROR_CHECK(wcang_get_sec2_verifier(&sec2_params.verifier, &sec2_params.verifier_len));

    wifi_prov_security2_params_t *sec_params = &sec2_params;
#endif

    /*
     * What is the service key (could be NULL)
     * This translates to :
     *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
     *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
     *     - simply ignored when scheme is wifi_prov_scheme_ble
     */
    const char *service_key = NULL;

#ifdef CONFIG_PROV_TRANSPORT_BLE
    /*
     * This step is only useful when scheme is wifi_prov_scheme_ble. This will
     * set a custom 128 bit UUID which will be included in the BLE advertisement
     * and will correspond to the primary GATT service that provides
     * provisioning endpoints as GATT characteristics. Each GATT characteristic
     * will be formed using the primary service UUID as base, with different
     * auto assigned 12th and 13th bytes (assume counting starts from 0th byte).
     * The client side applications must identify the endpoints by reading the
     * User Characteristic Description descriptor (0x2901) for each
     * characteristic, which contains the endpoint name of the characteristic
     */
    
    uint8_t custom_service_uuid[] = {
      /*
       * LSB <---------------------------------------
       * ---------------------------------------> MSB
       */
      0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04, 0x90, 0x1a, 0x02,
    };

    /*
     * If your build fails with linker errors at this point, then you may have
     * forgotten to enable the BT stack or BTDM BLE settings in the SDK (e.g.
     * see the sdkconfig.defaults in the example project)
     */
    wifi_prov_scheme_ble_set_service_uuid(custom_service_uuid);
#endif /* CONFIG_PROV_TRANSPORT_BLE */

    /*
     * An optional endpoint that applications can create if they expect to
     * get some additional custom data during provisioning workflow.
     * The endpoint name can be anything of your choice.
     * This call must be made before starting the provisioning.
     */
    wifi_prov_mgr_endpoint_create("custom-data");

    // Start provisioning service 
    ESP_ERROR_CHECK(wifi_prov_mgr_start_provisioning(security, (const void *)sec_params, service_name, service_key));

    /*
     * The handler for the optional endpoint created above.
     * This call must be made after starting the provisioning, and only if the
     * endpoint has already been created above.
     */
    wifi_prov_mgr_endpoint_register("custom-data", custom_prov_data_handler, NULL);    

    /*
     * Uncomment the following to wait for the provisioning to finish and then
     * release the resources of the manager. Since in this case
     * de-initialization is triggered by the default event loop handler, we
     * don't need to call the following
     */
    // wifi_prov_mgr_wait();
    // wifi_prov_mgr_deinit();

    /* Print QR code for provisioning */
#ifdef CONFIG_PROV_TRANSPORT_BLE
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_BLE);
#else  // CONFIG_PROV_TRANSPORT_SOFTAP
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_SOFTAP);
#endif // CONFIG_PROV_TRANSPORT_BLE 
    
    
  }
  
  return true;

}

