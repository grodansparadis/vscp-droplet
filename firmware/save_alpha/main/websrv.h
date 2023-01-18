/*
  VSCP droplet alpha webserver

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

  curl 192.168.43.130:80/hello
  curl -X POST --data-binary @registers.txt 192.168.1.112:80/echo > tmpfile
  curl -X PUT -d "0" 192.168.1.112:80/ctrl
  curl -X PUT -d "1" 192.168.1.112:80/ctrl

  1. "curl 192.168.43.130:80/hello"  - tests the GET "\hello" handler
  2. "curl -X POST --data-binary @anyfile 192.168.43.130:80/echo > tmpfile"
      * "anyfile" is the file being sent as request body and "tmpfile" is where the body of the response is saved
      * since the server echoes back the request body, the two files should be same, as can be confirmed using : "cmp
  anyfile tmpfile"
  3. "curl -X PUT -d "0" 192.168.43.130:80/ctrl" - disable /hello and /echo handlers
  4. "curl -X PUT -d "1" 192.168.43.130:80/ctrl" -  enable /hello and /echo handlers

*/
cxccxc
#ifndef __VSCP_ALPHA_WEBSRV_H__
#define __VSCP_ALPHA_WEBSRV_H__

fgfgfg

/*>>
  Page start HTML
  Parameter 1: Page head
  Parameter 2: Section header
*/
#define WEBPAGE_START_TEMPLATE "<!DOCTYPE html><html lang=\"en\" class=\"\"><head><meta charset='utf-8'>" \
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,user-scalable=no\" /><title>Droplet " \
"Alpha node - Main Menu</title><link rel=\"icon\" href=\"favicon.ico\">" \
"<link rel=\"stylesheet\" href=\"style.css\" /></head><body><div " \
"style='text-align:left;display:inline-block;color:#eaeaea;min-width:340px;'>" \
"<div style='text-align:center;color:#eaeaea;'><noscript>To use Droplet admin interface, please enable " \
"JavaScript<br></noscript><h3>%s</h3></div>" \
"<div style='text-align:center;color:#f7f1a6;'><h4>%s</h4></div>"

/*>>
  Page end HTML
  Parameter 1: Page head
  Parameter 2: Section header
*/
#define WEBPAGE_END_TEMPLATE "jhjh"

#define CONFIG_EXAMPLE_BASIC_AUTH_USERNAME "admin"
#define CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD "secret"

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

typedef struct {
  char *username;
  char *password;
} basic_auth_info_t;

/*!
  Start the webserver
  @return esp error code
*/

httpd_handle_t
start_webserver(void);

/*!
  Stop the webserver
  @param server Server handle
  @return esp error code
*/

esp_err_t
stop_webserver(httpd_handle_t server);

#endif