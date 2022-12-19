# Common Alpha node registers

## Wifi SSID
Wifi SSID for access point to connect to.

| register | Description |
| -------- | ----------- |
| 0x0001000 - 0x0001001f | ssid storage. 2 - 32 bytes. [Rules](https://www.cisco.com/assets/sol/sb/WAP321_Emulators/WAP321_Emulator_v1.0.0.3/help/Wireless05.html) |

## Wifi Key
Wifi WEP key for access point to connect to.

| register | Description |
| -------- | ----------- |
| 0x0001100 - 0x0001011f | WEP key |

## Channel
Wifi channel to use. This is the channel for Droplet and the access point.

| register | Description |
| -------- | ----------- |
| 0x0001200 | Wifi/Droplet channel 0-11. Zero uses the access point channel. |

## Master key
This is the master secret key for the Droplet segment. It is always 16-bytes.

| register | Description |
| -------- | ----------- |
| 0x0001300-- 0x000131f | Master key. |

## Enable Long range
Set if long range should be enabled.

| Register | Description |
| -------- | ----------- |
| 0x0001201 | Enable long range. |

## Heartbeat interval
Interval for heartbeats. Default and recommended value is 3000 milliseconds.

| Register | Description |
| -------- | ----------- |
| 0x0001202 - 0x0001202 | Heartbeat frequency in milliseconds. Set to zero for no heartbeats. |

## VSCP tcp/ip Link Protocol settings

Settings for the VSCP tcp/ip link protocol. 

### Enable VSCP tcp/ip link protocol 
Enable the VSCP tcp/ip link protocol. Clients can connect to port with username and password set below.

### Username
Username needed to use the VSCP tcp/ip link.

| Register | Description |
| -------- | ----------- |
| 0x0001400 - 0x000141f | Username for VSCP tcp/ip link. |

### Password
Password needed to use the VSCP tcp/ip link.

| Register | Description |
| -------- | ----------- |
| 0x0001420 - 0x000142f | Password for VSCP tcp/ip link. |

### Port
Port that VSCP tcp/ip link protocol uses.

| Register | Description |
| -------- | ----------- |
| 0x0001430 - 0x0001431 | VSCP tcp/ip link port. |

### Valid source address
Port that VSCP tcp/ip link protocol uses.

| Register | Description |
| -------- | ----------- |
| 0x0001432 - 0x0001435 | VSCP tcp/ip link ipv4 valid source address. |

## Web server settings

Settings for the web server.

### Enable webserver

Enable web server

| Register | Description |
| -------- | ----------- |
| 0x0001500 - 0x0001500 | Enable web server. |

## Username
admin user name for web server.

| Register | Description |
| -------- | ----------- |
| 0x0001510 - 0x000151f | Username for webserver. |

### Password
admin password for web server.

| Register | Description |
| -------- | ----------- |
| 0x0001520 - 0x000152f | Password for webserver. |

### Port
Port that web server uses.

| Register | Description |
| -------- | ----------- |
| 0x0001501 - 0x0001502 | Port for webserver. |

## MQTT client settings

Settings for the MQTT client.

### Enable MQTT client

Enable the MQTT client.

| Register | Description |
| -------- | ----------- |
| 0x0001600 - 0x0001600 | Enable MQTT client. |

### Username
Username for MQTT client to use to connect to MQTT broker.

| Register | Description |
| -------- | ----------- |
| 0x0001610 - 0x000161f | Username for MQTT broker. |

### Password
Password for MQTT client to use to connect to MQTT broker.

| Register | Description |
| -------- | ----------- |
| 0x0001620 - 0x000162f | Password for MQTT broker. |

### Port
Port on MQTT broker client should connect to.

| Register | Description |
| -------- | ----------- |
| 0x0001601 - 0x0001602 | Port for MQTT broker. |

### Client id
The client id the MQTT client should use. Default is the VSCP GUID.

| Register | Description |
| -------- | ----------- |
| 0x0001630 - 0x000164f | Client if for MQTT broker. |

### Rx Topic
Topic template from which the MQTT client will subscribe VSCP events.

| Register | Description |
| -------- | ----------- |
| 0x0001650 - 0x000168f | RX topic for MQTT broker. |

### Tx Topic
Topic template to which the MQTT client will publish VSCP events.

| Register | Description |
| -------- | ----------- |
| 0x0001690 - 0x00016Cf | TX topic for MQTT broker. |

## Logging

### Serial log level
none/error/info/debug/verbose

| Register | Description |
| -------- | ----------- |
| 0x0001700 - 0x0001700 | Serial log level. |

### Web log level
none/error/info/debug/verbose

Web server needs to be enabled.

| Register | Description |
| -------- | ----------- |
| 0x0001701 - 0x0001701 | Web server log level. |

### tcp/ip link log level
none/error/info/debug/verbose

VSCP tcp(ip link protocol needs to be enabled.

| Register | Description |
| -------- | ----------- |
| 0x0001702 - 0x0001702 | VSCP tcp/ip link log level. |

### MQTT Log level
none/error/info/debug/verbose

MQTT client needs to be enabled.

| Register | Description |
| -------- | ----------- |
| 0x0001703 - 0x0001703 | MQTT log level. |

### Syslog

#### Sylog log level
none/error/info/debug/verbose

| Register | Description |
| -------- | ----------- |
| 0x0001704 - 0x0001704 | Syslog log level. |

#### Syslog host
Host ipv4 address the syslog server lives on.

| Register | Description |
| -------- | ----------- |
| 0x0001705 - 0x0001708 | Ipv4 address for syslog server. |

#### Syslog port
Port the syslog server listen on.


------

Commands

## Provision node XX:XX:XX:XX:XX:XX
Provision node XX:XX:XX:XX:XX:XX

